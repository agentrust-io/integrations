#!/usr/bin/env python3
"""Weight Custody Manifest -> Kyverno ClusterPolicy.

Generates the admission rules a cluster must enforce for a WCM-governed workload
to be deployable at all. It is a **precondition** gate, not an attestation gate,
and the distinction is the most important thing in this file.

**What an admission controller cannot do, and why.**

The obvious idea is to make Kyverno check the pod's image digest against
``release_policy.required_serving_image.accepted_measurements``. That would be
wrong. Those measurements are *launch measurements*: the value an enclave reports
in its quote as ``CpuQuote.serving_image_measurement``, produced by the
confidential-computing platform over the loaded workload. An OCI image digest is
a hash of a tarball in a registry. The two are different numbers over different
bytes, and comparing them would fail every time, or, worse, would pass if someone
"helpfully" populated the manifest with registry digests and thereby destroyed
the binding the KBS relies on.

Verifying a launch measurement requires a quote, a nonce and a trust store.
Kyverno has none of those at admission time. That check belongs to the key
broker, happens at release time, and cannot be moved earlier.

**So what is left is worth having anyway.** WCM's threat model names an operator
with software access on the host. Most of what such an operator needs is granted
by the pod spec: a privileged sidecar, ``hostPID``, ``shareProcessNamespace``,
``SYS_PTRACE``, a ``hostPath`` mount over the enclave's runtime directory. A
cluster that permits those has handed away the software half of the guarantee
before any key is released. These rules close that, and they are checkable
without a quote.

The generated policy therefore enforces, in order of how much it matters:

1. The confidential runtime class the manifest's ``required_hw_platform``
   implies, so the workload cannot silently land on an ordinary node.
2. No process-inspection escape hatches: privileged, ``hostPID``, ``hostIPC``,
   ``shareProcessNamespace``, ``SYS_PTRACE``, ``SYS_ADMIN``, ``CAP_SYS_MODULE``.
3. Images referenced by digest, never by tag, so what was reviewed is what runs.
4. A ``wcm.agentrust-io.com/manifest-hash`` annotation equal to this manifest's
   canonical hash, so a pod cannot claim custody governance it is not under.
5. GPU and dedicated-tenancy requirements when the manifest asks for them.

Usage::

    pip install weight-custody-manifest

    python wcm_kyverno.py manifest.json --name custody-example > policy.yaml
    kubectl apply -f policy.yaml
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

from wcm import (
    MemoryFingerprintChallenge,
    Tenancy,
    WeightCustodyManifest,
    canonical_hash,
)

__all__ = [
    "MANIFEST_HASH_ANNOTATION",
    "RUNTIME_CLASS_BY_PLATFORM",
    "NOT_ENFORCEABLE_AT_ADMISSION",
    "build_policy",
    "render_yaml",
]

#: The annotation a governed pod carries. Its value is the manifest's canonical
#: hash, so two manifests differing in any signed field produce different values
#: and a pod cannot be moved between custody agreements by editing a label.
MANIFEST_HASH_ANNOTATION = "wcm.agentrust-io.com/manifest-hash"

#: WCM platform -> conventional Kata confidential runtime class names.
#:
#: Cluster operators rename these freely, which is why ``build_policy`` takes a
#: ``runtime_classes`` override. The defaults are the names the
#: confidential-containers project ships; a cluster using others will reject
#: every pod until the override is supplied, which is the correct failure
#: direction for a policy generator.
RUNTIME_CLASS_BY_PLATFORM = {
    "amd-sev-snp": ("kata-qemu-snp", "kata-cc"),
    "intel-tdx": ("kata-qemu-tdx", "kata-cc"),
    # nvidia-cc-gpu is a GPU-side requirement, not a VM runtime class. It is
    # handled as a resource and label requirement, not by runtimeClassName.
}

#: Manifest fields that cannot be enforced here, and where they are enforced.
#: Reproduced in the generated YAML as a comment so an operator reading the
#: policy in a cluster sees the boundary without finding this file.
NOT_ENFORCEABLE_AT_ADMISSION = {
    "required_serving_image.accepted_measurements": (
        "launch measurements from a hardware quote, not OCI digests. Verified by "
        "the key broker at release time against a nonce and a trust store."
    ),
    "required_assurance_tier": (
        "asserted by a signed quote. Admission sees a pod spec, which cannot "
        "attest to anything."
    ),
    "attestation_cadence / kbs_attestation_cadence": (
        "Layer 3 runtime custody. Enforced by the lease loop inside the workload; "
        "admission runs once, at creation."
    ),
    "revocation_authority": (
        "a release-time and runtime decision. Revoking weights does not delete a "
        "running pod, it stops the next key release and triggers wipe-on-lapse."
    ),
    "physical_hardening": (
        "a datacentre control. No cluster-level policy can observe whether the "
        "rack has a tamper-evident enclosure."
    ),
}

_FORBIDDEN_CAPABILITIES = ("SYS_PTRACE", "SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO")


def _match_block(namespaces: list[str] | None, selector: dict[str, str]) -> dict[str, Any]:
    resource: dict[str, Any] = {"kinds": ["Pod"], "selector": {"matchLabels": selector}}
    if namespaces:
        resource["namespaces"] = namespaces
    return {"any": [{"resources": resource}]}


def _runtime_class_rule(
    manifest: WeightCustodyManifest, runtime_classes: dict[str, tuple[str, ...]]
) -> dict[str, Any] | None:
    allowed: list[str] = []
    for platform in manifest.release_policy.required_hw_platform:
        allowed.extend(runtime_classes.get(platform, ()))
    # dict.fromkeys rather than set(): the order an operator reads in the policy
    # should follow the manifest, not hash iteration order.
    allowed = list(dict.fromkeys(allowed))
    if not allowed:
        return None
    return {
        "name": "require-confidential-runtime-class",
        "match": None,  # filled by build_policy
        "validate": {
            "message": (
                "This workload is governed by a Weight Custody Manifest requiring "
                f"{', '.join(manifest.release_policy.required_hw_platform)}. Pods must run "
                f"under one of: {', '.join(allowed)}. Without a confidential runtime class "
                "the workload lands on an ordinary node, where the key broker will refuse "
                "to release anyway and the failure will look like a broker problem."
            ),
            "pattern": {"spec": {"runtimeClassName": " | ".join(allowed)}},
        },
    }


def _no_inspection_rule() -> dict[str, Any]:
    return {
        "name": "deny-process-inspection",
        "match": None,
        "validate": {
            "message": (
                "Privileged execution, host namespaces, shared process namespaces and "
                "process-tracing capabilities give an operator with software access the "
                "memory of a neighbouring container. WCM's guarantee against a software "
                "adversary does not survive them (THREAT-MODEL: operator with software "
                "access)."
            ),
            "foreach": [
                {
                    "list": "request.object.spec.containers",
                    "deny": {
                        "conditions": {
                            "any": [
                                {
                                    "key": "{{ element.securityContext.privileged || false }}",
                                    "operator": "Equals",
                                    "value": True,
                                },
                                {
                                    "key": (
                                        "{{ element.securityContext.capabilities.add[] "
                                        "|| `[]` }}"
                                    ),
                                    "operator": "AnyIn",
                                    "value": list(_FORBIDDEN_CAPABILITIES),
                                },
                            ]
                        }
                    },
                }
            ],
        },
    }


def _no_host_namespaces_rule() -> dict[str, Any]:
    return {
        "name": "deny-host-namespaces",
        "match": None,
        "validate": {
            "message": (
                "hostPID, hostIPC and shareProcessNamespace expose the protected "
                "workload's processes to the host or to a sidecar."
            ),
            "pattern": {
                "spec": {
                    "=(hostPID)": "false",
                    "=(hostIPC)": "false",
                    "=(hostNetwork)": "false",
                    "=(shareProcessNamespace)": "false",
                }
            },
        },
    }


def _digest_pinned_images_rule() -> dict[str, Any]:
    return {
        "name": "require-digest-pinned-images",
        "match": None,
        "validate": {
            "message": (
                "Images must be referenced by digest, not by tag. A tag resolves to "
                "different bytes over time, so a reviewed serving stack and a running "
                "one stop being the same thing without any change to the manifest."
            ),
            "pattern": {"spec": {"containers": [{"image": "*@sha256:*"}]}},
        },
    }


def _manifest_binding_rule(manifest_hash: str) -> dict[str, Any]:
    return {
        "name": "require-manifest-hash-annotation",
        "match": None,
        "validate": {
            "message": (
                f"Pods under this policy must carry {MANIFEST_HASH_ANNOTATION}: "
                f"{manifest_hash}. The value is the manifest's canonical hash, so a pod "
                "cannot be moved to different custody terms by editing a label."
            ),
            "pattern": {"metadata": {"annotations": {MANIFEST_HASH_ANNOTATION: manifest_hash}}},
        },
    }


def _gpu_rule(rim_pin: str) -> dict[str, Any]:
    return {
        "name": "require-confidential-gpu",
        "match": None,
        "validate": {
            "message": (
                "The manifest requires a GPU measurement "
                f"(rim_pin {rim_pin}), so the pod must request an NVIDIA GPU and be "
                "scheduled to a node labelled as running in confidential-compute mode. "
                "This checks the pod asks for the right hardware; whether that GPU's "
                "report matches the rim_pin is verified by the key broker."
            ),
            "pattern": {
                "spec": {
                    "containers": [{"resources": {"limits": {"nvidia.com/gpu": ">0"}}}],
                    "nodeSelector": {"nvidia.com/cc.mode": "on"},
                }
            },
        },
    }


def _dedicated_tenancy_rule() -> dict[str, Any]:
    return {
        "name": "require-dedicated-node",
        "match": None,
        "validate": {
            "message": (
                "The manifest sets tenancy: dedicated, so the pod must tolerate a "
                "dedicated-node taint and select a node reserved for it. Kyverno cannot "
                "observe what else is scheduled beside it, so this enforces the "
                "declaration, not the outcome; pair it with a NoSchedule taint on those "
                "nodes for the outcome to follow."
            ),
            "pattern": {"spec": {"nodeSelector": {"wcm.agentrust-io.com/tenancy": "dedicated"}}},
        },
    }


def build_policy(
    manifest: WeightCustodyManifest,
    *,
    name: str,
    selector: dict[str, str] | None = None,
    namespaces: list[str] | None = None,
    runtime_classes: dict[str, tuple[str, ...]] | None = None,
    validation_failure_action: str = "Enforce",
) -> dict[str, Any]:
    """Build a Kyverno ClusterPolicy from a manifest.

    ``selector`` is the label that marks a pod as governed by this manifest; it
    defaults to ``{"wcm.agentrust-io.com/governed": "true"}``. A policy that
    matched every pod in the cluster would be the wrong shape: most workloads are
    not serving custody-governed weights, and a rule that blocked them would be
    switched off within the day.

    ``validation_failure_action`` defaults to ``Enforce``. ``Audit`` exists so an
    operator can measure the blast radius before turning it on, and a policy left
    in Audit is a policy that enforces nothing, which the generated YAML says.
    """
    selector = selector or {"wcm.agentrust-io.com/governed": "true"}
    runtime_classes = runtime_classes or RUNTIME_CLASS_BY_PLATFORM
    if validation_failure_action not in {"Enforce", "Audit"}:
        raise ValueError("validation_failure_action must be 'Enforce' or 'Audit'")

    manifest_hash = canonical_hash(manifest.model_dump(mode="json", exclude_none=True))
    match = _match_block(namespaces, selector)

    rules: list[dict[str, Any]] = []
    runtime_rule = _runtime_class_rule(manifest, runtime_classes)
    if runtime_rule is not None:
        rules.append(runtime_rule)
    rules.append(_no_inspection_rule())
    rules.append(_no_host_namespaces_rule())
    rules.append(_digest_pinned_images_rule())
    rules.append(_manifest_binding_rule(manifest_hash))

    gpu = manifest.release_policy.required_gpu_measurement
    if gpu is not None:
        rules.append(_gpu_rule(gpu.rim_pin))
    if manifest.release_policy.tenancy is Tenancy.dedicated:
        rules.append(_dedicated_tenancy_rule())

    for rule in rules:
        rule["match"] = match

    return {
        "apiVersion": "kyverno.io/v1",
        "kind": "ClusterPolicy",
        "metadata": {
            "name": name,
            "annotations": {
                MANIFEST_HASH_ANNOTATION: manifest_hash,
                "wcm.agentrust-io.com/weights-hash": manifest.weights_hash,
                "wcm.agentrust-io.com/builder": manifest.builder.identity,
                "policies.kyverno.io/title": "Weight Custody Manifest preconditions",
                "policies.kyverno.io/subject": "Pod",
                "policies.kyverno.io/description": (
                    "Deployment preconditions implied by a WCM manifest. This policy "
                    "does not verify attestation; see the comment header."
                ),
            },
        },
        "spec": {"validationFailureAction": validation_failure_action, "rules": rules},
    }


def _yaml(value: Any, indent: int = 0) -> str:
    """Minimal YAML emitter for the policy shape, so PyYAML is not a dependency.

    Handles the mapping/sequence/scalar subset a ClusterPolicy uses. Strings are
    always quoted, which is verbose but sidesteps every YAML type-coercion trap
    ("on" becoming True, "1.10" becoming a float, a leading "*" starting an
    alias). A policy that changed meaning between generation and apply would be
    the worst possible bug in this file.
    """
    pad = " " * indent
    if isinstance(value, dict):
        if not value:
            return "{}"
        lines = []
        for key, item in value.items():
            rendered = _yaml(item, indent + 2)
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}{json.dumps(key)}:\n{rendered}")
            else:
                lines.append(f"{pad}{json.dumps(key)}: {rendered}")
        return "\n".join(lines)
    if isinstance(value, list):
        if not value:
            return "[]"
        lines = []
        for item in value:
            rendered = _yaml(item, indent + 2)
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}-\n{rendered}")
            else:
                lines.append(f"{pad}- {rendered}")
        return "\n".join(lines)
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value))


def render_yaml(policy: dict[str, Any]) -> str:
    """Render the policy with the enforcement boundary as a header comment."""
    header = [
        "# Generated from a Weight Custody Manifest. Do not hand-edit: regenerate.",
        "#",
        "# THIS POLICY DOES NOT VERIFY ATTESTATION. It enforces the deployment",
        "# preconditions a WCM manifest implies. Verifying that a workload is the",
        "# approved one requires a hardware quote, a nonce and a trust store, none",
        "# of which an admission controller has. That check is the key broker's, and",
        "# happens at key-release time.",
        "#",
        "# Not enforceable here:",
    ]
    for field, why in NOT_ENFORCEABLE_AT_ADMISSION.items():
        header.append(f"#   {field}")
        header.append(f"#     {why}")
    header.append("#")
    if policy["spec"]["validationFailureAction"] == "Audit":
        header.append("# validationFailureAction is Audit: this policy BLOCKS NOTHING.")
        header.append("#")
    return "\n".join(header) + "\n" + _yaml(policy) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="WCM manifest -> Kyverno ClusterPolicy")
    parser.add_argument("manifest", type=pathlib.Path)
    parser.add_argument("--name", required=True, help="ClusterPolicy metadata.name")
    parser.add_argument("--namespace", action="append", dest="namespaces")
    parser.add_argument(
        "--selector",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="pod label marking a governed workload; repeatable",
    )
    parser.add_argument("--audit", action="store_true", help="emit validationFailureAction: Audit")
    parser.add_argument(
        "--runtime-class",
        action="append",
        default=[],
        metavar="PLATFORM=CLASS",
        help="override the runtime class for a WCM platform; repeatable",
    )
    args = parser.parse_args(argv)

    selector = dict(item.split("=", 1) for item in args.selector) or None
    overrides: dict[str, tuple[str, ...]] = {}
    for item in args.runtime_class:
        platform, _, klass = item.partition("=")
        overrides.setdefault(platform, ())
        overrides[platform] = overrides[platform] + (klass,)

    manifest = WeightCustodyManifest.model_validate_json(
        args.manifest.read_text(encoding="utf-8")
    )
    policy = build_policy(
        manifest,
        name=args.name,
        selector=selector,
        namespaces=args.namespaces,
        runtime_classes={**RUNTIME_CLASS_BY_PLATFORM, **overrides} if overrides else None,
        validation_failure_action="Audit" if args.audit else "Enforce",
    )
    sys.stdout.write(render_yaml(policy))
    if manifest.release_policy.memory_fingerprint_challenge is (
        MemoryFingerprintChallenge.required_for_hostile_owner_posture
    ):
        print(
            "note: this manifest requires the memory-fingerprint challenge, a "
            "hostile-owner control that no cluster policy can provide. It is verified "
            "by the key broker against enclave-produced evidence.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
