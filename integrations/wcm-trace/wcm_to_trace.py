#!/usr/bin/env python3
"""WCM release and custody decisions -> TRACE v0.2 Trust Records.

A Weight Custody Manifest key broker already decides, per release, whether an
enclave is entitled to a model key. It checks the manifest signatures, the
certificate chain, the serving-image measurement, the GPU measurement, the
channel binding, revocation state and freshness, and it fails closed. What it
has never done is hand anyone a portable artifact saying so.

That is what a TRACE Trust Record is for, and the two schemas line up almost
field for field, because both describe the same moment: a measured workload, a
policy that was in force, and a verdict.

**This is a first-party record.** The broker describes its own decision about
its own gate, so the record carries no ``origin`` block: absence means ``self``
and self is the truth. It deliberately does not use
``packages/agentrust-trace-adapters``, which exists to transcribe somebody
else's control plane and is forced to ``origin.kind: third-party-control-plane``
and ``runtime.platform: software-only``. Routing a broker's own decision through
it would label a first-party record as a third-party one, and would throw away
the hardware platform the broker actually verified.

**The assurance is derived, never asserted.** ``runtime.platform`` names
hardware only when the ``cpu_quote_verified`` check passed, which is to say only
when the broker cryptographically verified a quote against its trust store. A
broker fed ``SoftwareProvider`` evidence, or one where that check did not run,
produces a record that says ``software-only``. Nothing in this module lets a
caller overrule that; the honest platform falls out of ``ReleaseDecision``.

**A refusal is a record too.** ``build_release_record`` accepts a decision whose
``released`` is false and emits ``appraisal.status: contraindicated`` naming the
failed checks. A gate that produces evidence only when it says yes is not an
audit trail, and the refusals are the interesting half.

Usage::

    pip install weight-custody-manifest agentrust-trace

    from wcm_to_trace import build_release_record
    from agentrust_trace.sign import generate_key, sign_record

    decision = kbs.verify_and_release(manifest, evidence)
    record = build_release_record(
        manifest=manifest,
        decision=decision,
        evidence=evidence,
        data_class="restricted",
        model_provider="example-labs",
        model_id="example-8b-instruct",
    )
    signed = sign_record(record, generate_key())
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Iterable, Sequence

from wcm import (
    CheckResult,
    CompositeEvidence,
    ReleaseDecision,
    RuntimeEvent,
    RuntimeRecord,
    SessionState,
    WeightCustodyManifest,
    signing_pre_image,
    verify_runtime_record_chain,
)

__all__ = [
    "PLATFORM_MAP",
    "UNMAPPED_FIELDS",
    "TRACE_PROFILE",
    "MissingEvidence",
    "build_release_record",
    "build_custody_record",
    "build_custody_chain_record",
    "manifest_policy_bundle",
]

TRACE_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"

#: WCM platform identifier -> TRACE ``runtime.platform``.
#:
#: WCM emits exactly three platform strings (``wcm._hw_providers``):
#: ``amd-sev-snp``, ``intel-tdx`` and ``nvidia-cc-gpu``. Two of them are TRACE
#: values verbatim. The third is not, and is not silently coerced into one; see
#: UNMAPPED_FIELDS.
PLATFORM_MAP = {
    "amd-sev-snp": "amd-sev-snp",
    "intel-tdx": "intel-tdx",
}

#: Fields deliberately not carried across, and why. Read this before adding one.
UNMAPPED_FIELDS = {
    "GpuReport.platform": (
        "WCM says 'nvidia-cc-gpu'. TRACE's runtime.platform enumerates specific "
        "silicon ('nvidia-h100', 'nvidia-blackwell'), and WCM records no GPU "
        "model, so picking one would be a guess about which card ran. Whether "
        "the GPU chain verified is reported through the appraisal check list "
        "instead, where it is a fact rather than a hardware claim."
    ),
    "required_gpu_measurement.rim_pin": (
        "TRACE's runtime.rim_uri is format: uri and expects a vendor-published "
        "Reference Integrity Manifest. A rim_pin is an opaque golden-measurement "
        "identifier, not a resolvable URI. Emitting it as one would produce a "
        "record whose rim_uri no consumer can fetch."
    ),
    "release_terms.license": (
        "Licence and derivative terms are custody terms, not execution evidence. "
        "They are already bound into policy.bundle_hash by way of the manifest "
        "signing pre-image; repeating them as free text would put unverifiable "
        "prose into a record meant to be machine-checked."
    ),
    "MemoryFingerprint.readback_hash": (
        "A DRAM readback digest describes the host's memory, not the workload. "
        "TRACE has no field for it, and inventing one would leak a physical "
        "topology fingerprint into an artifact meant to be handed to third "
        "parties. Whether the sweep passed is in the check list."
    ),
}

#: Chain events meaning the runtime gave the key up.
_TERMINAL_EVENTS = frozenset(
    {
        RuntimeEvent.lapse_detected.value,
        RuntimeEvent.revocation_detected.value,
        RuntimeEvent.wipe_requested.value,
        RuntimeEvent.wipe_completed.value,
        RuntimeEvent.process_terminated.value,
    }
)

_SUBJECT_RE = re.compile(r"^(spiffe://[^/]+/.+|did:[a-z0-9]+:.+)$")
_DIGEST_RE = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")


class MissingEvidence(ValueError):
    """Raised rather than filling a required field with something invented."""


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def manifest_policy_bundle(manifest: WeightCustodyManifest) -> bytes:
    """The policy bundle bytes for a WCM release: the manifest signing pre-image.

    A WCM manifest *is* the policy the broker enforces, so ``policy.bundle_hash``
    should digest the manifest rather than something adjacent to it. The signing
    pre-image is the right slice: the RFC 8785 canonicalization of exactly the
    fields the builder and custodian signed. Two brokers enforcing the same terms
    therefore produce the same ``bundle_hash`` even when their manifest copies
    carry different signature sets or key ids.

    Digesting the whole document instead would change the hash every time another
    party countersigned, and a consumer comparing two records by ``bundle_hash``
    is entitled to assume equal hashes mean equal terms.
    """
    return signing_pre_image(manifest.model_dump(mode="json", exclude_none=True))


def _passed(checks: Iterable[CheckResult], name: str) -> bool:
    return any(check.name == name and check.passed for check in checks)


def _runtime_block(
    decision: ReleaseDecision, evidence: CompositeEvidence, policy_bundle: bytes
) -> dict[str, Any]:
    """Derive the runtime block from what the broker actually verified.

    Hardware is named only when ``cpu_quote_verified`` passed. That check is the
    broker's own cryptographic verification of the quote against its trust store
    (``KeyBrokerService._check_cpu_quote``), which is the one signal separating
    "an enclave sent a well-formed quote" from "we verified it".
    """
    platform = PLATFORM_MAP.get(evidence.cpu.platform)
    if platform is not None and _passed(decision.checks, "cpu_quote_verified"):
        block: dict[str, Any] = {
            "platform": platform,
            "measurement": evidence.cpu.serving_image_measurement,
        }
        if evidence.cpu.nonce_echo:
            block["nonce"] = evidence.cpu.nonce_echo
        return block

    # No verified hardware root, so the record must not name silicon. The
    # measurement is derived from inputs the operator holds and is labelled
    # software-only, so it can never be read as a hardware measurement. Same
    # construction the LangChain adapter and the agentrust-trace sandbox use.
    return {
        "platform": "software-only",
        "measurement": _digest(
            evidence.cpu.serving_image_measurement.encode()
            + b"\n"
            + _digest(policy_bundle).encode()
        ),
    }


def _appraisal(decision: ReleaseDecision) -> dict[str, Any]:
    """Appraisal status from the decision, with the failed checks named.

    Unlike a framework callback, a WCM broker genuinely appraises: it evaluates
    every check and withholds the key on failure. ``affirming`` is therefore
    honest here in a way it would not be for an observer. A refusal is
    ``contraindicated``, which is the value a consumer should act on.
    """
    failures = sorted(check.name for check in decision.failures)
    if not decision.released:
        status = "contraindicated"
    elif failures:
        # Released despite a failed check should be impossible. Report it rather
        # than smoothing it over: a broker in that state is misconfigured, and a
        # record that hid it would be the last place anyone would look.
        status = "warning"
    else:
        status = "affirming"
    appraisal: dict[str, Any] = {"status": status, "verifier": "wcm-key-broker"}
    if failures:
        appraisal["failed_checks"] = failures
    return appraisal


def build_release_record(
    *,
    manifest: WeightCustodyManifest,
    decision: ReleaseDecision,
    evidence: CompositeEvidence,
    data_class: str,
    model_provider: str,
    model_id: str,
    subject: str | None = None,
    model_version: str | None = None,
    workload_digest: str | None = None,
    slsa_level: int = 0,
    iat: int | None = None,
) -> dict[str, Any]:
    """Build a Trust Record describing one Layer 2 release decision.

    ``subject`` defaults to ``custody.enclave_id``, which WCM already requires in
    order to identify the enclave and which is conventionally a DID. It is only a
    default: a deployment whose enclave ids are neither DIDs nor SPIFFE URIs must
    pass the workload identity explicitly rather than have one invented for it.

    ``model_provider`` and ``model_id`` have no source in a WCM manifest, which
    binds a weights digest and a builder identity rather than a catalogue name,
    so both are required. ``model.weights_digest`` comes from the manifest and is
    the field that actually ties this record to those weights.
    """
    subject = subject or manifest.custody.enclave_id
    if not _SUBJECT_RE.match(subject or ""):
        raise MissingEvidence(
            f"subject {subject!r} must be a SPIFFE URI or a DID. custody.enclave_id "
            "is used by default, but this deployment's enclave id is neither, so "
            "pass subject= explicitly. Workload identity is not something an "
            "adapter may invent."
        )
    if not model_provider or not model_id:
        raise MissingEvidence(
            "model_provider and model_id are required. A WCM manifest binds a "
            "weights digest and a builder identity, not a model catalogue name, "
            "so there is nothing truthful to default them to."
        )
    if not _DIGEST_RE.match(manifest.weights_hash):
        raise MissingEvidence(
            f"weights_hash {manifest.weights_hash!r} is not a sha256:/sha384: digest. "
            "TRACE's model.weights_digest uses the same shape as WCM's weights_hash, "
            "so a manifest hashed with shake256 cannot populate it, and omitting the "
            "field would drop the one binding between this record and those weights."
        )

    workload_digest = workload_digest or evidence.cpu.serving_image_measurement
    if not _DIGEST_RE.match(workload_digest or ""):
        raise MissingEvidence(
            "build_provenance.digest must be a sha256:/sha384: digest of the workload "
            "that ran. The serving-image measurement is used by default; pass "
            "workload_digest= when the deployment builds a different artifact."
        )

    policy_bundle = manifest_policy_bundle(manifest)
    record: dict[str, Any] = {
        "eat_profile": TRACE_PROFILE,
        "iat": int(iat if iat is not None else time.time()),
        "subject": subject,
        "model": {
            "provider": model_provider,
            "model_id": model_id,
            "weights_digest": manifest.weights_hash,
        },
        "runtime": _runtime_block(decision, evidence, policy_bundle),
        "policy": {
            # The broker withholds the key when a check fails, which is what
            # enforce means. This is not the LangChain case: something did
            # evaluate the policy, so "declared" would understate the record.
            "bundle_hash": _digest(policy_bundle),
            "enforcement_mode": "enforce",
            "version": manifest.manifest_version,
        },
        "data_class": data_class,
        "build_provenance": {"slsa_level": slsa_level, "digest": workload_digest},
        "appraisal": _appraisal(decision),
    }
    if model_version is not None:
        record["model"]["version"] = model_version
    # transparency is omitted rather than empty: anchoring a manifest in the WCM
    # transparency log is a separate step, and "" is not a URI.
    return record


def build_custody_record(
    *,
    manifest: WeightCustodyManifest,
    state: SessionState,
    lease_deadline: str,
    operations_used: int,
    data_class: str,
    model_provider: str,
    model_id: str,
    workload_digest: str,
    subject: str | None = None,
    iat: int | None = None,
) -> dict[str, Any]:
    """Build a Trust Record describing Layer 3 runtime custody at a point in time.

    A release record says a key was handed over. This one says whether the
    runtime still holds it. ``SessionState.wiped`` produces ``contraindicated``:
    the session no longer has the key, so any inference attributed to it after
    this record did not use those weights.

    **This record is never hardware-attested.** A custody state is a fact about a
    software state machine, reported by that state machine. The broker verified a
    quote at release time; nothing re-verifies silicon on every lease tick, so
    ``runtime.platform`` is ``software-only`` here without exception. Reading a
    Layer 3 record as continued hardware attestation is exactly the mistake the
    field exists to prevent.

    ``build_custody_chain_record`` is the stronger path and should be preferred
    where the runtime signs: it reads a hash-chained receipt rather than the
    process's current opinion of itself. This one remains for a runtime with no
    signing key, which is a real deployment and not a degraded one; it simply
    proves less, and the appraisal says so by carrying no chain fields.
    """
    subject = subject or manifest.custody.enclave_id
    if not _SUBJECT_RE.match(subject or ""):
        raise MissingEvidence(
            f"subject {subject!r} must be a SPIFFE URI or a DID; pass subject= explicitly."
        )
    if not _DIGEST_RE.match(workload_digest or ""):
        raise MissingEvidence("workload_digest must be a sha256:/sha384: digest.")

    policy_bundle = manifest_policy_bundle(manifest)
    holding = state is SessionState.holding
    return {
        "eat_profile": TRACE_PROFILE,
        "iat": int(iat if iat is not None else time.time()),
        "subject": subject,
        "model": {
            "provider": model_provider,
            "model_id": model_id,
            "weights_digest": manifest.weights_hash,
        },
        "runtime": {
            "platform": "software-only",
            "measurement": _digest(
                workload_digest.encode() + b"\n" + _digest(policy_bundle).encode()
            ),
        },
        "policy": {
            "bundle_hash": _digest(policy_bundle),
            "enforcement_mode": "enforce",
            "version": manifest.manifest_version,
        },
        "data_class": data_class,
        "build_provenance": {"slsa_level": 0, "digest": workload_digest},
        "appraisal": {
            "status": "affirming" if holding else "contraindicated",
            "verifier": "wcm-custody-session",
            "custody_state": state.value,
            "lease_deadline": lease_deadline,
            "operations_used": operations_used,
        },
    }


def build_custody_chain_record(
    *,
    manifest: WeightCustodyManifest,
    records: Sequence[RuntimeRecord],
    runtime_public_key_b64url: str,
    data_class: str,
    model_provider: str,
    model_id: str,
    workload_digest: str,
    subject: str | None = None,
    require_terminal_sequence: bool = True,
    iat: int | None = None,
) -> dict[str, Any]:
    """Build a Trust Record from a signed, hash-chained custody receipt.

    This is the stronger of the two Layer 3 paths. ``build_custody_record`` reads
    a session's current state, which is whatever the process says about itself
    right now. This reads ``wcm.runtime_records``: an Ed25519-signed chain where
    each record commits to the previous one's hash, so a record cannot be removed
    from the middle without the chain failing to verify.

    **What the chain proves, exactly.** That the runtime holding that key said
    these things, in this order, and that nothing was excised. It does *not*
    prove the runtime was attested at each step. Attestation happened once, at
    release, and the broker verified it there. So ``runtime.platform`` is still
    ``software-only``: a signature from a key the runtime holds is not a hardware
    measurement, and treating it as one is the mistake that field exists to
    prevent.

    What does change is the appraisal. A verified chain lets this record say the
    custody account is complete and tamper-evident, which the state-based path
    cannot say at all.

    ``require_terminal_sequence`` defaults to True because the usual reason to
    build this record is that a lease ended and somebody wants the account of it.
    Pass False for a chain collected from a server still running, where the
    absence of a boundary is correct rather than suspicious.
    """
    if not records:
        raise MissingEvidence(
            "no runtime records. An empty chain is not a custody account, and a "
            "record built from one would assert an outcome nothing witnessed."
        )
    subject = subject or manifest.custody.enclave_id
    if not _SUBJECT_RE.match(subject or ""):
        raise MissingEvidence(
            f"subject {subject!r} must be a SPIFFE URI or a DID; pass subject= explicitly."
        )
    if not _DIGEST_RE.match(workload_digest or ""):
        raise MissingEvidence("workload_digest must be a sha256:/sha384: digest.")

    ordered = list(records)
    bound = {record.weights_hash for record in ordered}
    if bound != {manifest.weights_hash}:
        raise MissingEvidence(
            f"the chain binds {sorted(bound)} but this manifest binds "
            f"{manifest.weights_hash}. A record pairing one lease's receipts with "
            "another manifest would misattribute whatever the chain describes."
        )

    verified, reason = verify_runtime_record_chain(
        ordered,
        runtime_public_key_b64url,
        require_terminal_sequence=require_terminal_sequence,
    )
    events = [record.event for record in ordered]
    ended = _TERMINAL_EVENTS.intersection(events)

    policy_bundle = manifest_policy_bundle(manifest)
    appraisal: dict[str, Any] = {
        "verifier": "wcm-runtime-record-chain",
        "chain_verified": verified,
        "chain_length": len(ordered),
        "lease_id": ordered[0].lease_id,
        "final_event": events[-1],
    }
    if not verified:
        # An unverifiable chain is worse than no chain: it is an account that
        # does not hold together. Report the SDK's reason rather than a summary,
        # because "sequence is not contiguous" and "signature is invalid" send an
        # investigator to different places.
        appraisal["status"] = "contraindicated"
        appraisal["reason"] = reason
    elif ended:
        # The chain verified and it records the runtime giving the key up. That
        # is the gate working, and it is contraindicated for exactly the reason
        # a wiped session is: inference attributed afterwards did not use these
        # weights.
        appraisal["status"] = "contraindicated"
        appraisal["reason"] = reason
    else:
        appraisal["status"] = "affirming"
        appraisal["reason"] = reason

    return {
        "eat_profile": TRACE_PROFILE,
        "iat": int(iat if iat is not None else time.time()),
        "subject": subject,
        "model": {
            "provider": model_provider,
            "model_id": model_id,
            "weights_digest": manifest.weights_hash,
        },
        "runtime": {
            # Still software-only, and for the reason in the docstring. A signed
            # chain is a stronger account, not a hardware root of trust.
            "platform": "software-only",
            "measurement": _digest(
                workload_digest.encode() + b"\n" + _digest(policy_bundle).encode()
            ),
        },
        "policy": {
            "bundle_hash": _digest(policy_bundle),
            "enforcement_mode": "enforce",
            "version": manifest.manifest_version,
        },
        "data_class": data_class,
        "build_provenance": {"slsa_level": 0, "digest": workload_digest},
        "appraisal": appraisal,
    }


def decision_from_json(raw: dict[str, Any]) -> ReleaseDecision:
    """Rebuild a decision from a serialized check list.

    Only the fields this module reads are restored. The key material is not, on
    purpose: a released key has no business travelling through a JSON file on its
    way to an evidence generator.
    """
    return ReleaseDecision(
        released=bool(raw.get("released")),
        key=None,
        checks=[
            CheckResult(
                name=str(item["name"]),
                passed=bool(item["passed"]),
                detail=item.get("detail"),
            )
            for item in raw.get("checks", [])
        ],
    )


def main(argv: list[str] | None = None) -> int:
    """Print a release record for a manifest and a captured evidence bundle."""
    import argparse
    import pathlib

    parser = argparse.ArgumentParser(description="WCM release decision -> TRACE record")
    parser.add_argument("manifest", type=pathlib.Path)
    parser.add_argument("--evidence", type=pathlib.Path, required=True)
    parser.add_argument("--decision", type=pathlib.Path, required=True)
    parser.add_argument("--model-provider", required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--data-class", default="restricted")
    parser.add_argument("--subject")
    args = parser.parse_args(argv)

    manifest = WeightCustodyManifest.model_validate_json(
        args.manifest.read_text(encoding="utf-8")
    )
    evidence = CompositeEvidence.model_validate_json(
        args.evidence.read_text(encoding="utf-8")
    )
    record = build_release_record(
        manifest=manifest,
        decision=decision_from_json(json.loads(args.decision.read_text(encoding="utf-8"))),
        evidence=evidence,
        data_class=args.data_class,
        model_provider=args.model_provider,
        model_id=args.model_id,
        subject=args.subject,
    )
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
