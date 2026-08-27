"""Tests for the WCM -> Kyverno policy generator.

Two themes. First, the policy must never claim to verify attestation, because it
cannot. Second, the YAML it emits must mean in a cluster exactly what it meant
when generated, which is a quoting problem more than a policy one.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from wcm import WeightCustodyManifest, canonical_hash  # noqa: E402

from wcm_kyverno import (  # noqa: E402
    MANIFEST_HASH_ANNOTATION,
    NOT_ENFORCEABLE_AT_ADMISSION,
    RUNTIME_CLASS_BY_PLATFORM,
    build_policy,
    main,
    render_yaml,
)

SERVING = "sha256:" + "5e2d" * 16
WEIGHTS = "sha256:" + "4a1c" * 16


def make_manifest(**policy_overrides: object) -> WeightCustodyManifest:
    release_policy: dict = {
        "required_assurance_tier": "hardware-attested",
        "physical_hardening": "not-required",
        "trusted_time_source": "secure-tsc",
        "memory_fingerprint_challenge": "not-required",
        "required_hw_platform": ["amd-sev-snp"],
        "tenancy": "shared",
        "required_serving_image": {
            "signer": "ed25519:builder-key",
            "release_rule": "prefer-current",
            "accepted_measurements": [{"measurement": SERVING, "status": "current"}],
        },
        "key_release_mode": "attestation-gated",
        "replay_protection": "kbs-nonce-required",
        "revocation_authority": "builder-and-opaque-joint",
    }
    release_policy.update(policy_overrides)
    return WeightCustodyManifest.model_validate(
        {
            "manifest_version": "0.1",
            "weights_hash": WEIGHTS,
            "builder": {"identity": "example-labs", "signing_key": "ed25519:builder-key"},
            "release_terms": {
                "license": "customer-deployment-agreement-ref:CDA-2026-0091",
                "permitted_derivatives": "fine-tune-only",
                "permitted_environments": ["attested-enclave"],
            },
            "release_policy": release_policy,
            "custody": {
                "custodian": "example-custodian",
                "custodian_type": "opaque-hosted",
                "kbs_image": {"measurement": "sha256:" + "ab12" * 16, "signer": "ed25519:kbs"},
                "enclave_id": "did:example:enclave-04",
                "attestation_cadence": "24h",
            },
            "signatures": [],
        }
    )


def rule_names(policy: dict) -> list[str]:
    return [rule["name"] for rule in policy["spec"]["rules"]]


def test_serving_image_measurements_never_appear_in_the_policy() -> None:
    """The central correctness claim: launch measurements are not OCI digests.

    Emitting one as an allowed image digest would either block every pod or,
    worse, invite someone to "fix" the manifest by putting registry digests in
    the field the key broker compares against a quote.
    """
    rendered = render_yaml(build_policy(make_manifest(), name="p"))

    assert SERVING not in rendered
    assert "accepted_measurements" in "".join(NOT_ENFORCEABLE_AT_ADMISSION)


def test_header_states_the_boundary_in_the_cluster_not_only_in_the_source() -> None:
    rendered = render_yaml(build_policy(make_manifest(), name="p"))

    assert "DOES NOT VERIFY ATTESTATION" in rendered
    assert "key broker" in rendered


def test_platform_drives_the_runtime_class() -> None:
    policy = build_policy(make_manifest(required_hw_platform=["intel-tdx"]), name="p")

    rule = next(r for r in policy["spec"]["rules"] if r["name"] == "require-confidential-runtime-class")
    allowed = rule["validate"]["pattern"]["spec"]["runtimeClassName"]

    assert "kata-qemu-tdx" in allowed
    assert "kata-qemu-snp" not in allowed


def test_both_platforms_produce_both_classes_without_duplicates() -> None:
    policy = build_policy(
        make_manifest(required_hw_platform=["amd-sev-snp", "intel-tdx"]), name="p"
    )

    rule = next(r for r in policy["spec"]["rules"] if r["name"] == "require-confidential-runtime-class")
    allowed = rule["validate"]["pattern"]["spec"]["runtimeClassName"].split(" | ")

    assert allowed == list(dict.fromkeys(allowed)), "kata-cc is shared and must appear once"
    assert set(allowed) == {"kata-qemu-snp", "kata-cc", "kata-qemu-tdx"}


def test_runtime_class_order_follows_the_manifest_not_hash_order() -> None:
    policy = build_policy(
        make_manifest(required_hw_platform=["intel-tdx", "amd-sev-snp"]), name="p"
    )

    rule = next(r for r in policy["spec"]["rules"] if r["name"] == "require-confidential-runtime-class")

    assert rule["validate"]["pattern"]["spec"]["runtimeClassName"].startswith("kata-qemu-tdx")


def test_gpu_only_platform_emits_no_runtime_class_rule() -> None:
    """nvidia-cc-gpu is a device requirement, not a VM runtime class."""
    policy = build_policy(make_manifest(required_hw_platform=["nvidia-cc-gpu"]), name="p")

    assert "require-confidential-runtime-class" not in rule_names(policy)


def test_gpu_measurement_adds_a_device_rule_not_a_measurement_check() -> None:
    policy = build_policy(
        make_manifest(required_gpu_measurement={"rim_pin": "nvidia-rim:golden-01"}), name="p"
    )

    rule = next(r for r in policy["spec"]["rules"] if r["name"] == "require-confidential-gpu")

    assert rule["validate"]["pattern"]["spec"]["nodeSelector"] == {"nvidia.com/cc.mode": "on"}
    assert "verified by the key broker" in rule["validate"]["message"]


def test_dedicated_tenancy_adds_a_node_rule_and_says_what_it_cannot_see() -> None:
    policy = build_policy(make_manifest(tenancy="dedicated"), name="p")

    rule = next(r for r in policy["spec"]["rules"] if r["name"] == "require-dedicated-node")

    assert "cannot observe what else is scheduled" in rule["validate"]["message"]


def test_shared_tenancy_adds_no_node_rule() -> None:
    assert "require-dedicated-node" not in rule_names(build_policy(make_manifest(), name="p"))


def test_process_inspection_capabilities_are_denied() -> None:
    policy = build_policy(make_manifest(), name="p")

    rule = next(r for r in policy["spec"]["rules"] if r["name"] == "deny-process-inspection")
    conditions = rule["validate"]["foreach"][0]["deny"]["conditions"]["any"]
    forbidden = next(c for c in conditions if c["operator"] == "AnyIn")["value"]

    assert "SYS_PTRACE" in forbidden
    assert "SYS_ADMIN" in forbidden


def test_host_namespaces_are_denied() -> None:
    policy = build_policy(make_manifest(), name="p")

    rule = next(r for r in policy["spec"]["rules"] if r["name"] == "deny-host-namespaces")

    assert rule["validate"]["pattern"]["spec"]["=(shareProcessNamespace)"] == "false"


def test_images_must_be_digest_pinned() -> None:
    policy = build_policy(make_manifest(), name="p")

    rule = next(r for r in policy["spec"]["rules"] if r["name"] == "require-digest-pinned-images")

    assert rule["validate"]["pattern"]["spec"]["containers"][0]["image"] == "*@sha256:*"


def test_manifest_hash_binds_the_pod_to_these_exact_terms() -> None:
    manifest = make_manifest()
    expected = canonical_hash(manifest.model_dump(mode="json", exclude_none=True))

    policy = build_policy(manifest, name="p")
    rule = next(r for r in policy["spec"]["rules"] if r["name"] == "require-manifest-hash-annotation")

    assert rule["validate"]["pattern"]["metadata"]["annotations"][MANIFEST_HASH_ANNOTATION] == expected
    assert policy["metadata"]["annotations"][MANIFEST_HASH_ANNOTATION] == expected


def test_changing_any_signed_field_changes_the_bound_hash() -> None:
    one = build_policy(make_manifest(), name="p")
    two = build_policy(make_manifest(tenancy="dedicated"), name="p")

    assert (
        one["metadata"]["annotations"][MANIFEST_HASH_ANNOTATION]
        != two["metadata"]["annotations"][MANIFEST_HASH_ANNOTATION]
    )


def test_every_rule_carries_the_match_block() -> None:
    policy = build_policy(make_manifest(), name="p", namespaces=["serving"])

    for rule in policy["spec"]["rules"]:
        resource = rule["match"]["any"][0]["resources"]
        assert resource["namespaces"] == ["serving"]
        assert resource["selector"]["matchLabels"] == {"wcm.agentrust-io.com/governed": "true"}


def test_default_selector_does_not_match_the_whole_cluster() -> None:
    policy = build_policy(make_manifest(), name="p")

    assert policy["spec"]["rules"][0]["match"]["any"][0]["resources"]["selector"]["matchLabels"]


def test_audit_mode_says_it_blocks_nothing() -> None:
    rendered = render_yaml(
        build_policy(make_manifest(), name="p", validation_failure_action="Audit")
    )

    assert "BLOCKS NOTHING" in rendered


def test_enforce_mode_has_no_audit_warning() -> None:
    assert "BLOCKS NOTHING" not in render_yaml(build_policy(make_manifest(), name="p"))


def test_invalid_failure_action_is_refused() -> None:
    with pytest.raises(ValueError, match="Enforce"):
        build_policy(make_manifest(), name="p", validation_failure_action="whatever")


def test_yaml_quotes_scalars_so_types_cannot_drift() -> None:
    """'on' must stay a string, not become a boolean, between here and the cluster."""
    rendered = render_yaml(
        build_policy(make_manifest(required_gpu_measurement={"rim_pin": "r"}), name="p")
    )

    assert '"nvidia.com/cc.mode": "on"' in rendered
    assert '"nvidia.com/cc.mode": on' not in rendered


def test_yaml_quotes_glob_patterns_so_they_do_not_start_an_alias() -> None:
    rendered = render_yaml(build_policy(make_manifest(), name="p"))

    assert '"image": "*@sha256:*"' in rendered


def test_rendered_policy_parses_as_yaml_if_pyyaml_is_available() -> None:
    yaml = pytest.importorskip("yaml")
    manifest = make_manifest(
        tenancy="dedicated", required_gpu_measurement={"rim_pin": "nvidia-rim:golden-01"}
    )

    parsed = yaml.safe_load(render_yaml(build_policy(manifest, name="custody-example")))

    assert parsed["kind"] == "ClusterPolicy"
    assert parsed["apiVersion"] == "kyverno.io/v1"
    assert parsed["metadata"]["name"] == "custody-example"
    assert parsed["spec"]["validationFailureAction"] == "Enforce"
    assert len(parsed["spec"]["rules"]) == len(rule_names(build_policy(manifest, name="p")))
    gpu = next(r for r in parsed["spec"]["rules"] if r["name"] == "require-confidential-gpu")
    assert gpu["validate"]["pattern"]["spec"]["nodeSelector"]["nvidia.com/cc.mode"] == "on"


def test_cli_writes_a_policy_and_warns_about_the_memory_challenge(
    tmp_path: pathlib.Path, capsys
) -> None:
    manifest = make_manifest(memory_fingerprint_challenge="required-for-hostile-owner-posture")
    path = tmp_path / "manifest.json"
    path.write_text(manifest.model_dump_json(exclude_none=True), encoding="utf-8")

    assert main([str(path), "--name", "custody-example"]) == 0

    captured = capsys.readouterr()
    assert "kind: " not in captured.err
    assert "ClusterPolicy" in captured.out
    assert "no cluster policy can provide" in captured.err


def test_cli_runtime_class_override(tmp_path: pathlib.Path, capsys) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(make_manifest().model_dump_json(exclude_none=True), encoding="utf-8")

    assert main([str(path), "--name", "p", "--runtime-class", "amd-sev-snp=my-cc-class"]) == 0

    assert "my-cc-class" in capsys.readouterr().out


def test_runtime_class_defaults_are_the_confidential_containers_names() -> None:
    assert RUNTIME_CLASS_BY_PLATFORM["amd-sev-snp"][0] == "kata-qemu-snp"
    assert "nvidia-cc-gpu" not in RUNTIME_CLASS_BY_PLATFORM
