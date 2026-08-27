"""Tests for the WCM -> TRACE adapter.

The point of most of these is the same: a record must not claim more than the
release decision supports. Anything that lets ``runtime.platform`` name silicon
without a verified quote, or ``appraisal.status`` say ``affirming`` over a
refusal, is the failure this adapter exists to prevent.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from wcm import (
    CheckResult,
    CompositeEvidence,
    CpuQuote,
    GpuReport,
    ReleaseDecision,
    RuntimeEvent,
    SessionState,
    WeightCustodyManifest,
    canonical_hash,
    generate_ed25519,
    runtime_public_key,
    sign_runtime_record,
)

from wcm_to_trace import (  # noqa: E402
    PLATFORM_MAP,
    UNMAPPED_FIELDS,
    MissingEvidence,
    build_custody_chain_record,
    build_custody_record,
    build_release_record,
    decision_from_json,
    manifest_policy_bundle,
)

SERVING = "sha256:" + "5e2d" * 16
WEIGHTS = "sha256:" + "4a1c" * 16
GPU_RIM = "nvidia-rim:golden-measurement-01"


def make_manifest(**overrides: object) -> WeightCustodyManifest:
    document: dict[str, object] = {
        "manifest_version": "0.1",
        "weights_hash": WEIGHTS,
        "builder": {"identity": "example-labs", "signing_key": "ed25519:builder-key"},
        "release_terms": {
            "license": "customer-deployment-agreement-ref:CDA-2026-0091",
            "permitted_derivatives": "fine-tune-only, no re-export of base weights",
            "permitted_environments": ["attested-enclave"],
            "jurisdiction_restriction": "US, EU",
        },
        "release_policy": {
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
        },
        "custody": {
            "custodian": "example-custodian",
            "custodian_type": "opaque-hosted",
            "kbs_image": {"measurement": "sha256:" + "ab12" * 16, "signer": "ed25519:kbs-key"},
            "enclave_id": "did:example:enclave-04",
            "attestation_cadence": "24h",
        },
        "signatures": [],
    }
    document.update(overrides)
    return WeightCustodyManifest.model_validate(document)


def make_evidence(platform: str = "amd-sev-snp", *, gpu: bool = False) -> CompositeEvidence:
    return CompositeEvidence(
        cpu=CpuQuote(
            platform=platform,
            assurance_tier="hardware-attested",
            serving_image_measurement=SERVING,
            nonce_echo="dGVzdC1ub25jZQ",
            attestation_key_id="vcek-0001",
        ),
        gpu=(
            GpuReport(platform="nvidia-cc-gpu", measurement=GPU_RIM, nonce_echo="dGVzdC1ub25jZQ")
            if gpu
            else None
        ),
    )


def decision(released: bool = True, *, verified_quote: bool = True, extra=()) -> ReleaseDecision:
    checks = [CheckResult("nonce_fresh", True), CheckResult("serving_image", True)]
    checks.append(CheckResult("cpu_quote_verified", verified_quote))
    checks.extend(extra)
    return ReleaseDecision(released=released, key=b"k" * 32 if released else None, checks=checks)


def record(**kwargs: object) -> dict:
    base = dict(
        manifest=make_manifest(),
        decision=decision(),
        evidence=make_evidence(),
        data_class="restricted",
        model_provider="example-labs",
        model_id="example-8b-instruct",
    )
    base.update(kwargs)
    return build_release_record(**base)  # type: ignore[arg-type]


def test_verified_quote_names_the_hardware_platform() -> None:
    value = record()

    assert value["runtime"]["platform"] == "amd-sev-snp"
    assert value["runtime"]["measurement"] == SERVING
    assert value["runtime"]["nonce"] == "dGVzdC1ub25jZQ"


def test_unverified_quote_is_software_only_even_on_real_silicon() -> None:
    """The platform string in the evidence is a claim; the check is the fact.

    An enclave can put "amd-sev-snp" in a quote it made up. Only
    cpu_quote_verified says the broker checked it against a trust store, so that
    check, not the claimed platform, decides whether the record names hardware.
    """
    value = record(decision=decision(verified_quote=False))

    assert value["runtime"]["platform"] == "software-only"
    assert value["runtime"]["measurement"] != SERVING
    assert "nonce" not in value["runtime"]


def test_unmappable_platform_is_software_only_not_a_guess() -> None:
    value = record(evidence=make_evidence(platform="some-future-tee"))

    assert value["runtime"]["platform"] == "software-only"


def test_gpu_platform_never_reaches_runtime() -> None:
    """nvidia-cc-gpu has no TRACE equivalent and must not become one."""
    value = record(evidence=make_evidence(gpu=True))

    assert value["runtime"]["platform"] == "amd-sev-snp"
    assert "nvidia-cc-gpu" not in json.dumps(value)
    assert "GpuReport.platform" in UNMAPPED_FIELDS


def test_platform_map_covers_only_what_trace_enumerates() -> None:
    trace_platforms = {
        "intel-tdx",
        "amd-sev-snp",
        "azure-cvm-sev-snp",
        "nvidia-h100",
        "nvidia-blackwell",
        "aws-nitro",
        "arm-cca",
        "google-confidential-space",
        "tpm2",
        "software-only",
    }

    assert set(PLATFORM_MAP.values()) <= trace_platforms


def test_refusal_is_contraindicated_and_names_the_failed_checks() -> None:
    failed = decision(
        released=False,
        extra=[CheckResult("serving_image", False, "revoked"), CheckResult("gpu", False)],
    )

    value = record(decision=failed)

    assert value["appraisal"]["status"] == "contraindicated"
    assert value["appraisal"]["failed_checks"] == ["gpu", "serving_image"]


def test_release_with_a_failed_check_is_reported_as_a_warning() -> None:
    """A broker that released anyway is misconfigured; the record says so."""
    odd = decision(released=True, extra=[CheckResult("gpu", False)])

    assert record(decision=odd)["appraisal"]["status"] == "warning"


def test_clean_release_is_affirming_with_no_failed_check_list() -> None:
    value = record()

    assert value["appraisal"] == {"status": "affirming", "verifier": "wcm-key-broker"}


def test_weights_hash_binds_the_record_to_the_manifest() -> None:
    assert record()["model"]["weights_digest"] == WEIGHTS


def test_policy_bundle_is_stable_across_added_signatures() -> None:
    """Two brokers enforcing the same terms must agree on bundle_hash.

    The signing pre-image covers only the signed fields, so countersigning does
    not move the hash. Digesting the whole document would, and would break the
    one comparison a consumer is entitled to make.
    """
    unsigned = make_manifest()
    countersigned = make_manifest(
        signatures=[
            {
                "role": "builder",
                "signer": "example-labs",
                "algorithm": "Ed25519",
                "key_id": "k1",
                "signature_value": "AA",
            }
        ]
    )

    assert manifest_policy_bundle(unsigned) == manifest_policy_bundle(countersigned)


def test_policy_bundle_moves_when_the_terms_move() -> None:
    original = make_manifest()
    relaxed = make_manifest()
    relaxed.release_terms.permitted_environments = ["anywhere"]

    assert manifest_policy_bundle(original) != manifest_policy_bundle(relaxed)


def test_enforcement_mode_is_enforce_because_the_broker_gates() -> None:
    """Not "declared": the broker evaluated the policy and withheld the key."""
    assert record()["policy"]["enforcement_mode"] == "enforce"


def test_subject_defaults_to_the_enclave_id() -> None:
    assert record()["subject"] == "did:example:enclave-04"


def test_non_did_enclave_id_is_refused_rather_than_coerced() -> None:
    manifest = make_manifest()
    manifest.custody.enclave_id = "enclave-04"

    with pytest.raises(MissingEvidence, match="SPIFFE URI or a DID"):
        record(manifest=manifest)

    assert record(manifest=manifest, subject="spiffe://example.org/enclave/04")["subject"] == (
        "spiffe://example.org/enclave/04"
    )


def test_model_identity_has_no_source_in_a_manifest_and_is_required() -> None:
    with pytest.raises(MissingEvidence, match="model catalogue name"):
        record(model_id="")


def test_non_sha_weights_hash_is_refused() -> None:
    manifest = make_manifest(weights_hash="shake256:" + "ab" * 32)

    with pytest.raises(MissingEvidence, match="weights_digest"):
        record(manifest=manifest)


def test_workload_digest_defaults_to_the_serving_image_measurement() -> None:
    assert record()["build_provenance"]["digest"] == SERVING


def test_transparency_is_absent_rather_than_empty() -> None:
    assert "transparency" not in record()


def test_no_origin_block_because_the_broker_is_first_party() -> None:
    assert "origin" not in record()


def test_custody_record_is_always_software_only() -> None:
    """Layer 3 is a software state machine reporting on itself."""
    value = build_custody_record(
        manifest=make_manifest(),
        state=SessionState.holding,
        lease_deadline="2026-08-26T12:00:00Z",
        operations_used=17,
        data_class="restricted",
        model_provider="example-labs",
        model_id="example-8b-instruct",
        workload_digest=SERVING,
    )

    assert value["runtime"]["platform"] == "software-only"
    assert value["appraisal"]["status"] == "affirming"
    assert value["appraisal"]["custody_state"] == "holding"


def test_wiped_session_is_contraindicated() -> None:
    value = build_custody_record(
        manifest=make_manifest(),
        state=SessionState.wiped,
        lease_deadline="2026-08-26T12:00:00Z",
        operations_used=17,
        data_class="restricted",
        model_provider="example-labs",
        model_id="example-8b-instruct",
        workload_digest=SERVING,
    )

    assert value["appraisal"]["status"] == "contraindicated"
    assert value["appraisal"]["custody_state"] == "wiped"


def test_decision_from_json_never_carries_key_material() -> None:
    rebuilt = decision_from_json(
        {"released": True, "key": "c2VjcmV0", "checks": [{"name": "nonce_fresh", "passed": True}]}
    )

    assert rebuilt.key is None
    assert rebuilt.released is True


def test_record_matches_the_shapes_the_trace_schema_requires() -> None:
    """A structural check against the v0.2 required fields and patterns.

    The full schema lives in trace-spec and is fetched by CI elsewhere; this
    keeps the adapter honest about the fields it is responsible for.
    """
    value = record()
    digest = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")

    for field in ("eat_profile", "iat", "subject", "model", "runtime", "policy",
                  "data_class", "build_provenance", "appraisal"):
        assert field in value, field
    assert digest.match(value["runtime"]["measurement"])
    assert digest.match(value["policy"]["bundle_hash"])
    assert digest.match(value["build_provenance"]["digest"])
    assert digest.match(value["model"]["weights_digest"])
    assert value["appraisal"]["status"] in {"affirming", "warning", "contraindicated", "none"}
    assert isinstance(value["iat"], int)


# --------------------------------------------------------------------------
# Chain-backed Layer 3 records (weight-custody-manifest 0.27.0)
# --------------------------------------------------------------------------


def chain(*, terminal: bool = True, renewals: int = 0):
    """A signed chain plus the public key a verifier holds."""
    keypair = generate_ed25519()
    public = runtime_public_key(keypair.private_key)
    manifest = make_manifest()
    manifest_hash = canonical_hash(manifest.model_dump(mode="json", exclude_none=True))

    records: list = []

    def append(event, **detail):
        records.append(
            sign_runtime_record(
                signing_key=keypair.private_key,
                sequence=len(records),
                event=event,
                occurred_at="2026-08-27T00:00:0%dZ" % min(len(records), 9),
                weights_hash=WEIGHTS,
                manifest_hash=manifest_hash,
                lease_id="lease-0001",
                previous=records[-1] if records else None,
                detail=detail or None,
            )
        )

    append(RuntimeEvent.lease_started)
    for _ in range(renewals):
        append(RuntimeEvent.renewal_succeeded)
    if terminal:
        append(RuntimeEvent.lapse_detected)
        append(RuntimeEvent.wipe_requested)
        append(RuntimeEvent.wipe_completed)
        append(RuntimeEvent.process_terminated)
    return manifest, records, public


def chain_record(**kwargs):
    manifest, records, public = kwargs.pop("built", chain())
    base = dict(
        manifest=manifest,
        records=records,
        runtime_public_key_b64url=public,
        data_class="restricted",
        model_provider="example-labs",
        model_id="example-8b-instruct",
        workload_digest=SERVING,
    )
    base.update(kwargs)
    return build_custody_chain_record(**base)


def test_verified_terminal_chain_is_contraindicated_because_the_key_is_gone() -> None:
    value = chain_record()

    assert value["appraisal"]["chain_verified"] is True
    assert value["appraisal"]["status"] == "contraindicated"
    assert value["appraisal"]["final_event"] == RuntimeEvent.process_terminated.value


def test_verified_live_chain_is_affirming() -> None:
    value = chain_record(built=chain(terminal=False, renewals=2), require_terminal_sequence=False)

    assert value["appraisal"]["chain_verified"] is True
    assert value["appraisal"]["status"] == "affirming"
    assert value["appraisal"]["chain_length"] == 3


def test_a_chain_record_is_still_software_only() -> None:
    """A signature from a key the runtime holds is not a hardware measurement."""
    value = chain_record()

    assert value["runtime"]["platform"] == "software-only"


def test_broken_chain_is_contraindicated_with_the_sdk_reason() -> None:
    """"sequence is not contiguous" and "signature invalid" go to different places."""
    manifest, records, public = chain()
    tampered = [records[0], *records[2:]]

    value = chain_record(built=(manifest, tampered, public), require_terminal_sequence=False)

    assert value["appraisal"]["chain_verified"] is False
    assert value["appraisal"]["status"] == "contraindicated"
    assert "contiguous" in value["appraisal"]["reason"]


def test_wrong_key_cannot_produce_an_affirming_record() -> None:
    manifest, records, _ = chain(terminal=False)
    other = runtime_public_key(generate_ed25519().private_key)

    value = chain_record(
        built=(manifest, records, other), require_terminal_sequence=False
    )

    assert value["appraisal"]["chain_verified"] is False
    assert value["appraisal"]["status"] == "contraindicated"


def test_partial_chain_fails_when_a_terminal_one_was_required() -> None:
    value = chain_record(built=chain(terminal=False))

    assert value["appraisal"]["chain_verified"] is False
    assert value["appraisal"]["status"] == "contraindicated"


def test_chain_from_another_manifest_is_refused() -> None:
    """Pairing one lease's receipts with another manifest would misattribute it."""
    manifest, records, public = chain()
    other = make_manifest(weights_hash="sha256:" + "9f0b" * 16)

    with pytest.raises(MissingEvidence, match="misattribute"):
        chain_record(built=(other, records, public))


def test_empty_chain_is_refused() -> None:
    manifest, _, public = chain()

    with pytest.raises(MissingEvidence, match="nothing witnessed"):
        chain_record(built=(manifest, [], public))


def test_lease_id_reaches_the_record() -> None:
    assert chain_record()["appraisal"]["lease_id"] == "lease-0001"


def test_chain_record_carries_the_same_bindings_as_the_release_record() -> None:
    value = chain_record()

    assert value["model"]["weights_digest"] == WEIGHTS
    assert value["policy"]["enforcement_mode"] == "enforce"
    assert value["policy"]["bundle_hash"] == _release_bundle_hash()
    assert "origin" not in value


def _release_bundle_hash() -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(manifest_policy_bundle(make_manifest())).hexdigest()


def test_state_based_record_carries_no_chain_fields() -> None:
    """The weaker path must not look like the stronger one."""
    value = build_custody_record(
        manifest=make_manifest(),
        state=SessionState.holding,
        lease_deadline="2026-08-27T12:00:00Z",
        operations_used=3,
        data_class="restricted",
        model_provider="example-labs",
        model_id="example-8b-instruct",
        workload_digest=SERVING,
    )

    assert "chain_verified" not in value["appraisal"]
    assert value["appraisal"]["verifier"] == "wcm-custody-session"


def test_chain_record_names_a_different_verifier() -> None:
    assert chain_record()["appraisal"]["verifier"] == "wcm-runtime-record-chain"
