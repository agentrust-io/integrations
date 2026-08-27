"""Tests for the WCM OpenTelemetry instrumentation.

No collector. The attribute builders are pure functions, so what would be
exported is assertable directly, which is also the only way to test the rule
that matters: key material never reaches a telemetry backend.
"""

from __future__ import annotations

import pathlib
import sys
from typing import Any

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from wcm import (  # noqa: E402
    CheckResult,
    CompositeEvidence,
    CpuQuote,
    EnclaveSession,
    GpuReport,
    ReleaseDecision,
    SessionState,
    WeightCustodyManifest,
)

from wcm_otel import (  # noqa: E402
    ATTRIBUTES,
    NEVER_EXPORTED,
    CustodyInstrumentation,
    custody_attributes,
    main,
    release_attributes,
)

SERVING = "sha256:" + "5e2d" * 16
WEIGHTS = "sha256:" + "4a1c" * 16


class FakeSpan:
    def __init__(self) -> None:
        self.attributes: dict[str, Any] = {}
        self.status: Any = None

    def set_attributes(self, values: dict[str, Any]) -> None:
        self.attributes.update(values)

    def set_status(self, status: Any) -> None:
        self.status = status

    def __enter__(self) -> "FakeSpan":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class FakeTracer:
    def __init__(self) -> None:
        self.spans: list[tuple[str, FakeSpan]] = []

    def start_as_current_span(self, name: str) -> FakeSpan:
        span = FakeSpan()
        self.spans.append((name, span))
        return span


class FakeInstrument:
    def __init__(self, name: str) -> None:
        self.name = name
        self.points: list[tuple[float, dict[str, Any]]] = []

    def add(self, value: float, attributes: dict[str, Any]) -> None:
        self.points.append((value, attributes))

    def record(self, value: float, attributes: dict[str, Any]) -> None:
        self.points.append((value, attributes))


class FakeMeter:
    def __init__(self) -> None:
        self.instruments: dict[str, FakeInstrument] = {}

    def _make(self, name: str, **_: Any) -> FakeInstrument:
        instrument = FakeInstrument(name)
        self.instruments[name] = instrument
        return instrument

    create_counter = _make
    create_histogram = _make


def make_manifest(**overrides: object) -> WeightCustodyManifest:
    document: dict = {
        "manifest_version": "0.1",
        "weights_hash": WEIGHTS,
        "builder": {"identity": "example-labs", "signing_key": "ed25519:builder-key"},
        "release_terms": {
            "license": "customer-deployment-agreement-ref:CDA-2026-0091",
            "permitted_derivatives": "fine-tune-only",
            "permitted_environments": ["attested-enclave"],
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
            "kbs_image": {"measurement": "sha256:" + "ab12" * 16, "signer": "ed25519:kbs"},
            "enclave_id": "did:example:enclave-04",
            "attestation_cadence": "24h",
        },
        "signatures": [],
    }
    document.update(overrides)
    return WeightCustodyManifest.model_validate(document)


def make_evidence(gpu: bool = False) -> CompositeEvidence:
    return CompositeEvidence(
        cpu=CpuQuote(
            platform="amd-sev-snp",
            assurance_tier="hardware-attested",
            serving_image_measurement=SERVING,
            nonce_echo="dGVzdC1ub25jZQ",
            attestation_key_id="vcek-0001",
            attestation_key_cache_age_seconds=42,
            quote_b64="c3VwZXItc2VjcmV0LXF1b3Rl",
        ),
        gpu=(
            GpuReport(platform="nvidia-cc-gpu", measurement="rim", nonce_echo="dGVzdC1ub25jZQ")
            if gpu
            else None
        ),
    )


def make_decision(released: bool = True, *, verified: bool = True, sealed: bool = False):
    checks = [
        CheckResult("nonce_fresh", True),
        CheckResult("serving_image", released),
        CheckResult("cpu_quote_verified", verified),
    ]
    return ReleaseDecision(
        released=released,
        key=b"k" * 32 if released and not sealed else None,
        sealed_key=b"s" * 48 if sealed else None,
        checks=checks,
    )


def test_every_emitted_attribute_is_documented() -> None:
    """An undocumented attribute in a dashboard is a field nobody can interpret."""
    attributes = release_attributes(make_manifest(), make_decision(False), make_evidence(gpu=True))

    assert set(attributes) <= set(ATTRIBUTES)


def test_no_key_material_or_raw_evidence_reaches_a_span() -> None:
    manifest, evidence = make_manifest(), make_evidence(gpu=True)
    tracer = FakeTracer()
    telemetry = CustodyInstrumentation(tracer=tracer, meter=FakeMeter())

    telemetry.record_release(manifest, make_decision(sealed=True), evidence)

    _, span = tracer.spans[0]
    exported = " ".join(f"{k}={v}" for k, v in span.attributes.items())
    assert "c3VwZXItc2VjcmV0LXF1b3Rl" not in exported, "the raw quote must not be exported"
    assert "dGVzdC1ub25jZQ" not in exported, "the nonce must not be exported"
    for banned in NEVER_EXPORTED:
        assert not any(key.lower().endswith(f".{banned}") for key in span.attributes)


def test_sealed_release_reports_the_fact_not_the_bytes() -> None:
    attributes = release_attributes(make_manifest(), make_decision(sealed=True), make_evidence())

    assert attributes["wcm.release.sealed"] is True
    assert "s" * 48 not in str(attributes)


def test_claimed_platform_and_verified_flag_are_both_exported() -> None:
    """A dashboard showing only the claim would present it as a fact."""
    attributes = release_attributes(
        make_manifest(), make_decision(verified=False), make_evidence()
    )

    assert attributes["wcm.evidence.cpu.platform"] == "amd-sev-snp"
    assert attributes["wcm.evidence.cpu.verified"] is False


def test_refusal_marks_the_span_as_an_error_with_the_check_names() -> None:
    pytest.importorskip("opentelemetry.trace")
    tracer = FakeTracer()
    telemetry = CustodyInstrumentation(tracer=tracer, meter=FakeMeter())

    telemetry.record_release(make_manifest(), make_decision(released=False), make_evidence())

    _, span = tracer.spans[0]
    assert span.status is not None
    assert "serving_image" in str(span.status.description)


def test_successful_release_leaves_the_span_unmarked() -> None:
    tracer = FakeTracer()
    CustodyInstrumentation(tracer=tracer, meter=FakeMeter()).record_release(
        make_manifest(), make_decision(), make_evidence()
    )

    assert tracer.spans[0][1].status is None


def test_failed_checks_are_listed_and_sorted() -> None:
    decision = ReleaseDecision(
        released=False,
        key=None,
        checks=[CheckResult("gpu", False), CheckResult("serving_image", False)],
    )

    attributes = release_attributes(make_manifest(), decision)

    assert attributes["wcm.release.failed_checks"] == ["gpu", "serving_image"]
    assert attributes["wcm.release.checks.failed"] == 2


def test_clean_release_omits_the_failed_check_list() -> None:
    assert "wcm.release.failed_checks" not in release_attributes(make_manifest(), make_decision())


def test_metrics_exclude_high_cardinality_hashes() -> None:
    """One time series per manifest revision is how a metrics backend dies."""
    meter = FakeMeter()
    CustodyInstrumentation(tracer=FakeTracer(), meter=meter).record_release(
        make_manifest(), make_decision(), make_evidence()
    )

    _, attributes = meter.instruments["wcm.release.decisions"].points[0]
    assert "wcm.manifest.hash" not in attributes
    assert "wcm.weights.hash" not in attributes
    assert attributes["wcm.release.released"] is True


def test_spans_do_carry_the_hashes() -> None:
    tracer = FakeTracer()
    CustodyInstrumentation(tracer=tracer, meter=FakeMeter()).record_release(
        make_manifest(), make_decision(), make_evidence()
    )

    assert tracer.spans[0][1].attributes["wcm.weights.hash"] == WEIGHTS


def test_duration_is_recorded_when_supplied() -> None:
    meter = FakeMeter()
    CustodyInstrumentation(tracer=FakeTracer(), meter=meter).record_release(
        make_manifest(), make_decision(), make_evidence(), duration_seconds=0.25
    )

    assert meter.instruments["wcm.release.duration"].points[0][0] == 0.25


def test_duration_is_omitted_when_not_measured() -> None:
    meter = FakeMeter()
    CustodyInstrumentation(tracer=FakeTracer(), meter=meter).record_release(
        make_manifest(), make_decision(), make_evidence()
    )

    assert meter.instruments["wcm.release.duration"].points == []


def test_holding_session_reports_its_lease() -> None:
    manifest = make_manifest()
    session = EnclaveSession(b"k" * 32, cadence_seconds=3600, max_operations=10)

    attributes = custody_attributes(manifest, session)

    assert attributes["wcm.custody.state"] == "holding"
    assert attributes["wcm.custody.operations_remaining"] == 10
    assert attributes["wcm.custody.trusted_time_source"] == "secure-tsc"
    assert all(
        isinstance(value, (str, int, float, bool)) for value in attributes.values()
    ), "a bound method reaching a span shows up in a dashboard as <bound method ...>"


def test_wipe_is_counted_and_marks_the_span() -> None:
    pytest.importorskip("opentelemetry.trace")
    manifest = make_manifest()
    session = EnclaveSession(b"k" * 32, cadence_seconds=3600)
    session.zeroize()
    tracer, meter = FakeTracer(), FakeMeter()

    CustodyInstrumentation(tracer=tracer, meter=meter).record_custody(manifest, session)

    assert tracer.spans[0][1].attributes["wcm.custody.state"] == SessionState.wiped.value
    assert tracer.spans[0][1].status is not None
    assert len(meter.instruments["wcm.custody.wipes"].points) == 1


def test_holding_session_is_not_counted_as_a_wipe() -> None:
    meter = FakeMeter()
    CustodyInstrumentation(tracer=FakeTracer(), meter=meter).record_custody(
        make_manifest(), EnclaveSession(b"k" * 32, cadence_seconds=3600)
    )

    assert meter.instruments["wcm.custody.wipes"].points == []


def test_observe_release_returns_the_decision_unchanged() -> None:
    """Telemetry that could alter a release decision would be a security control."""

    class StubBroker:
        def verify_and_release(self, manifest, evidence):  # noqa: ANN001
            return make_decision(released=False)

    decision = CustodyInstrumentation(tracer=FakeTracer(), meter=FakeMeter()).observe_release(
        StubBroker(), make_manifest(), make_evidence()
    )

    assert decision.released is False
    assert [c.name for c in decision.checks] == ["nonce_fresh", "serving_image", "cpu_quote_verified"]


def test_instrumentation_is_a_noop_without_otel_installed() -> None:
    telemetry = CustodyInstrumentation(tracer=None, meter=None)
    telemetry._tracer = None
    telemetry._meter = None
    telemetry._release_counter = None
    telemetry._release_duration = None

    assert telemetry.record_release(make_manifest(), make_decision(), make_evidence()).released


def test_sequence_attributes_are_stringified_for_otel() -> None:
    tracer = FakeTracer()
    CustodyInstrumentation(tracer=tracer, meter=FakeMeter()).record_release(
        make_manifest(), make_decision(released=False), make_evidence()
    )

    value = tracer.spans[0][1].attributes["wcm.release.failed_checks"]
    assert isinstance(value, tuple)
    assert all(isinstance(item, str) for item in value)


def test_cli_describes_the_attribute_reference(capsys) -> None:
    import io

    assert main([str(pathlib.Path(__file__)), "--describe"]) == 0
    assert "wcm.release.released" in capsys.readouterr().out
    assert io  # keep the import meaningful for linters


def test_cli_prints_manifest_attributes(tmp_path: pathlib.Path, capsys) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(make_manifest().model_dump_json(exclude_none=True), encoding="utf-8")

    assert main([str(path)]) == 0
    assert WEIGHTS in capsys.readouterr().out
