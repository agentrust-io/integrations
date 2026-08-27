"""Tests for the NVIDIA GPU attestation adapter.

Every refusal path gets a case, because the failure mode that matters is
emitting a GpuReport for a GPU whose firmware did not actually match NVIDIA's
published reference measurements.
"""

from __future__ import annotations

import base64
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from wcm_nvidia import (  # noqa: E402
    CERT_CHAIN_CLAIMS,
    GPU_PLATFORM,
    REQUIRED_TRUE_CLAIMS,
    NvidiaAttestationError,
    adapt,
    main,
    rim_pin,
)

NONCE = "ab" * 32
OTHER_NONCE = "cd" * 32
CERT_PEM = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"


def cert_claim(**overrides: object) -> dict:
    value = {
        "x-nvidia-cert-ocsp-nonce-matches": True,
        "x-nvidia-cert-ocsp-response-valid": True,
        "x-nvidia-cert-status": "valid",
        "x-nvidia-cert-ocsp-status": "good",
    }
    value.update(overrides)
    return value


def jwt(payload: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJFUzM4NCJ9.{body}.c2ln"


def gpu_claims(**overrides: object) -> dict:
    claims: dict = {name: True for name in REQUIRED_TRUE_CLAIMS}
    claims["eat_nonce"] = NONCE
    claims["x-nvidia-gpu-driver-version"] = "580.65.06"
    claims["x-nvidia-gpu-vbios-version"] = "96.00.9F.00.01"
    for name in CERT_CHAIN_CLAIMS:
        claims[name] = cert_claim()
    claims.update(overrides)
    return claims


def appraisal_doc(*, overall: bool = True, result_code: int = 0, **claim_overrides: object) -> dict:
    return {
        "result_code": result_code,
        "detached_eat": [
            ["JWT", jwt({"x-nvidia-overall-att-result": overall})],
            {"GPU-0": jwt(gpu_claims(**claim_overrides))},
        ],
    }


def evidence_doc(*, nonce: str = NONCE, result_code: int = 0, count: int = 1) -> dict:
    item = {
        "arch": "HOPPER",
        "nonce": nonce,
        "certificate": base64.b64encode(CERT_PEM.encode()).decode(),
        "evidence": base64.b64encode(b"raw-attestation-report").decode(),
    }
    return {"result_code": result_code, "evidences": [dict(item) for _ in range(count)]}


def test_appraised_gpu_produces_a_report() -> None:
    report = adapt(evidence_doc(), appraisal_doc(), NONCE)

    assert report.platform == GPU_PLATFORM
    assert report.cc_mode is True
    assert report.nonce_echo == NONCE
    assert report.measurement == "nvidia-rim:arch=HOPPER;driver=580.65.06;vbios=96.00.9F.00.01"


def test_raw_report_and_chain_survive_for_wcm_to_verify_independently() -> None:
    """Without these, the record rests on this process having parsed a JWT."""
    report = adapt(evidence_doc(), appraisal_doc(), NONCE)

    container = json.loads(base64.b64decode(report.quote_b64))
    assert base64.b64decode(container["report_b64"]) == b"raw-attestation-report"
    assert container["cert_chain_pem"] == CERT_PEM


def test_collector_nonce_mismatch_is_refused() -> None:
    with pytest.raises(NvidiaAttestationError, match="collected evidence nonce"):
        adapt(evidence_doc(nonce=OTHER_NONCE), appraisal_doc(), NONCE)


def test_appraisal_nonce_mismatch_is_refused() -> None:
    with pytest.raises(NvidiaAttestationError, match="appraisal nonce"):
        adapt(evidence_doc(), appraisal_doc(eat_nonce=OTHER_NONCE), NONCE)


def test_both_nonces_are_checked_independently() -> None:
    """One document agreeing is not enough; replay needs only the weaker check."""
    with pytest.raises(NvidiaAttestationError):
        adapt(evidence_doc(nonce=OTHER_NONCE), appraisal_doc(eat_nonce=OTHER_NONCE), NONCE)


@pytest.mark.parametrize("claim", REQUIRED_TRUE_CLAIMS)
def test_each_required_claim_being_false_is_a_refusal(claim: str) -> None:
    with pytest.raises(NvidiaAttestationError, match=claim):
        adapt(evidence_doc(), appraisal_doc(**{claim: False}), NONCE)


@pytest.mark.parametrize("claim", REQUIRED_TRUE_CLAIMS)
def test_each_required_claim_being_absent_is_a_refusal(claim: str) -> None:
    document = appraisal_doc()
    claims = gpu_claims()
    del claims[claim]
    document["detached_eat"][1]["GPU-0"] = jwt(claims)

    with pytest.raises(NvidiaAttestationError, match=claim):
        adapt(evidence_doc(), document, NONCE)


def test_truthy_but_not_true_is_refused() -> None:
    """A claim of "yes" or 1 is not True, and must not be read as one."""
    with pytest.raises(NvidiaAttestationError, match="secboot"):
        adapt(evidence_doc(), appraisal_doc(secboot=1), NONCE)


def test_overall_result_false_is_refused() -> None:
    with pytest.raises(NvidiaAttestationError, match="overall attestation result"):
        adapt(evidence_doc(), appraisal_doc(overall=False), NONCE)


def test_nonzero_appraisal_result_code_is_refused() -> None:
    with pytest.raises(NvidiaAttestationError, match="appraisal failed"):
        adapt(evidence_doc(), appraisal_doc(result_code=3), NONCE)


def test_nonzero_collection_result_code_is_refused() -> None:
    with pytest.raises(NvidiaAttestationError, match="evidence collection failed"):
        adapt(evidence_doc(result_code=1), appraisal_doc(), NONCE)


def test_mismatched_measurement_records_are_refused() -> None:
    document = appraisal_doc(**{"x-nvidia-mismatch-measurement-records": ["driver"]})

    with pytest.raises(NvidiaAttestationError, match="mismatched measurement records"):
        adapt(evidence_doc(), document, NONCE)


@pytest.mark.parametrize("claim", CERT_CHAIN_CLAIMS)
def test_revoked_certificate_is_refused(claim: str) -> None:
    """A revoked certificate still presents a well-formed chain."""
    document = appraisal_doc(**{claim: cert_claim(**{"x-nvidia-cert-ocsp-status": "revoked"})})

    with pytest.raises(NvidiaAttestationError, match="OCSP status is not good"):
        adapt(evidence_doc(), document, NONCE)


@pytest.mark.parametrize("claim", CERT_CHAIN_CLAIMS)
def test_stale_ocsp_response_is_refused(claim: str) -> None:
    document = appraisal_doc(**{claim: cert_claim(**{"x-nvidia-cert-ocsp-nonce-matches": False})})

    with pytest.raises(NvidiaAttestationError, match="ocsp-nonce-matches"):
        adapt(evidence_doc(), document, NONCE)


@pytest.mark.parametrize("claim", CERT_CHAIN_CLAIMS)
def test_missing_certificate_claim_is_refused(claim: str) -> None:
    document = appraisal_doc(**{claim: None})

    with pytest.raises(NvidiaAttestationError, match="missing"):
        adapt(evidence_doc(), document, NONCE)


def test_multi_gpu_evidence_is_refused_rather_than_silently_narrowed() -> None:
    with pytest.raises(NvidiaAttestationError, match="exactly one GPU evidence item"):
        adapt(evidence_doc(count=2), appraisal_doc(), NONCE)


def test_zero_gpu_evidence_is_refused() -> None:
    with pytest.raises(NvidiaAttestationError, match="exactly one GPU evidence item"):
        adapt({"result_code": 0, "evidences": []}, appraisal_doc(), NONCE)


def test_malformed_raw_evidence_is_refused() -> None:
    document = evidence_doc()
    document["evidences"][0]["certificate"] = "not base64!!"

    with pytest.raises(NvidiaAttestationError, match="malformed"):
        adapt(document, appraisal_doc(), NONCE)


def test_unparseable_token_is_refused() -> None:
    document = appraisal_doc()
    document["detached_eat"][1]["GPU-0"] = "not.a.jwt"

    with pytest.raises(NvidiaAttestationError, match="unparseable"):
        adapt(evidence_doc(), document, NONCE)


def test_missing_gpu0_claims_are_refused() -> None:
    document = appraisal_doc()
    document["detached_eat"][1] = {"GPU-1": document["detached_eat"][1]["GPU-0"]}

    with pytest.raises(NvidiaAttestationError, match="GPU-0"):
        adapt(evidence_doc(), document, NONCE)


def test_missing_firmware_identity_is_refused() -> None:
    with pytest.raises(NvidiaAttestationError, match="arch, driver or VBIOS"):
        adapt(evidence_doc(), appraisal_doc(**{"x-nvidia-gpu-driver-version": ""}), NONCE)


def test_rim_pin_rejects_separator_characters() -> None:
    """A version containing ';' would produce a pin that parses back differently."""
    with pytest.raises(NvidiaAttestationError, match="no ';' or '='"):
        rim_pin(arch="HOPPER", driver_version="580;06", vbios_version="96.00")


def test_rim_pin_is_the_one_place_the_format_is_defined() -> None:
    report = adapt(evidence_doc(), appraisal_doc(), NONCE)

    assert report.measurement == rim_pin(
        arch="HOPPER", driver_version="580.65.06", vbios_version="96.00.9F.00.01"
    )


def test_cli_emits_a_report(tmp_path: pathlib.Path, capsys) -> None:
    evidence = tmp_path / "evidence.json"
    appraisal = tmp_path / "appraisal.json"
    evidence.write_text(json.dumps(evidence_doc()), encoding="utf-8")
    appraisal.write_text(json.dumps(appraisal_doc()), encoding="utf-8")

    assert main(["--nonce", NONCE, "--evidence", str(evidence), "--appraisal", str(appraisal)]) == 0
    assert json.loads(capsys.readouterr().out)["platform"] == GPU_PLATFORM


def test_cli_rejects_a_short_nonce(tmp_path: pathlib.Path, capsys) -> None:
    path = tmp_path / "x.json"
    path.write_text("{}", encoding="utf-8")

    assert main(["--nonce", "ab", "--evidence", str(path), "--appraisal", str(path)]) == 1
    assert "32 bytes of hex" in capsys.readouterr().err


def test_cli_reports_a_refusal_on_stderr(tmp_path: pathlib.Path, capsys) -> None:
    evidence = tmp_path / "evidence.json"
    appraisal = tmp_path / "appraisal.json"
    evidence.write_text(json.dumps(evidence_doc()), encoding="utf-8")
    appraisal.write_text(json.dumps(appraisal_doc(secboot=False)), encoding="utf-8")

    assert main(["--nonce", NONCE, "--evidence", str(evidence), "--appraisal", str(appraisal)]) == 1
    assert "secboot" in capsys.readouterr().err
