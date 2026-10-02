"""Public CLI smoke and refusal behavior using real ephemeral signatures."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from ucp_commerce.__main__ import main

EXAMPLE_ROOT = Path(__file__).resolve().parents[1]


def assert_demo_summary(summary: dict) -> None:
    assert summary["decision"] == "allow"
    assert summary["spends"] == 1
    assert summary["effects"] == 1
    assert summary["invocation_number"] == 1
    assert summary["identical_retry_cached"] is True
    assert summary["fresh_token_replay"] == "GRANT_SPENT"


def assert_sanitized_failure(result: int, captured, *forbidden: str) -> None:
    assert result == 1
    output = captured.out + captured.err
    assert output.strip()
    assert "Traceback" not in output
    for text in forbidden:
        assert text not in output


@pytest.fixture
def exported(tmp_path, capsys) -> Path:
    directory = tmp_path / "retained-demo"
    assert main(["--output", str(directory)]) == 0
    capsys.readouterr()
    return directory


def test_cli_default_demo_reports_one_effect_and_verified_retry_behavior(capsys):
    assert main([]) == 0
    captured = capsys.readouterr()
    assert not captured.err
    assert_demo_summary(json.loads(captured.out))


def test_cli_output_contains_only_bundle_and_public_trust(exported):
    assert {path.name for path in exported.iterdir()} == {"bundle.json", "public-trust.json"}
    trust = json.loads((exported / "public-trust.json").read_text())
    assert set(trust) == {"merchant", "platform", "authority", "receipt"}
    for role, pem in trust.items():
        key = serialization.load_pem_public_key(pem.encode())
        if role in {"merchant", "platform"}:
            assert isinstance(key, ec.EllipticCurvePublicKey)
            assert isinstance(key.curve, ec.SECP256R1)
        else:
            assert isinstance(key, ed25519.Ed25519PublicKey)
    for path in exported.iterdir():
        contents = path.read_text()
        assert "PRIVATE KEY" not in contents
        assert "BEGIN EC PRIVATE" not in contents
    assert json.loads((exported / "bundle.json").read_text())["receipt"]


@pytest.mark.parametrize("existing_kind", ["directory", "file"])
def test_cli_never_overwrites_an_existing_output_target(tmp_path, capsys, existing_kind):
    target = tmp_path / "existing-output"
    if existing_kind == "directory":
        target.mkdir()
        sentinel = target / "preserve.txt"
    else:
        sentinel = target
    sentinel.write_text("existing user content")
    result = main(["--output", str(target)])
    assert_sanitized_failure(result, capsys.readouterr())
    assert sentinel.read_text() == "existing user content"
    if target.is_dir():
        assert {path.name for path in target.iterdir()} == {"preserve.txt"}


def test_cli_export_can_be_audited_in_a_fresh_process(exported):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ucp_commerce",
            "audit",
            str(exported / "bundle.json"),
            "--trust",
            str(exported / "public-trust.json"),
        ],
        cwd=EXAMPLE_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert not result.stderr
    decision = json.loads(result.stdout)
    assert decision["decision"] == "allow"
    assert decision["invocation_number"] == 1


def test_cli_audit_refuses_a_different_configured_authority_key(exported, capsys):
    trust_path = exported / "public-trust.json"
    trust = json.loads(trust_path.read_text())
    trust["authority"] = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    trust_path.write_text(json.dumps(trust))
    result = main(["audit", str(exported / "bundle.json"), "--trust", str(trust_path)])
    assert_sanitized_failure(result, capsys.readouterr(), trust["authority"])


def test_cli_audit_refuses_tampered_signed_evidence(exported, capsys):
    bundle_path = exported / "bundle.json"
    bundle = json.loads(bundle_path.read_text())
    bundle["receipt"] = "tampered-private-business-marker"
    bundle_path.write_text(json.dumps(bundle))
    result = main(["audit", str(bundle_path), "--trust", str(exported / "public-trust.json")])
    assert_sanitized_failure(result, capsys.readouterr(), bundle["receipt"])


@pytest.mark.parametrize("mutation", ["unknown_field", "missing_field", "wrong_type"])
def test_cli_audit_requires_closed_strict_public_trust(exported, capsys, mutation):
    trust_path = exported / "public-trust.json"
    trust = json.loads(trust_path.read_text())
    marker = "private-input-do-not-echo"
    if mutation == "unknown_field":
        trust["unknown"] = marker
    elif mutation == "missing_field":
        del trust["receipt"]
    else:
        trust["authority"] = {"unexpected": marker}
    trust_path.write_text(json.dumps(trust))
    result = main(["audit", str(exported / "bundle.json"), "--trust", str(trust_path)])
    assert_sanitized_failure(result, capsys.readouterr(), marker)


@pytest.mark.parametrize("mixed_with_public", [False, True])
def test_cli_audit_refuses_private_key_material_in_public_trust(
    exported, capsys, mixed_with_public
):
    trust_path = exported / "public-trust.json"
    trust = json.loads(trust_path.read_text())
    # Disposable test-only key: never a checked-in credential or service key.
    private_pem = (
        ed25519.Ed25519PrivateKey.generate()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    trust["authority"] = (trust["authority"] if mixed_with_public else "") + private_pem
    trust_path.write_text(json.dumps(trust))
    result = main(["audit", str(exported / "bundle.json"), "--trust", str(trust_path)])
    assert_sanitized_failure(result, capsys.readouterr(), private_pem, "PRIVATE KEY")


def test_cli_audit_does_not_echo_malformed_bundle_input(exported, capsys):
    bundle_path = exported / "bundle.json"
    marker = "private-business-data-not-json"
    bundle_path.write_text(marker)
    result = main(["audit", str(bundle_path), "--trust", str(exported / "public-trust.json")])
    assert_sanitized_failure(result, capsys.readouterr(), marker)


def test_cli_audit_missing_file_is_a_sanitized_failure(exported, capsys):
    missing = exported / "private-customer-location.json"
    result = main(["audit", str(missing), "--trust", str(exported / "public-trust.json")])
    assert_sanitized_failure(result, capsys.readouterr(), str(missing))
