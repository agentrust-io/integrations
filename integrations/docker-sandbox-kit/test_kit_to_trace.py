"""Tests for the Docker Sandbox Kit adapter.

The fixtures are real platform manifests pulled from Docker Hub on 2026-10-01,
kept byte for byte so their digests match the registry. Two things are pinned:
a published Kit becomes a record the released TRACE packages accept, and every
way a manifest can fail to be a v3 Kit ends in a refusal rather than a record.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))

from agentrust_trace import TrustRecord, generate_key, iter_errors, key_to_jwk, sign_record, verify_record  # noqa: E402
from agentrust_trace_adapters import MissingEvidence  # noqa: E402
from kit_to_trace import ADAPTER_URI, CAPABILITIES, DESCRIPTOR, KitEvidence, build_from_kit  # noqa: E402

ACP = HERE / "fixtures" / "claude-acp-set-1.0.1.amd64.manifest.json"
ACP_INDEX = HERE / "fixtures" / "claude-acp-set-1.0.1.index.json"
DOODLE = HERE / "fixtures" / "doodle-2026.amd64.manifest.json"
# Registry digests, as served in Docker-Content-Digest on 2026-10-01.
ACP_DIGEST = "sha256:86d56a3b2ea714d55c2a48b55b9ca64e2145245f43583100dd944eccfb8fe78e"
DOODLE_DIGEST = "sha256:c9bce67af2c384dc0eadee2b4900e9c0a5beb557ed395ce05709eb0989945d91"
RAN = "sha256:" + "e" * 64


def build(evidence, jwk=None, **over):
    kwargs = dict(
        subject="spiffe://example.org/agent/claude-acp",
        model_provider="anthropic",
        model_id="claude-sonnet-4-6",
        workload_digest=RAN,
        jwk=jwk or key_to_jwk(generate_key()),
        kit_reference="docker.io/docker/sbx-kit-claude-acp-set",
    )
    kwargs.update(over)
    return build_from_kit(evidence, **kwargs)


def mutate(path, change):
    manifest = json.loads(path.read_bytes())
    change(manifest)
    return json.dumps(manifest).encode()


def test_fixtures_are_the_registry_bytes():
    assert "sha256:" + hashlib.sha256(ACP.read_bytes()).hexdigest() == ACP_DIGEST
    assert "sha256:" + hashlib.sha256(DOODLE.read_bytes()).hexdigest() == DOODLE_DIGEST


@pytest.mark.parametrize("path", [ACP, DOODLE])
def test_published_kit_signs_and_verifies(path):
    key = generate_key()
    jwk = key_to_jwk(key)
    record = build(KitEvidence.from_manifest(path.read_bytes()), jwk=jwk)
    assert list(iter_errors(record)) == []
    TrustRecord.model_validate(record)
    verify_record(sign_record(record, key), jwk)


def test_policy_binds_the_descriptor_bytes_and_says_declared():
    evidence = KitEvidence.from_manifest(ACP.read_bytes(), expected_digest=ACP_DIGEST)
    record = build(evidence)
    annotation = json.loads(ACP.read_bytes())["annotations"][DESCRIPTOR]
    policy = record["policy"]
    assert policy["bundle_hash"] == "sha256:" + hashlib.sha256(annotation.encode()).hexdigest()
    assert policy["enforcement_mode"] == "declared"
    assert policy["policy_uri"] == f"oci://docker.io/docker/sbx-kit-claude-acp-set@{ACP_DIGEST}"
    assert "com.docker.sandbox/network-policy@1" in evidence.capability_types
    assert "com.docker.sandbox/credential@1" in evidence.capability_types


def test_kit_digest_identifies_evidence_not_the_execution():
    record = build(KitEvidence.from_manifest(ACP.read_bytes()))
    assert record["origin"] == {
        "kind": "third-party-control-plane",
        "producer": "docker/sandbox-kit/dev",
        "source_event_id": ACP_DIGEST,
    }
    assert record["build_provenance"]["digest"] == RAN
    assert record["runtime"]["platform"] == "software-only"
    assert record["appraisal"] == {"status": "none", "verifier": ADAPTER_URI}


def test_built_by_absent_falls_back_to_frontend_name():
    record = build(KitEvidence.from_manifest(DOODLE.read_bytes()))
    assert record["origin"]["producer"] == "docker/sandbox-kit"


def test_refuses_an_index():
    with pytest.raises(MissingEvidence, match="image index"):
        KitEvidence.from_manifest(ACP_INDEX.read_bytes())


def test_refuses_reserialised_bytes_when_digest_is_pinned():
    raw = json.dumps(json.loads(ACP.read_bytes()), indent=2).encode()
    with pytest.raises(MissingEvidence, match="re-serialised"):
        KitEvidence.from_manifest(raw, expected_digest=ACP_DIGEST)


def test_refuses_an_image_that_is_not_a_kit():
    raw = mutate(ACP, lambda m: m["annotations"].pop(DESCRIPTOR))
    with pytest.raises(MissingEvidence, match="not a Kit"):
        KitEvidence.from_manifest(raw)


def test_names_the_v2_grammar():
    def to_v2(m):
        m["annotations"] = {"vnd.docker.sandbox.kit.kind": "agent", "vnd.docker.sandbox.kit.name": "x"}

    with pytest.raises(MissingEvidence, match="v2 grammar"):
        KitEvidence.from_manifest(mutate(ACP, to_v2))


def test_refuses_capability_index_that_disagrees_with_descriptor():
    raw = mutate(ACP, lambda m: m["annotations"].__setitem__(CAPABILITIES, "com.docker.sandbox/sbx@1"))
    with pytest.raises(MissingEvidence, match="must mirror"):
        KitEvidence.from_manifest(raw)


def test_refuses_capability_index_on_a_kit_that_requests_nothing():
    def strip(m):
        d = json.loads(m["annotations"][DESCRIPTOR])
        d["capabilities"] = []
        m["annotations"][DESCRIPTOR] = json.dumps(d)

    with pytest.raises(MissingEvidence, match="must mirror"):
        KitEvidence.from_manifest(mutate(DOODLE, strip))


def test_refuses_schema_version_disagreement():
    raw = mutate(ACP, lambda m: m["annotations"].__setitem__("vnd.docker.sandbox.kit.schema-version", "2"))
    with pytest.raises(MissingEvidence, match="MUST be equal"):
        KitEvidence.from_manifest(raw)


def test_refuses_a_set():
    def to_set(m):
        d = json.loads(m["annotations"][DESCRIPTOR])
        d["kind"] = "set"
        m["annotations"][DESCRIPTOR] = json.dumps(d)

    with pytest.raises(MissingEvidence, match="never a set"):
        KitEvidence.from_manifest(mutate(ACP, to_set))


def test_refuses_an_artifact_manifest():
    raw = mutate(ACP, lambda m: m.__setitem__("artifactType", "application/vnd.example"))
    with pytest.raises(MissingEvidence, match="no artifactType"):
        KitEvidence.from_manifest(raw)


def test_refuses_yaml_descriptor():
    raw = mutate(ACP, lambda m: m["annotations"].__setitem__(DESCRIPTOR, "schemaVersion: '3'\nkind: workload\n"))
    with pytest.raises(MissingEvidence, match="not JSON"):
        KitEvidence.from_manifest(raw)


def test_requires_the_digest_of_what_ran():
    with pytest.raises(MissingEvidence, match="build_provenance.digest"):
        build(KitEvidence.from_manifest(ACP.read_bytes()), workload_digest=None)


def test_rejects_a_reference_carrying_its_own_digest():
    with pytest.raises(ValueError, match="no tag or digest"):
        build(KitEvidence.from_manifest(ACP.read_bytes()), kit_reference=f"docker.io/docker/x@{ACP_DIGEST}")


def test_cli_emits_a_record_and_refuses_an_index(tmp_path):
    jwk = tmp_path / "pub.jwk"
    jwk.write_text(json.dumps(key_to_jwk(generate_key())))
    common = [
        "--subject", "spiffe://example.org/agent/claude-acp",
        "--model-provider", "anthropic",
        "--model-id", "claude-sonnet-4-6",
        "--workload-digest", RAN,
        "--jwk", str(jwk),
    ]
    ok = subprocess.run(
        [sys.executable, str(HERE / "kit_to_trace.py"), str(ACP), "--expected-digest", ACP_DIGEST, *common],
        capture_output=True, text=True, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["policy"]["enforcement_mode"] == "declared"
    refused = subprocess.run(
        [sys.executable, str(HERE / "kit_to_trace.py"), str(ACP_INDEX), *common],
        capture_output=True, text=True, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert refused.returncode == 2
    assert "image index" in refused.stderr
