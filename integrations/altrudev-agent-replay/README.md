# Agent Replay integration with TRACE

Agent Replay consumes standalone TRACE Trust Records as supplementary evidence during AI-agent incident reconstruction. It verifies the TRACE record against a caller-supplied trusted issuer key, then records a bounded verification summary alongside the reconstructed timeline.

## Pinned reproduction target

This listing is pinned to:

- Agent Replay commit `77d4934e1560d2cfc2b80263cfc08c104a9ee079` (package version 0.4.3)
- `agentrust-trace==0.9.0`
- `agentrust-trace-tests==0.5.1`

The earlier v0.4.2 dependency declared `agentrust-trace>=0.9.1,<0.10.0`, but 0.9.1 was not published. The pinned commit above repairs that dependency to the released 0.9.0 verifier.

## Reproduce

```bash
git clone https://github.com/altrudev/Agent-Replay.git
cd Agent-Replay
git checkout 77d4934e1560d2cfc2b80263cfc08c104a9ee079

python3 -m venv .venv
source .venv/bin/activate

python -m pip install -e '.[dev,trace]'
python -m pip install 'agentrust-trace-tests==0.5.1'

python - <<'PY'
import json, time
from pathlib import Path
from agentrust_trace import generate_key, key_to_jwk, sign_record

key = generate_key()
record = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": int(time.time()),
    "subject": "spiffe://example.test/agent/refund",
    "model": {"provider": "example", "model_id": "demo"},
    "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
    "policy": {
        "bundle_hash": "sha256:" + "b" * 64,
        "enforcement_mode": "enforce",
    },
    "data_class": "internal",
    "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "e" * 64},
    "appraisal": {"status": "none", "verifier": "https://verifier.example.test"},
    "transparency": "https://registry.example.test/trace/sample",
}
signed = sign_record(record, key)
Path("session.trace.json").write_text(json.dumps(signed), encoding="utf-8")
Path("issuer.jwk").write_text(json.dumps(key_to_jwk(key)), encoding="utf-8")

tampered = dict(signed)
tampered["subject"] = "spiffe://example.test/agent/tampered"
Path("tampered.trace.json").write_text(json.dumps(tampered), encoding="utf-8")

wrong = generate_key()
Path("wrong-issuer.jwk").write_text(json.dumps(key_to_jwk(wrong)), encoding="utf-8")
PY

# Real released TRACE verifier through Agent Replay.
agent-replay verify-trace session.trace.json --trusted-key issuer.jwk

# Both commands below must fail closed.
! agent-replay verify-trace tampered.trace.json --trusted-key issuer.jwk
! agent-replay verify-trace session.trace.json --trusted-key wrong-issuer.jwk

# Agent Replay's real-verifier cryptographic regression cases.
pytest -q tests/test_trace_real_verifier.py

# TRACE Level 0 conformance.
trace-tests verify --record session.trace.json --level 0
```

The adapter calls the released `agentrust-trace` `validate_json()` and `verify_record()` functions directly. It does not enable embedded-key trust; the issuer key is supplied independently.

## Expected Level 0 result

The generated record is a software-only TRACE v0.2 development record. Level 0 should exit 0. Higher conformance levels are not claimed by this listing.

## What is verified

A reviewer can reproduce that:

- a correctly signed TRACE record verifies with the independently supplied trusted key;
- tampering after signing is rejected;
- the same valid record is rejected under a different trusted key;
- the Level 0 TRACE conformance command succeeds for the generated software-only record;
- a successfully verified record is attached under `trace_evidence`;
- the verification scope explicitly does not claim hardware-attestation verification, transparency-ledger verification, or transcript-to-incident binding.

## What this integration does not claim

Agent Replay does not independently verify TEE evidence or SCITT/registry inclusion. It does not yet accept cMCP RuntimeClaim envelopes. It also does not claim that an incident input is the transcript committed by `tool_transcript.hash` unless a separate transcript-binding verifier establishes that relationship.

## Conformance

The marketplace submission claims TRACE conformance level 0 only.
