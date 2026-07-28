# Agent Sentinel

Runtime behavioral anomaly detection, collusion detection, and quarantine for
agent fleets. Sentinel scores incoming agent traces, decides whether to admit,
review, or deny an action, and emits an Ed25519-signed TRACE v0.2 record for
every enforcement.

## Features

- Detectors: delegation escalation, tool drift, policy avoidance, identity
  drift, and collusion.
- Risk aggregation with a quarantine threshold (0.7).
- Fail-closed enforcement: a detector error forces a DENY rather than an admit.
- Signed evidence: every enforcement emits an Ed25519-signed TRACE Level 0
  record, offline-verifiable against the embedded `cnf.jwk`.
- CLI plus a FastAPI service.

## Signing key (required)

Sentinel signs every TRACE claim and refuses to emit unsigned records. Provide a
PEM-encoded Ed25519 private key in `TRACE_PRIVATE_KEY_PEM`. Without it, claim
generation and `/enforce` fail closed.

```bash
export TRACE_PRIVATE_KEY_PEM="$(cat sentinel-ed25519.pem)"
```

## Install and run

```bash
pip install -r requirements.txt
uvicorn sentinel.main:app --host 0.0.0.0 --port 8001 --reload
# open http://localhost:8001
```

The CLI reads a TRACE claim and writes a risk report:

```bash
python -m sentinel.cli claim.jwt --output report.json
```

## Tests

Run from this directory so the `sentinel` package is importable:

```bash
pip install -r requirements-dev.txt
python -m pytest tests -q
```

`tests/test_trace_conformance.py` runs the `agentrust-trace-tests` Level 0 suite
against the generated records.

## Integration with agentrust-io

Sentinel consumes agent traces and produces signed TRACE records that AGT, cMCP,
and other agentrust-io components can verify. It targets TRACE conformance
Level 0 (software-only; no hardware TEE attestation).

## License

MIT
