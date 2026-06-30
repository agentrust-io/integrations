# Agent Sentinel

Runtime behavioral anomaly detection, collusion detection, and quarantine for agent fleets.

## Features
- **5 detectors**: delegation escalation, tool drift, policy avoidance, identity drift, collusion
- **Risk aggregation** with quarantine threshold (0.7)
- **Quarantine enforcement**: blocks tools, requires human review
- **Multi-agent collusion detection**: delegation chains, shared tools
- **CLI + FastAPI dashboard**
- **TRACE-native** (consumes TRACE claims)

## Usage


```bash
pip install -r requirements.txt
python -m src.cli claim.jwt --output report.json

Integration with AgenTrust

Sentinel consumes TRACE claims and produces risk scores that can be used by AGT, cMCP, and other AgenTrust components.

Dashboard

bash
uvicorn src.server:app --host 0.0.0.0 --port 8001 --reload
Open http://localhost:8001

Integration with AgenTrust

Sentinel fills the documented gap: "no dedicated behavioral anomaly detection or agent quarantine tooling."

## Security

Sentinel fails closed. Two controls are configured by environment variable:

- **Trace verification gate.** Incoming traces are scored and enforced only
  after their Ed25519 signature is verified against a trusted key supplied in
  `TRACE_TRUSTED_JWK` (an OKP/Ed25519 public JWK as JSON). Unsigned traces,
  bad signatures, or a missing trusted key are rejected. To run against
  unsigned demo data, set `SENTINEL_ALLOW_UNVERIFIED=1` — this bypasses
  verification and logs a loud warning on every use, and must not be used in
  production.
- **Incident report signatures.** Exported incident reports are signed with
  HMAC-SHA256 using the secret in `SENTINEL_SIGNING_KEY`. If the key is unset
  the report is marked `"signature_status": "unsigned"` and carries no
  signature (it is never emitted with a value that merely looks signed). The
  `/verify` endpoint checks the keyed HMAC in constant time and returns
  `UNVERIFIABLE` when no key is configured.

```bash
# Example: run the demo against unsigned sample data
SENTINEL_ALLOW_UNVERIFIED=1 python -m src.cli sample_trace.json --output report.json

# Production: verify traces and sign incidents
export TRACE_TRUSTED_JWK='{"kty":"OKP","crv":"Ed25519","x":"<base64url public key>"}'
export SENTINEL_SIGNING_KEY='<high-entropy secret>'
```

License

MIT
---

## 🚀 How to build and run

```bash
cd /Users/akhileshwarik/agentrust-io/integrations/sentinel
pip install -r requirements.txt
python -m src.cli ../decisionassure/claim.jwt --output report.json