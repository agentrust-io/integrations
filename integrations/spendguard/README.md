# Agentic SpendGuard integration with TRACE + Confidential MCP

Agentic SpendGuard is a spend firewall for LLM agents: it reserves budget and
gates tool calls before the provider is called, and records each decision in a
signed, hash-chained ledger. This integration maps those decisions onto TRACE
Trust Records and enforces spend and approval policy at the Confidential MCP
tool boundary.

What it does NOT claim: see rule 4 in [CONTRIBUTING.md](../../CONTRIBUTING.md).
This directory is a scaffold. The TRACE conformance level is unverified until
the conformance workflow passes, and the tier stays `community` until maintainers
run it end to end.

## Run it

Against released packages:

```bash
pip install agentrust-trace cmcp-runtime agentrust-trace-tests
pip install spendguard-sdk            # SpendGuard SDK; see the upstream repo
python examples/emit_record.py --out trust-record.jwt
trace-tests verify --record trust-record.jwt --level 0
```

## What is verified

- `examples/emit_record.py` produces a TRACE Trust Record from a SpendGuard
  spend/gate decision. (TODO: implement.)
- `tests/` exercises the mapping from SpendGuard's signed decision to TRACE
  record fields. (TODO: implement.)
- A reviewer reproduces a passing result by running the two commands above.

## Conformance CI

`.github/workflows/agentrust-conformance.yml` installs the released agentrust-io
packages, emits a record, and runs `trace-tests verify` at the claimed level. A
clean matrix run is the basis for the Verified tier.
