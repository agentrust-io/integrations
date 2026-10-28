# PIC Standard MCP Guard integration with TRACE

[PIC Standard](https://github.com/pic-standard/pic-standard) gates an agent's MCP tool
calls before they run. A tool is wrapped by `guard_mcp_tool`; PIC validates the
supplied Action Proposal, applies the configured trust, policy, and
evidence-verification requirements, and, for proposal-backed MCP calls, enforces exact
tool and argument binding. It either allows or blocks the call. This integration
combines a PIC allow decision with a separately produced, caller-verified
post-dispatch observation to emit a signed TRACE Level 0 Trust Record linked through a
detached bridge.

The adapter consumes PIC 0.9.1's released `on_allow` pre-execution hook. An outer
coordinator reserves the reserved `__pic_request_id` and owns the lifecycle; the hook
runs before dispatch and builds the bridge from the structured `MCPAllowDecision` and
the sanitized `MCPToolCall`:

```json
{
  "profile": "tag:agentrust-io.com,2026:pic-trace-bridge-v1",
  "authorization": {
    "authorization_id": "urn:sha256:<SHA-256 of decision.to_audit_bytes()>",
    "decision": "allow",
    "authorizer": "urn:pic-standard:integration:pic-trace-stage1-harness",
    "scope": {"tools": ["<tool>"], "impacts": ["<impact>"]},
    "pic": {"profile": "PIC-CJSON/1.0", "intent_digest": "sha256:<hex>", "args_digest": "sha256:<hex>"},
    "declaration_digest": "sha256:<hex>",
    "tool_call_digest": "sha256:<hex>",
    "transcript_required": false
  },
  "signature": "<Ed25519 over the authorization>"
}
```

`decision.to_audit_bytes()` is the UTF-8 encoding of the exact `LogRecord.getMessage()`
text emitted for the PIC allow event, without a logging formatter prefix or trailing
newline, so the `authorization_id` is the hash of PIC's own decision. The bridge's PIC
digests are PIC's `canonical.py` values, prefixed to TRACE's `sha256:<hex>` form and
never reinterpreted. After the tool runs and a caller-supplied observation verifier
passes, the adapter builds the Trust Record with `agentrust_trace_adapters.build_record`
and signs it with `agentrust_trace.sign_record`, referencing the bridge.

## Run it

From the repository root:

```bash
pip install -e "integrations/pic-standard-mcp-guard[test]"
pytest integrations/pic-standard-mcp-guard/tests -q
python integrations/pic-standard-mcp-guard/examples/emit_record.py --out trust-record.json
trace-tests verify --record trust-record.json --level 0
```

`emit_record.py` runs one harmless tool (`delete_demo_marker`, operating only inside a
fresh temporary sandbox, declared `impact: irreversible`) through `guard_mcp_tool` with
`strict_trust=True` and `verify_evidence=True`, builds and verifies the bridge in the
hook, observes that the tool actually ran, signs a Level 0 Trust Record, and
self-verifies it before writing. All keys are deterministic Ed25519 TEST keys.

## What is verified

- Missing, empty, or `None` `__pic_request_id` is rejected by the coordinator before
  entering the guard; a plain `request_id` cannot substitute for it.
- Missing or `None` `__pic` is rejected before entering the guard. The hook
  independently refuses any non-proposal-backed allow, preventing `sha256:None`.
- Duplicate active request IDs fail closed, state transitions are one-time, and the
  request context is removed on every success or failure path.
- The hook-driven allowed call produces a signed Level 0 Trust Record whose
  `authorization_id`, `origin.source_event_id`, and `references[0].id` all equal
  `urn:sha256:<SHA-256 of decision.to_audit_bytes()>`.
- The bridge is signed and `verify_bridge`'d **before** the tool is dispatched
  (recorded order `bridge_signed -> bridge_verified -> tool_entered`).
- Digest boundary: `decision.args_digest == tool_call.arguments_digest`, and the
  bridge's PIC digests equal `canonical.py`'s intent/args digests prefixed with
  `sha256:`. A bare-hex PIC digest is refused by the bridge.
- The Trust Record validates (`agentrust_trace.validate.validate_json`), its
  `policy.bundle_hash` is the SHA-256 of the exact policy bytes, `runtime.measurement`
  recomputes from `software_measurement`, and the supplied bridge matches the record's
  signed `authorized-intent` reference by id and JCS digest (the verifier does not
  contact the reference `resolver`).
- The record `subject` `did:key` decodes to `cnf.jwk.x`; the three test keys (PIC
  evidence, bridge, record) are pairwise distinct.
- `trace-tests verify --level 0` passes on the emitted signed record (Ed25519
  signature check against the record's own `cnf.jwk`).
- A tampered-evidence call **blocks** (`PIC_EVIDENCE_FAILED`): no bridge, no record,
  an absence report instead. A call whose live arguments diverge from `action.args`
  blocks with `PIC_ARG_BINDING_MISMATCH` (PIC 0.9.1 binds them; the adapter re-checks
  as defense-in-depth).
- An altered observation no longer matches the signed transcript hash, and changing
  one policy byte changes `bundle_hash` and `runtime.measurement`.

## What it does NOT claim

See rules 2 and 5 in [CONTRIBUTING.md](../../CONTRIBUTING.md).

- **No hardware evidence.** `runtime.platform` is `software-only`. The deterministic
  test keys do not chain to a trusted issuer and must never be used in production.
- **No PIC-native authorization signature.** The `MCPAllowDecision` and its
  audit-message bytes are not signed by PIC. The bridge signature authenticates the
  adapter's translation of that decision; it is not a PIC-issued authorization
  signature.
- **No TRACE Level 1**, and **no independent operator**: the observation is a separate
  code path in the same workflow, not a separate trusted operator.
- **A PIC allow does not prove the tool was dispatched; dispatch does not prove the
  tool succeeded; a filesystem observation does not prove a general real-world
  outcome.** Each is checked separately and only within this synthetic workflow.
- **No released TRACE successor artifact.** The two-stage successor-observation
  mechanism post-dates `agentrust-trace==0.11.0`; this adapter does not use it. The
  observation is carried in the adapter's signed transcript, not a successor artifact.
- **No cMCP or Agent Manifest integration**, and **no portable bridge-corpus
  conformance** (that corpus is still in progress upstream and is not a basis here).
- **The example's `model`, `data_class`, and `build_provenance` are fixed TEST
  values**; in a real deployment they come from the governed run, not from PIC.

## Conformance CI

[`.github/workflows/pic-standard-mcp-guard-conformance.yml`](../../.github/workflows/pic-standard-mcp-guard-conformance.yml),
scoped to this directory, runs two jobs on Python 3.11 to 3.13. `fixed` pins the
versions in `integration.yaml` plus `pic-standard[crypto]` 0.9.1 and
`agentrust-trace-adapters` 0.2.0. `floating` installs the latest releases as drift
detection. Each runs the tests, emits a record, and runs `trace-tests verify --level 0`.
