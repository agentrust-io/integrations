# WIMSE CTA MCP Guard integration with TRACE

Gates an MCP tool call on the taint of the session context before it dispatches, using the
Context Taint Attestation (CTA) rules in
[draft-durga-wimse-ctx-isolation-00](https://datatracker.ietf.org/doc/draft-durga-wimse-ctx-isolation/),
and emits a signed TRACE Level 0 Trust Record linked through a detached bridge.

Both drafts cited here are individual Internet-Drafts: not endorsed by the IETF and with no
formal standing. They are the text this adapter follows, not a standard it conforms to. The
verification rules for canonical JSON, key identifiers, and timestamps come from
[draft-durga-agenttrust-trace-verification-01](https://datatracker.ietf.org/doc/draft-durga-agenttrust-trace-verification/).

## How it works

`CtaGuard.run` handles one tool call:

1. **Session taint.** A session starts `TRUSTED_ONLY`. `ingest_untrusted(session_id)`, a call
   to a tool whose pinned declaration says `output_trust: untrusted`, or a caller-supplied
   `claimed_taint` of `UNTRUSTED_INGESTED` moves it to `UNTRUSTED_INGESTED`. Nothing moves it
   back, and a caller-supplied `TRUSTED_ONLY` claim is ignored.
2. **Effect class.** `READ_ONLY` or `STATE_MUTATING` comes from the pinned declaration in the
   policy bytes. Runtime annotations such as `readOnlyHint` are accepted and never read. A tool
   with no declaration is `STATE_MUTATING` with untrusted output.
3. **Gate.** A `STATE_MUTATING` call in an `UNTRUSTED_INGESTED` session is refused with
   `CTA_TAINTED_CONTROL_PLANE` before the tool is entered, unless a `StepUpReceipt` verifies.
   The receipt is Ed25519-signed by the pinned policy-engine key (`kid` is
   `sha256:` plus the SHA-256 of the raw public key) and bound to
   `(session_id, request_id, tool_name, args_digest)`.
4. **Bridge.** On allow, the guard signs a detached `cta-trace-bridge-v1` envelope and verifies
   it, in that order, before the tool is entered:

```json
{
  "profile": "cta-trace-bridge-v1",
  "authorization": {
    "cta_version": "1.0",
    "authorization_id": "urn:sha256:<SHA-256 of the JCS decision>",
    "decision": "allow",
    "decision_basis": "read-only | trusted-context | step-up-receipt",
    "authorizer": "<identifier>",
    "authorizer_key_id": "sha256:<SHA-256 of the raw bridge public key>",
    "authorized_at": 1795158233,
    "expires_at": 1795158533,
    "session_id": "<id>", "request_id": "<id>", "tool_name": "<tool>",
    "tool_effect_class": "STATE_MUTATING",
    "taint_lattice_level": "UNTRUSTED_INGESTED",
    "args_digest": "sha256:<hex>",
    "declaration_digest": "sha256:<hex>",
    "tool_call_digest": "sha256:<hex>",
    "step_up_receipt_hash": "sha256:<hex, present only for step-up-receipt>"
  },
  "signature": "<unpadded base64url Ed25519 over JCS({profile, authorization})>"
}
```

5. **Observation and record.** After dispatch a caller-supplied observer returns a verdict and a
   document that names the exact call (`request_id`, `tool_name`, `args_digest`,
   `tool_call_count: 1`). Only `established` yields a record: the transcript preimage is hashed
   into `tool_transcript.hash`, the record is built with
   `agentrust_trace_adapters.build_record`, signed with `agentrust_trace.sign_record`, and
   self-verified by `cta_trace_verify` before it is returned.

The policy bytes the guard enforces are the bytes recorded in `policy.bundle_hash`. Example
(`step_up_key_id` is the `kid` of the policy-engine key the gate trusts):

```json
{
  "profile": "cta-gate-policy/v1",
  "step_up_key_id": "sha256:<hex>",
  "tools": {
    "delete_demo_marker": {"effect_class": "STATE_MUTATING", "output_trust": "trusted"},
    "read_inbox": {"effect_class": "READ_ONLY", "output_trust": "untrusted"}
  }
}
```

Relationship to the drafts:

| Draft rule | Where |
|---|---|
| wimse-ctx-isolation-00 section 4 rule 1, `TAINT_LATTICE_MONOTONICITY` (two of the four levels) | `CtaGuard.ingest_untrusted`, `_effective_taint` |
| wimse-ctx-isolation-00 section 4 rule 2, `CONFUSED_DEPUTY_FAIL_CLOSED` | `CtaGuard._check_step_up` |
| trace-verification-01 section 3, JCS and duplicate keys | `canonical_bytes`, `loads_unique` |
| trace-verification-01 section 4, canonical base64url and private JWK members | `b64url_decode`, `public_key_from_jwk` |
| trace-verification-01 section 6 item 3, `kid` derivation | `key_id` |
| trace-verification-01 section 6 item 5 and section 7, 60-second skew and integer timestamps | `verify_step_up_receipt`, `require_timestamp` |

## Run it

From the repository root:

```bash
pip install -e "integrations/wimse-cta-mcp-guard[test,cov]"
pytest integrations/wimse-cta-mcp-guard/tests -q \
  --cov=cta_trace_guard --cov=cta_trace_verify --cov-branch --cov-fail-under=100
python integrations/wimse-cta-mcp-guard/examples/emit_record.py --out trust-record.json
trace-tests verify --record trust-record.json --level 0
```

`emit_record.py` runs one harmless tool (`delete_demo_marker`, operating only inside a fresh
temporary sandbox, declared `STATE_MUTATING`) in a session that has ingested untrusted data. The
first call carries a forged `TRUSTED_ONLY` claim and no receipt: it is refused before the tool is
entered, the tool runs zero times, and the marker file is untouched. The second call carries a
policy-engine `StepUpReceipt` bound to that call: the bridge is signed and verified, the tool
runs, the observer confirms the file is gone and the tool ran once, and a Level 0 Trust Record is
signed. The example then verifies the record from the file it wrote. All keys are deterministic
Ed25519 TEST keys.

## Reproduce from the fixed lock

This is the exact procedure for evaluating this integration. Runtime and test dependencies are
installed from the committed hash-locked requirements, and the integration is then installed with
`--no-deps`.

From the repository root of a fresh clone, with Python 3.11 (CI also runs the same lock on
Python 3.12 and 3.13):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements/wimse-cta-mcp-guard-fixed.txt
.venv/bin/python -m pip check
.venv/bin/python -m pip install --no-deps -e integrations/wimse-cta-mcp-guard
.venv/bin/python -m pip check
.venv/bin/python -m pytest integrations/wimse-cta-mcp-guard/tests -q \
  --cov=cta_trace_guard --cov=cta_trace_verify --cov-branch --cov-fail-under=100
.venv/bin/python integrations/wimse-cta-mcp-guard/examples/emit_record.py --out trust-record.json
.venv/bin/trace-tests verify --record trust-record.json --level 0
```

On Windows, create the environment with `py -3.11 -m venv .venv` and use `.venv\Scripts\` in
place of `.venv/bin/`.

Expected:

- both `pip check` runs report no broken requirements;
- pytest reports `338 passed` and `Required test coverage of 100% reached`;
- `emit_record.py` prints, in order,
  `blocked: status=blocked code=CTA_TAINTED_CONTROL_PLANE reason=no_step_up_receipt tool_entered=False tool_calls=0 marker_intact=True`,
  an `allowed:` line whose events end `bridge_signed > bridge_verified > tool_entered > tool_returned > observation_verified > record_signed > record_verified`,
  a `verified from the written file:` line, and
  `wrote trust-record.json (status=record-emitted, taint=UNTRUSTED_INGESTED, basis=step-up-receipt)`;
- `trace-tests verify` reports `Result: PASS  (15 checks, 4 skipped)`.

The fixed lock pins `agentrust-trace` 0.11.0, `agentrust-trace-adapters` 0.2.0, and
`agentrust-trace-tests` 0.6.2. All three are released on PyPI.

## Before vs. After verification summary

| | Before dispatch (the gate) | After dispatch (observation and record) |
|---|---|---|
| Checked | Pinned effect class, tracked session taint, the caller's claim (it can only raise taint), and for a tainted `STATE_MUTATING` call a `StepUpReceipt`: profile, signature by the pinned key, `kid`, window, session, request, tool, arguments, one use | Observer verdict is `established`; the observation names this request, tool, and `args_digest` and reports `tool_call_count` 1; `authorized_at <= observed_at <= iat` |
| Produced | A detached `cta-trace-bridge-v1`, signed then verified; recorded order `bridge_signed -> bridge_verified -> tool_entered` | `tool_transcript.hash` over the JCS transcript preimage; a Level 0 Trust Record, signed then self-verified |
| On failure | `precondition-failed`, `blocked`, `authorization-failed`, or an `adapter-error` raised before dispatch (for example an invalid clock value): the tool is not entered and no record is signed | `dispatch-error`, `observation-failed`, or an `adapter-error` from record finalization: the verified bridge is returned, no record |
| Relying party | `verify_authorization_artifacts` (bridge, and receipt if cited) | `verify_adapter_artifacts` (bridge, receipt, record, policy bytes, transcript) |

| Scenario in an `UNTRUSTED_INGESTED` session | Result |
|---|---|
| `STATE_MUTATING`, no receipt | `blocked`, `CTA_TAINTED_CONTROL_PLANE`, tool not entered |
| `STATE_MUTATING`, `claimed_taint: TRUSTED_ONLY`, no receipt | Same; `taint_claim_ignored` is true |
| `STATE_MUTATING`, `runtime_annotations: {readOnlyHint: true}`, no receipt | Same; the pinned declaration decides |
| `STATE_MUTATING`, receipt bound to another session, request, tool, or arguments; expired; replayed; signed by another key | `blocked`, `CTA_TAINTED_CONTROL_PLANE`, tool not entered |
| `STATE_MUTATING`, valid receipt | Allowed with `decision_basis: step-up-receipt`; the bridge carries `step_up_receipt_hash` |
| `READ_ONLY`, no receipt | Allowed with `decision_basis: read-only` |
| Tool with no declaration | Treated as `STATE_MUTATING`: blocked without a receipt |

## What is verified

Each item is exercised by `tests/` (run the command above).

- **Sticky taint.** Untrusted ingestion, untrusted tool output (including from a tool that
  raised), and a claimed `UNTRUSTED_INGESTED` all raise a session to `UNTRUSTED_INGESTED`; no
  code path lowers it; a forged `TRUSTED_ONLY` claim is ignored and reported.
- **Mutability comes from the pinned declaration.** A `readOnlyHint` in `runtime_annotations`
  changes nothing in either direction; an unknown tool is `STATE_MUTATING` with untrusted
  output.
- **Fail closed before tool entry.** A tainted `STATE_MUTATING` call without a verifying receipt
  returns `CTA_TAINTED_CONTROL_PLANE`; the tool function is not called and no bridge is signed.
- **StepUpReceipt.** Refused when missing, expired, not yet valid (more than 60 seconds ahead),
  windowed at 60 seconds or less or more than one hour, signed by another key, carrying another
  key's `kid`, bound to a different session, request, tool, or arguments, malformed, replayed, or
  carrying boolean or float timestamps. A spent receipt id is remembered until it expires, so
  eviction of the request-id tombstone does not re-enable it.
- **Request ids are single use,** including ids of blocked calls; concurrent duplicates dispatch
  once.
- **Order.** Spies on `sign_envelope`, `verify_bridge`, and the tool show
  `bridge_signed -> bridge_verified -> tool_entered`. A bridge that expires, or a clock that steps
  back, between signing and verification stops the call before dispatch. A clock value that is
  boolean, not an integer, negative, below 1,700,000,000 (the TRACE schema minimum for `iat`), or
  above 2^53 - 1 stops the call before dispatch.
- **Observation.** Contradicted, not-established, malformed, mismatched (request, tool,
  arguments, call count other than 1, boolean or early `observed_at`), or erroring observations
  emit no record and keep the verified bridge.
- **Strict encoding.** `loads_unique` rejects duplicate keys, `NaN`, `Infinity`, overflowing
  numbers, invalid UTF-8, and runaway nesting; timestamps reject `bool` and floats; base64url
  must be unpadded and canonical (a second spelling of the same bytes is refused); JWKs with any
  of `d p q dp dq qi oth`, unsupported members, or a wrong `kid` are refused; arguments with no
  RFC 8785 form are refused.
- **Forged but correctly signed artifacts are refused** by the verifier: a bridge whose basis
  contradicts its taint and effect class, a wrong `authorization_id`, declaration, tool call, or
  receipt digest; a record with a wrong reference, subject, policy hash, measurement,
  transcript hash, or call count; a record signed by a key other than the pinned one.
- **Record.** `validate_json` passes; the signature verifies against the pinned key, not only
  the embedded one; `origin.source_event_id` and exactly one `authorized-intent` reference carry
  the `authorization_id` and the bridge's JCS digest; the `subject` `did:key` decodes to
  `cnf.jwk.x`; `policy.bundle_hash` is the SHA-256 of the exact policy bytes and
  `runtime.measurement` recomputes from `software_measurement`. Changing one policy byte changes
  both.
- **Import independence.** `cta_trace_verify` loads without `agentrust_trace_adapters` or
  `cta_trace_guard`.
- **100% line and branch coverage** of `cta_trace_guard.py` and `cta_trace_verify.py`.
- `trace-tests verify --level 0` passes on the emitted record (Ed25519 signature check against
  the record's own `cnf.jwk`, plus the other Level 0 checks).

## What it does NOT claim

See rules 2 and 5 in [CONTRIBUTING.md](../../CONTRIBUTING.md).

- **No hardware evidence.** `runtime.platform` is `software-only`. The deterministic test keys do
  not chain to a trusted issuer and must never be used in production.
- **TRACE Level 0 only.** No Level 1 or Level 2 claim, and no independent operator: the
  observation is a separate code path in the same workflow, not a separate trusted operator.
- **Not the draft's wire format.** There is no COSE_Sign1 object, no `Agent-Ctx-Isolation` or
  `Agent-Step-Up-Receipt` header, and no `_meta.ctxIsolation` member. `cta-trace-bridge-v1`,
  `cta-step-up-receipt-v1`, and the transcript profile are this integration's own detached JSON
  profiles, not registered with TRACE or the IETF. `agentrust_trace.intent_bridge.verify_bridge`
  accepts only the PIC profile and refuses this bridge; use `cta_trace_verify`.
- **Part of the draft only.** Section 4 rule 3, `CONTEXT_MERKLE_BINDING`, is not implemented, so
  there is no `data_plane_merkle_root`, `system_prompt_digest`, or `parent_trace_ref`. The
  lattice has two of the four levels (`MIXED_TAINT` and `QUARANTINED` are absent), `PRIVILEGED_ACTUATE`
  is not an effect class, and there is no context-reset boundary: taint never clears for a
  session id. The draft names the refusal `ERR_TAINTED_CONTROL_PLANE`; this adapter's code is
  `CTA_TAINTED_CONTROL_PLANE`.
- **Taint is reported to the guard, not observed by it.** The guard cannot see what entered the
  model's context. A host that never calls `ingest_untrusted`, and whose declarations mark tool
  output `trusted`, leaves the session `TRUSTED_ONLY`.
- **The approver is not established.** The receipt proves a signature by the pinned key over
  that exact call. `approver` is a self-asserted string; nothing here shows a human or an
  independent policy engine decided, and this package does not issue receipts.
- **The bridge signature authenticates the adapter's own decision.** No external authority signs
  the `authorization_id`; it is a content hash computed by the adapter.
- **A gate decision does not prove the tool was dispatched; dispatch does not prove it
  succeeded; a filesystem observation does not prove a general real-world outcome.** Each is
  checked separately and only within this synthetic workflow.
- **State is process-local.** Session taint, request-id tombstones (bounded, so eventually
  evictable), and spent receipt ids are not shared across workers or kept across restarts.
- **No released TRACE successor artifact, no cMCP, no Agent Manifest.** The observation is
  carried in the adapter's signed transcript.
- **The example's `model`, `data_class`, and `build_provenance` are fixed TEST values**; in a
  real deployment they come from the governed run.
- **No standards status.** The drafts are individual submissions, not IETF consensus documents.
  `tier: community` means structure checks pass, nothing more.

## Conformance CI

[`.github/workflows/wimse-cta-mcp-guard-conformance.yml`](../../.github/workflows/wimse-cta-mcp-guard-conformance.yml),
scoped to this directory, runs two jobs on Python 3.11 to 3.13. `fixed` pins the versions in
`integration.yaml` plus `agentrust-trace-adapters` 0.2.0. `floating` installs the latest releases
as drift detection. Each runs the tests with 100% coverage required, emits a record, and runs
`trace-tests verify --level 0`.
