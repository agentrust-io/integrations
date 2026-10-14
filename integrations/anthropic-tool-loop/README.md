# Anthropic SDK tool loop → AgenTrust Telemetry and TRACE

Records a tool-use loop written directly against the
[`anthropic`](https://pypi.org/project/anthropic/) Python SDK (the application
calls `client.messages.create` in a loop and dispatches each `tool_use` block
itself) as [AgenTrust Telemetry](https://github.com/agentrust-io/agentrust-telemetry)
governance events, and signs one TRACE v0.2 record per finished run. There is no
framework to hook into here, so the loop calls the recorder explicitly.

The code this package was generalised from runs in production in front of two
Slack operations agents, an ERP/purchasing agent and a sales-operations agent.

## Two parts

| Part | Where it runs | Needs |
|---|---|---|
| `anthropic_tool_loop_trace.Run` | Inside the agent process | Standard library only, Python 3.9+ |
| `anthropic_tool_loop_trace.recorder.Recorder` | Out of process (sidecar, timer, cron) | Python 3.11+, `agentrust-telemetry`, `agentrust-trace`; `opentelemetry-sdk` for spans |

`Run` appends metadata-only JSON lines to a spool file: `run.start`, one
`model.call` per `messages.create` round, one `tool.call` per `tool_use` block,
`run.end`. Every method is fail-open: a spool problem logs one warning and never
raises into the reply path. The agent process never imports the signing stack and
never holds the signing key.

`Recorder.poll()` reads new rows, and for each finished run builds the events,
optional OpenTelemetry spans with the observed start and end times, an
`EvidenceAccumulator` chain, and a signed record from `finalize_trace`
(`origin.kind: log-import`). It never consumes a half-written line, and keeps its
read offset and unfinished runs in `state.json`, so a restart mid-run loses
nothing.

## The hook lines

```python
import time
from anthropic_tool_loop_trace import Run                                       # 1

run = Run("spiffe://example.org/agent/purchasing", "purchasing", model,         # 2
          toolset=[t["name"] for t in tools], action_field="action")
for round_no in range(max_rounds):
    t0 = time.time_ns()
    response = client.messages.create(model=model, max_tokens=1024, tools=tools, messages=messages)
    run.model_call(round_no, t0, response)                                       # 3
    if response.stop_reason != "tool_use":
        run.end(response.stop_reason)                                            # 4
        break
    results = []
    for block in response.content:
        if block.type != "tool_use":
            continue
        t0 = time.time_ns()
        reason = my_gate(block.name, block.input)  # your own check; None means allow
        result = None if reason else my_tools[block.name](block.input)
        run.tool_call(round_no, block, t0, decision="deny" if reason else "allow",  # 5
                      policy="my_gate", reason=reason, result=result)
        results.append(...)
    messages += [{"role": "assistant", "content": response.content},
                 {"role": "user", "content": results}]
else:
    run.end("max_rounds")                                                        # 6
```

`tool_call` also takes `error_type=` when the tool raised and `gate_ns=` for how
long the check took. [`examples/offline_tool_loop.py`](examples/offline_tool_loop.py)
has the complete loop.

## Recorder setup

```python
from agentrust_trace import load_key
from anthropic_tool_loop_trace import ToolCatalog, ToolInfo
from anthropic_tool_loop_trace.recorder import Recorder, source_digest

catalog = ToolCatalog(
    {
        "inventory_lookup": ToolInfo("inventory-db", "database", "internal"),
        "purchase_orders": ToolInfo("erp", "erp", "confidential",
                                    write=lambda verb: verb not in {"get", "list"}),
        "crm_*": ToolInfo("crm", "crm", "confidential"),  # prefix match
    },
    taxonomy="example.v1",
    order=("public", "internal", "confidential"),          # lowest first
)
recorder = Recorder(
    spool="~/.local/state/agentrust/anthropic-spool.jsonl",
    data_dir="/var/lib/agent-records",
    signing_key=load_key(open("recorder-key.pem").read()),
    catalog=catalog,
    enforcement_mode="enforce",                  # required, no default
    policy_bundle_digest=source_digest("app/gates"),
    build_digest=source_digest("app"),
    prompt_classification="internal",            # required: the recorder cannot see prompts
    tracer_provider=my_tracer_provider,          # optional
)
recorder.poll()   # call on a timer; returns the run ids it recorded
```

Records land in `data_dir/records/<day>/<run_id>.json` as
`{"run": summary, "events": [...], "trace": signed_record_or_null}`, the hash-chained
evidence in `data_dir/evidence/<day>.jsonl`, and one summary line per run in
`data_dir/index.jsonl`.

## Events per run

| Event | When | Notes |
|---|---|---|
| `policy.decision` | Run start | `policy_id: toolset`, the tools offered to the model, digested. Every run has it, so a run with no tool calls still carries policy evidence and can be signed |
| `policy.decision` | Each tool call | The caller's verdict, `reason_codes` on a deny, gate time as `evaluation_duration_ns`, input digest |
| `action.executed` | Each tool call | Bound to its decision by `policy_event_id`; `outcome` success, error or denied |
| `usage.recorded` | Each model round, plus an `agent_run` rollup | Tokens including cache reads and writes; cost only when you pass `prices` |
| `data_flow.observed` | Each successful tool call | Read or write between the agent and the catalog's system, classified by the catalog |
| `data_flow.observed` | Run end | Agent → `model-provider` `anthropic`, `policy_decision: not_evaluated` |

## What it does NOT claim

See rules 2 and 5 in [CONTRIBUTING.md](../../CONTRIBUTING.md).

- **It evaluates no policy.** Every decision comes from the application's own
  gate, passed in by the caller. `enforcement_mode` must be stated: `enforce` only
  when a deny actually blocks the call, `monitor` when the gate only observes,
  `disabled` when there is no gate (TRACE records `declared`).
  `policy_bundle_digest` names the gate code you say made the decisions; nothing
  here checks that it did.
- **The record is only as trustworthy as the spool.** `origin.kind` is
  `log-import` because the recorder reads a file the application wrote. Anything
  that can write that file can write rows. Protect it like an audit log.
- **`runtime.platform` is `software-only`.** Level 0 passes. Level 1 fails on
  `TR-RTE-001` and `TR-RTE-004`; nothing here carries a hardware attestation or a
  verifier nonce.
- **Classification is yours.** The catalog is supplied by the caller, never inferred
  from tool names. A tool missing from the catalog is treated as a write to an
  `uncatalogued` system at the highest class, so a gap overstates rather than
  understates. What is sent to the model is classed as the highest of
  `prompt_classification` and every class a tool read; nothing evaluated that flow,
  so it is marked `not_evaluated`.
- **A deny makes the appraisal `contraindicated`.** That is the upstream
  `finalize_trace` rule. For a run where the gate refused a call it is the expected
  result: the record shows a refused action, not a failed gate.
- **Unfinished runs are not signed.** A run with no `run.end` (crash, restart, or
  idle longer than `idle_seconds`) is sealed `incomplete` and stored with
  `trace: null`. Rows arriving after a run was sealed are ignored.
- **Metadata only, with one caveat.** No prompt, reply, tool argument or tool
  result is written; a test puts a secret in tool inputs and results and checks it
  appears nowhere in the spool, evidence, records or spans. Reason codes and policy
  ids must be short tokens, otherwise they are replaced with `UNSPECIFIED`. The
  input digest is an unsalted sha256, so an input with few possible values (a short
  id) can be confirmed by guessing.
- **The model id is the one requested** in `run.start`. Per-round `usage.recorded`
  events carry the model each response reported.

## Run it

Offline, no API key, against released packages:

```bash
pip install -e "integrations/anthropic-tool-loop[recorder,test]"
python integrations/anthropic-tool-loop/examples/offline_tool_loop.py --out record.json
trace-tests verify --record record.json --level 0
```

The example drives two turns of a purchasing conversation through a scripted
stand-in for `anthropic.Anthropic()`: in the first, a requester without purchasing
rights asks for stock and a purchase order, the stock lookup runs and the gate
denies the order; in the second, a buyer confirms and the order is created. Output:

```
turn 1: contraindicated  signed=True tool_calls=2 denies=1 writes=0 data_class=internal events=10 verify=True
    inventory_lookup  -       allow success  read
    purchase_orders   create  deny  denied   write WRITERS_ONLY
turn 2: affirming        signed=True tool_calls=1 denies=0 writes=1 data_class=confidential events=8 verify=True
    purchase_orders   create  allow success  write

tampered copy (data_class -> public): verify ok=False (InvalidSignature)
supplier name found in spool/records: nowhere
```

## What is verified

```bash
pytest integrations/anthropic-tool-loop/tests -q
pip install anthropic==1.14.0
pytest integrations/anthropic-tool-loop/tests/test_anthropic_interop.py -q
```

- `test_anthropic_spool.py` (standard library and pytest only, runs on 3.9):
  rows carry no content, the action verb is opt-in and token-shaped, reason codes
  are never free text, outcomes, `end` written once, dict-shaped responses, the
  writer survives an unwritable spool, malformed responses and a broken lock, and
  the catalog's prefix matching and conservative default.
- `test_anthropic_recorder.py`: a clean run is signed `affirming` and verifies; a
  deny is `contraindicated` with its reason code and produces no write flow; an
  allowed write is a confidential write flow; a chat-only run is signed; unfinished
  and idle runs are unsigned; edits to appraisal, data class, enforcement mode or
  subject, and a different key, all fail verification; the metadata-only check end
  to end; restart mid-run; half-written lines; late rows; a malformed run is logged and
  does not stop the others; no OpenTelemetry; required configuration; `trace-tests verify --level 0` on a signed record.
- `test_anthropic_interop.py`: the example's loop driven by the released
  `anthropic` SDK with only its HTTP transport replaced, so a renamed field on
  `Message`, `Usage` or `ToolUseBlock` fails a specific assertion. Run against
  `anthropic` 0.69.0, 1.12.1, 1.13.0 and 1.14.0.

Tested with `agentrust-telemetry` 0.1.0a6, `agentrust-trace` 0.11.0,
`agentrust-trace-tests` 0.6.2 and `opentelemetry-sdk` 1.45.1 on Python 3.11, 3.12
and 3.13; the writer tests also on 3.9.

## Conformance CI

The repository-root workflow
[`.github/workflows/anthropic-tool-loop-conformance.yml`](../../.github/workflows/anthropic-tool-loop-conformance.yml)
(path-scoped to this directory) runs the writer tests on Python 3.9 with nothing
else installed, then on 3.11 to 3.13 installs the released packages, runs the
tests and the interop test, emits a record with the offline example, and runs
`trace-tests verify --level 0`.
