# Demo 4: context-aware enforcement

**Duration:** ~90 seconds

Demo 1 gates on the tool's identity: which tools may be called at all. This demo gates on the **context of the call**. The same capability is permitted inside one workflow and denied inside another. The agent cannot widen its own authority by restating its intent, because cMCP evaluates the declared workflow context, it does not trust the model.

## Run

```bash
python demo-04-context-enforcement/run.py   # cross-platform
# or, bash only:
bash demo-04-context-enforcement/run.sh
```

## What to show the audience

Three calls go through the gateway in one session:

1. `write_file` under `workflow_id="invoice-run"` — **allowed**. The Cedar `permit` for `WriteFile` is guarded by `context.workflow_id == "invoice-run"`.
2. The **identical** `write_file`, same arguments, under `workflow_id="chat-freeform"` — **denied, HTTP 403**. No `permit` matches `WriteFile` outside `invoice-run`, so Cedar's default-deny holds. Same tool, same payload, different context, different decision.
3. `read_file` under `workflow_id="chat-freeform"` — **allowed**. Reads are permitted in any workflow, so the point is not that the second workflow is blocked wholesale; only the write capability is scoped.

Then the session closes into a signed TRACE claim. Both the allow and the deny are committed to the hash-chained audit log under the same `policy.bundle_hash`, so you can prove which policy decided each call.

## Why it matters

"Trust the LLM to only write when it's supposed to" is not a control. Here the write authority is bound to a declared workflow and enforced before the call leaves the environment. A model that changes its stated intent does not change what it is allowed to do.

## Policy

`policies/workflow-scoped.cedar`:

- `ReadFile` — permitted for any principal, any workflow.
- `WriteFile` — permitted only `when { context.workflow_id == "invoice-run" }`.

The runtime maps `tool_name` to a PascalCase Cedar action (`write_file` → `Action::"WriteFile"`) and places call context (`workflow_id`, `compliance_domain`, `baa_covered`, `session_max_sensitivity`) on `context`. The agent supplies `workflow_id` per call via the `_cmcp` field; see `call.py`.

Runs in software-only mode with `CMCP_DEV_MODE=1`; no hardware required. On real TDX the policy bundle hash flows into RTMR[2] at startup exactly as in demo 1.
