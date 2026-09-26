# OpenAI Agents SDK → TRACE

Emits a TRACE v0.2 Trust Record from the OpenAI Agents SDK's own tracing
callbacks, using the documented `agents.tracing.TracingProcessor` surface.

## First-party, unlike the transcription adapters

A `TracingProcessor` runs **in the agent's own process**. What it observes is the
operator's own agent, so records carry **no `origin` block**: absence means
`self`, and self is the truth.

This deliberately does not use
[`agentrust-trace-adapters`](../../packages/agentrust-trace-adapters), which
exists to transcribe somebody else's control-plane output and is therefore
forced to `origin.kind: third-party-control-plane` and
`runtime.platform: software-only`. Routing a first-party observation through it
would produce a worse description, not a safer one.

Where the deployment runs inside a TEE, passing an attestation lifts the same
record from Level 0 to Level 1 and nothing else about the call changes.

## `enforcement_mode` is required

The Agents SDK enforces no policy. Guardrails exist and can stop a run, but they
are the operator's own code, not a policy engine evaluating a bundle. So a bare
run is `declared`: the policy is named and bound into the signed record, and
nothing evaluated it. TRACE spec section 4.3 says `declared` MUST NOT be a
default, so the caller states it; leaving it out raises `TypeError`.

Pass another value only when a real enforcement layer sat in front of the tools. A
record claiming `enforce` from a bare Agents SDK run describes enforcement that
did not happen.

## What the transcript carries, and what it does not

Identity: which tools ran, in what order, their call ids, and whether each was a
function or an MCP tool. Handoffs are included too, because in a multi-agent run
the order tools fired is not the whole story: which agent was holding the run
matters to anyone reconstructing it.

`UNMAPPED_SPANS` is the authoritative list of what stays out:

| Span | Why |
|---|---|
| `GenerationSpanData` | Carries the full input and output message list. Model identity comes from the caller instead, which is the one thing here a verifier can check against a deployment |
| `FunctionSpanData.input` / `.output` | Tool arguments and results. The name and call id go in; what was passed does not |
| `GuardrailSpanData` | A guardrail is the operator's code, not a policy engine. Recording a tripwire as policy enforcement is the overclaim `declared` exists to prevent |
| `MCPListToolsSpanData` | The tool roster belongs in an Agent Manifest, signed at deploy time, not in a per-session record |

A Trust Record exists to be handed to a third party. Handing over tool arguments
defeats that, and there is a test that runs a real agent with a secret in the
tool input and asserts it does not appear anywhere in the record.

## Concurrency

The SDK can run agents concurrently. The processor keys everything by
`trace_id`, so two runs cannot interleave into one transcript. `build_record`
takes an optional `trace_id` to select which run; without it the most recently
completed one is used.

A record whose transcript describes several executions and whose subject names
one is wrong rather than incomplete.

## Run it

```bash
pip install agentrust-trace openai-agents
```

```python
from agents import Runner, add_trace_processor
from openai_agents_to_trace import TraceRecordProcessor
from agentrust_trace.sign import generate_key, sign_record

processor = TraceRecordProcessor()
add_trace_processor(processor)

Runner.run_sync(agent, "...")

record = processor.build_record(
    subject="spiffe://example.org/agent/support-bot",
    policy_bundle=open("policy.cedar", "rb").read(),
    enforcement_mode="declared",
    workload_digest="sha256:...",
    data_class="internal",
    model_provider="openai",     # the span that reports it is not read; see above
    model_id="gpt-5",
)
signed = sign_record(record, generate_key())
```

The module imports without `openai-agents` installed, so record construction and
the honesty rules can be tested independently of the framework.

## Coverage and limits

| Runtime | Exercised against the released SDK | Unit-tested only | Not described |
|---|---|---|---|
| Agents SDK | Tool calls, agent spans | Handoffs, MCP tool calls (the interop suite checks the span fields they use still exist) | Reasoning traces, guardrail outcomes, session state, retries |

`test_openai_agents_interop.py` runs a real released `Agent` with a real tool
through a real `TracingProcessor`, using a scripted model so no API key or
network is needed, and asserts the field names this adapter reads still exist. A
rename upstream fails there with a specific assertion rather than silently
producing an empty transcript.

## Tests

```bash
pip install -r requirements.txt pytest
python -m pytest test_openai_agents_to_trace.py -q

pip install openai-agents==0.22.3 agentrust-trace-tests==0.5.1
python -m pytest . -q
```

The first suite runs without the SDK. The second adds the interop tests. To check
conformance, write a signed record from a real run to `record.json` and run
`trace-tests verify --record record.json --level 0`; it passes. Level 1 fails on
`TR-RTE-001` and `TR-RTE-004`, because nothing here carries a hardware
attestation.
