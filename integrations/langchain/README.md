# LangChain and LangGraph → TRACE

Emits a TRACE v0.2 Trust Record from LangChain callbacks, including callbacks
propagated through a LangGraph run, using the documented `BaseCallbackHandler`
surface.

## First-party, unlike the other adapters here

A callback handler runs **in the agent's own process**. What it observes is the operator's own agent, so the record carries **no `origin` block** — absence means `self`, and self is the truth.

That is a different thing from [`agentrust-trace-adapters`](../../packages/agentrust-trace-adapters), which transcribes *somebody else's* control-plane output and is therefore forced to `origin.kind: third-party-control-plane` and `runtime.platform: software-only`. Do not use that library here; it would label a first-party record as a third-party one.

Where the deployment runs inside a TEE, passing an attestation lifts the same record from Level 0 to Level 1 and nothing else about the call changes, the way the sandbox adapter in `agentrust-trace` works.

## Framework coverage and limits

| Runtime | What is exercised | What the record does not describe |
|---|---|---|
| LangChain | The released callback manager and tool lifecycle | Chain topology and intermediate runnable state |
| LangGraph | A released `StateGraph` with a nested LangChain tool call | Graph nodes, conditional edges, state transitions, checkpoints, and rollback decisions |

The LangGraph row is callback interoperability, not graph-native provenance.
CI exercises a tool callback propagated by a graph. Model callbacks use the
same LangChain handler surface, but the graph's state machine is not observed: a
run with no tool callback has no tool transcript, and this adapter must not be
cited as evidence of which edge ran or which state was restored. CI currently
pins LangChain Core 1.6.0 and LangGraph 1.2.11 for the interoperability
regression.

The module remains importable without LangChain installed so record construction
and the evidence rules can be tested independently. Framework callback support
requires `langchain-core`, as the installation command below states.

## Run it

```bash
pip install agentrust-trace langchain-core
```

Install `langgraph` as well when the handler is attached to a LangGraph run. The
same callback configuration is used by either framework:

```python
from langchain_to_trace import TraceCallbackHandler
from agentrust_trace.sign import generate_key, sign_record

handler = TraceCallbackHandler()
agent.invoke({"input": "..."}, config={"callbacks": [handler]})

record = handler.build_record(
    subject="spiffe://example.org/agent/research-bot",
    policy_bundle=open("policy.cedar", "rb").read(),
    # enforcement_mode defaults to "declared"; see below
    workload_digest="sha256:...",
    data_class="internal",
)
signed = sign_record(record, generate_key())
```

## `enforcement_mode` defaults to `declared`

**LangChain enforces no policy.** It has no policy engine, and this handler is an observer that cannot block anything. So the default is `declared`: the policy is named and bound into the signed record, and nothing evaluated it.

That value did not exist when this adapter was written. `enforce`, `advisory` and `silent` all presuppose that *something evaluated the policy*, so the adapter refused to default the field and made the caller pick a value that overstated their run. TRACE 0.9.0 added `declared` for exactly this case, and it needs `agentrust-trace>=0.9`.

| Value | When it is true here |
|---|---|
| `declared` | The default. The policy is named and bound; nothing evaluated it. |
| `enforce` | Only when a real enforcement layer (cMCP, a policy proxy) sat in front of the tools. |
| `advisory` | Only when something evaluated the policy and chose not to act on it. |
| `silent` | Only when something enforced it with the operational logs suppressed. |

## What is captured, and what is not

| In the record | From |
|---|---|
| Tool name, run id, parent run id, outcome (`ok` / `error`) | `on_tool_start`, `on_tool_end`, `on_tool_error` |
| Model provider and id | `invocation_params` on `on_chat_model_start` / `on_llm_start` |

**Payloads never enter the transcript.** `on_tool_start` receives `input_str` and `inputs`, `on_tool_end` receives the output, and `on_tool_error` receives the exception — none of it is hashed. A Trust Record exists to be handed to a third party, and handing over tool arguments defeats that. Two tests assert it: one puts an IBAN in a tool argument, another in an exception message, and neither appears in the transcript.

Three things come from the operator, because LangChain does not have them: the policy bundle bytes, the workload identity (`spiffe://` or `did:`), and the artifact digest.

## Two behaviours worth knowing

**A tool end with no matching start is recorded as `<unobserved-start>`, not dropped.** It means the handler was attached mid-run. A transcript that silently omits a call is worse than one that says it could not name it.

**Provider detection is best effort and always loses to the caller.** `ChatAnthropic` → `anthropic` is a class-name guess. Pass `model_provider` and `model_id` explicitly in production; a guessed provider is not model identity.

## Conformance

**Level 0** without an attestation, **Level 1** with one.

```bash
pip install agentrust-trace-tests
trace-tests report --record record.json --html report.html
```

## Tests

```bash
pip install -r requirements.txt pytest langchain-core==1.6.0 langgraph==1.2.11
python -m pytest test_langchain_to_trace.py test_langgraph_interop.py -q
```

24 tests: observation, payload exclusion, every refusal, a real LangGraph tool
run, and records parsed by the released `TrustRecord` model after signing.
