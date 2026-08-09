# LangChain → TRACE

Emits a TRACE v0.2 Trust Record from a LangChain run, using the documented `BaseCallbackHandler` surface.

## First-party, unlike the other adapters here

A callback handler runs **in the agent's own process**. What it observes is the operator's own agent, so the record carries **no `origin` block** — absence means `self`, and self is the truth.

That is a different thing from [`agentrust-trace-adapters`](../../packages/agentrust-trace-adapters), which transcribes *somebody else's* control-plane output and is therefore forced to `origin.kind: third-party-control-plane` and `runtime.platform: software-only`. Do not use that library here; it would label a first-party record as a third-party one.

Where the deployment runs inside a TEE, passing an attestation lifts the same record from Level 0 to Level 1 and nothing else about the call changes, the way the sandbox adapter in `agentrust-trace` works.

## Run it

```bash
pip install agentrust-trace langchain-core
```

```python
from langchain_to_trace import TraceCallbackHandler
from agentrust_trace.sign import generate_key, sign_record

handler = TraceCallbackHandler()
agent.invoke({"input": "..."}, config={"callbacks": [handler]})

record = handler.build_record(
    subject="spiffe://example.org/agent/research-bot",
    policy_bundle=open("policy.cedar", "rb").read(),
    enforcement_mode="advisory",     # no default; see below
    workload_digest="sha256:...",
    data_class="internal",
)
signed = sign_record(record, generate_key())
```

## The honest limit: `enforcement_mode` has no default here

**LangChain enforces no policy.** It has no policy engine, and this handler is an observer that cannot block anything. TRACE offers `enforce`, `advisory` and `silent`, and all three presuppose that *something evaluated the policy*. For a bare LangChain run, nothing did.

So the adapter refuses to choose. The caller passes a value knowingly, and the truthful reading of each is:

| Value | What it means here |
|---|---|
| `enforce` | **False** for a bare LangChain run. Only use it if a real enforcement layer (cMCP, a policy proxy) sat in front of the tools. |
| `advisory` | The closest available, and still an overstatement: it implies the policy was evaluated and not enforced. In a bare run it was neither. |
| `silent` | Implies enforcement with suppressed logging. Also not what happened. |

The gap is in the vocabulary, not in this adapter: TRACE has no value meaning *declared but never evaluated*. It is the same shape of ambiguity that `runtime.platform: "software-only"` had before the `origin` block, and it is worth a spec revision rather than a workaround here.

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
python -m pytest test_langchain_to_trace.py -q
```

21 tests: observation, payload exclusion, every refusal, and the record parsed by the real `TrustRecord` model after signing.
