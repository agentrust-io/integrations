# LlamaIndex → TRACE

Emits a TRACE v0.2 Trust Record from LlamaIndex instrumentation events.

## First-party, like the LangChain adapter

A `BaseEventHandler` runs in the agent's own process, so what it observes is the operator's own agent. The record carries **no `origin` block** — absence means `self`. It does not use [`agentrust-trace-adapters`](../../packages/agentrust-trace-adapters), which exists for *somebody else's* evidence and would mislabel this as a third-party transcription.

## The risk here is different from LangChain's

LangChain has a dozen typed callbacks. LlamaIndex has **one method** — `handle(event)` — and several event types carry payloads:

| Event | Payload it carries |
|---|---|
| `AgentToolCallEvent` | `arguments` |
| `LLMChatStartEvent` | the whole `messages` list |
| `LLMCompletionEndEvent` | `prompt` and `response` |

One entry point is easier to consume and harder to consume *safely*. So this handler reads an **explicit allow-list of fields** rather than the event object: tool name, event id, span id, and `model_dict` for identity. Nothing else is read, which means a payload-bearing field added upstream in a future version is ignored by default rather than captured.

Four tests hold that line: an IBAN in tool `arguments`, an IBAN in chat `messages`, an IBAN in a field a later version might add, and an entire unrelated event type carrying prompt and response.

## Run it

```bash
pip install agentrust-trace llama-index-core
```

```python
from llama_index.core.instrumentation import get_dispatcher
from llama_index.core.instrumentation.event_handlers import BaseEventHandler
from llamaindex_to_trace import TraceEventHandler

tracker = TraceEventHandler()

class Bridge(BaseEventHandler):
    def handle(self, event, **kwargs):
        tracker.observe(event)

get_dispatcher().add_event_handler(Bridge())
# ... run your agent ...

record = tracker.build_record(
    subject="spiffe://example.org/agent/index-bot",
    policy_bundle=open("policy.cedar", "rb").read(),
    enforcement_mode="advisory",   # no default; see below
    workload_digest="sha256:...",
    data_class="internal",
)
```

## `enforcement_mode` has no default

**LlamaIndex enforces no policy.** TRACE offers `enforce`, `advisory` and `silent`, and all three presuppose that something *evaluated* the policy. For a bare run, nothing did, and TRACE has no value meaning *declared but never evaluated*. The adapter refuses to choose; `advisory` is the closest and still an overstatement. Same gap the LangChain adapter documents.

## Conformance

**Level 0** without an attestation, **Level 1** with one.

```bash
python -m pytest test_llamaindex_to_trace.py -q
```

20 tests.
