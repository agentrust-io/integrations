# LlamaIndex → TRACE

Builds a first-party TRACE Trust Record from LlamaIndex tool observations.
There are two distinct event routes: legacy instrumentation and the per-run
workflow stream used by modern `FunctionAgent`. A global instrumentation
handler alone does **not** observe `FunctionAgent` tool requests.

## Modern FunctionAgent workflow

The released-framework tests exercise `llama-index-core==0.14.24`,
`llama-index-workflows==2.23.3`, and `llama-index-instrumentation==0.6.0`, with
`agentrust-trace==0.9.0` and `agentrust-trace-tests==0.5.1`. Exact test pins live
in [requirements-interop.txt](requirements-interop.txt).

Dependency-audit limitation: the tested environment resolves LlamaIndex's
transitive NLTK dependency to 3.10.3, affected by
[GHSA-8mgp-746c-j5xp](https://github.com/advisories/GHSA-8mgp-746c-j5xp),
with no patched release listed at verification time. These tests do not use
NLTK's affected model-file APIs. A passing interoperability run is not a clean
dependency-security audit; reassess dependencies for deployment.

Use a fresh tracker for each run and pass events from that run's stream to
`observe_workflow`. No global dispatcher registration is needed. Supply the
model's identity explicitly from your configured agent; a process-global model
observer could mix identities from concurrent runs.
Once any event is passed to `observe_workflow`, record construction requires
both explicit model fields, even for a run with no tool requests.

```python
from agentrust_trace.sign import sign_record
from llamaindex_to_trace import TraceEventHandler


async def run_with_record(
    agent, user_msg, *, subject, policy_bundle, workload_digest,
    model_provider, model_id, signing_key,
):
    tracker = TraceEventHandler()
    handler = agent.run(user_msg=user_msg)
    try:
        async for event in handler.stream_events():
            tracker.observe_workflow(event)
        result = await handler
    finally:
        if not handler.is_done():
            await handler.cancel_run()

    unsigned = tracker.build_record(
        subject=subject,
        policy_bundle=policy_bundle,       # bytes of the declared policy
        workload_digest=workload_digest,   # digest of your artifact
        model_provider=model_provider,
        model_id=model_id,
        data_class="internal",
    )
    return result, sign_record(unsigned, signing_key)
```

The caller supplies its own configured agent, identity, policy bytes, artifact
digest, and signing key. The offline tests supply a scripted local model and
real local tools; they need no provider account, API key, or network requests.
The stream has one consumer: if your application already processes it, call
`observe_workflow` in that existing loop rather than starting a second consumer.
The caller owns run cancellation and persistence. The adapter registers no
hooks or background tasks, and does not label partial/cancelled observations
as a successful run.

### What enters the workflow transcript

Each `ToolCall` contributes its `tool_name`, a SHA-256 fingerprint of `tool_id`
in the existing `event_id` field, and `span_id: null`. Workflow events do not
supply an instrumentation span. The call ID may be model-supplied, so its raw
text is not retained. Fingerprints support correlation, not authentication or
secrecy against guessing. Tool names remain visible metadata; do not put
sensitive content in names.

`ToolCallResult` and other events are ignored without reading their payloads.
Arguments, results, prompts, responses, and arbitrary future fields never enter
this transcript. One request plus one result counts once. Distinct requests
with a repeated call ID still count separately: model IDs are not guaranteed
unique. Replaying the stream is outside this observer's contract.

In the tested framework, `ToolCall` is emitted **before lookup and execution**.
The transcript therefore counts observed requests, including requests whose
tool is unavailable or fails. It does not prove function-body execution,
completion, business success, retry history, graph state, or exhaustive activity.
Only events the caller actually passes to this tracker are observed.

## Legacy instrumentation

Existing `AgentToolCallEvent` handling is preserved. `LLMChatStartEvent` and
`LLMCompletionStartEvent` can supply model identity through `model_dict`.
The framework-free tests continue to check this route's explicit field
allow-list. They do not establish support for every legacy LlamaIndex agent.

```python
from llama_index.core.instrumentation import get_dispatcher
from llama_index.core.instrumentation.event_handlers import BaseEventHandler
from llamaindex_to_trace import TraceEventHandler

tracker = TraceEventHandler()


class Bridge(BaseEventHandler):
    def handle(self, event, **kwargs):
        tracker.observe(event)


bridge = Bridge()
dispatcher = get_dispatcher()
dispatcher.add_event_handler(bridge)
try:
    # Run one legacy agent here, with no unrelated concurrent runs.
    ...
finally:
    dispatcher.event_handlers.remove(bridge)
```

Global instrumentation is not per-run isolation. Do not feed legacy tool events
and workflow tool requests into the same tracker: their identifiers cannot be
reliably deduplicated. The first tool event selects a source; an event from the
other source raises `MissingEvidence` before appending. Unknown event types
are not recorded. Workflow requests with missing/non-string identity fields are
also refused without retaining their values.

## Evidence boundary and conformance

These are in-process observations of the operator's own agent. Records have
no `origin` block (self), default to `runtime.platform: software-only`, and
retain `appraisal.status: none`. Signing binds the record to its signing key;
it does not attest the observer, authenticate model-supplied tool identity,
prove safe behavior, or establish hardware provenance or runtime integrity.

`policy.enforcement_mode` defaults to `declared`: the caller's policy is named
and hashed, but LlamaIndex has not evaluated or enforced it. Supplying another
mode requires an actual external policy layer. Supplied attestation fields are
passed through by the existing record builder; this adapter does not verify
them or independently establish Level 1 assurance.

The real `FunctionAgent` tests sign and verify records and pass the released
TRACE Level 0 conformance checks with the honest `declared` mode. Level 0
conformance does not raise this software-only evidence boundary.

## Reproduce

From the repository root in a fresh virtual environment:

```bash
pip install pytest==9.1.1 agentrust-trace==0.9.0
python -m pytest integrations/llamaindex/test_llamaindex_to_trace.py -q
pip install -r integrations/llamaindex/requirements-interop.txt
python -m pytest integrations/llamaindex -q
```

Or run `nox -s framework_adapters`, which preserves the framework-free pass
and then installs the pinned released frameworks. CI runs both routes too.
The real workflow regression is [test_llamaindex_interop.py](test_llamaindex_interop.py);
it uses the released runner and a local scripted `MockFunctionCallingLLM`, not
hand-constructed stand-ins for workflow delivery. Tests cover streaming and
non-streaming model responses, request order, error and no-tool paths,
concurrent run isolation, payload exclusion, and signed record validation.
