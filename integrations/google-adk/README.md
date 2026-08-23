# Google ADK to TRACE

Emits a TRACE v0.2 Trust Record from the released Google ADK `BasePlugin`
lifecycle. CI exercises Google ADK 2.7.1 through a real `InMemoryRunner` with a
deterministic local model, so the interoperability test makes no network call.

## Evidence boundary

The plugin runs inside the operator's ADK runner. Its records are first-party
evidence and carry no `origin` block. Without a hardware attestation they use
`runtime.platform: software-only`; building a record does not appraise it, so
`appraisal.status` is `none`.

| Observed from ADK | Supplied by the operator | Not claimed |
|---|---|---|
| Invocation id, model id, available tool name, function-call fingerprint, callback-visible lifecycle outcome | Model provider, workload identity and digest, policy bytes, data class | Prompts, responses, arguments, results, exception text, retries, agent graph, policy enforcement, whether a tool function body ran |

The model provider is operator-supplied because ADK can use models from more
than one provider. A single TRACE record has one model field, so an invocation
that exposes multiple model ids is refused rather than relabelled. A caller may
supply the model id only when ADK exposed none; it may not override an observed
id.

The plugin starts each run as `incomplete`. A successful `after_run` changes it
to `ok`; a reported run error changes it to `error`. A cancelled or interrupted
run that never reaches either callback remains `incomplete`. That is lifecycle
evidence, not a claim that ADK reported a cancellation reason.

Tool starts are retained in call order and correlated with completions through
ADK's function-call id. An unmatched start remains `incomplete`; an unmatched
completion is retained with `observed_start: false`. Neither case is silently
dropped. When an id is absent and more than one same-name start is pending, the
completion is retained as uncorrelated instead of being assigned by FIFO.

These are callback-visible outcomes. Another plugin can short-circuit a tool or
recover its exception. The adapter therefore does not claim that the function
body ran. If an error callback is followed by a recovered completion for the
same fingerprint, both outcomes are retained on one call and the final
callback-visible outcome is `ok`.

## Use it

```bash
pip install agentrust-trace google-adk==2.7.1
```

```python
from agentrust_trace.sign import generate_key, sign_record
from google.adk.apps import App
from google.adk.runners import InMemoryRunner
from google_adk_to_trace import GoogleAdkTracePlugin

plugin = GoogleAdkTracePlugin()
app = App(name="research_app", root_agent=agent, plugins=[plugin])
runner = InMemoryRunner(app=app)
await runner.run_debug("...", quiet=True)

invocation_id = plugin.invocation_ids[-1]
record = plugin.build_record(
    invocation_id,
    subject="spiffe://example.org/agent/research-bot",
    policy_bundle=open("policy.cedar", "rb").read(),
    workload_digest="sha256:...",
    data_class="internal",
    model_provider="google",
)
signed = sign_record(record, generate_key())
plugin.discard(invocation_id)
```

`enforcement_mode` defaults to `declared`: the policy is bound into the signed
record, but Google ADK itself did not evaluate it. Override that value only when
a separate enforcement layer actually evaluated the policy.

One plugin can observe concurrent invocations. It retains state by ADK
invocation id until `discard()` is called, so long-running processes should
discard an invocation after persisting its record.

## Tests

```bash
pip install -r requirements.txt pytest
python -m pytest test_google_adk_to_trace.py -q

pip install google-adk==2.7.1 agentrust-trace-tests==0.5.0
python -m pytest test_google_adk_interop.py -q
```

The first suite exercises evidence construction without installing ADK. The
second uses the released runner and checks success, tool failure, cancellation,
concurrent invocations, payload exclusion, signed TRACE validation, and Level 0
conformance for the optional externally enforced path. The bare ADK path keeps
the honest `declared` policy mode; `agentrust-trace-tests` 0.5.0 predates that
mode, so the conformance fixture uses `advisory` to represent an external layer.
