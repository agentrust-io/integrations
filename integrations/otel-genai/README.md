# OpenTelemetry GenAI → TRACE

Builds a TRACE Trust Record from [OpenTelemetry GenAI semantic convention](https://github.com/open-telemetry/semantic-conventions-genai) spans.

## Why this rather than a per-vendor adapter

Most runtime governance products do not publish a log or export schema. Nearly all of them export OpenTelemetry. Mapping the published, vendor-neutral conventions covers any of them without that vendor documenting anything or agreeing to anything, and without anyone reverse-engineering a private format from a trial account.

## What the record claims

OTel spans are **telemetry**. Anything holding the collector endpoint can write one, spans are not signed, and an exporter reports what it chose to report. Nothing here changes that, and the record says so in fields a consumer can key on:

| Field | Value |
|---|---|
| `origin.kind` | `log-import`, or `third-party-control-plane` with `--origin-kind` when the exporter *is* the governance product |
| `origin.producer` | the system that emitted the spans |
| `origin.source_event_id` | `gen_ai.conversation.id`, so the record traces back to the telemetry |
| `runtime.platform` | `software-only` |
| `appraisal.status` | `none` |

A record built here is evidence that a session was *reported* a certain way. It is not evidence that the session happened that way. That distinction is the whole reason the `origin` block exists.

## Run it

```bash
pip install agentrust-trace-adapters

python otel_to_trace.py spans.json \
  --subject spiffe://example.org/agent/support-bot \
  --policy-bundle policy.cedar \
  --workload-digest sha256:<64 hex> \
  --jwk pubkey.jwk > record.json
```

`spans.json` is the spans of **one** conversation, either as flat `{"attributes": {...}}` objects or as OTLP-JSON key/value lists. Spanning two `gen_ai.conversation.id` values is refused: a record describes one execution, and merging two would be wrong rather than incomplete.

Three inputs come from the operator, because telemetry does not carry them: the policy bundle bytes, the workload identity, and the artifact digest. See the [library README](../../packages/agentrust-trace-adapters) for why those are required rather than defaulted.

## What is mapped

| TRACE field | From |
|---|---|
| `model.provider` | `gen_ai.provider.name` |
| `model.model_id` | `gen_ai.request.model` |
| `origin.source_event_id` | `gen_ai.conversation.id` |
| `tool_transcript.hash` | canonical digest over each `execute_tool` span's `gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.tool.type` |
| `tool_transcript.call_count` | number of `execute_tool` spans |

## Pydantic AI interoperability

Pydantic AI needs no dedicated adapter: its instrumentation emits OpenTelemetry
GenAI spans that this adapter already accepts. CI pins Pydantic AI 2.35.1 and
runs a released `Agent` with a `TestModel` and a real tool call, without network
access.

The result remains a telemetry transcription, with `origin.kind: log-import`
and `appraisal.status: none`. The interoperability test also records the current
boundary: Pydantic AI does not emit `gen_ai.tool.type`, so the transcript leaves
that value unset. It emits `gen_ai.agent.call.id` where the conventions define
`gen_ai.agent.id`; neither is used as the TRACE subject identity. Tool arguments,
tool results, and input and output messages are emitted by default and remain
excluded as payloads.

## What is deliberately not mapped

`gen_ai.tool.call.arguments` and `gen_ai.tool.call.result` are **payloads**. Hashing them into the transcript would put request and response content into an artifact whose purpose is being handed to a third party. A test asserts that a span carrying an IBAN in its arguments produces the same transcript hash as one without, so the exclusion cannot regress silently.

`gen_ai.tool.definitions` is the tool roster, which belongs in an Agent Manifest where it is signed at deploy time, not in a per-session record.

`gen_ai.agent.id` and `gen_ai.agent.name` are vendor-scoped strings, not identities a verifier can resolve. TRACE `subject` is a SPIFFE URI or a DID and comes from the operator.

Each exclusion is recorded with its reason in `UNMAPPED_ATTRIBUTES` in the adapter, so adding one is a deliberate act.

## Convention stability

Every GenAI attribute is marked **Development**, and the conventions repository has published no tagged release. The attribute names here were read at commit [`46d43c89`](https://github.com/open-telemetry/semantic-conventions-genai/commit/46d43c8949afb53765a202e89f4534eeb75ca3fa) on 2026-08-09 and are pinned in the source as `CONVENTIONS_COMMIT`.

Upstream renames should be expected. The adapter **refuses rather than guessing** when an attribute it needs is absent: `gen_ai.request.model` is only Conditionally Required upstream, so a missing model raises with the attribute name rather than producing a record that names no model. A rename therefore surfaces as a clear failure instead of a quietly incomplete record.

## Conformance

**Level 0.** No hardware attestation and no claim of any.

```bash
pip install agentrust-trace-tests
trace-tests verify --record record.json --level 0
```

## Tests

```bash
pip install agentrust-trace-adapters pytest
python -m pytest test_otel_to_trace.py -q
```

14 tests: the mapping, the refusals, OTLP-JSON parsing, transcript determinism and order-sensitivity, and the payload exclusion.
