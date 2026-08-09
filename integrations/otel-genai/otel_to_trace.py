#!/usr/bin/env python3
"""OpenTelemetry GenAI spans -> TRACE v0.2 Trust Record.

Most runtime governance products do not publish a log or export schema. Nearly
all of them export OpenTelemetry. This adapter maps the published, vendor-neutral
`GenAI semantic conventions
<https://github.com/open-telemetry/semantic-conventions-genai>`_ instead of any
one vendor's private format, so a deployment can produce Trust Records from
whatever it already emits, without that vendor doing anything.

**What OTel spans are, as evidence.** Telemetry. Anything holding the collector
endpoint can write a span, spans are not signed, and an exporter reports what it
chose to report. Nothing here changes that, and the record says so: it carries
``origin.kind: log-import`` (or ``third-party-control-plane`` when the exporter
is itself the control plane), ``runtime.platform: software-only`` and
``appraisal.status: none``. A consumer can tell it apart from a TEE-backed record
by reading three fields.

**Conventions are pinned and unstable.** Every GenAI attribute is marked
Development, and the repository has published no tagged release. The attribute
names below were read at commit ``46d43c89`` (2026-08-09). Upstream renames are
expected; ``UNMAPPED_ATTRIBUTES`` exists so a rename shows up as an explicit
absence rather than as a record with a quietly missing field.

Usage:
    python otel_to_trace.py spans.json \\
        --subject spiffe://example.org/agent/support-bot \\
        --policy-bundle policy.cedar \\
        --workload-digest sha256:<64 hex> \\
        --jwk pubkey.jwk > record.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, Iterable

from agentrust_trace_adapters import MissingEvidence, PolicyEvidence, SourceSystem, build_record

# Pinned at the commit these were read from. Not a version: the repository has
# published no tagged release, and every attribute below is marked Development.
CONVENTIONS_COMMIT = "46d43c8949afb53765a202e89f4534eeb75ca3fa"
CONVENTIONS_URL = "https://github.com/open-telemetry/semantic-conventions-genai"

OPERATION = "gen_ai.operation.name"
PROVIDER = "gen_ai.provider.name"
REQUEST_MODEL = "gen_ai.request.model"
CONVERSATION_ID = "gen_ai.conversation.id"
AGENT_ID = "gen_ai.agent.id"
AGENT_NAME = "gen_ai.agent.name"
TOOL_NAME = "gen_ai.tool.name"
TOOL_CALL_ID = "gen_ai.tool.call.id"
TOOL_TYPE = "gen_ai.tool.type"

#: Attributes deliberately not mapped, and why. Read this before adding one.
UNMAPPED_ATTRIBUTES = {
    "gen_ai.tool.call.arguments": "payload, not provenance: hashing it into the "
    "transcript would put request content in an artifact meant to be shareable",
    "gen_ai.tool.call.result": "payload, same reason",
    "gen_ai.tool.definitions": "the tool roster belongs in an Agent Manifest, "
    "where it is signed at deploy time, not in a per-session record",
    "gen_ai.agent.description": "free text, unverifiable, no consumer keys on it",
    "gen_ai.agent.id": "a vendor-scoped string, not an identity a verifier can "
    "resolve. TRACE subject is a SPIFFE URI or DID and comes from the operator",
    "gen_ai.agent.name": "same reason as gen_ai.agent.id",
}


def _attrs(span: dict[str, Any]) -> dict[str, Any]:
    """Accept both a flat {"attributes": {...}} span and OTLP-JSON key/value lists."""
    raw = span.get("attributes", {})
    if isinstance(raw, dict):
        return raw
    flat: dict[str, Any] = {}
    for item in raw:
        value = item.get("value", {})
        flat[item.get("key")] = next(iter(value.values()), None) if isinstance(value, dict) else value
    return flat


def _transcript(tool_spans: list[dict[str, Any]]) -> bytes:
    """Canonical bytes over the tool calls, identity only.

    Name, call id and type: enough to say which tools ran, in what order, and to
    detect a changed sequence. Arguments and results are excluded on purpose (see
    ``UNMAPPED_ATTRIBUTES``); a Trust Record is meant to be handed to someone who
    should not thereby receive the payloads.
    """
    calls = []
    for span in tool_spans:
        a = _attrs(span)
        calls.append(
            {
                "tool": a.get(TOOL_NAME),
                "call_id": a.get(TOOL_CALL_ID),
                "type": a.get(TOOL_TYPE),
            }
        )
    return json.dumps(calls, sort_keys=True, separators=(",", ":")).encode()


def build_from_spans(
    spans: Iterable[dict[str, Any]],
    *,
    subject: str,
    policy_bundle: bytes,
    workload_digest: str,
    jwk: dict[str, Any],
    producer: str,
    data_class: str = "unclassified",
    origin_kind: str = "log-import",
) -> dict[str, Any]:
    """Map one session's GenAI spans onto a Trust Record.

    ``spans`` should be the spans of a single conversation. Mixing sessions would
    produce a record whose transcript describes several executions and whose
    subject names one, which is a record that is wrong rather than incomplete.
    """
    spans = list(spans)
    if not spans:
        raise MissingEvidence("no spans: there is no execution here to describe")

    conversations = {
        _attrs(s).get(CONVERSATION_ID) for s in spans if _attrs(s).get(CONVERSATION_ID)
    }
    if len(conversations) > 1:
        raise MissingEvidence(
            f"spans span {len(conversations)} conversations "
            f"({', '.join(sorted(map(str, conversations)))}). Group by "
            f"{CONVERSATION_ID} and build one record each: a record describes one "
            "execution."
        )

    tool_spans = [s for s in spans if _attrs(s).get(OPERATION) == "execute_tool"]

    provider = next((_attrs(s).get(PROVIDER) for s in spans if _attrs(s).get(PROVIDER)), None)
    model_id = next(
        (_attrs(s).get(REQUEST_MODEL) for s in spans if _attrs(s).get(REQUEST_MODEL)), None
    )
    if not provider or not model_id:
        missing = ", ".join(n for n, v in ((PROVIDER, provider), (REQUEST_MODEL, model_id)) if not v)
        raise MissingEvidence(
            f"no span carries {missing}. {REQUEST_MODEL} is only Conditionally Required "
            "in the conventions, so an exporter may legitimately omit it, and a record "
            "cannot name a model the telemetry never identified."
        )

    conversation = next(iter(conversations), None)

    return build_record(
        source=SourceSystem(
            producer=producer,
            kind=origin_kind,
            # The conversation id is the handle that traces this record back to
            # the telemetry it came from. The agent id is not: it identifies the
            # agent, not the event.
            source_event_id=conversation,
        ),
        subject=subject,
        model_provider=provider,
        model_id=model_id,
        policy=PolicyEvidence(bundle=policy_bundle),
        data_class=data_class,
        workload_digest=workload_digest,
        transcript_bytes=_transcript(tool_spans) if tool_spans else None,
        tool_call_count=len(tool_spans) if tool_spans else None,
        jwk=jwk,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("spans", help="JSON file: a list of GenAI spans for one conversation")
    ap.add_argument("--subject", required=True, help="spiffe:// or did: identity of the workload")
    ap.add_argument("--policy-bundle", required=True, help="File holding the policy bytes in force")
    ap.add_argument("--workload-digest", required=True, help="sha256:/sha384: digest of the artifact")
    ap.add_argument("--jwk", required=True, help="File holding the public confirmation key (JWK)")
    ap.add_argument("--producer", default="opentelemetry-genai", help="System that emitted the spans")
    ap.add_argument("--data-class", default="unclassified")
    ap.add_argument(
        "--origin-kind",
        default="log-import",
        choices=["log-import", "third-party-control-plane"],
        help="log-import for a telemetry export; third-party-control-plane when the "
        "exporter is itself the governance product",
    )
    args = ap.parse_args()

    payload = json.loads(pathlib.Path(args.spans).read_text())
    spans = payload.get("spans", payload) if isinstance(payload, dict) else payload

    try:
        record = build_from_spans(
            spans,
            subject=args.subject,
            policy_bundle=pathlib.Path(args.policy_bundle).read_bytes(),
            workload_digest=args.workload_digest,
            jwk=json.loads(pathlib.Path(args.jwk).read_text()),
            producer=args.producer,
            data_class=args.data_class,
            origin_kind=args.origin_kind,
        )
    except MissingEvidence as exc:
        print(f"cannot build a truthful record: {exc}", file=sys.stderr)
        return 2

    json.dump(record, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
