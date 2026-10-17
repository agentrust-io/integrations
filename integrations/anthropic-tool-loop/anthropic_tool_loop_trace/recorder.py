"""Turn spool rows into AgenTrust Telemetry events, optional OpenTelemetry spans, and one signed
TRACE record per finished run.

Runs out of process (a sidecar, a cron job, or the same host on a timer) and needs Python 3.11+,
agentrust-telemetry and agentrust-trace. OpenTelemetry is optional: pass a TracerProvider to get
spans with the real start and end times of each model round and tool call.

Per finished run it emits, in order of the observed timeline:

    policy.decision     one run-level decision for the toolset offered to the model, then one per
                        tool call carrying the caller's gate verdict and reason code
    action.executed     one per tool call, bound to its policy decision
    usage.recorded      one per model round, plus an agent_run rollup
    data_flow.observed  one per successful tool call (read or write, classified by the caller's
                        catalog), plus one agent -> model-provider flow marked not_evaluated,
                        because nothing evaluated what was sent to the model

The events are chained by an EvidenceAccumulator and sealed. A complete run is finalized into a
TRACE v0.2 record (origin.kind "log-import") and signed. A run that never wrote run.end is sealed
"incomplete" and is not signed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from agentrust_telemetry import (
    EventFactory,
    EvidenceAccumulator,
    SchemaValidator,
    TelemetryClient,
    TraceConfiguration,
    UsageAccumulator,
    finalize_trace,
)
from agentrust_trace import jwk_thumbprint, key_to_jwk, verify_record

from . import __version__
from .catalog import ToolCatalog

try:  # optional: spans are produced only when a TracerProvider is passed
    from opentelemetry import trace as _otel
except ImportError:  # pragma: no cover - exercised only without the SDK installed
    _otel = None

__all__ = ["Recorder", "verify", "source_digest", "PRODUCER"]

PRODUCER = "anthropic-tool-loop-trace"
RUN_ID_RE = re.compile(r"^run-[0-9a-f]{32}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_KINDS = {"run.start", "model.call", "tool.call", "run.end"}
_log = logging.getLogger("anthropic_tool_loop_trace.recorder")


def source_digest(root: str | os.PathLike, pattern: str = "*.py") -> str:
    """sha256 over every file matching `pattern` under `root` (relative path + bytes, sorted).

    Use it for build_digest (your agent's code) or policy_bundle_digest (your gate code)."""
    root = Path(root)
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob(pattern) if "__pycache__" not in p.parts):
        h.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes() + b"\0")
    return "sha256:" + h.hexdigest()


def verify(record: dict, public_jwk: dict) -> dict:
    """Check a stored TRACE record's signature and structure. Never raises."""
    try:
        result = verify_record(record, public_jwk, max_age_seconds=None)
        return {"ok": True, "profile": getattr(result, "profile", None)}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__}


def _day(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d")


class _EvidenceStore:
    """Append-only JSONL per UTC day, fsynced, idempotent by event id."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.seen: set[str] = set()

    def append(self, entry) -> bool:
        if entry.event_id in self.seen:
            return True
        path = self.root / f"{_day(int(entry.event['time_unix_nano']))}.jsonl"
        row = {"run_id": entry.event["run_id"], "sequence": entry.sequence, "event_id": entry.event_id,
               "previous_digest": entry.previous_digest, "digest": entry.digest, "event": entry.event}
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self.seen.add(entry.event_id)
        return True


@dataclass
class Recorder:
    """Reads the spool, records finished runs, keeps its read position across restarts.

    spool, data_dir:        where the agent writes rows; where records, evidence and state go.
    signing_key:            Ed25519 private key (agentrust_trace.load_key / generate_key).
    catalog:                your ToolCatalog.
    enforcement_mode:       "enforce" if your gates block denied calls, "monitor" if they only
                            observe, "disabled" if there is no gate (TRACE records "declared").
                            Required: there is no safe default.
    policy_bundle_digest:   "sha256:<hex>" of the gate code or policy that made the decisions.
    build_digest:           "sha256:<hex>" of the agent build that produced the run.
    prompt_classification:  what class of data your prompts carry. The recorder cannot see them,
                            so you state it; the model-provider flow is at least this class.
    appraisal_verifier:     a URI naming who appraised the record (e.g. your ledger's URL).
                            Defaults to urn:anthropic-tool-loop-trace:<producer_instance_id>.
    """

    spool: str | os.PathLike
    data_dir: str | os.PathLike
    signing_key: Any
    catalog: ToolCatalog
    enforcement_mode: Literal["enforce", "monitor", "disabled"]
    policy_bundle_digest: str
    build_digest: str
    prompt_classification: str
    policy_engine: str = "application-gates"
    producer_instance_id: str | None = None
    appraisal_verifier: str | None = None
    tracer_provider: Any = None
    idle_seconds: int = 1200
    prices: dict[str, tuple[float, float, float, float]] | None = None
    pricing_version: str | None = None

    def __post_init__(self):
        if self.enforcement_mode not in ("enforce", "monitor", "disabled"):
            raise ValueError("enforcement_mode must be enforce, monitor or disabled")
        for name in ("policy_bundle_digest", "build_digest"):
            if not DIGEST_RE.match(getattr(self, name) or ""):
                raise ValueError(f"{name} must look like sha256:<64 hex>")
        if self.prompt_classification not in self.catalog.order:
            raise ValueError("prompt_classification is not in the catalog's order")
        if self.prices and not self.pricing_version:
            raise ValueError("pricing_version is required with prices")
        self.spool = Path(self.spool).expanduser()
        self.data_dir = Path(self.data_dir).expanduser()
        (self.data_dir / "records").mkdir(parents=True, exist_ok=True)
        self._state_path = self.data_dir / "state.json"
        self._index_path = self.data_dir / "index.jsonl"
        self._validator = SchemaValidator.bundled()
        self._factory = EventFactory(self._validator, producer_name=PRODUCER, producer_version=__version__,
                                     producer_instance_id=self.producer_instance_id)
        self._evidence = _EvidenceStore(self.data_dir / "evidence")
        self.public_jwk = {k: v for k, v in key_to_jwk(self.signing_key).items() if k != "d"}
        self.key_thumbprint = jwk_thumbprint(self.public_jwk)
        self._tracer = None
        if self.tracer_provider is not None:
            if _otel is None:
                raise ValueError("tracer_provider given but opentelemetry-api is not installed")
            self._tracer = self.tracer_provider.get_tracer(PRODUCER, __version__)
        self._lock = threading.Lock()
        saved = json.loads(self._state_path.read_text()) if self._state_path.exists() else {}
        self.offset = int(saved.get("offset", 0))
        self.pending: dict[str, list[dict]] = saved.get("pending", {})

    # -- spool -----------------------------------------------------------------------------
    def _save_state(self):
        tmp = self._state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"offset": self.offset, "pending": self.pending}))
        os.replace(tmp, self._state_path)

    def poll(self, final: bool = False) -> list[str]:
        """Read new spool rows and record every run that ended, or went idle, or (final=True)
        everything still pending. Returns the run ids recorded."""
        done: list[str] = []
        if self.spool.exists():
            if self.spool.stat().st_size < self.offset:  # rotated or truncated
                self.offset = 0
            with self.spool.open("rb") as fh:
                fh.seek(self.offset)
                chunk = fh.read()
            usable = chunk[: chunk.rfind(b"\n") + 1]  # never consume a half-written line
            self.offset += len(usable)
            sealed: dict[str, bool] = {}
            for raw in usable.splitlines():
                try:
                    row = json.loads(raw)
                except ValueError:
                    continue
                run_id = row.get("run_id") if isinstance(row, dict) else None
                if not isinstance(run_id, str) or not RUN_ID_RE.match(run_id) or row.get("kind") not in _KINDS:
                    continue
                if run_id not in self.pending:
                    if run_id not in sealed:
                        sealed[run_id] = self._record_path(run_id) is not None
                    if sealed[run_id]:
                        continue  # already recorded; a late row cannot reopen a record
                self.pending.setdefault(run_id, []).append(row)
        now = time.time_ns()
        for run_id, rows in list(self.pending.items()):
            ended = any(r["kind"] == "run.end" for r in rows)
            last = max(int(r.get("end") or r.get("t") or 0) for r in rows)
            if ended or final or now - last > self.idle_seconds * 1_000_000_000:
                try:
                    self.record(rows, complete=ended)
                except Exception:
                    _log.exception("recording %s failed; its rows are dropped", run_id)
                done.append(run_id)
                del self.pending[run_id]
        self._save_state()
        return done

    # -- reads -----------------------------------------------------------------------------
    def _record_path(self, run_id: str) -> Path | None:
        return next(iter(sorted((self.data_dir / "records").glob(f"*/{run_id}.json"))), None)

    def run(self, run_id: str) -> dict | None:
        """The stored {"run", "events", "trace"} for a run id, or None."""
        if not RUN_ID_RE.match(run_id or ""):
            return None
        path = self._record_path(run_id)
        return json.loads(path.read_text()) if path else None

    def verify(self, record: dict) -> dict:
        return verify(record, self.public_jwk)

    # -- recording -------------------------------------------------------------------------
    def _cost(self, row: dict) -> float | None:
        price = (self.prices or {}).get(row["model"])
        if not price:
            return None
        p_in, p_out, p_read, p_write = price
        return round((row["input"] * p_in + row["output"] * p_out + row["cache_read"] * p_read
                      + row["cache_write"] * p_write) / 1_000_000, 6)

    def record(self, rows: list[dict], complete: bool) -> dict:
        with self._lock:
            return self._record(rows, complete)

    def _record(self, rows: list[dict], complete: bool) -> dict:
        rows = sorted(rows, key=lambda r: int(r.get("start") or r.get("t") or 0))
        start = next((r for r in rows if r["kind"] == "run.start"), None)
        end = next((r for r in rows if r["kind"] == "run.end"), None)
        models = [r for r in rows if r["kind"] == "model.call"]
        tools = [r for r in rows if r["kind"] == "tool.call"]
        complete = bool(complete and start and end)
        run_id = rows[0]["run_id"]
        agent_id = (start or {}).get("agent_id") or "unknown-agent"
        agent_name = (start or {}).get("agent_name") or "unknown"
        model = (start or {}).get("model") or (models[0]["model"] if models else "unknown")
        workflow_id = (start or {}).get("workflow_id")
        t_start = int((start or {}).get("t") or min(int(r.get("start") or r.get("t")) for r in rows))
        t_end = int((end or {}).get("t") or max(int(r.get("end") or r.get("t") or t_start) for r in rows))
        common = {"run_id": run_id, "agent_id": agent_id}
        if workflow_id:
            common["workflow_id"] = workflow_id
        cat = self.catalog
        bundle = {"algorithm": "sha256", "value": self.policy_bundle_digest[7:]}
        policy_base = {"engine": self.policy_engine, "engine_version": self.policy_bundle_digest[7:19],
                       "bundle_digest": bundle}

        events: list[dict] = []
        current = {"span": None}
        accumulator = EvidenceAccumulator(run_id, self._validator, durable_append=self._evidence.append)
        client = TelemetryClient(self._validator, span_resolver=lambda: current["span"],
                                 evidence_sink=accumulator)
        usage = UsageAccumulator(self._validator)
        otel = _otel
        def ids(span):
            if span is None:
                return {}
            c = span.get_span_context()
            return {"trace_id": f"{c.trace_id:032x}", "span_id": f"{c.span_id:016x}"}

        def emit(span, event_type, at_ns, **payload):
            event = self._factory.build(event_type, **common, **ids(span), time_unix_nano=int(at_ns), **payload)
            current["span"] = span
            client.emit(event)
            events.append(event)
            return event

        def start_span(name, at_ns, attributes, parent=None):
            if self._tracer is None:
                return None
            return self._tracer.start_span(name, context=parent, start_time=int(at_ns), attributes=attributes)

        root = start_span(f"invoke_agent {agent_name}", t_start, {
            "gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": agent_name,
            "gen_ai.agent.id": agent_id, "gen_ai.provider.name": "anthropic",
            "gen_ai.request.model": model, "agentrust.run_id": run_id})
        ctx = otel.set_span_in_context(root) if root is not None else None

        # Run-level decision: the toolset offered to the model. It is the policy decision every run
        # has, so a run with no tool calls still carries policy evidence and can be signed.
        toolset = (start or {}).get("toolset") or []
        emit(root, "policy.decision", t_start, decision="allow", action_type="agent.invoke",
             resource_type="toolset", enforcement_mode=self.enforcement_mode, evaluation_duration_ns=0,
             policy={**policy_base, "policy_id": "toolset",
                     "input_digest": {"algorithm": "sha256",
                                      "value": hashlib.sha256(json.dumps(sorted(toolset)).encode()).hexdigest()}})

        summary_tools, read_classes = [], []
        tokens = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
        cost_total, priced = 0.0, True
        for row in sorted(models + tools, key=lambda r: int(r["start"])):
            if row["kind"] == "model.call":
                span = start_span(f"chat {row['model']}", row["start"], {
                    "gen_ai.operation.name": "chat", "gen_ai.provider.name": "anthropic",
                    "gen_ai.request.model": row["model"], "gen_ai.usage.input_tokens": row["input"],
                    "gen_ai.usage.output_tokens": row["output"],
                    "gen_ai.usage.cache_read.input_tokens": row["cache_read"],
                    "gen_ai.usage.cache_creation.input_tokens": row["cache_write"],
                    "gen_ai.response.finish_reasons": [str(row.get("stop_reason") or "")],
                    "agentrust.round": row["round"]}, ctx)
                payload = {"scope": "model_call", "operation": "chat", "provider": "anthropic",
                           "request_model": row["model"] or model, "input_tokens": row["input"],
                           "output_tokens": row["output"], "cache_read_tokens": row["cache_read"],
                           "cache_write_tokens": row["cache_write"]}
                amount = self._cost(row)
                if amount is not None:
                    payload["cost"] = {"amount": amount, "currency": "USD", "source": "estimate",
                                       "pricing_version": self.pricing_version}
                    cost_total += amount
                else:
                    priced = False
                usage.add(emit(span, "usage.recorded", row["end"], **payload))
                for k in tokens:
                    tokens[k] += row[k]
                if span is not None:
                    span.end(end_time=int(row["end"]))
                continue

            tool = row["tool"]
            info = cat.lookup(tool)
            write = cat.is_write(tool, row.get("action"))
            span = start_span(f"execute_tool {tool}", row["start"], {
                "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tool,
                "gen_ai.tool.call.id": row["tool_use_id"], "agentrust.policy": row["policy"],
                "agentrust.decision": row["decision"], "agentrust.outcome": row["outcome"],
                "agentrust.system": info.system, "agentrust.write": write, "agentrust.round": row["round"]}, ctx)
            gate_ns = int(row.get("gate_ns") or 0)
            policy = emit(span, "policy.decision", int(row["start"]) + gate_ns, decision=row["decision"],
                          action_type=f"{info.system}.{'write' if write else 'read'}",
                          resource_type=info.system, enforcement_mode=self.enforcement_mode,
                          evaluation_duration_ns=gate_ns,
                          policy={**policy_base, "policy_id": row["policy"],
                                  "input_digest": {"algorithm": "sha256", "value": row["input_digest"]}},
                          **({"reason_codes": [row["reason"]]} if row.get("reason") else {}))
            action = {"action_id": row["tool_use_id"], "action_kind": "tool", "action_name": tool,
                      "operation": row.get("action") or ("write" if write else "read"),
                      "outcome": row["outcome"], "duration_ns": max(0, int(row["end"]) - int(row["start"])),
                      "action_digest": {"algorithm": "sha256", "value": row["input_digest"]},
                      "target": {"kind": info.kind, "id": info.system}, "policy_event_id": policy["event_id"]}
            if row.get("error_type"):
                action["error_type"] = row["error_type"]
            emit(span, "action.executed", row["end"], **action)
            if row["outcome"] == "success" and not row.get("tool_error"):
                me, there = {"kind": "agent", "id": agent_id}, {"kind": info.kind, "id": info.system}
                emit(span, "data_flow.observed", row["end"], direction="write" if write else "read",
                     source=me if write else there, destination=there if write else me,
                     classification={"taxonomy": cat.taxonomy, "value": info.classification,
                                     "producer": f"{PRODUCER} tool catalog"},
                     purpose=f"tool call ({agent_name})", policy_decision=row["decision"], transformation="none")
                if not write:
                    read_classes.append(info.classification)
            if span is not None:
                if row["outcome"] != "success":
                    span.set_status(otel.Status(otel.StatusCode.ERROR,
                                                f"{row['outcome']}: {row.get('reason') or row.get('error_type') or ''}"))
                span.end(end_time=int(row["end"]))
            summary_tools.append({"tool": tool, "action": row.get("action"), "system": info.system,
                                  "write": write, "classification": info.classification,
                                  "outcome": row["outcome"], "decision": row["decision"], "policy": row["policy"],
                                  "reason": row.get("reason"), "error_type": row.get("error_type"),
                                  "tool_error": bool(row.get("tool_error")), "round": row["round"],
                                  "start": row["start"], "ms": round((int(row["end"]) - int(row["start"])) / 1e6, 1)})

        # What went to the model provider: the prompt (classified by the caller) plus everything the
        # tools read, which the loop hands back to the model. Nothing evaluated that flow.
        sent_class = cat.highest(read_classes + [self.prompt_classification])
        if models:
            emit(root, "data_flow.observed", t_end, direction="send",
                 source={"kind": "agent", "id": agent_id}, destination={"kind": "model-provider", "id": "anthropic"},
                 classification={"taxonomy": cat.taxonomy, "value": sent_class,
                                 "producer": f"{PRODUCER} tool catalog"},
                 purpose="inference", policy_decision="not_evaluated", transformation="none")
            rollup = usage.rollup(self._factory, scope="agent_run", run_id=run_id, operation="invoke_agent",
                                  agent_id=agent_id, workflow_id=workflow_id)
            rollup = {**rollup, **common, **ids(root), "time_unix_nano": str(t_end)}
            self._validator.validate(rollup)
            current["span"] = root
            client.emit(rollup)
            events.append(rollup)

        if root is not None:
            root.set_attribute("agentrust.complete", complete)
            root.set_attribute("agentrust.tool_calls", len(tools))
            if any(t["outcome"] == "denied" for t in summary_tools):
                root.set_status(otel.Status(otel.StatusCode.ERROR, "a gate denied a tool call"))
            root.end(end_time=t_end)

        snapshot = accumulator.seal(completeness="complete" if complete else "incomplete")
        record, trace_error = None, None
        if complete:
            try:
                record = finalize_trace(snapshot, TraceConfiguration(
                    subject=agent_id, model_provider="anthropic", model_id=model, build_digest=self.build_digest,
                    origin_kind="log-import", origin_producer=f"{PRODUCER}/{__version__}",
                    appraisal_verifier=self.appraisal_verifier
                    or f"urn:{PRODUCER}:{self.producer_instance_id or 'recorder'}",
                    classification_taxonomy=cat.taxonomy, classification_order=cat.order),
                    signing_key=self.signing_key)
            except Exception as exc:
                trace_error = f"{type(exc).__name__}: {exc}"
        else:
            trace_error = "run never finished (no run.end): evidence sealed incomplete, not signed"

        summary = {
            "run_id": run_id, "agent_id": agent_id, "agent_name": agent_name, "workflow_id": workflow_id,
            "model": model, "start": t_start, "end": t_end, "duration_ms": round((t_end - t_start) / 1e6),
            "stop": (end or {}).get("stop") or "unfinished", "rounds": len(models), "tool_calls": len(tools),
            "denies": sum(t["outcome"] == "denied" for t in summary_tools),
            "errors": sum(t["outcome"] == "error" or t["tool_error"] for t in summary_tools),
            "writes": sum(t["write"] and t["outcome"] == "success" for t in summary_tools),
            "systems": sorted({t["system"] for t in summary_tools}), "tokens": tokens,
            "toolset_size": len(toolset),
            "cost_usd": round(cost_total, 6) if priced and models and self.prices else None,
            "data_class": record["data_class"] if record else sent_class,
            "sent_to_model": sent_class if models else None,
            "verdict": record["appraisal"]["status"] if record else "unsigned",
            "signed": record is not None, "complete": complete, "trace_error": trace_error,
            "otel_trace_id": ids(root).get("trace_id"), "events": len(events),
            "evidence_chain": snapshot.chain_digest, "build": self.build_digest, "tools": summary_tools,
        }
        out = self.data_dir / "records" / _day(t_start)
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{run_id}.json").write_text(json.dumps(
            {"run": summary, "events": events, "trace": record}, indent=1, default=str))
        with self._index_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({k: v for k, v in summary.items() if k != "tools"}, default=str) + "\n")
        return summary
