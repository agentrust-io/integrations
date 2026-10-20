"""In-process spool writer for an Anthropic Messages API tool loop.

Standard library only and importable on Python 3.9, so it can sit inside an
existing agent without adding dependencies. Every method is fail-open: a spool
problem logs one warning and never raises into the agent's reply path.

Rows are metadata only. No prompt, reply, tool argument or tool result is
written. A row carries names, counts, timings, the caller's gate decision, and a
sha256 digest of each tool input, so a later audit can show which exact call ran
without the call's content leaving the process.

Row kinds, one JSON object per line:

    run.start   agent id/name, requested model, toolset, optional workflow id
    model.call  one per messages.create round: model, token usage, stop reason
    tool.call   one per tool_use block: decision, outcome, input digest, timings
    run.end     why the loop stopped
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid

__all__ = ["Run", "digest", "default_spool_path", "SPOOL_ENV"]

SPOOL_ENV = "AGENTRUST_ANTHROPIC_SPOOL"
_LOCK = threading.Lock()
_VERB_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_CODE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_log = logging.getLogger("anthropic_tool_loop_trace")


def default_spool_path() -> str:
    """$AGENTRUST_ANTHROPIC_SPOOL, else ~/.local/state/agentrust/anthropic-spool.jsonl."""
    return os.environ.get(SPOOL_ENV) or os.path.expanduser(
        "~/.local/state/agentrust/anthropic-spool.jsonl"
    )


def digest(value) -> str:
    """sha256 over canonical JSON (sorted keys, no whitespace). Same input, same digest."""
    try:
        blob = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        blob = repr(value)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _get(obj, name, default=None):
    """Read a field from an SDK object or a plain dict."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _code(value):
    """A reason code or policy id: short and token-shaped, never free text."""
    if value is None:
        return None
    value = str(value)
    return value if _CODE_RE.match(value) else "UNSPECIFIED"


class Run:
    """One pass through the tool loop (one user turn). Every method is fail-open.

    agent_id:     stable identity of the agent, e.g. a SPIFFE id. Becomes the TRACE subject.
    agent_name:   short display name.
    model:        the model requested in messages.create.
    toolset:      names of the tools offered to the model on this run.
    workflow_id:  optional opaque id grouping runs (a ticket, a thread). Do not put content here.
    action_field: optional name of a tool-input field holding a verb such as "get" or "create".
                  When set, its value is recorded if it is a short lowercase token; nothing else
                  from the input is.
    spool:        path of the JSONL spool; defaults to default_spool_path().
    """

    def __init__(self, agent_id, agent_name, model, toolset=None, workflow_id=None,
                 action_field=None, spool=None):
        self.id = "run-" + uuid.uuid4().hex
        self.ended = False
        self._action_field = action_field
        self._spool = spool or default_spool_path()
        try:
            names = sorted({str(t) for t in toolset}) if toolset else []
            self._write({"kind": "run.start", "t": time.time_ns(), "agent_id": str(agent_id),
                         "agent_name": str(agent_name), "model": str(model), "toolset": names,
                         "workflow_id": str(workflow_id) if workflow_id else None})
        except Exception as exc:
            _log.warning("agentrust spool: run.start failed: %s", exc)

    # -- writing ---------------------------------------------------------------------------
    def _write(self, row):
        try:
            line = json.dumps({"run_id": self.id, **row}, separators=(",", ":"), default=str) + "\n"
            with _LOCK:
                parent = os.path.dirname(self._spool)
                if parent and not os.path.isdir(parent):
                    os.makedirs(parent, exist_ok=True)
                # One write() per row in append mode: a reader sees whole lines or a trailing
                # partial line it must leave for the next poll.
                with open(self._spool, "a", encoding="utf-8") as fh:
                    fh.write(line)
        except Exception as exc:
            _log.warning("agentrust spool: write failed: %s", exc)

    def _verb(self, tool_input):
        if not self._action_field or not isinstance(tool_input, dict):
            return None
        value = tool_input.get(self._action_field)
        return value if isinstance(value, str) and _VERB_RE.match(value) else None

    # -- hooks -----------------------------------------------------------------------------
    def model_call(self, round_no, start_ns, response):
        """After each client.messages.create. `response` is the Message (or a dict shaped like one)."""
        try:
            usage = _get(response, "usage") or {}
            self._write({"kind": "model.call", "round": int(round_no),
                         "model": str(_get(response, "model") or ""), "start": int(start_ns),
                         "end": time.time_ns(), "stop_reason": _get(response, "stop_reason"),
                         "input": int(_get(usage, "input_tokens", 0) or 0),
                         "output": int(_get(usage, "output_tokens", 0) or 0),
                         "cache_read": int(_get(usage, "cache_read_input_tokens", 0) or 0),
                         "cache_write": int(_get(usage, "cache_creation_input_tokens", 0) or 0)})
        except Exception as exc:
            _log.warning("agentrust spool: model_call failed: %s", exc)

    def tool_call(self, round_no, block, start_ns, decision="allow", policy="toolset", reason=None,
                  outcome=None, error_type=None, result=None, gate_ns=0):
        """After each tool_use block is handled.

        block:      the tool_use content block (name, id, input).
        decision:   your gate's verdict, "allow" or "deny".
        policy:     which check decided, e.g. "toolset" or "writers_only". Token-shaped.
        reason:     a short reason code for a deny, e.g. "WRITERS_ONLY". Never the message text.
        outcome:    "success" | "error" | "denied". Defaults to "denied" for a deny, "error" when
                    error_type is given, else "success".
        error_type: exception class name when the tool raised.
        result:     the tool's return value. Only its length, and whether it is a dict with an
                    "error" key, are recorded.
        gate_ns:    how long the gate check took, in nanoseconds.
        """
        try:
            tool_input = _get(block, "input")
            if decision not in ("allow", "deny"):
                decision = "deny"
            if outcome not in ("success", "error", "denied"):
                outcome = "denied" if decision == "deny" else ("error" if error_type else "success")
            self._write({"kind": "tool.call", "round": int(round_no), "tool": str(_get(block, "name")),
                         "tool_use_id": str(_get(block, "id")), "action": self._verb(tool_input),
                         "input_digest": digest(tool_input), "start": int(start_ns),
                         "end": time.time_ns(), "outcome": outcome, "policy": _code(policy) or "toolset",
                         "decision": decision, "reason": _code(reason),
                         "error_type": _code(error_type), "gate_ns": int(gate_ns or 0),
                         "result_chars": len(str(result)) if result is not None else None,
                         "tool_error": bool(isinstance(result, dict) and "error" in result
                                            and outcome == "success")})
        except Exception as exc:
            _log.warning("agentrust spool: tool_call failed: %s", exc)

    def end(self, stop):
        """When the loop stops: "end_turn", "max_tokens", "max_rounds", or your own token."""
        if self.ended:
            return
        self.ended = True
        try:
            self._write({"kind": "run.end", "t": time.time_ns(), "stop": _code(stop)})
        except Exception as exc:
            _log.warning("agentrust spool: run.end failed: %s", exc)
