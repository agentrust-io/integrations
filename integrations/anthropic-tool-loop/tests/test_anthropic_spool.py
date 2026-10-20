"""The in-process writer: standard library only, metadata only, never raises into the agent.

Runs without agentrust-telemetry or agentrust-trace installed, and on Python 3.9.
"""

from __future__ import annotations

import json
import logging
import pathlib
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from anthropic_tool_loop_trace import Run, ToolCatalog, ToolInfo, digest  # noqa: E402
from anthropic_tool_loop_trace import spool as spool_module  # noqa: E402

SECRET = "Acme Wholesale card 4111-1111-1111-1111"


def _response(stop="tool_use"):
    return SimpleNamespace(model="claude-sonnet-5-5", stop_reason=stop, usage=SimpleNamespace(
        input_tokens=100, output_tokens=20, cache_read_input_tokens=5, cache_creation_input_tokens=7))


def _block(tool="crm_search", args=None, tool_id="toolu_1"):
    return SimpleNamespace(type="tool_use", id=tool_id, name=tool, input=args or {"q": SECRET})


def _rows(path):
    return [json.loads(line) for line in pathlib.Path(path).read_text().splitlines()]


def test_rows_carry_metadata_and_no_content(tmp_path):
    path = tmp_path / "spool.jsonl"
    run = Run("spiffe://example.org/agent/a", "a", "claude-sonnet-5-5", toolset=["crm_search", "crm_update"],
              workflow_id="ticket-7", action_field="action", spool=str(path))
    run.model_call(0, 1, _response())
    run.tool_call(0, _block(args={"action": "update", "note": SECRET}), 2, result={"rows": [SECRET]}, gate_ns=5)
    run.tool_call(0, _block(tool="crm_update", tool_id="toolu_2", args={"action": SECRET}), 3,
                  decision="deny", policy="writers_only", reason="WRITERS_ONLY")
    run.end("end_turn")

    text = path.read_text()
    assert SECRET not in text and "Acme" not in text
    start, model, allowed, denied, end = _rows(path)
    assert start["kind"] == "run.start" and start["toolset"] == ["crm_search", "crm_update"]
    assert start["workflow_id"] == "ticket-7" and start["agent_name"] == "a"
    assert model["input"] == 100 and model["cache_read"] == 5 and model["cache_write"] == 7
    assert allowed["action"] == "update" and allowed["outcome"] == "success" and allowed["result_chars"] > 0
    assert allowed["input_digest"] == digest({"action": "update", "note": SECRET})
    # A free-text value in the action field is not a verb and is not recorded.
    assert denied["action"] is None and denied["outcome"] == "denied" and denied["reason"] == "WRITERS_ONLY"
    assert end["stop"] == "end_turn"
    assert len({r["run_id"] for r in _rows(path)}) == 1


def test_action_field_is_opt_in(tmp_path):
    path = tmp_path / "spool.jsonl"
    run = Run("agent", "a", "m", spool=str(path))
    run.tool_call(0, _block(args={"action": "create"}), 1)
    assert _rows(path)[-1]["action"] is None


def test_reason_and_policy_are_codes_not_messages(tmp_path):
    path = tmp_path / "spool.jsonl"
    run = Run("agent", "a", "m", spool=str(path))
    run.tool_call(0, _block(), 1, decision="deny", policy="gate", reason="Only Dana may send POs to " + SECRET)
    row = _rows(path)[-1]
    assert row["reason"] == "UNSPECIFIED" and SECRET not in json.dumps(row)


def test_outcomes(tmp_path):
    path = tmp_path / "spool.jsonl"
    run = Run("agent", "a", "m", spool=str(path))
    run.tool_call(0, _block(), 1, error_type="TimeoutError")
    run.tool_call(0, _block(), 1, result={"error": "not found"})
    run.tool_call(0, _block(), 1, decision="maybe")  # anything but allow is treated as deny
    errored, tool_error, odd = _rows(path)[1:]
    assert errored["outcome"] == "error" and errored["error_type"] == "TimeoutError"
    assert tool_error["outcome"] == "success" and tool_error["tool_error"] is True
    assert odd["decision"] == "deny" and odd["outcome"] == "denied"


def test_end_is_written_once(tmp_path):
    path = tmp_path / "spool.jsonl"
    run = Run("agent", "a", "m", spool=str(path))
    run.end("end_turn")
    run.end("max_rounds")
    assert [r["kind"] for r in _rows(path)] == ["run.start", "run.end"]


def test_dict_shaped_responses_work(tmp_path):
    path = tmp_path / "spool.jsonl"
    run = Run("agent", "a", "m", spool=str(path))
    run.model_call(0, 1, {"model": "m", "stop_reason": "end_turn", "usage": {"input_tokens": 3, "output_tokens": 4}})
    run.tool_call(0, {"name": "t", "id": "toolu_x", "input": {}}, 1)
    model, tool = _rows(path)[1:]
    assert model["input"] == 3 and model["output"] == 4 and tool["tool"] == "t"


def test_writer_fails_open(tmp_path, caplog):
    blocked = tmp_path / "is-a-directory"
    blocked.mkdir()
    with caplog.at_level(logging.WARNING, logger="anthropic_tool_loop_trace"):
        run = Run("agent", "a", "m", toolset=[object()], spool=str(blocked))
        run.model_call(0, 1, object())                  # no usage, no model
        run.model_call("not-a-number", 1, _response())  # bad round
        run.tool_call(0, None, 1)                       # no block at all
        run.end("end_turn")
    assert run.ended
    assert any("write failed" in r.message for r in caplog.records)


def test_writer_survives_a_broken_lock(tmp_path, monkeypatch):
    class Broken:
        def __enter__(self):
            raise RuntimeError("lock broke")

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(spool_module, "_LOCK", Broken())
    run = Run("agent", "a", "m", spool=str(tmp_path / "s.jsonl"))
    run.tool_call(0, _block(), 1)
    run.end("end_turn")
    assert not (tmp_path / "s.jsonl").exists()


def test_default_path_from_environment(monkeypatch, tmp_path):
    monkeypatch.setenv(spool_module.SPOOL_ENV, str(tmp_path / "env.jsonl"))
    Run("agent", "a", "m").end("end_turn")
    assert len(_rows(tmp_path / "env.jsonl")) == 2


def test_digest_is_canonical():
    assert digest({"b": 1, "a": [1, 2]}) == digest({"a": [1, 2], "b": 1})
    assert digest({"a": 1}) != digest({"a": 2})


def test_catalog_lookup_and_conservative_default():
    catalog = ToolCatalog(
        {"crm_*": ToolInfo("crm", "crm", "confidential"), "crm_public_*": ToolInfo("site", "saas", "public"),
         "orders": ToolInfo("erp", "erp", "internal", write=lambda verb: verb not in {"get", None})},
        taxonomy="t.v1", order=("public", "internal", "confidential"))
    assert catalog.lookup("crm_search").system == "crm"
    assert catalog.lookup("crm_public_faq").system == "site"  # longest prefix wins
    assert catalog.is_write("orders", "create") and not catalog.is_write("orders", "get")
    assert not catalog.is_write("crm_search")
    unknown = catalog.lookup("shell_exec")
    assert unknown.system == "uncatalogued" and unknown.classification == "confidential"
    assert catalog.is_write("shell_exec")
    assert catalog.highest(["public", "internal"]) == "internal"
    with pytest.raises(ValueError):
        ToolCatalog({"x": ToolInfo("x", classification="secret")}, taxonomy="t", order=("public",))
