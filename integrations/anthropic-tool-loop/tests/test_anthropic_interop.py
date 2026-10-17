"""The example's tool loop driven by the released `anthropic` SDK, offline.

The SDK's own client, request building and response parsing run for real; only the HTTP transport
is replaced (MockTransport from the SDK's own HTTP library), so no API key or network is needed. A renamed field on Message,
Usage or ToolUseBlock fails here rather than silently producing empty spool rows.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

anthropic = pytest.importorskip("anthropic")
from anthropic import _base_client  # noqa: E402

# Use whichever HTTP library this SDK release is built on (httpx in older releases, httpx2 in newer).
httpx = getattr(_base_client, "httpx2", None) or _base_client.httpx
pytest.importorskip("agentrust_telemetry")

from agentrust_trace import generate_key  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("offline_tool_loop", HERE / "examples" / "offline_tool_loop.py")
example = importlib.util.module_from_spec(spec)
spec.loader.exec_module(example)

from anthropic_tool_loop_trace.recorder import Recorder  # noqa: E402


def _message(stop_reason, content, cache_read=0):
    return {"id": "msg_01", "type": "message", "role": "assistant", "model": example.MODEL,
            "content": content, "stop_reason": stop_reason, "stop_sequence": None,
            "usage": {"input_tokens": 400, "output_tokens": 30, "cache_read_input_tokens": cache_read,
                      "cache_creation_input_tokens": 0}}


def _tool_use(tool_id, name, args):
    return {"type": "tool_use", "id": tool_id, "name": name, "input": args}


SCRIPT = [
    _message("tool_use", [_tool_use("toolu_01", "inventory_lookup", {"sku": "SKU-118"}),
                          _tool_use("toolu_02", "purchase_orders",
                                    {"action": "create", "supplier": example.SUPPLIER, "qty": 20})]),
    _message("end_turn", [{"type": "text", "text": "A buyer has to create it."}], cache_read=380),
    _message("tool_use", [_tool_use("toolu_03", "purchase_orders",
                                    {"action": "create", "supplier": example.SUPPLIER, "qty": 20})]),
    _message("end_turn", [{"type": "text", "text": "Created."}], cache_read=380),
]


def test_real_sdk_loop_records_and_signs(tmp_path):
    requests = []
    script = list(SCRIPT)

    def handler(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=script.pop(0))

    client = anthropic.Anthropic(api_key="offline-test-key", max_retries=0,
                                 http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    spool = str(tmp_path / "spool.jsonl")
    assert example.answer(client, "requester", "Stock? Order 20.", spool) == "A buyer has to create it."
    assert example.answer(client, "buyer", "Go ahead.", spool) == "Created."
    assert not script

    # The denied call went back to the model as an error result; the allowed one as data.
    results = {b["tool_use_id"]: b for m in requests[1]["messages"] if m["role"] == "user"
               and isinstance(m["content"], list) for b in m["content"]}
    assert results["toolu_02"]["is_error"] is True and "is_error" not in results["toolu_01"]

    rows = [json.loads(line) for line in pathlib.Path(spool).read_text().splitlines()]
    model_rows = [r for r in rows if r["kind"] == "model.call"]
    assert [r["stop_reason"] for r in model_rows] == ["tool_use", "end_turn", "tool_use", "end_turn"]
    assert model_rows[1]["cache_read"] == 380 and model_rows[0]["model"] == example.MODEL
    assert [r["tool_use_id"] for r in rows if r["kind"] == "tool.call"] == ["toolu_01", "toolu_02", "toolu_03"]
    assert "Northwind" not in pathlib.Path(spool).read_text()

    recorder = Recorder(spool=spool, data_dir=tmp_path / "data", signing_key=generate_key(),
                        catalog=example.CATALOG, enforcement_mode="enforce",
                        policy_bundle_digest="sha256:" + "ab" * 32, build_digest="sha256:" + "cd" * 32,
                        prompt_classification="internal")
    first, second = (recorder.run(run_id)["run"] for run_id in recorder.poll())
    assert first["verdict"] == "contraindicated" and first["denies"] == 1
    assert second["verdict"] == "affirming" and second["writes"] == 1
    assert first["signed"] and second["signed"]
