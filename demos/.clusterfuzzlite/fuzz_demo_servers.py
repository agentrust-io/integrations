#!/usr/bin/python3
"""Fuzz the two demo HTTP servers that take JSON from the network.

server/server.py (the filesystem MCP server behind demos 1 to 5) turns a
JSON-RPC body into file reads and writes. Property: it always answers with a
JSON-RPC response, and nothing it does touches a path outside its workspace.

demo-10-model-gateway/endpoint.py (the OpenAI-compatible endpoint) turns a chat
request into a governed tool call. Properties: it always answers with 200, 400
or 403; a request is only forwarded with a data class the Cedar bundle knows;
and the prompt it forwards matches none of its own identifier patterns, so
redaction is not undone by the order the patterns run in.

The gateway hop is stubbed, so this needs no ports and no cmcp-runtime.
"""
import asyncio
import json
import os
import sys
import tempfile

import atheris

HERE = os.path.dirname(os.path.abspath(__file__))
for sub in ("server", "demo-10-model-gateway"):
    for base in (os.path.join(HERE, ".."), HERE):
        if os.path.isdir(os.path.join(base, sub)):
            sys.path.insert(0, os.path.join(base, sub))
            break

with atheris.instrument_imports():
    import endpoint
    import server

from starlette.requests import Request  # noqa: E402

ROOT = tempfile.mkdtemp(prefix="demos-fuzz-")
WORKSPACE = os.path.join(ROOT, "workspace")
os.makedirs(WORKSPACE)
server.WORKSPACE = __import__("pathlib").Path(WORKSPACE)

FORWARDED = []


def _fake_post(url, payload, timeout=20):
    FORWARDED.append(payload)
    text = json.dumps({"content": "ok"})
    return {"result": {"content": [{"type": "text", "text": text}]}}, 200


endpoint._post = _fake_post

TOOLS = ["write_file", "read_file", "list_dir", "unknown"]
CLASSES = ["public", "pii", "confidential", "hipaa_phi", "Confidential", "", None]
MODELS = list(endpoint.MODELS) + ["unknown-model"]


def _request(path, body: bytes, headers: dict) -> Request:
    scope = {
        "type": "http", "method": "POST", "path": path, "raw_path": path.encode(),
        "query_string": b"", "scheme": "http", "server": ("127.0.0.1", 9001),
        "client": ("127.0.0.1", 50000), "root_path": "",
        "headers": [(k.lower().encode("latin-1"), v.encode("latin-1"))
                    for k, v in headers.items()],
    }
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="surrogateescape").encode(
        "utf-8", errors="replace").decode("utf-8")


def _outside_workspace() -> set:
    return {e for e in os.listdir(ROOT) if e != "workspace"}


def _fuzz_fs_server(sel: int, data: bytes) -> None:
    if sel & 1:
        body = data  # raw bytes, whatever they are
    else:
        cut = len(data) // 2
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": TOOLS[sel % len(TOOLS)],
            "arguments": {"path": _text(data[:cut]), "content": _text(data[cut:])},
        }}).encode()
    before = _outside_workspace()
    resp = asyncio.run(server.handle(_request(
        "/mcp", body, {"host": "localhost:9001", "content-type": "application/json"})))
    assert resp.status_code in (200, 400, 403, 404, 415, 500), resp.status_code
    out = json.loads(resp.body)
    assert out.get("jsonrpc") == "2.0" and ("result" in out or "error" in out)
    assert _outside_workspace() == before, "a write escaped the workspace"


def _fuzz_endpoint(sel: int, data: bytes) -> None:
    headers = {"host": "127.0.0.1:8500", "content-type": "application/json"}
    if sel & 1:
        body = data
    else:
        cls = CLASSES[sel % len(CLASSES)]
        if cls is not None:
            headers["x-data-class"] = cls
        body = json.dumps({"model": MODELS[(sel >> 3) % len(MODELS)],
                           "messages": [{"role": "user", "content": _text(data)}]}).encode()
    FORWARDED.clear()
    resp = asyncio.run(endpoint.chat_completions(_request("/v1/chat/completions", body, headers)))
    assert resp.status_code in (200, 400, 403), resp.status_code
    json.loads(resp.body)
    for call in FORWARDED:
        args = call["params"]["arguments"]
        assert args["data_class"] in endpoint.DATA_CLASSES, args["data_class"]
        for label, pattern in endpoint.REDACTIONS:
            assert not pattern.search(args["prompt"]), f"{label} survived redaction"
        if args["contains_identifiers"]:
            assert args["redacted"], "identifiers seen but nothing redacted"


def TestOneInput(data: bytes) -> None:
    if len(data) < 2:
        return
    sel, rest = data[1], data[2:]
    if data[0] & 1:
        _fuzz_fs_server(sel, rest)
    else:
        _fuzz_endpoint(sel, rest)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
