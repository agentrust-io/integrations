"""Request handling on the demo servers that a browser on the same machine can reach.

Every server here binds loopback, but loopback is not a trust boundary against a
web page: any site the presenter has open can send a cross-origin "simple" POST
(text/plain, no preflight) to localhost, and a DNS-rebinding page can make that
request same-origin. These tests pin the refusals, and the 400s for bodies that
used to escape as unhandled exceptions.
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


# --- web console (http.server) ------------------------------------------------


@pytest.fixture()
def console(monkeypatch):
    webserver = _load("hardening_webserver", "web-console/webserver.py")
    runs = []

    def fake_run_agent(scenario, gateway=webserver.GATEWAY):
        runs.append(scenario)
        return {"scenario": scenario, "steps": [], "claim": None, "error": None}

    monkeypatch.setattr(webserver, "_run_agent", fake_run_agent)
    monkeypatch.setattr(webserver, "_policy_hashes",
                        lambda: {"approved": "sha256:a", "tampered": "sha256:t"})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), webserver.Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv.server_address[1], runs
    finally:
        srv.shutdown()
        srv.server_close()


def _request(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _json_headers(port, **extra):
    return {"Content-Type": "application/json", "Host": f"localhost:{port}", **extra}


def test_console_same_origin_run_still_works(console):
    port, runs = console
    status, _ = _request(port, "POST", "/api/run",
                         json.dumps({"scenario": "clean"}),
                         _json_headers(port, Origin=f"http://localhost:{port}"))
    assert status == 200
    assert runs == ["clean"]


def test_console_refuses_cross_origin_simple_post(console):
    """text/plain is a CORS-safelisted type, so a foreign page's fetch() sends
    it without a preflight. The server parsed it as JSON anyway and ran the
    agent (and could start the tampered gateway)."""
    port, runs = console
    status, _ = _request(port, "POST", "/api/run",
                         json.dumps({"scenario": "clean", "variant": "approved"}),
                         {"Content-Type": "text/plain", "Host": f"localhost:{port}",
                          "Origin": "https://attacker.example"})
    assert status in (403, 415)
    assert runs == []


def test_console_refuses_foreign_origin_even_with_json(console):
    port, runs = console
    status, _ = _request(port, "POST", "/api/run", json.dumps({"scenario": "clean"}),
                         _json_headers(port, Origin="https://attacker.example"))
    assert status == 403
    assert runs == []


def test_console_refuses_rebound_host(console):
    """A DNS-rebinding page reaches the server with its own name in Host."""
    port, runs = console
    status, _ = _request(port, "GET", "/api/context",
                         headers={"Host": f"attacker.example:{port}"})
    assert status == 403
    status, _ = _request(port, "POST", "/api/run", json.dumps({"scenario": "clean"}),
                         {"Content-Type": "application/json",
                          "Host": f"attacker.example:{port}"})
    assert status == 403
    assert runs == []


@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b"\"clean\"", b"\xff\xfe",
                                  pytest.param(b"[" * 50000, id="nested-past-recursion-limit")])
def test_console_malformed_body_is_a_400(console, body):
    """These used to raise inside do_POST, so the client saw a dropped
    connection instead of an error."""
    port, runs = console
    status, _ = _request(port, "POST", "/api/run", body, _json_headers(port))
    assert status == 400
    assert runs == []


@pytest.mark.parametrize("length", ["-1", "abc", str(10 * 1024 * 1024)])
def test_console_bad_or_oversized_content_length(console, length):
    port, runs = console
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.putrequest("POST", "/api/run", skip_host=True)
        conn.putheader("Host", f"localhost:{port}")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", length)
        conn.endheaders()
        resp = conn.getresponse()
        assert resp.status in (400, 413)
    finally:
        conn.close()
    assert runs == []


# --- demo filesystem MCP server (starlette) ----------------------------------


@pytest.fixture()
def fs_server(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    server = _load("hardening_fs_server", "server/server.py")
    monkeypatch.setattr(server, "WORKSPACE", tmp_path)
    return TestClient(server.app, base_url="http://localhost:9001"), tmp_path


def _write_call(path="note.txt", content="hi"):
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": path, "content": content}}}


def test_fs_server_gateway_style_write_still_works(fs_server):
    client, ws = fs_server
    r = client.post("/mcp", json=_write_call())
    assert r.status_code == 200
    assert (ws / "note.txt").read_text(encoding="utf-8") == "hi"


def test_fs_server_refuses_cross_origin_text_plain_write(fs_server):
    client, ws = fs_server
    r = client.post("/mcp", content=json.dumps(_write_call()),
                    headers={"Content-Type": "text/plain"})
    assert r.status_code == 415
    assert not (ws / "note.txt").exists()


def test_fs_server_refuses_rebound_host(fs_server):
    client, ws = fs_server
    r = client.post("/mcp", json=_write_call(),
                    headers={"Host": "attacker.example:9001"})
    assert r.status_code == 403
    assert not (ws / "note.txt").exists()


@pytest.mark.parametrize("body", [[1, 2], "x", 3,
                                  {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": ["write_file"]},
                                  {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": {"name": "write_file", "arguments": ["a"]}}])
def test_fs_server_non_object_request_is_invalid_request(fs_server, body):
    client, _ = fs_server
    r = client.post("/mcp", json=body)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32600


# --- demo 10 OpenAI-compatible endpoint --------------------------------------


@pytest.fixture()
def endpoint(monkeypatch):
    from starlette.testclient import TestClient

    ep = _load("hardening_endpoint", "demo-10-model-gateway/endpoint.py")
    forwarded = []

    def fake_post(url, payload, timeout=20):
        forwarded.append(payload)
        text = json.dumps({"content": "ok"})
        return {"result": {"content": [{"type": "text", "text": text}]}}, 200

    monkeypatch.setattr(ep, "_post", fake_post)
    return TestClient(ep.app, base_url="http://127.0.0.1:8500"), forwarded


def _chat(model="frontier-large"):
    return {"model": model, "messages": [{"role": "user", "content": "hello"}]}


@pytest.mark.parametrize("data_class", ["public", "pii", "confidential", "hipaa_phi"])
def test_endpoint_known_classes_are_forwarded(endpoint, data_class):
    client, forwarded = endpoint
    r = client.post("/v1/chat/completions", json=_chat(),
                    headers={"x-data-class": data_class})
    assert r.status_code == 200
    assert forwarded[-1]["params"]["arguments"]["data_class"] == data_class


@pytest.mark.parametrize("data_class", ["Confidential", "HIPAA_PHI", "phi", "secret", " pii"])
def test_endpoint_unknown_class_is_refused_not_forwarded(endpoint, data_class):
    """The Cedar bundle forbids by listing classes, so any label outside the
    list matched no forbid and went out of region under the permit."""
    client, forwarded = endpoint
    r = client.post("/v1/chat/completions", json=_chat(),
                    headers={"x-data-class": data_class})
    assert r.status_code == 400
    assert forwarded == []


@pytest.mark.parametrize("body", [b"not json", b"[]", b"{\"messages\": \"hi\"}",
                                  b"{\"messages\": [{\"role\": \"user\", \"content\": 7}]}"])
def test_endpoint_malformed_body_is_a_400(endpoint, body):
    client, forwarded = endpoint
    r = client.post("/v1/chat/completions", content=body,
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 400
    assert forwarded == []
