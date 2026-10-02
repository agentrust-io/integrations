#!/usr/bin/python3
"""Fuzz the web console's request gate and JSON body handling.

web-console/webserver.py is the one thing in this repo a browser talks to, and
POST /api/run spawns the example agent and can start a second gateway. The
properties asserted here:

  1. every request gets exactly one response and nothing escapes the handler
     (an exception there drops the connection instead of answering it);
  2. the agent only runs for a request that carried a loopback Host, no
     foreign Origin, Content-Type application/json, a JSON object body, and a
     known scenario and variant.

The agent run and the policy-bundle hashing are stubbed: they are subprocess
and cmcp-runtime territory, not request parsing, and the gate must hold
regardless of what they would do.
"""
import http.client
import io
import json
import os
import sys
import types

import atheris

HERE = os.path.dirname(os.path.abspath(__file__))
CONSOLE = os.path.join(HERE, "..", "web-console")
if os.path.isdir(os.path.join(HERE, "web-console")):  # layout inside the fuzz build
    CONSOLE = os.path.join(HERE, "web-console")
sys.path.insert(0, CONSOLE)

# policy_variants pulls in cmcp-runtime (Cedar bindings, crypto) only to hash
# bundles and start a gateway. Neither is on the request-parsing path.
_pv = types.ModuleType("policy_variants")
_pv.TamperedGateway = lambda: types.SimpleNamespace(
    ensure=lambda env: "http://localhost:8444", applied=[], stop=lambda: None)
_pv.EDITS = []
sys.modules["policy_variants"] = _pv

with atheris.instrument_imports():
    import webserver

PORT = 8000
RUNS = []


def _fake_run_agent(scenario, gateway=None):
    RUNS.append(scenario)
    return {"scenario": scenario, "steps": [], "claim": None, "error": None}


webserver._run_agent = _fake_run_agent
webserver._policy_hashes = lambda: {"approved": "sha256:a", "tampered": "sha256:t"}
webserver._verify = lambda pinned=None: ({"raw": "", "checks": [], "result": None}, 200)

HOSTS = [f"localhost:{PORT}", f"127.0.0.1:{PORT}", f"[::1]:{PORT}",
         f"attacker.example:{PORT}", "localhost", ""]
ORIGINS = [None, f"http://localhost:{PORT}", "https://attacker.example", "null"]
CTYPES = ["application/json", "application/json; charset=utf-8", "text/plain",
          "application/x-www-form-urlencoded", ""]
PATHS = ["/api/run", "/api/verify", "/api/other", "/"]
SCENARIOS = {s["id"] for s in webserver.SCENARIOS}


def _pick(options, byte):
    return options[byte % len(options)]


def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return
    host, origin = _pick(HOSTS, data[0]), _pick(ORIGINS, data[1])
    ctype, path = _pick(CTYPES, data[2]), _pick(PATHS, data[3])
    raw_length = data[4] % 4
    body = data[5:]

    headers = http.client.HTTPMessage()
    if host:
        headers["Host"] = host
    if origin is not None:
        headers["Origin"] = origin
    if ctype:
        headers["Content-Type"] = ctype
    # Mostly honest lengths, sometimes the lies a raw socket can tell.
    headers["Content-Length"] = {0: str(len(body)), 1: "-5", 2: "x", 3: str(len(body))}[raw_length]

    handler = object.__new__(webserver.Handler)
    handler.headers = headers
    handler.path = path
    handler.rfile = io.BytesIO(body)
    handler.server = types.SimpleNamespace(server_address=("127.0.0.1", PORT))
    sent = []
    handler._send = lambda status, payload, ct="application/json": sent.append(status)

    RUNS.clear()
    handler.do_POST()

    assert len(sent) == 1, f"expected one response, got {sent}"
    if not RUNS:
        return
    # The agent ran: every gate must have been satisfied.
    assert path == "/api/run"
    assert host in HOSTS[:3], host
    assert origin in (None, f"http://localhost:{PORT}"), origin
    assert ctype.startswith("application/json"), ctype
    payload = json.loads(body or b"{}")
    assert isinstance(payload, dict)
    assert payload.get("scenario", "clean") in SCENARIOS
    assert payload.get("variant", "approved") in ("approved", "tampered")
    assert sent == [200]


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
