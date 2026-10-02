"""Web server for the cMCP financial-services console.

Serves the UI in web/ and a small JSON API. The API runs the real example
agent (examples/financial-services) as a subprocess against the running
gateway and parses its output into structured steps; it also runs cmcp verify
on the signed record. The browser never talks to the gateway directly.

    python webserver.py             # serves on http://localhost:8000
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import policy_variants

HERE = pathlib.Path(__file__).parent.resolve()
WEB = HERE / "web"
CHILD_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
EXAMPLE = HERE.parents[1] / "examples" / "financial-services"
AGENT = EXAMPLE / "agent" / "credit_risk_agent.py"
WORKSPACE = HERE.parent / "workspace"
CLAIM_FILE = WORKSPACE / "fs-claim.json"

GATEWAY = os.environ.get("CMCP_GATEWAY_URL", "http://localhost:8443")
PORT = int(os.environ.get("WEB_CONSOLE_PORT", "8000"))

TAMPERED = policy_variants.TamperedGateway()
_HASHES: dict[str, str] = {}


def _policy_hashes() -> dict[str, str]:
    """Approved and tampered bundle hashes, computed the way the runtime does.
    Cached: the approved bundle is read-only and the tampered one is generated
    deterministically from it."""
    if not _HASHES:
        _HASHES["approved"] = policy_variants.bundle_hash(policy_variants.APPROVED_DIR)
        tampered_dir, _ = policy_variants.build_tampered()
        _HASHES["tampered"] = policy_variants.bundle_hash(tampered_dir)
    return _HASHES

# Names the console answers to. Anything else in Host is a rebinding attempt.
LOOPBACK_NAMES = ("localhost", "127.0.0.1", "[::1]")
# The UI posts a few dozen bytes; nothing legitimate comes close to this.
MAX_BODY = 64 * 1024

_CT = {".html": "text/html", ".js": "text/javascript", ".css": "text/css",
       ".svg": "image/svg+xml", ".json": "application/json"}

SCENARIOS = [
    {"id": "clean", "label": "Performing obligor",
     "obligor": "Rheintal Präzisionstechnik GmbH", "amount": "€250,000",
     "expect": "Write allowed", "outcome": "allow"},
    {"id": "large-exposure", "label": "Concentration breach",
     "obligor": "Nordwind Logistik AG", "amount": "€750,000",
     "expect": "Write blocked", "outcome": "deny"},
    {"id": "sanctions-hit", "label": "Sanctions / impaired",
     "obligor": "Meridian Trading DMCC", "amount": "€200,000",
     "expect": "Write blocked", "outcome": "deny"},
]

# Plain-English gloss for the guardrails in policy/allow.cedar, keyed by the
# @reason annotation the runtime returns on deny.
GUARDRAILS = [
    {"reason": "cdd-clearance-required", "regulation": "EU AML Regulation 2024/1624",
     "plain": "No assessment is written until customer due diligence clears."},
    {"reason": "human-review-required", "regulation": "EBA/GL/2020/06",
     "plain": "Facilities above the €500k delegated authority need a human decision-maker."},
    {"reason": "concentration-limit-breached", "regulation": "CRR Art. 395",
     "plain": "The facility must not breach the single-obligor concentration limit."},
    {"reason": "ifrs9-stage-3-credit-impaired", "regulation": "IFRS 9",
     "plain": "Credit-impaired (stage 3) obligors cannot be auto-approved."},
    {"reason": "attested-runtime-required", "regulation": "DORA Art. 9",
     "plain": "Confidential financial data only flows through an attested runtime."},
]


def _find_cmcp() -> str:
    found = shutil.which("cmcp")
    if found:
        return found
    import sysconfig
    for scripts in (pathlib.Path(sys.executable).parent,
                    pathlib.Path(sysconfig.get_path("scripts"))):
        for name in ("cmcp.exe", "cmcp"):
            if (scripts / name).exists():
                return str(scripts / name)
    return "cmcp"


def _run_agent(scenario: str, gateway: str = GATEWAY):
    """Run the real example agent and parse its output into steps + claim."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, str(AGENT), "--scenario", scenario, "--gateway", gateway],
        capture_output=True, text=True, encoding="utf-8", env=env, timeout=60, creationflags=CHILD_FLAGS)
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")

    claim = None
    marker = out.find("TRACE Trust Record")
    body = out
    if marker != -1:
        rest = out[marker:]
        brace = rest.find("{")
        if brace != -1:
            try:
                claim, _ = json.JSONDecoder().raw_decode(rest[brace:])
            except json.JSONDecodeError:
                claim = None
        body = out[:marker]

    steps, cur = [], None
    for line in body.splitlines():
        m = re.match(r"\s*\[(\d)/6\]\s+(\S+)", line)
        if m:
            cur = {"n": m.group(1), "tool": m.group(2), "decision": None, "note": "", "advice": {}}
            steps.append(cur)
            continue
        if cur is None:
            continue
        m = re.search(r"->\s*decision:\s*(allow|deny)(?:\s*\(([^)]+)\))?(.*)", line)
        if m:
            cur["decision"] = m.group(1)
            if m.group(2):
                cur["deny_code"] = m.group(2)
            note = (m.group(3) or "").strip()
            if note:
                cur["note"] = note
            continue
        m = re.match(r"\s+(reason|regulation|delegated_authority_limit_eur|error_code):\s*(.+)", line)
        if m:
            cur["advice"][m.group(1)] = m.group(2).strip()

    if claim:
        WORKSPACE.mkdir(exist_ok=True)
        CLAIM_FILE.write_text(json.dumps(claim, indent=2))

    # A run that crashed or produced no steps must not be reported as a clean
    # pass. Previously the UI inferred "allowed" from the absence of a denied
    # write, so a failed run rendered as a green success banner.
    error = None
    if proc.returncode != 0 or not steps:
        tail = "\n".join(l for l in out.strip().splitlines()[-6:] if l.strip())
        error = (f"the example agent exited with code {proc.returncode} and "
                 f"produced {len(steps)} of 6 steps.\n{tail}")
    return {"scenario": scenario, "steps": steps, "claim": claim, "error": error}


def _verify(pinned_hash: str | None = None):
    """Verify the last record. When pinned_hash is given, the verifier is held
    to the policy bundle it approved -- which is what makes a tampered run
    detectable rather than merely different."""
    if not CLAIM_FILE.exists():
        return {"error": "run an assessment first"}, 409
    env = os.environ.copy()
    env["CMCP_DEV_MODE"] = "1"
    cmd = [_find_cmcp(), "verify", str(CLAIM_FILE)]
    if pinned_hash:
        cmd += ["--policy-hash", pinned_hash]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, creationflags=CHILD_FLAGS)
    raw = (proc.stdout or "") + (proc.stderr or "")
    checks = [{"name": m.group(1).strip(), "status": m.group(2)}
              for m in re.finditer(r"\[cmcp verify\]\s+(.+?)\s{2,}(PASS|FAIL)", raw)]
    result = None
    m = re.search(r"RESULT:\s*(\w+)\s*\(([^)]+)\)", raw)
    if m:
        result = {"status": m.group(1), "detail": m.group(2)}
    return {"raw": raw.strip(), "checks": checks, "result": result}, 200


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, body, ct="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._local_request():
            return
        if self.path in ("/", "/index.html"):
            return self._serve("index.html")
        if self.path.startswith("/web/"):
            return self._serve(self.path[len("/web/"):])
        if self.path == "/api/context":
            catalog = json.loads((EXAMPLE / "catalog.json").read_text(encoding="utf-8"))
            tools = [{"tool_name": c["tool_name"], "compliance_domain": c.get("compliance_domain"),
                      "sensitivity_level": c.get("sensitivity_level"),
                      "description": c["approved_definition"]["description"]} for c in catalog]
            return self._send(200, {
                "scenarios": SCENARIOS, "tools": tools, "guardrails": GUARDRAILS,
                "policy": (EXAMPLE / "policy" / "allow.cedar").read_text(encoding="utf-8"),
                "gateway": GATEWAY,
                "policy_hashes": _policy_hashes(),
                "tamper_edits": [label for _, _, label in policy_variants.EDITS],
            })
        return self._send(404, {"error": "not found"})

    def _local_request(self) -> bool:
        """Refuse requests a browser page from another site could have sent.

        Loopback is not a boundary against the presenter's own browser: any open
        page can POST a CORS-safelisted text/plain body here without a preflight,
        and a DNS-rebinding page arrives with its own name in Host. /api/run
        spawns the agent and can start a second gateway, so both are refused.
        """
        port = self.server.server_address[1]
        allowed = {f"{h}:{port}" for h in LOOPBACK_NAMES}
        if self.headers.get("Host", "").lower() not in allowed:
            self._send(403, {"error": "host not allowed"})
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin.lower() not in {f"http://{a}" for a in allowed}:
            self._send(403, {"error": "cross-origin request refused"})
            return False
        return True

    def _read_json(self):
        """The request body as a JSON object, or None after sending the error."""
        ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self._send(415, {"error": "Content-Type must be application/json"})
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0:
            self._send(400, {"error": "bad Content-Length"})
            return None
        if length > MAX_BODY:
            self._send(413, {"error": "request body too large"})
            return None
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, RecursionError):  # bad UTF-8, bad JSON, or nested past the stack
            payload = None
        if not isinstance(payload, dict):
            self._send(400, {"error": "request body must be a JSON object"})
            return None
        return payload

    def do_POST(self):
        if not self._local_request():
            return
        payload = self._read_json()
        if payload is None:
            return
        if self.path == "/api/run":
            scenario = payload.get("scenario", "clean")
            variant = payload.get("variant", "approved")
            if scenario not in {s["id"] for s in SCENARIOS}:
                return self._send(400, {"error": "unknown scenario"})
            if variant not in ("approved", "tampered"):
                return self._send(400, {"error": "unknown policy variant"})
            try:
                gateway, applied = GATEWAY, []
                if variant == "tampered":
                    gateway = TAMPERED.ensure(os.environ.copy())
                    applied = TAMPERED.applied
                body = _run_agent(scenario, gateway)
                body["variant"] = variant
                body["tamper_edits"] = applied
                body["policy_hash"] = _policy_hashes()[variant]
                return self._send(200, body)
            except subprocess.TimeoutExpired:
                return self._send(504, {"error": "agent run timed out"})
            except RuntimeError as exc:
                return self._send(500, {"error": str(exc)})
        if self.path == "/api/verify":
            # The verifier is pinned to the APPROVED bundle: that is the whole
            # point. A record from the tampered gateway fails this check.
            pinned = _policy_hashes()["approved"] if payload.get("pinned", True) else None
            body, status = _verify(pinned)
            if isinstance(body, dict):
                body["pinned_hash"] = pinned
            return self._send(status, body)
        return self._send(404, {"error": "not found"})

    def _serve(self, rel):
        root = WEB.resolve()
        requested = pathlib.PurePosixPath(str(rel))
        if requested.is_absolute() or ".." in requested.parts:
            return self._send(404, "not found", "text/plain")
        target = (root / pathlib.Path(*requested.parts)).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            return self._send(404, "not found", "text/plain")
        self._send(200, target.read_bytes(), _CT.get(target.suffix, "application/octet-stream"))


def main():
    WORKSPACE.mkdir(exist_ok=True)
    srv = ThreadingHTTPServer(("localhost", PORT), Handler)
    print(f"web console on http://localhost:{PORT}  (gateway {GATEWAY})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
    finally:
        # the tampered gateway is ours to clean up; the approved one belongs
        # to run.py
        TAMPERED.stop()


if __name__ == "__main__":
    main()
