"""cMCP browser console -- one-command launcher (cross-platform).

Runs the shared examples/financial-services scenario behind a small web console.
The tool server, Cedar policy, catalog, and agent run directly from this checkout. This launcher only supplies a loopback gateway
config (tokenless dev mode binds to loopback) and starts:

    - the example's mock EU credit-risk MCP server on :8080
    - the cMCP gateway on :8443 (CMCP_DEV_MODE=1, software-only TEE)
    - this demo's web server on :8000

Then it opens http://localhost:8000. Ctrl+C stops everything.

    python web-console/run.py       # from repo root
    python run.py                   # from the web-console directory
"""
import argparse
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import time
import webbrowser

sys.stdout.reconfigure(line_buffering=True)

HERE = pathlib.Path(__file__).parent.resolve()
REPO_ROOT = HERE.parent
EXAMPLE = HERE.parents[1] / "examples" / "financial-services"
WORKSPACE = REPO_ROOT / "workspace"
GATEWAY_CFG = WORKSPACE / "fs-gateway.yaml"
PORT = os.environ.get("WEB_CONSOLE_PORT", "8000")
CHILD_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


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
    sys.exit("cmcp not found. Run: pip install cmcp-runtime httpx")


def _log_tail(what: str, lines: int = 15) -> str:
    """Return the tail of the log for `what`, or "" if there is nothing to show.

    A service that fails to bind has already written the reason to its log. The
    launcher used to point at the file and leave; printing the tail turns a 60
    second wait plus a scavenger hunt into the actual error.
    """
    name = "cmcp.log" if "cMCP" in what or "cmcp" in what else "server.log"
    path = pathlib.Path(__file__).parent.resolve() / name
    try:
        tail = path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
    except OSError:
        return ""
    if not tail:
        return ""
    body = "\n".join("    " + line for line in tail)
    return f"\n\nLast {len(tail)} lines of {name}:\n{body}"


def _wait_for_port(port: int, what: str, process=None, timeout: float = 60.0) -> None:
    """Block until something is listening on 127.0.0.1:port.

    A fixed sleep used to be enough; cMCP Runtime now does attestation and audit
    setup before it binds, so the console raced startup and the first assessment
    failed on a refused connection.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            sys.exit(f"{what} exited with code {process.returncode} before listening on :{port}."
                     + _log_tail(what))
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    sys.exit(f"{what} did not start listening on :{port} within {timeout:.0f}s."
             + _log_tail(what))


def _assert_port_free(port: int, what: str) -> None:
    """Refuse to start if something already owns the port.

    _wait_for_port() returns as soon as *anything* answers, so a gateway left
    over from a demo run satisfies it instantly while this console's own
    gateway dies on a bind error in cmcp.log. The console then scores every
    assessment against the other gateway's policy bundle and still prints
    plausible allow/deny lines. Same guard the terminal demos already carry.
    """
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            pass
    except OSError:
        return
    sys.exit(
        f"Port {port} is already in use, so {what} cannot start and this console "
        f"would be scored against whatever is already listening. Stop it first "
        f"(a cMCP gateway left over from another demo is the usual cause), then "
        f"re-run."
    )


def _ensure_example() -> None:
    if not (EXAMPLE / "agent" / "credit_risk_agent.py").is_file():
        sys.exit("shared example missing. Use a complete integrations checkout.")


def _gateway_env(base_env: dict) -> dict:
    """Env for the approved gateway subprocess: software-only TEE, and no
    inherited bearer token -- see the CMCP_BEARER_TOKEN.pop comment at the
    call site for why."""
    env = dict(base_env)
    env["CMCP_DEV_MODE"] = "1"
    # loopback demo, tokenless: the shared credit_risk_agent.py never sends
    # an Authorization header. If CMCP_BEARER_TOKEN is inherited from the
    # shell -- e.g. left set from the terminal demos' README step -- cmcp
    # starts requiring it anyway and every /api/run call fails.
    env.pop("CMCP_BEARER_TOKEN", None)
    return env


def _write_gateway_config() -> None:
    # A loopback config pointing at the shared example's own policy and
    # catalog. We do not copy them -- we reference them where they live.
    WORKSPACE.mkdir(exist_ok=True)
    GATEWAY_CFG.write_text(
        f"policy_bundle_path: {(EXAMPLE / 'policy').as_posix()}\n"
        f"catalog_path: {(EXAMPLE / 'catalog.json').as_posix()}\n"
        f"listen_addr: 127.0.0.1:8443\n"
        f"max_response_size_bytes: 2097152\n"
        f"audit_db_path: {(WORKSPACE / 'fs-audit.db').as_posix()}\n"
        f"attestation:\n"
        f"  provider: auto\n"
        f"  enforcement_mode: enforcing\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-browser", action="store_true", help="print the URL without opening a browser")
    args = parser.parse_args()
    _ensure_example()
    _assert_port_free(8080, "the EU credit-risk MCP server")
    _assert_port_free(8443, "the cMCP gateway")
    _assert_port_free(int(PORT), "the web console")
    _write_gateway_config()
    server_log = open(HERE / "server.log", "w")
    cmcp_log = open(HERE / "cmcp.log", "w")
    procs = []
    try:
        print("-- EU credit-risk MCP server on :8080", flush=True)
        procs.append(subprocess.Popen(
            [sys.executable, str(EXAMPLE / "server" / "mock_mcp_server.py")],
            stdout=server_log, stderr=server_log, creationflags=CHILD_FLAGS))
        _wait_for_port(8080, "EU credit-risk MCP server", procs[-1])

        print("-- cMCP gateway on :8443 (CMCP_DEV_MODE=1)", flush=True)
        procs.append(subprocess.Popen(
            [_find_cmcp(), "start", "--config", str(GATEWAY_CFG)],
            stdout=cmcp_log, stderr=cmcp_log, env=_gateway_env(os.environ), creationflags=CHILD_FLAGS))
        _wait_for_port(8443, "cMCP gateway", procs[-1])

        print(f"-- web console on http://localhost:{PORT}", flush=True)
        web = subprocess.Popen([sys.executable, str(HERE / "webserver.py")], env=os.environ.copy(), creationflags=CHILD_FLAGS)
        procs.append(web)
        _wait_for_port(int(PORT), "web console", web)

        url = f"http://localhost:{PORT}"
        print(f"\nOpen {url}. Ctrl+C to stop.\n", flush=True)
        if not args.no_browser:
            try:
                webbrowser.open(url)
            except Exception:
                pass
        web.wait()
    except KeyboardInterrupt:
        print("\nstopping...", flush=True)
    finally:
        for p in reversed(procs):
            if p and p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
        server_log.close()
        cmcp_log.close()


if __name__ == "__main__":
    main()
