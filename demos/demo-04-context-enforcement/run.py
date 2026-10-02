"""Demo 4: context-aware enforcement — cross-platform launcher (replaces run.sh).

Usage:
    python demo-04-context-enforcement/run.py    # from repo root
    python run.py                                 # from demo-04 directory
"""
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import time

sys.stdout.reconfigure(line_buffering=True)

SCRIPT_DIR = pathlib.Path(__file__).parent.resolve()
REPO_ROOT = SCRIPT_DIR.parent


def _find_cmcp() -> str:
    found = shutil.which("cmcp")
    if found:
        return found
    import sysconfig
    candidates = [
        pathlib.Path(sys.executable).parent,
        pathlib.Path(sysconfig.get_path("scripts")),
        pathlib.Path(sysconfig.get_path("scripts", "nt_user")),
    ]
    for scripts in candidates:
        for name in ("cmcp.exe", "cmcp"):
            p = scripts / name
            if p.exists():
                return str(p)
    sys.exit("cmcp not found. Run: pip install cmcp-runtime")



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
    setup before it binds, so the demo raced startup and failed on a refused
    connection.
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
    running by an earlier demo satisfies it instantly. Every call then goes to
    that gateway and is decided by its policy bundle, not this demo's. The
    verdicts still look plausible, which is what makes it dangerous: the demo
    prints allow/deny lines that are simply wrong, with no error anywhere.
    """
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            pass
    except OSError:
        return
    sys.exit(
        f"Port {port} is already in use, so {what} cannot start and this demo "
        f"would be scored against whatever is already listening. Stop it first "
        f"(a cMCP gateway left over from another demo is the usual cause), then "
        f"re-run."
    )


def _wait_for_port_release(port: int, timeout: float = 10.0) -> None:
    """Block until the port is actually free, so the next demo starts clean."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                time.sleep(0.25)
        except OSError:
            return
    print(f"warning: port {port} still held after teardown", file=sys.stderr)


def main() -> None:
    # Before anything starts: both ports must be ours.
    _assert_port_free(9001, "the MCP filesystem server")
    _assert_port_free(8443, "the cMCP Runtime")

    os.environ.setdefault("CMCP_BEARER_TOKEN", "demo-token")

    log_dir = SCRIPT_DIR
    server_log = open(log_dir / "server.log", "w")
    cmcp_log = open(log_dir / "cmcp.log", "w")

    server = cmcp_proc = None
    try:
        print("-- Starting MCP filesystem server on :9001 --", flush=True)
        server = subprocess.Popen(
            [sys.executable, str(REPO_ROOT / "server" / "server.py")],
            stdout=server_log, stderr=server_log,
        )
        _wait_for_port(9001, "MCP filesystem server", server)

        print("-- Starting cMCP Runtime (CMCP_DEV_MODE=1) on :8443 --", flush=True)
        env = os.environ.copy()
        env["CMCP_DEV_MODE"] = "1"
        cmcp_proc = subprocess.Popen(
            [_find_cmcp(), "start", "--config", str(SCRIPT_DIR / "cmcp-config.yaml")],
            stdout=cmcp_log, stderr=cmcp_log,
            cwd=SCRIPT_DIR, env=env,
        )
        _wait_for_port(8443, "cMCP Runtime", cmcp_proc)

        print()
        subprocess.run([sys.executable, str(SCRIPT_DIR / "call.py")], check=True)

    finally:
        for proc in (cmcp_proc, server):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        _wait_for_port_release(8443)
        _wait_for_port_release(9001)
        server_log.close()
        cmcp_log.close()


if __name__ == "__main__":
    main()
