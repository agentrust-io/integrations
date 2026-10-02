"""Demo 10: a governed, OpenAI-compatible model endpoint.

    python demo-10-model-gateway/run.py            # start everything, run the client
    python demo-10-model-gateway/run.py --serve    # stay up, drive it yourself

Ctrl+C stops all three. Logs go to *.log beside this file.
"""
import argparse
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).parent
PORTS = {"model backend": 9010, "model gateway": 8444, "endpoint": 8500}


def _wait(port, name, process=None, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            print(f"{name} exited with code {process.returncode} before listening on :{port}. "
                  "See the *.log files.", file=sys.stderr)
            return False
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.3)
    print(f"{name} did not come up on :{port}. See the *.log files.", file=sys.stderr)
    return False


def _free(port):
    with socket.socket() as s:
        s.settimeout(0.4)
        return s.connect_ex(("127.0.0.1", port)) != 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", action="store_true", help="stay up instead of running the client")
    args = ap.parse_args()

    config = "cmcp-config.yaml"

    busy = [f"{n} (:{p})" for n, p in PORTS.items() if not _free(p)]
    if busy:
        print("These ports are already in use: " + ", ".join(busy))
        print("Stop the older run first, or the gateway will refuse to bind.")
        return 1

    cmcp = shutil.which("cmcp")
    if not cmcp:
        print("`cmcp` is not on PATH. Activate the venv that has cmcp-runtime installed:")
        print(r'  pip install -r requirements.txt')
        return 1

    env = dict(os.environ)
    env["CMCP_DEV_MODE"] = "1"          # software-only TEE, no hardware needed
    env.pop("CMCP_BEARER_TOKEN", None)  # loopback demo, tokenless like the web console

    logs = {n: open(HERE / f"{n.replace(chr(32), chr(45))}.log", "w") for n in PORTS}
    procs = []
    try:
        print("-- model backend on :9010")
        procs.append(subprocess.Popen(
            [sys.executable, str(HERE / "model_server.py")],
            stdout=logs["model backend"], stderr=logs["model backend"], env=env, cwd=HERE))
        if not _wait(9010, "model backend", procs[-1]):
            return 1

        print("-- cMCP gateway on :8444  (CMCP_DEV_MODE=1)")
        procs.append(subprocess.Popen(
            [cmcp, "start", "--config", config],
            stdout=logs["model gateway"], stderr=logs["model gateway"], env=env, cwd=HERE))
        if not _wait(8444, "model gateway", procs[-1]):
            return 1

        print("-- OpenAI-compatible endpoint on :8500")
        procs.append(subprocess.Popen(
            [sys.executable, str(HERE / "endpoint.py")],
            stdout=logs["endpoint"], stderr=logs["endpoint"], env=env, cwd=HERE))
        if not _wait(8500, "endpoint", procs[-1]):
            return 1

        print()
        if args.serve:
            print("Up. base_url = http://127.0.0.1:8500/v1     Ctrl+C to stop.")
            while True:
                time.sleep(1)
        else:
            # The client's exit code is this demo's exit code. Discarding it kept
            # CI green through a gateway that denied every call.
            rc = subprocess.call([sys.executable, str(HERE / "client.py")], cwd=HERE)
            if rc != 0:
                print(f"client.py exited with code {rc}. See the *.log files.", file=sys.stderr)
                return rc
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()
        for fh in logs.values():
            fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
