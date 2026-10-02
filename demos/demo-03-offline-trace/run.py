"""Demo 3: Offline TRACE verification — cross-platform launcher (replaces run.sh).

Usage:
    python demo-03-offline-trace/run.py          # from repo root
    python run.py                                # from demo-03 directory
"""
import pathlib
import subprocess
import sys

sys.stdout.reconfigure(line_buffering=True)

SCRIPT_DIR = pathlib.Path(__file__).parent.resolve()
REPO_ROOT = SCRIPT_DIR.parent
CLAIM_PATH = REPO_ROOT / "workspace" / "trace-claim.json"


def main() -> None:
    if not CLAIM_PATH.exists():
        sys.exit("No claim found. Run demo-01 first:\n  python demo-01-cmcp-in-action/run.py")

    sys.stdout.flush()
    subprocess.run([sys.executable, str(SCRIPT_DIR / "verify.py")], check=True)


if __name__ == "__main__":
    main()
