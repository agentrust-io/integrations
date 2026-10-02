#!/usr/bin/env python3
"""One command, the agentrust-io demos.

    python demo.py              # run all, pausing before each (for live talks)
    python demo.py --no-pause   # run straight through, no prompts
    python demo.py 2            # run only demo 2 (1 through 10)

The trust chain, end to end:
    Demo 1  cMCP enforces Cedar on every tool call and signs a TRACE claim.
    Demo 2  Swap the policy bundle and the claim's hash changes; a pinned verifier rejects it.
    Demo 3  Verify that signed claim offline: no server, no gateway, no network.

Then, on a second axis, two ways the policy decides a call:
    Demo 4  by call context   -- the same tool, allowed in one workflow, denied in another.
    Demo 5  by tool attribute -- a non-BAA-covered tool refused by one guardrail rule.

And the layer beneath it all, the weights themselves:
    Demo 6  Weight custody -- a signed manifest binds the exact weight hash; a tampered
            checkpoint is refused before load, and a fine-tune's lineage verifies to the base.
    Demo 7  Closed-weight custody -- the frontier case where secrecy is the job.
    Demo 8  Derivative lineage -- the fine-tune is the real IP; its chain resolves to the base.
    Demo 9  Sovereign threshold -- split the key 2-of-3 so no single release is enough.

And one axis out from the tool boundary:
    Demo 10 Governed model calls -- the same policy boundary on an OpenAI-compatible
            endpoint, routing each request by its data class.

All demos run in software-only mode (CMCP_DEV_MODE=1). That is deliberate: software
proves the whole chain except the hardware root, so verification reads
'partially_verified'. On real TDX / SEV-SNP the hardware field verifies too and it
becomes 'verified'. That last gap is exactly what the hardware path closes.
"""
import argparse
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).parent.resolve()

DEMOS = [
    ("1", "cMCP in action",
     "demo-01-cmcp-in-action/run.py",
     "Three tool calls through cMCP. write_file and read_file are allowed; list_dir is\n"
     "  denied by Cedar. The session closes into a signed TRACE claim."),
    ("2", "Policy swap = attestation failure",
     "demo-02-policy-swap/run.py",
     "Load a different Cedar bundle. The policy hash changes. Watch the\n"
     "  policy_bundle.hash line flip FAIL -> PASS when the pinned hash matches."),
    ("3", "Offline TRACE verification",
     "demo-03-offline-trace/run.py",
     "Verify the demo-1 claim with nothing but the claim and a public key. No network."),
    ("4", "Context-aware enforcement",
     "demo-04-context-enforcement/run.py",
     "The same tool is allowed in one workflow and denied in another. Enforcement is\n"
     "  on the declared call context, not on the model's stated intent."),
    ("5", "Attribute-based enforcement",
     "demo-05-compliance-domain/run.py",
     "A tool that is not BAA-covered is refused by one guardrail rule, whatever it is\n"
     "  named. The decision is on the tool's compliance attribute, not its identity."),
    ("6", "Weight custody",
     "demo-06-weight-custody/run.py",
     "A checkpoint signed to its exact weight hash. Attestation gates the key, a\n"
     "  tampered fork is refused before load, and a fine-tune's lineage verifies back to\n"
     "  the signed base. Possession is not provenance."),
    ("7", "Closed-weight custody",
     "demo-07-closed-weight/run.py",
     "The frontier case where secrecy is the job: closed weights, the key releases only\n"
     "  into the attested lab-signed enclave, and an unapproved serving stack gets\n"
     "  nothing. The mirror of demo 6's open-weight framing."),
    ("8", "Derivative lineage",
     "demo-08-derivative-lineage/run.py",
     "The fine-tune is the real IP. A derivative gets its own manifest with derived_from\n"
     "  and a rights split; lineage resolves it to the base, and the base's terms travel\n"
     "  down the chain (a fork of a no-derivatives model is rejected)."),
    ("9", "Sovereign threshold",
     "demo-09-sovereign-threshold/run.py",
     "The model key is split 2-of-3 across independent parties, each releasing its share\n"
     "  only against attestation. A quorum reconstructs; one forged root is below\n"
     "  threshold, which is why threshold is a prerequisite for sovereign self-custody."),
    ("10", "Governed model calls",
     "demo-10-model-gateway/run.py",
     "The other demos govern tool calls; this one governs model calls. An\n"
     "  OpenAI-compatible endpoint routes by data class: PII leaves only once\n"
     "  identifiers are stripped, confidential stays in region, and PHI also\n"
     "  stays off shared infrastructure."),
]

GREEN = "\033[92m"; BLUE = "\033[96m"; DIM = "\033[90m"; BOLD = "\033[1m"; RST = "\033[0m"


def _c(s, color):
    # colour only when attached to a real terminal
    return f"{color}{s}{RST}" if sys.stdout.isatty() else s


def banner(idx, title, blurb):
    line = "=" * 70
    print()
    print(_c(line, DIM))
    print(_c(f"  DEMO {idx}:  {title}", BOLD + BLUE))
    print(f"  {blurb}")
    print(_c(line, DIM))
    print()


def _venv_python():
    p = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    return p if p.exists() else None


def _reexec_into_venv_if_needed():
    """If this interpreter can't resolve cmcp but the demo .venv can, re-run there.
    Makes `python demo.py` work regardless of which Python is on PATH."""
    if os.environ.get("_DEMO_REEXEC"):
        return
    if shutil.which("cmcp") or _cmcp_in_scripts():
        return
    vp = _venv_python()
    if not vp:
        return
    os.environ["_DEMO_REEXEC"] = "1"
    rc = subprocess.run([str(vp), str(pathlib.Path(__file__).resolve()), *sys.argv[1:]]).returncode
    sys.exit(rc)


def preflight():
    if not (shutil.which("cmcp") or _cmcp_in_scripts()):
        print(_c("cmcp not found.", BOLD))
        print("Set up the demo environment once:")
        print("  python -m venv .venv")
        print("  .venv\\Scripts\\python -m pip install cmcp-runtime   # (Scripts/ -> bin/ on macOS/Linux)")
        print("Then just run:  python demo.py")
        sys.exit(1)
    ver = _cmcp_version()
    print(_c(f"cmcp-runtime {ver or '(unknown)'} detected.", DIM))
    if ver and _older_than(ver, (0, 3, 0)):
        print(_c(
            "  WARNING: the demo narration assumes 0.3.0+. On this older version, demo 2\n"
            "  step 6 and demo 3 will read 'verified' instead of 'partially_verified'.\n"
            "  For the talk, upgrade:  pip install -U cmcp-runtime", BOLD))


def _cmcp_version():
    try:
        import importlib.metadata as m
        return m.version("cmcp-runtime")
    except Exception:
        return None


def _older_than(ver, target):
    try:
        parts = tuple(int(x) for x in ver.split(".")[:3])
        return parts < target
    except Exception:
        return False


def _cmcp_in_scripts():
    import sysconfig
    for base in (pathlib.Path(sys.executable).parent,
                 pathlib.Path(sysconfig.get_path("scripts")),
                 pathlib.Path(sysconfig.get_path("scripts", "nt_user"))):
        for name in ("cmcp.exe", "cmcp"):
            if (base / name).exists():
                return True
    return False


def run(idx, title, script, blurb, pause):
    if pause:
        try:
            input(_c(f">>> Press Enter to run Demo {idx}: {title} ", GREEN))
        except (EOFError, KeyboardInterrupt):
            print("\nStopped."); sys.exit(0)
    banner(idx, title, blurb)
    try:
        rc = subprocess.run(
            [sys.executable, str(ROOT / script)], timeout=180
        ).returncode
    except subprocess.TimeoutExpired:
        print(_c(f"\n[!] Demo {idx} timed out after 180 seconds.", BOLD))
        return 1
    if rc != 0:
        print(_c(f"\n[!] Demo {idx} exited with code {rc}. See the *.log files in the demo folder.", BOLD))
    return rc


def main():
    ap = argparse.ArgumentParser(description="Run the agentrust-io trust-chain demos.")
    ap.add_argument("only", nargs="?", choices=[d[0] for d in DEMOS], help="run only this demo")
    ap.add_argument("--no-pause", action="store_true", help="run straight through, no prompts")
    args = ap.parse_args()

    os.environ.setdefault("CMCP_BEARER_TOKEN", "demo-token")
    os.environ.setdefault("CMCP_DEV_MODE", "1")
    _reexec_into_venv_if_needed()
    preflight()

    print(_c("\nagentrust-io  ·  the trust chain, live", BOLD))
    print(_c("Agent Manifest (what the agent is)  ·  cMCP (what it does)  ·  TRACE (the proof)", DIM))

    selected = [d for d in DEMOS if (args.only is None or d[0] == args.only)]
    pause = not args.no_pause and sys.stdin.isatty()

    failures = 0
    for idx, title, script, blurb in selected:
        if run(idx, title, script, blurb, pause) != 0:
            failures += 1

    print()
    if failures:
        print(_c(f"Done with {failures} failure(s).", BOLD))
        sys.exit(1)
    print(_c("Done. The proof outlives the runtime that made it.", BOLD + GREEN))


if __name__ == "__main__":
    main()
