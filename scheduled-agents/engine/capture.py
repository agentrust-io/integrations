"""AgenTrust capture engine for Claude Code scheduled agents.

A coding-agent session is something you drive: you watch every tool call. A
scheduled agent is not. It runs on a cron, headless, and keeps running long
after you set it up. "Set it and forget it" assumes the agent's behaviour next
week is the agent's behaviour today. It rarely is.

This engine fingerprints the things that act WITHOUT you watching and warns when
any of them drifts from a baseline you approved:

  * routines -- declared scheduled-agent specs: schedule, allowed tools, MCP
    servers, prompt, model. Claude Code does not expose its cloud routines on
    disk, so you DECLARE each routine's approved shape as a spec file and this
    engine baselines it. Drift means the committed definition changed, not that
    a live cloud routine was introspected.
  * hooks -- the commands in ~/.claude/settings.json that auto-run on events
    (SessionStart, PreToolUse, ...). These fire on their own; a widened or
    added hook command is a real change to what runs behind your back.

The core question it answers: "are the things that run without me watching the
ones I approved -- nothing added, nothing subtracted?"

The SessionStart hook and the drift check (snapshot / verify / approve) use only
the Python standard library. Signing a TRACE Trust Record (report / approve
--sign) needs agentrust-trace and runs only on demand.

Safety: hashes prompts and settings, never stores secrets. Records routine,
tool, MCP, and hook-command NAMES only, never tokens or environment values.
Never reads .credentials.json.

Subcommands:
  snapshot   capture the scheduled-agent surface from disk (stdlib only)
  hook       SessionStart entrypoint: snapshot + drift check + warn
  verify     diff the current surface against the approved baseline
  approve    promote the current surface to the approved baseline
  report     build + sign a TRACE record of the current surface, render it
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

CLAUDE_HOME = Path(os.path.expanduser("~")) / ".claude"
STATE_DIR = CLAUDE_HOME / "agentrust" / "scheduled"
BASELINE = STATE_DIR / "baseline.json"
LATEST = STATE_DIR / "session-latest.json"
SIGNING_KEY = STATE_DIR / "signing_key.json"
SETTINGS = CLAUDE_HOME / "settings.json"

CATEGORIES = ["routines", "hooks"]


# --------------------------------------------------------------------------- #
# hashing (never secrets)
# --------------------------------------------------------------------------- #
def _sha_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def _sha_text(s: str) -> str:
    return _sha_bytes(s.encode("utf-8"))


def _sha_obj(obj: object) -> str:
    return _sha_bytes(json.dumps(obj, sort_keys=True).encode("utf-8"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _uuid7() -> str:
    """RFC 9562 UUID v7 (time-ordered)."""
    ms = int(time.time() * 1000)
    b = bytearray(ms.to_bytes(6, "big") + os.urandom(10))
    b[6] = 0x70 | (b[6] & 0x0F)
    b[8] = 0x80 | (b[8] & 0x3F)
    return str(uuid.UUID(bytes=bytes(b)))


# --------------------------------------------------------------------------- #
# snapshot: read the surface that runs without you (stdlib only)
# --------------------------------------------------------------------------- #
def _routines_dir() -> Path:
    """Where declared routine specs live. Override with AGENTRUST_ROUTINES_DIR."""
    env = os.environ.get("AGENTRUST_ROUTINES_DIR")
    if env:
        return Path(os.path.expanduser(env))
    return CLAUDE_HOME / "agentrust" / "routines"


def _str_list(v: object) -> list[str]:
    """A sorted list of the string items in v, or [] if v is not a list."""
    if not isinstance(v, list):
        return []
    return sorted(x for x in v if isinstance(x, str))


def _routine_prompt_hash(spec: dict, rdir: Path) -> str:
    """Hash the routine's instruction, whether inline (``prompt``) or in a file
    (``prompt_file``, resolved relative to the routines dir). Missing prompt
    hashes the empty string so an added prompt later reads as a change."""
    prompt = spec.get("prompt")
    if isinstance(prompt, str):
        return _sha_text(prompt)
    pf = spec.get("prompt_file")
    if isinstance(pf, str):
        p = Path(os.path.expanduser(pf))
        if not p.is_absolute():
            p = rdir / pf
        try:
            if p.is_file():
                return _sha_bytes(p.read_bytes())
        except OSError:
            pass
    return _sha_text("")


def _routines() -> dict[str, dict]:
    """Fingerprint each declared routine spec. Best-effort: a missing dir,
    unreadable file, bad JSON, or non-object spec is skipped, never fatal."""
    out: dict[str, dict] = {}
    rdir = _routines_dir()
    if not rdir.is_dir():
        return out
    try:
        files = sorted(rdir.glob("*.json"))
    except OSError:
        return out
    for f in files:
        try:
            spec = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(spec, dict):
            continue
        name = spec.get("name") if isinstance(spec.get("name"), str) else f.stem
        schedule = spec.get("schedule") if isinstance(spec.get("schedule"), str) else ""
        model = spec.get("model") if isinstance(spec.get("model"), str) else ""
        out[name] = {
            "schedule": schedule,
            "prompt_hash": _routine_prompt_hash(spec, rdir),
            "allowed_tools": _str_list(spec.get("allowed_tools")),
            "mcp_servers": _str_list(spec.get("mcp_servers")),
            "model": model,
        }
    return out


def _hooks() -> dict[str, list[str]]:
    """The auto-run hook commands declared per event in ~/.claude/settings.json.

    Returns {event: sorted[command, ...]}. Best-effort: a missing, unreadable,
    malformed, or unexpectedly-shaped settings file yields {}, never an
    exception. Records the command strings only, never their output.
    """
    if not SETTINGS.is_file():
        return {}
    try:
        data = json.loads(SETTINGS.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return {}
    out: dict[str, list[str]] = {}
    for event, groups in hooks.items():
        if not isinstance(event, str) or not isinstance(groups, list):
            continue
        cmds: list[str] = []
        for group in groups:
            if not isinstance(group, dict):
                continue
            entries = group.get("hooks")
            if not isinstance(entries, list):
                continue
            for h in entries:
                if isinstance(h, dict) and isinstance(h.get("command"), str):
                    cmds.append(h["command"])
        if cmds:
            out[event] = sorted(cmds)
    return out


def _identity() -> str:
    host = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "localhost"
    user = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
    return f"spiffe://claude-code.local/{user}/{host}".lower()


def snapshot() -> dict:
    """Capture the scheduled-agent surface. Everything here is observable from
    disk, so a SessionStart hook sees exactly what an interactive command sees --
    no live runtime context is needed."""
    routines = _routines()
    hooks = _hooks()
    return {
        "captured_at": _now_iso(),
        "observed": list(CATEGORIES),
        "agent_id": _identity(),
        "routines": routines,
        "hooks": hooks,
        "hashes": {
            "routines_set": _sha_obj(routines),
            "hooks_set": _sha_obj(hooks),
        },
    }


# --------------------------------------------------------------------------- #
# diff: nothing added, nothing subtracted
# --------------------------------------------------------------------------- #
def _diff_routines(base: dict, cur: dict) -> list[dict]:
    out: list[dict] = []
    b, c = base.get("routines", {}), cur.get("routines", {})
    for name in sorted(set(c) - set(b)):
        out.append({"change": "added", "what": "routine", "detail": name})
    for name in sorted(set(b) - set(c)):
        out.append({"change": "removed", "what": "routine", "detail": name})
    for name in sorted(set(b) & set(c)):
        rb, rc = b[name], c[name]
        if rb.get("schedule") != rc.get("schedule"):
            out.append({"change": "changed", "what": "routine schedule",
                        "detail": f"{name}: {rb.get('schedule') or '(none)'} -> {rc.get('schedule') or '(none)'}"})
        if rb.get("model") != rc.get("model"):
            out.append({"change": "changed", "what": "routine model",
                        "detail": f"{name}: {rb.get('model') or '(none)'} -> {rc.get('model') or '(none)'}"})
        if rb.get("prompt_hash") != rc.get("prompt_hash"):
            out.append({"change": "changed", "what": "routine prompt", "detail": name})
        bt, ct = set(rb.get("allowed_tools", [])), set(rc.get("allowed_tools", []))
        for t in sorted(ct - bt):
            out.append({"change": "added", "what": "routine tool", "detail": f"{name}: {t}"})
        for t in sorted(bt - ct):
            out.append({"change": "removed", "what": "routine tool", "detail": f"{name}: {t}"})
        bm, cm = set(rb.get("mcp_servers", [])), set(rc.get("mcp_servers", []))
        for s in sorted(cm - bm):
            out.append({"change": "added", "what": "routine MCP server", "detail": f"{name}: {s}"})
        for s in sorted(bm - cm):
            out.append({"change": "removed", "what": "routine MCP server", "detail": f"{name}: {s}"})
    return out


def _diff_hooks(base: dict, cur: dict) -> list[dict]:
    out: list[dict] = []
    b, c = base.get("hooks", {}), cur.get("hooks", {})
    for event in sorted(set(b) | set(c)):
        bset, cset = set(b.get(event, [])), set(c.get(event, []))
        for cmd in sorted(cset - bset):
            out.append({"change": "added", "what": "hook", "detail": f"{event}: {cmd}"})
        for cmd in sorted(bset - cset):
            out.append({"change": "removed", "what": "hook", "detail": f"{event}: {cmd}"})
    return out


def diff(base: dict, cur: dict) -> list[dict]:
    """Return a list of {change, what, detail}, change in {added,removed,changed}.

    Only categories BOTH snapshots observed are compared, so a snapshot taken by
    an older engine that measured fewer categories is never falsely reported as
    having removed the rest.
    """
    obs = set(base.get("observed", CATEGORIES)) & set(cur.get("observed", CATEGORIES))
    out: list[dict] = []
    if "routines" in obs:
        out += _diff_routines(base, cur)
    if "hooks" in obs:
        out += _diff_hooks(base, cur)
    return out


# --------------------------------------------------------------------------- #
# signed TRACE record (lazy import -- only when generating a report)
# --------------------------------------------------------------------------- #
def build_trace(cur: dict) -> dict:
    """A TRACE Trust Record for the scheduled-agent surface. Software integrity
    only: Level 0, no hardware attestation on a normal dev box. enforcement_mode
    is 'advisory' because this warns, it does not block a routine from running."""
    return {
        "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
        "iat": int(time.time()),
        "subject": cur["agent_id"],
        "model": {"provider": "anthropic", "model_id": "unknown", "version": "unknown"},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
        "policy": {"bundle_hash": cur["hashes"]["hooks_set"], "enforcement_mode": "advisory"},
        "data_class": "internal",
        "build_provenance": {"slsa_level": 0, "digest": cur["hashes"]["routines_set"]},
        "appraisal": {"status": "none", "verifier": "https://claude-code.local"},
        "transparency": "https://registry.agentrust.io/claim/placeholder",
    }


def _load_or_create_trace_key():
    """Return a stable Ed25519 signing key, persisted at ~/.claude/agentrust.

    Signing with a fresh key each run would give the surface a different identity
    every session and make records unlinkable. One persisted key, whose public
    JWK is published beside each record, lets any third party verify trace.json
    without trusting this machine. The private half never leaves ~/.claude.
    """
    from agentrust_trace import generate_key, key_to_jwk, load_key
    from cryptography.hazmat.primitives import serialization as ser

    existing = _load(SIGNING_KEY)
    if existing and isinstance(existing.get("private_pem"), str):
        try:
            return load_key(existing["private_pem"])
        except (ValueError, TypeError):
            pass  # corrupt key: fall through and mint a fresh one

    key = generate_key()
    pem = key.private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()
    ).decode("utf-8")
    SIGNING_KEY.parent.mkdir(parents=True, exist_ok=True)
    SIGNING_KEY.write_text(
        json.dumps(
            {"algorithm": "Ed25519", "private_pem": pem,
             "jwk": key_to_jwk(key), "created_at": _now_iso()},
            indent=2,
        ),
        encoding="utf-8",
    )
    try:  # best-effort owner-only permissions (no-op where unsupported)
        os.chmod(SIGNING_KEY, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return key


def sign_all(cur: dict, outdir: Path) -> dict:
    try:
        from agentrust_trace import key_to_jwk, sign_record, verify_record
    except ImportError as e:
        raise SystemExit(
            "Signing needs agentrust-trace, which is not installed. Run:\n"
            "  pip install -r requirements.txt\n"
            f"(missing module: {e.name}). Drift detection (snapshot / verify / "
            "approve without --sign) does not need it."
        )
    key = _load_or_create_trace_key()
    record = sign_record(build_trace(cur), key)
    verify_record(record, key_to_jwk(key))  # self-check: the record verifies

    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "trace.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    (outdir / "verification_key.json").write_text(
        json.dumps(
            {"algorithm": "Ed25519", "jwk": key_to_jwk(key),
             "note": "verify trace.json with agentrust_trace.verify_record(record, jwk)"},
            indent=2,
        ),
        encoding="utf-8",
    )
    return record


# --------------------------------------------------------------------------- #
# report rendering
# --------------------------------------------------------------------------- #
def render_report(cur: dict, changes: list[dict] | None, signed: bool) -> str:
    routines, hooks = cur["routines"], cur["hooks"]
    n_hook_cmds = sum(len(v) for v in hooks.values())
    L = ["=" * 66,
         "  SCHEDULED-AGENT INTEGRITY REPORT  --  Claude Code routines & hooks",
         "=" * 66, "",
         f"  Agent identity : {cur['agent_id']}",
         f"  Captured       : {cur['captured_at']}", "",
         "  WHAT RUNS WITHOUT YOU WATCHING",
         "  " + "-" * 62,
         f"  Routines       : {len(routines)} declared"]
    for name in sorted(routines):
        r = routines[name]
        L.append(f"    - {name}  [{r['schedule'] or 'no schedule'}]  "
                 f"{len(r['allowed_tools'])} tool(s), {len(r['mcp_servers'])} MCP")
    L.append(f"  Auto-run hooks : {n_hook_cmds} command(s) across {len(hooks)} event(s)")
    for event in sorted(hooks):
        L.append(f"    - {event}: {len(hooks[event])} command(s)")
    L += ["",
          "  Fingerprints (change here == something runs differently):",
          f"    routines set : {cur['hashes']['routines_set'][:23]}...",
          f"    hooks set    : {cur['hashes']['hooks_set'][:23]}...", ""]
    if changes is not None:
        L += ["  NOTHING ADDED, NOTHING SUBTRACTED?  (vs approved baseline)",
              "  " + "-" * 62]
        if not changes:
            L.append("  >> Verified: nothing added, nothing subtracted.")
        else:
            sym = {"added": "+", "removed": "-", "changed": "~"}
            for c in changes:
                L.append(f"  {sym[c['change']]} {c['change'].upper()} {c['what']}: {c['detail']}")
            L.append(f"  >> {len(changes)} change(s) since baseline. Review above.")
        L.append("")
    if signed:
        L += ["  Signed record written: trace.json (TRACE Level 0, software-only),",
              "                         verification_key.json (public key to verify",
              "                         trace.json on another machine).", ""]
    L.append("=" * 66)
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# state helpers
# --------------------------------------------------------------------------- #
def _save(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def _load(path: Path) -> dict | None:
    """Load a state file, or None if absent, unreadable, or corrupt.

    A truncated baseline (crash mid-write, disk full, racing sessions) must not
    brick the hook forever. Treating corrupt state as absent lets the next run
    re-establish it.
    """
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #
def cmd_snapshot(args) -> int:
    snap = snapshot()
    _save(LATEST, snap)
    print(json.dumps(snap, indent=2) if args.json else render_report(snap, None, False))
    return 0


def _emit_context(msg: str) -> None:
    out = {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": msg}}
    print(json.dumps(out))


def _hook_body() -> None:
    snap = snapshot()
    _save(LATEST, snap)
    base = _load(BASELINE)
    n_routines, n_hooks = len(snap["routines"]), sum(len(v) for v in snap["hooks"].values())
    if base is None:
        _save(BASELINE, snap)
        msg = (f"AgenTrust: scheduled-agent baseline established "
               f"({n_routines} routine(s), {n_hooks} auto-run hook command(s)). "
               "Future sessions are checked against it. Run /schedule-manifest approve to re-baseline.")
    else:
        changes = diff(base, snap)
        if not changes:
            msg = ("AgenTrust: your scheduled agents and auto-run hooks are unchanged since "
                   "your approved baseline (nothing added, nothing subtracted).")
        else:
            detail = "; ".join(f"{c['change']} {c['what']} {c['detail']}" for c in changes[:8])
            msg = (f"AgenTrust WARNING: {len(changes)} change(s) to what runs without you watching "
                   f"since baseline: {detail}. Run /schedule-manifest verify for detail, "
                   "or /schedule-manifest approve to accept.")
    _emit_context(msg)


def cmd_hook(args) -> int:
    """SessionStart entrypoint. A SessionStart hook must never block or break the
    session: whatever goes wrong, emit a benign context and exit 0."""
    try:
        _hook_body()
    except Exception:  # noqa: BLE001 -- last-resort guard: the session must start
        _emit_context(
            "AgenTrust: scheduled-agent check skipped this session (could not read the "
            "configuration). Run /schedule-manifest verify to check manually."
        )
    return 0


def cmd_verify(args) -> int:
    base = _load(BASELINE)
    # Always re-snapshot so verify reflects the CURRENT surface, not a cached
    # session-latest.json: a routine edited or a hook widened after session start
    # must still be caught.
    snap = snapshot()
    _save(LATEST, snap)
    if base is None:
        print("No approved baseline yet. Run /schedule-manifest approve to establish one.")
        return 0
    print(render_report(snap, diff(base, snap), False))
    return 0


def cmd_approve(args) -> int:
    snap = snapshot()
    _save(LATEST, snap)
    _save(BASELINE, snap)
    print(render_report(snap, [], False))
    print(f"\nApproved baseline updated: {BASELINE}")
    if args.sign:
        sign_all(snap, Path(args.out))
        print(f"Signed TRACE record written to {args.out}")
    return 0


def cmd_report(args) -> int:
    snap = snapshot()
    _save(LATEST, snap)
    base = _load(BASELINE)
    changes = diff(base, snap) if base else None
    sign_all(snap, Path(args.out))
    print(render_report(snap, changes, True))
    print(f"\nwrote {args.out}/trace.json  {args.out}/verification_key.json")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agentrust-scheduled-capture", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("snapshot", "hook", "verify", "approve", "report"):
        p = sub.add_parser(name)
        p.add_argument("--out", default=".", help="output dir for the signed record")
        p.add_argument("--json", action="store_true", help="emit raw JSON snapshot")
        p.add_argument("--sign", action="store_true", help="(approve) also write a signed record")
    args = ap.parse_args(argv)
    return {
        "snapshot": cmd_snapshot, "hook": cmd_hook, "verify": cmd_verify,
        "approve": cmd_approve, "report": cmd_report,
    }[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
