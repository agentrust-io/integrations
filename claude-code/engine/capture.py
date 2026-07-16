"""AgenTrust capture engine for Claude Code.

Introspects the running Claude Code agent and produces, for one session:

  * an Agent Manifest -- what the agent IS: skills, tools, MCP servers, model,
    permission policy, and instruction layer, each fingerprinted. Signed with
    agent-manifest (Ed25519).
  * a TRACE Trust Record -- what the agent DID this run. Signed with
    agentrust-trace. Shares the manifest's agent_id and policy hash.
  * a plain-English integrity report.

The design keeps the SessionStart hook cheap and dependency-free: `snapshot`,
`verify`, and `approve` use only the Python standard library. Signing (which
needs agent-manifest / agentrust-trace) runs only in `report` and `approve
--sign`, on demand.

The core question it answers: "is the agent I am running the one I approved --
nothing added, nothing subtracted?"

Safety: hashes files, never stores secrets. Never reads .credentials.json.
Records skill / MCP / tool NAMES only, never tokens or environment values.

Subcommands:
  snapshot   capture the agent's composition from disk (stdlib only)
  hook       SessionStart entrypoint: snapshot + drift check + warn
  verify     diff the latest snapshot against the approved baseline
  approve    promote the latest snapshot to the approved baseline
  report     build + sign the manifest and TRACE record, render the report
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

CLAUDE_HOME = Path(os.path.expanduser("~")) / ".claude"
STATE_DIR = CLAUDE_HOME / "agentrust"
BASELINE = STATE_DIR / "baseline.json"
LATEST = STATE_DIR / "session-latest.json"
SIGNING_KEY = STATE_DIR / "signing_key.json"


# --------------------------------------------------------------------------- #
# hashing (files only, never secrets)
# --------------------------------------------------------------------------- #
def _sha_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def _sha_file(p: Path) -> str:
    return _sha_bytes(p.read_bytes())


def _sha_tree(root: Path, pattern: str = "*.md") -> str:
    if not root.exists():
        return _sha_bytes(b"")
    h = hashlib.sha256()
    for f in sorted(root.rglob(pattern)):
        if f.is_file():
            h.update(f.relative_to(root).as_posix().encode())
            h.update(b"\0")
            h.update(f.read_bytes())
            h.update(b"\0")
    return "sha256:" + h.hexdigest()


def _uuid7() -> str:
    """RFC 9562 UUID v7 (time-ordered) -- required by agent-manifest."""
    ms = int(time.time() * 1000)
    b = bytearray(ms.to_bytes(6, "big") + os.urandom(10))
    b[6] = 0x70 | (b[6] & 0x0F)
    b[8] = 0x80 | (b[8] & 0x3F)
    return str(uuid.UUID(bytes=bytes(b)))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# snapshot: read the real box (stdlib only)
# --------------------------------------------------------------------------- #
def _skills() -> dict[str, str]:
    out: dict[str, str] = {}
    sdir = CLAUDE_HOME / "skills"
    # is_dir(), not exists(): tolerate ~/.claude/skills being a stray file.
    if not sdir.is_dir():
        return out
    try:
        entries = sorted(sdir.iterdir())
    except OSError:
        return out
    for d in entries:
        sk = d / "SKILL.md"
        try:
            if sk.is_file():
                out[d.name] = _sha_file(sk)
        except OSError:
            continue  # unreadable skill file: skip it, never crash the hook
    return out


def _server_names(mapping: object) -> list[str]:
    """Keys of a config mapping, or [] if it is not a dict (malformed config)."""
    return list(mapping.keys()) if isinstance(mapping, dict) else []


def _policy() -> tuple[str, list[str]]:
    settings = CLAUDE_HOME / "settings.json"
    if not settings.is_file():
        return _sha_bytes(b"{}"), []
    # Always hash the real file bytes so a hand-edit is detected as drift, even
    # if the JSON is malformed. Parsing the allow-list is best-effort: bad JSON
    # or an unexpected shape yields an empty list rather than crashing the hook.
    try:
        policy_hash = _sha_file(settings)
    except OSError:
        return _sha_bytes(b"{}"), []
    allow: list[str] = []
    try:
        data = json.loads(settings.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            perms = data.get("permissions")
            if isinstance(perms, dict) and isinstance(perms.get("allow"), list):
                allow = perms["allow"]
    except (json.JSONDecodeError, OSError):
        pass
    return policy_hash, allow


def _mcp_from_config() -> list[str]:
    """MCP server names declared on disk (global + per-project). Names only.

    Best-effort: a missing, unreadable, malformed, or unexpectedly-shaped
    ``~/.claude.json`` yields an empty list, never an exception.
    """
    servers: set[str] = set()
    cfg = Path(os.path.expanduser("~")) / ".claude.json"
    if not cfg.is_file():
        return []
    try:
        data = json.loads(cfg.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, dict):
        return []
    servers.update(_server_names(data.get("mcpServers")))
    projects = data.get("projects")
    if isinstance(projects, dict):
        for proj in projects.values():
            if isinstance(proj, dict):
                servers.update(_server_names(proj.get("mcpServers")))
    return sorted(servers)


def _identity() -> str:
    host = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "localhost"
    user = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
    return f"spiffe://claude-code.local/{user}/{host}".lower()


def snapshot(live: dict | None = None) -> dict:
    """Capture the agent's composition. `live` carries session facts the agent
    knows at runtime (model, tool roster, connected MCP servers) that a shell
    hook cannot see; merged in when present."""
    live = live or {}
    skills = _skills()
    policy_hash, allow = _policy()
    prompt_hash = _sha_tree(CLAUDE_HOME / "projects")  # instruction / memory layer

    # Skills, permissions, and the instruction layer are observable from disk in
    # any context (including the shell hook). The live tool roster and connected
    # MCP servers are runtime state only the agent can report; they are recorded
    # -- and diffed -- only when a live context supplies them. `observed` marks
    # which categories this snapshot actually measured, so a disk-only hook
    # snapshot is never diffed against the live categories of a richer baseline.
    observed = ["skills", "policy", "prompt"]
    mcp_live = live.get("mcp_servers")
    mcp = mcp_live if mcp_live is not None else _mcp_from_config()
    builtin = live.get("builtin_tools") or []
    tools = sorted(builtin) + [f"mcp:{s}" for s in sorted(mcp)]
    if mcp_live is not None:
        observed.append("mcp")
    if builtin:
        observed.append("tools")

    return {
        "captured_at": _now_iso(),
        "observed": observed,
        "agent_id": _identity(),
        "model": {
            "provider": live.get("model_provider", "anthropic"),
            "model_id": live.get("model_id", "unknown"),
            "version": live.get("model_version", "unknown"),
            "capability_level": live.get("capability_level"),
        },
        "skills": skills,
        "policy_hash": policy_hash,
        "allow_rules": allow,
        "prompt_hash": prompt_hash,
        "mcp_servers": mcp,
        "tools": tools,
        "data_class": live.get("data_class", "internal"),
        "hashes": {
            "system_prompt": prompt_hash,
            "policy_bundle": policy_hash,
            "skills_set": _sha_bytes(json.dumps(skills, sort_keys=True).encode()),
            "tool_catalog": _sha_bytes(json.dumps(tools, sort_keys=True).encode()),
        },
    }


# --------------------------------------------------------------------------- #
# diff: nothing added, nothing subtracted
# --------------------------------------------------------------------------- #
def diff(base: dict, cur: dict) -> list[dict]:
    """Return a list of {change, what, detail}, change in {added,removed,changed}.

    Only categories BOTH snapshots observed are compared, so a disk-only hook
    snapshot never reports the live tool roster of a richer baseline as removed.
    """
    out: list[dict] = []
    obs = set(base.get("observed", ["skills", "policy", "prompt"])) & set(
        cur.get("observed", ["skills", "policy", "prompt"])
    )

    if "prompt" in obs and base["hashes"].get("system_prompt") != cur["hashes"].get("system_prompt"):
        out.append({"change": "changed", "what": "instruction layer", "detail": "system_prompt"})
    if "policy" in obs and base["hashes"].get("policy_bundle") != cur["hashes"].get("policy_bundle"):
        out.append({"change": "changed", "what": "permissions", "detail": "policy_bundle"})

    if "skills" in obs:
        b_sk, c_sk = base.get("skills", {}), cur.get("skills", {})
        for name in sorted(set(c_sk) - set(b_sk)):
            out.append({"change": "added", "what": "skill", "detail": name})
        for name in sorted(set(b_sk) - set(c_sk)):
            out.append({"change": "removed", "what": "skill", "detail": name})
        for name in sorted(set(b_sk) & set(c_sk)):
            if b_sk[name] != c_sk[name]:
                out.append({"change": "changed", "what": "skill", "detail": name})

    if "mcp" in obs:
        b_mcp, c_mcp = set(base.get("mcp_servers", [])), set(cur.get("mcp_servers", []))
        for s in sorted(c_mcp - b_mcp):
            out.append({"change": "added", "what": "MCP server", "detail": s})
        for s in sorted(b_mcp - c_mcp):
            out.append({"change": "removed", "what": "MCP server", "detail": s})

    if "tools" in obs:
        b_t, c_t = set(base.get("tools", [])), set(cur.get("tools", []))
        for t in sorted(c_t - b_t):
            out.append({"change": "added", "what": "tool", "detail": t})
        for t in sorted(b_t - c_t):
            out.append({"change": "removed", "what": "tool", "detail": t})
    return out


# --------------------------------------------------------------------------- #
# signed records (lazy imports -- only when generating a report)
# --------------------------------------------------------------------------- #
def build_manifest(cur: dict) -> dict:
    now = _now_iso()
    expires = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    m = cur["model"]
    tools = [
        {
            "tool_id": (f"claude-code.mcp.{t[4:]}" if t.startswith("mcp:")
                        else f"claude-code.builtin.{t}"),
            "tool_name": t,
            "endpoint_id": (f"spiffe://claude-code.local/mcp/{t[4:]}".lower()
                            if t.startswith("mcp:") else "spiffe://claude-code.local/host"),
            "schema_hash": _sha_bytes(t.encode()),
            "description_hash": _sha_bytes(("desc:" + t).encode()),
            "version": "1.0.0",
            "egress_destinations": ["claude.ai"] if t.startswith("mcp:") else [],
        }
        for t in cur["tools"]
    ]
    return {
        "@context": "https://agentmanifest.agentrust.io/v0.1/context.json",
        "@type": "AgentManifest",
        "manifest_id": _uuid7(),
        "agent_id": cur["agent_id"],
        "version": "0.1",
        "issued_at": now,
        "expires_at": expires,
        "issuer": "spiffe://claude-code.local/self-signed",
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {
                "hash": cur["hashes"]["system_prompt"],
                "hash_algorithm": "SHA-256",
                "version": "1.0.0",
                "classification": "internal",
                "bound_at": now,
            },
            "policy_bundle": {
                # policy_language has no host-native value for Claude Code
                # permissions; modelled as composite. See README "Known gaps".
                "hash": cur["hashes"]["policy_bundle"],
                "policy_language": "composite",
                "version": "1.0.0",
                "enforcement_mode": "enforce",
                "scope": cur["allow_rules"][:32] or ["claude-code:permissions"],
                "agt_version": "0.0.0-claude-code",
                "bound_at": now,
            },
            "tool_manifest": {
                "catalog_hash": cur["hashes"]["tool_catalog"],
                "tools": tools,
                "allow_dynamic_registration": True,
                "rug_pull_policy": "deny-and-alert",
                "bound_at": now,
            },
            "model_identity": {
                "provider": m["provider"],
                "model_id": m["model_id"],
                "version": m["version"],
                "capability_level": m.get("capability_level"),
                "deployment_type": "api",
                "model_attestation_type": "provider-asserted",
                "bound_at": now,
            },
        },
    }


def build_trace(cur: dict) -> dict:
    return {
        "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
        "iat": int(time.time()),
        "subject": cur["agent_id"],
        "model": {k: cur["model"][k] for k in ("provider", "model_id", "version")},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
        "policy": {"bundle_hash": cur["hashes"]["policy_bundle"], "enforcement_mode": "enforce"},
        "data_class": cur["data_class"],
        "build_provenance": {"slsa_level": 0, "digest": cur["hashes"]["tool_catalog"]},
        "appraisal": {"status": "none", "verifier": "https://claude-code.local"},
        "transparency": "https://registry.agentrust.io/claim/placeholder",
    }


def sign_all(cur: dict, outdir: Path) -> tuple[dict, dict]:
    try:
        from agent_manifest import Ed25519Signer, Ed25519Verifier, Manifest
        from agentrust_trace import generate_key, sign_record
    except ImportError as e:
        raise SystemExit(
            "Signing needs the crypto packages, which are not installed. Run:\n"
            "  pip install -r requirements.txt\n"
            f"(missing module: {e.name}). Drift detection (snapshot / verify / "
            "approve without --sign) does not need them."
        )

    kp = _load_or_create_manifest_keypair()

    manifest = build_manifest(cur)
    Manifest.model_validate(manifest)
    manifest["signature"] = Ed25519Signer(kp).sign(manifest)
    Ed25519Verifier(kp.public_bytes).verify(manifest, manifest["signature"]["signature_value"])

    trace = sign_record(build_trace(cur), generate_key())

    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (outdir / "trace.json").write_text(json.dumps(trace, indent=2), encoding="utf-8")
    # Publish the public key so a third party can verify manifest.json without
    # trusting this machine: load it into the verifier's trusted_keys as
    # {key_id: public_key_b64url}. The private key never leaves ~/.claude.
    verification_key = {
        "algorithm": "Ed25519",
        "key_id": kp.key_id,
        "public_key_b64url": kp.public_b64url(),
        "note": "load as {key_id: public_key_b64url} into the verifier's trusted_keys",
    }
    (outdir / "verification_key.json").write_text(
        json.dumps(verification_key, indent=2), encoding="utf-8"
    )
    return manifest, trace


def _load_or_create_manifest_keypair():
    """Return a stable Ed25519 keypair, persisted at ~/.claude/agentrust.

    Signing the Agent Manifest with a fresh key every run would make the
    signature unverifiable (nobody has the public half) and give the agent a
    different identity each session. Instead we persist one key and publish its
    public half beside each record, so manifest.json is genuinely third-party
    verifiable and records chain to a single identity. The private key stays
    local, readable only by the owner where the OS supports it.
    """
    from agent_manifest import Ed25519KeyPair, generate_ed25519
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    existing = _load(SIGNING_KEY)
    if existing and isinstance(existing.get("private_b64url"), str):
        try:
            pad = "=" * (-len(existing["private_b64url"]) % 4)
            raw = base64.urlsafe_b64decode(existing["private_b64url"] + pad)
            priv = Ed25519PrivateKey.from_private_bytes(raw)
            return Ed25519KeyPair(priv, priv.public_key())
        except (ValueError, TypeError):
            pass  # corrupt key file: fall through and mint a fresh one

    kp = generate_ed25519()
    SIGNING_KEY.parent.mkdir(parents=True, exist_ok=True)
    SIGNING_KEY.write_text(
        json.dumps(
            {
                "algorithm": "Ed25519",
                "key_id": kp.key_id,
                "public_key_b64url": kp.public_b64url(),
                "private_b64url": kp.private_b64url(),
                "created_at": _now_iso(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    try:  # best-effort owner-only permissions (no-op on filesystems without it)
        os.chmod(SIGNING_KEY, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return kp


# --------------------------------------------------------------------------- #
# report rendering
# --------------------------------------------------------------------------- #
def render_report(cur: dict, changes: list[dict] | None, signed: bool) -> str:
    m = cur["model"]
    n_builtin = len([t for t in cur["tools"] if not t.startswith("mcp:")])
    L = ["=" * 66,
         "  AGENT INTEGRITY REPORT  --  your Claude Code session",
         "=" * 66, "",
         f"  Agent identity : {cur['agent_id']}",
         f"  Model          : {m['provider']}/{m['model_id']} {m['version']}",
         f"  Captured       : {cur['captured_at']}", "",
         "  WHAT THIS AGENT IS  (agent-manifest -- signed composition)",
         "  " + "-" * 62,
         f"  Skills loaded  : {len(cur['skills'])}  ({', '.join(cur['skills']) or 'none'})",
         f"  Tools exposed  : {n_builtin} built-in + {len(cur['mcp_servers'])} MCP server(s)",
         f"  MCP servers    : {', '.join(cur['mcp_servers']) or 'none on disk'}",
         f"  Permissions    : {len(cur['allow_rules'])} allow-rule(s), enforce mode", "",
         "  Fingerprints (change here == your agent changed):",
         f"    instruction layer : {cur['hashes']['system_prompt'][:23]}...",
         f"    permissions       : {cur['hashes']['policy_bundle'][:23]}...",
         f"    skills set        : {cur['hashes']['skills_set'][:23]}...",
         f"    tool catalog      : {cur['hashes']['tool_catalog'][:23]}...", ""]
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
        L += ["  Signed records written: manifest.json (agent-manifest, verified),",
              "                          trace.json (TRACE Level 0, software-only),",
              "                          verification_key.json (public key to verify",
              "                          manifest.json on another machine).", ""]
    L.append("=" * 66)
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# state helpers
# --------------------------------------------------------------------------- #
def _save(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def _load(path: Path) -> dict | None:
    """Load a state file, or None if it is absent, unreadable, or corrupt.

    A truncated baseline.json (crash mid-write, disk full, racing sessions) must
    not brick the hook on every future session. Treating corrupt state as absent
    lets the next run re-establish it instead of crashing forever.
    """
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _live_from(args) -> dict | None:
    if args.live_context:
        return json.loads(Path(args.live_context).read_text(encoding="utf-8"))
    return None


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #
def cmd_snapshot(args) -> int:
    snap = snapshot(_live_from(args))
    _save(LATEST, snap)
    print(json.dumps(snap, indent=2) if args.json else render_report(snap, None, False))
    return 0


def _emit_context(msg: str) -> None:
    out = {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": msg}}
    print(json.dumps(out))


def _hook_body() -> None:
    try:
        payload = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except (json.JSONDecodeError, ValueError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    live = {k: payload[k] for k in ("model_id", "model_provider", "model_version") if k in payload}
    snap = snapshot(live or None)
    _save(LATEST, snap)

    base = _load(BASELINE)
    if base is None:
        _save(BASELINE, snap)
        msg = ("AgenTrust: baseline established for this Claude agent "
               f"({len(snap['skills'])} skills, {len(snap['mcp_servers'])} MCP on disk). "
               "Future sessions are checked against it. Run /manifest approve to re-baseline.")
    else:
        changes = diff(base, snap)
        if not changes:
            msg = "AgenTrust: agent composition unchanged since your approved baseline (nothing added, nothing subtracted)."
        else:
            detail = "; ".join(f"{c['change']} {c['what']} {c['detail']}" for c in changes[:8])
            msg = (f"AgenTrust WARNING: {len(changes)} change(s) to your agent since baseline: "
                   f"{detail}. Run /manifest verify for detail, or /manifest approve to accept.")
    _emit_context(msg)


def cmd_hook(args) -> int:
    """SessionStart entrypoint. Reads the hook payload on stdin, snapshots,
    checks drift against the baseline, and emits SessionStart context.

    A SessionStart hook must never block or break the session. Whatever goes
    wrong (unreadable config, a bug, an OS error), emit a benign context and
    exit 0 rather than dumping a traceback into the user's session.
    """
    try:
        _hook_body()
    except Exception:  # noqa: BLE001 -- last-resort guard: the session must start
        _emit_context(
            "AgenTrust: integrity check skipped this session (could not read the "
            "agent configuration). Run /manifest verify to check manually."
        )
    return 0


def cmd_verify(args) -> int:
    base = _load(BASELINE)
    # Always re-snapshot so verify reflects the agent's CURRENT composition,
    # not a cached session-latest.json. Otherwise drift introduced after
    # session start (a skill dropped in, a widened permission) would be missed
    # and verify would falsely report "nothing added, nothing subtracted".
    # The live context supplied by the /manifest command is merged in here.
    snap = snapshot(_live_from(args))
    _save(LATEST, snap)
    if base is None:
        print("No approved baseline yet. Run /manifest approve to establish one.")
        return 0
    print(render_report(snap, diff(base, snap), False))
    return 0


def cmd_approve(args) -> int:
    snap = snapshot(_live_from(args))
    _save(LATEST, snap)
    _save(BASELINE, snap)
    print(render_report(snap, [], False))
    print(f"\nApproved baseline updated: {BASELINE}")
    if args.sign:
        _, _ = sign_all(snap, Path(args.out))
        print(f"Signed manifest + trace written to {args.out}")
    return 0


def cmd_report(args) -> int:
    snap = snapshot(_live_from(args))
    _save(LATEST, snap)
    base = _load(BASELINE)
    changes = diff(base, snap) if base else None
    sign_all(snap, Path(args.out))
    print(render_report(snap, changes, True))
    print(f"\nwrote {args.out}/manifest.json  {args.out}/trace.json")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agentrust-capture", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("snapshot", "hook", "verify", "approve", "report"):
        p = sub.add_parser(name)
        p.add_argument("--live-context", help="JSON of live session facts (model, tools, mcp)")
        p.add_argument("--out", default=".", help="output dir for signed records")
        p.add_argument("--json", action="store_true", help="emit raw JSON snapshot")
        p.add_argument("--sign", action="store_true", help="(approve) also write signed records")
    args = ap.parse_args(argv)
    return {
        "snapshot": cmd_snapshot, "hook": cmd_hook, "verify": cmd_verify,
        "approve": cmd_approve, "report": cmd_report,
    }[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
