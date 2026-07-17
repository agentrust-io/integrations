"""AgenTrust capture engine for OpenAI Codex.

The SessionStart path uses the Python standard library. It fingerprints Codex
configuration and stores names plus hashes, never file contents, tokens,
environment values, auth data, or transcripts. Signing imports the released
Agent Manifest and TRACE packages only when a user requests a report.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import socket
import stat
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


VERSION = "0.1.0"
HOME = Path.home()
CODEX_HOME = Path(os.environ.get("CODEX_HOME", str(HOME / ".codex"))).expanduser()
STATE_DIR = Path(
    os.environ.get("AGENTRUST_STATE_DIR", str(CODEX_HOME / "agentrust"))
).expanduser()
SIGNING_KEY = STATE_DIR / "signing_key.json"

_CONFIG_VALUE_KEYS = ("approval_policy", "sandbox_mode")
_LIVE_KEYS = {
    "builtin_tools",
    "capability_level",
    "cwd",
    "data_class",
    "mcp_servers",
    "model_id",
    "model_provider",
    "model_version",
    "permission_mode",
    "session_id_hash",
}


def _sha_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _sha_file(path: Path) -> str:
    return _sha_bytes(path.read_bytes())


def _sha_mapping(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha_bytes(encoded)


def _safe_hash(path: Path) -> Optional[str]:
    try:
        if path.is_file() and not path.is_symlink():
            return _sha_file(path)
    except OSError:
        return None
    return None


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def _uuid7() -> str:
    milliseconds = int(time.time() * 1000)
    raw = bytearray(milliseconds.to_bytes(6, "big") + os.urandom(10))
    raw[6] = 0x70 | (raw[6] & 0x0F)
    raw[8] = 0x80 | (raw[8] & 0x3F)
    return str(uuid.UUID(bytes=bytes(raw)))


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9._-]+", "-", value.lower()).strip("-")
    return normalized or "unknown"


def _workspace(cwd: Optional[str] = None) -> Tuple[Path, List[Path], str]:
    try:
        current = Path(cwd or os.getcwd()).expanduser().resolve()
    except (OSError, RuntimeError):
        current = Path(os.getcwd())
    if not current.is_dir():
        current = current.parent

    upward = [current] + list(current.parents)
    root = next((path for path in upward if (path / ".git").exists()), current)
    chain: List[Path] = []
    cursor = current
    while True:
        chain.append(cursor)
        if cursor == root:
            break
        if root not in cursor.parents:
            chain = [current]
            root = current
            break
        cursor = cursor.parent
    chain.reverse()
    workspace_id = hashlib.sha256(str(root).encode("utf-8")).hexdigest()
    return root, chain, workspace_id


def _workspace_state(workspace_id: str) -> Tuple[Path, Path]:
    root = STATE_DIR / "workspaces" / workspace_id
    return root / "baseline.json", root / "session-latest.json"


def _logical_workspace_path(root: Path, path: Path) -> str:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.name
    return "workspace:" + (relative or ".")


def _instruction_fingerprints(root: Path, chain: Sequence[Path]) -> Dict[str, str]:
    found: Dict[str, str] = {}

    global_override = CODEX_HOME / "AGENTS.override.md"
    global_default = CODEX_HOME / "AGENTS.md"
    global_active = global_override if global_override.is_file() else global_default
    digest = _safe_hash(global_active)
    if digest:
        found["user:" + global_active.name] = digest

    memory_summary = CODEX_HOME / "memories" / "memory_summary.md"
    digest = _safe_hash(memory_summary)
    if digest:
        found["user:memories/memory_summary.md"] = digest

    for directory in chain:
        override = directory / "AGENTS.override.md"
        default = directory / "AGENTS.md"
        active = override if override.is_file() else default
        digest = _safe_hash(active)
        if digest:
            found[_logical_workspace_path(root, active)] = digest
    return dict(sorted(found.items()))


def _policy_fingerprints(root: Path, chain: Sequence[Path]) -> Dict[str, str]:
    found: Dict[str, str] = {}
    user_files = (
        CODEX_HOME / "config.toml",
        CODEX_HOME / "hooks.json",
        CODEX_HOME / "requirements.toml",
    )
    for path in user_files:
        digest = _safe_hash(path)
        if digest:
            found["user:" + path.name] = digest

    user_rules = CODEX_HOME / "rules"
    if user_rules.is_dir():
        for path in sorted(user_rules.rglob("*")):
            digest = _safe_hash(path)
            if digest:
                found["user:rules/" + path.relative_to(user_rules).as_posix()] = digest

    for directory in chain:
        layer = directory / ".codex"
        for filename in ("config.toml", "hooks.json", "requirements.toml"):
            path = layer / filename
            digest = _safe_hash(path)
            if digest:
                found[_logical_workspace_path(root, path)] = digest
        rules = layer / "rules"
        if rules.is_dir():
            for path in sorted(rules.rglob("*")):
                digest = _safe_hash(path)
                if digest:
                    found[_logical_workspace_path(root, path)] = digest
    return dict(sorted(found.items()))


def _skill_roots(chain: Sequence[Path]) -> List[Tuple[str, Path]]:
    roots: List[Tuple[str, Path]] = [
        ("user:agents", HOME / ".agents" / "skills"),
        ("user:codex", CODEX_HOME / "skills"),
    ]
    for index, directory in enumerate(chain):
        roots.append(("workspace:%d" % index, directory / ".agents" / "skills"))
    return roots


def _skill_fingerprints(chain: Sequence[Path]) -> Dict[str, str]:
    found: Dict[str, str] = {}
    for prefix, root in _skill_roots(chain):
        if not root.is_dir():
            continue
        try:
            candidates = sorted(root.rglob("SKILL.md"))
        except OSError:
            continue
        for path in candidates:
            digest = _safe_hash(path)
            if not digest:
                continue
            try:
                relative = path.parent.relative_to(root).as_posix()
            except ValueError:
                relative = path.parent.name
            found["%s:%s" % (prefix, relative)] = digest
    return dict(sorted(found.items()))


def _read_toml(path: Path) -> Optional[Dict[str, Any]]:
    try:
        import tomllib  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _fallback_toml_state(path: Path) -> Tuple[Set[str], Set[str], Dict[str, str]]:
    mcp: Set[str] = set()
    plugins: Set[str] = set()
    scopes: Dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return mcp, plugins, scopes

    header = re.compile(
        r'^\s*\[\s*(mcp_servers|plugins)\.(?:"([^"]+)"|([A-Za-z0-9_.@/-]+))\s*\]\s*$'
    )
    value_line = re.compile(
        r'^\s*(approval_policy|sandbox_mode)\s*=\s*["\']([^"\']+)["\']\s*$'
    )
    enabled_line = re.compile(r"^\s*enabled\s*=\s*(true|false)\s*$", re.IGNORECASE)
    current_plugin: Optional[str] = None
    for line in lines:
        match = header.match(line)
        if match:
            name = match.group(2) or match.group(3)
            current_plugin = name if match.group(1) == "plugins" else None
            (mcp if match.group(1) == "mcp_servers" else plugins).add(name)
            continue
        match = enabled_line.match(line)
        if match and current_plugin and match.group(1).lower() == "false":
            plugins.discard(current_plugin)
            continue
        match = value_line.match(line)
        if match:
            scopes[match.group(1)] = match.group(2)
    return mcp, plugins, scopes


def _config_state(paths: Iterable[Path]) -> Tuple[List[str], List[str], Dict[str, str]]:
    mcp: Set[str] = set()
    plugins: Set[str] = set()
    scopes: Dict[str, str] = {}
    for path in paths:
        if not path.is_file():
            continue
        data = _read_toml(path)
        if data is None:
            fallback_mcp, fallback_plugins, fallback_scopes = _fallback_toml_state(path)
            mcp.update(fallback_mcp)
            plugins.update(fallback_plugins)
            scopes.update(fallback_scopes)
            continue

        server_map = data.get("mcp_servers")
        if isinstance(server_map, dict):
            mcp.update(str(name) for name in server_map)

        plugin_map = data.get("plugins")
        if isinstance(plugin_map, dict):
            for name, config in plugin_map.items():
                if isinstance(config, dict) and config.get("enabled") is False:
                    continue
                plugins.add(str(name))

        for key in _CONFIG_VALUE_KEYS:
            value = data.get(key)
            if isinstance(value, (str, int, float, bool)):
                scopes[key] = str(value)
    return sorted(mcp), sorted(plugins), dict(sorted(scopes.items()))


def _plugin_root(plugin_ref: str) -> Optional[Path]:
    if "@" not in plugin_ref:
        return None
    name, marketplace = plugin_ref.rsplit("@", 1)
    cache = CODEX_HOME / "plugins" / "cache"
    bases = (
        cache / marketplace / name,
        cache / (marketplace + "-remote") / name,
    )
    candidates: List[Path] = []
    for base in bases:
        if not base.is_dir():
            continue
        try:
            candidates.extend(path for path in base.iterdir() if path.is_dir())
        except OSError:
            continue
    if not candidates:
        return None
    try:
        return max(candidates, key=lambda path: path.stat().st_mtime_ns)
    except OSError:
        return sorted(candidates, key=lambda path: path.name)[-1]


def _plugin_digest(root: Path) -> str:
    selected: List[Path] = []
    direct = (
        root / ".codex-plugin" / "plugin.json",
        root / ".mcp.json",
        root / ".app.json",
    )
    selected.extend(path for path in direct if path.is_file())
    for pattern in (
        "skills/**/SKILL.md",
        "hooks/**/*.json",
        "scripts/**/*",
        "engine/**/*.py",
    ):
        try:
            selected.extend(path for path in root.glob(pattern) if path.is_file())
        except OSError:
            continue

    digest = hashlib.sha256()
    for path in sorted(set(selected)):
        if path.is_symlink():
            continue
        try:
            relative = path.relative_to(root).as_posix().encode("utf-8")
            content = path.read_bytes()
        except (OSError, ValueError):
            continue
        digest.update(relative)
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _plugin_fingerprints(
    plugin_refs: Sequence[str],
) -> Tuple[Dict[str, str], Dict[str, str]]:
    plugins: Dict[str, str] = {}
    skills: Dict[str, str] = {}
    for plugin_ref in plugin_refs:
        root = _plugin_root(plugin_ref)
        if root is None:
            continue
        plugins[plugin_ref] = _plugin_digest(root)
        skill_root = root / "skills"
        if not skill_root.is_dir():
            continue
        try:
            candidates = sorted(skill_root.rglob("SKILL.md"))
        except OSError:
            continue
        for path in candidates:
            digest = _safe_hash(path)
            if digest:
                try:
                    name = path.parent.relative_to(skill_root).as_posix()
                except ValueError:
                    name = path.parent.name
                skills["plugin:%s:%s" % (plugin_ref, name)] = digest
    return dict(sorted(plugins.items())), dict(sorted(skills.items()))


def _identity() -> str:
    host = (
        os.environ.get("COMPUTERNAME")
        or os.environ.get("HOSTNAME")
        or socket.gethostname()
    )
    user = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
    pseudonym = hashlib.sha256((user + "\0" + host).encode("utf-8")).hexdigest()[:32]
    return "spiffe://codex.local/host/%s" % pseudonym


def _runtime_hash() -> str:
    engine_hash = _safe_hash(Path(__file__)) or _sha_bytes(b"unknown-engine")
    facts = {
        "engine": engine_hash,
        "machine": platform.machine(),
        "python": "%d.%d" % sys.version_info[:2],
        "system": platform.system(),
        "version": VERSION,
    }
    return _sha_mapping(facts)


def _sanitize_live(live: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not isinstance(live, Mapping):
        return {}
    cleaned = {key: live[key] for key in _LIVE_KEYS if key in live}
    for key in ("builtin_tools", "mcp_servers"):
        value = cleaned.get(key)
        if not isinstance(value, list):
            cleaned.pop(key, None)
        else:
            cleaned[key] = sorted({str(item) for item in value if str(item).strip()})
    return cleaned


def snapshot(live: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    live_state = _sanitize_live(live)
    root, chain, workspace_id = _workspace(
        str(live_state.get("cwd")) if live_state.get("cwd") else None
    )
    instructions = _instruction_fingerprints(root, chain)
    policy_files = _policy_fingerprints(root, chain)
    config_paths = [CODEX_HOME / "config.toml"] + [
        directory / ".codex" / "config.toml" for directory in chain
    ]
    configured_mcp, enabled_plugin_refs, config_scope = _config_state(config_paths)
    plugins, plugin_skills = _plugin_fingerprints(enabled_plugin_refs)
    skills = _skill_fingerprints(chain)
    skills.update(plugin_skills)
    skills = dict(sorted(skills.items()))

    permission_mode = str(live_state.get("permission_mode", "unknown"))
    model_id = str(live_state.get("model_id", "unknown"))
    model_version = str(live_state.get("model_version", model_id))
    model_provider = str(live_state.get("model_provider", "openai"))
    live_mcp = live_state.get("mcp_servers")
    builtin_tools = list(live_state.get("builtin_tools") or [])
    tools = sorted(
        set(builtin_tools)
        | {"mcp:" + name for name in configured_mcp}
        | {"plugin:" + name for name in plugins}
    )

    observed = ["instructions", "mcp_config", "plugins", "policy", "skills"]
    if model_id != "unknown":
        observed.append("model")
    if permission_mode != "unknown":
        observed.append("permission")
    if isinstance(live_mcp, list):
        observed.append("mcp_live")
    if builtin_tools:
        observed.append("tools")

    policy_scope = dict(config_scope)
    if permission_mode != "unknown":
        policy_scope["permission_mode"] = permission_mode
    policy_material = {
        "files": policy_files,
        "mcp": configured_mcp,
        "plugins": plugins,
        "scope": policy_scope,
    }
    runtime_context = {
        "capability_level": live_state.get("capability_level"),
        "data_class": str(live_state.get("data_class", "internal")),
        "model_id": model_id,
        "model_provider": model_provider,
        "model_version": model_version,
        "permission_mode": permission_mode,
    }
    if isinstance(live_mcp, list):
        runtime_context["mcp_servers"] = sorted(live_mcp)
    if builtin_tools:
        runtime_context["builtin_tools"] = sorted(builtin_tools)
    if live_state.get("session_id_hash"):
        runtime_context["session_id_hash"] = str(live_state["session_id_hash"])

    return {
        "captured_at": _now_iso(),
        "workspace_id": workspace_id,
        "observed": sorted(observed),
        "agent_id": _identity(),
        "model": {
            "provider": model_provider,
            "model_id": model_id,
            "version": model_version,
            "capability_level": live_state.get("capability_level"),
        },
        "permission_mode": permission_mode,
        "instructions": instructions,
        "skills": skills,
        "plugins": plugins,
        "policy_files": policy_files,
        "policy_scope": policy_scope,
        "configured_mcp_servers": configured_mcp,
        "live_mcp_servers": sorted(live_mcp) if isinstance(live_mcp, list) else [],
        "tools": tools,
        "data_class": str(live_state.get("data_class", "internal")),
        "runtime_context": runtime_context,
        "hashes": {
            "system_prompt": _sha_mapping(instructions),
            "policy_bundle": _sha_mapping(policy_material),
            "skills_set": _sha_mapping(skills),
            "plugin_set": _sha_mapping(plugins),
            "tool_catalog": _sha_mapping({name: True for name in tools}),
            "runtime": _runtime_hash(),
        },
    }


def _map_changes(
    before: Mapping[str, str],
    after: Mapping[str, str],
    label: str,
) -> List[Dict[str, str]]:
    changes: List[Dict[str, str]] = []
    before_keys, after_keys = set(before), set(after)
    for name in sorted(after_keys - before_keys):
        changes.append({"change": "added", "what": label, "detail": name})
    for name in sorted(before_keys - after_keys):
        changes.append({"change": "removed", "what": label, "detail": name})
    for name in sorted(before_keys & after_keys):
        if before[name] != after[name]:
            changes.append({"change": "changed", "what": label, "detail": name})
    return changes


def _set_changes(
    before: Iterable[str],
    after: Iterable[str],
    label: str,
) -> List[Dict[str, str]]:
    changes: List[Dict[str, str]] = []
    before_set, after_set = set(before), set(after)
    for name in sorted(after_set - before_set):
        changes.append({"change": "added", "what": label, "detail": name})
    for name in sorted(before_set - after_set):
        changes.append({"change": "removed", "what": label, "detail": name})
    return changes


def diff(base: Mapping[str, Any], current: Mapping[str, Any]) -> List[Dict[str, str]]:
    common = set(base.get("observed", [])) & set(current.get("observed", []))
    changes: List[Dict[str, str]] = []
    if "instructions" in common:
        changes += _map_changes(
            base.get("instructions", {}), current.get("instructions", {}), "instruction"
        )
    if "policy" in common:
        changes += _map_changes(
            base.get("policy_files", {}), current.get("policy_files", {}), "policy file"
        )
        before_scope = base.get("policy_scope", {})
        after_scope = current.get("policy_scope", {})
        changes += _map_changes(before_scope, after_scope, "policy setting")
    if "skills" in common:
        changes += _map_changes(
            base.get("skills", {}), current.get("skills", {}), "skill"
        )
    if "plugins" in common:
        changes += _map_changes(
            base.get("plugins", {}), current.get("plugins", {}), "plugin"
        )
    if "mcp_config" in common:
        changes += _set_changes(
            base.get("configured_mcp_servers", []),
            current.get("configured_mcp_servers", []),
            "configured MCP server",
        )
    if "mcp_live" in common:
        changes += _set_changes(
            base.get("live_mcp_servers", []),
            current.get("live_mcp_servers", []),
            "live MCP server",
        )
    if "tools" in common:
        changes += _set_changes(base.get("tools", []), current.get("tools", []), "tool")
    if "model" in common and base.get("model") != current.get("model"):
        before = base.get("model", {}).get("model_id", "unknown")
        after = current.get("model", {}).get("model_id", "unknown")
        changes.append(
            {
                "change": "changed",
                "what": "model",
                "detail": "%s -> %s" % (before, after),
            }
        )
    if "permission" in common and base.get("permission_mode") != current.get(
        "permission_mode"
    ):
        changes.append(
            {
                "change": "changed",
                "what": "permission mode",
                "detail": "%s -> %s"
                % (
                    base.get("permission_mode", "unknown"),
                    current.get("permission_mode", "unknown"),
                ),
            }
        )
    return changes


def _enforcement_mode(permission_mode: str) -> str:
    if permission_mode == "bypassPermissions":
        return "audit-only"
    if permission_mode == "unknown":
        return "advisory"
    return "enforce"


def _trace_enforcement_mode(permission_mode: str) -> str:
    if permission_mode == "bypassPermissions":
        return "silent"
    if permission_mode == "unknown":
        return "advisory"
    return "enforce"


def build_manifest(current: Mapping[str, Any]) -> Dict[str, Any]:
    now = _now_iso()
    expires = (
        (datetime.now(timezone.utc) + timedelta(days=90))
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    model = current["model"]
    tools = []
    for name in current.get("tools", []):
        kind = (
            "mcp"
            if name.startswith("mcp:")
            else "plugin"
            if name.startswith("plugin:")
            else "builtin"
        )
        clean_name = name.split(":", 1)[1] if ":" in name else name
        tools.append(
            {
                "tool_id": "codex.%s.%s" % (kind, _slug(clean_name)),
                "tool_name": name,
                "endpoint_id": "spiffe://codex.local/%s/%s" % (kind, _slug(clean_name)),
                "schema_hash": _sha_bytes(name.encode("utf-8")),
                "description_hash": _sha_bytes(("codex:" + name).encode("utf-8")),
                "version": "1.0.0",
                "egress_destinations": [],
            }
        )

    scope = [
        "codex:%s=%s" % (key, value)
        for key, value in sorted(current.get("policy_scope", {}).items())
    ] or ["codex:configuration"]
    return {
        "@context": "https://agentmanifest.agentrust.io/v0.1/context.json",
        "@type": "AgentManifest",
        "manifest_id": _uuid7(),
        "agent_id": current["agent_id"],
        "version": "0.1",
        "issued_at": now,
        "expires_at": expires,
        "issuer": "spiffe://codex.local/self-signed",
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {
                "hash": current["hashes"]["system_prompt"],
                "hash_algorithm": "SHA-256",
                "version": "1.0.0",
                "classification": "internal",
                "bound_at": now,
            },
            "policy_bundle": {
                "hash": current["hashes"]["policy_bundle"],
                "policy_language": "composite",
                "version": "1.0.0",
                "enforcement_mode": _enforcement_mode(
                    current.get("permission_mode", "unknown")
                ),
                "scope": scope,
                "agt_version": "0.0.0-codex",
                "bound_at": now,
            },
            "tool_manifest": {
                "catalog_hash": current["hashes"]["tool_catalog"],
                "tools": tools,
                "allow_dynamic_registration": True,
                "rug_pull_policy": "deny-and-alert",
                "bound_at": now,
            },
            "model_identity": {
                "provider": model["provider"],
                "model_id": model["model_id"],
                "version": model["version"],
                "capability_level": model.get("capability_level"),
                "deployment_type": "api",
                "model_attestation_type": "provider-asserted",
                "bound_at": now,
            },
        },
    }


def build_trace(current: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
        "iat": int(time.time()),
        "subject": current["agent_id"],
        "model": {
            key: current["model"][key] for key in ("provider", "model_id", "version")
        },
        "runtime": {
            "platform": "software-only",
            "measurement": current["hashes"]["runtime"],
        },
        "policy": {
            "bundle_hash": current["hashes"]["policy_bundle"],
            "enforcement_mode": _trace_enforcement_mode(
                current.get("permission_mode", "unknown")
            ),
        },
        "data_class": current["data_class"],
        "build_provenance": {
            "slsa_level": 0,
            "digest": current["hashes"]["plugin_set"],
        },
        "appraisal": {"status": "none", "verifier": "https://codex.local"},
        "transparency": "https://registry.agentrust.io/claim/placeholder",
    }


def _atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=".%s." % path.name,
            delete=False,
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            temporary = handle.name
        try:
            os.chmod(temporary, mode)
        except OSError:
            pass
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _save(path: Path, value: Mapping[str, Any], mode: int = 0o600) -> None:
    _atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n", mode)


def _load(path: Path) -> Tuple[Optional[Dict[str, Any]], str]:
    if not path.is_file():
        return None, "missing"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, "corrupt"
    return (data, "ok") if isinstance(data, dict) else (None, "corrupt")


def _load_or_create_manifest_keypair():
    from agent_manifest import Ed25519KeyPair, generate_ed25519
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    existing, status = _load(SIGNING_KEY)
    if status == "corrupt":
        raise SystemExit(
            "The AgenTrust signing key is unreadable. Restore it from backup or move it "
            "aside before generating a new identity: %s" % SIGNING_KEY
        )
    if existing and isinstance(existing.get("private_b64url"), str):
        try:
            padding = "=" * (-len(existing["private_b64url"]) % 4)
            raw = base64.urlsafe_b64decode(existing["private_b64url"] + padding)
            private = Ed25519PrivateKey.from_private_bytes(raw)
            return Ed25519KeyPair(private, private.public_key())
        except (TypeError, ValueError):
            raise SystemExit(
                "The AgenTrust signing key is invalid. Restore it or move it aside: %s"
                % SIGNING_KEY
            )

    keypair = generate_ed25519()
    _save(
        SIGNING_KEY,
        {
            "algorithm": "Ed25519",
            "key_id": keypair.key_id,
            "public_key_b64url": keypair.public_b64url(),
            "private_b64url": keypair.private_b64url(),
            "created_at": _now_iso(),
        },
        stat.S_IRUSR | stat.S_IWUSR,
    )
    return keypair


def sign_all(
    current: Mapping[str, Any], outdir: Path
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if current["model"]["model_id"] == "unknown":
        raise SystemExit(
            "A signed record needs the active Codex model. Start a session with the "
            "AgenTrust hook enabled, or pass --model."
        )
    try:
        from agent_manifest import Ed25519Signer, Ed25519Verifier, Manifest
        from agentrust_trace import generate_key, sign_record
    except ImportError as error:
        raise SystemExit(
            "Signing needs the released packages in requirements.txt "
            "(missing module: %s)." % error.name
        )

    keypair = _load_or_create_manifest_keypair()
    manifest = build_manifest(current)
    Manifest.model_validate(manifest)
    manifest["signature"] = Ed25519Signer(keypair).sign(manifest)
    Ed25519Verifier(keypair.public_bytes).verify(
        manifest, manifest["signature"]["signature_value"]
    )
    trace = sign_record(build_trace(current), generate_key())

    outdir.mkdir(parents=True, exist_ok=True)
    _save(outdir / "manifest.json", manifest, 0o644)
    _save(outdir / "trace.json", trace, 0o644)
    verification_key = {
        "algorithm": "Ed25519",
        "key_id": keypair.key_id,
        "public_key_b64url": keypair.public_b64url(),
        "note": "Load this key into agent-manifest trusted_keys to verify the manifest signature.",
    }
    _save(outdir / "verification_key.json", verification_key, 0o644)
    return manifest, trace


def render_report(
    current: Mapping[str, Any],
    changes: Optional[Sequence[Mapping[str, str]]],
    signed: bool,
) -> str:
    model = current["model"]
    lines = [
        "=" * 68,
        "  AGENTRUST CODEX INTEGRITY REPORT",
        "=" * 68,
        "",
        "  Workspace      : %s" % current["workspace_id"][:16],
        "  Agent identity : %s" % current["agent_id"],
        "  Model          : %s/%s" % (model["provider"], model["model_id"]),
        "  Permission mode: %s" % current["permission_mode"],
        "  Captured       : %s" % current["captured_at"],
        "",
        "  Composition",
        "  " + "-" * 64,
        "  Instructions   : %d fingerprint(s)" % len(current["instructions"]),
        "  Skills         : %d fingerprint(s)" % len(current["skills"]),
        "  Plugins        : %d enabled" % len(current["plugins"]),
        "  Configured MCP : %d server(s)" % len(current["configured_mcp_servers"]),
        "",
        "  Fingerprints",
        "    instruction layer : %s..." % current["hashes"]["system_prompt"][:23],
        "    policy bundle     : %s..." % current["hashes"]["policy_bundle"][:23],
        "    skills set        : %s..." % current["hashes"]["skills_set"][:23],
        "    plugin set        : %s..." % current["hashes"]["plugin_set"][:23],
        "    tool catalog      : %s..." % current["hashes"]["tool_catalog"][:23],
        "",
    ]
    if changes is not None:
        lines += ["  Baseline comparison", "  " + "-" * 64]
        if not changes:
            lines.append("  Verified: no composition changes.")
        else:
            symbols = {"added": "+", "removed": "-", "changed": "~"}
            for change in changes:
                lines.append(
                    "  %s %s %s: %s"
                    % (
                        symbols[change["change"]],
                        change["change"].upper(),
                        change["what"],
                        change["detail"],
                    )
                )
            lines.append("  %d change(s) need review." % len(changes))
        lines.append("")
    if signed:
        lines += [
            "  Wrote manifest.json, trace.json, and verification_key.json.",
            "  TRACE scope: Level 0 software integrity.",
            "",
        ]
    lines.append("=" * 68)
    return "\n".join(lines)


def _live_from_file(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit("Could not read live context: %s" % error)
    if not isinstance(data, dict):
        raise SystemExit("Live context must contain a JSON object.")
    return _sanitize_live(data)


def _live_for_args(args: argparse.Namespace) -> Dict[str, Any]:
    cwd = args.cwd or os.getcwd()
    _, _, workspace_id = _workspace(cwd)
    _, latest_path = _workspace_state(workspace_id)
    latest, status = _load(latest_path)
    live: Dict[str, Any] = {}
    if status == "ok" and latest:
        live.update(_sanitize_live(latest.get("runtime_context", {})))
    live.update(_live_from_file(args.live_context))
    live["cwd"] = cwd
    if args.model:
        live["model_id"] = args.model
        live["model_version"] = args.model
        live["model_provider"] = "openai"
    if args.permission_mode:
        live["permission_mode"] = args.permission_mode
    if args.tool:
        live["builtin_tools"] = sorted(set(args.tool))
    if args.mcp_server:
        live["mcp_servers"] = sorted(set(args.mcp_server))
    if args.data_class:
        live["data_class"] = args.data_class
    return live


def _snapshot_for_args(args: argparse.Namespace) -> Dict[str, Any]:
    return snapshot(_live_for_args(args))


def cmd_snapshot(args: argparse.Namespace) -> int:
    current = _snapshot_for_args(args)
    _, latest_path = _workspace_state(current["workspace_id"])
    _save(latest_path, current)
    if args.json:
        print(json.dumps(current, indent=2, sort_keys=True))
    else:
        print(render_report(current, None, False))
    return 0


def _emit_context(message: str, warning: bool = False) -> None:
    output: Dict[str, Any] = {
        "continue": True,
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": message,
        },
    }
    if warning:
        output["systemMessage"] = message
    print(json.dumps(output))


def _hook_payload() -> Dict[str, Any]:
    try:
        payload = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except (json.JSONDecodeError, ValueError):
        payload = {}
    if not isinstance(payload, dict):
        return {}
    live: Dict[str, Any] = {
        "cwd": payload.get("cwd") or os.getcwd(),
        "model_id": payload.get("model") or "unknown",
        "model_provider": "openai",
        "model_version": payload.get("model") or "unknown",
        "permission_mode": payload.get("permission_mode") or "unknown",
    }
    session_id = payload.get("session_id")
    if isinstance(session_id, str) and session_id:
        live["session_id_hash"] = _sha_bytes(session_id.encode("utf-8"))
    return live


def _hook_body() -> None:
    current = snapshot(_hook_payload())
    baseline_path, latest_path = _workspace_state(current["workspace_id"])
    _save(latest_path, current)
    baseline, status = _load(baseline_path)

    if status == "missing":
        _save(baseline_path, current)
        _emit_context(
            "AgenTrust established a baseline for this workspace "
            "(%d skills, %d plugins, %d configured MCP servers)."
            % (
                len(current["skills"]),
                len(current["plugins"]),
                len(current["configured_mcp_servers"]),
            )
        )
        return
    if status == "corrupt":
        _emit_context(
            "AgenTrust WARNING: the workspace baseline is unreadable and was not "
            "replaced. Verify the current composition, then approve a new baseline.",
            warning=True,
        )
        return

    changes = diff(baseline or {}, current)
    if not changes:
        return
    detail = "; ".join(
        "%s %s %s" % (item["change"], item["what"], item["detail"])
        for item in changes[:8]
    )
    _emit_context(
        "AgenTrust WARNING: %d Codex composition change(s): %s. "
        "Use the AgenTrust agent-integrity skill to verify or approve."
        % (len(changes), detail),
        warning=True,
    )


def cmd_hook(_args: argparse.Namespace) -> int:
    try:
        _hook_body()
    except Exception:
        _emit_context(
            "AgenTrust skipped the integrity check because it could not read the "
            "Codex configuration. Run a manual verification.",
            warning=True,
        )
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    current = _snapshot_for_args(args)
    baseline_path, latest_path = _workspace_state(current["workspace_id"])
    _save(latest_path, current)
    baseline, status = _load(baseline_path)
    if status == "missing":
        print(
            "No baseline exists for this workspace. Approve the current composition first."
        )
        return 2
    if status == "corrupt":
        print(
            "The workspace baseline is unreadable. Review the snapshot before approving a replacement."
        )
        return 2
    print(render_report(current, diff(baseline or {}, current), False))
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    current = _snapshot_for_args(args)
    baseline_path, latest_path = _workspace_state(current["workspace_id"])
    _save(latest_path, current)
    _save(baseline_path, current)
    print(render_report(current, [], False))
    print("\nApproved baseline: %s" % baseline_path)
    if args.sign:
        sign_all(current, Path(args.out))
        print("Signed records: %s" % Path(args.out).resolve())
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    current = _snapshot_for_args(args)
    baseline_path, latest_path = _workspace_state(current["workspace_id"])
    _save(latest_path, current)
    baseline, status = _load(baseline_path)
    changes = diff(baseline or {}, current) if status == "ok" else None
    sign_all(current, Path(args.out))
    print(render_report(current, changes, True))
    return 0


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--cwd", help="workspace to inspect; defaults to the current directory"
    )
    parser.add_argument(
        "--live-context", help="JSON file with explicit live session facts"
    )
    parser.add_argument("--model", help="active Codex model slug")
    parser.add_argument("--permission-mode", help="active Codex permission mode")
    parser.add_argument(
        "--tool", action="append", help="observed built-in tool name; repeat as needed"
    )
    parser.add_argument(
        "--mcp-server",
        action="append",
        help="observed live MCP server; repeat as needed",
    )
    parser.add_argument(
        "--data-class", default=None, help="TRACE data class; defaults to internal"
    )
    parser.add_argument("--out", default=".", help="directory for signed records")
    parser.add_argument(
        "--json", action="store_true", help="print the raw snapshot JSON"
    )
    parser.add_argument(
        "--sign", action="store_true", help="with approve, also write signed records"
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="agentrust-codex")
    parser.add_argument("--version", action="version", version=VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)
    commands = {
        "snapshot": cmd_snapshot,
        "hook": cmd_hook,
        "verify": cmd_verify,
        "approve": cmd_approve,
        "report": cmd_report,
    }
    for name in commands:
        command_parser = subparsers.add_parser(name)
        _add_common_arguments(command_parser)
    args = parser.parse_args(argv)
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
