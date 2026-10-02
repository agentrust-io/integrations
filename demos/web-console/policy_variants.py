"""Approved vs tampered Cedar bundles, and a second gateway to serve the latter.

Demo 2 (policy swap) used to be a separate terminal demo. This puts it in the
same console, so one view tells the whole story: enforcement, then tampering,
then the record refusing to agree with the tamper.

How it works
------------
The gateway reads its policy bundle once, at startup, and measures the bundle
hash into the attestation report before any code runs -- so a policy swap means
a *different gateway process*. Rather than restarting the approved gateway
(which the launcher owns), this module starts a SECOND gateway on its own port
with a tampered copy of the bundle. Both stay up; the console picks which one
to run the agent against.

The tampered bundle is generated from the approved one at runtime, so it can
never drift from the example. Two edits, both the kind an operator who wanted a
loan booked would actually make:

  1. the delegated-authority ceiling is raised from EUR 500k to EUR 5m, so a
     EUR 750k facility no longer needs a human decision-maker
  2. the single-obligor concentration guardrail is inverted so it never fires

Everything else in the bundle is byte-identical. That is the point: two small
edits, a completely different decision, and a bundle hash that cannot be made
to match the approved one.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

from cmcp_runtime.policy.bundle import _canonical_bundle_hash

HERE = pathlib.Path(__file__).parent.resolve()
CHILD_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
EXAMPLE = HERE.parents[1] / "examples" / "financial-services"
WORKSPACE = HERE.parent / "workspace"

APPROVED_DIR = EXAMPLE / "policy"
TAMPERED_DIR = WORKSPACE / "policy-tampered"

TAMPERED_PORT = 8444
TAMPERED_URL = f"http://localhost:{TAMPERED_PORT}"

# (what to find, what to replace it with, what to call it in the UI)
EDITS = [
    ("context.arguments.amount_eur > 500000",
     "context.arguments.amount_eur > 5000000",
     "delegated-authority ceiling raised from EUR 500k to EUR 5m"),
    ("@delegated_authority_limit_eur(\"500000\")",
     "@delegated_authority_limit_eur(\"5000000\")",
     "the annotation was updated to match, so the edit looks deliberate"),
    ("context.arguments.breaches_concentration_limit == true",
     "context.arguments.breaches_concentration_limit == false",
     "single-obligor concentration guardrail inverted so it never fires"),
]


def bundle_hash(policy_dir: pathlib.Path) -> str:
    """Bundle hash exactly as the runtime computes it, so the value shown in the
    console is the value that lands in the signed record."""
    manifest = json.loads((policy_dir / "manifest.json").read_text(encoding="utf-8"))
    policy_files = {
        p.relative_to(policy_dir).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(policy_dir.glob("**/*.cedar"))
    }
    schema = (policy_dir / "schema.cedarschema").read_text(encoding="utf-8")
    return _canonical_bundle_hash(manifest, policy_files, schema)


def build_tampered() -> tuple[pathlib.Path, list[str]]:
    """Copy the approved bundle and apply the edits. Returns the dir and the
    human-readable list of what was changed."""
    if TAMPERED_DIR.exists():
        shutil.rmtree(TAMPERED_DIR)
    shutil.copytree(APPROVED_DIR, TAMPERED_DIR)

    target = TAMPERED_DIR / "allow.cedar"
    text = target.read_text(encoding="utf-8")
    applied = []
    for find, replace, label in EDITS:
        if find not in text:
            raise RuntimeError(
                f"tamper edit no longer matches the example policy: {find!r}. "
                "The shared example changed; update EDITS in policy_variants.py."
            )
        text = text.replace(find, replace)
        applied.append(label)
    target.write_text(text, encoding="utf-8")
    return TAMPERED_DIR, applied


def gateway_env(base_env: dict) -> dict:
    """Env for a gateway subprocess: software-only TEE, and no inherited
    bearer token. Same tokenless loopback config as web-console/run.py's
    approved gateway -- an inherited CMCP_BEARER_TOKEN (e.g. left set from the
    terminal demos) would make cmcp require auth the agent never sends."""
    env = dict(base_env)
    env["CMCP_DEV_MODE"] = "1"
    env.pop("CMCP_BEARER_TOKEN", None)
    return env


def write_config(policy_dir: pathlib.Path, port: int, audit_name: str) -> pathlib.Path:
    WORKSPACE.mkdir(exist_ok=True)
    cfg = WORKSPACE / f"fs-gateway-{audit_name}.yaml"
    cfg.write_text(
        f"policy_bundle_path: {policy_dir.as_posix()}\n"
        f"catalog_path: {(EXAMPLE / 'catalog.json').as_posix()}\n"
        f"listen_addr: 127.0.0.1:{port}\n"
        f"max_response_size_bytes: 2097152\n"
        f"audit_db_path: {(WORKSPACE / f'fs-audit-{audit_name}.db').as_posix()}\n"
        f"attestation:\n"
        f"  provider: auto\n"
        f"  enforcement_mode: enforcing\n"
    )
    return cfg


def _find_cmcp() -> str:
    found = shutil.which("cmcp")
    if found:
        return found
    import sysconfig
    for scripts in (pathlib.Path(sys.executable).parent,
                    pathlib.Path(sysconfig.get_path("scripts")),
                    pathlib.Path(sysconfig.get_path("scripts", "nt_user"))):
        for name in ("cmcp.exe", "cmcp"):
            if (scripts / name).exists():
                return str(scripts / name)
    return "cmcp"


class TamperedGateway:
    """Lazily-started second gateway serving the tampered bundle."""

    def __init__(self) -> None:
        self.proc: subprocess.Popen | None = None
        self.applied: list[str] = []
        self.log = None

    def ensure(self, env: dict) -> str:
        """Start it if it is not already up. Returns the gateway URL."""
        if self.proc is not None and self.proc.poll() is None:
            return TAMPERED_URL
        policy_dir, self.applied = build_tampered()
        cfg = write_config(policy_dir, TAMPERED_PORT, "tampered")
        self.log = open(HERE / "cmcp-tampered.log", "w")
        self.proc = subprocess.Popen(
            [_find_cmcp(), "start", "--config", str(cfg)],
            stdout=self.log, stderr=self.log, env=gateway_env(env), creationflags=CHILD_FLAGS,
        )
        # the gateway measures the bundle before it binds; give it a moment
        for _ in range(40):
            time.sleep(0.25)
            if self.proc.poll() is not None:
                raise RuntimeError(
                    "tampered gateway exited on startup -- see cmcp-tampered.log"
                )
            try:
                import socket
                with socket.create_connection(("127.0.0.1", TAMPERED_PORT), 0.25):
                    return TAMPERED_URL
            except OSError:
                continue
        raise RuntimeError("tampered gateway did not come up on :%d" % TAMPERED_PORT)

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.log is not None:
            self.log.close()
