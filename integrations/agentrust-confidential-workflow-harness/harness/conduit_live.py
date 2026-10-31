"""Bounded live cMCP-to-Conduit experiment, not a cA2A peer acceptance claim.

Uses the published cMCP admission API, then an existing locked-down Conduit
CLI SSH transport to run an approved, non-networked 'inspect' intent remotely.
The remote receipt is hash chained but NOT digitally signed or independent.
"""
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cmcp_runtime.runtime_gateway import GovernancePolicy, MCPGateway


@dataclass(frozen=True)
class LiveResult:
    outcome: str
    transaction_id: str
    start_hash: str | None = None
    finish_hash: str | None = None
    commit_sha: str | None = None
    evidence_class: str = "live-two-host-same-operator"
    assurance: str = "software-hash-chain-only"


def _call(cli: str, action: str, params: dict, timeout: int = 45) -> dict:
    process = subprocess.run(
        [cli, "call", "vps", action, "--params", json.dumps(params, sort_keys=True)],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout,
        check=False,
    )
    if process.returncode:
        raise RuntimeError("conduit-transport-failure")
    response = json.loads(process.stdout)
    if not isinstance(response, dict):
        raise ValueError("non-object-conduit-response")
    return response


def _receipt_hash(r: dict) -> bool:
    if not isinstance(r, dict) or not isinstance(r.get("hash"), str):
        return False
    material = {k: v for k, v in r.items() if k != "hash"}
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return digest == r["hash"]


def run(*, transaction_id: str, repo: str, cli: str,
        tool_allowed: bool = True, transport=_call) -> LiveResult:
    if not transaction_id or not repo or not Path(cli).is_file():
        return LiveResult("invalid-request", transaction_id)
    admitted, _ = MCPGateway(GovernancePolicy(
        allowed_tools=["conduit.inspect"] if tool_allowed else [],
        max_tool_calls=1,
    )).intercept_tool_call("frequency-live-harness", "conduit.inspect",
                          {"transaction_id": transaction_id, "repo": repo})
    if not admitted:
        return LiveResult("refused-cmcp", transaction_id)
    try:
        start = transport(cli, "job_start", {"intent": "inspect", "repo": repo, "transaction_id": transaction_id})
        if not isinstance(start, dict):
            raise ValueError("non-object-start")
        if not start.get("ok"):
            return LiveResult("refused-conduit", transaction_id)
        sr = start["receipt"]
        job = start["result"]
        if (not isinstance(job, dict) or not isinstance(sr, dict)
                or not isinstance(sr.get("detail"), dict)):
            raise ValueError("malformed-start")
        session = job["session_id"]
        if (not isinstance(session, str) or not session
            or not isinstance(job.get("commit_sha"), str)
            or re.fullmatch(r"[0-9a-f]{40}", job["commit_sha"]) is None
            or job.get("transaction_id") != transaction_id
            or sr["detail"].get("transaction_id") != transaction_id
            or not _receipt_hash(sr) or sr["status"] != "PASS"
            or sr["action"] != "job_start" or sr["node"] != "vps-377a113a"
            or sr.get("detail", {}).get("session_id") != session
            or job.get("repo") != repo
            or job.get("intent") != "inspect"
            or job.get("network") is not False):
            return LiveResult("untrusted-start", transaction_id)
        poll = transport(cli, "job_poll", {"session_id": session, "transaction_id": transaction_id})
        if not isinstance(poll, dict):
            raise ValueError("non-object-poll")
        if not poll.get("ok"):
            return LiveResult("unknown-unobserved-result", transaction_id, sr["hash"])
        fr = poll["receipt"]
        finished = poll["result"]
        if (not isinstance(finished, dict) or not isinstance(fr, dict)
                or not isinstance(fr.get("detail"), dict)):
            raise ValueError("malformed-finish")
        if (finished.get("transaction_id") != transaction_id
            or fr["detail"].get("transaction_id") != transaction_id
            or not _receipt_hash(fr) or fr.get("action") != "job_poll"
            or fr.get("status") != "PASS"
            or fr.get("node") != sr["node"]
            or fr.get("detail", {}).get("session_id") != session
            or fr.get("prev_hash") != sr["hash"]
            or finished.get("session_id") != session
            or finished.get("running") or finished.get("exit_code") != 0
            or finished.get("commit_sha") != job.get("commit_sha")
            or finished.get("commit_sha_end") != job.get("commit_sha")
            or finished.get("worktree_clean_start") is not True
            or finished.get("worktree_clean_end") is not True):
            return LiveResult("untrusted-or-unsuccessful-result", transaction_id, sr["hash"])
        return LiveResult("observed-live-conduit-inspect", transaction_id,
                          sr["hash"], fr["hash"], job["commit_sha"])
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired, RuntimeError):
        return LiveResult("unknown-transport-or-protocol", transaction_id)
