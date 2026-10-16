"""Restricted CA2A 0.4.0 peer acceptance service for one non-networked Conduit intent.

The service is intended ONLY behind a separately restricted SSH forced command.
It is a software trust boundary, not a TEE; its issuer root and channel public
key must be provisioned and pinned out of band. Never expose as a public API.
"""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from harness.trace_live_binding import sign_bundle
from ca2a_runtime.challenge import issue_challenge
from ca2a_runtime.delegation.credential import DelegationCredential
from ca2a_runtime.delegation import HolderProof
from ca2a_runtime.peer import PeerRequest, handle_peer_request
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.response import ResponseProducer, encode


CAPABILITY = "conduit.inspect"
REPO = "/home/ubuntu/src/integrations"
MAX_REQUEST = 65536


def _canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(value):
    return hashlib.sha256(_canon(value)).hexdigest()


def _consume(path: Path, occurrence: str) -> bool:
    """Atomic persistent replay refusal; failure is denial, not cache reset."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=5) as db:
        db.execute("CREATE TABLE IF NOT EXISTS spent (id TEXT PRIMARY KEY, seen INTEGER NOT NULL)")
        try:
            db.execute("INSERT INTO spent (id,seen) VALUES (?,?)", (occurrence, int(time.time())))
            db.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def _receipt_ok(receipt, action, session):
    if not isinstance(receipt, dict):
        return False
    digest = receipt.get("hash")
    body = {key: value for key, value in receipt.items() if key != "hash"}
    return (isinstance(digest, str) and _digest(body) == digest
            and receipt.get("action") == action
            and receipt.get("status") == "PASS"
            and receipt.get("detail", {}).get("session_id") == session)


def _agent(agent_path: str, action: str, params: dict, *, timeout=12) -> dict:
    proc = subprocess.run([agent_path], input=_canon({
        "request_id": os.urandom(16).hex(), "action": action, "params": params
    }), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=timeout, check=False)
    if proc.returncode != 0 or len(proc.stdout) > 262144:
        raise RuntimeError("conduit-operation-failed")
    data = json.loads(proc.stdout)
    if not isinstance(data, dict):
        raise ValueError("malformed-conduit-response")
    return data


def execute_job(agent: str, repo: str) -> dict:
    started = _agent(agent, "job_start", {"intent": "inspect", "repo": repo})
    if not started.get("ok"):
        raise RuntimeError("conduit-refused-start")
    start = started["receipt"]
    job = started["result"]
    sid = job["session_id"]
    if not (_receipt_ok(start, "job_start", sid)
            and job.get("intent") == "inspect"
            and job.get("network") is False
            and job.get("repo") == repo):
        raise RuntimeError("untrusted-conduit-start")
    # There is intentionally no retry of job_start on uncertain delivery.
    for _ in range(16):
        polled = _agent(agent, "job_poll", {"session_id": sid})
        if not polled.get("ok"):
            raise RuntimeError("unobserved-conduit-completion")
        finished = polled["result"]
        if finished.get("running"):
            time.sleep(0.3)
            continue
        finish = polled["receipt"]
        if not (_receipt_ok(finish, "job_poll", sid)
                and finish.get("prev_hash") == start["hash"]
                and finished.get("session_id") == sid
                and finished.get("exit_code") == 0
                and finished.get("commit_sha") == job.get("commit_sha")
                and finished.get("commit_sha_end") == job.get("commit_sha")
                and finished.get("worktree_clean_start") is True
                and finished.get("worktree_clean_end") is True):
            raise RuntimeError("invalid-conduit-outcome")
        return {"session_id": sid, "start_receipt_hash": start["hash"],
                "finish_receipt_hash": finish["hash"],
                "commit_sha": job["commit_sha"], "exit_code": 0}
    raise RuntimeError("unknown-conduit-timeout")


def serve(request: dict, *, channel_private, challenge_secret: bytes,
          trusted_issuer: str, replay_db: Path,
          agent: str = "", allowed_repo: str = REPO, dispatch=None,
          trace_private=None) -> dict:
    if not isinstance(request, dict) or request.get("schema") != "frequency-ca2a-peer/1":
        return {"status": 400, "error": "invalid-request"}
    public = channel_private.public_key().public_bytes_raw().hex()
    if request.get("method") == "challenge":
        return {"status": 200, "challenge": issue_challenge(challenge_secret),
                "peer_public_key": public, "assurance": "none",
                "capability": CAPABILITY}
    if request.get("method") != "execute":
        return {"status": 400, "error": "unsupported-method"}
    try:
        envelope = request["envelope"]
        producer = ResponseProducer(channel_private, envelope)
        message = producer.envelope["request"]
    except (KeyError, ValueError, TypeError):
        return {"status": 400, "error": "malformed-request-envelope"}
    try:
        if (not isinstance(message, dict)
                or set(message) != {"transaction_id", "nonce", "repo", "capability"}
                or not isinstance(message["transaction_id"], str)
                or not 5 <= len(message["transaction_id"]) <= 128
                or not isinstance(message["nonce"], str)
                or not 8 <= len(message["nonce"]) <= 128
                or message["repo"] != allowed_repo
                or message["capability"] != CAPABILITY):
            raise ValueError("bad-scope")
        credential = DelegationCredential.from_dict(request["credential"])
        proof = HolderProof.from_dict(request["holder_proof"])
        record_id = hashlib.sha256(encode(producer.envelope)).hexdigest()
        handle_peer_request(
            PeerRequest([credential], CAPABILITY, record_id, holder_proof=proof),
            policy=LocalPolicy(frozenset({CAPABILITY})),
            trusted_root_issuers={trusted_issuer},
            challenge_secret=challenge_secret, audience=public,
            require_holder_proof=True)
        # Persist the one-time occurrence before any possible side effect.
        unique = hashlib.sha256(
            proof.challenge.encode()
        ).hexdigest()
        if not _consume(replay_db, unique):
            raise PermissionError("already-consumed")
    except Exception:
        return {"status": 403, "envelope": producer.finish(403, {
            "error": {"code": "delegation-or-context-refused"}})}
    try:
        observed = ((dispatch or execute_job)(agent, allowed_repo))
        body = {"accepted": True,
                "transaction_id": message["transaction_id"],
                "nonce": message["nonce"], "repo": allowed_repo,
                "capability": CAPABILITY, "execution": observed,
                "assurance": "software-only"}
        if trace_private is not None:
            body["trace_bundle"] = sign_bundle(
                key=trace_private, transaction_id=message["transaction_id"],
                nonce=message["nonce"], request_sha256=producer.request_sha256,
                execution=observed, repo=allowed_repo,
                trusted_issuer=trusted_issuer)
        return {"status": 200, "envelope": producer.finish(200, body)}
    except Exception:
        return {"status": 503, "envelope": producer.finish(503, {
            "error": {"code": "execution-unknown"}})}


def main():
    cfg_path = Path("/home/ubuntu/.local/state/frequency-ca2a-peer/config.json")
    cfg = json.loads(cfg_path.read_text())
    private = X25519PrivateKey.from_private_bytes(
        bytes.fromhex(Path(cfg["private_key_path"]).read_text().strip()))
    secret = bytes.fromhex(Path(cfg["challenge_secret_path"]).read_text().strip())
    trace_private = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(Path(cfg["trace_private_key_path"]).read_text().strip()))
    raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
    if len(raw) > MAX_REQUEST:
        raise SystemExit(1)
    response = serve(json.loads(raw), channel_private=private,
                     challenge_secret=secret,
                     trusted_issuer=cfg["trusted_issuer"],
                     replay_db=Path(cfg["replay_db"]), agent=cfg["agent"],
                     allowed_repo=cfg["allowed_repo"], trace_private=trace_private)
    sys.stdout.buffer.write(_canon(response) + b"\n")


if __name__ == "__main__":
    main()
