"""Map an Auditant evidence bundle to a TRACE v0.2 log-import Trust Record.

An Auditant evidence bundle (``GET /v1/export``, bundle format 1.0.0) is one JSON
file: a run of hash-chained agent events, the signed checkpoints that pin the chain
head, and the public keys for those signatures. This module re-checks the bundle
offline first and only then builds a Trust Record for it:

1. Chain: ``seq`` increments by one, each ``prevHash`` equals the previous
   ``eventHash``, and each ``eventHash`` equals ``sha256`` over the RFC 8785
   canonical form of the event without its ``eventHash``.
2. Checkpoints: the C2SP tlog-checkpoint body (origin, tree size, base64 head hash)
   re-serialises from the checkpoint fields, the ECDSA P-256 / SHA-256 signature
   over that body verifies, and the signed head equals the recomputed head at that
   tree size.
3. Anchoring: a verified checkpoint covers the last event in the bundle.

A bundle that fails any of these raises :class:`BundleNotVerified` and no record is
built. What this does NOT check: RFC 3161 timestamp tokens on checkpoints, and
whether the checkpoint key is the operator's real key. A bundle carries its own
public keys, so a valid signature proves the bundle is consistent with those keys,
not who holds them. Pass ``pinned_keys`` to require keys you obtained out of band.

The record is Level 0: ``runtime.platform`` is ``software-only``, ``origin.kind`` is
``log-import``, ``appraisal.status`` is ``none``. ``tool_transcript.hash`` is
``sha256`` of the exact bundle bytes, so anyone holding the bundle can recompute it.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from agentrust_trace.models import TrustRecord
from agentrust_trace.sign import load_key, load_signing_key, sign_record

__all__ = [
    "BundleCheck",
    "BundleNotVerified",
    "build_trust_record",
    "check_bundle",
    "models_in_bundle",
]

ADAPTER = "auditant-trace/0.1.0"
SUPPORTED_BUNDLE_VERSIONS = frozenset({"1.0.0"})
CHECKPOINT_ORIGIN_PREFIX = "auditant.dev"
ZERO_DIGEST = "sha256:" + "0" * 64
ENFORCEMENT_MODES = ("enforce", "advisory", "silent", "declared")


class BundleNotVerified(ValueError):
    """The bundle did not verify; no record may be built from it."""

    def __init__(self, reasons: list[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = reasons


@dataclass
class BundleCheck:
    ok: bool
    log_id: str
    events: int
    anchored_through_size: int
    anchoring_body: str | None
    anchoring_head: str | None
    reasons: list[str] = field(default_factory=list)


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def event_hash(event: dict[str, Any]) -> str:
    """``sha256`` over the RFC 8785 form of the event minus ``eventHash``."""
    payload = {k: v for k, v in event.items() if k != "eventHash"}
    return _sha256(rfc8785.dumps(payload))


def checkpoint_body(checkpoint: dict[str, Any]) -> str:
    head = checkpoint["headHash"]
    hex_digest = head[7:] if head.startswith("sha256:") else head
    b64 = base64.b64encode(bytes.fromhex(hex_digest)).decode()
    return "\n".join([checkpoint["origin"], str(checkpoint["treeSize"]), b64, ""])


def _public_key(pem: str) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ValueError("checkpoint key is not an ECDSA P-256 public key")
    return key


def _same_key(a: str, b: str) -> bool:
    fmt = serialization.PublicFormat.SubjectPublicKeyInfo
    der = serialization.Encoding.DER
    return _public_key(a).public_bytes(der, fmt) == _public_key(b).public_bytes(der, fmt)


def check_bundle(
    bundle: dict[str, Any], *, pinned_keys: dict[str, str] | None = None
) -> BundleCheck:
    """Re-verify a bundle offline. Never raises on bad content; reports it."""
    reasons: list[str] = []
    log_id = bundle.get("logId", "")
    events: list[dict[str, Any]] = bundle.get("events") or []

    version = bundle.get("bundleVersion")
    if version not in SUPPORTED_BUNDLE_VERSIONS:
        reasons.append(f"unsupported bundleVersion {version!r}")
    if not events:
        reasons.append("bundle holds no events")
    if reasons:
        return BundleCheck(False, log_id, len(events), 0, None, None, reasons)

    start = bundle.get("startHead") or {}
    expected_seq = start.get("treeSize", events[0].get("seq"))
    expected_prev = start.get("headHash", events[0].get("prevHash"))
    head_at: dict[int, str] = {}
    for event in events:
        seq = event.get("seq")
        if event.get("logId") != log_id:
            reasons.append(f"event {seq} belongs to log {event.get('logId')!r}")
        if seq != expected_seq:
            reasons.append(f"sequence gap: expected {expected_seq}, found {seq}")
        if event.get("prevHash") != expected_prev:
            reasons.append(f"broken link at {seq}")
        if event_hash(event) != event.get("eventHash"):
            reasons.append(f"content altered at {seq}")
        if isinstance(seq, int):
            head_at[seq + 1] = event.get("eventHash", "")
            expected_seq = seq + 1
        expected_prev = event.get("eventHash")
    if reasons:
        return BundleCheck(False, log_id, len(events), 0, None, None, reasons)

    keys = {k["keyId"]: k["pem"] for k in bundle.get("publicKeys") or []}
    origin = f"{CHECKPOINT_ORIGIN_PREFIX}/{log_id}"
    best_size, best_body, best_head = 0, None, None
    for signed in bundle.get("checkpoints") or []:
        cp = signed.get("checkpoint") or {}
        size = cp.get("treeSize")
        key_id = signed.get("keyId")
        pem = keys.get(key_id)
        if pem is None:
            reasons.append(f"checkpoint {size}: no public key {key_id!r} in bundle")
            continue
        if pinned_keys is not None:
            pinned = pinned_keys.get(key_id)
            if pinned is None or not _same_key(pinned, pem):
                reasons.append(f"checkpoint {size}: key {key_id!r} is not a pinned key")
                continue
        try:
            body_ok = checkpoint_body(cp) == signed.get("body")
            _public_key(pem).verify(
                base64.b64decode(signed.get("signature", "")),
                signed.get("body", "").encode(),
                ec.ECDSA(hashes.SHA256()),
            )
        except InvalidSignature:
            reasons.append(f"checkpoint {size}: signature does not verify")
            continue
        except (ValueError, KeyError, TypeError) as exc:
            reasons.append(f"checkpoint {size}: unreadable ({exc})")
            continue
        if not body_ok:
            reasons.append(f"checkpoint {size}: fields do not match the signed body")
            continue
        covers = (
            cp.get("origin") == origin
            and isinstance(size, int)
            and head_at.get(size) == cp.get("headHash")
        )
        if not covers:
            # Checkpoints before this window are normal in a ranged export.
            continue
        if size > best_size:
            best_size, best_body, best_head = size, signed["body"], cp["headHash"]

    last_size = events[-1]["seq"] + 1
    if best_size != last_size:
        reasons.append(
            f"no verified checkpoint covers the last event (anchored through tree size "
            f"{best_size}, bundle ends at {last_size})"
        )
        return BundleCheck(False, log_id, len(events), best_size, best_body, best_head, reasons)
    return BundleCheck(True, log_id, len(events), best_size, best_body, best_head, reasons)


def models_in_bundle(bundle: dict[str, Any]) -> list[tuple[str, str]]:
    """Distinct (provider, model) pairs named by the bundle's model_call events."""
    seen: set[tuple[str, str]] = set()
    for event in bundle.get("events") or []:
        if event.get("actionType") != "model_call":
            continue
        cost = event.get("cost") or {}
        seen.add((cost.get("provider") or "unknown", cost.get("model") or event.get("action", "")))
    return sorted(seen)


def build_trust_record(
    bundle_bytes: bytes,
    *,
    enforcement_mode: str,
    data_class: str,
    model_provider: str | None = None,
    model_id: str | None = None,
    pinned_keys: dict[str, str] | None = None,
    iat: int | None = None,
) -> dict[str, Any]:
    """Return an unsigned Level 0 Trust Record for a bundle that verifies.

    ``enforcement_mode`` has no default: pass what your Auditant deployment actually
    did for the whole window (``enforce`` when tool calls were held by policy before
    they ran, ``advisory`` when decisions were recorded only, ``declared`` when no
    policy was evaluated). The record never upgrades it.
    """
    if enforcement_mode not in ENFORCEMENT_MODES:
        raise ValueError(f"enforcement_mode must be one of {ENFORCEMENT_MODES}")
    bundle = json.loads(bundle_bytes)
    check = check_bundle(bundle, pinned_keys=pinned_keys)
    if not check.ok:
        raise BundleNotVerified(check.reasons)

    if model_provider is None or model_id is None:
        models = models_in_bundle(bundle)
        if len(models) != 1:
            raise ValueError(
                f"the bundle names {len(models)} models {models}; pass model_provider "
                "and model_id explicitly"
            )
        model_provider, model_id = models[0]

    events = bundle["events"]
    issued = int(time.time()) if iat is None else iat
    policies = sorted(
        {
            json.dumps(
                {k: (e.get("policy") or {}).get(k) for k in ("policyId", "policyVersion", "engine")},
                sort_keys=True,
            )
            for e in events
            if e.get("actionType") == "policy_decision"
        }
    )
    record: dict[str, Any] = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": issued,
        "subject": f"spiffe://{CHECKPOINT_ORIGIN_PREFIX}/{check.log_id}",
        "model": {"provider": model_provider, "model_id": model_id},
        "runtime": {
            "platform": "software-only",
            # Not a hardware measurement: the digest of the signed checkpoint body
            # that anchors the chain, binding the record to that chain head.
            "measurement": _sha256(check.anchoring_body.encode()),
        },
        "policy": {
            # The export carries policy identifiers, not policy text: this is the
            # digest of the sorted identifiers the log names.
            "bundle_hash": _sha256(rfc8785.dumps([json.loads(p) for p in policies])),
            "enforcement_mode": enforcement_mode,
        },
        "data_class": data_class,
        "tool_transcript": {
            "hash": _sha256(bundle_bytes),
            "call_count": sum(1 for e in events if e.get("actionType") == "tool_call"),
        },
        "origin": {
            "kind": "log-import",
            "producer": ADAPTER,
            "source_event_id": check.anchoring_head,
            "ingested_at": issued,
        },
        # Auditant does not record the agent's image digest: no provenance claim.
        "build_provenance": {"slsa_level": 0, "digest": ZERO_DIGEST},
        "appraisal": {"status": "none", "verifier": "https://agentrust-io.com/verify"},
        "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "A" * 43}},
    }
    return record


def _pins(paths: list[str]) -> dict[str, str] | None:
    if not paths:
        return None
    pins: dict[str, str] = {}
    for item in paths:
        key_id, _, path = item.partition("=")
        if not path:
            raise SystemExit(f"--pin-key takes KEYID=PEMFILE, got {item!r}")
        pins[key_id] = Path(path).read_text()
    return pins


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("bundle", type=Path, help="Auditant evidence bundle (JSON)")
    ap.add_argument("--out", type=Path, required=True, help="where to write the signed record")
    ap.add_argument("--enforcement-mode", required=True, choices=ENFORCEMENT_MODES)
    ap.add_argument("--data-class", required=True)
    ap.add_argument("--model-provider")
    ap.add_argument("--model-id")
    ap.add_argument("--pin-key", action="append", default=[], metavar="KEYID=PEMFILE")
    ap.add_argument(
        "--signing-key",
        type=Path,
        help="Ed25519 private key PEM; otherwise TRACE_PRIVATE_KEY_PEM, else an ephemeral key",
    )
    args = ap.parse_args(argv)

    bundle_bytes = args.bundle.read_bytes()
    try:
        record = build_trust_record(
            bundle_bytes,
            enforcement_mode=args.enforcement_mode,
            data_class=args.data_class,
            model_provider=args.model_provider,
            model_id=args.model_id,
            pinned_keys=_pins(args.pin_key),
        )
    except BundleNotVerified as exc:
        print("bundle did not verify, no record written:", file=sys.stderr)
        for reason in exc.reasons:
            print("  " + reason, file=sys.stderr)
        return 2
    key = load_key(args.signing_key.read_text()) if args.signing_key else load_signing_key()
    signed = sign_record(record, key)
    TrustRecord.model_validate(signed)
    args.out.write_text(json.dumps(signed, indent=2) + "\n")
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
