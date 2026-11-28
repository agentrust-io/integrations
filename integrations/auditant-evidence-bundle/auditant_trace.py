"""Map an Auditant evidence bundle to a TRACE v0.2 log-import Trust Record.

An Auditant evidence bundle (``GET /v1/export``, bundle format 1.0.0) is one JSON
file: a run of hash-chained agent events, signed checkpoints over the chain head,
and the public keys for those signatures. This module re-checks the bundle offline
and only then builds a record. Every check fails closed: one failure anywhere and
no record is built.

1. Structure: the fields each check reads are present and have the right type.
   Integers are integers (a JSON ``true`` is not a tree size), digests are
   ``sha256:`` plus 64 hex characters, and a JSON object may not repeat a key.
2. Chain: ``seq`` increments by one, each ``prevHash`` equals the previous
   ``eventHash`` (the first links to ``startHead`` when the export starts
   mid-log, to the all-zero genesis hash when it starts at ``seq`` 0), and each
   ``eventHash`` equals ``sha256`` over the RFC 8785 form of the event without
   its ``eventHash``.
3. Checkpoints: every checkpoint in the bundle must verify, not just one. Its key
   is listed in the bundle (and pinned, when keys are pinned), its origin is this
   log's, its fields re-serialise to the signed body, its signature is canonical
   base64 and verifies, and if its tree size falls inside the exported window its
   head equals the recomputed chain head at that size. A checkpoint outside the
   window is checked for all of that except the head, which the bundle cannot
   recompute, and is not used for anchoring.
4. Anchoring: a verified checkpoint covers the last event in the bundle, and the
   head the bundle starts from is either the genesis hash or signed by a verified
   checkpoint, so deleting the first events cannot pass for a shorter export.

A record is built only from a whole log (first ``seq`` 0). A ranged export can
verify, but TRACE has no field that says a record covers part of a log, so a
record from one would read as the whole of it.

**What an Auditant checkpoint is, and is not.** Its signed body uses the line
layout of a C2SP tlog-checkpoint (origin, tree size, base64 hash), but the hash
line is the head of a linear hash chain, the ``eventHash`` of the last event, not
an RFC 6962 Merkle tree root, and the signature is a bare ECDSA P-256 / SHA-256
signature over the body, not a C2SP signed note. It is therefore not a C2SP
checkpoint: there are no inclusion or consistency proofs, and C2SP witnesses and
tools do not apply. Checking a bundle means walking every event, which this does.

Not checked: RFC 3161 timestamp tokens on checkpoints, and whether a key is the
operator's real key. A bundle carries its own public keys, so a valid signature
shows the bundle agrees with itself, not who made it. Pass ``pinned_keys`` with
keys obtained out of band to require them.

The record is assembled by ``agentrust_trace_adapters.build_record`` and claims
only what the bundle or the operator supplies. The bundle names the model, the
tool calls and the anchored event. It does not carry the workload's identity, the
policy bundle's bytes or the workload's artifact digest, so the operator supplies
``subject``, ``policy_bundle`` and ``workload_digest``; nothing is derived from
the log ID or from policy names.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import rfc8785
from agentrust_trace_adapters import MissingEvidence, PolicyEvidence, SourceSystem, build_record
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from agentrust_trace.models import TrustRecord
from agentrust_trace.sign import key_to_jwk, load_key, load_signing_key, sign_record

__all__ = [
    "BundleCheck",
    "BundleNotVerified",
    "build_trust_record",
    "check_bundle",
    "models_in_bundle",
    "select_model",
    "tool_transcript_bytes",
]

SUPPORTED_BUNDLE_VERSIONS = frozenset({"1.0.0"})
CHECKPOINT_ORIGIN_PREFIX = "auditant.dev"
GENESIS = "sha256:" + "0" * 64
# A URI: build_record also carries the producer as appraisal.verifier, which the schema types as a URI.
DEFAULT_PRODUCER = "https://auditant.co"
ENFORCEMENT_MODES = PolicyEvidence.MODES
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


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
    anchored_through_size: int = 0
    anchoring_body: str | None = None
    anchoring_head: str | None = None
    anchored_event_id: str | None = None
    reasons: list[str] = field(default_factory=list)


def _is_int(value: Any) -> bool:
    # bool is a subclass of int in Python; JSON true is not a sequence number.
    return type(value) is int


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _b64decode_canonical(text: str) -> bytes:
    """Strict base64: standard alphabet, correct padding, and the one encoding of its bytes."""
    raw = base64.b64decode(text, validate=True)
    if base64.b64encode(raw).decode("ascii") != text:
        raise ValueError("base64 is not in canonical form")
    return raw


def event_hash(event: dict[str, Any]) -> str:
    """``sha256`` over the RFC 8785 form of the event minus ``eventHash``."""
    payload = {k: v for k, v in event.items() if k != "eventHash"}
    return "sha256:" + hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def checkpoint_body(checkpoint: dict[str, Any]) -> str:
    """The signed body: origin, tree size, base64 of the chain head, newline-terminated."""
    head = bytes.fromhex(checkpoint["headHash"][len("sha256:") :])
    return "\n".join(
        [checkpoint["origin"], str(checkpoint["treeSize"]), base64.b64encode(head).decode(), ""]
    )


def _public_key(pem: str) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ValueError("not an ECDSA P-256 public key")
    return key


def _spki(pem: str) -> bytes:
    return _public_key(pem).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _structure(bundle: Any) -> list[str]:
    """Shape errors, so that no later check can raise on unexpected content."""
    if not isinstance(bundle, dict):
        return [f"the bundle is a JSON {type(bundle).__name__}, not an object"]
    reasons: list[str] = []
    version = bundle.get("bundleVersion")
    if version not in SUPPORTED_BUNDLE_VERSIONS:
        reasons.append(f"unsupported bundleVersion {version!r}")
    log_id = bundle.get("logId")
    if not isinstance(log_id, str) or not log_id:
        reasons.append("logId is missing or not a string")

    events = bundle.get("events")
    if not isinstance(events, list) or not events:
        reasons.append("events is missing, empty or not a list")
    else:
        for i, event in enumerate(events):
            where = f"events[{i}]"
            if not isinstance(event, dict):
                reasons.append(f"{where} is not an object")
                continue
            if not _is_int(event.get("seq")) or event["seq"] < 0:
                reasons.append(f"{where}.seq is not a non-negative integer")
            for key in ("prevHash", "eventHash"):
                if not _is_digest(event.get(key)):
                    reasons.append(f"{where}.{key} is not a sha256 digest")
            for key in ("logId", "actionType"):
                if not isinstance(event.get(key), str):
                    reasons.append(f"{where}.{key} is not a string")
            if not isinstance(event.get("eventId"), str) or not event["eventId"]:
                reasons.append(f"{where}.eventId is not a non-empty string")

    checkpoints = bundle.get("checkpoints")
    if not isinstance(checkpoints, list):
        reasons.append("checkpoints is missing or not a list")
    else:
        for i, signed in enumerate(checkpoints):
            where = f"checkpoints[{i}]"
            if not isinstance(signed, dict) or not isinstance(signed.get("checkpoint"), dict):
                reasons.append(f"{where} is not a signed checkpoint object")
                continue
            cp = signed["checkpoint"]
            if not isinstance(cp.get("origin"), str):
                reasons.append(f"{where}.checkpoint.origin is not a string")
            if not _is_int(cp.get("treeSize")) or cp["treeSize"] < 1:
                reasons.append(f"{where}.checkpoint.treeSize is not a positive integer")
            if not _is_digest(cp.get("headHash")):
                reasons.append(f"{where}.checkpoint.headHash is not a sha256 digest")
            for key in ("body", "keyId", "signature"):
                if not isinstance(signed.get(key), str):
                    reasons.append(f"{where}.{key} is not a string")

    keys = bundle.get("publicKeys")
    if not isinstance(keys, list):
        reasons.append("publicKeys is missing or not a list")
    else:
        seen: set[str] = set()
        for i, entry in enumerate(keys):
            if not (
                isinstance(entry, dict)
                and isinstance(entry.get("keyId"), str)
                and isinstance(entry.get("pem"), str)
            ):
                reasons.append(f"publicKeys[{i}] needs a string keyId and pem")
                continue
            if entry["keyId"] in seen:
                reasons.append(f"publicKeys lists {entry['keyId']!r} more than once")
            seen.add(entry["keyId"])

    start = bundle.get("startHead")
    if start is not None:
        if not (
            isinstance(start, dict)
            and _is_int(start.get("treeSize"))
            and start["treeSize"] >= 0
            and _is_digest(start.get("headHash"))
        ):
            reasons.append("startHead needs a non-negative integer treeSize and a sha256 headHash")
        elif start.get("logId", log_id) != log_id:
            reasons.append("startHead belongs to another log")
        elif start["treeSize"] == 0 and start["headHash"] != GENESIS:
            reasons.append("startHead at tree size 0 is not the genesis hash")
    return reasons


def _check(bundle: Any, pinned_keys: dict[str, str] | None) -> BundleCheck:
    reasons = _structure(bundle)
    if reasons:
        log_id = bundle.get("logId") if isinstance(bundle, dict) else None
        events = bundle.get("events") if isinstance(bundle, dict) else None
        return BundleCheck(
            False,
            log_id if isinstance(log_id, str) else "",
            len(events) if isinstance(events, list) else 0,
            reasons=reasons,
        )

    log_id: str = bundle["logId"]
    events: list[dict[str, Any]] = bundle["events"]
    start = bundle.get("startHead")

    # 2. Chain.
    first_size = events[0]["seq"]
    if start is not None:
        expected_seq, expected_prev = start["treeSize"], start["headHash"]
    elif first_size == 0:
        expected_seq, expected_prev = 0, GENESIS
    else:
        # An excerpt without startHead links to whatever its first event names; step 3
        # accepts that only if a verified checkpoint signs that head.
        expected_seq, expected_prev = first_size, events[0]["prevHash"]
    head_at: dict[int, str] = {expected_seq: expected_prev}
    for event in events:
        seq = event["seq"]
        if event["logId"] != log_id:
            reasons.append(f"event {seq} belongs to log {event['logId']!r}")
        if seq != expected_seq:
            reasons.append(f"sequence gap: expected {expected_seq}, found {seq}")
        if event["prevHash"] != expected_prev:
            reasons.append(f"broken link at {seq}")
        try:
            recomputed = event_hash(event)
        except (rfc8785.CanonicalizationError, TypeError, ValueError) as exc:
            reasons.append(f"event {seq} has no RFC 8785 form ({exc})")
        else:
            if recomputed != event["eventHash"]:
                reasons.append(f"content altered at {seq}")
        head_at[seq + 1] = event["eventHash"]
        expected_seq, expected_prev = seq + 1, event["eventHash"]
    if reasons:
        return BundleCheck(False, log_id, len(events), reasons=reasons)

    # 3. Checkpoints. Every one must verify; none is skipped because another passed.
    window_start = start["treeSize"] if start is not None else first_size
    last_size = events[-1]["seq"] + 1
    origin = f"{CHECKPOINT_ORIGIN_PREFIX}/{log_id}"
    keys = {entry["keyId"]: entry["pem"] for entry in bundle["publicKeys"]}
    anchor: dict[str, Any] | None = None
    start_pinned = window_start == 0  # the genesis hash needs no signature
    for i, signed in enumerate(bundle["checkpoints"]):
        cp = signed["checkpoint"]
        size, key_id = cp["treeSize"], signed["keyId"]
        label = f"checkpoint {i} (tree size {size})"
        pem = keys.get(key_id)
        if pem is None:
            reasons.append(f"{label}: signed by {key_id!r}, which the bundle does not list")
            continue
        try:
            listed = _spki(pem)
        except (ValueError, UnsupportedAlgorithm) as exc:
            reasons.append(f"{label}: key {key_id!r} is unreadable ({exc})")
            continue
        if pinned_keys is not None:
            pinned = pinned_keys.get(key_id)
            try:
                pinned_ok = pinned is not None and _spki(pinned) == listed
            except (ValueError, UnsupportedAlgorithm) as exc:
                reasons.append(f"{label}: pinned key {key_id!r} is unreadable ({exc})")
                continue
            if not pinned_ok:
                reasons.append(f"{label}: key {key_id!r} is not a pinned key")
                continue
        if cp["origin"] != origin:
            reasons.append(f"{label}: origin {cp['origin']!r} is not this log's {origin!r}")
            continue
        if checkpoint_body(cp) != signed["body"]:
            reasons.append(f"{label}: fields do not match the signed body")
            continue
        try:
            signature = _b64decode_canonical(signed["signature"])
            _public_key(pem).verify(signature, signed["body"].encode(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            reasons.append(f"{label}: signature does not verify")
            continue
        except ValueError as exc:
            reasons.append(f"{label}: signature is unreadable ({exc})")
            continue
        if window_start <= size <= last_size:
            if head_at.get(size) != cp["headHash"]:
                reasons.append(
                    f"{label}: contradicts the chain; it signs head {cp['headHash']} "
                    f"where the events give {head_at.get(size)}"
                )
                continue
            if size == window_start:
                start_pinned = True
            if size == last_size:
                anchor = {"body": signed["body"], "head": cp["headHash"]}
        # Outside the window: verified above, but the bundle cannot recompute its head.

    # 4. Anchoring, at both ends. A start nothing signs could be any head, so an
    # export with its first events deleted would otherwise pass as a shorter one.
    if not start_pinned:
        reasons.append(
            f"the bundle starts at tree size {window_start} and no verified checkpoint "
            "signs the head it starts from"
        )
    if anchor is None:
        reasons.append(
            f"no verified checkpoint covers the last event (the bundle ends at tree size {last_size})"
        )
    if reasons:
        return BundleCheck(False, log_id, len(events), reasons=reasons)
    return BundleCheck(
        True,
        log_id,
        len(events),
        anchored_through_size=last_size,
        anchoring_body=anchor["body"],
        anchoring_head=anchor["head"],
        anchored_event_id=events[-1]["eventId"],
    )


def check_bundle(bundle: Any, *, pinned_keys: dict[str, str] | None = None) -> BundleCheck:
    """Re-verify a parsed bundle offline. Never raises on bad content: it reports it.

    Every structural problem the checks know about is reported with its own reason.
    The broad ``except`` below is a last line, so that an input nobody anticipated
    still fails closed instead of escaping as an exception.
    """
    try:
        return _check(bundle, pinned_keys)
    except Exception as exc:  # noqa: BLE001 - fail closed on anything unanticipated
        return BundleCheck(False, "", 0, reasons=[f"bundle could not be checked ({type(exc).__name__}: {exc})"])


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def parse_bundle(bundle_bytes: bytes) -> Any:
    """Parse bundle bytes, refusing a JSON object that repeats a key."""
    if not isinstance(bundle_bytes, (bytes, bytearray)):
        raise BundleNotVerified(["the bundle must be given as bytes"])
    try:
        return json.loads(bundle_bytes, object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, ValueError) as exc:
        raise BundleNotVerified([f"the bundle is not valid JSON ({exc})"]) from None
    except RecursionError:
        raise BundleNotVerified(["the bundle nests too deeply to parse"]) from None


def models_in_bundle(bundle: dict[str, Any]) -> list[tuple[str, str]]:
    """Distinct (provider, model) pairs the bundle's ``model_call`` events name.

    Read from ``cost.provider`` and ``cost.model``. A ``model_call`` event that does
    not name both raises: the record would otherwise name a model the evidence never
    identified.
    """
    seen: set[tuple[str, str]] = set()
    for event in bundle["events"]:
        if event.get("actionType") != "model_call":
            continue
        cost = event.get("cost")
        provider = cost.get("provider") if isinstance(cost, dict) else None
        model = cost.get("model") if isinstance(cost, dict) else None
        if not (isinstance(provider, str) and provider and isinstance(model, str) and model):
            raise MissingEvidence(
                f"the model_call event at seq {event.get('seq')} does not name its provider "
                "and model (cost.provider, cost.model), so the bundle cannot support a record "
                "that names its model"
            )
        seen.add((provider, model))
    return sorted(seen)


def select_model(
    bundle: dict[str, Any], provider: str | None = None, model_id: str | None = None
) -> tuple[str, str]:
    """The one (provider, model) the record names, checked against the bundle.

    With neither given, the bundle must name exactly one. A given value narrows the
    bundle's pairs and must leave exactly one: an explicit choice is never accepted
    without a ``model_call`` event behind it, and a value given for one half is
    never replaced by the other half's inference.
    """
    models = models_in_bundle(bundle)
    if not models:
        raise MissingEvidence("the bundle has no model_call event, so it names no model")
    matches = [
        (p, m)
        for p, m in models
        if (provider is None or p == provider) and (model_id is None or m == model_id)
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        asked = f"{provider or '*'} / {model_id or '*'}"
        raise ValueError(f"{asked} is not a model the bundle's model_call events name; they name {models}")
    raise ValueError(
        f"the bundle names {len(matches)} models {matches}; pass --model-provider and "
        "--model-id to choose one"
    )


def tool_transcript_bytes(bundle: dict[str, Any]) -> bytes:
    """The tool-call transcript: RFC 8785 form of the ``tool_call`` events, in order.

    Each event exactly as exported, ``eventHash`` included, so anyone holding the
    bundle can recompute ``tool_transcript.hash`` and it is bound to the chain.
    """
    return rfc8785.dumps([e for e in bundle["events"] if e.get("actionType") == "tool_call"])


def build_trust_record(
    bundle_bytes: bytes,
    *,
    subject: str,
    policy_bundle: bytes,
    enforcement_mode: str,
    workload_digest: str,
    data_class: str,
    jwk: dict[str, Any],
    model_provider: str | None = None,
    model_id: str | None = None,
    producer: str = DEFAULT_PRODUCER,
    pinned_keys: dict[str, str] | None = None,
    iat: int | None = None,
) -> dict[str, Any]:
    """Return an unsigned Level 0 Trust Record for a bundle that verifies.

    ``subject`` (SPIFFE URI or DID), ``policy_bundle`` (the bytes of the policy in
    force) and ``workload_digest`` (the agent's artifact digest) come from the
    operator because the bundle does not carry them. ``enforcement_mode`` has no
    default: pass what the deployment did for the whole window (``enforce`` when
    tool calls were held by policy before they ran, ``advisory`` when decisions were
    recorded only, ``declared`` when no policy was evaluated, which a bundle holding
    ``policy_decision`` events contradicts and is refused).
    """
    bundle = parse_bundle(bundle_bytes)
    check = check_bundle(bundle, pinned_keys=pinned_keys)
    if not check.ok:
        raise BundleNotVerified(check.reasons)
    if bundle["events"][0]["seq"] != 0:
        # TRACE has no field that says a record covers part of a log, so a record from
        # an excerpt would read as the whole of it: its transcript, model and policy
        # facts would silently omit everything before the excerpt.
        raise BundleNotVerified(
            [
                f"the bundle starts at seq {bundle['events'][0]['seq']}, not 0; a record is "
                "built only from a whole log, because nothing in it could say it covers part"
            ]
        )
    decisions = sum(1 for e in bundle["events"] if e.get("actionType") == "policy_decision")
    if enforcement_mode == "declared" and decisions:
        # TRACE v0.2: "A producer that evaluates policy MUST NOT use [declared]".
        raise ValueError(
            f"the bundle records {decisions} policy decision(s), so a policy was evaluated; "
            "'declared' says nothing evaluated it. Pass advisory or enforce."
        )
    provider, model = select_model(bundle, model_provider, model_id)
    tool_calls = sum(1 for e in bundle["events"] if e.get("actionType") == "tool_call")
    return build_record(
        source=SourceSystem(
            producer=producer,
            kind="log-import",
            # The event the anchoring checkpoint covers, by Auditant's own event id.
            source_event_id=check.anchored_event_id,
        ),
        subject=subject,
        model_provider=provider,
        model_id=model,
        policy=PolicyEvidence(bundle=policy_bundle, enforcement_mode=enforcement_mode),
        data_class=data_class,
        jwk=jwk,
        transcript_bytes=tool_transcript_bytes(bundle) if tool_calls else None,
        tool_call_count=tool_calls if tool_calls else None,
        workload_digest=workload_digest,
        iat=iat,
    )


def _pins(items: list[str]) -> dict[str, str] | None:
    if not items:
        return None
    pins: dict[str, str] = {}
    for item in items:
        key_id, _, path = item.partition("=")
        if not key_id or not path:
            raise ValueError(f"--pin-key takes KEYID=PEMFILE, got {item!r}")
        pins[key_id] = Path(path).read_text()
    return pins


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("bundle", type=Path, help="Auditant evidence bundle (JSON)")
    ap.add_argument("--out", type=Path, required=True, help="where to write the signed record")
    ap.add_argument("--subject", required=True, help="spiffe:// or did: identity of the agent workload")
    ap.add_argument("--policy-bundle", type=Path, required=True, help="file holding the policy bytes in force")
    ap.add_argument("--enforcement-mode", required=True, choices=ENFORCEMENT_MODES)
    ap.add_argument("--workload-digest", required=True, help="sha256:/sha384: digest of the agent's artifact")
    ap.add_argument("--data-class", required=True)
    ap.add_argument("--model-provider")
    ap.add_argument("--model-id")
    ap.add_argument("--producer", default=DEFAULT_PRODUCER, help="URI of the system that produced the bundle (a self-hosted Auditant: its own URL)")
    ap.add_argument("--pin-key", action="append", default=[], metavar="KEYID=PEMFILE")
    ap.add_argument(
        "--signing-key",
        type=Path,
        help="Ed25519 private key PEM; otherwise TRACE_PRIVATE_KEY_PEM, else an ephemeral key",
    )
    args = ap.parse_args(argv)

    try:
        key = load_key(args.signing_key.read_text()) if args.signing_key else load_signing_key()
        bundle_bytes = args.bundle.read_bytes()
        policy_bytes = args.policy_bundle.read_bytes()
        pins = _pins(args.pin_key)
    except (OSError, ValueError) as exc:
        print(f"cannot read the inputs, no record written: {exc}", file=sys.stderr)
        return 2
    try:
        record = build_trust_record(
            bundle_bytes,
            subject=args.subject,
            policy_bundle=policy_bytes,
            enforcement_mode=args.enforcement_mode,
            workload_digest=args.workload_digest,
            data_class=args.data_class,
            jwk=key_to_jwk(key),
            model_provider=args.model_provider,
            model_id=args.model_id,
            producer=args.producer,
            pinned_keys=pins,
        )
    except BundleNotVerified as exc:
        print("bundle did not verify, no record written:", file=sys.stderr)
        for reason in exc.reasons:
            print("  " + reason, file=sys.stderr)
        return 2
    except ValueError as exc:  # MissingEvidence included
        print(f"cannot build a truthful record, none written: {exc}", file=sys.stderr)
        return 2
    signed = sign_record(record, key)
    TrustRecord.model_validate(signed)
    args.out.write_text(json.dumps(signed, indent=2) + "\n")
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
