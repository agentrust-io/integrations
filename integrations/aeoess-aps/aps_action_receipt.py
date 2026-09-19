"""aps_action_receipt: verify one signed APS action receipt as external action evidence.

TRACE keeps three evidence layers apart (trace-spec ``spec/trace-v0.2.md``
section 3.3.3): session evidence, action issuance evidence, and outcome
evidence. An APS ``ReceiptV1`` (profile ``aps-receipt-v1``, produced by
``agent_passport.receipt_core.create_receipt_v1``) is action issuance
evidence. It carries who issued it, which agent it is about, a content
addressed ``action_ref``, a ``delegation_ref``, an ``issued_at`` timestamp,
and one or more Ed25519 signatures whose keys are resolved by the caller,
never taken from the receipt.

This module runs the checks TRACE lists for external action receipts
(``docs/verification.md``, "Action receipts and embodied workflows") against
one such receipt and reports an APS issuance evidence status:

``verified``
    Every check that could be run passed and the issuer key was one the
    caller pinned. The receipt is authentic, is the expected receipt type,
    is bound to the supplied action preimage and expectations, and is fresh
    at the caller's reference time.
``invalid``
    The receipt is present but at least one check failed: structure,
    receipt id, signature, receipt type, subject agent, delegation
    reference, action binding, or freshness.
``unverified``
    The receipt names a signer key the caller did not pin, and nothing else
    failed. Per trace-spec section 3.3.2 this confers no trust and proves no
    wrongdoing.

Mapping to TRACE's action receipt outcomes (``docs/verification.md``):
``invalid`` corresponds to ``receipt_invalid`` and ``unverified`` to
``receipt_unverified``. ``verified`` has no TRACE outcome, on purpose. TRACE
splits a valid receipt into ``receipt_valid_accepted`` and
``receipt_valid_rejected`` by the outcome the receipt payload carries.
``ReceiptV1.result`` is an open object and the APS receipt core defines no
verdict field inside it, so reading acceptance or rejection out of it would
be a convention this module invented. That split is outcome evidence and
belongs to the bound decision output. ``receipt_missing_required`` is a
chain level outcome and out of scope for a verifier that takes one receipt.

What ``verified`` does not mean:

- that the action executed or succeeded anywhere.
- that the delegation named by ``delegation_ref`` was valid, current or
  unrevoked at issuance. Delegation material is verified separately, by
  ``agent_passport.verify_delegation``, and this module does not call it.
- that the receipt's signature proves authority, as opposed to authorship.
- that anyone appraised the evidence.

Nothing here touches ``agentrust_trace``. The function consumes an APS
artifact and reports in TRACE terms so a TRACE profile can consume the
result. It emits no TRACE record.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from agent_passport.action_ref import DuplicateScopeRequiredError, compute_action_ref
from agent_passport.receipt_core import verify_receipt_v1

VERIFIED = "verified"
INVALID = "invalid"
UNVERIFIED = "unverified"
STATUSES = (VERIFIED, INVALID, UNVERIFIED)

#: The receipt type this verifier is for. ``ReceiptV1`` is one envelope for
#: several receipt types, and only an action intent receipt is action
#: issuance evidence.
ACTION_INTENT_RECEIPT_TYPE = "aps:action-intent:v1"

#: Checks in the order they run. A structural failure stops the run: the
#: remaining checks are reported as ``not_checked`` because their inputs
#: cannot be trusted.
CHECKS = (
    "structure",
    "receipt_id",
    "signature",
    "receipt_type",
    "subject_agent",
    "delegation_ref",
    "action_binding",
    "freshness",
)

PASS = "pass"
FAIL = "fail"
NOT_CHECKED = "not_checked"

#: ``resolve_key(signer, key_id, issued_at)`` returns the hex Ed25519 public
#: key the caller pins for that signer and key id, or ``None`` when the
#: caller has no key for it. It is the trust input. A key embedded in the
#: receipt is never consulted, because ``ReceiptV1`` carries none.
KeyResolver = Callable[[str, str, str], Optional[str]]

_ISSUED_AT_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def _parse_issued_at(value: str) -> datetime:
    # validate_receipt_v1 already required exact UTC milliseconds with a Z
    # designator, so this parse cannot fail on a structurally valid receipt.
    return datetime.strptime(value, _ISSUED_AT_FORMAT).replace(tzinfo=timezone.utc)


def verify_aps_action_receipt(
    receipt: dict,
    *,
    resolve_key: KeyResolver,
    reference_time: datetime,
    max_age_seconds: int,
    expected_receipt_type: str = ACTION_INTENT_RECEIPT_TYPE,
    expected_subject_agent: str | None = None,
    expected_delegation_ref: str | None = None,
    action: dict | None = None,
    clock_skew_seconds: int = 0,
) -> dict:
    """Verify one APS ``ReceiptV1`` as external action issuance evidence.

    Arguments
    ---------
    receipt
        The ``ReceiptV1`` dict as produced by ``create_receipt_v1``.
    resolve_key
        The caller's pinned key lookup. See ``KeyResolver``.
    reference_time
        The instant freshness is judged at. Must be timezone aware. There is
        no wall clock default: the caller states the time the verdict is for,
        so a committed receipt verifies the same way on every run.
    max_age_seconds
        A receipt issued more than this long before ``reference_time`` is
        stale.
    expected_receipt_type
        ``receipt["receipt_type"]`` must equal it. Defaults to the action
        intent receipt type. Always checked: a correctly signed receipt of
        another type is not action issuance evidence.
    expected_subject_agent
        When given, ``receipt["subject_agent"]`` must equal it.
    expected_delegation_ref
        When given, ``receipt["delegation_ref"]`` must equal it.
    action
        When given, the canonical action preimage as a dict with keys
        ``agent_id``, ``action_type``, ``scope_required`` and ``timestamp``.
        ``agent_passport.compute_action_ref`` is recomputed over it and must
        equal ``receipt["action_ref"]``, and ``action["agent_id"]`` must
        equal ``receipt["subject_agent"]``, so the receipt cannot describe
        one agent while its digest describes another. Without a preimage the
        binding check is reported as ``not_checked``: a receipt whose action
        preimage the verifier does not hold is bound to a digest, not to an
        action the verifier can name.
    clock_skew_seconds
        Tolerance for an ``issued_at`` slightly after ``reference_time``.

    Returns
    -------
    dict
        ``status``: one of ``STATUSES``.
        ``checks``: each name in ``CHECKS`` mapped to ``pass``, ``fail`` or
        ``not_checked``.
        ``reasons``: the failure or non verification reasons, in check order.
        ``receipt_type``: ``receipt["receipt_type"]`` when structure passed,
        else ``None``.
        ``signature_results``: the per signature results from
        ``agent_passport.receipt_core.verify_receipt_v1``.
    """
    if reference_time.tzinfo is None or reference_time.utcoffset() is None:
        raise ValueError("reference_time must be timezone aware")
    if max_age_seconds < 0 or clock_skew_seconds < 0:
        raise ValueError("max_age_seconds and clock_skew_seconds must be non-negative")
    if not isinstance(receipt, dict):
        raise TypeError("receipt must be a dict")

    checks = {name: NOT_CHECKED for name in CHECKS}
    reasons: list[str] = []

    core = verify_receipt_v1(receipt, resolve_key)
    # verify_receipt_v1 reports receipt id and signature outcomes through
    # ``errors`` as well as through their own fields. Only what remains is a
    # structural refusal from validate_receipt_v1, which returns before any
    # signature is examined.
    structural = [error for error in core["errors"] if error not in ("receipt_id_mismatch", "signature_invalid")]
    if structural:
        checks["structure"] = FAIL
        reasons.extend(structural)
        return _result(INVALID, checks, reasons, None, core["signature_results"])
    checks["structure"] = PASS

    if core["receipt_id_valid"]:
        checks["receipt_id"] = PASS
    else:
        checks["receipt_id"] = FAIL
        reasons.append("receipt_id_mismatch")

    unresolved = False
    signature_failed = False
    for item in core["signature_results"]:
        if item["valid"]:
            continue
        reason = item.get("reason")
        if reason in ("key_unresolved", "key_resolution_error"):
            unresolved = True
            reasons.append(f"signature:{item['signer']}:{item['key_id']}:{reason}")
        else:
            signature_failed = True
            reasons.append(f"signature:{item['signer']}:{item['key_id']}:invalid")
    if signature_failed:
        checks["signature"] = FAIL
    elif unresolved:
        checks["signature"] = NOT_CHECKED
    else:
        checks["signature"] = PASS

    if receipt["receipt_type"] == expected_receipt_type:
        checks["receipt_type"] = PASS
    else:
        checks["receipt_type"] = FAIL
        reasons.append("receipt_type_mismatch")

    if expected_subject_agent is not None:
        if receipt["subject_agent"] == expected_subject_agent:
            checks["subject_agent"] = PASS
        else:
            checks["subject_agent"] = FAIL
            reasons.append("subject_agent_mismatch")

    if expected_delegation_ref is not None:
        if receipt["delegation_ref"] == expected_delegation_ref:
            checks["delegation_ref"] = PASS
        else:
            checks["delegation_ref"] = FAIL
            reasons.append("delegation_ref_mismatch")

    if action is not None:
        try:
            recomputed = compute_action_ref(
                action["agent_id"],
                action["action_type"],
                action["scope_required"],
                action["timestamp"],
            )
        except DuplicateScopeRequiredError:
            checks["action_binding"] = FAIL
            reasons.append("action_preimage_has_no_canonical_form")
        except (KeyError, TypeError, ValueError) as exc:
            checks["action_binding"] = FAIL
            reasons.append(f"action_preimage_invalid:{exc}")
        else:
            if recomputed != receipt["action_ref"]:
                checks["action_binding"] = FAIL
                reasons.append("action_ref_mismatch")
            elif action["agent_id"] != receipt["subject_agent"]:
                checks["action_binding"] = FAIL
                reasons.append("action_agent_mismatch")
            else:
                checks["action_binding"] = PASS

    issued_at = _parse_issued_at(receipt["issued_at"])
    oldest = reference_time - timedelta(seconds=max_age_seconds)
    newest = reference_time + timedelta(seconds=clock_skew_seconds)
    if issued_at < oldest:
        checks["freshness"] = FAIL
        reasons.append("stale")
    elif issued_at > newest:
        checks["freshness"] = FAIL
        reasons.append("issued_in_future")
    else:
        checks["freshness"] = PASS

    if any(state == FAIL for state in checks.values()):
        status = INVALID
    elif unresolved:
        status = UNVERIFIED
    else:
        status = VERIFIED
    return _result(status, checks, reasons, receipt["receipt_type"], core["signature_results"])


def _result(status: str, checks: dict, reasons: list[str], receipt_type: str | None, signature_results: list) -> dict:
    return {
        "status": status,
        "checks": dict(checks),
        "reasons": list(reasons),
        "receipt_type": receipt_type,
        "signature_results": list(signature_results),
    }
