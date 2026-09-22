"""aps_action_receipt: verify one signed APS action intent receipt as external action evidence.

TRACE keeps three evidence layers apart (trace-spec ``spec/trace-v0.2.md``
section 3.3.3): session evidence, action issuance evidence, and outcome
evidence. An APS ``ReceiptV1`` of type ``aps:action-intent:v1`` (profile
``aps-receipt-v1``, produced by
``agent_passport.receipt_core.create_receipt_v1``) is action issuance
evidence. It carries the acting agent as both issuer and subject, a content
addressed ``action_ref``, a ``delegation_ref``, an ``issued_at`` timestamp,
and one or more Ed25519 signatures whose keys are resolved by the caller,
never taken from the receipt.

This module runs the checks TRACE lists for external action receipts
(``docs/verification.md``, "Action receipts and embodied workflows") against
one such receipt and reports an APS issuance evidence status:

``verified``
    Every check that could be run passed and the issuer key was one the
    caller pinned. The receipt is authentic, is an action intent record that
    satisfies draft-pidlisnyi-aps-03 section 5.3.1, is bound to the supplied
    action preimage and expectations, and is fresh at the caller's reference
    time.
``invalid``
    The receipt is present but at least one check failed: structure, receipt
    id, signature, artifact class, stage rules, subject agent, delegation
    reference, action binding, or freshness.
``unverified``
    The caller's resolver could not establish the signer's key, and nothing
    else failed. Per trace-spec section 3.3.2 this confers no trust and
    proves no wrongdoing.

The ReceiptV1 envelope, identifier, signer authority and section 5.3 stage
state come from the SDK. This module consumes those axes and adds the TRACE
side checks below: the caller's expected subject agent and delegation
reference, the action binding, and freshness. Those four can fail on their
own and are this module's own verdict, not the SDK's.

Since agent-passport-system 4.0.0, ``verify_receipt_v1`` reports its outcome
on separate axes: an aggregate ``status``, a ``stage`` result for the section
5.3 rules of the record's own type, a ``signer_authority`` axis, a
``receipt_id_valid`` field, an ``other_signatures`` axis, and per signature
results. This module reads those axes and translates them into TRACE terms.
It does not reconstruct the SDK's state machine out of the error list, and
it does not decide key resolution semantics of its own: an unresolved key,
an ambiguous one, malformed key material, an unreachable resolver and an
unsupported identifier scheme are all the SDK's to classify, and all of them
reach ``unverified`` here rather than being reported as a failed signature.
A signature is reported as failed only where signature bytes were actually
checked and did not verify.

Mapping to TRACE's action receipt outcomes (``docs/verification.md``):
``invalid`` corresponds to ``receipt_invalid`` and ``unverified`` to
``receipt_unverified``. ``verified`` has no TRACE outcome, on purpose. TRACE
splits a valid receipt into ``receipt_valid_accepted`` and
``receipt_valid_rejected`` by the outcome the receipt payload carries. An
action intent's ``result`` is exactly ``{"profile":
"aps-action-intent-result-v1", "status": "declared"}``, which is declaration
state and not an execution or decision verdict, so there is no acceptance to
read out of it. That split is outcome evidence and belongs to the bound
decision output. ``receipt_missing_required`` is a chain level outcome and
out of scope for a verifier that takes one receipt.

What ``verified`` does not mean:

- that the action executed or succeeded anywhere.
- that the delegation named by ``delegation_ref`` exists, is valid, is
  current, or is unrevoked. This module compares ``delegation_ref`` to what
  the caller expected and does nothing else with it. The referenced record
  is an ``AuthorityDelegationV1`` and is verified separately, by
  ``agent_passport.verify_authority_delegation_chain``, which this module
  does not call. The legacy ``verify_delegation`` is a different, pre-draft
  primitive and is not the verifier for this reference.
- that the delegation's scope authorizes the action the receipt describes.
  No authority evaluation happens here at all.
- that the receipt's signature proves authority, as opposed to authorship.
- that anyone appraised the evidence.
- that the wire bytes carried no duplicate JSON object members. This
  function receives a dict, so by the time it runs, a later duplicate member
  has already overwritten the earlier one. Establishing that property needs
  ``agent_passport.receipt_core.verify_receipt_v1_serialized`` on the raw
  bytes, which this integration does not take.

Nothing here touches ``agentrust_trace``. The function consumes an APS
artifact and reports in TRACE terms so a TRACE profile can consume the
result. It emits no TRACE record.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from agent_passport import ActionReferenceError, compute_action_ref_v2
from agent_passport.receipt_core import verify_receipt_v1

VERIFIED = "verified"
INVALID = "invalid"
UNVERIFIED = "unverified"
STATUSES = (VERIFIED, INVALID, UNVERIFIED)

#: The receipt type this verifier is for, and the only one it accepts.
#: ``ReceiptV1`` is one envelope for several receipt types, and only an
#: action intent receipt is action issuance evidence. This is passed to the
#: SDK as its ``expected_receipt_type`` rather than compared here, so the
#: expectation has one source of truth.
ACTION_INTENT_RECEIPT_TYPE = "aps:action-intent:v1"

#: Checks in the order they run. A structural failure stops the run: the
#: remaining checks are reported as ``not_checked`` because their inputs
#: cannot be trusted.
CHECKS = (
    "structure",
    "receipt_id",
    "signature",
    "receipt_type",
    "stage",
    "subject_agent",
    "delegation_ref",
    "action_binding",
    "freshness",
)

PASS = "pass"
FAIL = "fail"
NOT_CHECKED = "not_checked"

#: ``resolve_key(signer, key_id, issued_at)`` returns the hex Ed25519 public
#: key the caller pins for that signer and key id. Since SDK 4.0.0 it may
#: instead return a mapping naming one of the draft section 2.5 resolution
#: outcomes, for example ``{"outcome": "not_found"}``. Returning ``None``
#: remains an unresolved answer. It is the trust input. A key embedded in
#: the receipt is never consulted, because ``ReceiptV1`` carries none.
KeyResolver = Callable[[str, str, str], Optional[object]]

_ISSUED_AT_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

#: The SDK's own aggregate state for a record that failed a check. It is
#: spelled the same as this module's ``INVALID`` and means something
#: narrower, so it is named separately rather than compared against ours.
_CORE_INVALID = "invalid"

#: ``verify_receipt_v1`` reports a mismatch against the expected receipt
#: type as a stage failure with this code. For this module that is not a
#: stage rule outcome, it is the wrong artifact class.
_STAGE_MISMATCH = "STAGE_MISMATCH"


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
    expected_subject_agent: str | None = None,
    expected_delegation_ref: str | None = None,
    action: dict | None = None,
    clock_skew_seconds: int = 0,
) -> dict:
    """Verify one APS ``ReceiptV1`` action intent as external action issuance evidence.

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
    expected_subject_agent
        When given, ``receipt["subject_agent"]`` must equal it.
    expected_delegation_ref
        When given, ``receipt["delegation_ref"]`` must equal it. That value
        is an ``AuthorityDelegationV1`` identifier and therefore carries its
        ``sha256:`` prefix. Comparing it establishes nothing about the
        referenced delegation itself.
    action
        When given, the exact ``aps-action-ref-v2`` input object, as
        ``agent_passport.create_action_reference_input_v2`` builds it:
        ``profile``, ``agent_id``, ``action_type``, ``target``,
        ``payload_ref``, ``scope_required``, ``issued_at`` and ``nonce``.
        ``compute_action_ref_v2`` is recomputed over it and must equal
        ``receipt["action_ref"]``, and ``action["agent_id"]`` must equal
        ``receipt["subject_agent"]``, so the receipt cannot describe one
        agent while its digest describes another. The pre-draft
        ``compute_action_ref`` hashes a different preimage and its digest
        cannot satisfy this check. Without a preimage the binding check is
        reported as ``not_checked``: a receipt whose action preimage the
        verifier does not hold is bound to a digest, not to an action the
        verifier can name.
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
        ``signature_results``: the per signature results from the SDK.
        ``core_status``: the SDK's own aggregate state, carried through
        unchanged so a caller can see what this translation was made from.
        ``other_signatures``: the SDK's axis for signatures that are not
        required. It never moves ``status`` here, because a third party can
        append a descriptor to a published receipt without changing its
        ``receipt_id``.
    """
    if reference_time.tzinfo is None or reference_time.utcoffset() is None:
        raise ValueError("reference_time must be timezone aware")
    if max_age_seconds < 0 or clock_skew_seconds < 0:
        raise ValueError("max_age_seconds and clock_skew_seconds must be non-negative")
    if not isinstance(receipt, dict):
        raise TypeError("receipt must be a dict")

    checks = {name: NOT_CHECKED for name in CHECKS}
    reasons: list[str] = []

    core = verify_receipt_v1(
        receipt, resolve_key, expected_receipt_type=ACTION_INTENT_RECEIPT_TYPE
    )
    stage = core["stage"]

    # The SDK reports "not_checked" for a record that never reached the stage
    # step. Two things land here: an envelope the schema refused, and an
    # artifact under another envelope profile, which is not judged against the
    # aps-receipt-v1 schema at all. Neither is action issuance evidence, and
    # nothing past this point has trustworthy inputs.
    if stage == NOT_CHECKED:
        checks["structure"] = FAIL
        reasons.extend(core["errors"])
        return _result(INVALID, checks, reasons, None, core)
    checks["structure"] = PASS

    receipt_id_valid = core["receipt_id_valid"]
    if receipt_id_valid is True:
        checks["receipt_id"] = PASS
    elif receipt_id_valid is False:
        checks["receipt_id"] = FAIL
        reasons.append("receipt_id_mismatch")

    # The signer axis, not the error list. "invalid" is the only outcome where
    # signature bytes were checked and did not verify. Every resolution outcome
    # the SDK keeps apart, not found, ambiguous, malformed key material,
    # unreachable, and an unsupported identifier scheme, arrives as
    # "not_established" and is a non verification here, never a failure.
    signer_authority = core["signer_authority"]
    unresolved = signer_authority == "not_established"
    if signer_authority == "verified":
        checks["signature"] = PASS
    elif signer_authority == "invalid":
        checks["signature"] = FAIL
    for item in core["signature_results"]:
        # Only a required signature contributes a reason. A non-required one
        # that fails or cannot be resolved moves the SDK's own
        # ``other_signatures`` axis and nothing else. Since signatures sit
        # outside the ``receipt_id`` preimage, anyone can append a descriptor
        # to a published receipt without changing its identifier, and letting
        # that put a failure reason on a verified result would hand this
        # module's output to that third party.
        if not item.get("required") or item.get("valid"):
            continue
        reasons.append(
            f"signature:{item['signer']}:{item['key_id']}:{item.get('reason', 'invalid')}"
        )

    # A mismatch against the expected receipt type is reported by the SDK as a
    # stage failure. For this module it is the wrong artifact class rather than
    # a section 5.3 outcome, and the stage rules of a type this verifier does
    # not accept were never the question.
    stage_failures = [failure["code"] for failure in stage["failures"]]
    if _STAGE_MISMATCH in stage_failures:
        checks["receipt_type"] = FAIL
        reasons.append("receipt_type_mismatch")
    else:
        checks["receipt_type"] = PASS
        if stage["status"] == "valid":
            checks["stage"] = PASS
        else:
            checks["stage"] = FAIL
            reasons.extend(stage_failures or [f"stage_{stage['status']}"])

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
            recomputed = compute_action_ref_v2(action)
        except ActionReferenceError as exc:
            checks["action_binding"] = FAIL
            reasons.append(f"action_preimage_invalid:{exc.code}")
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

    failed = any(state == FAIL for state in checks.values())
    # Translation guard, not a check. Every other invalid result names the
    # check that produced it, and that property is worth keeping. But if a
    # future SDK reports invalid for a state none of the axes above map to,
    # this must not read as verified, so the result is forced to invalid with
    # the SDK's own errors carried through. No entry in ``checks`` is FAIL on
    # this path, which is the one case where the failing check is not visible.
    # Unreachable through this wrapper on 4.0.0, where every invalid state the
    # SDK can report arrives on an axis that is mapped above.
    if not failed and core["status"] == _CORE_INVALID:
        failed = True
        reasons.append("unmapped_core_invalid:" + ",".join(core["errors"]))

    if failed:
        status = INVALID
    elif unresolved:
        status = UNVERIFIED
    else:
        status = VERIFIED
    return _result(status, checks, reasons, receipt["receipt_type"], core)


def _result(status: str, checks: dict, reasons: list[str], receipt_type: str | None, core: dict) -> dict:
    return {
        "status": status,
        "checks": dict(checks),
        "reasons": list(reasons),
        "receipt_type": receipt_type,
        "signature_results": list(core["signature_results"]),
        "core_status": core["status"],
        "other_signatures": core["other_signatures"],
    }
