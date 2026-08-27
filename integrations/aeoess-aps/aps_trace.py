"""aps_trace: export one signed APS policy decision as a TRACE Trust Record.

The Agent Passport System (APS) evaluates an ActionIntent against a Values
Floor and returns a PolicyDecision: a dict signed by the evaluator, carrying a
verdict of ``permit``, ``narrow`` or ``deny``. This module maps exactly one
such decision onto one TRACE Trust Record dict (EAT profile
``tag:agentrust-io.com,2026:trace-v0.2``).

Two different signatures are involved and they are never the same key:

1. The APS evaluator signature carried inside the decision. It is verified here,
   before any mapping happens, against the ``evaluatorPublicKey`` embedded in
   the decision, using ``agent_passport.policy.verify_policy_decision``.
2. The TRACE record signature, applied afterwards by
   ``agentrust_trace.sign_record`` with a separate key whose public JWK is bound
   into ``cnf.jwk``. This module never applies it.

A record that fails step 1 is never produced. The mapper raises instead, so an
unverified or expired APS decision cannot become a TRACE record that looks
appraised.

Field mapping
=============

TRACE field                 APS source
--------------------------  ---------------------------------------------------
eat_profile                 constant EAT_PROFILE
iat                         ``evaluatedAt``, parsed to Unix seconds
subject                     spiffe://<TRUST_DOMAIN>/evaluator/<evaluatorId>
                            /decision/<decisionId>
cnf.jwk                     caller-supplied ``trace_jwk``
policy.bundle_hash          sha256 over the canonical bytes of
                            {"floorVersion", "principlesEvaluated"}
policy.enforcement_mode     "enforce" when any principle was evaluated with
                            enforcementMode "inline", else "advisory"
policy.version              ``floorVersion`` (omitted when empty)
runtime.platform            "software-only"
runtime.measurement         sha256 over the canonical bytes of the full signed
                            decision
appraisal.status            constant "none": nothing here appraised the evidence
appraisal.verifier          urn:aps:evaluator:<evaluatorId>
appraisal.policy_ref        urn:aps:floor:<floorVersion> (omitted when empty)
appraisal.timestamp         iat
transparency                "urn:aps:transparency:none"

Deliberately absent
===================

``model``, ``data_class`` and ``build_provenance`` are required by the TRACE
v0.2 JSON Schema and are absent here. An APS policy decision carries no model
identity, no data classification and no build provenance, so any value would be
invented. The record is therefore a partial TRACE record: it passes
``trace-tests verify --level 0``, and it does not satisfy the full v0.2 schema.
``tests/test_mapping.py`` pins the exact set of absent required fields so the
gap stays deliberate. See the README section "What it does NOT claim".

``tool_transcript`` is absent because a policy decision is not a tool
transcript. ``delegation`` is absent because delegation chains are out of scope
for this integration.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from agent_passport.canonical import canonicalize
from agent_passport.policy import verify_policy_decision

#: EAT profile URI, identical to the constant the other integrations use.
EAT_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"

#: SPIFFE trust domain for APS workload identities.
TRUST_DOMAIN = "agent-passport.org"

#: APS verdicts this mapper accepts. permit authorizes the action, narrow
#: authorizes it under added constraints, deny withholds authorization. The
#: verdict is checked against this set so an unknown one is refused rather than
#: transcribed, but it no longer selects an appraisal status: see APPRAISAL_STATUS.
KNOWN_VERDICTS = frozenset({"permit", "narrow", "deny"})

#: appraisal.status is a constant, not a parameter.
#: The agentrust-trace-adapters convention (integrations packages/agentrust-
#: trace-adapters/README.md, commit e1aa231, 2026-08-08) sets appraisal.status
#: to "none" for a record assembled from evidence another system produced, on
#: the grounds that "Nobody appraised the evidence. Transcribing is not
#: appraising", and that "A vendor's bare ALLOW/DENY result is still a policy
#: decision, not an appraisal of the evidence behind that decision."
#: An APS verdict is exactly such a policy decision. It stays in the record as
#: policy.enforcement_mode and policy.version; it is not an evidence appraisal.
APPRAISAL_STATUS = "none"

#: Keys a signed APS policy decision must carry. Checked before signature
#: verification so a malformed input fails with a precise message.
REQUIRED_DECISION_KEYS = frozenset(
    {
        "decisionId",
        "intentId",
        "evaluatorId",
        "evaluatorPublicKey",
        "verdict",
        "principlesEvaluated",
        "reason",
        "floorVersion",
        "evaluatedAt",
        "expiresAt",
        "signature",
    }
)


def build_trace_record(decision: dict[str, Any], *, trace_jwk: dict[str, str]) -> dict[str, Any]:
    """Map one signed APS policy decision onto an unsigned TRACE Trust Record.

    Args:
        decision: The dict returned by ``agent_passport.policy.evaluate_intent``,
            including its evaluator ``signature``.
        trace_jwk: Public JWK bound into ``cnf.jwk``. It belongs to the key used
            later by ``agentrust_trace.sign_record``, and has nothing to do with
            the APS evaluator key.

    Returns:
        An unsigned TRACE Trust Record dict.

    Raises:
        ValueError: if the decision is malformed, its evaluator signature does
            not verify, it has expired, or its verdict is not one this mapper
            knows how to appraise. No record is returned in any of those cases.
    """
    _validate_decision(decision)

    evaluator_id = decision["evaluatorId"]
    decision_id = decision["decisionId"]
    floor_version = decision["floorVersion"]
    iat = _unix_seconds(decision["evaluatedAt"])

    appraisal: dict[str, Any] = {
        "status": APPRAISAL_STATUS,
        "timestamp": iat,
        "verifier": f"urn:aps:evaluator:{quote(str(evaluator_id), safe='')}",
    }
    if floor_version:
        appraisal["policy_ref"] = f"urn:aps:floor:{quote(str(floor_version), safe='')}"

    policy: dict[str, Any] = {
        "bundle_hash": _sha256_of(
            {
                "floorVersion": floor_version,
                "principlesEvaluated": decision["principlesEvaluated"],
            }
        ),
        "enforcement_mode": _enforcement_mode(decision["principlesEvaluated"]),
    }
    if floor_version:
        policy["version"] = str(floor_version)

    return {
        "eat_profile": EAT_PROFILE,
        "iat": iat,
        "subject": (
            f"spiffe://{TRUST_DOMAIN}"
            f"/evaluator/{quote(str(evaluator_id), safe='')}"
            f"/decision/{quote(str(decision_id), safe='')}"
        ),
        "cnf": {"jwk": trace_jwk},
        "policy": policy,
        "runtime": {
            "platform": "software-only",
            "measurement": _sha256_of(decision),
        },
        "appraisal": appraisal,
        "transparency": "urn:aps:transparency:none",
    }


def _validate_decision(decision: dict[str, Any]) -> None:
    """Refuse anything that must not become a TRACE Trust Record.

    Checks shape, then the evaluator signature and expiry through
    ``verify_policy_decision``, then the verdict. Every rejection raises
    ``ValueError`` with the reason, so a caller can never mistake a refusal for
    a mapped record.
    """
    if not isinstance(decision, dict):
        raise ValueError(f"decision must be a dict, got {type(decision).__name__}")

    missing = REQUIRED_DECISION_KEYS - decision.keys()
    if missing:
        raise ValueError(f"decision missing required fields: {sorted(missing)}")

    check = verify_policy_decision(decision)
    if not check["valid"]:
        raise ValueError(
            "refusing to map an APS decision that failed verification: "
            + "; ".join(check["errors"])
        )

    verdict = decision["verdict"]
    if verdict not in KNOWN_VERDICTS:
        raise ValueError(
            f"unknown APS verdict {verdict!r}; expected one of "
            f"{sorted(KNOWN_VERDICTS)}"
        )


def _enforcement_mode(principles: Any) -> str:
    """Return the TRACE enforcement mode implied by the evaluated principles.

    APS records a per-principle ``enforcementMode`` of ``inline``, ``audit`` or
    ``warn``. Inline blocks the action when the principle fails, which is what
    TRACE calls ``enforce``. Audit and warn log and let the action proceed,
    which is ``advisory``. ``silent`` is never emitted: APS has no mode that
    suppresses the operational record.
    """
    if isinstance(principles, list):
        for principle in principles:
            if isinstance(principle, dict) and principle.get("enforcementMode") == "inline":
                return "enforce"
    return "advisory"


def _sha256_of(obj: Any) -> str:
    """Return ``sha256:<hex>`` over the APS canonical bytes of *obj*.

    Uses the same canonicalization the APS evaluator signs over, so the digest
    is reproducible by any APS implementation from the same input.
    """
    digest = hashlib.sha256(canonicalize(obj).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _unix_seconds(timestamp: str) -> int:
    """Parse an APS ISO 8601 timestamp into integer Unix seconds (UTC)."""
    if not isinstance(timestamp, str) or not timestamp:
        raise ValueError(f"timestamp must be a non-empty ISO 8601 string, got {timestamp!r}")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"timestamp {timestamp!r} is not ISO 8601: {exc}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())
