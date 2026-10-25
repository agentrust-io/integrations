"""Fail-closed boundary between a source decision and a TRACE appraisal."""

from __future__ import annotations

from dataclasses import dataclass

from .evidence import MissingEvidence

__all__ = ["AppraisalEvidence", "appraisal_from_evidence"]


@dataclass(frozen=True)
class AppraisalEvidence:
    """Evidence required before mapping a third-party verdict to appraisal.status.

    A vendor ALLOW/DENY alone is not an appraisal. The adapter must have verified
    the evidence signature and identify the exact appraisal policy used.
    """

    verifier: str
    status: str
    policy_ref: str
    signature_verified: bool
    timestamp: int | None = None

    STATUSES = ("affirming", "warning", "contraindicated")

    def __post_init__(self) -> None:
        if self.status not in self.STATUSES:
            raise ValueError(f"unsupported appraisal status {self.status!r}")
        if (
            not isinstance(self.verifier, str)
            or not self.verifier.strip()
            or not isinstance(self.policy_ref, str)
            or not self.policy_ref.strip()
        ):
            raise MissingEvidence("appraisal requires verifier and policy_ref")
        if self.signature_verified is not True:
            raise MissingEvidence(
                "a source verdict is not a TRACE appraisal until its evidence signature is verified"
            )
        if self.timestamp is not None and (
            type(self.timestamp) is not int
            or not 0 < self.timestamp <= 9_007_199_254_740_991
        ):
            raise ValueError("appraisal timestamp must be a positive RFC 8785 safe integer")


def appraisal_from_evidence(evidence: AppraisalEvidence) -> dict[str, object]:
    block: dict[str, object] = {
        "status": evidence.status,
        "verifier": evidence.verifier,
        "policy_ref": evidence.policy_ref,
    }
    if evidence.timestamp is not None:
        block["timestamp"] = evidence.timestamp
    return block
