from __future__ import annotations
import re
from .base import AdapterResult
from ..model import Boundary, EvidenceClass, Observation, Outcome, Scenario


def _meets_version_floor(value: object) -> bool:
    """Check the fixed 1.0.0 floor using SemVer 2.0.0 precedence (semver.org)."""
    if not isinstance(value, str):
        return False
    match = re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
        r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
        r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", value
    )
    if match is None:
        return False
    major, minor, patch, prerelease = match.groups()
    if prerelease is not None and any(
        part.isdigit() and len(part) > 1 and part.startswith("0")
        for part in prerelease.split(".")
    ):
        return False
    # Components are canonical decimal strings; this fixed floor avoids int-size limits.
    above_floor = major != "0" and (major != "1" or minor != "0" or patch != "0")
    at_floor = (major, minor, patch) == ("1", "0", "0")
    return above_floor or (at_floor and prerelease is None)

class DeterministicWorkflowAdapter:
    """Deterministic software-only adapter used to prove harness semantics."""
    name = "deterministic-workflow"

    def run(self, scenario: Scenario) -> AdapterResult:
        i = scenario.inputs
        obs: list[Observation] = []

        def emit(boundary, outcome, source, caused_by=None, lineage="main", detail=None):
            obs.append(Observation(
                boundary=boundary,
                outcome=outcome,
                source=source,
                evidence_class=EvidenceClass.SYNTHETIC,
                caused_by=caused_by,
                lineage=lineage,
                detail=detail,
            ))

        auth_ok = (
            i.get("workload") == scenario.workload_principal
            and i.get("key_id") == "key-A"
            and i.get("policy_version") == scenario.policy_version
        )
        if scenario.mutation == "disable_authorization_gate":
            auth_ok = True
        emit(
            Boundary.AUTHORIZATION,
            Outcome.ESTABLISHED if auth_ok else Outcome.CONTRADICTED,
            "authorization-check",
        )

        if i.get("dispatch", True):
            emit(Boundary.DELIVERY, Outcome.ESTABLISHED, "dispatch", "authorization-check")
            if i.get("timeout_after_dispatch", False):
                emit(Boundary.RECEIPT, Outcome.UNAVAILABLE, "receipt-timeout", "dispatch")
                emit(Boundary.ADMISSION, Outcome.UNAVAILABLE, "receipt-timeout", "dispatch")
                emit(Boundary.EXECUTION, Outcome.UNAVAILABLE, "receipt-timeout", "dispatch")
            else:
                emit(Boundary.RECEIPT, Outcome.ESTABLISHED, "peer-receipt", "dispatch")
                admitted = _meets_version_floor(i.get("software_version", "1.0.0"))
                if scenario.mutation == "disable_version_gate":
                    admitted = True
                emit(
                    Boundary.ADMISSION,
                    Outcome.ESTABLISHED if admitted else Outcome.CONTRADICTED,
                    "version-admission",
                    "peer-receipt",
                )
                revoked = i.get("revoked_before_use", False)
                if scenario.mutation == "disable_revocation_gate":
                    revoked = False
                replayed = i.get("replay", False)
                if scenario.mutation == "disable_replay_gate":
                    replayed = False
                missing_execution_evidence = i.get("missing_execution_evidence", False)
                executed = auth_ok and admitted and not replayed and not revoked
                if missing_execution_evidence:
                    execution_outcome = Outcome.UNAVAILABLE
                else:
                    execution_outcome = (
                        Outcome.ESTABLISHED if executed else Outcome.CONTRADICTED
                    )
                if (
                    scenario.mutation == "assume_missing_execution_success"
                    and missing_execution_evidence
                ):
                    execution_outcome = Outcome.ESTABLISHED
                emit(
                    Boundary.EXECUTION,
                    execution_outcome,
                    "execution-check",
                    "version-admission",
                )
        else:
            emit(Boundary.DELIVERY, Outcome.NOT_APPLICABLE, "not-dispatched")
            emit(Boundary.RECEIPT, Outcome.NOT_APPLICABLE, "not-dispatched")
            emit(Boundary.ADMISSION, Outcome.NOT_APPLICABLE, "not-dispatched")
            emit(Boundary.EXECUTION, Outcome.NOT_APPLICABLE, "not-dispatched")

        if i.get("retry_lineage", False):
            emit(
                Boundary.DELIVERY,
                Outcome.ESTABLISHED,
                "retry-dispatch",
                "authorization-check",
                lineage="retry-1",
            )
            emit(
                Boundary.EXECUTION,
                Outcome.ESTABLISHED,
                "retry-execution",
                "retry-dispatch",
                lineage="retry-1",
            )

        exec_main = next(
            (
                o.outcome
                for o in reversed(obs)
                if o.boundary == Boundary.EXECUTION and o.lineage == "main"
            ),
            Outcome.UNAVAILABLE,
        )
        verified = exec_main == Outcome.ESTABLISHED and i.get("response_bound", True)
        if scenario.mutation == "disable_response_binding_gate":
            verified = exec_main == Outcome.ESTABLISHED
        emit(
            Boundary.RESPONSE_VERIFICATION,
            Outcome.ESTABLISHED
            if verified
            else (Outcome.UNAVAILABLE if exec_main == Outcome.UNAVAILABLE else Outcome.CONTRADICTED),
            "response-binding",
            "execution-check",
        )

        recipient = i.get("recipient", "recipient-R")
        allowed_recipient = (
            recipient in scenario.permitted_recipients
            and recipient not in scenario.forbidden_recipients
        )
        release_ok = verified and allowed_recipient and not i.get("bypass_egress", False)
        if scenario.mutation == "disable_release_gate":
            release_ok = verified
        release_outcome = (
            Outcome.ESTABLISHED
            if release_ok
            else Outcome.UNAVAILABLE
            if exec_main == Outcome.UNAVAILABLE
            else Outcome.CONTRADICTED
        )
        emit(Boundary.RELEASE, release_outcome, "release-check", "response-binding")

        return AdapterResult(tuple(obs))
