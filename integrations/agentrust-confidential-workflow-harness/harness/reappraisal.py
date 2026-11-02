"""Offline applicability checks for retained deterministic harness results.

Inputs are local, caller-trusted fixtures, not authenticated protocol evidence.
An applicable result is not permission to execute, a freshness attestation, or a
replacement for independent acceptance. No adapter or live transport is called.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import re

from .model import EvidenceClass, RunResult, Scenario
from .verdict import status, summarize


def _digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     allow_nan=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _check_digest(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("expected a lowercase sha256 digest")


def _check_time(value: int) -> None:
    if type(value) is not int or value < 0:
        raise ValueError("time must be a non-negative integer UTC Unix second")


@dataclass(frozen=True)
class EvaluationContext:
    """Verifier-selected fixture inputs, supplied separately from the producer."""

    policy_digest: str
    trust_digest: str
    dependencies: tuple[tuple[str, str], ...]

    def __post_init__(self):
        _check_digest(self.policy_digest)
        _check_digest(self.trust_digest)
        if not isinstance(self.dependencies, tuple) or not self.dependencies:
            raise ValueError("dependencies must be a non-empty immutable tuple")
        names = []
        for entry in self.dependencies:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise ValueError("dependency entries must be (name, digest) tuples")
            name, digest = entry
            if not isinstance(name, str) or not name.strip():
                raise ValueError("dependency names must be non-empty")
            _check_digest(digest)
            names.append(name)
        if len(set(names)) != len(names):
            raise ValueError("duplicate dependency name")


@dataclass(frozen=True)
class EvidenceSnapshot:
    """Immutable local record; the digest is identity, not authentication."""

    scenario_digest: str
    result_json: str
    result_digest: str
    context: EvaluationContext
    captured_at: int

    @classmethod
    def capture(cls, scenario: Scenario, result: RunResult,
                context: EvaluationContext, *, captured_at: int):
        _check_time(captured_at)
        if not isinstance(context, EvaluationContext):
            raise ValueError("explicit evaluation context required")
        if (scenario.scenario_id, scenario.transaction_id, scenario.claim) != (
                result.scenario_id, result.transaction_id, result.claim):
            raise ValueError("result does not match scenario identity")
        if result.scenario_digest != scenario.digest():
            raise ValueError("result does not match full scenario digest")
        _check_time(result.observed_at)
        if result.observed_at > captured_at:
            raise ValueError("capture precedes observation")
        if scenario.mutation is not None or result.mutation_proof != {
                "mutation": None, "gate_weakened": False}:
            raise ValueError("weakened-gate evidence cannot be retained for reuse")
        if not result.observations or any(
                o.evidence_class != EvidenceClass.SYNTHETIC
                for o in result.observations):
            raise ValueError("only explicit synthetic observations are supported")
        boundaries = summarize(result.observations)
        blocked = [scenario.waiting_on_release] if scenario.waiting_on_release else []
        if (result.boundary_outcomes != boundaries or result.blocked != blocked
                or result.status != status(boundaries, blocked)):
            raise ValueError("result conflicts with retained observations")
        # Local retention is deliberately separate from public serialization.
        data = result.to_dict()
        data.update(scenario_digest=result.scenario_digest, observed_at=result.observed_at)
        encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return cls(result.scenario_digest, encoded, _digest(data), context, captured_at)


@dataclass(frozen=True)
class Reappraisal:
    historical_status: str
    applicability: str
    reasons: tuple[str, ...]
    evidence_class: str = "synthetic"


def appraise(snapshot: EvidenceSnapshot, scenario: Scenario,
             current: EvaluationContext, *, evaluated_at: int,
             max_age_seconds: int) -> Reappraisal:
    """Compare a retained fixture against current verifier inputs.

    The caller selects a freshness budget on EVERY appraisal. Exactly at the
    deadline the evidence is expired. This is evidence-age checking, not a
    credential-expiry implementation. A changed context requires a fresh run;
    it does not imply that the new workload is incompatible or unauthorized.
    """
    _check_time(evaluated_at)
    _check_time(snapshot.captured_at)
    if type(max_age_seconds) is not int or max_age_seconds <= 0:
        raise ValueError("a positive verifier-selected freshness budget is required")
    if not isinstance(current, EvaluationContext):
        raise ValueError("explicit current evaluation context required")
    data = json.loads(snapshot.result_json)
    if _digest(data) != snapshot.result_digest:
        raise ValueError("snapshot content identity mismatch")
    _check_time(data["observed_at"])
    if data["observed_at"] > snapshot.captured_at:
        raise ValueError("capture precedes observation")
    if data["scenario_digest"] != snapshot.scenario_digest:
        raise ValueError("snapshot scenario identity mismatch")
    reasons = []
    if snapshot.scenario_digest != _digest(asdict(scenario)):
        reasons.append("scenario_changed")
    if snapshot.context.policy_digest != current.policy_digest:
        reasons.append("policy_changed")
    if snapshot.context.trust_digest != current.trust_digest:
        reasons.append("trust_changed")
    if dict(snapshot.context.dependencies) != dict(current.dependencies):
        reasons.append("dependencies_changed")
    if evaluated_at < snapshot.captured_at:
        reasons.append("evaluation_precedes_capture")
    elif evaluated_at - data["observed_at"] >= max_age_seconds:
        reasons.append("evidence_expired")
    if data["status"] != "passed":
        reasons.append("historical_result_not_passed")
    return Reappraisal(data["status"],
                       "reassessment_required" if reasons else "applicable",
                       tuple(reasons))
