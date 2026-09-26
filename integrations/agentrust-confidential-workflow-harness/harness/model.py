from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any

class Outcome(str, Enum):
    ESTABLISHED = "established"
    CONTRADICTED = "contradicted"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"

class EvidenceClass(str, Enum):
    SYNTHETIC = "synthetic"
    REPLAYED = "replayed"
    HOSTED_LIVE = "hosted/live"
    HARDWARE = "hardware"

class Boundary(str, Enum):
    AUTHORIZATION = "authorization"
    DELIVERY = "delivery"
    RECEIPT = "receipt"
    ADMISSION = "installation/admission"
    EXECUTION = "execution"
    RESPONSE_VERIFICATION = "response_verification"
    RELEASE = "release/disclosure"

@dataclass(frozen=True)
class Observation:
    boundary: Boundary
    outcome: Outcome
    source: str
    evidence_class: EvidenceClass = EvidenceClass.SYNTHETIC
    lineage: str = "main"
    caused_by: str | None = None
    detail: str | None = None

@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    transaction_id: str
    claim: str
    protected_asset: str
    workload_principal: str
    delegated_peer: str
    permitted_recipients: tuple[str, ...]
    forbidden_recipients: tuple[str, ...]
    policy_version: str
    trust_input_digest: str
    mutation: str | None = None
    waiting_on_release: str | None = None
    inputs: dict[str, Any] = field(default_factory=dict)

@dataclass
class RunResult:
    scenario_id: str
    transaction_id: str
    claim: str
    status: str
    observations: list[Observation]
    boundary_outcomes: dict[str, str]
    mutation_proof: dict[str, Any]
    blocked: list[str]
    limitations: list[str]
    package_versions: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["observations"] = [
            {
                **asdict(o),
                "boundary": o.boundary.value,
                "outcome": o.outcome.value,
                "evidence_class": o.evidence_class.value,
            }
            for o in self.observations
        ]
        return d
