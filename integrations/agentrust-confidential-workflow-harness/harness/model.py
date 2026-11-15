from __future__ import annotations
from dataclasses import dataclass, field, asdict
from copy import deepcopy
import hashlib
import json
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

    def digest(self) -> str:
        raw = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"),
                         allow_nan=False).encode("utf-8")
        return "sha256:" + hashlib.sha256(raw).hexdigest()

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

    scenario_digest: str | None = None
    observed_at: int | None = None

    def to_dict(self) -> dict[str, Any]:
        # Explicit public projection: new internal fields are private by default.
        # Values in declared public fields still require caller-side classification.
        return deepcopy({
            "scenario_id": self.scenario_id,
            "transaction_id": self.transaction_id,
            "claim": self.claim,
            "status": self.status,
            "observations": [
                {
                    "boundary": o.boundary.value,
                    "outcome": o.outcome.value,
                    "source": o.source,
                    "evidence_class": o.evidence_class.value,
                    "lineage": o.lineage,
                    "caused_by": o.caused_by,
                    "detail": o.detail,
                }
                for o in self.observations
            ],
            "boundary_outcomes": self.boundary_outcomes,
            "mutation_proof": self.mutation_proof,
            "blocked": self.blocked,
            "limitations": self.limitations,
            "package_versions": self.package_versions,
        })
