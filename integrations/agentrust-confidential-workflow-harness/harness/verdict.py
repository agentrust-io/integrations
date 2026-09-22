from __future__ import annotations
from .model import Boundary, Observation, Outcome

def summarize(observations: list[Observation]) -> dict[str, str]:
    """Summarize the main lineage without flattening alternate branches."""
    # Missing observations are unknown; not_applicable requires explicit evidence.
    out = {b.value: Outcome.UNAVAILABLE.value for b in Boundary}
    for observation in observations:
        if observation.lineage == "main":
            out[observation.boundary.value] = observation.outcome.value
    return out

def status(boundaries: dict[str, str], blocked: list[str]) -> str:
    if blocked:
        return "incomplete"
    if any(v == Outcome.CONTRADICTED.value for v in boundaries.values()):
        return "refused"
    if any(v == Outcome.UNAVAILABLE.value for v in boundaries.values()):
        return "unknown"
    return "passed"
