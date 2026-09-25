from __future__ import annotations
from .model import Boundary, Observation, Outcome

def summarize(observations: list[Observation]) -> dict[str, str]:
    """Summarize the main lineage without flattening alternate branches."""
    seen_sources = set()
    seen_boundaries = set()
    for observation in observations:
        source = (observation.lineage, observation.source)
        boundary = (observation.lineage, observation.boundary)
        if not observation.source or not observation.lineage:
            raise ValueError("observation source and lineage must be non-empty")
        if source in seen_sources:
            raise ValueError("duplicate observation source within lineage")
        if boundary in seen_boundaries:
            raise ValueError("duplicate boundary outcome within lineage")
        if (observation.caused_by is not None
                and (observation.lineage, observation.caused_by) not in seen_sources):
            raise ValueError("causal parent must name an earlier observation in the same lineage")
        seen_sources.add(source)
        seen_boundaries.add(boundary)
    # All seven fixed-workflow boundaries require established evidence.
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
    if any(boundaries.get(b.value) != Outcome.ESTABLISHED.value for b in Boundary):
        return "unknown"
    return "passed"
