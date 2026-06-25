import copy
from typing import List
from src.models import SentinelInput, ReplayResult
from src.risk_engine import RiskEngine

class ReplayEngine:
    def __init__(self):
        self.engine = RiskEngine()

    def replay(self, trace: SentinelInput, policy_versions: List[str]) -> List[ReplayResult]:
        results = []
        original_policy = trace.policy_version

        for version in policy_versions:
            trace_copy = copy.deepcopy(trace)
            trace_copy.policy_version = version

            output = self.engine.evaluate(trace_copy)

            decision = "ADMIT"
            reason = "All checks passed"

            if version == "v3" and len(trace_copy.delegation_chain) > 2:
                decision = "DENY"
                reason = f"Policy v3: Delegation chain length {len(trace_copy.delegation_chain)} exceeds allowed limit (2)"
            elif version == "v3" and any(d.risk_score > 0.7 for d in output.detections):
                decision = "DENY"
                reason = f"Policy v3: Risk score {output.risk_score:.2f} exceeds threshold"
            elif version == "v2" and len(trace_copy.delegation_chain) > 3:
                decision = "DENY"
                reason = f"Policy v2: Delegation chain length {len(trace_copy.delegation_chain)} exceeds limit (3)"
            elif output.risk_score > 0.7:
                decision = "DENY"
                reason = f"Risk score {output.risk_score:.2f} exceeds threshold (policy {version})"
            elif any(d.risk_score > 0.8 for d in output.detections):
                decision = "DENY"
                reason = f"Critical detection: {max(output.detections, key=lambda d: d.risk_score).detection_type}"

            if version in ["v1", "v2"] and len(trace_copy.delegation_chain) <= 2 and output.risk_score < 0.5:
                decision = "ADMIT"
                reason = "All governance checks passed"

            detections_dict = [d.model_dump(mode='json') for d in output.detections]

            results.append(ReplayResult(
                policy_version=version,
                risk_score=output.risk_score,
                risk_level=output.risk_level.value,
                decision=decision,
                reason=reason,
                detections=detections_dict
            ))

        trace.policy_version = original_policy
        return results