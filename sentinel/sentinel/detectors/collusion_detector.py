from src.models import SentinelInput, DetectionResult, DetectionType, RiskLevel, CollusionPattern
from src.detectors.base import BaseDetector
from typing import List
class CollusionDetector(BaseDetector):
    """
    Detects multi-agent collusion patterns:
    - Delegation chains with unusual depth
    - Agents sharing suspicious tool calls
    - Circular delegations
    """

    def name(self) -> str:
        return "collusion"

    def detect(self, input_data: SentinelInput) -> DetectionResult:
        risk_score = 0.0
        reason = "No collusion detected"
        evidence = {}

        # Simulate collusion detection based on delegation chain and fleet data
        if input_data.agent_fleet and len(input_data.agent_fleet) > 2:
            # Check if delegation chain is long
            if len(input_data.delegation_chain) > 2:
                risk_score = 0.75
                reason = f"Delegation chain of length {len(input_data.delegation_chain)} in fleet of {len(input_data.agent_fleet)} agents"
                evidence = {
                    "delegation_depth": len(input_data.delegation_chain),
                    "fleet_size": len(input_data.agent_fleet),
                    "pattern": "delegation_chain_collusion"
                }
            # Check for circular delegation (simplified: if agent appears twice in delegation chain)
            if len(set(input_data.delegation_chain)) < len(input_data.delegation_chain):
                risk_score = max(risk_score, 0.85)
                reason = "Circular delegation detected"
                evidence["circular"] = True

        return DetectionResult(
            detection_type=DetectionType.COLLUSION,
            risk_score=risk_score,
            risk_level=self._risk_level(risk_score),
            reason=reason,
            evidence=evidence
        )

    def detect_collusion_patterns(self, inputs: List[SentinelInput]) -> List[CollusionPattern]:
        patterns = []
        # Simple pattern: all agents share the same high-risk tool
        all_tools = []
        for inp in inputs:
            all_tools.extend([t.get("name", "") for t in inp.tool_calls])
        from collections import Counter
        tool_counts = Counter(all_tools)
        for tool, count in tool_counts.items():
            if count > 2 and tool in ["grant_permission", "delete_logs", "write_config"]:
                patterns.append(CollusionPattern(
                    pattern_type="shared_high_risk_tool",
                    agents=[inp.agent_id for inp in inputs],
                    risk_score=0.7,
                    description=f"{count} agents used tool '{tool}'"
                ))
        return patterns

    def _risk_level(self, score: float) -> RiskLevel:
        if score < 0.3: return RiskLevel.LOW
        if score < 0.6: return RiskLevel.MEDIUM
        if score < 0.8: return RiskLevel.HIGH
        return RiskLevel.CRITICAL
if __name__ == "__main__":
    # Quick test
    from ..models import DetectionResult, RiskLevel
    print("CollusionDetector loaded successfully.")