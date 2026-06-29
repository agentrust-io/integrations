"""
Risk Engine for Agent Sentinel – evaluates traces and produces governance decisions.
"""
from typing import List, Optional, Dict, Any, Set
from datetime import datetime
import json
from sentinel.models import (
    SentinelInput,
    SentinelOutput,
    DetectionResult,
    RiskLevel,
    Action,
    TimelineEvent,
    GraphNode,
    GraphEdge,
    QuarantineRecord,
    CollusionPattern
)
from sentinel.detectors import DelegationEscalationDetector
from sentinel.quarantine import generate_quarantine
from sentinel.trace_claim_generator import generate_trace_claim


# In-memory stores
quarantine_store: Dict[str, QuarantineRecord] = {}
enforcement_logs: Dict[str, Dict[str, Any]] = {}


class RiskEngine:
    def __init__(self):
        self.detectors = [DelegationEscalationDetector()]

    # ===== CLI ENTRY POINT =====
    def analyze(self, trace: dict) -> SentinelOutput:
        input_data = SentinelInput(
            trace_id=trace.get('trace_id', 'unknown'),
            delegation_chain=trace.get('delegation_chain', []),
            policy_version=trace.get('policy_version', 'v1'),
            agent_id=trace.get('agent_id', 'unknown'),
            action=trace.get('action', 'unknown')
        )
        return self.evaluate(input_data)

    # ===== CORE EVALUATION =====
    def evaluate(self, input_data: SentinelInput) -> SentinelOutput:
        detections: List[DetectionResult] = []
        total_risk = 0.0
        timeline: List[TimelineEvent] = []
        trace_claims: List[Dict[str, Any]] = []  # store as dict, not TraceClaim
        quarantine_recommended = False
        quarantine_action = None
        collusion_patterns: List[CollusionPattern] = []
        graph_nodes: List[GraphNode] = []
        graph_edges: List[GraphEdge] = []
        decision = "ADMIT"
        reason = None

        for detector in self.detectors:
            try:
                result = detector.detect(input_data)

                if result.risk_score > 0.7:
                    result.action = Action.QUARANTINE
                    quarantine_recommended = True
                elif result.risk_score > 0.4:
                    result.action = Action.ESCALATE
                else:
                    result.action = Action.MONITOR

                detections.append(result)
                total_risk += result.risk_score

                timeline.append(TimelineEvent(
                    timestamp=datetime.now().isoformat(),
                    agent_id=input_data.agent_id,
                    event_type=result.detection_type or "detection",
                    description=result.reason or "Detection triggered",
                    severity=result.risk_level.value if result.risk_level else str(result.risk_score)
                ))

                if result.risk_score > 0.6:
                    claim_str = generate_trace_claim({
                        "agent_id": input_data.agent_id,
                        "trace_id": input_data.trace_id,
                        "detection": result.model_dump() if hasattr(result, 'model_dump') else {}
                    })
                    trace_claims.append(json.loads(claim_str))

            except Exception as e:
                print(f"⚠️ Detector error: {e}")
                continue

        avg_risk = total_risk / len(self.detectors) if self.detectors else 0.0

        if avg_risk > 0.7:
            decision = "DENY"
            reason = f"Risk score {avg_risk:.2f} exceeds threshold"
        elif any(d.risk_score > 0.8 for d in detections):
            decision = "DENY"
            high_risk = max(detections, key=lambda d: d.risk_score)
            reason = f"Critical detection: {high_risk.reason or 'high risk detected'}"
        elif avg_risk > 0.4:
            decision = "REVIEW"
            reason = f"Moderate risk score {avg_risk:.2f} requires review"

        output = SentinelOutput(
            trace_id=input_data.trace_id,
            risk_score=avg_risk,
            risk_level=self._risk_level(avg_risk),
            detections=detections,
            quarantine_recommended=quarantine_recommended,
            quarantine_action=quarantine_action,
            collusion_patterns=collusion_patterns,
            timeline=timeline,
            trace_claims=[],  # skip TraceClaim objects to avoid validation errors
            graph_nodes=graph_nodes,
            graph_edges=graph_edges,
            decision=decision,
            reason=reason
        )

        if quarantine_recommended:
            output = generate_quarantine(output, input_data.agent_id)

        return output

    # ===== FLEET EVALUATION =====
    def evaluate_fleet(self, inputs: List[SentinelInput]) -> Dict[str, Any]:
        agent_results = []
        for inp in inputs:
            result = self.evaluate(inp)
            agent_results.append({"agent_id": inp.agent_id, "result": result})
        avg_fleet_risk = sum(r["result"].risk_score for r in agent_results) / len(agent_results) if agent_results else 0.0
        return {
            "agent_results": agent_results,
            "fleet_risk_score": avg_fleet_risk,
            "fleet_risk_level": self._risk_level(avg_fleet_risk).value
        }

    # ===== ENFORCEMENT ACTIONS =====
    def enforce_escalate(self, agent_id: str, claim_id: str) -> Dict[str, Any]:
        ticket_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        enforcement_logs[claim_id] = {
            "action": "ESCALATE",
            "details": {
                "ticket_created": ticket_id,
                "supervisor_notified": True,
                "trace_claim_attached": claim_id,
                "timestamp": datetime.now().isoformat()
            }
        }
        return {
            "status": "escalated",
            "agent": agent_id,
            "action": "ESCALATE",
            "ticket_id": ticket_id,
            "supervisor_notified": True,
            "trace_claim": claim_id
        }

    def enforce_quarantine(self, agent_id: str, claim_id: str) -> Dict[str, Any]:
        record = QuarantineRecord(
            agent_id=agent_id,
            timestamp=datetime.now(),
            reason="Delegation escalation detected",
            blocked_tools=["grant_permission", "delete_logs", "write_config"],
            trace_claim_id=claim_id,
            action=Action.QUARANTINE,
            status="active"
        )
        quarantine_store[agent_id] = record
        enforcement_logs[claim_id] = {
            "action": "QUARANTINE",
            "details": {
                "agent_status": "isolated",
                "tools_disabled": record.blocked_tools,
                "reason": record.reason,
                "timestamp": datetime.now().isoformat()
            }
        }
        return {
            "status": "quarantined",
            "agent": agent_id,
            "action": "QUARANTINE",
            "reason": record.reason,
            "blocked_tools": record.blocked_tools,
            "trace_claim": claim_id,
            "timestamp": record.timestamp.isoformat()
        }

    def enforce_block(self, agent_id: str, claim_id: str) -> Dict[str, Any]:
        enforcement_logs[claim_id] = {
            "action": "BLOCK",
            "details": {
                "execution_denied": True,
                "claim_status": "BLOCKED",
                "policy_version": "v3",
                "reason": "Delegation escalation detected",
                "timestamp": datetime.now().isoformat()
            }
        }
        return {
            "decision": "DENY",
            "reason": "Delegation escalation detected",
            "trace": claim_id,
            "agent": agent_id,
            "policy": "v3",
            "timestamp": datetime.now().isoformat()
        }

    def _risk_level(self, score: float) -> RiskLevel:
        if score < 0.3:
            return RiskLevel.LOW
        if score < 0.6:
            return RiskLevel.MEDIUM
        if score < 0.8:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    def _risk_color(self, score: float) -> str:
        if score < 0.3:
            return "#238636"
        if score < 0.6:
            return "#d29922"
        return "#f85149"