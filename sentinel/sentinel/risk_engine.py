from sentinel.models import (
    SentinelInput, SentinelOutput, DetectionResult, RiskLevel, Action,
    TimelineEvent, TraceClaim, GraphNode, GraphEdge, QuarantineRecord
)
from sentinel.detectors import (
    DelegationEscalationDetector,
    ToolDriftDetector,
    PolicyAvoidanceDetector,
    IdentityDriftDetector,
    CollusionDetector
)
from sentinel.quarantine import generate_quarantine
from sentinel.trace_claim_generator import generate_trace_claim
from datetime import datetime

# In-memory store for quarantine records (for demo)
quarantine_store = {}
enforcement_logs = {}  # claim_id -> log

class RiskEngine:
    def __init__(self):
        self.detectors = [
            DelegationEscalationDetector(),
            ToolDriftDetector(),
            PolicyAvoidanceDetector(),
            IdentityDriftDetector(),
            CollusionDetector()
        ]

    def evaluate(self, input_data: SentinelInput) -> SentinelOutput:
        detections: list[DetectionResult] = []
        total_risk = 0.0
        timeline: list[TimelineEvent] = []
        trace_claims: list[TraceClaim] = []
        decision = "ADMIT"
        reason = None

        for detector in self.detectors:
            result = detector.detect(input_data)
            if result.risk_score > 0.7:
                result.action = Action.QUARANTINE
            elif result.risk_score > 0.4:
                result.action = Action.ESCALATE
            else:
                result.action = Action.MONITOR

            detections.append(result)
            total_risk += result.risk_score

            timeline.append(TimelineEvent(
                timestamp=result.timestamp,
                agent_id=input_data.agent_id,
                event_type=result.detection_type.value,
                description=result.reason,
                severity=result.risk_level.value
            ))

            if result.risk_score > 0.6:
                claim = generate_trace_claim(input_data.agent_id, result)
                trace_claims.append(claim)

        avg_risk = total_risk / len(self.detectors) if self.detectors else 0.0

        if avg_risk > 0.7:
            decision = "DENY"
            reason = f"Risk score {avg_risk:.2f} exceeds threshold"
        elif any(d.risk_score > 0.8 for d in detections):
            decision = "DENY"
            reason = f"Critical detection: {max(detections, key=lambda d: d.risk_score).detection_type}"
        # else ADMIT

        output = SentinelOutput(
            risk_score=avg_risk,
            risk_level=self._risk_level(avg_risk),
            detections=detections,
            quarantine_recommended=False,
            quarantine_action=None,
            collusion_patterns=[],
            timeline=timeline,
            trace_claims=trace_claims,
            graph_nodes=[],
            graph_edges=[],
            decision=decision,
            reason=reason
        )

        if avg_risk > 0.7:
            output = generate_quarantine(output, input_data.agent_id)

        return output

    def evaluate_fleet(self, inputs: list[SentinelInput]) -> dict:
        agent_results = []
        all_timeline: list[TimelineEvent] = []
        all_trace_claims: list[TraceClaim] = []
        all_agents = set()
        all_delegations = []

        for inp in inputs:
            result = self.evaluate(inp)
            agent_results.append({
                "agent_id": inp.agent_id,
                "result": result
            })
            all_timeline.extend(result.timeline)
            all_trace_claims.extend(result.trace_claims)
            all_agents.add(inp.agent_id)
            chain = inp.delegation_chain
            for node in chain:
                all_agents.add(node)
            for i in range(len(chain) - 1):
                all_delegations.append((chain[i], chain[i+1]))

        all_timeline.sort(key=lambda e: e.timestamp)

        # Build graph
        nodes = []
        for agent in all_agents:
            risk = next((r["result"].risk_score for r in agent_results if r["agent_id"] == agent), 0.0)
            color = "#238636" if risk < 0.3 else "#d29922" if risk < 0.6 else "#f85149"
            shape = "diamond" if agent == "root" else "circle"
            nodes.append(GraphNode(id=agent, label=agent, risk=risk, color=color, shape=shape))

        edges = []
        for frm, to in set(all_delegations):
            risk = next((r["result"].risk_score for r in agent_results if r["agent_id"] == to), 0.0)
            color = "#8b949e" if risk < 0.6 else "#f85149"
            edges.append(GraphEdge(
                from_=frm,
                to=to,
                label=f"risk: {risk:.2f}",
                color=color,
                dashes=risk > 0.6
            ))

        collusion_detector = CollusionDetector()
        collusion_patterns = collusion_detector.detect_collusion_patterns(inputs)
        for pat in collusion_patterns:
            if pat.risk_score > 0.6:
                for i in range(len(pat.agents) - 1):
                    edges.append(GraphEdge(
                        from_=pat.agents[i],
                        to=pat.agents[i+1],
                        label="collusion",
                        color="#f85149",
                        dashes=True,
                        width=2
                    ))

        avg_fleet_risk = sum(r["result"].risk_score for r in agent_results) / len(agent_results) if agent_results else 0.0

        return {
            "agent_results": agent_results,
            "collusion_patterns": collusion_patterns,
            "fleet_risk_score": avg_fleet_risk,
            "fleet_risk_level": self._risk_level(avg_fleet_risk).value,
            "timeline": all_timeline,
            "trace_claims": all_trace_claims,
            "graph_nodes": nodes,
            "graph_edges": edges
        }

    def enforce_escalate(self, agent_id: str, claim_id: str) -> dict:
        """Escalate: create ticket, notify supervisor."""
        enforcement_logs[claim_id] = {
            "action": "ESCALATE",
            "details": {
                "ticket_created": f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "supervisor_notified": True,
                "trace_claim_attached": claim_id,
                "timestamp": datetime.now().isoformat()
            }
        }
        return {
            "status": "escalated",
            "agent": agent_id,
            "action": "ESCALATE",
            "ticket_id": f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "supervisor_notified": True,
            "trace_claim": claim_id
        }

    def enforce_quarantine(self, agent_id: str, claim_id: str) -> dict:
        """Quarantine: isolate agent, disable tools."""
        record = QuarantineRecord(
            agent_id=agent_id,
            timestamp=datetime.now(),
            reason="Delegation escalation and tool drift detected",
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

    def enforce_block(self, agent_id: str, claim_id: str) -> dict:
        """Block: deny execution."""
        enforcement_logs[claim_id] = {
            "action": "BLOCK",
            "details": {
                "execution_denied": True,
                "claim_status": "BLOCKED",
                "policy_version": "v3",  # simulate policy change
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