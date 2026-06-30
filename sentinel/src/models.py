from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Action(str, Enum):
    MONITOR = "monitor"
    ESCALATE = "escalate"
    QUARANTINE = "quarantine"
    BLOCK = "block"

class DetectionType(str, Enum):
    DELEGATION_ESCALATION = "delegation_escalation"
    TOOL_DRIFT = "tool_drift"
    POLICY_AVOIDANCE = "policy_avoidance"
    IDENTITY_DRIFT = "identity_drift"
    COLLUSION = "collusion"

class TimelineEvent(BaseModel):
    timestamp: datetime
    agent_id: str
    event_type: str
    description: str
    severity: Optional[str] = None

class TraceClaim(BaseModel):
    claim_id: str
    agent_id: str
    detection_type: DetectionType
    risk_score: float
    evidence: Dict[str, Any]
    timestamp: datetime
    jwt: Optional[str] = None
    json_export: Optional[Dict[str, Any]] = None
    enforcement_status: Optional[str] = "pending"
    decision: Optional[str] = None
    reason: Optional[str] = None

class QuarantineRecord(BaseModel):
    agent_id: str
    timestamp: datetime
    reason: str
    blocked_tools: List[str]
    trace_claim_id: str
    action: Action = Action.QUARANTINE
    status: str = "active"

class Ticket(BaseModel):
    ticket_id: str
    agent_id: str
    claim_id: str
    created_at: datetime
    status: str = "open"
    assignee: Optional[str] = None

class Receipt(BaseModel):
    receipt_id: str
    executed_by: str = "sentinel"
    timestamp: datetime
    result: str  # "SUCCESS" or "FAILED"

class EnforcementResult(BaseModel):
    action: Action
    agent_id: str
    claim_id: str
    timestamp: datetime
    details: Dict[str, Any]
    status: str
    receipt: Optional[Receipt] = None

class ReplayResult(BaseModel):
    policy_version: str
    risk_score: float
    risk_level: str
    decision: str
    reason: str
    detections: List[Dict[str, Any]] = []

class QuarantineAction(BaseModel):
    agent_id: str
    reason: str
    blocked_tools: List[str]
    fallback: str
    risk_score: float
    action: Action = Action.QUARANTINE

class DetectionResult(BaseModel):
    detection_type: DetectionType
    risk_score: float
    risk_level: RiskLevel
    reason: str
    evidence: Dict[str, Any]
    timestamp: datetime = datetime.now()
    action: Action = Action.MONITOR

class CollusionPattern(BaseModel):
    pattern_type: str
    agents: List[str]
    risk_score: float
    description: str

class GraphNode(BaseModel):
    id: str
    label: str
    risk: float
    shape: str = "circle"
    color: str = "#238636"

class GraphEdge(BaseModel):
    from_: str = Field(..., alias="from")
    to: str
    label: str
    color: str = "#8b949e"
    dashes: bool = False
    width: int = 1

    class Config:
        validate_by_name = True

class SentinelInput(BaseModel):
    trace_id: str = "unknown"
    agent_id: str = "unknown"
    session_id: str = "unknown"
    policy_version: str = "v1"
    delegation_chain: List[str] = []
    tool_calls: List[Dict[str, Any]] = []
    observer_identity_hash: str = ""
    reference_frame_hash: str = ""
    timestamp: str = ""
    delegation_source: Optional[str] = None
    delegation_target: Optional[str] = None
    agent_fleet: Optional[List[str]] = None

class SentinelOutput(BaseModel):
    risk_score: float
    risk_level: RiskLevel
    detections: List[DetectionResult]
    quarantine_recommended: bool
    quarantine_action: Optional[QuarantineAction] = None
    collusion_patterns: List[CollusionPattern] = []
    timeline: List[TimelineEvent] = []
    trace_claims: List[TraceClaim] = []
    graph_nodes: List[GraphNode] = []
    graph_edges: List[GraphEdge] = []
    decision: str = "ADMIT"
    reason: Optional[str] = None

class IncidentReport(BaseModel):
    incident_id: str
    agent_id: str
    detection_type: str
    risk_score: float
    risk_level: str
    trace_claim_id: str
    enforcement_action: str
    enforcement_status: str
    replay_results: List[ReplayResult]
    final_recommendation: str
    timestamp: datetime = datetime.now()
    evidence_export: Dict[str, Any]
    receipt: Optional[Receipt] = None
    signature: Optional[str] = None
    signature_status: str = "unsigned"  # "signed" or "unsigned" (fail closed)
    claim_hash: Optional[str] = None
    incident_hash: Optional[str] = None