from pydantic import BaseModel
from typing import List, Optional, Dict, Any
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


class DetectionResult(BaseModel):
    detection_type: Optional[str] = None
    risk_score: float
    risk_level: Optional[RiskLevel] = None
    reason: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None
    action: Optional[Action] = None
    detected: bool = False


class SentinelInput(BaseModel):
    trace_id: str
    delegation_chain: List[str]
    policy_version: str
    agent_id: str
    action: str


class TimelineEvent(BaseModel):
    timestamp: str
    agent_id: str
    event_type: str
    description: Optional[str] = None
    severity: Optional[str] = None


class GraphNode(BaseModel):
    id: str
    label: str
    risk: float
    color: str
    shape: str = "circle"


class GraphEdge(BaseModel):
    from_: str
    to: str
    label: Optional[str] = None
    color: str = "#8b949e"
    dashes: bool = False
    width: int = 1


class CollusionPattern(BaseModel):
    agents: List[str]
    risk_score: float
    pattern_type: str


class QuarantineRecord(BaseModel):
    agent_id: str
    timestamp: datetime
    reason: str
    blocked_tools: List[str]
    trace_claim_id: str
    action: Action
    status: str = "active"


class SentinelOutput(BaseModel):
    trace_id: str
    risk_score: float
    risk_level: RiskLevel
    detections: List[DetectionResult]
    quarantine_recommended: bool = False
    quarantine_action: Optional[Dict[str, Any]] = None
    collusion_patterns: List[CollusionPattern] = []
    timeline: List[TimelineEvent] = []
    trace_claims: List[Dict[str, Any]] = []
    graph_nodes: List[GraphNode] = []
    graph_edges: List[GraphEdge] = []
    decision: str = "ADMIT"
    reason: Optional[str] = None
