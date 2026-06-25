from pydantic import BaseModel, ConfigDict
from typing import List, Optional


class SentinelInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trace_id: str
    delegation_chain: List[str]
    policy_version: str
    agent_id: str
    action: str


class DetectionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    detected: bool
    risk_score: float
    reason: Optional[str] = None