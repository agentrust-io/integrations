from pydantic import BaseModel
from typing import List, Optional


class SentinelInput(BaseModel):
    trace_id: str
    delegation_chain: List[str]
    policy_version: str
    agent_id: str
    action: str
    # additional fields as needed


class DetectionResult(BaseModel):
    detected: bool
    risk_score: float
    reason: Optional[str] = None