from fastapi import FastAPI
from sentinel.schemas import SentinelInput, DetectionResult
from sentinel.detectors.delegation_escalation import DelegationEscalationDetector
from sentinel.trace_claim_generator import TraceClaimGenerator, generate_trace_claim

app = FastAPI(title="Agent Sentinel", version="1.0.0")
detector = DelegationEscalationDetector()
claim_gen = TraceClaimGenerator()


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "sentinel", "version": "1.0.0"}


@app.post("/detect", response_model=DetectionResult)
async def detect(input_data: SentinelInput):
    return detector.detect(input_data)


@app.post("/enforce")
async def enforce(input_data: SentinelInput):
    detection = detector.detect(input_data)
    if detection.detected:
        claim = claim_gen.generate_claim({
            "event_id": f"enforce-{input_data.trace_id}",
            "event_type": "ENFORCEMENT",
            "detection": detection.model_dump(),
            "input": input_data.model_dump()
        })
        return {
            "status": "DENY",
            "reason": detection.reason or "Detection triggered enforcement.",
            "claim": claim.to_json()
        }
    return {
        "status": "ADMIT",
        "reason": "No violation detected.",
        "claim": None
    }