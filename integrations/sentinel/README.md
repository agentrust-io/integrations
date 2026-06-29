# Agent Sentinel

Runtime behavioral anomaly detection, collusion detection, and quarantine for agent fleets.

## Features
- **5 detectors**: delegation escalation, tool drift, policy avoidance, identity drift, collusion
- **Risk aggregation** with quarantine threshold (0.7)
- **Quarantine enforcement**: blocks tools, requires human review
- **Multi-agent collusion detection**: delegation chains, shared tools
- **CLI + FastAPI dashboard**
- **TRACE-native** (consumes TRACE claims)

## Usage


```bash
pip install -r requirements.txt
python -m src.cli claim.jwt --output report.json

Integration with AgentTrust

Sentinel consumes TRACE claims and produces risk scores that can be used by AGT, cMCP, and other AgentTrust components.

Dashboard

bash
uvicorn src.server:app --host 0.0.0.0 --port 8001 --reload
Open http://localhost:8001

Integration with AgentTrust

Sentinel fills the documented gap: "no dedicated behavioral anomaly detection or agent quarantine tooling."

License

MIT
---

## 🚀 How to build and run

```bash
cd /Users/akhileshwarik/agentrust-io/integrations/sentinel
pip install -r requirements.txt
python -m src.cli ../decisionassure/claim.jwt --output report.json