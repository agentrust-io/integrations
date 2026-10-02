[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![cMCP](https://img.shields.io/badge/Uses-cMCP_Runtime-7c3aed)](https://github.com/agentrust-io/cmcp)
[![Agent Manifest](https://img.shields.io/badge/Uses-Agent_Manifest-0ea5e9)](https://github.com/agentrust-io/agent-manifest)
[![cA2A](https://img.shields.io/badge/Uses-cA2A-7c3aed)](https://github.com/agentrust-io/ca2a)
[![Discord](https://dcbadge.limes.pink/api/server/grgzFEHgkj?style=flat)](https://discord.gg/grgzFEHgkj)

# agentrust-io Examples

Community updates and contributor highlights: [AgenTrust on LinkedIn](https://www.linkedin.com/company/agentrust-io/).

End-to-end integration examples showing cMCP, Agent Manifest, and TRACE working together across deployment scenarios. Each example is self-contained and runnable on a fresh cloud VM. Running them shows how the projects compose: cMCP enforces policy at the tool call boundary, Agent Manifest carries the identity and capability declaration, cA2A attenuates authority at the agent-to-agent boundary, and TRACE emits a signed Trust Record for every tool invocation so you can see what the full audit trail looks like in practice.

Project support is recognized in [SPONSORS.md](SPONSORS.md). Sponsorship is
separate from example authorship, fixture identities, partner provenance,
adoption, and project governance.

## Examples

| Example | What it shows | Platform | Compliance |
|---|---|---|---|
| `agentic-commerce-accountability/` | Delegated spend authority linked to checkout, policy, runtime evidence and receipt, with offline tamper detection | Software-only (offline) | Accountability, least authority |
| `ca2a-delegation/` | Agent-to-agent delegation with cA2A: attenuated credit-workflow chain, offline verification, and a rejected scope escalation | Software-only (offline) | Separation of duties, least authority |
| `embodied-action-receipts/` | Fixture-style offline verification for embodied action receipts: accepted chain, missing receipt, signature mismatch and valid controller rejection | Software-only fixtures | TRACE action-receipt evidence boundary |
| `financial-services/` | Corporate credit risk agent: six-step assessment with CDD, exposure and IFRS 9 guardrails on the write | SEV-SNP / TDX | EU AI Act Art. 9/12, CRR Art. 395, EBA/GL/2020/06, EU AML, DORA Art. 9 |
| `healthcare/` | Clinical agent on a coherent ICD-10 patient: drug-interaction check feeds EU AI Act Art. 14 HITL and contraindication denies | SEV-SNP / TDX | EU AI Act Art. 14, HIPAA |
| `industrial-embodied-ai/` | Material-movement agent with cMCP authorization, an independent safety-controller boundary and offline-verifiable closed-session evidence | TEE / software-only development mode | OT security and industrial robot safety references |
| `multi-tenant-saas/` | HR SaaS with an EU tenant (enforcing GDPR residency/Art. 9) and a US tenant (advisory) on one catalog | TDX | GDPR Art. 6/9/44, customer DPA |
| `startup-tpm/` | 15-minute quickstart on any cloud VM with Trusted Launch | TPM 2.0 | Development / staging |

Most examples are fully runnable with no external dependencies: they ship a mock upstream MCP server, an agent script, an attested tool catalog, and a Cedar policy bundle, and end by printing the signed TRACE Trust Record for the session. The `trace-output/` files are captured from real runs. The `ca2a-delegation/` and `embodied-action-receipts/` examples are offline verifiers and ship their captured chains instead.

## Quickstart

```bash
git clone https://github.com/agentrust-io/integrations.git
cd integrations/examples/startup-tpm
pip install cmcp-runtime httpx

# Terminal 1: mock upstream MCP server
python server/mock_mcp_server.py

# Terminal 2: the runtime (CMCP_DEV_MODE=1 for machines without a TPM/TEE)
CMCP_DEV_MODE=1 cmcp start --config cmcp-config.yaml

# Terminal 3: one tool call + signed TRACE Trust Record
python agent/echo_agent.py
```

See `startup-tpm/README.md` for the full walkthrough.

## Prerequisites

- Python 3.11+
- An MCP server to protect (existing servers work unchanged)
- For Level 1 attestation: a VM with TPM 2.0, AMD SEV-SNP, or Intel TDX
- For GPU-CC attestation (v0.2): NVIDIA H100/H200 with CC mode enabled

## Status

Launching at Confidential Computing Summit, San Francisco, June 23 2026.

## Community

Questions, feedback, integration help: [Discord](https://discord.gg/grgzFEHgkj).

## License

Apache 2.0
