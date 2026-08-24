# Ecosystem Evaluation: 2026-08-24

Purpose: distinguish projects that belong in the governance resource list from
projects for which AgenTrust has built and tested a real integration.

| Project | Decision | AgenTrust opportunity | Next evidence gate |
|---|---|---|---|
| Google Sovereign Agent Mesh (SAM) | Add to `awesome-ai-governance`; integration candidate | Map SAM node identity and authenticated packet metadata into Agent Manifest identity and TRACE subject fields; evaluate cMCP as the governed MCP sidecar boundary. | [integrations#134](https://github.com/agentrust-io/integrations/issues/134): build a runnable adapter against a tagged SAM release and verify identity mismatch and replay failure cases. |
| Universal Commerce Protocol (UCP) | Add to `awesome-ai-governance`; example now available | Compose UCP checkout constraints with cA2A delegated spend authority, AGT policy decisions, and TRACE outcome evidence. | [examples#89](https://github.com/agentrust-io/examples/issues/89): replace the illustrative checkout document with a released UCP schema and signed protocol artifacts. |
| AG-UI event metadata proposal | Watch | Carry evidence identifiers across UI events, messages, and tool calls without putting them in user-visible content. | Wait for a released specification and cross-language merge semantics, then test loss and overwrite behavior. |
| agentgateway security work | Watch for adapter | Map gateway policy and identity events into TRACE without claiming the gateway itself provides hardware attestation. | Select a stable event/API surface and build a tested adapter. |

No item is added to the integrations marketplace until code calls a released
AgenTrust package, includes tests and fixtures, and satisfies
[`CONTRIBUTING.md`](../CONTRIBUTING.md).
