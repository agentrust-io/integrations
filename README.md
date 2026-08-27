[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Discord](https://dcbadge.limes.pink/api/server/9JWNpH7E?style=flat)](https://discord.gg/9JWNpH7E)

# agentrust-io Integrations

The ecosystem front door for cMCP, TRACE, and Agent Manifest. Vendors and community projects integrate here, on their own terms, under published rules - while the core repos stay first-party.

Project support is recognized in [SPONSORS.md](SPONSORS.md). Sponsorship is
separate from marketplace listing, verification tier, maintainership, and
project governance.

## Where things live

| Repo | What belongs there | Who contributes |
|---|---|---|
| [cmcp](https://github.com/agentrust-io/cmcp), [agent-manifest](https://github.com/agentrust-io/agent-manifest), [trace-spec](https://github.com/agentrust-io/trace-spec), [trace-tests](https://github.com/agentrust-io/trace-tests) | The standard and reference implementation. Bug fixes and spec feedback welcome; no vendor product code. | Maintainers; community fixes |
| [examples](https://github.com/agentrust-io/examples) | First-party, end-to-end runnable examples, plus flagship partner examples by invitation. Every line is reviewed and every claim verified before merge. | Maintainers; invited partners |
| **this repo** | Your product's integration with cMCP, TRACE, or Agent Manifest: adapters, exporters, dashboards, policy packs, verifiers. Vendor-maintained. | Anyone, self-serve |
| [awesome-ai-governance](https://github.com/agentrust-io/awesome-ai-governance) | Neutral listings of notable agent-governance tools, including ones that do not integrate with this stack. | Anyone meeting the listing criteria |

## Tiers

**Community** - structure-validated and listed. We check that the directory follows the layout, the manifest validates, the links resolve, and the description makes no claims we can falsify. We do not run your code. The listing says exactly that.

**Verified** - everything above, plus we ran the integration end-to-end against released packages and confirmed the documented behavior. Verified integrations get the badge in the index and are eligible for the awesome list. Request verification in your PR; re-verification happens at every release that touches your integration.

Tier is recorded in each integration's `integration.yaml` and is set by maintainers, never self-declared.

## The neutrality rule

TRACE only works as a standard if it is genuinely neutral. Integrations are listed on technical merit under identical rules, including products that compete with anything we build. What gets a submission declined is never *who* you are - it is unverifiable claims, misrepresentation, or marketing dressed as documentation. See [CONTRIBUTING.md](CONTRIBUTING.md) for the precise rules.

## Index

<!-- integration-index:start -->
| Integration | Vendor | Integrates with | Tier |
|---|---|---|---|
| [claude-code](claude-code/) | agentrust-io | agent-manifest, trace | community |
| [Agent Passport System](integrations/aeoess-aps/) | aeoess | trace | community |
| [cA2A Cross-Operator Delegation](integrations/agentrust-ca2a-cross-operator/) | agentrust-io | ca2a | community |
| [comply54](integrations/comply54/) | comply54 | trace | community |
| [DecisionAssure](integrations/decisionassure/) | DecisionAssure (a1k7) | trace | community |
| [Google ADK](integrations/google-adk/) | agentrust-io | trace | community |
| [LangChain](integrations/langchain/) | agentrust-io | trace | community |
| [SOVP](integrations/litzki-systems-sovp/) | Litzki Systems | trace | verified |
| [LlamaIndex](integrations/llamaindex/) | agentrust-io | trace | community |
| [Nobulex](integrations/nobulex/) | Nobulex | trace | community |
| [OpenShell TRACE Adapter](integrations/openshell/) | agentrust-io | trace | community |
| [OpenTelemetry GenAI](integrations/otel-genai/) | agentrust-io | trace | community |
| [ramen-ai cMCP Adapter](integrations/ramen-ai-cmcp/) | ramen-ai | cmcp, trace | verified |
| [SAGE AgenTrust Bridge](integrations/sage-agenttrust/) | SAGE AgenTrust Bridge | cmcp, trace | community |
| [Agent Sentinel](integrations/sentinel/) | a1k7 | trace | community |
| [Shadow AI Discovery](integrations/shadow-ai/) | agentrust-io | cmcp, agent-manifest | community |
| [Agentic SpendGuard](integrations/spendguard/) | SpendGuard | trace | community |
| [WCM Agent Manifest Binding](integrations/wcm-agent-manifest/) | agentrust-io | wcm, agent-manifest | community |
| [WCM Azure Secure Key Release](integrations/wcm-azure-skr/) | agentrust-io | wcm | community |
| [WCM Confidential Containers Trustee](integrations/wcm-coco-trustee/) | agentrust-io | wcm | community |
| [WCM CycloneDX ML-BOM](integrations/wcm-cyclonedx/) | agentrust-io | wcm | community |
| [WCM GCP Confidential Space](integrations/wcm-gcp-confidential-space/) | agentrust-io | wcm | community |
| [Hugging Face WCM Download Gate](integrations/wcm-huggingface/) | agentrust-io | wcm | community |
| [WCM in-toto Attestation](integrations/wcm-in-toto/) | agentrust-io | wcm | community |
| [WCM Kyverno Policy Pack](integrations/wcm-kyverno/) | agentrust-io | wcm | community |
| [WCM NVIDIA GPU Attestation](integrations/wcm-nvidia-nras/) | agentrust-io | wcm | community |
| [WCM OCI Referrer](integrations/wcm-oci/) | agentrust-io | wcm | community |
| [WCM OpenTelemetry](integrations/wcm-opentelemetry/) | agentrust-io | wcm | community |
| [WCM Key Release to TRACE](integrations/wcm-trace/) | agentrust-io | wcm, trace | community |
| [WCM Triton Repository Staging](integrations/wcm-triton/) | agentrust-io | wcm | community |
| [WCM Serving Guard for vLLM](integrations/wcm-vllm/) | agentrust-io | wcm | community |
| [agentrust-codex](plugins/agentrust-codex/) | agentrust-io | agent-manifest, trace | community |
| [scheduled-agents](scheduled-agents/) | agentrust-io | trace | community |
<!-- integration-index:end -->

### First-party framework coverage

| Framework | Adapter | Released framework exercised in CI | Evidence boundary |
|---|---|---|---|
| Google ADK | [Google ADK](integrations/google-adk/) | Yes - Google ADK 2.7.1 `InMemoryRunner` plugin lifecycle | Callback-visible invocation, model, and available tool identity; no payloads, retries, agent graph, function-body execution, or policy enforcement |
| LangChain | [LangChain](integrations/langchain/) | Yes — LangChain Core 1.6.0 callback contract | Tool identity and outcome plus model identity; no chain topology or runnable state |
| LangGraph | [LangChain](integrations/langchain/) | Yes — LangGraph 1.2.11 `StateGraph` with a nested tool call | Propagated tool callbacks; no nodes, edges, state transitions, checkpoints, or rollback decisions |
| LlamaIndex | [LlamaIndex](integrations/llamaindex/) | No — current tests use representative event objects | Allow-listed tool and model fields; released-framework interoperability remains unverified |

“Adapter exists” and “released framework exercised” are separate claims here.
The adapter README documents the evidence each callback surface can support; a
missing graph or state concept is not inferred into the TRACE record.

The [Copilot](copilot/), [Cursor](cursor/), [Windsurf](windsurf/) and
[Gemini CLI](gemini-cli/) drift checks are intentionally outside this manifest
index: none of them emit TRACE or Agent Manifest today, so none can truthfully
select an `integrates_with` value from the current schema. See the note below.

All seven engines share [`agentrust-capture-core`](packages/agentrust-capture-core),
which owns fingerprinting, comparison, baseline sealing and the report honesty rules.

Adapters that build a Trust Record from evidence **another system produced** share
[`agentrust-trace-adapters`](packages/agentrust-trace-adapters). Records built through it
carry `origin.kind: third-party-control-plane`, `runtime.platform: software-only` and
`appraisal.status: none`, so the assurance downgrade is something a consumer reads from
the record rather than from a README. None of the three is a parameter.

**Note on the Copilot, Cursor, Windsurf and Gemini CLI entries.** Each is a
pull-request status check rather than a session hook, because all four agents'
composition lives in the repository rather than a developer's home directory.
Each emits no TRACE record and no Agent Manifest, so each claims neither. None
currently produces or consumes one of the supported AgenTrust artifacts or
protocols, and asserting otherwise would be an unverifiable claim.

That is currently blocked on a spec question rather than on implementation, tracked
in [agent-manifest#256](https://github.com/agentrust-io/agent-manifest/issues/256).
TRACE describes an execution and these checks describe a composition, so a TRACE
record is the wrong artifact. Agent Manifest is the right one, but every level
requires `artifacts.model_identity`, and a repository cannot know the model: each
of these agents picks it at session time from the user's own plan and settings.
The same repository serves every model, with an identical contributed composition.
Manufacturing a model to satisfy the field would be exactly the kind of
unverifiable claim `CONTRIBUTING.md` rules out, so all four integrations ship
without one until the spec has a way to express a composition whose model is
unknowable at authoring time.

## Community

Questions, feedback, integration help: [Discord](https://discord.gg/9JWNpH7E).

## License

Apache 2.0. Each integration directory may carry its own compatible license; the manifest declares it.
