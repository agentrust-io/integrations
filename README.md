[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Discord](https://dcbadge.limes.pink/api/server/9JWNpH7E?style=flat)](https://discord.gg/9JWNpH7E)

# agentrust-io Integrations

The ecosystem front door for cMCP, TRACE, and Agent Manifest. Vendors and community projects integrate here, on their own terms, under published rules - while the core repos stay first-party.

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
| [comply54](integrations/comply54/) | comply54 | trace | community |
| [DecisionAssure](integrations/decisionassure/) | DecisionAssure (a1k7) | trace | community |
| [LangChain](integrations/langchain/) | agentrust-io | trace | community |
| [LlamaIndex](integrations/llamaindex/) | agentrust-io | trace | community |
| [Nobulex](integrations/nobulex/) | Nobulex | trace | community |
| [OpenTelemetry GenAI](integrations/otel-genai/) | agentrust-io | trace | community |
| [ramen-ai cMCP Adapter](integrations/ramen-ai-cmcp/) | ramen-ai | cmcp, trace | community |
| [SAGE AgenTrust Bridge](integrations/sage-agenttrust/) | SAGE AgenTrust Bridge | cmcp, trace | community |
| [Agent Sentinel](integrations/sentinel/) | a1k7 | trace | community |
| [Shadow AI Discovery](integrations/shadow-ai/) | agentrust-io | cmcp, agent-manifest | community |
| [Agentic SpendGuard](integrations/spendguard/) | SpendGuard | trace | community |
| [agentrust-codex](plugins/agentrust-codex/) | agentrust-io | agent-manifest, trace | community |
| [scheduled-agents](scheduled-agents/) | agentrust-io | trace | community |
<!-- integration-index:end -->

The [Copilot drift check](copilot/) is intentionally outside this manifest index:
it emits neither TRACE nor Agent Manifest today, so it cannot truthfully select
an `integrates_with` value from the current schema. See the note below.

All four engines share [`agentrust-capture-core`](packages/agentrust-capture-core),
which owns fingerprinting, comparison, baseline sealing and the report honesty rules.

Adapters that build a Trust Record from evidence **another system produced** share
[`agentrust-trace-adapters`](packages/agentrust-trace-adapters). Records built through it
carry `origin.kind: third-party-control-plane`, `runtime.platform: software-only` and
`appraisal.status: none`, so the assurance downgrade is something a consumer reads from
the record rather than from a README. None of the three is a parameter.

**Note on the Copilot entry.** It is a pull-request status check rather than a
session hook, because Copilot's composition lives in the repository. It emits no
TRACE record and no Agent Manifest, so it claims neither: `integrates_with` offers
only `cmcp`, `trace` and `agent-manifest`, and asserting one today would be an
unverifiable claim.

That is currently blocked on a spec question rather than on implementation, tracked
in [agent-manifest#256](https://github.com/agentrust-io/agent-manifest/issues/256).
TRACE describes an execution and this check describes a composition, so a TRACE
record is the wrong artifact. Agent Manifest is the right one, but every level
requires `artifacts.model_identity`, and a repository cannot know the model: Copilot
picks it at session time from the user's plan and settings. The same repository
serves every model, with an identical contributed composition. Manufacturing a
model to satisfy the field would be exactly the kind of unverifiable claim
`CONTRIBUTING.md` rules out, so the integration ships without one until the spec
has a way to express a composition whose model is unknowable at authoring time.

## Community

Questions, feedback, integration help: [Discord](https://discord.gg/9JWNpH7E).

## License

Apache 2.0. Each integration directory may carry its own compatible license; the manifest declares it.
