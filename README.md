[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Discord](https://dcbadge.limes.pink/api/server/9JWNpH7E?style=flat)](https://discord.gg/9JWNpH7E)

# agentrust-io Integrations

The ecosystem front door for cMCP, TRACE, and Agent Manifest. Vendors and community projects integrate here, on their own terms, under published rules - while the core repos stay first-party.

## Where things live

| Repo | What belongs there | Who contributes |
|---|---|---|
| [cmcp](https://github.com/agentrust-io/cmcp), [agent-manifest](https://github.com/agentrust-io/agent-manifest), [trace-spec](https://github.com/agentrust-io/trace-spec), [trace-tests](https://github.com/agentrust-io/trace-tests), [trace-registry](https://github.com/agentrust-io/trace-registry) | The standard and reference implementation. Bug fixes and spec feedback welcome; no vendor product code. | Maintainers; community fixes |
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

| Integration | Vendor | Integrates with | Tier |
|---|---|---|---|
| _none yet - be the first_ | | | |

## Community

Questions, feedback, integration help: [Discord](https://discord.gg/9JWNpH7E).

## License

Apache 2.0. Each integration directory may carry its own compatible license; the manifest declares it.
