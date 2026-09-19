# AI Agent Incident Register

Reads an Agent Manifest and returns the decided AI-agent incidents that bear on what it declares, each with the liability allocation the register assigned.

The [AI Agent Incident Register](https://companyscope.io/register) is a numbered public corpus of AI-agent incidents, each analysed for the legal duty engaged, who carries liability across the chain, and the governance that would have prevented it.

## What it does

`air_review.py` takes a signed or unsigned Agent Manifest, reads the artefacts and scopes it declares, and selects register entries that bear on those declarations. Every finding names the manifest field that triggered it, so a reviewer can see why an entry was selected and disagree with it.

Selection runs against the live register feed on the fields the feed publishes (`incident_class`, `owasp_asi`, `liability_locus`, and words in the title and summary), not against a pinned list of entry IDs. Entries published after this integration was written are picked up without a code change.

| Manifest declaration | What gets selected |
|---|---|
| `tool_manifest.allow_dynamic_registration` is true | Entries mapped to OWASP ASI02 Tool Misuse |
| `policy_bundle.enforcement_mode` is `advisory` or `audit-only` | Autonomous-agent-breach entries |
| `policy_bundle.scope` is empty | Autonomous-agent-breach entries |
| `hitl_record` absent or not required | Entries where liability fell on the deployer |
| `data_scope.personal_data_categories` populated | Entries turning on personal data |
| `data_scope.automated_decision_making` is true | Entries with a crystallised legal outcome |
| `delegation_chain` present | Entries mapped to OWASP ASI03 Identity and Privilege Abuse |
| `model_identity.deployment_type` is `api` or `third-party-api` | Entries where liability fell on the vendor |
| Tool names matching code or package operations | Coding-agent entries |
| `unbound_artifacts` populated | Reported as a manifest gap, with no entry selected |

## What it does not claim

- It is **not a compliance verdict**. It produces a reading list for a human reviewer, and says so in its own output.
- It issues **no TRACE records** and verifies no manifests, so it declares no TRACE or WCM role and no conformance level.
- It does **not** assert that a listed incident applies to your deployment. It asserts that the manifest declares something the incident turned on.
- Register entries analyse public facts and are not legal advice.

## Install

```bash
pip install agent-manifest
```

No other runtime dependency. Python 3.11+.

## Usage

```bash
python src/air_review.py path/to/manifest.json
python src/air_review.py path/to/manifest.json --format json
python src/air_review.py path/to/manifest.json --feed ./register-snapshot.json
```

`--feed` accepts a URL or a local JSON file, so the review runs offline against a pinned snapshot of the register.

## Reproduction

```bash
python -m venv .venv && . .venv/bin/activate
pip install agent-manifest==0.12.0
python src/air_review.py tests/sample_manifest.json
```

`tests/sample_manifest.json` is a valid manifest built with the SDK: three tools including `shell.exec`, dynamic tool registration enabled, an advisory policy bundle with empty scope, no human-approval record, personal data in scope, and a third-party API model. Against the register as at 17 September 2026 it triggers seven of the ten rules.

Tests run with `pytest tests/` and use a pinned feed fixture, so they do not depend on the network.

## Source and licence

The register feed at `https://companyscope.io/api/register` is CC BY 4.0. Attribution: Michael K. Onyekwere, AI Agent Incident Register (companyscope.io/register). The feed carries a DOI and an archived snapshot. Entry prose remains the author's copyright and is free to quote and cite with attribution. This integration's own code is Apache-2.0.
