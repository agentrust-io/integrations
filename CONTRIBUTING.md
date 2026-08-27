# Contributing an integration

One directory per integration, one PR per change. Self-serve: you do not need an invitation.

## Layout

```
integrations/<vendor>-<product>/
  integration.yaml      required - validated against schema/integration.schema.json in CI
  README.md             required - what it does, how to run it, what it does NOT claim
  <your code/config>    optional - adapters, policy packs, dashboards, manifests
```

Start by copying `integrations/_template/`.

The `marketplace` block in `integration.yaml` controls discovery in the public
[AgenTrust Marketplace](https://agentrust-io.com/marketplace/). After editing a
manifest, run `python scripts/generate_marketplace_catalog.py`; CI rejects a
stale catalog so the repository index and public Marketplace cannot silently drift.

## Hard rules

These come from operating large OSS governance projects. PRs that break them are closed, repeat offenses are banned, and merged integrations that turn out to break them are removed:

1. **Runnable against released packages.** Integrations target published PyPI releases (`cmcp-runtime`, `agentrust-trace`, `agent-manifest`, `weight-custody-manifest`), never forks or unmerged branches.
2. **Every claim verifiable.** Download counts, user numbers, certifications, "merged into X" - if a reviewer cannot verify it in two minutes, it does not go in. We check. Inflated claims are the fastest way to removal.
3. **One line of positioning, maximum.** Your README describes what the integration does technically. Marketing copy, comparison tables against competitors, and pricing belong on your site - link it in `integration.yaml`, not here.
4. **Link only to what an anonymous reader can open.** The WCM source repository is private, so every `github.com/agentrust-io/weight-custody-manifest` URL 404s for anyone outside the org. A WCM integration cites [wcm.agentrust-io.com](https://wcm.agentrust-io.com) and the [PyPI project](https://pypi.org/project/weight-custody-manifest/) instead. Dead links in a README are a review blocker.
5. **TRACE semantics are not negotiable.** If your product emits or consumes TRACE records, it must conform to [trace-spec](https://github.com/agentrust-io/trace-spec) and pass [agentrust-trace-tests](https://pypi.org/project/agentrust-trace-tests/) at the level you claim. A record without a verifiable signature binding is not a TRACE record; calling non-attested output "attested" gets the integration removed.
6. **You maintain it.** The manifest names a maintainer contact. Integrations that break against a current release and stay broken for 60 days after notice are moved to `attic/`.
7. **Humans submit, not bots.** Automated submission PRs and issue spam are closed on sight.

## Review process

Every PR runs: schema validation of `integration.yaml`, link checking, and the contributor reputation check. A maintainer reviews the claims in your README against rule 2 and the scope against rule 3. External PRs need maintainer approval of the current head commit to merge.

Want the **Verified** tier? Say so in the PR and include exact reproduction steps. We run it end-to-end; if the documented behavior holds, the tier flips and the index badge follows.

## Declaring a WCM integration

WCM is a four-layer protocol, so a single conformance number would say nothing
useful. Declare instead:

- `wcm_roles` - what the integration *does*: `manifest-producer`,
  `manifest-verifier`, `key-broker`, `protected-runtime`, `attestation-source`,
  or `evidence-consumer`.
- `wcm_conformance_levels` - which `wcm conformance` levels you pass, as layer
  identifiers (`L1` manifest and joint signature, `L2` attestation-gated
  release, `L3` runtime custody, `L4` derivative lineage). Required for the four
  roles that handle WCM material directly.

An `attestation-source` hands evidence to somebody else's verifier and an
`evidence-consumer` reads custody output downstream. Neither verifies a manifest,
so neither declares a level. Claiming one you do not run is the WCM equivalent of
calling non-attested output attested, and carries the same consequence.

The honesty rules in the WCM specification apply here unchanged. Confidential
computing does not hold against an operator who physically owns the hardware
(`SPEC.md` section 3.6), and no integration README may imply otherwise.

Package support floors are declared once in `compatibility.yaml`. An
integration's `tested_against` block records an exact run, not a version range,
and CI rejects declarations below the repository floor. Raising a floor is a
separate compatibility change and must update affected integrations or explain
their archival path.

## Running first-party tests locally

Install [nox](https://nox.thea.codes/) and run `nox`. Each suite gets an
isolated virtual environment, matching the repository's split package model and
avoiding import collisions between integration-local test packages. Use
`nox -s <session>` for one area; `nox -l` lists the available sessions.

Community/vendor integrations continue to use their integration-specific
conformance workflows. The root matrix intentionally does not turn the
community tier into a claim that maintainers run or certify vendor code.
## What this repo is not

- Not a place to ship product code that *requires* changes to core repos - propose those upstream as issues first.
- Not a listing service for tools unrelated to cMCP/TRACE/Agent Manifest - that is [awesome-ai-governance](https://github.com/agentrust-io/awesome-ai-governance), with its own criteria.
- Not an endorsement. Community tier means "structure checks pass," nothing more, and the index says so.
