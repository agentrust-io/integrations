# <Product> integration with <cMCP | TRACE | Agent Manifest>

What this integration does, technically, in a paragraph. What it does NOT
claim is just as important: see rule 4 in [CONTRIBUTING.md](../../CONTRIBUTING.md)
if you emit or consume TRACE records.

## Run it

Exact, copy-pasteable steps against released packages:

```bash
pip install cmcp-runtime
# ...
```

## What is verified

State precisely what a reviewer can reproduce. If you want the Verified tier,
these steps are what we run.

## Conformance CI

Copy `agentrust-conformance.yml.example` to the repository root as
`.github/workflows/<vendor>-conformance.yml`, then replace `<vendor>-<product>`
and `<LEVEL>`. Workflows only run from the repo-root `.github/workflows/`
directory, never from inside an integration folder, so keep the file at the root
with a `paths:` filter scoped to `integrations/<vendor>-<product>/**`. It installs
the released agentrust-io packages, emits a record, and runs `trace-tests verify`
at the level you claim; a clean matrix run is the basis for the Verified tier.
