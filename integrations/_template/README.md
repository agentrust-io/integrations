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

This template ships `.github/workflows/agentrust-conformance.yml`. Replace
`<vendor>-<product>` in it, keep only the packages your integration declares in
`integrates_with`, and point the conformance step at the level you claim in
`integration.yaml`. It installs the released agentrust-io packages and runs the
TRACE conformance suite across a Python matrix; a clean run is the basis for the
Verified tier and the index badge.
