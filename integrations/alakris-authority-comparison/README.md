# AAIF authority comparison evidence runner

A shared evidence-appraisal runner and executable synthetic boundary fixtures for AAIF Identity & Trust [WG issue 13](https://github.com/aaif/wg-identity-and-trust/issues/13).

## Run

Python 3.12 and published `agentrust-trace==0.11.0` are supported for this contribution.

```sh
cd integrations/alakris-authority-comparison
python3.12 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/python check_package.py --fetch
```

The single check command downloads pinned fixtures, runs the tests, writes both author appraisals, preserves the expected Proofable hash failure, and validates TRACE reference shapes. To rerun individual stages:

```sh
.venv/bin/python fetch_fixtures.py --out fixtures
.venv/bin/python -m unittest -v
.venv/bin/python reference_adapter.py > results/synthetic-reference.json
.venv/bin/python runner.py mintid --evidence fixtures/mintid \
  --record revocation-trace-testnet-20261006T073712Z --output results/mintid-author-testnet.json
.venv/bin/python runner.py mintid --evidence fixtures/mintid \
  --record revocation-trace-local-20261005T094532Z --output results/mintid-author-local.json
.venv/bin/python runner.py proofable --evidence fixtures/proofable --output results/proofable-author.json
.venv/bin/python create_references.py --lock fixtures/download-lock.json --output results/trace-reference-shapes.json
```

The Proofable appraisal command intentionally exits **1** for the pinned Proofable package's published-byte checksum mismatch. `results/proofable-author.json` retains the failing digest and LF/CRLF diagnostic. Never update an expected publisher digest to make a run green.

`fetch_fixtures.py` downloads immutable source URLs and emits a download lock. Vendor evidence remains in its source repository; downloaded fixtures are not redistributed by this integration.

## Contract

This case-level appraisal complements [Sankalp's per-attempt comparison contract](https://github.com/probityai/agent-evidence-observer/blob/fb8cabc5c9c54459743497f2325bfef49b137a1a/interop/authority-unreachable-2026-10-03/CONTRACT.md). It does not replace native records, exact action/target identities, retained committed-effect evidence or terminal/recovery appraisal. Media bytes, destination and packaging need their own bindings; the original Alakris source snapshot is not a complete runnable provider deployment.

Four cases: binding veto; revoked authority with stale evidence and valid control; authority unavailable; revocation after dispatch. Each comparison keeps authority, decision, dispatch, committed effect, task outcome and receipt distinct. Evidence custody names the producer, artifact scope and appraiser separately. Each field has `state`, `value`, and `reason`:

- `measured`: the cited source has an observation; it can still be author-operated.
- `not_applicable`: this implementation/path has no equivalent.
- `not_emitted`: the public evidence does not expose the field.
- `not_measured`: the requested appraisal or measurement was not performed.

The evidence basis is separate (`author_record`, `synthetic_fixture`; actual native execution provenance is kept separately). A publisher's `SUPPORTED` result is retained as `publisher_claim`; it is not promoted to independent validation. Reference fixtures exercise a synthetic counter, not an Alakris production deployment or a completed matched scientific experiment.

MintID root epoch/height, root age, freshness limits, t0 definition, observed refusal and bound remain distinct. First-refusal observations are single-run measurements, not an end-to-end revocation SLA. Emergency bounds remain block-based and are never interpreted as a zero-second deadline. Original source revision, published evidence commit and live service build are separate pins. Old `public-v2026-10-05.5` outage evidence is not a result for the current `public-v2026-10-06.2` verifier. Refusal of a presentation does not establish that an external executor suppresses an effect. A post-dispatch accepted decision is not retroactively revoked by MintID; the relying party owns that boundary.

The synthetic executor rechecks expiry and revocation at commit, binds issued dispatch tokens to the action digest, refuses a veto, and deduplicates committed effects. Late recovery cannot reopen the original expired request. Its valid-control test must commit exactly once.

## TRACE bridge

`trace_references.behavior_reference()` uses released `agentrust-trace`'s `Reference.model_validate` with `rel: behavior-trace` and a raw-byte SHA-256 digest. It validates pointer shape only. No Trust Record or attestation is issued. A reference digest proves byte identity, not enforcement, effect, freshness or a signature. The contribution is an `external-evidence-source` and claims no TRACE conformance level.

Proofable qHashes and private receipt labels do not supply a verifiable envelope. Signature verification is `not_measured`; signature material is `not_emitted` in the public package. Its revocation latency is unmeasured and target-side effects lack an independent witness.

## Native implementation runs

Use the vendor's pinned release and official sandbox only, with synthetic identities. The MintID public command is:

```sh
uv run python test-harness/trace/revocation_trace.py \
  --target testnet --paths issuer,kill_switch,cascade --out <isolated-output-prefix>
```

This exercises presentation refusal, refresh and control paths; it does not execute a payment. Emergency credentials are operator-only and excluded. Unavailability requires an isolated local stack and is not independently reproduced by the public testnet run. Native results, exact revisions, commands and environment are recorded in `RESULTS.md`; an attempted or blocked run is not a pass.

## Review requests

- Chris: correct the public trace digests and expose a complete offline-verifiable envelope or a public reproducible sandbox procedure. Retain sanitized trace, author custody, unmeasured latency and absent target witness.
- Marc: rerun the disconnected-authority case on the current verifier; publish veto evidence and keep unavailable/protected-effect boundaries explicit.
- Sankalp and other reviewers: review field states and propose an observer adapter for actual committed effects.
- Imran: review runner/adapter placement and the pointer bridge. Maintainers set listing tier; no verification badge is requested before review/reproduction.

Further work: implementation-side dispatch/effect adapters, an independent observer, a matched same-input run, public receipt verification, and the current-build outage run. This initial PR exposes those gaps rather than marking them complete.
