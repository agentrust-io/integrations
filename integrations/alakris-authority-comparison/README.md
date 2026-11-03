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

The single check command downloads pinned fixtures, runs the tests normally and under `-O`, validates the earlier author packets while retaining their historical reports, writes the separate positive fetch appraisal, preserves the historical Proofable hash failure, and validates TRACE reference shapes. To rerun individual stages (the `runner.py` commands explicitly regenerate the named historical appraisal):

```sh
.venv/bin/python fetch_fixtures.py --out fixtures
.venv/bin/python -m unittest -v
.venv/bin/python reference_adapter.py > results/synthetic-reference.json
.venv/bin/python runner.py mintid --evidence fixtures/mintid \
  --record revocation-trace-testnet-20261006T073712Z --output results/mintid-author-testnet.json
.venv/bin/python runner.py mintid --evidence fixtures/mintid \
  --record revocation-trace-local-20261005T094532Z --output results/mintid-author-local.json
.venv/bin/python runner.py proofable --evidence fixtures/proofable --output results/proofable-author-oct8.json
.venv/bin/python proofable_fetch.py --input fixtures/proofable-fetch --output results/proofable-fetch-author.json
.venv/bin/python create_references.py --lock fixtures/download-lock.json --output results/trace-reference-shapes.json
```

The corrected Proofable command exits **0** only when the checksums, trace inventory and offline envelope appraisal pass. The separate historical packet at `fixtures/proofable-historical` still exits **1** for its published-byte checksum mismatch. `results/proofable-author.json` retains the failing digest and LF/CRLF diagnostic. Never update an expected publisher digest to make a run green.

`fetch_fixtures.py` downloads immutable source URLs and emits a download lock. Vendor evidence remains in its source repository; downloaded fixtures are not redistributed by this integration.

## Contract

This case-level appraisal complements [Sankalp's per-attempt comparison contract](https://github.com/probityai/agent-evidence-observer/blob/fb8cabc5c9c54459743497f2325bfef49b137a1a/interop/authority-unreachable-2026-10-03/CONTRACT.md). It does not replace native records, exact action/target identities, retained committed-effect evidence or terminal/recovery appraisal. Media bytes, destination and packaging need their own bindings; the original Alakris source snapshot is not a complete runnable provider deployment.

Four cases: binding veto; revoked authority with stale evidence and valid control; authority unavailable; revocation after dispatch. Each comparison keeps authority, decision, dispatch, committed effect, task outcome and receipt distinct. Evidence custody names the producer, artifact scope and appraiser separately. Each field has `state`, `value`, and `reason`:

- `measured`: the cited source has an observation; it can still be author-operated.
- `not_applicable`: this implementation/path has no equivalent.
- `not_emitted`: the public evidence does not expose the field.
- `not_measured`: the requested appraisal or measurement was not performed.

The evidence basis is separate (`author_record`, `synthetic_fixture`; actual native execution provenance is kept separately). A publisher's `SUPPORTED` result is retained as `publisher_claim`; it is not promoted to independent validation. Reference fixtures exercise a synthetic counter, not an Alakris production deployment or a completed matched scientific experiment.

### Independent execution reporting boundary

`independent_live_reproduction` is a reporting assertion supplied by the report producer. `validate_report()` checks required case fields and evidence states and rejects a true flag unless `basis="independent_run"`; it does not authenticate the producer, resolve native execution artifacts, or verify their binding to the reported cases. A report with `basis="independent_run"` and a true flag can therefore pass this validator without supporting execution provenance. Validator acceptance alone does not establish independent execution.

The current MintID and Proofable adapters emit `basis="author_record"` and `independent_live_reproduction=false`. Offline signature appraisal of their published bytes does not change that execution status. Consumers must not infer an independently reproduced run from the flag or from successful case validation alone.

An evidence-backed execution status would require a separately reviewed provenance-appraisal layer that binds operator identity and independence, exact implementation revision, invocation and environment, and retained artifacts to the reported cases, with positive and negative controls. This package does not implement that layer. Its schema and verification policy remain future work for maintainer review; the reporting flag cannot substitute for it.

MintID root epoch/height, root age, freshness limits, t0 definition, observed refusal and bound remain distinct. First-refusal observations are single-run measurements, not an end-to-end revocation SLA. Emergency bounds remain block-based and are never interpreted as a zero-second deadline. Original source revision, published evidence commit and live service build are separate pins. Old `public-v2026-10-05.5` outage evidence is not a result for the current `public-v2026-10-06.2` verifier. Refusal of a presentation does not establish that an external executor suppresses an effect. A post-dispatch accepted decision is not retroactively revoked by MintID; the relying party owns that boundary.

The synthetic executor rechecks expiry and revocation at commit, binds issued dispatch tokens to the action digest, refuses a veto, and deduplicates committed effects. Late recovery cannot reopen the original expired request. Its valid-control test must commit exactly once.

## TRACE bridge

`trace_references.behavior_reference()` uses released `agentrust-trace`'s `Reference.model_validate` with `rel: behavior-trace` and a raw-byte SHA-256 digest. It validates pointer shape only. No Trust Record or attestation is issued. A reference digest proves byte identity, not enforcement, effect, freshness or a signature. The contribution is an `external-evidence-source` and claims no TRACE conformance level.

The corrected Proofable Oct 8 packet discloses 11 portable envelopes. The adapter recomputes qHashes, recovers EIP-191 signers with DID/chain binding, and requires exact qHash-set equality across trace, manifest references and envelopes. This measures historical receipt integrity; current freshness remains unappraised. The unreachable case has no applicable receipt to verify. Revocation latency remains unmeasured and target-side effects lack an independent witness.

The verifier is vendored unchanged from the reviewed reader revision `2b54ee47491f0d1a86c7d9f47d434f8f02622043`; see `PORTABLE_ENVELOPE_NOTICE.txt` and its retained Apache-2.0 license. `fixtures/proofable` uses docs commit `9851059900e29ba701bb0f4df2bf89a2107f430c`. `fixtures/proofable-historical` preserves the earlier `3a45f026` packet, and `results/proofable-author.json` preserves its checksum FAIL. New results are written separately to `results/proofable-author-oct8.json`.

### Separate Proofable positive fetch appraisal

`proofable_fetch.py` reads the ten unmodified files in [the retained Oct 24 fetch packet](https://github.com/proofable/docs/tree/e6eb5b9307be24a5d82cc7490f647f0c98e2d24a/public/evidence/aaif/authority-at-dispatch/2026-10-24-fetch-route), at exact publication `e6eb5b9307be24a5d82cc7490f647f0c98e2d24a`. Its per-file SHA-256 pins include the publisher's `SHA256SUMS`, README and verifier script. Downloaded scripts are retained as bytes and never executed. The separate eight-case served run on revision `61724c9f...` is not an input to this adapter.

The command above exits **0** only for the fixed bytes, exact nine-entry checksum inventory, two valid EIP-191/qHash/DID-chain envelopes, matching declared signer/context, request projection and retained response/job consistency checks. Source-file digests in the output identify the tested appraiser and its helper/test bytes. Unsafe or missing paths, oversized files, duplicate JSON keys (including JSON inside signed content), nonfinite constants and ambiguous SSE messages fail closed. No vendor API, target URL, credential or downloaded code is used. Output must be outside the input packet and is replaced atomically from a fresh temporary file, so an existing output hard link cannot overwrite a packet inode.

The publisher reports hosted MCP `0.1.7`, service revision `18433a48d74af913550de7a018f02c7c724cc1c9`, and job `d259c7cc-0701-4624-a148-77b149f84e06`. These deployment fields are unsigned publisher claims, not independent binary attestation. The signed dispatch statement commits to SHA-256 of the documented `JSON.stringify` projection, in its specified key order. The URL occurs in `prompt`, the acceptance criterion is the generic `target-ack`, and the full returned marker is signed only in the terminal receipt. `runNowFirst` and the `acceptance.criteria` alias are outside that digest projection. The original publisher README's marker wording is retained unchanged; the appraisal does not infer a precommitment to the full marker.

`integrity: PASS` means fixed artifact bytes and checksum coverage match. `positive_dispatch_appraisal: PASS` additionally means the signature, request and correlation checks pass. **Neither means scenario conformance.** The four existing scenario cases each remain `UNMET`, with all fourteen fields and explicit missing-measurement reasons. EO01 is unestablished and `not_measured` for this positive run; the historical appraisals and their earlier N/A fields are not rewritten or treated as a passing EO01 result.

The signer is bound to its declared DID/wallet, but attribution of that wallet to Proofable is `not_measured` without a separately verified canonical trust source. No caller-provided wallet flag can promote that status. Grant and agent-identity proof records are absent. The decision's `jobId` is null; the unsigned create response correlates its qHash to the job ID, and identical requests share a digest. The service reports one GET and a returned marker; there is no executor-signed GET, retained external target ingress log, independent target witness, target-commit authority check or revocation-latency measurement. Service acceptance/completeness flags do not override these gaps. `independent_live_reproduction` and `independent_comparison_completed` remain false.

Negative controls independently generate signed envelopes using local test keys. They check altered request digests, a different validly signed receipt request, bad signatures/qHashes/DID bindings, different valid signers/chains/principals and unsigned decision/job join mismatches independently of outer artifact hashes. A separate tamper control keeps semantic checks valid while the publication hash fails. These controls exercise the offline appraiser, not Proofable's live enforcement.

## Native implementation runs

Use the vendor's pinned release and official sandbox only, with synthetic identities. The MintID public command is:

```sh
uv run python test-harness/trace/revocation_trace.py \
  --target testnet --paths issuer,kill_switch,cascade --out <isolated-output-prefix>
```

This exercises presentation refusal, refresh and control paths; it does not execute a payment. Emergency credentials are operator-only and excluded. Unavailability requires an isolated local stack and is not independently reproduced by the public testnet run. Native results, exact revisions, commands and environment are recorded in `RESULTS.md`; an attempted or blocked run is not a pass.

## Review requests

- Chris: corrected public digests and offline envelopes are appraised for the Oct 8 packet. Independent live reproduction remains open; retain sanitized trace, author custody, unmeasured latency and absent target witness.
- Marc: rerun the disconnected-authority case on the current verifier; publish veto evidence and keep unavailable/protected-effect boundaries explicit.
- Sankalp and other reviewers: review field states and propose an observer adapter for actual committed effects.
- Imran: review runner/adapter placement and the pointer bridge. Maintainers set listing tier; no verification badge is requested before review/reproduction.

Further work: implementation-side dispatch/effect adapters, an independent observer, a matched same-input run, independent live reproduction, and the current-build outage run. This initial PR exposes those gaps rather than marking them complete.
