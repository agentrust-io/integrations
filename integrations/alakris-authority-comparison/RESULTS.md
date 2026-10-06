# Execution and appraisal record — 2026-10-06

## Scope

This contribution is an evidence appraiser and synthetic boundary fixture, with separate independently executed MintID client runs. It does not establish a matched end-to-end comparison between Alakris, MintID and Proofable. A field marked `measured` in an author appraisal means that an observation is present in the cited author record; it does not mean independent verification.

## Package checks

- Environment: isolated Frankfurt Linux task checkout, Python 3.12.15.
- Released dependency: `agentrust-trace==0.11.0`. Inputs are `requirements.txt`; reproducible dependency versions and distribution hashes are in `requirements.lock`. Actual installed versions are in `results/python-packages.txt`.
- Command: `python check_package.py --fetch` (or without `--fetch` to reuse pinned downloaded bytes).
- **27 tests passed**, including a positive control that commits once, forged dispatch rejection, action tampering, a late veto invalidating an earlier token, duplicate suppression, expiry closure, manifest coverage, missing-case handling, emergency bound units and credential-bearing URL rejection.
- **12 TRACE Reference shapes validated** with the released SDK. These are unsigned external evidence pointers, not Trust Records, signature verification or a conformance-level claim.
- Candidate integration manifest shape passes the upstream JSON Schema. The authenticated human GitHub maintainer identity is still required before `integration.yaml.in` becomes `integration.yaml`, and before generating the integration index/marketplace catalog. Existing repository manifests and compatibility policy pass; the new candidate is not yet listed in those generated catalogs.

## Pinned author evidence

| Artifact | Exact pin | Result and limits |
|---|---|---|
| MintID public evidence | `b678e5cd6b5736e1795fd18d497fd8e501272dcd` (`public-v2026-10-07`) | Operator JSONL and summary hashes pass. Current service release and old local outage release remain separate. |
| MintID current service | Public `044f6888874ede33186310b9ec86fbcb1ee83ad7`; source `497509ebf0c3bbc9c1a924996018b67db6ca949f` | Build-info reports source prefix `497509ebf0c3`, release `public-v2026-10-06.2`. Evidence-only publication 10-07 does not change the service code. |
| Proofable public evidence | Docs `3a45f026fd0c06b9d1d411c053597584b6b1c3dc`; deployed source claimed `f92faf39a4bae480cca3e5c07ce2c95d6ab68411` | Strict public byte integrity **FAIL** for `trace.jsonl`. Other four payload digests pass. No independent production execution was performed. |

Proofable's actual LF trace SHA-256 is `8df7ed9d49d1d6fb696a05661fd11db194db7c808719a66cadbf0f0a562cc1e2`; the published expected digest is `d749cf16fe8dd599f528e21e95863b930004a0b3f0a9882695e3d3b03e8c2183`. Converting LF to CRLF produces the expected digest. This diagnoses a byte-format mismatch; it does not modify the validation input or allege alteration of scenario content. The same mismatch occurs in SHA256SUMS and the manifest.

The sanitized Proofable trace contains publisher observations and receipt references, with no full public portable envelope, signature or signer material. Receipt signature verification and revocation latency remain unperformed; independent target-side effects are absent. Its `SUPPORTED` labels remain publisher claims. The unavailable-authority case is inapplicable to its current locally evaluated path. An allowlist/policy refusal alone does not establish a structurally independent oversight veto.

MintID's published outage record `revocation-trace-local-20261005T094532Z` belongs to `public-v2026-10-05.5`, before the remote-RPC change. The operator reports a 40.2-second pause, a pre-cut presentation refused `state_unproven` after 10.1 seconds, three 503 challenges during the outage, and acceptance 0.9 seconds after restoration. Those are author observations and are not current-build reproduction. MintID has no executor; dispatch, external committed effect and task outcome are outside its implementation. Full delegated scope is intentionally not emitted.

## Independently executed MintID public client run — attempt 1

Artifacts: `results/native-mintid/attempt-1/`; exact command, environment, pre/postflight build information and SHA-256 values are recorded in `run-result.json` and `partial-findings.json`.

- Source: `b678e5cd6b5736e1795fd18d497fd8e501272dcd`, clean tracked source; uv 0.12.23, Python 3.12.15, Rust 1.97.0. Native source was not patched.
- Requested paths: issuer, kill switch, cascade; public vendor sandbox with newly created synthetic principals/credentials. No operator credentials or payments.
- UTC interval: 2026-10-06 19:59:34–20:02:17. Exit **1**, partial run.
- Issuer path: positive baseline accepted; t0 is the revoke response at 20:00:35.705Z. A forced proof with the old witness was last accepted at +11.6 seconds and first refused at +23.8 seconds with `status_root_stale`. These are polling observations, not an exact transition time or end-to-end effect latency.
- The revoked agent's refresh returned `credential_revoked`. A never-revoked control also encountered a stale-root refusal (+33.5 seconds), then refreshed and was accepted. That contrast separates a stale-evidence refusal from the revoked credential's inability to refresh.
- Kill switch was triggered and some old-witness proofs were accepted; a hosted challenge returned HTTP 503 `state_unavailable`. The native harness raised an uncaught `ServiceRefusal` (`revocation_trace.py:627`, through `service_client.py:64` and `force_until_refused:698`) and did not reach cascade or write its final manifest. No complete kill-switch refusal/bound result is inferred from this attempt.
- This incidental error is not a controlled outage injection or a proof of fail-closed enforcement. The failed attempt is retained instead of replaced by retry evidence.

Operator-only decision logs were unavailable, so actual consulted root identity/age and deciding condition remain **not emitted** for this independent client run. A public client chain read after a decision cannot establish which root the verifier used. The relying service and chain RPC remain vendor-operated; this is not independent chain validation, target-side effect observation or hardware assurance.

## Bounded retry for remaining paths

Artifacts: `results/native-mintid/retry-remaining/`; native JSONL, summary and manifest are preserved unchanged. Exact commands, pre/postflight builds and hashes are in `run-result.json`; `independent-audit.json` records the appraisal. UTC interval: 2026-10-06 20:03:20–20:07:58. Native exit **0**, completed with a baseline qualification.

| Path / agent | First observed refusal after path t0 | Revoked refresh refusal after path t0 | Publisher seconds bound |
|---|---:|---:|---:|
| Kill switch | 8.4 s | 37.1 s | 245 s |
| Cascade agent 1 | 66.8 s | 150.1 s | 395 s |
| Cascade agent 2 | 42.7 s | 95.9 s | 395 s |

All three refresh failures are `credential_revoked`. The first-refusal figures are single-run polling observations tied to each path's t0, not exact transition timestamps, protected-effect latency or a general service guarantee. Eleven artifact/observation consistency checks pass. **Not every positive baseline passed:** `cascade_agent_1` was refused `status_root_stale` before revocation; a subsequent forced proof was accepted after the trigger. The native harness logs baselines without asserting or retrying their acceptance (`revocation_trace.py:857–859`). This record is not labeled a clean conformance PASS.

Retry raw JSONL SHA-256: `e0618e6fca7322f7e8168ce48b6ebbe8fc9a5a7b8dfdf6bc3052544266fc9076`; summary: `b339a82972c83b2d98dafed6cf0840e8eda115e1780dd921165233c692a89397`; manifest: `4f5fa6cce83f1122d597523ff91b1f7fa87534c9160c81014c45f915f3316e27`. Collector digest checks pass for both attempts. The failed first attempt is retained separately; no results are combined into a fictitious clean four-case run.

## Open evidence work

- Current-build controlled outage run and published MintID scope/veto trace.
- Robust native harness handling of transient challenge errors, and explicit positive-baseline checks.
- Corrected Proofable raw-byte digests plus complete public receipt verification material or a public sandbox reproduction procedure.
- Implementation-side dispatch/effect adapters and an independent committed-effect observer, including lost response after a committed write.
- Same-input matched runs, original deadlines/fallback scope, retries/duplicates and useful work lost.
- Maintainer review, upstream issue/PR publication and links from AAIF WG #13. No Verified badge is requested by this packet.
