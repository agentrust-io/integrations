# TRACE Conformance Result

**Result: FAIL at Level 0 — 1 of 7 checks fails.**

This is the real result of running `agentrust-trace-tests` 0.5.1 against a TRACE record built, moments before this run, from a fresh, real ComputeID `/verify` API response (not a hand-built sample, and not a stale fixture — see "Reproducing this result" below for the exact capture-to-verification timeline).

## Exact command and environment

```
$ pip install agentrust-trace-tests==0.5.1
$ node convert-to-trace.js evidence/<fresh-bundle>.json > trace-record.json
$ trace-tests verify --record trace-record.json --level 0 --max-age 86400
```

- `trace-tests` version: `0.5.1` (the same version this document's failures are described against — the modules that exist in this release are `TR-ANC`, `TR-ENV`, `TR-POL`, `TR-RTE`, `TR-SCA`, `TR-SIG`, `TR-TXN`; there is no `TR-APR` module in 0.5.1, and an earlier draft of this document incorrectly cited one).
- `--max-age`: default (`86400` seconds / 24h). Not overridden.
- Record `iat`: `1789031581` (2026-09-10T09:13:01Z) — the evidence bundle's own `issued_at`, captured seconds before this run.
- Capture time of this run: 2026-09-10, immediately following passport registration against a live, unmodified ComputeID `/verify` endpoint.

## Verbatim result

```
TRACE Conformance Report -- Level 0
Format : trace

  TR-ENV  PASS        eat_profile sentinel matches
  TR-ENV  PASS        iat is valid and fresh (1789031581)
  TR-ENV  PASS        subject is a valid workload identity URI ('did:computeid:agent:7818f1e3-d2a5-430a-a34d-f0180188f0f5')
  TR-ENV  PASS        cnf.jwk.kty present ('OKP')
  TR-SIG  PASS        cnf.jwk key type is supported (kty='OKP', crv='Ed25519')
  TR-SIG  PASS        Ed25519 signature verified
  TR-POL  FAIL        TR-POL-001: policy field is missing or not an object

Result: FAIL  (7 checks, 1 failure(s), 0 skipped)
```

## The one failure, and why it is expected

**TR-POL-001: policy field is missing or not an object** — expected. ComputeID is an identity-issuance system; it does not evaluate or enforce policy, so it has no `policy.bundle_hash` or `policy.enforcement_mode` to report.

## What changed since the previous result in this document

The previous draft of this document reported `FAIL (8 checks, 4 failure(s))`, including a `TR-APR-001` finding that does not exist in `trace-tests` 0.5.1, and a stale `iat` that failed freshness (`TR-ENV-002`) simply because the fixture bundle had aged past `--max-age`. Both were real problems with how the result was produced and recorded, not with ComputeID's evidence itself:

1. **`references[]` now uses the schema's actual shape** (`rel`/`id`/`resolver`/`digest`, per `schema/trace-claim.json`'s `additionalProperties: false`), replacing the previous `name`/`value` fields the schema rejects. `convert-to-trace.js` now emits a single reference pointing at the evidence bundle by SHA-256 digest (hex-encoded, per the schema's `digest` pattern), rather than six fabricated per-check entries.
2. **The record now carries a genuine `cnf.jwk` and is genuinely signed** (Ed25519, `adapter-signing-key.pem` / `adapter-signing-pubkey.pem`). `cnf` identifies the key that signs *this TRACE record* — a separate concern from the ComputeID AgentPassport's own RSA + ML-DSA-65 identity keys, which remain in the referenced evidence bundle. This is why `TR-ENV-004` and both `TR-SIG` checks now pass: the record is honestly, verifiably signed, by a key named in the record itself.
3. **`offline-verifier.js` now independently recomputes both signature checks.** It previously read `bundle.signature_valid` / `bundle.pq_signature_valid` — the service's own self-reported flags — which contradicted its documented claim of independent verification. It now recomputes RSA-SHA256 (PKCS#1 v1.5) against the embedded `public_key`, and ML-DSA-65 (via `@noble/post-quantum` 0.4.1) against the embedded `pq_public_key`, both over the embedded `signed_payload`. Verified adversarially: both correctly return `true` against the genuine bundle and `false` against a locally tampered payload.
4. **`iat` is now genuinely fresh** because the evidence bundle itself is freshly captured (see "Reproducing this result"), not because freshness was special-cased or the record's clock was patched.

`appraisal` and `data_class` remain a residual, structural gap common to every top-level-schema validation attempt below — see next section.

## Full JSON Schema validation (`schema/trace-claim.json` @ `3a561d84d752794b9afa994ce16ed35c24ac0acb`)

`trace-tests verify` checks the module-based rules above; it is not a full JSON Schema validator. Running the record through the pinned schema directly (Python `jsonschema`, `Draft202012Validator`) gives a stricter, complementary result:

```
5 schema errors
- [] : 'model' is a required property
- [] : 'policy' is a required property
- [] : 'data_class' is a required property
- [] : 'build_provenance' is a required property
- ['runtime'] : 'measurement' is a required property
```

Down from 31 errors in the previous submission (which included the `references[]` shape defects fixed above). All five remaining errors are the same, single, honestly-disclosed fact: **ComputeID issues identity credentials; it does not run model inference, evaluate policy, execute tool calls, track build provenance, or hold a hardware measurement.** `runtime.measurement` is unconditionally required by the schema whenever `runtime` is present — including for `runtime.platform: "software-only"` — even though no measurement can exist for a software-only origin; TRACE-MAPPING.md §3 already documents this as "not populated," not an oversight. None of these five fields is fabricated here, and none of the five errors is expected to be fixable without ComputeID beginning to perform work (policy enforcement, model inference, hardware attestation) it does not do today.

## What this result proves

That this adapter's mapping is honest and internally consistent: the one remaining `trace-tests` failure and all five schema errors trace directly to a documented scope boundary (identity issuance, not execution attestation), not to an implementation defect. Every fixable defect identified in review — the `references[]` shape, the unsigned record, the non-independent signature checks in `offline-verifier.js`, the wrong digest encoding, the stale freshness reading, and the nonexistent `TR-APR-001` citation — has been fixed and is demonstrated above, not asserted.

## Reproducing this result

Because `iat` freshness (`TR-ENV-002`) is time-bound, this exact `trace-tests` pass/fail count will not reproduce indefinitely from a static fixture — that is expected, correct behavior (an old record should eventually read as stale), not a flaw. To reproduce a fresh result:

1. Register a new ComputeID AgentPassport and fetch its `/verify` response (this is the evidence bundle format `convert-to-trace.js` expects).
2. Run `node convert-to-trace.js <fresh-bundle>.json > trace-record.json` immediately after.
3. Run `trace-tests verify --record trace-record.json --level 0` immediately after that.

The `TR-POL-001` failure and the 5 schema errors above are not time-bound and will reproduce from any ComputeID evidence bundle, fresh or not.
