# Released UCP commerce accountability

A runnable, offline example connecting an authenticated merchant checkout,
explicit spending authority, a local policy decision, and independently
verifiable evidence. This advances [examples #89](https://github.com/agentrust-io/examples/issues/89)
using released UCP **2026-08-25** artifacts. The existing parent-directory
illustrative example remains unchanged.

**This is a verification harness, not an interactive broker or payment system.**
One fictional reservation, USD, one configured merchant/platform pair, and empty
payment instruments keep the supported profile deliberately small. Completion
changes local SQLite rows; no money moves and no real merchant is contacted.

| Start here | Purpose |
| --- | --- |
| [Run the smoke](#run-it) | One no-network container command after the build |
| [Business boundary](ucp_commerce/flow.py) | Authorization, transaction, retry cache, independent audit |
| [Protocol signatures](ucp_commerce/wire.py) | Released RFC 9421 library plus raw-body and coverage checks |
| [Schema provenance](schemas/README.md) | Exact released inputs, hashes, regeneration, limitations |
| [Acceptance tests](#acceptance-evidence) | Concrete assertions, including refusal paths |

## Run it

From this directory, with Docker available:

```sh
docker build --no-cache --tag released-ucp-accountability:local .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 128 \
  --memory 1g --cpus 2 --tmpfs /tmp:rw,nosuid,nodev,size=256m \
  released-ucp-accountability:local
```

Expected result: an allowed simulated purchase whose evidence passes independent
audit, passing tests, a measured branch-coverage report, Ruff checks/formatting,
mypy, Bandit, and the final line `OFFLINE_SMOKE_PASSED`. A failing stage stops the
smoke. CI runs this same script as non-root UID/GID `10001:10001`, without network
access, writable image layers, Linux capabilities, secrets, or publishing steps.

For host development with Python 3.12 and uv 0.12.5:

```sh
uv sync --frozen
uv run --frozen --offline --no-sync python -m ucp_commerce
./scripts/smoke.sh
```

Optional separate-process evidence verification, within the local freshness
window:

```sh
uv run --frozen --offline --no-sync python -m ucp_commerce --output ./run/demo
uv run --frozen --offline --no-sync python -m ucp_commerce audit \
  ./run/demo/bundle.json --trust ./run/demo/public-trust.json
```

The output contains signed evidence and public keys, not private signing keys.
For this demonstration the operator generated those keys. For other evidence,
select trusted keys independently: accepting a stranger's bundle and its
self-supplied trust file would not authenticate the stranger. Generated output
and databases are local run artifacts, not fixtures to commit.

The initial build/install needs dependency-download access. Verification does
not. The image has a digest-pinned Python base, hash-verified uv bootstrap wheels,
and a locked Python dependency graph. This is **not** a claim of bit-reproducible
image output. No package is published by this example.

## What crosses the trust boundary

```text
Configured authority key ── signs bounded local grant ──┐
Configured merchant key ── signs UCP checkout ─────────┤
Configured platform key ── signs exact completion ─────┤
                                                     ▼
                           Merchant.complete: authenticate + authorize
                                                     │
                            one SQLite transaction: spend + local effect
                                      + cached signed result
                                                     │
                    merchant UCP response + TRACE record + decision JWS
                                                     ▼
                           read-only audit with independent trusted keys
```

The demo generates four disposable signing keys in one local process. The roles
are cryptographically separate, not deployed as separate security domains. The
auditor receives trusted public keys out of band; neither `kid` nor a key inside
submitted evidence grants trust. A configured merchant key represents only that
local configured signer, not verified ownership of a real business or domain.

### Readable allow trace

1. The merchant supplies a signed, schema-valid `ready_for_complete` checkout
   for a fictional USD 125.00 reservation.
2. A separately signed local grant permits `checkout.complete`, USD, the exact
   configured merchant and platform keys, a USD 200.00 cap, and a bounded expiry.
3. The platform signs `POST /checkout-sessions/{id}/complete`, its raw JSON body,
   a fresh 128-bit-random idempotency key, and the configured `UCP-Agent` profile
   declaration. The supported request contains empty instruments.
4. Under a SQLite write lock, the merchant authenticates the evidence, checks
   the supported profile and authority, and compares the supplied signed
   checkout with current local checkout state before invoking
   its private completion handler.
5. One transaction records the spend, simulated effect, and cached result. The
   result includes a signed completed UCP response, a released TRACE record, and
   a canonical signed decision receipt binding their digests.
6. The independent audit re-verifies signatures, schemas, policy, purchase terms,
   and receipt bindings without invoking a handler or modifying redemption state.

## Three different kinds of evidence

| Artifact | Exact meaning and implementation |
| --- | --- |
| Local authority grant | Strict, closed example schema; RFC 8785 canonical JSON and an Ed25519 compact JWS through `joserfc`. These are local spending-policy semantics, not a UCP/AP2 mandate. |
| UCP HTTP artifacts | ES256 signatures through `http-message-signatures`; RFC 9530 SHA-256 covers the **original body bytes**, not canonicalized JSON. Request target and required headers are covered; a standard response signature covers status and body, **not its enclosing request URL/method**. |
| TRACE plus decision receipt | Released `agentrust-trace` signing, schema validation and verification authenticate a software-only policy statement. A separate Ed25519 decision JWS commits the grant, checkout body, request/response snapshots, TRACE record, policy, key bindings, and per-call invocation number. |

The wire layer checks `Content-Digest` and required signature coverage itself;
the signature library alone does not establish those application conditions.
UCP derives the algorithm from the key, so the HTTP `Signature-Input` omits
`alg`. The five-minute signature/audit window is **local policy**, not an
additional UCP protocol requirement. HTTP snapshots are constructed and verified
in-process; this does not test a deployed HTTPS transport or discovery client.
The merchant checks the authenticated `UCP-Agent` declaration against the local
configured profile URL. It never fetches that URL or trusts keys obtained from
it; profile hosting and discovery remain outside this example.

The authority is deliberately **cap-based**: the grant permits one supported
USD purchase under its signed limit. The platform signature binds the checkout
ID/route and completion body, **not a particular quoted price or revision**.
The merchant checks the supplied authenticated quote against current state and
its local policy. This is not AP2-style buyer consent to an exact signed price.

The TRACE record declares `origin.kind=self`, `appraisal.status=none`, no model,
and SLSA level 0. Its `evidence.py` source-file hash is an operator-generated
description of that helper, not a whole-program measurement, hardware evidence,
or proof that the code executed. TRACE
alone does not bind the purchase; the outer decision and the complete audit do.

## State and retry guarantees

- Identical client/target/idempotency-key retries with the same raw-body digest
  return the original cached signed bundle, without a second handler invocation.
- Conflicting raw bytes under the same scoped key are refused. Semantically
  equivalent reserialized JSON is not the same RFC 9530 body digest.
- A fresh idempotency key does not let a spent grant authorize a second purchase.
- Authentication and authorization denials precede handler invocation. An error
  after invocation is a transaction abort, not evidence that no handler ran.
- Spend, simulated effect, and cached result commit or roll back together because
  **all effects are local SQLite changes**. This cannot be generalized to
  exactly-once external payment execution or settlement.

The SQLite database retains retry entries for its lifetime, with no automatic
pruning. This short-lived harness revalidates authority before looking up a
cached result, and audit imposes a five-minute freshness window. It does not
implement a production 24-hour retry SLA, durable archival validation, distributed
idempotency, user-consent enrollment, or a revocation-distribution service.

## Acceptance evidence

The test suite uses the actual released schema/model, signature, and TRACE APIs.
Fault injection is confined to explicitly named unit tests; it is not presented
as protocol interoperability evidence. The complete smoke measures branch
coverage rather than assigning an invented coverage target.

| Invariant | Enforcing layer and representative test |
| --- | --- |
| Released schemas before SDK validation; original payload unchanged | `schema.py`; `test_checkout_passes_released_schema_and_sdk_without_mutation`, `test_checkout_rejects_invalid_amount_before_sdk_coercion` |
| Frozen offline schema inputs | `schemas/provenance.json`; `test_vendored_schemas_are_valid_offline_and_match_provenance` |
| Authenticated exact HTTP target and body | `wire.py`; `test_request_target_substitutions_are_denied`, `test_digest_checks_raw_bytes_not_equivalent_json` |
| Authenticated configured platform-profile declaration | `flow.py`; `test_missing_or_wrong_authenticated_platform_profile_is_denied` |
| Required signature coverage, not merely a valid signature | `wire.py`; `test_valid_signature_with_insufficient_request_coverage_is_denied`, `test_valid_signature_with_insufficient_response_coverage_is_denied` |
| Authority comes from configured trust | `evidence.py`; `test_grant_requires_configured_key`, `test_grant_payload_substitution_fails_signature` |
| Strict authenticated grant fields | `evidence.py`; `test_correctly_signed_invalid_claim_is_refused`, `test_grant_rejects_ambiguous_or_open_schema_payloads` |
| TRACE is authenticated but not purchase authority | `evidence.py`; `test_trace_signature_is_not_purchase_authorization`, `test_nonpolicy_http_data_needs_the_outer_decision_binding` |
| No hardware-assurance inflation | `evidence.py`; `test_correctly_signed_trace_must_keep_local_assurance_ceiling` |
| Correctly signed overspend still refused before the handler | `flow.py`; `test_correctly_signed_overspend_is_policy_denial` |
| Merchant/key/currency authority is independently checked | `flow.py`; `test_signed_authority_constraints_are_enforced`, `test_untrusted_keys_cannot_self_authorize` |
| An authenticated stale checkout is not current approval | `flow.py`; `test_stale_signed_quote_is_rejected_against_current_checkout` |
| Matching retries cache; changed bytes conflict; fresh keys cannot re-spend a grant | `flow.py`; `test_identical_retry_returns_original_signed_bundle`, `test_same_idempotency_key_with_changed_raw_payload_conflicts`, `test_new_idempotency_key_does_not_redeem_spent_grant` |
| Concurrency produces one spend/effect, with correct per-call receipt IDs | `flow.py`; `test_concurrent_identical_requests_have_one_handler_call`, `test_concurrent_fresh_keys_still_spend_grant_once`, `test_parallel_purchases_receipts_match_each_own_invocation` |
| Lock waits cannot preserve expired authority | `flow.py`; `test_expiry_rechecked_after_sqlite_lock_wait`, `test_pre_handler_final_freshness_recheck` |
| Post-handler failure is an abort, not a denial/no-invocation claim | `flow.py`; `test_post_handler_signing_failure_rolls_back_without_denial_claim` |
| Receipt links and independently configured trust are checked | `flow.py`; `test_auditor_rejects_cross_bound_signed_artifact_substitution`, `test_auditor_requires_each_independently_configured_trust_key` |
| Audit authenticates observations, not database truth | `flow.py`; `test_audit_authenticates_controller_assertion_not_database_state` |

Business-boundary refusal, retry, and concurrency cases are in
[`tests/test_flow.py`](tests/test_flow.py); the `INV-*` comments in
[`flow.py`](ucp_commerce/flow.py) identify the enforcing transaction boundaries.

## Released sources and nonclaims

- [UCP v2026-08-25 Checkout schema](https://github.com/Universal-Commerce-Protocol/ucp/blob/v2026-08-25/source/schemas/shopping/checkout.json),
  [REST binding](https://github.com/Universal-Commerce-Protocol/ucp/blob/v2026-08-25/docs/specification/shopping/checkout/rest.md),
  and [HTTP signatures](https://github.com/Universal-Commerce-Protocol/ucp/blob/v2026-08-25/docs/specification/signatures.md).
- [Official UCP Python SDK release](https://github.com/Universal-Commerce-Protocol/python-sdk/releases/tag/v2026-08-25),
  installed as `ucp-sdk==0.5.0`; JSON Schema validation complements its models.
- [http-message-signatures v2.0.1](https://github.com/pyauth/http-message-signatures/tree/v2.0.1),
  [joserfc 1.7.5](https://pypi.org/project/joserfc/1.7.5/), and
  [TRACE v0.10.0 signing/verification](https://github.com/agentrust-io/trace-spec/blob/v0.10.0/src/agentrust_trace/sign.py).

This demonstrates application-level accountability under configured local keys
and policy. It does **not** establish real merchant identity, buyer consent,
payment authorization by a financial institution, settlement, AP2 compliance,
full UCP conformance/certification, TPM/TEE attestation, key residency,
agent/platform co-location, safe behavior, or runtime integrity. It is not a
claim that #89 is closed or that signed observations independently prove their
truth. All payment, identity, and hardware trust boundaries remain explicit.
