# Gap disclosure reconciler

Library slice for [agentrust-io/integrations#416](https://github.com/agentrust-io/integrations/issues/416).
The rules below are trace-spec section 3.3.4 at `b938790f7f46d3a943c76a5360d2de60bb72112c`,
as narrowed by the contract review on that issue. This module does not change
`ca2a` or `cmcp`, does not emit an orphaned-session disclosure, and does not
authorize a retry.

```python
from agentrust_trace_adapters import reconcile_chain

result = reconcile_chain(
    elements,  # JSON bytes, one object per chain element
    session_id="wf-001",
    trusted_issuer_keys=public_jwks,
    expected_credential_ids=["cred-0", "cred-1", "cred-2"],
)
assert result.effect_status == "unknown"
assert result.retry_authorized is False
```

`verify_disclosure` judges one element. `reconcile_chain` walks the chain.
Untrusted documents must be bytes or str so the parser can reject duplicate
keys. A pre-parsed dict is accepted only by `verify_disclosure`, and only
after the same value bounds.

## Outcomes

| Status | When |
|---|---|
| `receipt_missing_required` | An inventory entry has no authenticated hop and no bound disclosure. Case A. |
| `receipt_gap_disclosed` | Ed25519 signature verifies, the issuer is the predecessor's key or an authenticated ancestor, `session_id` matches, and both splice ends are present and hash-linked. Case B. |
| `gap_disclosure_unverified` | The other checks pass but no successor seals the splice. A tail. Not coverage, and not invalid. |
| `receipt_invalid` | A check ran and failed: bad signature, wrong type, wrong stream, dangling or unsealed splice, unauthorized signer, or a record inside the gap. |
| `complete` | The inventory is present, every entry has one authenticated hop, and the chain has no disclosure. |

`accepted_as_complete` is true only for `complete`. A profile that requires
proven completeness must pass `completeness_required=True`. That flag ignores
`accept_disclosed_gaps`. A disclosed gap is attested absence, not completeness.

## The four contract rules

1. **Case A is not Case B.** No disclosure means `receipt_missing_required`.
   Case B requires the authenticated splice above. A tail stays
   `gap_disclosure_unverified`.
2. **Inventory is an input, not an inference.** `expected_credential_ids` is
   the independently retained inventory. `chain[:2]` does not imply a third
   credential. A disclosure covers an entry only when its signed
   `credential_id` names that entry. The binding does not prove the credential
   ran, and a disclosure with no `credential_id` covers nothing.
3. **Descriptive fields stay descriptive.** `cause` and
   `receipts_lost_estimate` are echoed when their shapes are a string and a
   safe integer or null. A `lease_id` in `cause`, or `cas_fence_epoch` on a
   hop, does not change status, does not prove non-execution, and does not
   set `retry_authorized`. A second hop for the same credential is
   `receipt_invalid`, not a retry.
4. **Fixture booleans are not evidence.** The API has no
   `predecessor_present`, `successor_present`, `permitted_ancestor_key_ids`,
   or `claimed_absent_but_present` parameter. Presence is an element whose
   digest equals `previous_receipt_hash`. The seal is the next non-hierarchy
   element after the disclosure. Ancestors come only from a
   `KeyHierarchy/1.0` element signed by the ancestor key. Contradiction is a
   receipt positioned in the splice span, or a receipt whose `sequence` falls
   strictly between the predecessor and successor sequences. Those sequence
   fields impeach; they never grant coverage.

`KeyHierarchy/1.0` is this library's carrier for the section 3.2.1 ancestor
link. It is not a TRACE record type and it is not a wire change for `ca2a`.

## Parser bounds

`parse_untrusted_json` rejects oversize input, duplicate keys, non-finite
numbers, non-integral numbers, integers outside ±(2^53−1), nesting deeper
than 32, and private JWK members (`d`). A malformed signature is
`disclosure_signature_invalid`, not an exception, including a 32-byte value
and non-canonical base64url.

## Corpus

`tests/fixtures/gap-disclosure/` is the twenty-vector corpus from
`trace-spec` `examples/action-receipts/gap-disclosure/`. The tests rebuild
each contrast with signed elements and compare outcome codes to the fixture
oracle. The fixture chain object itself is hostile input: passing it to the
verifier must not produce `receipt_gap_disclosed`.

## Out of scope

- `ca2a_verify.verify_trace_dag` and `cross_check_trace_dag`
- cMCP orphaned-session emission
- manifest binding
- resource-side lease expiry, fencing enforcement, and automatic retry
