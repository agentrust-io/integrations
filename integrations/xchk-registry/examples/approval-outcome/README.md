# xChk sealed receipts as `approval-outcome` references

A TRACE Trust Record can point at the human decision an act was taken under. These
fixtures show that composition with the sealed receipts of an xChk registry
(<https://in.xchk.io>): the record carries a `references` entry with
`rel: "approval-outcome"` whose `id` is the receipt's record hash, and the registry
serves the receipt as a bundle at `/api/receipt/<id>/bundle` that verifies offline with
no network and no shared secret, down to the approver's own passkey assertion.

Full mapping and rationale:
[`CROSSWALK.md`](../../CROSSWALK.md).

Every record here was minted and signed by the registry at `in.xchk.io` for one run of
plate `ENG-WNP3` on 18 October 2026 (`expected.json` names the run and the signing key),
by `scripts/trace-fixtures.js`, part of the registry's own code (not public), which also
fetched each bundle from the public receipt endpoint and made the altered copies. It is not
run here, because the registry is not a dependency of this repository; its record of each
case is `expected.json`.
[`tests/test_approval_outcome_fixtures.py`](../../tests/test_approval_outcome_fixtures.py)
re-verifies all of it on every run without xChk: the TRACE signatures with this
repository's library, each reference digest with `rfc8785`, and each bundle with
`verify_receipt.py`, the registry's standard-library-only offline verifier, vendored one level up
as the registry serves it at <https://in.xchk.io/verify/verify_receipt.py> (MIT, per its header; listed in
`NOTICE`). Run with no extras, the verifier checks the Ed25519 half of each registry
signature and reports the ML-DSA-65 half as pending, so "bundle verifies" here means no
check failed and the Ed25519 signatures passed.

## Fixture cases

Expected results are machine-readable in [`expected.json`](expected.json). Every record
verifies as a TRACE record; what differs is what the reference resolves to and whether the
bundle it resolves to still verifies.

| Record | Bundle | Reference | Digest | Bundle verifies | Disposition | Verdict |
|---|---|---|---|---|---|---|
| `01-approval-confirmed.json` | its own | resolves | matches | yes | `approved` | approval confirmed |
| `02-bundle-altered-after-issue.json` | `record.summary` edited after issue | resolves | **differs** | **no** (record hash) | `approved` | approval contradicted |
| `03-decision-is-a-denial.json` | its own | resolves | matches | yes | `denied` | not an approval |
| `04-no-answer.json` | an ask nobody answered | resolves | matches | yes | `expired` | not an approval |
| `05-reference-unresolvable.json` | none | **no such receipt** | n/a | n/a | n/a | approval unconfirmed |
| `06-assertion-from-another-credential.json` | the approver's key and assertion replaced by another key's | resolves | matches | **no** (binding names a different key) | `approved` | approval contradicted |
| `07-amended.json` | its own; the sealed record commits to `decision.amendment.command` | resolves | matches | yes | `approved` | approval confirmed, as amended |
| `08-assertion-over-another-ask.json` | the approver's assertion from another approval in the run | resolves | matches | **no** (the challenge the device signed names another ask) | `approved` | approval contradicted |

`02`, `06` and `08` are the same approval as `01` with the served bundle changed afterwards; the
Trust Record is identical and still verifies, because the record is a pointer and the
tampering is on the thing pointed at. In `06` the assertion is a valid ECDSA P-256
signature by a key that is not the one the registry's signed binding names for this
credential: an impersonated approver. A verifier that checks the assertion against the
key the bundle offers, and not against the key the binding names, passes it; the bundle's
own `howToVerify` step 5 and the vendored verifier both require the two to be equal.

In `08` everything about the approver is genuine: the credential is the one the binding
names, the signature verifies with that key, the user was verified. The assertion is the
same person's answer to a different ask in the same run. What tells the two apart is the
challenge the device signed: since 18 October 2026 the registry derives it from the ask
(`approver.challenge`, rule `ask-v1`: the attestation id, the prompt the person saw, the
digest of the action's parameters), and the verifier recomputes it from the bundle's own
`decision` block. A bundle from before that date carries no `challenge`; the verifier
reports that step as pending and the registry's binding is then the only pairing.

`05` is what spec section 3.1.2 rule 3 requires: a verifier must not reject a record
because a reference cannot be resolved. The record verifies, and the approval it points at
is reported as unconfirmed, which is a different answer from "no approval".

`03` is a declined ask and `04` an ask nobody answered within its life: both verify, both
are on the record, neither is an approval. `07` was approved with changes. What makes it
so is not the readable `decision.amendment` block, which is unsigned text: the sealed
record's `paramsHash` is the registry's action-binding digest over the *amended* command
(here with the record's own tool and summary, which a short summary keeps exactly; the
registry now serves the binding itself as `amendment.boundAs`), so the Merkle chain
commits to it, and the
amendment's `originalParamsHash` is the digest the person's passkey signed over in the
ask-v1 challenge. The verifier checks both and the test recomputes the digest with
`rfc8785`. An amendment typed into `01` after issue, or `07`'s amended command edited
after issue, fails those checks and the approval is contradicted, never "as amended". The
person's signature covers the ask as proposed; the amendment's scope rests on the
registry's seal, and a relying party that needs the person's own signature over the
amended text does not have it in this bundle (see the cross-walk's boundary).

## Running the checks

```
pytest integrations/xchk-registry/tests -q
```

Regeneration is the registry operator's: the generator runs on the registry with the seal
key and writes this directory. A new run points at new receipts and replaces every file.
