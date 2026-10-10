# Parmana

[Parmana](https://github.com/pavancharak/parmana) decides whether an agent's action may run under a versioned policy,
requires a signed human approval where the policy says so, and signs a record of every decision, refusals included.

This integration treats those records as TRACE external evidence. Parmana issues no TRACE Trust Record. An agent
runtime that does points at the Parmana record for its step through `references` (trace-spec §3.1.2):

| Parmana decision | Parmana record             | `references` entries                                                   |
| ---------------- | -------------------------- | ---------------------------------------------------------------------- |
| Approved         | Execution Trust Record     | `authorized-intent` to the record; `approval-outcome` to the approval  |
| Refused          | Refusal Record             | `authorized-intent` to the record                                      |

One Parmana record per decision. Each entry's `digest` is `sha256:` over the RFC 8785 canonical form of the complete
object as the resolver retains it. The `approval-outcome` entry points at the signed approval inside the Trust Record
(`#/transaction/signals/approvalArtifact`), because Parmana retains it there, under the Trust Record's own signature.

Parmana signs in its own canonical form, not RFC 8785, and TRACE does not re-sign its records: `parmana_evidence.py`
checks those signatures offline, with Parmana's public key and nothing else.

## Fixtures

`fixtures/` is one run of Parmana's refund evaluation, unedited: a refund through `paytm:refund` under policy
`customer-refund` 1.2.0. `fixtures/report.json` names the commit, Node.js version and time of the run.

| File                                           | What it is                                                                     |
| ---------------------------------------------- | ------------------------------------------------------------------------------ |
| `01-valid-approval.execution-trust-record.json` | Refund with a manager approval for this order up to 500: approved              |
| `02-refusal.refusal-record.json`               | Refund with every caller fact `true` and no approval: refused                  |
| `03-replay.refusal-record.json`                | The approval from 01 sent again with a new request: refused, already used      |
| `approval.json`                                | The manager's signed approval used in 01                                       |
| `parmana-signing-key.json`                     | Parmana's public key for the run, as `GET /keys/default` served it             |
| `approver-key.json`                            | The approver's public key for the run                                          |
| `report.json`                                  | HTTP status, decision and connector calls per case                             |
| `references.json`                              | The `references` entries for each case, written by `examples/emit_references.py` |

Both keys were generated for the run and do not chain to any trusted issuer.

## Running it

```
pip install -e ".[test]"
python examples/emit_references.py
python -m pytest tests
```

`emit_references.py` checks every record's signature, then writes `fixtures/references.json`. The tests check every
signature, that a changed amount, outcome or approval limit no longer verifies, that the approval in 01 is the one the
Trust Record was signed over, that all three decisions name the same policy content hash, and that
`references.json` is exactly what the records produce and validates as `agentrust_trace.Reference`.

To regenerate the fixtures, run `npm run evaluate:agentrust-refund` in a checkout of Parmana and copy
`evaluations/agentrust-refund/fixtures/` and `evaluations/agentrust-refund/report.json` here, then run
`emit_references.py`. A new run makes new keys and identifiers, so it replaces every file.

## What this does not claim

- **No downstream effect.** The connector in the run is a mock, in process. The Trust Record's execution entry records
  the mock's response; it is not a confirmed refund. No entry here is, or may be cited as, `observed-effect`, and
  `report.json` labels every connector result as a mock.
- **Two caller facts are unchecked.** `refundEligible` and `fraudCheckPassed` are declared by the caller and checked
  against no system; under this policy they can only refuse. The signed approval is what authorizes.
- **The policy was not approved through governance in this run.** The run is hermetic, so the Trust Record's
  `transaction.policy.governanceAnchor` reads `NO_APPROVAL_RECORD`.
- **A reference is a pointer, not evidence** (trace-spec §3.1.2 rules 3 and 4). A resolved, matching, verifying
  Parmana record establishes what Parmana decided and signed, not that the decision was right.
- **No TRACE Trust Record and no conformance level.** The runtime's `subject`, `model`, `data_class` and
  `build_provenance` are not Parmana's to state, so this integration fills none of them in.
- **The resolver in `references.json` is an example URL.** A runtime names the Parmana deployment that retains the
  record.

Parmana's server is source available for evaluation; its SDKs, including the `parmana` package these checks use, are
Apache-2.0. Everything in this directory is Apache-2.0.
