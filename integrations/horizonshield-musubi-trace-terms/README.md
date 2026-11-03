# MUSUBI trace terms

`musubi-trace-terms-v0` reads TRACE evidence about an agent's tool calls and
judges it against what two parties agreed. Its inputs are one bundle: an
`a2a-contract-v0` both parties signed, a terms annex both parties signed
(agreed authorizer keys, a map from TRACE tool names to contract actions,
per-action and total call counts, and optionally the runtime they agreed on),
the authorizer public keys, and one item per executed call. Each item holds an
act the contractor signed, the PIC/TRACE authorization
(`tag:agentrust-io.com,2026:pic-trace-bridge-v1`) with its tool call,
declaration and transcript, and optionally the Trust Record the act names. The
output is a verdict per call and overall: `within_terms`, `outside_terms`,
`undetermined` or `refused`.

TRACE checks one call against one authorization; this adds up all the calls
under one two-party contract.

The evaluator does not reimplement TRACE. Each authorization is checked by
`agentrust_trace.intent_bridge.verify_bridge` from the released
[agentrust-trace 0.11.0](https://pypi.org/project/agentrust-trace/0.11.0/), at
the time the contractor states the call ran. TRACE objects are read unchanged
and digested as TRACE digests them (RFC 8785).

The specification, the evaluator and the vector generator live in
[horizon-shield at 05b4924](https://github.com/ogasurfproject-jpg/horizon-shield/tree/05b4924254ebf3c7a5c4523bb2f2fd74ff22b61a/workers/hs-ledger/nenrin/trace-terms-v0)
([SPEC.md](https://github.com/ogasurfproject-jpg/horizon-shield/blob/05b4924254ebf3c7a5c4523bb2f2fd74ff22b61a/workers/hs-ledger/nenrin/trace-terms-v0/SPEC.md)
is the normative text).

## Pinned to agentrust-trace 0.11.0

The evaluator calls TRACE's own `verify_bridge`, so the agentrust-trace
release is part of every verdict, and the 55 vectors were built and are checked
against 0.11.0. This entry pins `agentrust-trace==0.11.0`. The evaluator also
records the version it ran against in its output and adds the finding
`agentrust_trace_not_the_pinned_version` under any other release.

The JSON Schema shipped in agentrust-trace 0.11.0 is older than the schema on
trace-spec main; this is tracked upstream in
[agentrust-io/trace-spec#591](https://github.com/agentrust-io/trace-spec/issues/591).
Every result in this directory is against the 0.11.0 release. None of it is a
statement about trace-spec main.

## Run it

Against released packages, from the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e "integrations/horizonshield-musubi-trace-terms[test]"
pytest integrations/horizonshield-musubi-trace-terms/tests -q
```

Expected: `75 passed`. Python 3.11 or later. No network access is needed after
installation.

The evaluator's own self-test and CLI, run directly:

```bash
MUSUBI_DIR="$(python -c 'from nenrin_verify import musubi; print(musubi.MUSUBI_DIR)')"
PYTHONPATH="$MUSUBI_DIR" python integrations/horizonshield-musubi-trace-terms/vendor/trace-terms-v0/trace_terms_v0.py --selftest
# === 55 / 55 (musubi-trace-terms-v0) ===
PYTHONPATH="$MUSUBI_DIR" python integrations/horizonshield-musubi-trace-terms/vendor/trace-terms-v0/trace_terms_v0.py check bundle.json
# exit 0 within_terms, 1 outside_terms, 2 refused, 3 undetermined
```

## What is in this directory

| Path | What it is |
|---|---|
| `vendor/trace-terms-v0/trace_terms_v0.py` | the evaluator, unchanged |
| `vendor/trace-terms-v0/vectors/vectors.json` | the 55 vectors, unchanged |
| `tests/test_trace_terms_vectors.py` | all 55 vectors against their expected results, and named cases |
| `tests/test_trace_terms_vendored.py` | the vendored files' SHA-256 against the source commit, the CLI self-test and exit codes, and `trace-tests verify --level 0` on the two consumed Trust Records |
| `NOTICE` | attribution for the two Trust Records the vectors carry |

The two vendored files are byte for byte the files at horizon-shield commit
`05b4924254ebf3c7a5c4523bb2f2fd74ff22b61a`:

| File | SHA-256 |
|---|---|
| `trace_terms_v0.py` | `5fbd7dd7a8d7313973673f2b0593c8b06f7f9f5c01381daf95c8faa81853e069` |
| `vectors/vectors.json` | `a636029b66d66768fbf37ea4e7a61ef0035548d6b0cc407b4c0830a43ac0d38a` |

The evaluator imports `contract_v0` (MUSUBI's contract verifier),
`agreement_verify` (the canonical form and Ed25519 check) and
`nenrin_verify.trace` (the Trust Record intake). They are not copied here: the
released [nenrin-verify 0.5.6](https://pypi.org/project/nenrin-verify/0.5.6/)
ships them byte for byte from the same repository, and the tests load them
with `nenrin_verify.musubi.load`. nenrin-verify is published by the same
vendor. The vector generator is not vendored, because it reads the source
records from horizon-shield; the horizon-shield workflow rebuilds the vectors
byte for byte.

## Where the evidence in the vectors comes from

Every authorization is signed by agentrust-trace's own `sign_bridge`. Two
Trust Records are real records copied unchanged from
[agentrust-io/trace-registry](https://github.com/agentrust-io/trace-registry)
(CC BY 4.0, see `NOTICE`): the summit demo record and a Bernstein 3.20.0
record. Both pass `trace-tests verify --level 0` with agentrust-trace-tests
0.6.2, which this entry's tests run. Other records are signed in the vectors by
agentrust-trace's `sign_record`. Every other key is a test key derived from a
fixed label.

## What the tests show

Each line is a case a per-call check cannot see, shown by a vector:

| Vector | Result |
|---|---|
| TT01 | three calls, each allowed by TRACE, inside the grant and the counts, on the agreed runtime: `within_terms` |
| TT02, TT03 | every call allowed, the third one more than the parties agreed: `calls_exceed_terms` |
| TT04 | the bridge scope includes the tool and TRACE allows it; the contract prohibits the action: `prohibited_action` |
| TT07 | TRACE verifies the bridge under the supplied key; the principal never agreed to that authorizer: `authorizer_not_agreed` |
| TT08 to TT10 | TRACE's `verify_bridge` refuses (deny, expired, mismatch): reported by kind, with `executed_without_valid_authorization` |
| TT12 | one authorization carried two calls: `authorization_reused` |
| TT15, TT16 | the real Bernstein record outside the runtime the parties agreed, and inside terms that agreed on exactly that runtime |
| TT11, TT36, TT43 | whoever assembles the bundle swaps evidence or withholds a key: `undetermined`, never `outside_terms` |
| TT25 | terms signed by one party only: `refused` |
| TT41 | no acts at all: `undetermined`, not `within_terms` |

The rule behind every code: an act is outside the terms only on what the
contractor signed and on signatures nobody else can forge.

## What a verdict does not establish

From SPEC.md section 8:

- Anything about acts that were not presented. An act the contractor never
  signed, or signed and withheld, is not counted.
- That `executed_at` is true. The contractor states it, within the bridge's
  window and the record's age.
- That a grant or an authorizer key was not revoked. Revocations are not read.
- That the runtime which ran the call is the one in the Trust Record the
  contractor names, or that any Trust Record claim is true. Nothing here
  appraises a hardware attestation.
- That the PIC intent and argument digests are what PIC would compute.
- Liability, fault, or that the contract is a legal agreement.

Clauses this profile does not judge (conditional grants, amount limits,
approval policies, parent contracts, evidence or recovery requirements) make
the bundle `refused`, not judged as if absent (TT47, TT48, TT52, TT53).

## What this entry does not claim

- It emits no Trust Record. TRACE Level 0 is claimed only in the sense stated
  in `integration.yaml`: the Trust Records it consumes pass Level 0.
- The evaluator, its specification and its vectors have one author, the
  maintainer of this entry. They are not an independent implementation.

## Conformance CI

`.github/workflows/horizonshield-musubi-trace-terms-conformance.yml` runs the
tests on Python 3.11, 3.12 and 3.13 in two modes: `fixed` installs the versions
in `tested_against` with this entry's pins, `floating` installs the latest
agentrust-trace and agentrust-trace-tests releases. It runs on changes to this
directory and weekly.
