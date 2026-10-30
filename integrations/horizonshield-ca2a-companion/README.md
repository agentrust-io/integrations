# MUSUBI companion for cA2A

An offline verifier for evidence that sits around cA2A delegation chains. It
reads one bundle: an append-only log whose entries are signed by the log's
operator, a checkpoint of that log anchored in a Bitcoin block header by a
merkle proof, a view of block headers, and the relying party's trust
configuration. The log items are cA2A revocation statements (unchanged, type
`ca2a.delegation-revocation.v1`), issuer-signed use limits, holder-signed
credential-use items, responder-signed execution receipts, and commit and
reveal items. The verifier first checks the log, then judges each receipt with
`ca2a_runtime.delegation.verify_chain` and cA2A's own revocation check, and
reports a disposition per receipt and a result per commit-reveal session. It
adds no field to any cA2A object and does not reimplement cA2A's delegation
rules; a cA2A refusal is reported with cA2A's own error code.

It covers four things cA2A's documents say cA2A does not do; it replaces no
cA2A check.

This directory runs the companion's profile v0 against the released
[ca2a-runtime 0.4.0](https://pypi.org/project/ca2a-runtime/0.4.0/). The
specification, the reference verifier and the vector generator live in
[horizon-shield at 05b4924](https://github.com/ogasurfproject-jpg/horizon-shield/tree/05b4924254ebf3c7a5c4523bb2f2fd74ff22b61a/workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0)
([COMPANION_v0.md](https://github.com/ogasurfproject-jpg/horizon-shield/blob/05b4924254ebf3c7a5c4523bb2f2fd74ff22b61a/workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0/COMPANION_v0.md)
is the normative text).

## Pinned to ca2a-runtime 0.4.0, and why

The at-execution verdict calls a private function,
`ca2a_runtime.delegation.credential._check_revocation`. It is used so that
every revocation the log published before a receipt is in force for that
receipt, whatever the revoker wrote in `issued_at`: the chain is checked with
`verify_chain(..., revocations=None)` at the receipt's logged time, then
`_check_revocation(chain, snapshot, at_time=None, now=logged_at,
max_staleness=None)` runs over a snapshot built from the revocations logged
before the receipt. The public `verify_chain(..., revocations=snapshot)`, with
every revocation in the log, is also run and reported beside it as
`ca2a_audit`; it applies revocations by their `issued_at`.

A private function can change in any release without notice, so this entry is
pinned to `ca2a-runtime==0.4.0`. The public call it needs, a chain evaluated
against a caller-supplied set of revocations taken as in force, is requested in
[agentrust-io/ca2a#263](https://github.com/agentrust-io/ca2a/issues/263). When
that ships, the companion switches to it and this entry drops the pin.
`test_the_private_ca2a_call_this_entry_is_pinned_for` fails if the private
function moves or changes its signature.

The schema's `tested_against` block has no `ca2a-runtime` key, so the exact run
is recorded in a comment in `integration.yaml` and pinned in `pyproject.toml`.

## Run it

Against released packages, from the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e "integrations/horizonshield-ca2a-companion[test]"
pytest integrations/horizonshield-ca2a-companion/tests -q
```

Expected: `83 passed`. Python 3.11 or later. No network access is
needed after installation; the Bitcoin headers in the vectors are a regtest
difficulty test chain built by the generator, not mainnet.

The companion's own self-test, run directly:

```bash
MUSUBI_DIR="$(python -c 'from nenrin_verify import musubi; print(musubi.MUSUBI_DIR)')"
PYTHONPATH="$MUSUBI_DIR" python integrations/horizonshield-ca2a-companion/vendor/ca2a-companion-v0/companion_v0.py --selftest
# 57/57 vectors agree
```

## What is in this directory

| Path | What it is |
|---|---|
| `vendor/ca2a-companion-v0/companion_v0.py` | the reference verifier, unchanged |
| `vendor/ca2a-companion-v0/gen_vectors.py` | the vector generator, unchanged; it builds and signs every credential and revocation with ca2a-runtime |
| `vendor/ca2a-companion-v0/vectors/vectors.json` | 45 settlement vectors and 12 evidence vectors, unchanged |
| `tests/test_ca2a_companion_gaps.py` | all 57 vectors grouped by the gap they exercise, named cases per gap, and the check on the private call |
| `tests/test_ca2a_companion_vendored.py` | the vendored files' SHA-256 against the source commit, the CLI self-test, and a byte for byte rebuild of the vectors with ca2a-runtime |

The three vendored files are byte for byte the files at horizon-shield commit
`05b4924254ebf3c7a5c4523bb2f2fd74ff22b61a`:

| File | SHA-256 |
|---|---|
| `companion_v0.py` | `a6e2b2c9d920eda65723e1d863e8e108df642c6b3ece8b40499726bfc425a781` |
| `gen_vectors.py` | `2904a9310bb8f32d9efd808e1fea0a9cb38d7145c54002b684ebd7946adac005` |
| `vectors/vectors.json` | `4b4e2362ab6dda3743e5ba1cd76285a0872344f40086bc95b18b3bd34490d2a2` |

`companion_v0.py` imports `settle_v1_1` (the Bitcoin header view check and the
anchor proof). It is not copied here: the released
[nenrin-verify 0.5.6](https://pypi.org/project/nenrin-verify/0.5.6/) ships it
byte for byte from the same repository, and the tests load it with
`nenrin_verify.musubi.load`. nenrin-verify is published by the same vendor.

## The four cases

Each case is one gap cA2A names in its own documents
([LIMITATIONS.md](https://github.com/agentrust-io/ca2a/blob/806d1147c0bc834ee8aabb698b341c926cd8531e/LIMITATIONS.md),
[failure-modes.md](https://github.com/agentrust-io/ca2a/blob/806d1147c0bc834ee8aabb698b341c926cd8531e/docs/spec/failure-modes.md),
[response-authentication.md](https://github.com/agentrust-io/ca2a/blob/806d1147c0bc834ee8aabb698b341c926cd8531e/docs/spec/response-authentication.md),
[ROADMAP.md](https://github.com/agentrust-io/ca2a/blob/806d1147c0bc834ee8aabb698b341c926cd8531e/ROADMAP.md)).
Vector ids refer to `vectors/vectors.json`.

### 1. Revocation publication

cA2A does not publish or fetch revocation data, and a snapshot supplier can
withhold a statement. Here revocations are log entries, each signed by the
operator when it accepts them, and the `RevocationSnapshot` handed to cA2A is
built from the log.

What the tests show:

- The evidence holds: a revoker holding its signed entry and a checkpoint that
  includes it gets `kept` (EV03); two checkpoints of one log are `consistent`
  (EV01).
- A checkpoint whose `as_of` covers a promised entry but whose size stops short
  of it gives `operator_withheld` (EV11). A different entry at that position, or
  two checkpoints of one size with different heads, give
  `operator_equivocation` (EV04, EV02). Both functions check the supplied
  entries against the checkpoint first, so whoever supplies the entries cannot
  steer the result (EV06 to EV10).
- A log with an entry removed under an unchanged checkpoint is refused
  (`size_mismatch`, CA18); a rewritten entry, a checkpoint re-signed after
  anchoring, too few confirmations and an `as_of` after the anchor are refused
  (CA17, CA19 to CA21).
- A revocation of the leaf or of an ancestor logged before the receipt makes
  cA2A's own revocation check fail at execution (`CREDENTIAL_REVOKED`,
  `executed_after_published_revocation`; CA04, CA28), also when the revoker
  dated it after it was logged (CA22, CA33, CA45, flagged as
  `revocation_dated_after_logging`).
- A revocation dated before the execution but logged after it is reported as
  `late_revocation_only`, with cA2A's audit verdict beside it (CA05). A
  revocation signed by the leaf's own subject has no authority in cA2A and does
  not apply (CA06).

What it does not show: that the operator accepted every revocation it was
sent. An operator that refuses an entry gives the submitter no signed entry,
and nothing here proves the refusal. v0 is one operator's log with no
independent witnesses. A verifier relies on the operator's signature alone
until the checkpoint is anchored and confirmed.

### 2. Single use across requests

cA2A's offline verifier has no used-credential database, so its checks do not
establish single use across requests. Here a holder-signed credential-use item
carries its whole chain and names its responder, and an issuer-signed use limit
counts every distinct pair of request and responder among the uses of a
credential, under any chain that contains it.

What the tests show:

- A single-use credential used once is `within_delegation` (CA01); the same use
  logged twice counts once (CA31).
- A second use gives `use_limit_exceeded` whether it is a second request
  (CA02), the same request sent to a second responder (CA43), a use under a
  credential delegated onward (CA32), or a use under a re-issued ancestor with
  the same `credential_id` (CA44).
- A limit only counts when signed by that hop's issuer (CA27) and logged before
  the receipt (CA37); the tightest limit applies (CA26). A receipt with no use
  logged before it is outside (CA11, CA12); a use logged for one responder does
  not cover another (CA35).

What it does not show: prevention. Single use is prevented only for a relying
party that logs the use and waits for the operator's signed entry before
acting. Otherwise the second use is detected after the fact. The operator
orders the log.

### 3. Portable execution receipts

cA2A's response MAC can be checked only by the live caller and does not sign
the execution lineage. Here a receipt is signed with the responder's Ed25519
key and names the caller, the lineage, the capability, the digest of the
request occurrence, a Bitcoin block the responder had seen, and the outcome
(result, denial or ack).

What the tests show:

- A denial followed by a result for one request gives two receipts and no
  duplicate (CA16).
- A receipt whose outcome was changed after signing is rejected
  (`signature_invalid`, CA14). A second result for one request occurrence is
  `duplicate_execution` (CA03).
- A receipt is bound to its request and to the leaf: a supplied request naming
  another responder (CA15), a caller who is not the leaf subject (CA10) and a
  capability outside the leaf's scope (CA39) are outside. A receipt logged more
  than two hours before its seen block is outside (CA40); a seen block the view
  does not hold, or a lineage with no chain, is `unassessed` (CA41, CA13). A hex
  field with a trailing newline is rejected (CA34).

What it does not show: that the work was done, or done correctly. A receipt is
the responder's signed statement. It does not show that the responder key
lives in a TEE or belongs to the attested workload; `attestation_sha256` only
carries the digest of the evidence the caller appraised. Times between the seen
block and the anchoring block are the operator's.

### 4. A commitment step

cA2A's roadmap says simultaneous attestation needs a commitment step neither
peer can back out of. Here commit and reveal items belong to a session whose
identifier is the hash of its participants and a nonce.

What the tests show:

- Every participant commits before any reveal, and every reveal opens its
  commitment: `simultaneous` (CA23). A key outside the participants cannot
  spoil the session (CA38).
- A reveal logged before another participant's commit (CA24), or a reveal that
  does not open its commitment (CA25), gives `simultaneous: false` with the
  problem named.

What it does not show: anything about the attestation evidence itself, which
is only carried as a digest. It does not force a participant to reveal; a
participant that walks away leaves the session not simultaneous, and that is
all the log shows.

### Not a gap: cA2A's own rules

Seven vectors check that cA2A's verdicts pass through unchanged and that input
is handled without a crash: scope escalation, an untrusted root, expiry at log
time and a forged hop signature give `outside_delegation:<cA2A code>` (CA07,
CA08, CA09, CA29); a forged second copy of a chain does not displace the copy
that verifies (CA36); an unknown item type is rejected by name (CA30); a
malformed trust configuration is refused, not raised (CA42).

## What this entry does not claim

- It does not emit or consume TRACE records.
- It makes no hardware or confidential-computing claim.
- The vectors, the verifier and its specification have one author, the
  maintainer of this entry. They are not an independent implementation.
- The log is public: keys, chains, request digests, capabilities and outcome
  kinds are visible to anyone who reads it.
- v0 is a hash chain, so a verifier reads the whole log.

## Conformance CI

`.github/workflows/horizonshield-ca2a-companion-conformance.yml` runs the tests
on Python 3.11, 3.12 and 3.13 in two modes: `fixed` installs this entry with its
pins, `floating` installs the latest ca2a-runtime release. It runs on changes to
this directory and weekly.
