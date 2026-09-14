# CHAP integration with TRACE

[CHAP](https://github.com/BrightbeamAI/chap), the Collaborative Human-Agent Protocol,
records a person approving, rejecting or overriding an agent's draft in a hash-linked
workspace audit log. This integration lets a TRACE Trust Record cite that decision,
and lets a relying party check the citation.

`chap_trace.approval_reference` turns a CHAP `audit.read` entry into the `references`
entry trace-spec v0.2 section 3.1.2 registers for this, `rel: "approval-outcome"`:

```json
{
  "rel": "approval-outcome",
  "id": "audit/9",
  "resolver": "https://chap.example.org/workspaces/wsp_refund_review",
  "retention": "P1Y",
  "digest": "sha256:<SHA-256 of the RFC 8785 form of the decision envelope>"
}
```

`chap_trace.check_approval` takes that reference and an exported CHAP log, and returns
one of four verdicts: `approval-confirmed`, `approval-contradicted` (digest or chain
does not match), `not-an-approval` (for example a `decide.reject` at that position),
or `approval-unconfirmed` (no entry). `chap_trace` imports nothing from CHAP: it
recomputes the digest with `rfc8785` and replays CHAP's `audit-scitt/1.0` chain,
`sha256(JCS(envelope) || prev_hash)`, itself.

## Run it

Against released packages:

```bash
pip install -e "integrations/chap[test]"    # agentrust-trace, rfc8785, chap-coordinator, trace-tests
pytest integrations/chap/tests -q
python integrations/chap/examples/emit_record.py --out trust-record.jwt
trace-tests verify --record trust-record.jwt --level 0
```

`emit_record.py` runs a CHAP review workspace through `chap-coordinator`, cites the
approval from a signed Level 0 Trust Record, verifies the signature, and checks the
reference against CHAP's log before writing the record.

## What is verified

- On every envelope CHAP writes in the test workspace, `rfc8785` and CHAP's own
  canonicalizer produce the same digest, and the chain replay reaches the head
  `audit.verify_chain` reports. This is what makes the digest portable between the
  two implementations.
- A rejection is never cited as an approval, and an override only when the caller
  opts in with `accept_override=True`. A reference without a resolver is refused, per
  section 3.1.2 rule 4.
- Each verdict has a test against a live coordinator: a confirmed approval, one edited
  after the reference was made, a rejection in the approval's place, an override with
  and without opt-in, a missing entry, and a chain head that does not match.
- The record signature covers the reference: changing the digest makes
  `agentrust_trace.verify_record` raise `InvalidSignature`.
- `trace-tests verify --level 0` passes on the emitted signed record, including the
  Ed25519 signature check.
- `examples/generate_trace_spec_fixtures.py` produces the fixture set committed in
  trace-spec at `examples/chap-approval-outcome/`, and a test runs it and checks all
  four verdicts, so that set's generator is exercised against CHAP on every run.

## What it does NOT claim

See rules 2 and 5 in [CONTRIBUTING.md](../../CONTRIBUTING.md).

- **`trace-tests` does not grade `references`.** Level 0 checks the envelope,
  signature and policy fields. The approval check is `check_approval`, exercised by
  this integration's tests.
- **A reference is a pointer, not evidence.** A Trust Record verifies whether or not
  its reference resolves (section 3.1.2 rule 3), and a resolved reference is not
  attested evidence.
- **It does not enforce the approval before the action runs.** A Trust Record is
  issued per execution. The component that runs the action has to refuse to act
  without a matching approval; the record then cites the approval it acted under.
- **It does not bind the executed action to the approved draft.** CHAP's
  `approved_artefact_digest` names the draft a decision settled. Comparing that with
  the call actually made is the enforcing component's job.
- **It does not establish who wrote the CHAP log.** The test workspace runs without
  CHAP's `security-signed/1.0`, so envelopes are unsigned and the chain shows
  consistency with the exported head, not authorship.
- **`runtime.platform` is `software-only`.** The example record's `model`, `policy`,
  `data_class` and `build_provenance` are fixed example values; in a real deployment
  they come from the governed run, not from CHAP. The ephemeral key does not chain to
  a trusted issuer.

## Conformance CI

[`.github/workflows/chap-conformance.yml`](../../.github/workflows/chap-conformance.yml),
scoped to this directory, runs two jobs on Python 3.11 to 3.13. `fixed` pins the
versions in `integration.yaml` plus `chap-coordinator` 0.2.13. `floating` installs the
latest releases of all three as drift detection. Each runs the tests, emits a record,
and runs `trace-tests verify --level 0`.
