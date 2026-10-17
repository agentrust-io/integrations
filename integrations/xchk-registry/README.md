# xChk registry integration with TRACE

An xChk registry licenses AI agents under a verified person and seals a record of each gated act, with the
person's own passkey assertion on the acts they answered. This integration is the relying party's side of the
[`xchk-sealed-receipts` crosswalk](https://github.com/agentrust-io/trace-spec/pull/560): it takes a Trust
Record the registry minted, resolves each `approval-outcome` reference to the sealed receipt it names, and
recomputes what may be concluded about the approval, offline, with the registry's own standard-library verifier.

## What the registry produces

- **A Trust Record per run**, software-only (Level 0, `origin` absent: the gate is in the execution path),
  signed with the registry's seal key, whose `cnf.jwk.kid` is the key id published at
  `https://in.xchk.io/.well-known/xchk-keys.json`. One `approval-outcome` reference per act a person was asked
  about, approved or not. Route: `GET /api/agents/<id>/runs/<runSeq>/trace-record` (plate owner's token).
- **A receipt bundle per record**, at `GET /api/receipt/<recordHash>/bundle` (public): the record, its Merkle path to
  the registry's seal, the seal's hybrid signatures and published keys, the Ravencoin anchor when confirmed, and,
  when a person answered, the approver block: the WebAuthn assertion, the credential's public key, the registry's
  signed binding of that credential to a named, identity-proofed person for that record, and (ceremonies from
  18 October 2026) the ask the device signed over, from which the challenge is recomputed.

## What this code does

```
python xchk_trace.py record.json                               # key from the resolver's published keys; references resolved there
python xchk_trace.py record.json --bundle bundle.json --jwk examples/expected.json   # offline
```

1. Verifies the Trust Record with released `agentrust-trace` against a key the relying party trusts: one pinned with `--jwk`, or the key the record's resolver publishes at `/.well-known/xchk-keys.json` under the record's `kid`. The record's own `cnf.jwk` is used only with `--allow-embedded-key` and reported as *self-consistent*, never as verified, because a self-signed record always passes against its own key.
2. For each `approval-outcome` reference, fetches `<resolver>/api/receipt/<id>/bundle`, or uses a saved one.
3. Canonicalizes `bundle.record` with RFC 8785 and compares the digest with the reference.
4. Runs `examples/verify_receipt.py` on the bundle as a subprocess: record hash, Merkle path, seal hash, registry
   signatures, the assertion (ECDSA P-256, `webauthn.get`, user verified), the binding (names this record, this
   credential, this public key), the challenge (sha256 over the ask, recomputed from the bundle's `decision`
   block), the anchor when present.
5. Reports a verdict per reference: `approval-confirmed`, `approval-confirmed-as-amended`, `not-an-approval`,
   `approval-contradicted`, or `approval-unconfirmed` when the reference does not resolve (the record stands,
   spec section 3.1.2 rule 3).

`examples/` holds one record and two bundles from a live run: the approval as served, and the same person's
assertion from a different approval placed in it (every key and signature genuine; the challenge names another
ask). `tests/` recomputes both verdicts from the committed bytes and runs the CLI offline; set `REGISTRY_LIVE=1` to
also resolve the reference at the registry.

## Run it

```
pip install -e "integrations/xchk-registry[test]"
pytest integrations/xchk-registry/tests -q
trace-tests verify --record integrations/xchk-registry/examples/01-approval-confirmed.json --level 0
```

## What it does not claim

- **Ordering.** A Trust Record is issued per execution and carries no commitment that the approval was checked
  before the act ran; the registry's gate holds the act until the ask is answered, but that claim is the gate's,
  not the record's. `authorized-intent` through the PIC bridge is the relation for a pre-execution authorization.
- **That the executed act is the approved one.** `record.paramsHash` binds the ask to the parameters the gate
  saw; comparing that with what a runtime executed is the runtime's job.
- **Hardware.** Nothing here is attested; `runtime.platform` is software-only and `appraisal` is none.
- **Policy or person.** `basis` says which rule asked and `authLevel` how the person was proofed; whether either
  suffices is the relying party's policy.
- **Bundles from before 18 October 2026** carry no `approver.challenge`; the verifier reports that step as pending
  and the registry's binding is then the only thing pairing the assertion with the record.
- The registry's server code is not public; what is public is the receipt endpoint, the published keys, the
  verifier and the fixtures. Regenerating fixtures is the registry operator's.

Maintained by the registry operator (see `integration.yaml`). Personal research project.
