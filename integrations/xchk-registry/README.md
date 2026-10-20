# xChk registry: a Trust Record per run

An xChk registry licenses AI agents under a verified person and gates each act. This integration covers one thing:
the Trust Record the registry mints for each run, and how a relying party verifies it against the key the registry
publishes.

## What the registry produces

A software-only TRACE v0.2 Trust Record per run, Level 0:
- `subject`: the plate as a `did:web` identifier under the registry's origin.
- `origin` absent (the gate is in the execution path, not a copy of someone else's telemetry);
  `runtime.platform: software-only`; `appraisal.status: none`.
- `tool_transcript`, `policy`, `model`, `data_class`, `build_provenance` as the registry recorded them for the run.
- `references`: one `approval-outcome` entry per act a person was asked about (approved or not), with `id` and
  `digest` the registry's record hash and `resolver` the registry origin.
- `cnf.jwk`: the registry's seal key, Ed25519, with `kid` the key id the registry publishes.

Route: `GET /api/agents/<id>/runs/<runSeq>/trace-record` with the plate owner's token. The signing key is published
at `https://in.xchk.io/.well-known/xchk-keys.json`.

## What this code does

```
python xchk_trace_record.py record.json --registry https://in.xchk.io   # verifies with the key that registry publishes under the record's kid
python xchk_trace_record.py record.json --jwk examples/expected.json     # offline, with a pinned key
```

It verifies the record with released `agentrust-trace` against a pinned key, or against the key published under the
record's `kid` at `<origin>/.well-known/xchk-keys.json`, where the origin is the registry the relying party trusts,
given out of band with `--registry`. Nothing in the record supplies the origin: not its `resolver` and not its
`did:web` subject, because a record signed under a publisher of its own choosing names that publisher in both,
and agreeing with itself is not a trust anchor. The record's subject and resolver must agree with the origin given.
Without `--registry` or `--jwk` the answer is `no-key`. It never verifies against the key the record itself carries,
for the same reason. `--registry` must be an https origin and nothing more (no credentials, path, query or
fragment; an explicit port 443 is the same origin as none). When `--registry` is given beside `--jwk`, both are enforced: the
pinned key verifies the signature, and the record's subject and every `approval-outcome` resolver must be under
the origin, compared as origins. The fetch is https only, follows no redirect, reads at most 256 KB, and a key document of the wrong
shape is no key, never a crash; the same holds for a record file or pinned-key file of the wrong shape, and for any
field of the record: every input ends in a JSON verdict and an exit code. A verified result carries the verified
`profile` and the complete `accepted_profiles` set (section 3.3), the thumbprint of the key actually used, `kid`
(the key the record names) and `pinned_kid` when a pinned key named one, the key source and the trusted origin, and
lists the `approval-outcome` references as they appear; it does not resolve them.

The record's age is bounded: `iat` may be at most `--max-age` seconds old, default 86400 (24 hours, the library's
default and section 3.2.2's), and the bound cannot be switched off. A retained record is re-verified at its own time
with `--now <epoch seconds>` rather than by widening the bound; every verdict carries `verified_at`, the instant it
was made against, and `verified_at_overridden`, so a historical verdict is never the same JSON as a current one. The output carries `revocation` as the library
reported it; this tool passes no revocation bundle or store, so it reports `no_check_performed`, which is not an
affirming appraisal (section 3.2.3). A stale or tampered record is `invalid`, with the reason.

## Run it

```
pip install -e "integrations/xchk-registry[test]" agentrust-trace-tests
pytest integrations/xchk-registry/tests -q                          # offline; REGISTRY_LIVE=1 adds one live key fetch
trace-tests verify --record integrations/xchk-registry/examples/01-trust-record.json --level 0 --max-age 315360000
```

The example record was minted on 17 Oct 2026, so the conformance command above carries an explicit `--max-age`
(ten years, the same as the workflow), as a historical fixture must; the verifier's own default stays 24 hours.

## What it does not claim

- **Nothing about what a reference resolves to.** An `approval-outcome` reference is a pointer the registry is
  obliged to keep resolvable (spec section 3.1.2); what the referenced receipt establishes, and how to check it, is a
  separate integration, not this one.
- **No hardware.** The record is software-only and unappraised, and says so in its own fields.
- **No ordering claim.** A Trust Record is issued per execution; it does not carry a commitment that an approval was
  checked before the act ran.
- The registry's server code is not public. What is public is the record route, the key document and this
  example.

Maintained by the registry operator (see `integration.yaml`). Personal research project.
