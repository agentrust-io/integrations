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
python xchk_trace_record.py record.json                     # verifies with the key the resolver publishes under the record's kid
python xchk_trace_record.py record.json --jwk examples/expected.json   # offline, with a pinned key
```

It verifies the record with released `agentrust-trace` against a pinned key, or against the key the record's
resolver publishes under the record's `kid`. It never verifies against the key the record itself carries, because a
self-signed record always passes that. It prints the key source and lists the `approval-outcome` references as
they appear; it does not resolve them.

## Run it

```
pip install -e "integrations/xchk-registry[test]" agentrust-trace-tests
pytest integrations/xchk-registry/tests -q                          # offline; REGISTRY_LIVE=1 adds one live key fetch
trace-tests verify --record integrations/xchk-registry/examples/01-trust-record.json --level 0
```

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
