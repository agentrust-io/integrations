# agentrust-trace-adapters

Build TRACE Trust Records from evidence another system produced, without fabricating what is not there.

## Why this exists

An adapter over someone else's runtime governance product is worth building for one reason: it states, in a form a machine can read, exactly what that evidence is worth next to a hardware-attested record. A record built here carries three signals a consumer can key on without reading prose:

| Field | Value | Meaning |
|---|---|---|
| `origin.kind` | `third-party-control-plane` or `log-import` | Something else produced the evidence; this record was assembled from it |
| `runtime.platform` | `software-only` | No hardware root. TRACE 0.7.0 rejects any other platform when `origin.kind` is not `self` |
| `appraisal.status` | `none` | Nobody appraised the evidence. Transcribing is not appraising |

None of the three is a parameter. An adapter that could set them would eventually set them wrong.

If the source separately produces a signed appraisal result, use
`AppraisalEvidence` / `appraisal_from_evidence` only after verifying that
signature. The contract requires a named verifier and appraisal-policy
reference. A vendor's bare ALLOW/DENY result is still a policy decision, not an
appraisal of the evidence behind that decision.

That argument only holds if the rest of the record is true, which is the harder half.

## The failure this package prevents

Before it existed, this repository contained one vendor-to-TRACE adapter. Its output failed `TrustRecord` validation on seven counts:

```
model.weights_digest      'sha256:placeholder-no-model'
runtime.platform          'software-simulated'          (not in the enum)
runtime.measurement       'sha384:000...000'
tool_transcript.hash      't1'                          (not a hash at all)
build_provenance.digest   'sha256:placeholder'
```

Five of those are the same mistake: a required-shaped field with nothing real to put in it, so a placeholder went in. Nothing in CI noticed, because nothing validated the output.

So every constructor here takes **bytes, not names of bytes**, and raises `MissingEvidence` rather than degrading:

```python
digest_bytes("policy-v1.2")     # TypeError: hashing a description of bytes is not a digest
digest_bytes(b"")               # MissingEvidence: the digest of nothing is a valid-looking hash of an absence
PolicyEvidence(bundle=b"")      # MissingEvidence: needs the policy bundle bytes
build_record(..., workload_digest=None)  # MissingEvidence: nothing truthful to default it to
```

A record nobody can build is a truthful outcome. A record full of placeholders is not.

## Use

```python
from agentrust_trace_adapters import PolicyEvidence, SourceSystem, build_record

record = build_record(
    source=SourceSystem(
        producer="vendor-gateway/2.1",
        source_event_id="evt-7f3a",
    ),
    subject="spiffe://example.org/agent/support-bot",
    model_provider="anthropic",
    model_id="claude-sonnet-4-6",
    # The policy bytes your deployment enforces. Most control planes do not put
    # the bundle in their telemetry; that is not a reason to hash something else.
    policy=PolicyEvidence(bundle=open("policy.cedar", "rb").read()),
    data_class="internal",
    workload_digest="sha256:...",   # the image or artifact the producer reports
    jwk=public_jwk,
)
```

Signing is not here. It belongs to `agentrust_trace.sign`, and an adapter that both assembles and signs invites a caller to skip looking at what it assembled.

## Two questions worth answering before you write an adapter

**Does the producer expose the policy bundle it enforced?** If not, you supply it: an operator knows the policy it runs even when its vendor's export does not carry it. If nobody can produce those bytes, the record cannot honestly carry a `policy.bundle_hash`, and it should not be built.

**Does the producer report the artifact it ran?** `build_provenance.digest` is required by the schema and there is nothing truthful to default it to.

If both answers are no, the finding is that the evidence does not support a Trust Record. That is a result, not a blocker to route around.

## What `runtime.measurement` means here

It is a deterministic digest over the identifying inputs (producer, subject, policy bundle hash), not a hardware measurement. The schema requires the field and there is no measurement to put in it; the same shape as the sandbox adapter in `agentrust-trace`. Two records over the same inputs agree, a changed input is visible, and `platform: software-only` carries the fact that nothing measured it.

## Tests

26 tests, one per way a record could validate and still be untrue, including two that parse the built record with the real `TrustRecord` model. That last pair is what the previous adapter did not have.

## Licence

Apache-2.0.
