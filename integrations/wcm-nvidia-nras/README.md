# NVIDIA GPU attestation to WCM

Turns `nvattest` output into the GPU half of a WCM `CompositeEvidence`, so a
manifest requiring `required_gpu_measurement` can actually be satisfied by a
confidential-compute GPU.

## Two appraisals, deliberately

This is the design point worth understanding before using it.

**NVIDIA's appraisal** checks what only NVIDIA can: that the driver and VBIOS
RIMs fetched from NVIDIA match the reference measurements, that the certificate
chain is live and its OCSP status is good, that the report signature verifies,
and that the nonce binds. That is a rich appraisal against NVIDIA's own reference
data.

**WCM's verification** then independently checks the raw report's certificate
chain, signature and nonce through `wcm.nvidia`. The raw evidence is carried
through in `quote_b64` precisely so that second check has something to check.

Neither replaces the other:

- Trusting only NVIDIA's appraisal means trusting a JWT this process parsed.
- Trusting only WCM's means losing the RIM comparison, which is the part that
  says the GPU is running firmware NVIDIA published.

The adapter's job is to refuse unless the first passed, and to hand the second
its input intact.

## The measurement is an identity, not a hash

`required_gpu_measurement.rim_pin` is a free-form string in WCM, not a
`HashValue`, and this emits:

```
nvidia-rim:arch=HOPPER;driver=580.65.06;vbios=96.00.9F.00.01
```

Deliberate. What a manifest wants to pin on the GPU side is the firmware identity
NVIDIA appraised, and there is no single digest meaning "this driver and this
VBIOS both matched their RIMs". A digest would look stronger and say less.

Build a manifest's pin with `rim_pin()` rather than by hand, so a manifest and an
adapter cannot disagree about spacing or field order and produce a mismatch that
reads as a firmware change. A version string containing `;` or `=` is refused,
because the resulting pin would parse back differently.

## Provenance of the claim list

`REQUIRED_TRUE_CLAIMS` and the certificate claim shapes are those a **real H100
in CC mode** produced under `nvattest --verifier local`. This adapter is promoted
from the WCM repository's validated hardware tooling, not written from
documentation.

Each claim must be exactly `True`. Absent or falsy is a refusal, not a warning:
each is a link in the chain from "a GPU produced a report" to "NVIDIA's published
reference measurements match what this GPU is running". A truthy value such as
`1` or `"yes"` is also refused. A claim NVIDIA renames makes this fail closed,
which is the correct direction.

## Refusals

| Condition | Why it matters |
|---|---|
| Either nonce mismatches | Both documents are checked independently; replay needs only the weaker check to be missing |
| Any required claim not `True` | See above |
| `x-nvidia-mismatch-measurement-records` present | The GPU is not running the firmware whose RIMs were fetched |
| OCSP status not `good`, or a stale OCSP nonce | A revoked certificate still presents a well-formed chain |
| More than one GPU evidence item | A multi-GPU host produces one report per device and a manifest pins one. Adapting several would silently pick one and claim it covered them all |
| Malformed raw evidence | WCM would have nothing to verify independently |

## Run it

```bash
pip install weight-custody-manifest

NONCE=$(openssl rand -hex 32)
nvattest --format=json collect-evidence --device gpu --nonce $NONCE > evidence.json
nvattest --format=json attest --device gpu --verifier local --nonce $NONCE > appraisal.json

python wcm_nvidia.py --nonce $NONCE --evidence evidence.json --appraisal appraisal.json
```

The nonce must be the WCM challenge nonce, 32 bytes of hex. As a library:

```python
from wcm_nvidia import adapt

gpu = adapt(evidence_doc, appraisal_doc, challenge.nonce)
evidence = CompositeEvidence(cpu=cpu_quote, gpu=gpu)
```

`nvattest` is not a Python dependency and this module does not shell out; it
takes parsed documents, so the adapter is testable without a GPU and the same
code path runs whether the documents came from a local run or a captured bundle.

## Scope

GPU firmware appraisal and report verification. A GPU attestation says the device
is in CC mode running appraised firmware. It says nothing about an operator who
physically owns the machine, where confidential computing does not hold (WCM
`SPEC.md` section 3.6), and published memory-bus attacks reach GPU-adjacent
memory as well as CPU memory.

- Specification and documentation: <https://wcm.agentrust-io.com>
- SDK: <https://pypi.org/project/weight-custody-manifest/>
