# WCM key release → TRACE

Turns a Weight Custody Manifest release decision into a portable, signable TRACE
v0.2 Trust Record. A WCM key broker already decides whether an enclave is
entitled to a model key; this is how it hands somebody the evidence.

## Why the two schemas fit

Both describe the same moment. A WCM release decision and a TRACE Trust Record
each say: this workload, measured this way, under this policy, got this verdict.

| WCM | TRACE | Note |
|---|---|---|
| `weights_hash` | `model.weights_digest` | Same `sha256:<64 hex>` shape, so this is a direct binding |
| `custody.enclave_id` | `subject` | Default only; a non-DID enclave id is refused, not coerced |
| `CpuQuote.platform` | `runtime.platform` | Only when `cpu_quote_verified` passed |
| `CpuQuote.serving_image_measurement` | `runtime.measurement` | The measured workload |
| `CpuQuote.nonce_echo` | `runtime.nonce` | Freshness binding |
| `signing_pre_image(manifest)` | `policy.bundle_hash` | The manifest is the policy |
| `ReleaseDecision.checks` | `appraisal.status` | Derived, never passed in |
| serving image measurement | `build_provenance.digest` | Overridable |

## The three things this gets right, and why they matter

**The platform is derived, not asserted.** An enclave can write `amd-sev-snp`
into a quote it invented. `runtime.platform` names hardware only when the
broker's own `cpu_quote_verified` check passed, meaning the quote was verified
against a trust store. Evidence from `SoftwareProvider`, or a broker where that
check did not run, produces `software-only`. No argument to this module can
override it.

**A refusal is a record.** Pass a decision whose `released` is false and you get
`appraisal.status: contraindicated` with the failed check names listed. A gate
that emits evidence only when it says yes is not an audit trail.

**`policy.bundle_hash` digests the signing pre-image, not the document.** Two
brokers enforcing identical terms produce an identical `bundle_hash` even when
their manifest copies carry different signature sets. Digesting the whole
document would move the hash on every countersignature, and a consumer comparing
records by `bundle_hash` is entitled to assume equal hashes mean equal terms.

## First-party, unlike the third-party adapters

The broker is describing its own gate, so records carry **no `origin` block**:
absence means `self`, and self is the truth. This deliberately does not use
[`agentrust-trace-adapters`](../../packages/agentrust-trace-adapters), which
transcribes somebody else's control plane and is therefore forced to
`origin.kind: third-party-control-plane` and `runtime.platform: software-only`.
Routing a broker's own decision through it would mislabel a first-party record
and discard the hardware platform the broker verified.

## What is not carried across

`UNMAPPED_FIELDS` in the module is the authoritative list. In short:

| WCM field | Why it stays out |
|---|---|
| `GpuReport.platform` | WCM says `nvidia-cc-gpu`; TRACE enumerates specific silicon (`nvidia-h100`, `nvidia-blackwell`) and WCM records no GPU model. Picking one would be a guess about which card ran |
| `required_gpu_measurement.rim_pin` | `runtime.rim_uri` is `format: uri` and expects a fetchable Reference Integrity Manifest. A rim_pin is an opaque identifier |
| `release_terms.license` | Custody terms, not execution evidence, and already bound into `policy.bundle_hash` |
| `MemoryFingerprint.readback_hash` | Describes the host's DRAM, not the workload. Publishing it would leak a physical topology fingerprint into a shareable artifact |

Whether the GPU chain and the memory sweep passed still reaches the record,
through the appraisal check list, where it is a verified fact rather than a
hardware claim.

## Layer 3 records are never attested

`build_custody_record` reports whether the runtime still holds the key.
`SessionState.wiped` produces `contraindicated`: any inference attributed to that
session afterwards did not use those weights.

Its `runtime.platform` is `software-only` without exception. The broker verified
a quote at release time; nothing re-verifies silicon on each lease tick, and
reading a Layer 3 record as continued hardware attestation is the mistake the
field exists to prevent.

The signed, hash-chained `RuntimeRecord` in the WCM SDK is the stronger artifact
for this. It is **not in PyPI 0.26.0**, so this module works from observable
session state today. When the SDK publishes it, a record built from a verified
chain can carry a real appraisal.

## Run it

```bash
pip install weight-custody-manifest agentrust-trace
```

```python
from wcm_to_trace import build_release_record
from agentrust_trace.sign import generate_key, sign_record

decision = kbs.verify_and_release(manifest, evidence)

record = build_release_record(
    manifest=manifest,
    decision=decision,
    evidence=evidence,
    data_class="restricted",
    model_provider="example-labs",   # no source in a manifest, so required
    model_id="example-8b-instruct",
)
signed = sign_record(record, generate_key())
```

`model_provider` and `model_id` are required rather than defaulted. A WCM
manifest binds a weights digest and a builder identity, not a catalogue name, so
there is nothing truthful to default them to.

There is also a CLI for a captured bundle:

```bash
python wcm_to_trace.py manifest.json \
  --evidence evidence.json --decision decision.json \
  --model-provider example-labs --model-id example-8b-instruct
```

The decision file carries the check list only. Key material is dropped on the way
in: a released key has no business travelling through a JSON file to reach an
evidence generator.

## Scope

Records describe what the broker checked. They do not extend WCM's guarantee.
Confidential computing does not hold against an operator who physically owns the
hardware (WCM `SPEC.md` §3.6), and a Trust Record over a WCM release inherits
that boundary unchanged. A `runtime.platform` of `amd-sev-snp` means a quote
verified against a trust store, not that the machine's owner cannot reach the
memory bus.

- Specification and documentation: <https://wcm.agentrust-io.com>
- SDK: <https://pypi.org/project/weight-custody-manifest/>
