# WCM custody lifecycle → OpenTelemetry

Emits key release decisions and runtime custody state as ordinary OTel spans and
metrics, so they land in whatever the deployment already runs.

A broker refusing a release and a runtime wiping a key after a lease lapse are
the two events an on-call engineer most needs to see and currently cannot. Today
they surface as an inference service that stopped working.

## Telemetry is not evidence

Spans are unsigned. Anything holding the collector endpoint can write one, an
exporter reports what it chose to report, and a dropped span is
indistinguishable from an event that did not happen.

Nothing here is a custody record. When you need an artifact to hand a third
party, use [`wcm-trace`](../wcm-trace), which produces a signed TRACE record over
the same decision. Run both: they answer different questions, and this one
answers "is the fleet healthy" rather than "can you prove it".

## The attributes are ours, not upstream conventions

OpenTelemetry's GenAI semantic conventions cover model calls and have no
vocabulary for weight custody, key release or lease state. Rather than bend
`gen_ai.*` attributes into meanings their authors did not give them, everything
lives under `wcm.*`.

`ATTRIBUTES` in the module is the full reference, and a test asserts that nothing
is emitted which is not listed there. An attribute added without a description
fails the build rather than shipping as a field nobody can interpret under
pressure.

```bash
python wcm_otel.py --describe manifest.json
```

If OTel later defines custody conventions, this should adopt them and keep
`wcm.*` as aliases for a release or two.

## The claim and the check are both exported

`wcm.evidence.cpu.platform` is what the quote **claimed**.
`wcm.evidence.cpu.verified` is whether the broker checked it.

Both, always. A dashboard showing only the first would present a claim as a fact,
and the gap between them is exactly what an operator needs when a fleet starts
failing closed.

## What never becomes an attribute

`NEVER_EXPORTED` enumerates it: key material sealed or otherwise, weight bytes,
nonces, the transport public key, raw quotes, memory readback hashes.

`_assert_safe` checks attribute **names** before every emission, because the
realistic failure is somebody adding an attribute in good faith rather than
smuggling a key out deliberately. A test greps a fully populated span for the
literal nonce and quote bytes.

Telemetry backends are not custody boundaries.

## Cardinality

Metrics carry a deliberately narrow attribute set. `wcm.weights.hash` and
`wcm.manifest.hash` are high-cardinality by design, since they change whenever
anything changes, and putting them on a counter creates one time series per
manifest revision. That is the classic way to take a metrics backend down.

They stay on spans, where cardinality is not a billing event.

| Signal | Carries |
|---|---|
| `wcm.release` span | Everything, including hashes |
| `wcm.custody` span | Everything, including hashes |
| `wcm.release.decisions` counter | Outcome, builder, custodian type, platform, verified flag |
| `wcm.custody.wipes` counter | Same narrow set |
| `wcm.release.duration` histogram | Same narrow set |

## Run it

```bash
pip install weight-custody-manifest opentelemetry-api
```

```python
from wcm_otel import CustodyInstrumentation

telemetry = CustodyInstrumentation()

# times the broker, emits the signals, returns the decision unchanged
decision = telemetry.observe_release(kbs, manifest, evidence)

# and periodically, from the lease loop
telemetry.record_custody(manifest, session)
```

`observe_release` returns the decision unwrapped and unaltered. Telemetry that
could change a release outcome would be a security control masquerading as
observability, and this is not one.

Already have a decision in hand?

```python
telemetry.record_release(manifest, decision, evidence, duration_seconds=elapsed)
```

Every method is a no-op when `opentelemetry` is not installed, so a library that
instruments itself with this does not force the dependency on its users. The
attribute builders stay pure functions either way, which is how the tests assert
on exactly what would be exported without running a collector.

## Refusals are error spans

A refused release sets span status `ERROR` with the failed check names in the
description, so a dashboard does not need to parse a message to group them. A
wiped session does the same.

A refusal is the gate working correctly. It is an error span because it is what
an operator is looking for, not because something is broken.

## Scope

Observability over WCM's decisions. It changes nothing about WCM's guarantee, and
confidential computing does not hold against an operator who physically owns the
hardware (WCM `SPEC.md` §3.6). An operator who can forge a quote can also forge
the span reporting it.

- Specification and documentation: <https://wcm.agentrust-io.com>
- SDK: <https://pypi.org/project/weight-custody-manifest/>
