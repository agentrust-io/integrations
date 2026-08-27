# WCM to CycloneDX 1.6 ML-BOM

Procurement, licence review and third-party risk all run on BOM tooling. A WCM
manifest carries the facts those processes ask for, and none of it currently
reaches them, because a custody manifest is not a format any of those tools read.

This emits a CycloneDX 1.6 `machine-learning-model` component carrying the
manifest's terms, so a custody agreement shows up where a licence review is
already looking.

## A BOM is a description, not a control

Nothing here is signed by this module, verified by a consumer, or enforced
anywhere. A BOM entry saying weights may not leave the EU does not stop anyone.

It exists so the constraint is visible to the people whose job is to notice it,
and so a deployment inventory and a custody agreement can be diffed rather than
compared by hand.

The manifest's own signatures are what make its terms trustworthy, and they do
not survive this conversion. So `build_component` records the manifest's
canonical hash in an `externalReferences` entry, and says in the comment that the
manifest is the authority. A reviewer who wants the real document can fetch it
and verify it rather than trusting the BOM's summary.

## What is carried

| CycloneDX | From |
|---|---|
| `hashes` `SHA-256` | `weights_hash` |
| `licenses` | `release_terms.license` |
| `bom-ref` | `wcm:<digest>` |
| `properties` under `agentrust:wcm:` | builder, custodian, deployment model, base confidentiality, permitted derivatives and environments, jurisdiction restriction, required platform and tier, tenancy, key release mode, attestation cadence, sovereign profile, rights holders |
| `dependencies` | `derived_from`, when the parent is also in the BOM |

Every property is namespaced, so a consumer can strip them wholesale and nothing
collides with another tool's.

## What is dropped, and why

`UNMAPPED_FIELDS` is the authoritative list. The temptation is to stuff the whole
release policy into `properties` as free text, which produces a BOM that looks
like it carries enforcement semantics and carries strings.

| Field | Why it stays out |
|---|---|
| `required_serving_image` | Launch measurements of an approved serving stack. CycloneDX has no field for "may only execute under these measurements", and a property holding them reads as enforceable |
| `required_gpu_measurement` | Same |
| `custody.kbs_image` | Describes the key broker, not this component. A model's BOM entry should not carry the measurement of an unrelated service |
| `memory_fingerprint_challenge` | A hostile-owner runtime control. Recording it would suggest a procurement process could verify it |
| `signatures` | A BOM carrying a signature over a different document is worse than one carrying none. The manifest hash is the way back to the signed original |

```bash
python wcm_cyclonedx.py --describe-unmapped --name x ignored
```

## shake256 is refused

CycloneDX hash algorithms are an enumerated set with no shake256 member. A
shake256 `weights_hash` raises rather than being recorded under `SHA-256`, which
would make every consumer compare the wrong bytes. Same failure this repository's
[in-toto integration](../wcm-in-toto) guards against, for the same reason.

## Reproducible output

`timestamp` and `serialNumber` are passed through rather than generated, so two
runs over the same manifests produce identical bytes and a BOM can be diffed
across builds. A tool that stamps its own clock makes every rebuild look like a
change.

## Lineage

A derivative's `derived_from` becomes a `dependencies` entry when the parent
manifest is also in the BOM. When it is not, no dangling dependency is emitted
and the parent digest is recorded as a property instead, so the lineage is still
readable without inventing a `bom-ref` for something absent.

## Run it

```bash
pip install weight-custody-manifest

python wcm_cyclonedx.py manifest.json --name example-8b-instruct --version 2026-08 > mlbom.json
```

`--name` and `--version` are required. A WCM manifest identifies weights by digest
on purpose and carries no catalogue name, and a nameless BOM entry is one nobody
can find in a review.

Pass several manifests to get one BOM with lineage resolved between them.

## Scope

Description only. Confidential computing does not hold against an operator who
physically owns the hardware (WCM `SPEC.md` section 3.6), and a BOM has no
bearing on that in either direction.

- Specification and documentation: <https://wcm.agentrust-io.com>
- SDK: <https://pypi.org/project/weight-custody-manifest/>
