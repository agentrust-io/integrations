# WCM as an OCI referrer artifact

Attaches a Weight Custody Manifest to a model artifact in a registry using the
OCI Referrers API (image spec v1.1). The model's own digest never moves, so
custody terms can be attached after publication without invalidating anything
downstream.

`artifactType: application/vnd.agentrust.wcm.manifest.v1+json`

## The digest-domain problem

This is the whole difficulty, and it is the same shape as the trap in
[`wcm-kyverno`](../wcm-kyverno).

An OCI `subject` descriptor names a **registry manifest digest**: the hash of the
model artifact's JSON manifest. WCM's `weights_hash` covers the **weight bytes**.
Different numbers, different bytes, and no registry can derive one from the
other. A registry stores blobs and does not know that one of them, decompressed,
is a safetensors shard.

So a referrer carrying only a subject digest proves the custody manifest was
attached to a particular registry object. It does **not** prove that object
contains the weights the manifest binds.

`verify_referrer` reports this as `weights_binding`, a string with three values,
never a bare boolean:

| Value | Meaning |
|---|---|
| `layer-digest` | A subject layer descriptor's digest equals the bound `weights_hash`. The strongest form available without unpacking |
| `annotation-only` | The referrer records the weights hash but no layer digest matches. The binding rests on whoever pushed it. Useful, not proof |
| `unbound` | Nothing connects this custody manifest to those bytes. Treat as unverified |

**To reach `layer-digest`, publish the weights as a single uncompressed layer
whose digest is the bound hash.** A compressed or multi-layer artifact lands on
`annotation-only`, which is the normal case and why the result explains itself in
`notes` rather than just failing.

`trusted` requires `layer-digest`. `annotation-only` may well be good enough for
a given deployment, and a caller is free to decide that, but the decision has to
be taken explicitly rather than inherited from a property that quietly accepted a
weaker binding.

## Verification checks

| Check | Failure |
|---|---|
| `artifactType` | Raises. Another referrer may legitimately be attached to this model; it is not a custody manifest |
| Blob digest vs layer descriptor | Raises. The referrer and blob did not come from the same push |
| Layer count and size | Raises |
| `subject` vs `expected_subject_digest` | Reported as `subject_matches` |
| Manifest joint signatures | Reported as `manifest_verified` |
| Weights binding | Reported as `weights_binding` |

Omitting `expected_subject_digest` is treated as a **failed** subject match, not
a skipped check. Without it the referrer is "a custody manifest, from somewhere",
and the result says exactly that.

If the `org.agentrust.wcm.weights-hash` annotation disagrees with the embedded
manifest, the manifest wins and a note records the disagreement, because a
referrer assembled by something that did not read the document it carries is
worth knowing about.

## Reproducible builds

Two builds of the same manifest produce byte-identical output. `created` is
passed through rather than defaulted to the current time: a timestamp injected
here would break reproducibility for no benefit, since a registry records push
time anyway.

The layer descriptor is computed over the exact bytes `build_referrer` returns.
A caller that re-serializes the manifest before pushing will produce a digest
mismatch at the registry, so push the bytes it hands back.

## Run it

```bash
pip install weight-custody-manifest

python wcm_oci.py build manifest.json \
  --subject-digest sha256:<model manifest digest> \
  --subject-size 1234 \
  --out-dir ./referrer
```

That writes `referrer.json` and `wcm.manifest.json`. Push with `oras`, `crane`,
or any client that supports referrers.

```bash
python wcm_oci.py verify referrer.json \
  --blob wcm.manifest.json \
  --expect-subject sha256:<the model you are pulling> \
  --subject-manifest model-manifest.json \
  --public-key builder.pub --public-key custodian.pub
```

`--subject-manifest` is the model's own OCI manifest. Without it the best
achievable result is `annotation-only`, and the tool says so rather than leaving
you to wonder. Exit code is non-zero unless `trusted`.

## Scope

Distribution-time binding. No attestation, no key release: a registry is not an
enclave. Confidential computing does not hold against an operator who physically
owns the hardware (WCM `SPEC.md` §3.6), and nothing here reaches that far in any
case.

- Specification and documentation: <https://wcm.agentrust-io.com>
- SDK: <https://pypi.org/project/weight-custody-manifest/>
