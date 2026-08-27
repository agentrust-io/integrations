# Hugging Face Hub → WCM download gate

Refuses a model snapshot whose bytes do not hash to the `weights_hash` a
jointly-signed Weight Custody Manifest binds. The manifest travels as an ordinary
file at the repository root, so nothing about the Hub has to change and no
private index is involved.

## Layer 1 only, and that matters

This answers one question: are these the weights the builder shipped, under terms
the builder and custodian both signed.

It is **not** Layer 2. Nothing here is attested, no key is released, and a public
Hub repository is not an enclave. A manifest published this way should normally
carry `base_confidentiality: open`, because the bytes are downloadable by anyone
and calling them confidential would be false on its face. If a manifest does say
`confidential`, the gate still passes but attaches a note saying a public
distribution channel cannot provide that.

What you do get: a swapped or tampered checkpoint is refused **before** it
reaches a loader, and the licence and derivative terms are bound into a signature
rather than sitting in a README nobody diffed.

## Pin an immutable revision

`guarded_snapshot_download` requires a 40-character commit sha. A branch or tag
resolves to whatever it points at today, so verifying a snapshot fetched from
`main` establishes that something on main matched at some moment, which nobody
can re-check later.

Pass `allow_mutable_revision=True` to accept the weaker claim deliberately. The
result then carries a note recording that you did.

## The digest recipe

`ARTIFACT_DIGEST_RECIPE` names it: `wcm-artifact-digest/v1`.

Files sorted by POSIX relative path. For each: the length-prefixed relative path,
then the 8-byte big-endian file size, then the contents. Length prefixing is what
stops two different directory layouts flattening into the same byte stream, so
renaming a shard changes the digest.

Hub bookkeeping (`.cache`, `.git`, `.huggingface`) is excluded, because it
differs between two caches holding byte-identical weights. The manifest sidecar
excludes itself: a manifest cannot bind a digest computed over a directory
containing that manifest.

This is the same construction the [WCM
examples](https://github.com/agentrust-io/examples/tree/main/weight-custody-manifest)
use for a real open-weight model. It is duplicated here because it is not part of
the published SDK. **It belongs in the SDK**, and a third dialect of it is the
thing to avoid; anyone needing it again should promote this one rather than write
another.

A digest mismatch names the recipe in its failure message for exactly this
reason. If a builder hashed only the weight shards and you hashed the whole
directory, the weights are fine and the inventory is not, so pass `include=` with
the exact list the builder used before concluding anything was tampered with.

## Two failures, kept apart

`verify_snapshot` never raises on a mismatch. It returns a result with two
independent facts:

| Field | Failure means |
|---|---|
| `signatures_verified` | The manifest's joint signatures did not verify against keys you trust. The terms are not the ones you think |
| `computed_digest` vs `expected_digest` | The bytes are not the ones those terms cover |

A signature failure short-circuits: there is no point hashing several gigabytes
under terms you do not trust, so `computed_digest` is `None`.

On a failed download the files are **left in place**, not deleted. Destroying
them would destroy the evidence of what was served, which is what an
investigation needs.

## Run it

```bash
pip install weight-custody-manifest huggingface_hub
```

```python
from wcm_hf_guard import guarded_snapshot_download

path, result = guarded_snapshot_download(
    "org/model",
    context,                       # a wcm.VerificationContext with the keys you trust
    revision="<40-char commit sha>",
)
```

It raises `GuardError` rather than returning weights that failed. Already have a
snapshot on disk?

```python
from wcm_hf_guard import verify_snapshot

result = verify_snapshot(path, context, revision=commit_sha)
if not result.ok:
    raise SystemExit(result.reason)
```

`verify_snapshot` needs no `huggingface_hub`, so verification works in an
air-gapped environment holding a copied snapshot.

CLI, which exits non-zero on refusal:

```bash
python wcm_hf_guard.py org/model --revision <sha> --key builder.pub --key custodian.pub
python wcm_hf_guard.py ./snapshot --local --key builder.pub --key custodian.pub
```

## Publishing side

Put the manifest at the repository root as `wcm.manifest.json`, with
`weights_hash` computed by `artifact_digest` over the inventory you intend to
bind, excluding the manifest itself.

## Scope

Integrity and provenance against software and remote adversaries. Confidential
computing does not hold against an operator who physically owns the hardware (WCM
`SPEC.md` §3.6), and this integration does not reach that far in any case: it
verifies bytes at rest and has nothing to say about what happens after a loader
reads them.

- Specification and documentation: <https://wcm.agentrust-io.com>
- SDK: <https://pypi.org/project/weight-custody-manifest/>
