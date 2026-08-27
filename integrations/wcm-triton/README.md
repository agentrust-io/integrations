# Attestation-gated model repository staging for NVIDIA Triton

Triton loads models from a model repository directory. This prepares that
directory: obtain the weight key through a WCM key broker, decrypt the model into
a staging path, verify the decrypted bytes hash to what the manifest binds, and
refuse to stage anything that does not.

Triton then starts against a directory whose contents are known good.

## This is not a Triton repository agent, and could not be

Repository agents are C shared objects loaded through the `TRITONREPOAGENT_*`
API. Python cannot provide one.

What Python can do is be the step that runs **before** Triton starts, in an init
container or an entrypoint wrapper, or the process a C agent shells out to.
`build_agent_stanza` emits the `model_repository_agents` block for a deployment
that does have an agent, so both shapes are covered.

## No cipher is chosen here

WCM specifies a manifest, a release protocol and a custody state machine. It does
**not** specify a container format for encrypted weights, and inventing one
inside an integration is how a project ends up with three incompatible dialects
of the same idea.

`prepare_repository` takes a `decrypt(encrypted, staging, key)` callable. The
deployment owns the cipher and the container; this owns the custody decisions
around it:

1. Attest and request release. `decrypt` is never called without a released key.
2. Refuse if the staging directory is not empty, before anything else happens.
3. Call `decrypt`.
4. Hash the result and compare with `weights_hash`.
5. On any failure, remove the staging directory.

## Removal on failure, unlike the Hugging Face gate

[`wcm-huggingface`](../wcm-huggingface) leaves failed downloads on disk, because
they are evidence of what a registry served.

Here the staged files are an intermediate this process just produced, and the
risk that matters is Triton finding them: it scans its model repository, and a
half-written or wrong directory is loadable. So a failure removes it. A
pre-existing non-empty staging directory is refused rather than cleaned, since
those files are not ours to delete.

## One digest recipe, one implementation

`ARTIFACT_DIGEST_RECIPE` is `wcm-artifact-digest/v1`, re-exported from
`wcm.artifact_digest`.

It used to be implemented separately here and in
[`wcm-huggingface`](../wcm-huggingface), kept in step by a test asserting the two
produced identical digests over the same tree. `weight-custody-manifest` 0.27.0
published it, so both now re-export the SDK function and there is nothing left to
drift. The test was replaced by a stronger one: it asserts neither module has a
local implementation, rather than checking that two implementations happen to
agree today.

**Symlinks are refused here, unlike in the Hugging Face gate.** That gate follows
them because a Hub cache is a symlink tree by design. This directory was produced
moments ago by the deployment's own `decrypt` into an empty path, so a link in it
is not a cache layout: it is something the decrypt routine put there, and Triton
would follow it at load time.

## The agent stanza

```
model_repository_agents {
  agents [
    {
      name: "wcm"
      parameters [
        { key: "wcm_weights_hash" value: "sha256:..." },
        { key: "wcm_serving_image" value: "sha256:..." },
        { key: "wcm_custodian" value: "example-custodian" }
      ]
    }
  ]
}
```

The weights hash and current serving-image measurement are passed as parameters,
so a C agent has the two values it needs without parsing the manifest, and a
config that has drifted from its manifest shows up in a diff.

A manifest with more than one `current` serving image is refused rather than
having one picked, because a `config.pbtxt` names one and an arbitrary choice
would be an unreviewed decision sitting in a deployment file.

## Run it

```bash
pip install weight-custody-manifest
```

```python
from wcm_triton import prepare_repository

result = prepare_repository(
    manifest=manifest,
    broker=kbs,
    provider=provider,
    encrypted=pathlib.Path("/models/encrypted"),
    staging=pathlib.Path("/models/repository/mymodel/1"),
    decrypt=my_decrypt,
)
print(result.files_staged, result.computed_digest)
```

Pair it with [`wcm-vllm`](../wcm-vllm)'s `CustodyGuard` if the serving process
also needs a live lease. Staging proves the weights were released to an attested
workload at load time; it says nothing about revocation an hour later.

## Scope

Load-time custody. Confidential computing does not hold against an operator who
physically owns the hardware (WCM `SPEC.md` section 3.6), and once weights are
staged as plaintext in a directory, everything protecting them is the
confidential VM they are inside.

- Specification and documentation: <https://wcm.agentrust-io.com>
- SDK: <https://pypi.org/project/weight-custody-manifest/>
