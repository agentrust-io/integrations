# Agent Manifest to WCM model identity binding

An Agent Manifest declares what an agent is, and artifact #4, `model_identity`,
names the model it runs on. For a `confidential-inference` deployment the spec
requires `model_hash` and `model_attestation_type: hash-bound`. A Weight Custody
Manifest binds exactly that digest as `weights_hash`.

## The grammars agree exactly

Both SDKs define `HashValue` as `(sha256|shake256):<64 lowercase hex>`. The value
transfers with no conversion, no re-hashing and no width problem, which is not
true of most pairs in this repository (see [`wcm-azure-skr`](../wcm-azure-skr)
for the opposite case).

`hash_grammars_agree()` asserts the two patterns are **identical** rather than
merely similar, and `model_identity_from_wcm` calls it. A future divergence
surfaces as a refusal at binding time rather than as a value that silently fails
to validate somewhere downstream.

## What a matching digest does and does not mean

It means the two documents describe the same weights.

It does **not** mean the agent obtained those weights under custody. An Agent
Manifest is signed at deployment and says what the agent is. Whether a key was
ever released to an attested workload is a WCM Layer 2 fact belonging to the
broker, and whether it is still authorized is Layer 3.

An agent whose `model_hash` matches a WCM manifest is an agent making a checkable
claim about which weights it runs. That is worth having, and it is a smaller
claim than "custody was enforced".

`verify_binding` returns three independent facts rather than a boolean:

| Field | Meaning |
|---|---|
| `digest_matches` | The Agent Manifest names the digest this WCM manifest binds |
| `deployment_type_is_custodial` | `local` or `confidential-inference`, so holding weights is meaningful |
| `hash_bound` | Declared `hash-bound`, not `provider-asserted` |

The combined property is called `describes_the_same_weights`. At length, on
purpose: it is not `verified`, `trusted` or `custody_enforced`, none of which
follow from two documents carrying the same digest, and a shorter name would
invite a caller to read one of them into it. There is a test asserting those
names are absent.

## API deployments are a category error here

`api` and `third-party-api` must have a null `model_hash`, because the weights
are the provider's and the caller never holds them. Pairing a custody manifest
with one is not a configuration choice, so `model_identity_from_wcm` raises
rather than emitting something that cannot mean what it says.

## Signatures are still yours to check

`verify_binding` does not verify the Agent Manifest's own signatures. That is
`agent_manifest.verify_manifest`'s job and answers a different question. Run
both: an unsigned Agent Manifest naming the right digest proves only that
somebody wrote the right digest down.

It takes a plain document rather than a parsed object, so it works on a manifest
fetched as JSON without the Agent Manifest SDK installed, and so a document
failing validation for unrelated reasons can still be checked for this property.

## Run it

```bash
pip install weight-custody-manifest agent-manifest
```

```python
from wcm_agent_manifest import model_identity_from_wcm, verify_binding

binding = model_identity_from_wcm(
    wcm_manifest,
    provider="example-labs",       # no source in a WCM manifest, so required
    model_id="example-8b-instruct",
    version="2026-08",
)

result = verify_binding(agent_manifest_document, wcm_manifest)
if not result.describes_the_same_weights:
    raise SystemExit(f"{result.agent_model_hash} != {result.wcm_weights_hash}")
```

`builder.identity` is deliberately not used to default `provider`. It names who
signed the custody terms, which is frequently not who publishes the model under a
product name.

## Scope

Two documents agreeing. Confidential computing does not hold against an operator
who physically owns the hardware (WCM `SPEC.md` section 3.6), and a matching
digest in an Agent Manifest changes nothing about that.

- WCM: <https://wcm.agentrust-io.com>
- Agent Manifest: <https://pypi.org/project/agent-manifest/>
