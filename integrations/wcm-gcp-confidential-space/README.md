# WCM to GCP Confidential Space

Confidential Space runs a container in a confidential VM and hands it an OIDC
attestation token from Google's Attestation Verifier. A Workload Identity Pool
provider carries a CEL attribute condition over that token's claims, and only a
workload whose token satisfies the condition can impersonate the service account
that decrypts with Cloud KMS.

That is WCM Layer 2 in Google's encoding. This generates the condition.

## Here the measurement mapping actually works

Confidential Space identifies the workload by `submods.container.image_digest`,
which is an OCI image digest: `sha256:` plus 64 hex characters. A WCM `HashValue`
is exactly that shape.

So if a manifest's `accepted_measurements` were computed as container image
digests, the condition compares like with like and no impedance mismatch exists.

Compare [`wcm-azure-skr`](../wcm-azure-skr), where a 256-bit WCM measurement and
a 384-bit SNP launch measurement cannot be compared at all, and the generator has
to refuse. The difference is worth knowing when choosing where to deploy.

**That "if" is real and is not hidden.** The generated command carries a comment
saying the manifest's measurements are being read as OCI image digests and that a
manifest built some other way produces a condition which never matches. A
measurement that is not `sha256:<64 hex>` is refused with that reason.
`--measurement-claim` overrides the claim when a deployment binds workload
identity differently.

## What the condition enforces

| Clause | From |
|---|---|
| `assertion.swname == "CONFIDENTIAL_SPACE"` | Always |
| `hwmodel` in the mapped set | `required_hw_platform` |
| `"STABLE" in support_attributes` | Default; `--support-attribute` overrides |
| `assertion.dbgstat == "disabled-since-boot"` | Default; `--allow-debuggable` drops it |
| image digest in the accepted set | `accepted_measurements`, excluding `revoked` |

`disabled-since-boot` rather than merely "not currently debuggable". A guest that
was debuggable at any point since boot may have been inspected, which is the
software adversary WCM's guarantee is against.

`STABLE` is the only support attribute appropriate for a production custody
deployment. The others mark images that may change behaviour without notice.

Retiring measurements are kept, revoked ones dropped, and a manifest whose
measurements are all revoked is refused rather than turned into a condition that
denies everything.

## Confirm `hwmodel` against your own tokens

`HWMODEL_BY_PLATFORM` maps WCM platforms to the values a Confidential Space token
is expected to carry. It is overridable, and worth confirming before pinning: a
condition naming a value your tokens do not carry denies every request and looks
like a broken attestation verifier.

```bash
python wcm_gcp_cs.py ignored --print-claims token-payload.json
```

## CEL is generated, not concatenated

Every literal in the condition is a validated digest, a claim path matching a
dotted-identifier pattern, or a value from a fixed set. This expression decides
who can decrypt model weights; building it from unvalidated input would be an
injection into that decision. There are tests that try.

## `evidence_from_cs_claims` does not verify anything

It takes a claims **mapping**, not a JWT, so it cannot be mistaken for a
verifier: no signature check, no JWKS fetch, no issuer validation. Verify the
token first. Unverified claims here produce evidence that looks hardware-attested
and is not.

It does refuse claim sets that cannot support the tier: a non-Confidential-Space
`swname`, an unmapped `hwmodel`, or a `dbgstat` other than `disabled-since-boot`.

## Run it

```bash
pip install weight-custody-manifest

python wcm_gcp_cs.py manifest.json \
  --project-number 123456789012 \
  --pool wcm-pool \
  --provider confidential-space
```

That prints the `gcloud iam workload-identity-pools providers update-oidc`
invocation with the condition attached. `--condition-only` prints just the CEL
for use in Terraform.

`--project-number` is the numeric project number, not the project id: workload
identity pool resource names use the number, and passing the id produces
resources that do not resolve.

## Scope

The condition gates who may assume an identity, based on a Google-issued
attestation token. Real against a software adversary and a remote attacker. Not a
control against an operator who physically owns the hardware, where confidential
computing does not hold (WCM `SPEC.md` section 3.6), and where an attestation
service verifying forged evidence issues a genuine token over it.

- Specification and documentation: <https://wcm.agentrust-io.com>
- SDK: <https://pypi.org/project/weight-custody-manifest/>
