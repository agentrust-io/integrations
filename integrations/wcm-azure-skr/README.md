# WCM → Azure Managed HSM Secure Key Release

Azure SKR is the same shape as WCM Layer 2. A key marked exportable carries a
release policy; a confidential VM gets an attestation token from Microsoft Azure
Attestation; Key Vault checks the token's claims against that policy and returns
the key wrapped to the TEE's public key. Nobody who cannot produce a conforming
token gets the key.

A WCM `release_policy` and an SKR release policy are two encodings of one intent.
This translates between them, and maps a verified MAA claim set into WCM
`CompositeEvidence` so the broker's own checks can run over the same attestation.

## The measurement mapping, which this module refuses to guess

**WCM's `HashValue` is strictly 256-bit**: `sha256:<64 hex>` or
`shake256:<64 hex>`. **An SEV-SNP launch measurement is 384-bit**, 96 hex
characters, reported by MAA as `x-ms-sevsnpvm-launchmeasurement`.

A WCM `accepted_measurements` entry therefore *cannot* be an SNP launch
measurement. It will not fit the type. On Azure the WCM path binds a SHA-256
PCR 23 digest instead (`wcm.azure_vtpm`), which is a different value from a
different chain.

Emitting `x-ms-sevsnpvm-launchmeasurement equals <64-hex value>` produces a policy
that never matches, and an engineer debugging it reasonably concludes the CVM is
broken. The plausible "fix" is to widen the manifest's measurement field, which
breaks the binding the WCM broker relies on.

So `build_release_policy` **requires** `measurement_claim`, naming which MAA claim
carries the value your manifest's measurements were computed against. Width is
checked at generation time:

```
SkrPolicyError: measurement sha256:5e2d... has 64 hex characters but
x-ms-sevsnpvm-launchmeasurement carries 96. These are values from different
chains; comparing them would produce a policy that never matches. On Azure the
WCM path binds a SHA-256 PCR 23 digest (see wcm.azure_vtpm), which is not the
SNP launch measurement.
```

`x-ms-sevsnpvm-hostdata` is 64 hex and is the usual answer, since host data is
where a deployment puts a workload-chosen binding value.

To generate a policy without workload binding, pass `--allow-unbound-workload`.
The result carries an `x-wcm-note` saying it enforces nothing about the workload,
and the CLI prints a warning to stderr. Any compliant CVM attesting to that
authority can then obtain the key; the manifest's measurements are enforced only
by the WCM broker.

## Claims

Only SEV-SNP claims Microsoft documents for MAA are emitted. `MAA_CLAIMS` is the
list, and a claim not in it is refused, because a policy referencing a claim MAA
does not issue never matches and presents as a broken CVM rather than as a policy
error.

```bash
python wcm_azure_skr.py --describe-claims --authority https://... ignored
```

TDX maps to `x-ms-attestation-type: tdxvm` and gets the compliance-status
condition. Its measurement claim names are **not asserted here** and must be
supplied like any other.

`nvidia-cc-gpu` has no attestation-type value: MAA's CVM attestation describes
the virtual machine, and there is no claim meaning "the GPU is in CC mode". GPU
binding stays with the WCM broker's GPU check, and a GPU-only requirement raises.

## What the manifest maps to

| WCM | SKR condition |
|---|---|
| `required_hw_platform: [amd-sev-snp]` | `x-ms-attestation-type equals sevsnpvm` |
| `required_assurance_tier: hardware-attested` | `x-ms-compliance-status equals azure-compliant-cvm` |
| (always, on SNP) | `x-ms-sevsnpvm-is-debuggable equals false` |
| `accepted_measurements`, status not `revoked` | one `anyOf` branch per measurement |
| `authority` | pinned on every branch |

`retiring` measurements are **included**. WCM's release rule is prefer-current
rather than refuse-retiring, and a policy that dropped them would take a fleet
offline during a rollover.

A debuggable guest can be inspected by the host, which defeats the
software-adversary half of WCM's guarantee before any key moves. Pass
`--allow-debuggable` to drop that condition deliberately.

`authority` is required. A release policy with no pinned authority accepts a
token from any attestation service, including one an attacker stood up.

## `evidence_from_maa_claims` does not verify anything

It takes a claims **mapping**, not a JWT, precisely so it cannot be mistaken for
a verifier. No signature check, no JWKS fetch, no issuer validation.

**Verify the token before calling it.** Feeding it unverified claims produces
evidence that looks hardware-attested and is not, which is the worst outcome
available in this file.

It does refuse claim sets that cannot support the tier: an unknown attestation
type, a compliance status other than `azure-compliant-cvm`, or a debuggable
guest.

## Run it

```bash
pip install weight-custody-manifest

python wcm_azure_skr.py manifest.json \
  --measurement-claim x-ms-sevsnpvm-hostdata \
  --authority https://sharedeus.eus.attest.azure.net > skr-policy.json

az keyvault key create --exportable true --policy skr-policy.json ...
```

## Scope

SKR gates key release on an Azure-issued attestation token. That is a real
control against a software adversary and against a remote attacker. It is not a
control against an operator who physically owns the hardware: confidential
computing does not hold there (WCM `SPEC.md` §3.6), and an attestation service
verifying a forged quote issues a genuine token over it.

- Specification and documentation: <https://wcm.agentrust-io.com>
- SDK: <https://pypi.org/project/weight-custody-manifest/>
