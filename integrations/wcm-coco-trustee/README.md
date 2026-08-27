# WCM to Confidential Containers Trustee

Trustee is the key broker the confidential-containers project ships, and the one
an open confidential-computing deployment is most likely already running. A
workload asks for a resource by URI, the Attestation Service verifies evidence
and issues a token, and a Rego policy decides whether that token entitles the
caller to the resource.

That is WCM Layer 2 with different nouns. This generates the Rego and the
resource layout the model key should live at.

## Prefer the vTPM path

| WCM platform | Bare metal | Cloud CVM (default) |
|---|---|---|
| `amd-sev-snp` | `snp` | `azsnpvtpm` |
| `intel-tdx` | `tdx` | `aztdxvtpm` |

The vTPM names are the default, and not arbitrarily. A WCM `HashValue` is
256-bit. An SEV-SNP launch measurement and a TDX MRTD are both 384-bit, so a Rego
rule comparing a WCM measurement to one of them denies every request while
looking entirely correct. The vTPM path reports TPM PCR digests, which are
256-bit and therefore fit.

That is the configuration where WCM and Trustee compose without an impedance
mismatch. `--bare-metal` selects the raw names when a deployment genuinely needs
them.

## The claim path cannot be inferred

`--measurement-path` is required: the dotted path into the token claims holding
the value your manifest's measurements were computed against, for example
`tcb_status.azsnpvtpm.tpm.pcr04`.

Which claim that is depends on how the manifest was built. Guessing produces a
policy that denies everything, and the operator debugging it looks at the
attestation service rather than at the policy.

Widths are checked where known (`CLAIM_HEX_WIDTH`), so pointing at
`tcb_status.snp.measurement` from a 256-bit manifest fails at generation with an
explanation. A path not in that table is accepted without a width check, because
Trustee's claim set is deployment-specific and asserting a width we have not
confirmed would be a worse error than not checking.

## Rego is generated, not templated

Every value interpolated into the policy is either a hex digest validated against
a character class or a TEE name from a fixed set. `measurement_path` must match a
dotted-identifier pattern.

A policy generator that concatenated arbitrary input into Rego would be an
injection vector into the component deciding who gets model keys. There are tests
that try.

## What the generated policy does not do

It does not verify evidence. Trustee's Attestation Service does that before the
policy runs; the policy reads the claims it produced. The header says so.

`sample` is excluded when the manifest requires `hardware-attested`. Trustee's
sample TEE attests nothing and must never satisfy the tier.

## Resources

```bash
python wcm_coco.py manifest.json --print-uri
kbs:///default/wcm-model-key/4a1c4a1c...
```

The tag is the weights digest. Two manifests over different weights cannot
collide on one resource, and rotating weights means publishing to a new URI
rather than overwriting a key that a running workload still holds a lease on.

## Run it

```bash
pip install weight-custody-manifest

python wcm_coco.py manifest.json \
  --measurement-path tcb_status.azsnpvtpm.tpm.pcr04 \
  --repository default > policy.rego
```

`--allow-unbound-workload` emits a TEE-only policy. The warning goes inside the
generated Rego as well as to stderr, because the file is what gets read six
months later.

Revoked measurements are dropped. Retiring ones are kept: WCM's rule is
prefer-current, and denying retiring images would take a fleet offline during a
rollover. A manifest whose measurements are all revoked is refused rather than
turned into a policy that denies everything, since that is a manifest problem and
should not be emitted and forgotten.

## Scope

Trustee gates on verified CVM evidence. Real against a software adversary and a
remote attacker; not a control against an operator who physically owns the
hardware, where confidential computing does not hold (WCM `SPEC.md` section 3.6).

- Specification and documentation: <https://wcm.agentrust-io.com>
- SDK: <https://pypi.org/project/weight-custody-manifest/>
