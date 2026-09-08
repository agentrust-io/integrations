# ComputeID ↔ TRACE Interoperability Mapping

**TRACE spec commit pinned:** `3a561d84d752794b9afa994ce16ed35c24ac0acb` (agentrust-io/trace-spec, `main`, committed 2026-09-05 21:33:47 -0700)

This document maps ComputeID's actual, verified credential-checking outcomes onto the TRACE v0.2 Trust Record schema (`schema/trace-claim.json`) and specification (`spec/trace-v0.2.md`) at the commit above. It uses TRACE's existing `origin` and `references` extension mechanisms (spec §3.1.1, §3.1.2) rather than inventing new normative fields. Nothing in this document is a claim that ComputeID emits, or has ever emitted, a conformant TRACE Trust Record.

---

## 1. What ComputeID actually verifies

Source of truth: `offline-verifier.js` (ComputeID's standalone, no-network offline verifier). Running it against a passport bundle produces these named outcomes:

| ComputeID outcome | What it checks |
|---|---|
| `credentialStructureValid` | All required passport fields present |
| `classicalSignatureValid` | RSA-SHA256 signature over the canonicalized passport body |
| `mlDsaSignatureValid` | ML-DSA-65 (Dilithium3 / FIPS 204) signature over the same body |
| `issuerTrusted` | `issuer_did` is present in the caller-supplied trust bundle |
| `subjectBindingValid` | Passport is structurally bound to an `agent_id` |
| `credentialFresh` | Current time is within `[issued_at, expires_at]` |
| `notRevoked` | A revocation snapshot is present, not stale (>300s old), and `state === "active"` |
| `auditIntegrityValid` | Audit-log hash chain is unbroken |
| `hardwareAttestationPresent` | **Always `false`.** The verifier hard-codes this: *"Software-bound only. No TPM/TEE/GPU attestation."* |

The task's requested six fields (`structure_valid`, `classical_signature_valid`, `ml_dsa_signature_valid`, `not_revoked`, `credential_fresh`, `issuer_trusted`) correspond 1:1 to the camelCase fields above; this document uses the verifier's actual field names as the source of truth.

## 2. Runtime classification (TRACE's own categories)

TRACE's `runtime.platform` enum (`schema/trace-claim.json`) includes `intel-tdx`, `amd-sev-snp`, `nvidia-h100`, `aws-nitro`, `tpm2`, and — the only value that fits ComputeID today — **`software-only`**.

Per spec §3.1.1: *"`runtime.platform: "software-only"` is the honest platform value... It is the correct value for a dev-mode record, where nothing attested the execution, and for a record transcribed from another vendor's control plane, where the party asserting the evidence also wrote the log."*

ComputeID's offline-verifier is exactly the second case: it is a control plane that authored its own evidence, with no silicon root of trust anywhere in the chain. So the correct mapping is:

```
runtime.platform = "software-only"
origin.kind      = "third-party-control-plane"
origin.producer  = "computeid-issuer"   (or the specific issuer DID)
```

This is not optional stylistic choice — it is a spec MUST. §3.1.1: *"A record whose `origin.kind` is not `self` MUST carry `runtime.platform: "software-only"`, and a verifier MUST reject it otherwise."* The JSON Schema encodes the same rule as a cross-field `allOf`/`if`/`then` constraint (`trace-claim.json` lines 529–564).

## 3. Field-by-field mapping

TRACE requires `eat_profile`, `iat`, `subject`, `model`, `runtime`, `policy`, `data_class`, `build_provenance`, `appraisal`, `cnf` on every Trust Record. ComputeID's passport-issuance flow does not produce most of these — it is an identity/credential system, not an execution-attestation runtime. This mapping does not pretend otherwise. It places ComputeID's real fields where they actually correspond, and is explicit about what has no TRACE analogue.

| ComputeID field/outcome | TRACE mapping | Mechanism | Notes |
|---|---|---|---|
| `passport.agent_id`, `passport.issuer_did` | `subject` | Native field | Requires a DID URI (`did:<method>:<id>`) or SPIFFE URI. ComputeID's `issuer_did` already fits the DID pattern if formatted as `did:computeid:agent:<agent_id>`. |
| `passport.issued_at` | `iat` | Native field | Direct value (Unix epoch seconds), not a mapping — same semantics. |
| `hardwareAttestationPresent: false` | `runtime.platform = "software-only"` | Native field | Not an inference — the verifier's own detail string already says this in plain English. |
| — (no TEE measurement exists) | `runtime.measurement` | **Not populated** | TRACE requires this field when `runtime` is present with a hardware platform. ComputeID has no measurement to supply; omitting `runtime` object content beyond `platform`/no measurement is out of scope for this mapping and would need spec guidance for the `software-only` case. |
| `credentialStructureValid`, `classicalSignatureValid`, `mlDsaSignatureValid`, `issuerTrusted`, `subjectBindingValid`, `credentialFresh`, `notRevoked`, `auditIntegrityValid` | `references[]` entries | **Extension mechanism (§3.1.2), not a native claim** | See §4 below — these are pointers to ComputeID's own evidence bundle, not TRACE-native claims, because none of them describe model, runtime, policy, or tool-call execution. |
| — | `model`, `policy`, `data_class`, `tool_transcript`, `build_provenance`, `appraisal`, `cnf` | **Not populated by ComputeID today** | ComputeID issues identity credentials; it does not run model inference, evaluate policy, or execute tool calls. These TRACE fields describe execution governance that ComputeID's current product does not perform or claim to perform. |

## 4. Using `references` for ComputeID's verification outcomes

Per spec §3.1.2, a `references` entry is *"a pointer, not evidence... What the signature attests is that this record points there, not the truth of what it points at."* This is the correct (and only sanctioned) place to attach ComputeID's per-check outcomes to a TRACE record, because:

- `references` is explicitly assurance-neutral (cannot raise or lower `runtime.platform` or overall trust)
- it does not require inventing a new top-level TRACE field
- a verifier "MUST NOT reject a record because an entry in `references` cannot be resolved" — appropriate, since ComputeID's evidence bundle lives outside any TRACE transparency log

Example (illustrative, not a claim that ComputeID emits this today):

```json
"references": [
  {
    "rel": "behavior-trace",
    "id": "computeid:verification-result:<passport_id>:<verified_at>",
    "resolver": "computeid-issuer",
    "digest": "sha256:<hash of the offline-verifier.js JSON output>"
  }
]
```

**Caveat on `rel`:** TRACE's spec text lists three *registered* `rel` values (`authorized-intent`, `approval-outcome`, `behavior-trace`); the schema comment notes this "is not a closed set," but none of the three registered values is a precise semantic fit for "a bundle of independent credential-validity checks." `behavior-trace` ("a behavioural record of what the agent did") is the closest available registered value, used here as a best-effort fit — it is not a strong match, since ComputeID's outcomes describe credential validity, not agent behavior. Proposing a more precise `rel` (e.g. `credential-verification`) to the TRACE editors is listed as a next step in §6, not something this document unilaterally adds to the spec.

## 5. Required verbatim scope statement

Per instruction, stated exactly as required, in TRACE's own language:

> The ComputeID credential authenticates an issued software identity; it does not attest to hardware, workload measurements, confidential execution, model identity, or policy enforcement unless separate evidence establishes those properties.

## 6. What this document does NOT claim

- **No conformance claim.** This mapping has not been run through, and has not passed, the TRACE conformance suite (`trace-tests`). See §7 for the actual result of attempting that.
- **No synthetic Trust Record.** No example JSON in this document should be read as a ComputeID-issued artifact; every example is illustrative of the mapping only.
- **No new normative TRACE fields.** Every mapping above uses `subject`, `iat`, `runtime.platform`, `origin`, or `references` — all existing TRACE v0.2 mechanisms.
- **Open item for TRACE editors:** if ComputeID (or similar credential-only issuers) becomes a common `references` producer, a registered `rel` value more precise than `behavior-trace` (e.g. `credential-verification`) would be worth proposing upstream, per §3.1.2's statement that the `rel` registry "grows."

## 7. Conformance suite (`trace-tests`) — actual result

The suite is the `agentrust-trace` Python package's own pytest suite (`tests/`), installed from the pinned commit via `pip install -e ".[dev]"` in a clean venv, no network access required at test time.

**Result: `1185 passed, 1 skipped` in 11.17s.**

This is **not** a conformance pass for anything ComputeID produces. The suite validates the reference implementation's own models, schema round-trips, canonicalization, signing, and fixture vectors — it is a self-test of `agentrust-trace`, not a CLI that ingests an arbitrary third-party artifact (such as a ComputeID passport or evidence bundle) and appraises it. ComputeID does not currently emit a JWT/CBOR-COSE TRACE Trust Record, so there is no ComputeID artifact to feed into this suite.

**Next step, not a claim:** producing an actual TRACE Trust Record from a ComputeID passport (per the mapping in §3–§4) and validating *that* artifact against `agentrust_trace.validate` / the schema would be the real conformance test. That has not been done and is out of scope for this mapping document.
