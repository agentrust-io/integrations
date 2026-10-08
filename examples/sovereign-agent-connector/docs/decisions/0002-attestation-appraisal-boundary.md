# ADR-0002: Reuse cMCP attestation and separate placement appraisal

**Status:** Accepted  
**Date:** 14 August 2026  
**Decider:** Imran Siddique

## Context

MVE-1 uses a verifier-signed, RATS-shaped dictionary that directly asserts both
the child workload key and jurisdiction. It proves the composition shape, but it
does not exercise an attestation provider or an evidence-appraisal result.

Hardware attestation can bind a measured workload, a nonce, and a key. It does
not establish physical geography or legal jurisdiction. Placement therefore
needs its own accountable evidence source and relying-party policy.

## Decision

Reuse cMCP's `AttestationReport` provider interface and EAR-shaped
`AppraisalResult`. Normalize them into the existing AUCP appraisal boundary and
bind them to:

- the delegated workload key;
- a versioned appraisal policy;
- evidence issuance and expiry times; and
- a separately signed operator placement assertion.

The relying party fails closed on stale evidence, workload-key mismatch,
untrusted placement issuer, contraindicated appraisal, and any hardware claim
without raw provider evidence and an affirming appraisal.

The local MVE uses cMCP's actual `SoftwareOnlyProvider`. Its result is explicitly
`hardware_attested: false`; the placement remains an operator assertion. A later
TDX, SEV-SNP, TPM, or NRAS run can replace the provider inputs without changing
AUCP receipt semantics.

## Options considered

### Keep the shaped dictionary

Simple, but it leaves the provider and appraisal interfaces untested.

### Define an AUCP attestation envelope

Rejected because RATS/EAT, TRACE, and cMCP already provide the necessary carrier
and verification layers.

### Consume cMCP provider and appraisal results

Selected because it tests the real integration boundary while keeping hardware
and geography claims separate.

## Consequences

- AUCP does not become a hardware-verification library.
- Production deployments must configure provider-specific verification and trust
  anchors outside AUCP.
- A signed placement assertion remains residual operator evidence, not a hardware
  fact.
- Software-only evidence remains useful for conformance but cannot satisfy a
  hardware-required relying-party policy.

