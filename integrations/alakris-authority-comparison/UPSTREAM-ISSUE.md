# AAIF #13: shared authority-at-dispatch runner, adapters and reproducible evidence fixtures

Human-directed contribution for Vladislav Kostitsyn, following Imran's request in the AAIF Identity & Trust discussion. This is a shared evidence-appraisal runner, not a comparative certification.

Scope:
- Four common cases: binding veto; revoked/stale authority plus a valid control; unavailable authority; revocation after dispatch.
- Separate authority, decision, dispatch, committed effect, receipt and relying-party appraisal.
- Preserve `not_applicable`, `not_emitted` and `not_measured`, public evidence commit vs source/deployed build, root epoch/height vs age, custody, exact commands and known gaps.
- Adapters for pinned MintID and Proofable public records; a synthetic effect boundary fixture with veto, final authorization recheck, action binding, deadline and duplicate checks.
- Released TRACE 0.11.0 reference shape validation only; no invented Trust Records, signatures or attestation/conformance claim.

Evidence:
- MintID public evidence commit `b678e5cd6b5736e1795fd18d497fd8e501272dcd` / `public-v2026-10-07`; testnet runs 10-06.2 (public `044f6888874ede33186310b9ec86fbcb1ee83ad7`, internal build `497509ebf0c3`). Existing disconnected-authority record is from 10-05.5 and must not become a current-build result.
- Proofable docs commit `3a45f026fd0c06b9d1d411c053597584b6b1c3dc`. Strict raw trace checksum mismatch: actual LF bytes `8df7ed9d49d1d6fb696a05661fd11db194db7c808719a66cadbf0f0a562cc1e2`; published `d749cf16fe8dd599f528e21e95863b930004a0b3f0a9882695e3d3b03e8c2183`. The latter equals LF-to-CRLF conversion. This is a byte-format diagnostic, not an allegation about the record contents. Four other payload checks pass.
- Full Proofable envelopes remain private, revocation latency unmeasured, independent target-side effects absent. Publisher `SUPPORTED` labels are not independent validation.

Review/action requests:
- Imran: confirm placement and shared field contract; review linked PR.
- Chris: correct the public trace hashes and provide a complete verifiable envelope/public sandbox reproduction path.
- Marc: rerun unavailability with the current verifier; publish veto observations; keep decision vs executor-effect limitations.
- Sankalp: review an independent observer/committed-effect adapter and the matching inputs.

Sources remain vendor-owned. Fixtures download from immutable URLs; exact results and commands are in the linked contribution. Link this issue/PR to [AAIF WG #13](https://github.com/aaif/wg-identity-and-trust/issues/13); TRACE semantics gaps should be raised separately in trace-spec only when a concrete gap is established.

Acceptance checklist:
- [x] Runnable shared evidence runner, immutable source pins and machine-readable output.
- [x] Distinct missing-value states and field boundaries.
- [x] Positive controls and tamper/forged-token/duplicate/deadline negative checks.
- [x] Strict fixture hashes and explicit known integrity failure.
- [ ] Current-build MintID unavailable-authority reproduction.
- [ ] Public offline Proofable envelope verification and corrected checksum.
- [ ] Independent target-side effect adapter and matched end-to-end comparative run.
- [ ] Maintainer review and integration tier decision.
