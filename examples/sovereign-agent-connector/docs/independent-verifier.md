# Independent MVE-1 verifier

`tools/independent_verify.py` is a deliberately separate implementation of the
MVE-1 verification semantics. It imports no code from AUCP, cMCP, cA2A, TRACE, or
TRACE Registry. Its only non-standard-library dependency is `cryptography` for
Ed25519 verification.

It independently checks:

- owner, appraisal, delegation, receipt, cMCP TRACE, and adapter signatures;
- every embedded signing key against a separately supplied trust-anchor file;
- delegation continuity and monotonic attenuation;
- agreement projection and action decisions;
- receipt boundaries, joins, and registry Merkle inclusion;
- cMCP audit entry hashes and chain continuity;
- TRACE bindings to audit root, tip, length, policy, and call counts;
- per-action receipt-to-audit-to-TRACE joins, with every cMCP tool call matched to
  exactly one receipt; and
- the distinction between software-only evidence and hardware attestation, taken
  from the signed appraisal and required to agree with the TRACE platform.

Run:

```bash
python tools/independent_verify.py vectors/french-healthcare/cmcp-live-bundle.json \n  --trust-anchors vectors/french-healthcare/cmcp-live-trust-anchors.json
```

Expected result:

```text
PASS: AUCP MVE-1 bundle independently verified
workflow: urn:uuid:workflow-fr-health-001
allowed: urn:uuid:action-allowed-001
denied-before-dispatch: urn:uuid:action-denied-001
platform: software-only; hardware-attested=false
```

This is an independent implementation in the code sense, not yet an independent
organization or reviewer. Reproduction by a third party is still open.

