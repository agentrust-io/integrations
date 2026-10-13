DRAFT — not published; replace placeholders with verified upstream URLs.

# Add shared AAIF authority comparison evidence runner

Closes TRACKING_ISSUE_URL_TO_BE_FILLED.

Adds pinned public-evidence adapters for MintID and Proofable, an executable synthetic executor fixture, and released TRACE reference shape validation. Reports keep publisher observations, absent fields, unperformed appraisals and actual execution provenance distinct; external evidence does not become attestation or an independently verified effect.

Validation: Python 3.12.15, 27 tests including valid control, forged dispatch, action tampering, duplicate suppression, deadline closure, manifest coverage and missing-case rejection. MintID operator-record hashes pass. The pinned Proofable trace intentionally fails the strict publisher digest check; the diagnostic identifies LF/CRLF equivalence without altering expected hashes. Native client runs reproduced issuer/control and remaining revocation observations, but retain an initial HTTP 503 abort and a failed positive baseline in the bounded retry. Native reproduction scope and artifact hashes are recorded in RESULTS.md.

No Verified tier or conformance level is requested. Original vendor sources/evidence remain in their repositories. GitHub maintainer is the authenticated human submitting account `wlad232`; the source/evidence and author-run limitations remain explicit.
