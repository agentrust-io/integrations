# SAGE integration with cMCP + TRACE (attested memory provenance)

[SAGE](https://github.com/l33tdawg/sage) is consensus-validated agent memory: writes go
through BFT consensus, carry a confidence score, and decay over time. This integration is an
attestation-verifying reverse proxy that sits in front of a **stock, unmodified** SAGE node
and admits a `POST /v1/memory/submit` only when it carries a verifiable AgenTrust attestation,
bound to the key that authors the memory on-chain. **Only the submit endpoint is gated** —
other SAGE writes (`/forget`, `/vote`, `/corroborate`, `/challenge`, governance, access) pass
through to SAGE's own Ed25519 auth + RBAC (out of scope for this submission-provenance bridge).

The agent signs its SAGE `POST /v1/memory/submit` with an Ed25519 key and presents an
attestation in an `X-Attestation` header. The proxy verifies it at the edge, binds it to the
SAGE author, then forwards the **byte-identical** signed request to SAGE (so the node's own
signature check still passes — no SAGE changes). On commit it stores the evidence keyed by the
returned `memory_id`, exposed as a provenance badge at `GET /v1/attestation/{memory_id}`.

Two paths:
- **TRACE (per-agent) — the enforcing security path.** A standalone TRACE record whose `cnf`
  key **is** the agent's SAGE key (signed with `agentrust_trace.sign_record`); the proxy checks
  canonical `cnf.jwk.x` encoding, signature, freshness, `cnf == author` key equality, and
  `tool_transcript.hash == sha256(submit body)` — a cryptographic, **write-scoped** binding.
- **cMCP — advisory session provenance, no trust root.** The proxy verifies a cMCP
  `RuntimeClaim`'s signature and approved policy/catalog hashes with the published
  `cmcp_verify.verify_trace_claim` and matches `gateway.agent_identity.agent_id`
  (gateway-asserted). With the published stack the gateway signing key is **not anchored to any
  trusted issuer**, so a valid C-1 signature authenticates only the claim's structure and that
  its policy/catalog hashes match the configured approved set — **anyone can mint a
  signature-valid claim naming any `agent_id`**. A RuntimeClaim is also session-scoped with
  **no** per-write binding and the agent controls the gateway key, so C-1 is provenance that an
  agent ran behind an attested gateway — **not** per-write authorization.

**What it does not claim:** the bridge does **not** verify any hardware root of trust with the
published AgenTrust stack — `cmcp_verify`'s per-platform verifiers check the measurement
format/parse but **defer the silicon root** (TPM EK chains / AMD VCEK / Intel DCAP quote
signatures go to *unverified_fields*, "out of scope for Phase 1"), and a C-2 record's
`runtime.platform` is self-asserted. So it **never** reports
`hardware_backed`; `verification` is always `edge-only` and a claimed TEE platform is surfaced
only as `platform_claimed` (unverified). Attestation here authenticates the *author and policy*
of a write — **not** the truth of the content (SAGE's content hash and confidence stay
client-asserted). Verification is at the edge (the digest is not re-checked in SAGE consensus —
proposed upstream, not shipped); the badge reflects edge-verification at submit (`proposed`)
time, not consensus commit. `agentrust-trace-tests` **rejects** a self-signed bare TRACE record
(`LoadError`: a `signature` field without `cmcp_version`) and never grades it, so we make **no**
conformance-level claim for the C-2 path; the cMCP-envelope form passes `agentrust-trace-tests`
**0.1.0** Level 0. The `ReplayCache` (byte-identical de-dup) only blocks naive third-party
replay, not the minting agent, is **process-local** (a multi-instance deployment needs a shared
store) and effective single-instance only. The `GET /v1/attestation/{memory_id}` badge endpoint
is **unauthenticated** read-only — no secrets, but it discloses the attestation digest, `cnf`
thumbprint, and SPIFFE subject for a known `memory_id`. Canonicalization follows
`agentrust_trace`'s recipe (sorted-keys JSON), which equals RFC 8785 / JCS only for ASCII string
+ integer-number content.

## Run it

Against released packages (`cmcp-runtime` 0.2.1, `agentrust-trace` 0.2.0):

```bash
git clone https://github.com/l33tdawg/sage-agenttrust && cd sage-agenttrust
python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"

# stock SAGE node, isolated in Docker (image pinned by digest for reproducibility)
docker run -d --name sage-demo -p 127.0.0.1:18080:8080 -e SAGE_PASSPHRASE=demo-passphrase \
  ghcr.io/l33tdawg/sage@sha256:f08ebd392638d28248a06dab5791d975041e635a5c814c7e57e7632c3c10c05d serve

# the attestation-verifying proxy
SAGE_UPSTREAM=http://127.0.0.1:18080 uvicorn bridge.app:app --port 19090 &

# end-to-end: attested submit -> consensus commit -> provenance-badge fetch
BRIDGE_URL=http://127.0.0.1:19090 python demo/run_demo.py
```

## What is verified (reproduction steps for maintainers when requesting verification)

`./run_tests.sh` (offline, no node) reproduces:

- A standalone TRACE record minted via `agentrust_trace.sign_record` verifies, and is
  **rejected** when (a) the record is tampered, (b) its `cnf` key ≠ the SAGE author key, or
  (c) it is replayed onto a different submit body.
- A cMCP `RuntimeClaim` is accepted via `cmcp_verify.verify_trace_claim`, and **rejected**
  when it names a different agent or its policy/catalog hash does not match the approved set.
- The cMCP `RuntimeClaim` **passes `agentrust-trace-tests` Level 0**, and `software-only`
  **fails Level 1** (no hardware root) — asserted in `tests/test_conformance.py`.

`demo/run_demo.py` reproduces the live chain against a stock SAGE container: an attested
submit reaches consensus `committed`, the badge is retrievable, and a tampered or
wrong-author attestation returns `422` and never reaches SAGE.

## Links

- Integration source: https://github.com/l33tdawg/sage-agenttrust
- SAGE: https://github.com/l33tdawg/sage
