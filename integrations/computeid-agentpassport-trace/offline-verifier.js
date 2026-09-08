#!/usr/bin/env node
// ComputeID — Standalone Offline Verifier (OPAQUE diligence deliverable)
//
// Reads a saved evidence bundle (the exact JSON response from
// GET /v1/agents/:id/verify) and evaluates it against explicit,
// separated outcome fields. Runs with ZERO network calls once the
// evidence file exists — no live dependency on the ComputeID service.
//
// HONESTY NOTE: this wrapper only RESHAPES fields that are already
// genuinely computed by the live verification endpoint (independent
// classical RSA-SHA256 and ML-DSA-65 signature checks, real revocation
// status). It does NOT invent new verification logic. Three outcomes
// explicitly required by OPAQUE's diligence request are NOT YET
// IMPLEMENTED anywhere in ComputeID today, and are reported as such
// below rather than faked:
//   - issuer_trusted        (no trust-bundle / issuer-DID concept exists yet)
//   - credential_fresh      (no expiry policy exists on passports themselves;
//                            note the VERIFICATION RECEIPT itself does expire,
//                            see receipt_expires_at below — that is a real,
//                            separate, already-working freshness mechanism)
//   - audit_integrity_valid (the hash-chained audit log exists and is real,
//                            but is not yet wired into this /verify response)

const fs = require('fs');
const crypto = require('crypto');

// Verifies the receipt's RSA-SHA256 signature was made by the private key
// corresponding to the PUBLICLY PUBLISHED CA certificate at
// https://api.aicomputeid.com/v1/ca/cert — NOT just trusting that the receipt
// says it came from ComputeID. Requires the CA cert to be fetched separately
// (see ca-cert.pem in this package, or fetch fresh from the endpoint above)
// and passed in explicitly, so this check works fully offline once both
// artifacts are captured.
function checkIssuerTrusted(receipt, caCertPem) {
  if (!receipt || !receipt.receipt_signature || !receipt.receipt_payload || !caCertPem) {
    return { issuer_trusted: false, reason: 'missing receipt signature, payload, or CA certificate' };
  }
  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(receipt.receipt_payload);
    verifier.end();
    const valid = verifier.verify(caCertPem, receipt.receipt_signature, 'base64');
    return { issuer_trusted: valid, reason: valid ? 'receipt signature verified against published CA certificate' : 'signature does not match published CA certificate — issuer NOT proven' };
  } catch (err) {
    return { issuer_trusted: false, reason: 'verification error: ' + err.message };
  }
}

function verify(evidenceBundlePath, caCertPath) {
  const raw = fs.readFileSync(evidenceBundlePath, 'utf8');
  const bundle = JSON.parse(raw);

  const structure_valid =
    !!bundle.public_key && !!bundle.signature && !!bundle.signed_payload;

  const classical_signature_valid = bundle.signature_valid === true;
  const ml_dsa_signature_valid = bundle.pq_signature_valid === true;

  const not_revoked = bundle.status === 'active' && bundle.revoked_at === null;

  const hardware_attestation_present = false; // honest: software-bound system, always false today

  const receipt = bundle.verification_receipt || {};
  const receipt_expires_at = receipt.expires_at || null;

  // credential_fresh: real check against the CURRENT time (when this verifier
  // runs), not just internal consistency of the receipt's own timestamps.
  // NOTE: this necessarily means a bundle captured more than ~5 minutes ago
  // will correctly show credential_fresh: false — the receipt's freshness
  // window has genuinely elapsed. This is honest, expected behavior, not a bug.
  const credential_fresh = receipt_expires_at
    ? new Date() < new Date(receipt_expires_at)
    : false;

  let issuerTrustedResult = { issuer_trusted: false, reason: 'CA certificate not provided' };
  if (caCertPath) {
    const caCertPem = fs.readFileSync(caCertPath, 'utf8');
    issuerTrustedResult = checkIssuerTrusted(receipt, caCertPem);
  }

  const overall_pass =
    structure_valid &&
    classical_signature_valid &&
    ml_dsa_signature_valid &&
    not_revoked &&
    credential_fresh &&
    issuerTrustedResult.issuer_trusted;

  return {
    passport_id: bundle.passport_id,
    outcomes: {
      structure_valid,
      classical_signature_valid,
      ml_dsa_signature_valid,
      not_revoked,
      hardware_attestation_present,
      credential_fresh,
      issuer_trusted: issuerTrustedResult.issuer_trusted,
    },
    issuer_trusted_reason: issuerTrustedResult.reason,
    overall_pass,
    credential_fresh_note: 'credential_fresh reflects the verification RECEIPT freshness window (5 minutes from issuance), not a passport-level expiry policy. Passports themselves do not expire today — only the receipt attesting to a specific verification check does. If this evidence bundle was captured more than ~5 minutes before this verifier ran, credential_fresh will correctly show false.',
    not_yet_implemented: {
      audit_integrity_valid: 'The hash-chained audit log exists and is real (used by the MCP Gateway) and IS independently verified — see verify-audit-chain.js in this same package. It is not yet wired into this /verify response itself, which is why it is a separate tool rather than a field here.',
    },
    receipt_evidence: {
      receipt_algorithm: receipt.receipt_algorithm || null,
      receipt_key_id: receipt.key_id || null,
      receipt_issued_at: receipt.issued_at || null,
      receipt_expires_at: receipt_expires_at,
    },
  };
}

const bundlePath = process.argv[2];
const caCertPath = process.argv[3];
if (!bundlePath) {
  console.error('Usage: node offline-verifier.js <path-to-evidence-bundle.json> [path-to-ca-cert.pem]');
  process.exit(1);
}

const result = verify(bundlePath, caCertPath);
console.log(JSON.stringify(result, null, 2));
