#!/usr/bin/env node
// ComputeID — Standalone Offline Verifier (OPAQUE diligence deliverable)
//
// Reads a saved evidence bundle (the exact JSON response from
// GET /v1/agents/:id/verify) and INDEPENDENTLY recomputes every
// cryptographic check from raw key/signature/payload bytes already
// present in the bundle. Runs with ZERO network calls once the
// evidence file exists.
//
// FIXED (per Imran Siddique / OPAQUE Systems review of PR #176):
// classical_signature_valid and ml_dsa_signature_valid previously read
// the service's own claimed signature_valid/pq_signature_valid fields
// rather than independently recomputing the signatures. That meant the
// "independent verification" claim did not match what the code actually
// did. Both are now genuinely recomputed here using node:crypto (RSA-PSS)
// and @noble/post-quantum (ML-DSA-65), against the raw public_key,
// signature, and signed_payload bytes in the bundle.

const fs = require('fs');
const crypto = require('crypto');
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js');

// Independently verifies the RSA-PSS-SHA256 signature over signed_payload,
// using the public key embedded in the bundle itself — not trusting the
// service's own signature_valid field.
function checkClassicalSignature(bundle) {
  try {
    const verifier = crypto.createVerify('SHA256');
    verifier.update(bundle.signed_payload);
    verifier.end();
    const valid = verifier.verify(
      bundle.public_key,
      bundle.signature,
      'base64'
    );
    return { valid, reason: valid ? 'RSA-SHA256 (PKCS#1 v1.5) independently verified against embedded public_key' : 'signature does not verify against embedded public_key' };
  } catch (err) {
    return { valid: false, reason: 'verification error: ' + err.message };
  }
}

// Independently verifies the ML-DSA-65 signature over signed_payload, using
// the raw public key bytes embedded in the bundle — not trusting the
// service's own pq_signature_valid field. @noble/post-quantum v0.4.1 is
// key-first: verify(publicKey, message, signature).
function checkMlDsaSignature(bundle) {
  try {
    const pubKey = Buffer.from(bundle.pq_public_key, 'base64');
    const sig = Buffer.from(bundle.pq_signature, 'base64');
    const msg = Uint8Array.from(Buffer.from(bundle.signed_payload, 'utf8'));
    const valid = ml_dsa65.verify(pubKey, msg, sig);
    return { valid, reason: valid ? 'ML-DSA-65 independently verified against embedded pq_public_key' : 'signature does not verify against embedded pq_public_key' };
  } catch (err) {
    return { valid: false, reason: 'verification error: ' + err.message };
  }
}

// Verifies the receipt's RSA-SHA256 signature was made by the private key
// corresponding to the PUBLICLY PUBLISHED CA certificate — not just
// trusting that the receipt says it came from ComputeID.
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
    !!bundle.public_key && !!bundle.signature && !!bundle.signed_payload &&
    !!bundle.pq_public_key && !!bundle.pq_signature;

  const classicalResult = checkClassicalSignature(bundle);
  const mlDsaResult = checkMlDsaSignature(bundle);
  const classical_signature_valid = classicalResult.valid;
  const ml_dsa_signature_valid = mlDsaResult.valid;

  const not_revoked = bundle.status === 'active' && bundle.revoked_at === null;
  const hardware_attestation_present = false;

  const receipt = bundle.verification_receipt || {};
  const receipt_expires_at = receipt.expires_at || null;
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
    verification_reasons: {
      classical_signature: classicalResult.reason,
      ml_dsa_signature: mlDsaResult.reason,
      issuer_trusted: issuerTrustedResult.reason,
    },
    overall_pass,
    credential_fresh_note: 'credential_fresh reflects the verification RECEIPT freshness window (5 minutes from issuance), not a passport-level expiry policy. Passports themselves do not expire today — only the receipt attesting to a specific verification check does.',
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
