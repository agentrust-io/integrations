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
//
// FIXED (receipt binding): the CA-signed receipt_payload was signature
// checked but never parsed, so freshness came from the unsigned
// receipt.expires_at, revocation from the unsigned bundle.status, and a
// bundle carrying an attacker's own keys plus another passport's genuine
// receipt passed. passport_id, status, issued_at and expires_at are now read
// ONLY from the verified receipt_payload and must equal the bundle's claims.
// The receipt ComputeID issues today signs expires_at, issued_at, key_id
// (the CA key: first 16 hex of sha256 over ca-cert.pem's public key PEM),
// passport_id, signature_valid and status. It does not sign either passport
// key, so public_key and pq_public_key are self-embedded and nothing ties
// them to the CA. issuer_trusted is therefore false, with the reason, until
// the receipt signs public_key and pq_public_key.

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
// Returns the parsed receipt_payload only when its signature verifies against
// the CA certificate; otherwise signed is null. Nothing outside the returned
// object may be used for a trust decision.
function checkReceiptSignature(receipt, caCertPem) {
  if (!receipt || !receipt.receipt_signature || !receipt.receipt_payload || !caCertPem) {
    return { signed: null, reason: 'missing receipt signature, payload, or CA certificate' };
  }
  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(receipt.receipt_payload);
    verifier.end();
    const valid = verifier.verify(caCertPem, receipt.receipt_signature, 'base64');
    if (!valid) {
      return { signed: null, reason: 'signature does not match published CA certificate, issuer NOT proven' };
    }
    const signed = JSON.parse(receipt.receipt_payload);
    if (!signed || typeof signed !== 'object' || Array.isArray(signed)) {
      return { signed: null, reason: 'receipt_payload verified but is not a JSON object' };
    }
    return { signed, reason: 'receipt signature verified against published CA certificate' };
  } catch (err) {
    return { signed: null, reason: 'verification error: ' + err.message };
  }
}

// key_id in the receipt names the CA key: first 16 hex of sha256 over the CA
// public key in SPKI PEM form (matches every ComputeID fixture in evidence/).
function caKeyId(caCertPem) {
  const pem = new crypto.X509Certificate(caCertPem).publicKey.export({ type: 'spki', format: 'pem' });
  return crypto.createHash('sha256').update(pem).digest('hex').slice(0, 16);
}

// The bundle's claims must equal what the CA signed. Unsigned copies inside
// verification_receipt must equal it too: a mismatch means someone edited them.
function checkReceiptBinding(bundle, receipt, signed, caCertPem) {
  const problems = [];
  if (typeof signed.passport_id !== 'string' || signed.passport_id !== bundle.passport_id) {
    problems.push('signed passport_id ' + JSON.stringify(signed.passport_id) + ' != bundle passport_id ' + JSON.stringify(bundle.passport_id));
  }
  if (typeof signed.status !== 'string' || signed.status !== bundle.status) {
    problems.push('signed status ' + JSON.stringify(signed.status) + ' != bundle status ' + JSON.stringify(bundle.status));
  }
  for (const field of ['passport_id', 'status', 'issued_at', 'expires_at', 'key_id', 'signature_valid']) {
    if (receipt[field] !== undefined && receipt[field] !== signed[field]) {
      problems.push('unsigned verification_receipt.' + field + ' ' + JSON.stringify(receipt[field]) + ' != signed ' + JSON.stringify(signed[field]));
    }
  }
  if (signed.key_id !== undefined && signed.key_id !== caKeyId(caCertPem)) {
    problems.push('signed key_id ' + JSON.stringify(signed.key_id) + ' does not name the supplied CA key');
  }
  if (problems.length) {
    return { bound: false, reason: 'signed receipt does not match the bundle: ' + problems.join('; ') };
  }
  // Key binding. Only an exact copy of the bundle's own key fields inside the
  // signed payload counts; no other field is taken as a binding.
  const missing = ['public_key', 'pq_public_key'].filter((k) => signed[k] === undefined);
  if (missing.length) {
    return {
      bound: false,
      reason: 'receipt_payload binds no passport key (' + missing.join(', ') + ' not signed; signed fields: ' +
        Object.keys(signed).sort().join(', ') + '). The keys are self-embedded in the bundle, so the CA receipt ' +
        'does not prove these keys belong to this passport.',
    };
  }
  const mismatched = ['public_key', 'pq_public_key'].filter((k) => signed[k] !== bundle[k]);
  if (mismatched.length) {
    return { bound: false, reason: 'bundle ' + mismatched.join(', ') + ' differs from the key the CA signed' };
  }
  return { bound: true, reason: 'receipt binds passport_id, status and both passport keys' };
}

// options.now pins the clock (Date or ISO string) for reproducible runs.
function verify(evidenceBundlePath, caCertPath, options = {}) {
  const raw = fs.readFileSync(evidenceBundlePath, 'utf8');
  const bundle = JSON.parse(raw);
  const now = options.now !== undefined ? new Date(options.now) : new Date();

  const structure_valid =
    !!bundle.public_key && !!bundle.signature && !!bundle.signed_payload &&
    !!bundle.pq_public_key && !!bundle.pq_signature;

  const classicalResult = checkClassicalSignature(bundle);
  const mlDsaResult = checkMlDsaSignature(bundle);
  const classical_signature_valid = classicalResult.valid;
  const ml_dsa_signature_valid = mlDsaResult.valid;

  const hardware_attestation_present = false;
  const receipt = bundle.verification_receipt || {};

  let receiptResult = { signed: null, reason: 'CA certificate not provided' };
  let bindingResult = { bound: false, reason: 'no verified receipt to bind against' };
  if (caCertPath) {
    const caCertPem = fs.readFileSync(caCertPath, 'utf8');
    receiptResult = checkReceiptSignature(receipt, caCertPem);
    if (receiptResult.signed) {
      bindingResult = checkReceiptBinding(bundle, receipt, receiptResult.signed, caCertPem);
    }
  }
  const signed = receiptResult.signed;
  // Everything below comes from the CA-signed payload, never from the
  // unsigned verification_receipt copies or the bundle's own status field.
  // bundle.revoked_at is unsigned and can only make the result stricter.
  const not_revoked = !!signed && signed.status === 'active' && bundle.status === 'active' &&
    bundle.revoked_at === null;
  const receipt_expires_at = signed && typeof signed.expires_at === 'string' ? signed.expires_at : null;
  const receipt_issued_at = signed && typeof signed.issued_at === 'string' ? signed.issued_at : null;
  const expiresMs = receipt_expires_at ? Date.parse(receipt_expires_at) : NaN;
  const issuedMs = receipt_issued_at ? Date.parse(receipt_issued_at) : NaN;
  const credential_fresh = Number.isFinite(expiresMs) && now.getTime() < expiresMs &&
    (!receipt_issued_at || (Number.isFinite(issuedMs) && issuedMs <= now.getTime()));

  const issuerTrustedResult = {
    issuer_trusted: !!signed && bindingResult.bound,
    reason: !signed ? receiptResult.reason : receiptResult.reason + '; ' + bindingResult.reason,
  };

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
      receipt_binding: bindingResult.reason,
      credential_fresh: receipt_expires_at
        ? 'window taken from the CA-signed receipt_payload, evaluated at ' + now.toISOString()
        : 'no CA-verified receipt expires_at, so freshness is not established',
    },
    overall_pass,
    credential_fresh_note: 'credential_fresh reflects the verification RECEIPT freshness window (5 minutes from issuance), not a passport-level expiry policy. Passports themselves do not expire today — only the receipt attesting to a specific verification check does.',
    not_yet_implemented: {
      audit_integrity_valid: 'The hash-chained audit log exists and is real (used by the MCP Gateway) and IS independently verified — see verify-audit-chain.js in this same package. It is not yet wired into this /verify response itself, which is why it is a separate tool rather than a field here.',
    },
    receipt_evidence: {
      receipt_algorithm: receipt.receipt_algorithm || null,
      receipt_key_id: signed && signed.key_id !== undefined ? signed.key_id : null,
      receipt_issued_at: receipt_issued_at,
      receipt_expires_at: receipt_expires_at,
      receipt_signed_fields: signed ? Object.keys(signed).sort() : [],
    },
  };
}

module.exports = { verify, checkReceiptBinding };

if (require.main === module) {
  const args = process.argv.slice(2);
  let nowArg;
  const nowIndex = args.indexOf('--now');
  if (nowIndex !== -1) {
    nowArg = args[nowIndex + 1];
    args.splice(nowIndex, 2);
    if (!nowArg || Number.isNaN(Date.parse(nowArg))) {
      console.error('--now needs an ISO 8601 timestamp');
      process.exit(1);
    }
  }
  const [bundlePath, caCertPath] = args;
  if (!bundlePath) {
    console.error('Usage: node offline-verifier.js <path-to-evidence-bundle.json> [path-to-ca-cert.pem] [--now <iso-8601>]');
    process.exit(1);
  }
  const result = verify(bundlePath, caCertPath, nowArg ? { now: nowArg } : {});
  console.log(JSON.stringify(result, null, 2));
}
