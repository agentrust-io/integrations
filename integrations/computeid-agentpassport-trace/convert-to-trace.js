#!/usr/bin/env node
// Converts a REAL ComputeID /verify evidence bundle into a genuinely signed
// TRACE v0.2 record, following TRACE-MAPPING.md and the AgenTrust
// maintainer's guidance on PR #176 / trace-spec#307.
//
// FIXED (per maintainer review):
// - references[] now uses the real schema (rel, id, resolver), pointing to
//   the evidence bundle as a single reference, not six fabricated entries.
// - classicalSignatureValid/mlDsaSignatureValid removed from references
//   entirely: they were reading the SERVICE'S OWN CLAIMED fields
//   (bundle.signature_valid / bundle.pq_signature_valid), which does not
//   match the "independent verification" claim. Real, independent
//   recomputation lives in offline-verifier.js; this script does not
//   duplicate that logic or re-assert its result as a TRACE claim.
// - The record itself is now genuinely signed (Ed25519, via
//   adapter-signing-key.pem), with the public key named in cnf, per the
//   maintainer's explanation that cnf identifies the RECORD-SIGNING key,
//   not a proof-of-possession selector. The ComputeID AgentPassport
//   identity evidence (RSA + ML-DSA-65) remains in the referenced
//   evidence bundle — a genuinely different, separate concern from what
//   signs this record.

const fs = require('fs');
const crypto = require('crypto');

const bundlePath = process.argv[2];
if (!bundlePath) {
  console.error('Usage: node convert-to-trace.js <evidence-bundle.json>');
  process.exit(1);
}

const bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));

const adapterPrivateKeyPem = fs.readFileSync(__dirname + '/adapter-signing-key.pem', 'utf8');
const adapterPublicKeyPem = fs.readFileSync(__dirname + '/adapter-signing-pubkey.pem', 'utf8');
const adapterPublicKey = crypto.createPublicKey(adapterPublicKeyPem);
const adapterJwk = adapterPublicKey.export({ format: 'jwk' });

// digest of the evidence bundle itself, so the reference is a checkable
// pointer (per spec 3.1.2: "a pointer, not evidence"). Schema's `digest`
// pattern is lowercase hex (^sha256:[0-9a-f]{64}$), not base64url.
const evidenceDigest = crypto.createHash('sha256').update(fs.readFileSync(bundlePath)).digest('hex');

const unsignedRecord = {
  eat_profile: "tag:agentrust-io.com,2026:trace-v0.2",
  iat: Math.floor(Date.now() / 1000),
  subject: `did:computeid:agent:${bundle.passport_id}`,
  origin: {
    kind: "third-party-control-plane",
    producer: "computeid-issuer",
  },
  runtime: {
    platform: "software-only",
  },
  appraisal: {
    status: "none",
    verifier: "https://api.aicomputeid.com",
  },
  cnf: {
    jwk: adapterJwk,
  },
  references: [
    {
      rel: "behavior-trace",
      id: `computeid:verification-evidence:${bundle.passport_id}:${bundle.issued_at}`,
      resolver: "computeid-issuer",
      digest: `sha256:${evidenceDigest}`,
    },
  ],
};

// Sign the canonical JSON of the record with the adapter's Ed25519 key.
// This is the record-signing key named in cnf above — a genuinely
// different key from the ComputeID AgentPassport RSA/ML-DSA-65 keys,
// which sign the identity evidence referenced above, not this record.
const canonicalize = require('canonicalize');
const canonical = canonicalize(unsignedRecord);
const signature = crypto.sign(null, Buffer.from(canonical, 'utf8'), adapterPrivateKeyPem);

const record = {
  ...unsignedRecord,
  signature: signature.toString('base64url'),
};

console.log(JSON.stringify(record, null, 2));
