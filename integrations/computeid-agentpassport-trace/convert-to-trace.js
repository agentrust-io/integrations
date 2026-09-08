#!/usr/bin/env node
// Converts a REAL ComputeID /verify evidence bundle into a TRACE v0.2-shaped
// record, following TRACE-MAPPING.md exactly. This tests ComputeID's ACTUAL
// production output against TRACE conformance -- not a hand-built sample.
//
// Usage: node convert-to-trace.js <evidence-bundle.json> > trace-record.json

const fs = require('fs');

const bundlePath = process.argv[2];
if (!bundlePath) {
  console.error('Usage: node convert-to-trace.js <evidence-bundle.json>');
  process.exit(1);
}

const bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
const receipt = bundle.verification_receipt || {};

const record = {
  eat_profile: "tag:agentrust-io.com,2026:trace-v0.2",
  iat: Math.floor(new Date(bundle.issued_at).getTime() / 1000),
  subject: `did:computeid:agent:${bundle.passport_id}`,
  origin: {
    kind: "third-party-control-plane",
    producer: "computeid-issuer",
  },
  runtime: {
    platform: "software-only",
  },
  references: [
    { name: "credentialStructureValid", value: !!(bundle.public_key && bundle.signature && bundle.signed_payload) },
    { name: "classicalSignatureValid", value: bundle.signature_valid === true },
    { name: "mlDsaSignatureValid", value: bundle.pq_signature_valid === true },
    { name: "notRevoked", value: bundle.status === 'active' && bundle.revoked_at === null },
    { name: "hardwareAttestationPresent", value: false },
    { name: "auditIntegrityValid", value: null, note: "checked by separate tool verify-audit-chain.js, not carried in this record" },
  ],
};

console.log(JSON.stringify(record, null, 2));
