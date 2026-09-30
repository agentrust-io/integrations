// Tests for offline-verifier.js receipt binding. Run: node --test test/
//
// These exercise the CA receipt, not ML-DSA. If @noble/post-quantum is not
// installed, ML-DSA verification is replaced by a stub that accepts every
// signature, so a pass here says nothing about the ML-DSA check.
const test = require('node:test');
const assert = require('node:assert');
const Module = require('module');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const NOBLE = '@noble/post-quantum/ml-dsa.js';
let mlDsaStubbed = false;
try {
  require.resolve(NOBLE);
} catch {
  mlDsaStubbed = true;
  const stubPath = path.join(__dirname, '__ml_dsa_stub__.js');
  const origResolve = Module._resolveFilename;
  Module._resolveFilename = function (request, ...rest) {
    return request === NOBLE ? stubPath : origResolve.call(this, request, ...rest);
  };
  const stub = new Module(stubPath);
  stub.filename = stubPath;
  stub.loaded = true;
  stub.exports = { ml_dsa65: { verify: () => true } };
  require.cache[stubPath] = stub;
}

const { verify, checkReceiptBinding } = require('../offline-verifier.js');

const ROOT = path.join(__dirname, '..');
const CA = path.join(ROOT, 'ca-cert.pem');
const FIXTURE = path.join(ROOT, 'evidence', 'opaque-diligence-demo.json');
const INSIDE_WINDOW = '2026-09-05T13:40:00Z';

function withBundle(mutate) {
  const bundle = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
  mutate(bundle);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'computeid-verifier-'));
  const file = path.join(dir, 'bundle.json');
  fs.writeFileSync(file, JSON.stringify(bundle));
  return file;
}

test('ML-DSA backend', (t) => {
  t.diagnostic(mlDsaStubbed ? 'ML-DSA STUBBED (accepts all): @noble/post-quantum not installed' : 'real @noble/post-quantum');
});

test('genuine fixture: expired at real time, overall false', () => {
  const r = verify(FIXTURE, CA);
  assert.strictEqual(r.outcomes.credential_fresh, false);
  assert.strictEqual(r.overall_pass, false);
});

test('genuine fixture inside its signed window: fresh, not revoked, but keys unbound', () => {
  const r = verify(FIXTURE, CA, { now: INSIDE_WINDOW });
  assert.strictEqual(r.outcomes.classical_signature_valid, true);
  assert.strictEqual(r.outcomes.credential_fresh, true);
  assert.strictEqual(r.outcomes.not_revoked, true);
  assert.strictEqual(r.outcomes.issuer_trusted, false);
  assert.match(r.verification_reasons.receipt_binding, /binds no passport key/);
  assert.strictEqual(r.overall_pass, false);
  assert.strictEqual(r.receipt_evidence.receipt_expires_at, '2026-09-05T13:42:51.013Z');
  assert.strictEqual(r.receipt_evidence.receipt_key_id, 'ebb276c2f18ed34f');
});

test('edited unsigned receipt.expires_at is rejected and not used for freshness', () => {
  const file = withBundle((b) => { b.verification_receipt.expires_at = '2099-01-01T00:00:00Z'; });
  const r = verify(file, CA, { now: '2030-01-01T00:00:00Z' });
  assert.strictEqual(r.outcomes.credential_fresh, false);
  assert.strictEqual(r.outcomes.issuer_trusted, false);
  assert.match(r.verification_reasons.receipt_binding, /unsigned verification_receipt\.expires_at/);
  assert.strictEqual(r.receipt_evidence.receipt_expires_at, '2026-09-05T13:42:51.013Z');
  assert.strictEqual(r.overall_pass, false);
});

test('attacker key and passport with a foreign CA receipt is rejected', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const file = withBundle((b) => {
    b.passport_id = 'attacker-passport';
    b.name = 'evil';
    b.public_key = publicKey.export({ type: 'spki', format: 'pem' });
    b.signed_payload = JSON.stringify({ capabilities: ['admin'], name: 'evil', organization: 'Evil' });
    b.signature = crypto.sign('sha256', Buffer.from(b.signed_payload), privateKey).toString('base64');
  });
  const r = verify(file, CA, { now: INSIDE_WINDOW });
  assert.strictEqual(r.outcomes.classical_signature_valid, true, 'attacker self-signature is valid by construction');
  assert.strictEqual(r.outcomes.issuer_trusted, false);
  assert.match(r.verification_reasons.receipt_binding, /signed passport_id .* != bundle passport_id "attacker-passport"/);
  assert.strictEqual(r.overall_pass, false);
});

test('attacker key keeping the victim passport_id is rejected for missing key binding', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const file = withBundle((b) => {
    b.public_key = publicKey.export({ type: 'spki', format: 'pem' });
    b.signature = crypto.sign('sha256', Buffer.from(b.signed_payload), privateKey).toString('base64');
  });
  const r = verify(file, CA, { now: INSIDE_WINDOW });
  assert.strictEqual(r.outcomes.issuer_trusted, false);
  assert.match(r.verification_reasons.receipt_binding, /binds no passport key/);
  assert.strictEqual(r.overall_pass, false);
});

test('unsigned bundle.status is not trusted for revocation', () => {
  const file = withBundle((b) => { b.status = 'active'; b.verification_receipt.status = 'revoked'; });
  const r = verify(file, CA, { now: INSIDE_WINDOW });
  assert.strictEqual(r.outcomes.issuer_trusted, false);
  assert.match(r.verification_reasons.receipt_binding, /verification_receipt\.status/);
});

test('without a CA certificate nothing from the receipt is used', () => {
  const r = verify(FIXTURE, undefined, { now: INSIDE_WINDOW });
  assert.strictEqual(r.outcomes.credential_fresh, false);
  assert.strictEqual(r.outcomes.not_revoked, false);
  assert.strictEqual(r.outcomes.issuer_trusted, false);
});

test('a receipt that signs both passport keys binds them; a different key fails', () => {
  const bundle = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
  const caPem = fs.readFileSync(CA, 'utf8');
  const signed = {
    ...JSON.parse(bundle.verification_receipt.receipt_payload),
    public_key: bundle.public_key,
    pq_public_key: bundle.pq_public_key,
  };
  assert.strictEqual(checkReceiptBinding(bundle, {}, signed, caPem).bound, true);
  const other = { ...bundle, public_key: 'x' };
  const res = checkReceiptBinding(other, {}, signed, caPem);
  assert.strictEqual(res.bound, false);
  assert.match(res.reason, /public_key differs/);
});
