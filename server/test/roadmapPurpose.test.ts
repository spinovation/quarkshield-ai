import { test } from 'node:test';
import assert from 'node:assert/strict';
import { purposeMeta } from '../src/lib/roadmapReport';
import { classifyPurpose } from '../src/lib/threatGraph/cryptoPurpose';

// ---- purposeMeta: HNDL-vs-forgery urgency split (P1) ------------------------

test('key establishment and RSA key transport are immediate HNDL', () => {
  assert.equal(purposeMeta('key_establishment').urgency, 'immediate_hndl');
  assert.equal(purposeMeta('rsa_key_transport').urgency, 'immediate_hndl');
  assert.match(purposeMeta('key_establishment').standard, /FIPS 203/);
});

test('signature / trust purposes are planned forgery risk (not HNDL)', () => {
  for (const p of ['tls_certificate', 'code_or_data_signing', 'ca_trust_anchor', 'ssh_authentication']) {
    assert.equal(purposeMeta(p).urgency, 'forgery_planned', p);
  }
  assert.match(purposeMeta('code_or_data_signing').standard, /FIPS 204/);
});

test('symmetric/configuration are hardening; unknown is review', () => {
  assert.equal(purposeMeta('symmetric').urgency, 'hardening');
  assert.equal(purposeMeta('configuration').urgency, 'hardening');
  assert.equal(purposeMeta('unknown').urgency, 'review');
});

test('purposeMeta defaults NULL / unrecognized purpose to unknown (legacy rows safe)', () => {
  assert.equal(purposeMeta(null).urgency, 'review');
  assert.equal(purposeMeta(undefined).urgency, 'review');
  assert.equal(purposeMeta('').urgency, 'review');
  assert.equal(purposeMeta('not_a_real_purpose').label, 'Unclassified');
});

// ---- classifyPurpose → purposeMeta end-to-end (what the ingest paths persist) ----

test('a TLS key-exchange finding classifies HNDL end-to-end', () => {
  const p = classifyPurpose({ type: 'tls_endpoint', name: 'Ingress TLS 1.3 Key Exchange', algorithm: 'ECDHE' });
  assert.equal(p, 'key_establishment');
  assert.equal(purposeMeta(p).urgency, 'immediate_hndl');
});

test('a code-signing finding classifies as planned forgery risk end-to-end', () => {
  const p = classifyPurpose({ type: 'signature', name: 'release signing key', algorithm: 'RSA-2048' });
  assert.equal(p, 'code_or_data_signing');
  assert.equal(purposeMeta(p).urgency, 'forgery_planned');
});

test('a CA root classifies as trust anchor (planned), never HNDL', () => {
  const p = classifyPurpose({ type: 'ca_root', name: 'Internal Root CA', algorithm: 'RSA-4096' });
  assert.equal(p, 'ca_trust_anchor');
  assert.notEqual(purposeMeta(p).urgency, 'immediate_hndl');
});
