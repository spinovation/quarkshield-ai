import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessSizeImpact, canonicalAlgo, pqcTargetFor } from '../src/lib/threatGraph/sizeImpact';

// ---- canonicalAlgo / pqcTargetFor ------------------------------------------

test('canonicalAlgo normalizes common algorithm strings', () => {
  assert.equal(canonicalAlgo('Ed25519'), 'ed25519');
  assert.equal(canonicalAlgo('ECDSA with P-384'), 'ecdsa-p384');
  assert.equal(canonicalAlgo('X25519'), 'x25519');
  assert.equal(canonicalAlgo('RSA', 4096), 'rsa-4096');
  assert.equal(canonicalAlgo('RSA-2048'), 'rsa-2048');
  assert.equal(canonicalAlgo('something-weird'), 'unknown');
});

test('pqcTargetFor picks ML-KEM for KEX, SLH-DSA for roots, ML-DSA otherwise', () => {
  assert.equal(pqcTargetFor('key_establishment'), 'ml-kem-768');
  assert.equal(pqcTargetFor('ca_trust_anchor'), 'slh-dsa-128s');
  assert.equal(pqcTargetFor('code_or_data_signing'), 'ml-dsa-65');
});

// ---- signature blow-up + firmware slot (the headline "it won't fit") -------

test('Ed25519 code-signing → ML-DSA-65 is ~52x and breaks a firmware slot (blocker)', () => {
  const r = assessSizeImpact({ algorithm: 'Ed25519', purpose: 'code_or_data_signing' });
  assert.equal(r.size_before, 64);
  assert.equal(r.size_after, 3309);
  assert.equal(r.blowup, 51.7);
  const fw = r.findings.find(f => f.constraint_id === 'firmware_slot');
  assert.ok(fw, 'expected a firmware_slot finding');
  assert.equal(fw!.verdict, 'breaks');
  assert.equal(fw!.severity, 'blocker');
});

test('CA root → SLH-DSA-128s is a 7856-byte signature (firmware-slot blocker)', () => {
  const r = assessSizeImpact({ algorithm: 'ECDSA P-384', purpose: 'ca_trust_anchor' });
  assert.equal(r.to_algo, 'slh-dsa-128s');
  assert.equal(r.size_after, 7856);
  assert.equal(r.findings.find(f => f.constraint_id === 'firmware_slot')!.severity, 'blocker');
});

// ---- key establishment blow-up + transport limits --------------------------

test('X25519 key establishment → ML-KEM-768 (2272 B) stresses MTU fragmentation', () => {
  const r = assessSizeImpact({ algorithm: 'X25519', purpose: 'key_establishment' });
  assert.equal(r.object_kind, 'kem_exchange');
  assert.equal(r.size_after, 1184 + 1088);
  const mtu = r.findings.find(f => f.constraint_id === 'mtu_frag');
  assert.ok(mtu);
  assert.equal(mtu!.verdict, 'breaks');
  assert.equal(mtu!.severity, 'degraded'); // transport limit, not a categorical fixed slot
});

test('firmware_slot does NOT apply to a TLS certificate purpose', () => {
  const r = assessSizeImpact({ algorithm: 'RSA-2048', purpose: 'tls_certificate' });
  assert.equal(r.findings.find(f => f.constraint_id === 'firmware_slot'), undefined);
});

// ---- honesty / edge cases --------------------------------------------------

test('unknown classical algorithm → size_before 0, blowup null, PQC size still shown', () => {
  const r = assessSizeImpact({ algorithm: 'mystery-cipher', purpose: 'code_or_data_signing' });
  assert.equal(r.size_before, 0);
  assert.equal(r.blowup, null);
  assert.equal(r.size_after, 3309);
  assert.match(r.note, /not in the reference table/);
});

test('symmetric / configuration purposes have no size migration', () => {
  for (const purpose of ['symmetric', 'configuration'] as const) {
    const r = assessSizeImpact({ algorithm: 'AES-128', purpose });
    assert.equal(r.findings.length, 0);
    assert.equal(r.size_after, 0);
    assert.match(r.note, /no asymmetric/i);
  }
});

test('findings are ordered blocker → degraded → advisory', () => {
  const r = assessSizeImpact({ algorithm: 'Ed25519', purpose: 'ca_trust_anchor' });
  const ranks = { blocker: 0, degraded: 1, advisory: 2 } as const;
  for (let i = 1; i < r.findings.length; i++) {
    assert.ok(ranks[r.findings[i - 1].severity] <= ranks[r.findings[i].severity]);
  }
});
