import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fipsAlgorithmStatus as s, FIPS_TABLE_VERSION } from '../src/lib/fipsAlgorithmStatus';

// ---- Post-quantum (FIPS 203 / 204 / 205, SP 800-208) -----------------------

test('final PQC standards are pq_approved with the right FIPS', () => {
  assert.deepEqual([s({ algorithm: 'ML-KEM-768' }).status, s({ algorithm: 'ML-KEM-768' }).standard], ['pq_approved', 'FIPS 203']);
  assert.equal(s({ algorithm: 'ML-DSA-65' }).standard, 'FIPS 204');
  assert.equal(s({ algorithm: 'SLH-DSA-SHA2-128s' }).status, 'pq_approved', 'embedded SHA2 must not split the PQ name');
  assert.equal(s({ algorithm: 'SLH-DSA-SHA2-128s' }).standard, 'FIPS 205');
  assert.equal(s({ algorithm: 'LMS' }).standard, 'SP 800-208');
});

test('hybrid X25519MLKEM768 is approved via its ML-KEM component, X25519 alone is not', () => {
  const h = s({ algorithm: 'X25519MLKEM768', purpose: 'key_establishment' });
  assert.equal(h.status, 'pq_approved');
  assert.equal(h.ruleId, 'pq.mlkem.hybrid');
  assert.equal(s({ algorithm: 'X25519', purpose: 'key_establishment' }).status, 'non_fips');
});

test('pre-standard Kyber/Dilithium names are NOT asserted approved', () => {
  assert.equal(s({ algorithm: 'Kyber-768' }).status, 'unknown');
  assert.equal(s({ algorithm: 'Dilithium3' }).status, 'unknown');
});

test('ML-DSA cert with a SHA-256 hash keeps pq_approved (hash does not demote it)', () => {
  assert.equal(s({ algorithm: 'ML-DSA-65', hash_algorithm: 'SHA-256', purpose: 'tls_certificate' }).status, 'pq_approved');
});

// ---- RSA / ECC / DH — SP 800-131A Rev. 2 + NIST IR 8547 (draft) dates -------

test('RSA < 2048 is disallowed; RSA-2048 is acceptable with 2030 deprecation + 2035 sunset (draft)', () => {
  assert.equal(s({ algorithm: 'RSA', key_size: 1024 }).status, 'disallowed');
  const r2048 = s({ algorithm: 'RSA', key_size: 2048, purpose: 'tls_certificate' });
  assert.equal(r2048.status, 'acceptable');
  assert.equal(r2048.deprecatedAfter, '2030-12-31');
  assert.equal(r2048.disallowedAfter, '2035-12-31');
  assert.equal(r2048.draft, true, 'IR 8547 dates must be flagged as draft guidance');
  const r3072 = s({ algorithm: 'RSA', key_size: 3072 });
  assert.equal(r3072.deprecatedAfter, undefined, '128-bit RSA has no 2030 deprecation');
  assert.equal(r3072.disallowedAfter, '2035-12-31');
});

test('RSA without a key size is not determined (never guessed)', () => {
  assert.equal(s({ algorithm: 'RSA' }).status, 'unknown');
});

test('ECDSA curves: P-256/P-384 acceptable, P-192 disallowed, secp256k1 not FIPS', () => {
  assert.equal(s({ algorithm: 'ECDSA P-256' }).status, 'acceptable');
  assert.equal(s({ algorithm: 'ECDSA', key_size: 384 }).status, 'acceptable');
  assert.equal(s({ algorithm: 'ECDSA P-192' }).status, 'disallowed');
  assert.equal(s({ algorithm: 'ECDSA secp256k1' }).status, 'non_fips');
  assert.equal(s({ algorithm: 'ECDSA' }).status, 'unknown', 'unsized curve is not determined');
});

test('DSA is restricted to legacy verification (FIPS 186-5); EdDSA is acceptable', () => {
  const d = s({ algorithm: 'DSA', key_size: 2048 });
  assert.equal(d.status, 'restricted');
  assert.equal(d.standard, 'FIPS 186-5');
  assert.equal(s({ algorithm: 'Ed25519' }).status, 'acceptable');
});

// ---- Hashes / symmetric / protocols ----------------------------------------

test('SHA-1 is disallowed for signatures but acceptable (sunset 2030) for non-signature use', () => {
  const sig = s({ algorithm: 'RSA', key_size: 2048, hash_algorithm: 'SHA-1', purpose: 'tls_certificate' });
  assert.equal(sig.status, 'disallowed', 'worst part (SHA-1 signature) decides the finding');
  assert.equal(sig.ruleId, 'hash.sha1.sig');
  const mac = s({ algorithm: 'HMAC-SHA1', purpose: 'symmetric' });
  assert.equal(mac.status, 'acceptable');
  assert.equal(mac.disallowedAfter, '2030-12-31');
});

test('sha256WithRSAEncryption is split so the RSA key size is judged', () => {
  assert.equal(s({ algorithm: 'sha256WithRSAEncryption', key_size: 1024 }).status, 'disallowed');
  assert.equal(s({ algorithm: 'sha256WithRSAEncryption', key_size: 3072 }).status, 'acceptable');
});

test('MD5, 3DES, DES disallowed; AES and SHA-2/3 approved; ChaCha20 not FIPS', () => {
  assert.equal(s({ algorithm: 'MD5' }).status, 'disallowed');
  assert.equal(s({ algorithm: '3DES' }).status, 'disallowed');
  assert.equal(s({ algorithm: 'DES' }).status, 'disallowed');
  assert.equal(s({ algorithm: 'AES-256-GCM' }).status, 'approved');
  assert.equal(s({ algorithm: 'SHA3-256' }).standard, 'FIPS 202');
  assert.equal(s({ algorithm: 'CHACHA20-POLY1305' }).status, 'non_fips');
});

test('TLS 1.0/1.1 disallowed under SP 800-52 Rev. 2', () => {
  assert.equal(s({ algorithm: 'TLS 1.0' }).standard, 'SP 800-52 Rev. 2');
  assert.equal(s({ algorithm: 'TLSv1.1' }).status, 'disallowed');
});

test('cipher suite resolves to its worst component', () => {
  assert.equal(s({ algorithm: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', key_size: 2048 }).status, 'disallowed');
  assert.equal(s({ algorithm: 'ECDHE-RSA-AES128-GCM-SHA256', key_size: 2048 }).status, 'unknown',
    'unsized ECDHE makes the suite not determined — never "approved"');
});

// ---- Honesty: modules, blanks, unrecognized ---------------------------------

test('package/SBOM rows are not_applicable (module validation is axis A2)', () => {
  assert.equal(s({ algorithm: 'TLS 1.3 / AES-256-GCM / SHA-256 / Classical RSA-ECC', type: 'package' }).status, 'not_applicable');
});

test('blank, UNKNOWN and unrecognized algorithms are not determined, with provenance', () => {
  assert.equal(s({ algorithm: '' }).status, 'unknown');
  assert.equal(s({ algorithm: 'UNKNOWN' }).status, 'unknown');
  const u = s({ algorithm: 'FrobCipher-9000' });
  assert.equal(u.status, 'unknown');
  assert.match(u.rationale, new RegExp(FIPS_TABLE_VERSION));
});

// ---- Roadmap rollup (summarizeFipsCompliance) — DB-free --------------------

import { summarizeFipsCompliance } from '../src/lib/roadmapReport';

const row = (algorithm: string, count: number, extra: Partial<{ key_size: number; hash_algorithm: string; purpose: string; type: string }> = {}) =>
  ({ algorithm, count, key_size: extra.key_size ?? null, hash_algorithm: extra.hash_algorithm ?? null, purpose: extra.purpose ?? null, type: extra.type ?? null });

test('rollup counts disallowed-now, sunsetting (earliest first) and module rows separately', () => {
  const fc = summarizeFipsCompliance([
    row('RSA', 10, { key_size: 1024 }),                 // disallowed
    row('3DES', 2),                                      // disallowed
    row('RSA', 5, { key_size: 2048 }),                   // acceptable → 2035 (draft)
    row('HMAC-SHA1', 3, { purpose: 'symmetric' }),       // acceptable → 2030 (not draft)
    row('ML-KEM-768', 4),                                // pq_approved
    row('openssl', 7, { type: 'package' }),              // module row (axis A2)
    row('RSA', 1),                                       // unknown (no key size)
  ]);
  assert.equal(fc.disallowedNow, 12);
  assert.equal(fc.moduleRows, 7);
  assert.equal(fc.assessed, 25, 'module rows excluded from the assessed total');
  assert.equal(fc.byStatus.unknown, 1);
  assert.equal(fc.sunsetting[0].disallowedAfter, '2030-12-31', 'earliest sunset first');
  assert.equal(fc.sunsetting[0].draft, false);
  assert.equal(fc.sunsetting[1].algorithm, 'RSA-2048');
  assert.equal(fc.sunsetting[1].draft, true);
  assert.equal(fc.topDisallowed[0].algorithm, 'RSA-1024');
});

test('rollup never calls approved algorithms "compliant" — module validation is undetermined', () => {
  const fc = summarizeFipsCompliance([row('AES-256-GCM', 9), row('ML-DSA-65', 1)]);
  assert.equal(fc.disallowedNow, 0);
  assert.equal(fc.approvedModuleUndetermined, 10);
  assert.match(fc.note, /NOT YET DETERMINED/);
  assert.doesNotMatch(fc.headline, /compliant\b(?! today)/i);
});

test('empty inventory produces a safe headline', () => {
  const fc = summarizeFipsCompliance([]);
  assert.equal(fc.assessed, 0);
  assert.match(fc.headline, /No algorithm instances/);
});
