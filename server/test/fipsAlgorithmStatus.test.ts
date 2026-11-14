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

// ---- Board deck / audit report gap lines (aiController.buildComplianceGaps) ----

import { buildComplianceGaps } from '../src/controllers/aiController';

test('deck/report gaps are derived from data and never cite SP 800-208 for discovery', () => {
  const g = buildComplianceGaps([
    { algorithm: 'RSA', key_size: 1024, is_vulnerable: true, compliance_violations: ['CNSA 2.0'] },
    { algorithm: 'RSA', key_size: 2048, is_vulnerable: true, compliance_violations: [] },
    { algorithm: 'AES-256-GCM', is_vulnerable: false },
  ]);
  assert.ok(g.lines.some(l => l.startsWith('NIST SP 800-131A Rev. 2 | 1 algorithm instance(s) disallowed')));
  assert.ok(g.lines.some(l => l.startsWith('NIST IR 8547 (draft) | 1 ')), 'RSA-2048 sunset is labelled draft');
  assert.ok(g.lines.some(l => l.startsWith('NSA CNSA 2.0 | 2 quantum-vulnerable')));
  assert.ok(g.lines.every(l => !/800-208/.test(l)));
  assert.deepEqual(g.recorded, ['CNSA 2.0']);
});

test('a clean inventory yields NO invented gaps', () => {
  const g = buildComplianceGaps([{ algorithm: 'ML-KEM-768', is_vulnerable: false }, { algorithm: 'AES-256-GCM', is_vulnerable: false }]);
  assert.deepEqual(g.lines, []);
});

// ---- AI generators: tenant scope + deck facts --------------------------------

import { resolveAssetScope, buildDeckFacts } from '../src/controllers/aiController';

const req = (user: any, query: any = {}, body: any = {}) => ({ user, query, body } as any);

test('tenant scope: tenant sessions are pinned to their own tenant; no fleet fall-through', () => {
  assert.deepEqual(resolveAssetScope(req(undefined)), { ok: false, status: 401, error: 'Authentication required.' });
  // A tenant user cannot widen scope via ?tenant / body.tenant.
  assert.deepEqual(resolveAssetScope(req({ role: 'admin', tenant: 'acme' }, { tenant: 'othercorp' }, { tenant: 'othercorp' })), { ok: true, tenant: 'acme' });
  // A non-super session with NO tenant must not see the whole fleet.
  const noTenant = resolveAssetScope(req({ role: 'admin', tenant: '' }));
  assert.equal(noTenant.ok, false);
  assert.equal((noTenant as any).status, 403);
});

test('tenant scope: super sessions may target a tenant, else fleet', () => {
  assert.deepEqual(resolveAssetScope(req({ role: 'superadmin' }, { tenant: 'acme' })), { ok: true, tenant: 'acme' });
  assert.deepEqual(resolveAssetScope(req({ role: 'superadmin' }, { tenant: 'all' })), { ok: true, tenant: null });
});

test('deck facts: HNDL only for key establishment; no invented Mosca numbers; 0 assets = 0%', () => {
  const f = buildDeckFacts([
    { algorithm: 'RSA', key_size: 2048, is_vulnerable: true, purpose: 'key_establishment' },
    { algorithm: 'ECDSA P-256', is_vulnerable: true, purpose: 'tls_certificate' },
    { algorithm: 'RSA', key_size: 1024, is_vulnerable: true, purpose: 'code_or_data_signing' },
    { algorithm: 'AES-256-GCM', is_vulnerable: false, purpose: 'symmetric' },
    { algorithm: 'SHA-256', is_vulnerable: false, purpose: 'unknown' },
  ]);
  assert.equal(f.hndl, 1);
  assert.equal(f.sig, 2);
  assert.match(f.baseline, /3 of 5 assets \(60%\)/);
  assert.match(f.baseline, /1 key-establishment asset/);
  assert.match(f.tiers[0], /Non-compliant today: 1 .*RSA-1024/);
  assert.ok(f.tiers.some(t => /RSA-2048 after 2035-12-31 \(NIST IR 8547 draft\)/.test(t)), 'RSA-2048 is a sunset, not a critical deficit');
  assert.ok(f.tiers.every(t => !/SHA-256[^.]*vulnerable/i.test(t)), 'SHA-256 is never called quantum-vulnerable');
  assert.ok(!/fully compliant/i.test(f.tiers.join(' ')));
  assert.doesNotMatch(f.mosca, /\d+\s*>\s*\d+|= \d/, 'no invented shelf-life / CRQC numbers');
  const empty = buildDeckFacts([]);
  assert.equal(empty.vulnPct, 0);
  assert.match(empty.baseline, /No cryptographic assets are in scope/);
});

// (Advisor chat scope tests live in test/tenantAccess.test.ts.)

// ---- Review regressions (PR #4 code review, 2026-11-14) ---------------------
// Each case is the exact input that produced a wrong answer before the fix.

import { summarizeFipsComplianceIndexed } from '../src/lib/roadmapReport';

test('review #1: underscore IANA suites are tokenized — DES / RC4 are not "acceptable"', () => {
  assert.equal(s({ algorithm: 'TLS_RSA_WITH_DES_CBC_SHA', key_size: 2048 }).status, 'disallowed');
  assert.equal(s({ algorithm: 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', key_size: 2048 }).status, 'non_fips');
  assert.equal(s({ algorithm: 'TLS_AES_256_GCM_SHA384' }).status, 'approved', 'TLS 1.3 AEAD suite still approved');
});

test('review #3: key establishment with no identifiable key exchange is unknown, not approved', () => {
  const kex = { purpose: 'key_establishment', type: 'protocol' };
  assert.equal(s({ algorithm: 'key-exchange group not reported / TLSv1.3 / TLS_AES_256_GCM_SHA384', ...kex }).status, 'unknown');
  assert.equal(s({ algorithm: 'key-exchange group not reported / TLSv1.3 / TLS_AES_256_GCM_SHA384', ...kex }).ruleId, 'kex.undetermined');
  assert.equal(s({ algorithm: 'x25519 / TLSv1.3 / TLS_AES_256_GCM_SHA384', ...kex }).status, 'non_fips');
  assert.equal(s({ algorithm: 'ML-KEM-768 + X25519 (Hybrid)', ...kex }).status, 'pq_approved');
});

test('review #4: a SHA-1-signed certificate with a NULL purpose (legacy row) is disallowed', () => {
  assert.equal(s({ algorithm: 'RSA', key_size: 2048, hash_algorithm: 'SHA-1', type: 'certificate', purpose: null }).status, 'disallowed');
  // Non-signature SHA-1 (e.g. HMAC on a config row) is still only on a sunset.
  assert.equal(s({ algorithm: 'HMAC-SHA1', type: 'config', purpose: null }).status, 'acceptable');
});

test('review #5: in a DHE-RSA suite the RSA modulus is not used as the DH group size', () => {
  assert.equal(s({ algorithm: 'DHE-RSA-AES256-SHA', key_size: 2048 }).status, 'unknown');
  assert.equal(s({ algorithm: 'DH', key_size: 2048 }).status, 'acceptable', 'a standalone DH group still uses its own size');
  assert.equal(s({ algorithm: 'DH', key_size: 1024 }).status, 'disallowed');
});

test('review #6: "OpenSSL 3…" is not the SSLv3 protocol; real SSLv3 still is', () => {
  assert.notEqual(s({ algorithm: 'OpenSSL 3.0 FIPS provider', type: 'config' }).status, 'disallowed');
  assert.equal(s({ algorithm: 'SSLv3' }).status, 'disallowed');
  assert.equal(s({ algorithm: 'SSL 3.0' }).status, 'disallowed');
});

test('review #2: the deck counts Shor-breakable public-key assets, not every is_vulnerable row', () => {
  const f = buildDeckFacts([
    { algorithm: '3DES', is_vulnerable: true, type: 'config', purpose: 'configuration' },
    { algorithm: 'MD5', is_vulnerable: true, type: 'config', purpose: 'configuration' },
    { algorithm: 'RSA', key_size: 2048, is_vulnerable: true, purpose: 'tls_certificate' },
  ]);
  assert.equal(f.vuln, 1);
  assert.match(f.baseline, /^1 of 3 assets \(33%\)/);
  assert.ok(f.gaps.lines.some(l => l.startsWith('NSA CNSA 2.0 | 1 quantum-vulnerable asset')));
});

test('review #7: the rollup indexes non-compliant instances per algorithm (proportional priority bump)', () => {
  const { nonCompliantByAlgorithm } = summarizeFipsComplianceIndexed([
    { algorithm: 'RSA', key_size: 2048, hash_algorithm: null, purpose: 'tls_certificate', type: 'certificate', count: 500 },
    { algorithm: 'RSA', key_size: 1024, hash_algorithm: null, purpose: 'tls_certificate', type: 'certificate', count: 1 },
  ]);
  assert.equal(nonCompliantByAlgorithm.get('RSA'), 1, 'only the RSA-1024 instance is non-compliant');
});
