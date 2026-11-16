import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cavpCoverage, cavpNeeds, cavpValidationsOf, CAVP_MAP_VERSION } from '../src/lib/cavpCoverage';
import { CAVP_BY_CERTIFICATE, CAVP_DATA_READ } from '../src/lib/cavpData';
import { complianceVerdict, VERDICT_ORDER } from '../src/lib/complianceVerdict';
import { CMVP_MODULES } from '../src/lib/cmvpModules';
import { HOST_VALIDATIONS } from '../src/lib/hostCryptoModules';
import { assessAsset, buildAttestationCsv, ATTESTATION_COLUMNS } from '../src/lib/fipsAttestation';
import { cbomComponent } from '../src/lib/cyclonedx';

const prop = (c: any, name: string): string | undefined => c.properties.find((p: any) => p.name === name)?.value;
const labels = (algorithm: string, extra: any = {}) => cavpNeeds({ algorithm, ...extra }).map(n => n.label);

// ---- The vendored data --------------------------------------------------------

test('the data file is stamped, and every list belongs to a certificate that is in a module map', () => {
  assert.match(CAVP_DATA_READ, /^\d{4}-\d{2}-\d{2}$/);
  assert.equal(CAVP_MAP_VERSION, CAVP_DATA_READ);
  const known = new Set<string>([
    ...Object.values(CMVP_MODULES).flatMap(m => m.certificates.map(c => c.certId)),
    ...HOST_VALIDATIONS.map(v => v.certId),
  ]);
  for (const [certId, list] of Object.entries(CAVP_BY_CERTIFICATE)) {
    assert.ok(known.has(certId), `list for #${certId}, which no module map names`);
    assert.ok(Object.keys(list).length > 0, `#${certId} has an empty list (absent is the way to say unknown)`);
    for (const [name, ids] of Object.entries(list)) {
      assert.ok(name.trim() === name && name.length > 0);
      assert.ok(ids.length > 0 && ids.every(i => /^([A-Z]+ )?[A-Z]?\d+$/.test(i)), `#${certId} ${name}: ${ids}`);
    }
  }
});

// ---- Turning an asset's algorithm text into CAVP needs ---------------------------

test('algorithm text maps to the CAVP algorithm it needs', () => {
  assert.deepEqual(labels('AES-256-GCM'), ['AES-GCM']);
  assert.deepEqual(labels('aes256-ctr'), ['AES-CTR']);
  assert.deepEqual(labels('AES-256'), ['AES (mode not observed)']);
  assert.deepEqual(labels('TLS_AES_256_GCM_SHA384'), ['AES-GCM', 'SHA2-384']);
  assert.deepEqual(labels('ECDHE-RSA-AES128-GCM-SHA256', { purpose: 'key_establishment' }),
    ['AES-GCM', 'ECDH key agreement', 'RSA signature', 'SHA2-256']);
  assert.deepEqual(labels('RSA', { hash_algorithm: 'sha256WithRSAEncryption' }), ['RSA signature', 'SHA2-256']);
  assert.deepEqual(labels('TLS_RSA_WITH_AES_128_CBC_SHA', { purpose: 'key_establishment' }), ['AES-CBC', 'RSA key transport', 'SHA-1']);
  assert.deepEqual(labels('ECDSA P-256'), ['ECDSA']);
  assert.deepEqual(labels('EC P-384', { purpose: 'key_establishment' }), ['ECDH key agreement']);
  assert.deepEqual(labels('ssh-ed25519'), ['EdDSA']);
  assert.deepEqual(labels('diffie-hellman-group14-sha256'), ['Diffie-Hellman key agreement', 'SHA2-256']);
  assert.deepEqual(labels('HMAC-SHA256'), ['HMAC-SHA2-256']);
  assert.deepEqual(labels('HMAC'), ['HMAC (hash not observed)']);
  assert.deepEqual(labels('SHA3-256'), ['SHA3-256']);
  assert.deepEqual(labels('SHA-512/256'), ['SHA2-512/256']);
  assert.deepEqual(labels('PBKDF2-HMAC-SHA256'), ['PBKDF', 'HMAC-SHA2-256']);
});

test('ECDSA, EdDSA and ML-DSA are never mistaken for DSA, nor ECDH for DH', () => {
  for (const a of ['ECDSA P-256', 'Ed25519', 'ML-DSA-65', 'SLH-DSA-SHA2-128s', 'ECDHE-ECDSA-AES256-GCM-SHA384']) {
    assert.ok(!labels(a).includes('DSA'), a);
    assert.ok(!labels(a).includes('Diffie-Hellman key agreement'), a);
  }
  assert.deepEqual(labels('DSA-2048'), ['DSA']);
});

test('a post-quantum name is one need; its embedded tokens are parameters', () => {
  assert.deepEqual(labels('X25519MLKEM768'), ['ML-KEM']);
  assert.deepEqual(labels('ML-DSA-65'), ['ML-DSA']);
  assert.deepEqual(labels('SLH-DSA-SHA2-128s'), ['SLH-DSA']);
});

test('text with nothing CAVP-testable yields no needs', () => {
  for (const a of ['', 'SM2', 'ChaCha20-Poly1305', 'X25519', 'UNKNOWN']) assert.deepEqual(labels(a), [], a);
});

// ---- Coverage against real certificate lists ------------------------------------

test('covered: algorithm and mode on the list, with the validation numbers NIST prints', () => {
  const r = cavpCoverage(['4884'], { algorithm: 'AES-256-GCM' });
  assert.equal(r.state, 'covered');
  assert.equal(r.certId, '4884');
  assert.equal(r.familyOnly, false);
  assert.deepEqual(r.matched[0].algorithms, ['AES-GCM']);
  assert.deepEqual(r.matched[0].validations, CAVP_BY_CERTIFICATE['4884']['AES-GCM']);
  assert.match(r.note, /Key sizes, curves and other tested capabilities are not checked/);
});

test('covered at family level says the mode was not observed', () => {
  const r = cavpCoverage(['4884'], { algorithm: 'AES-256' });
  assert.equal(r.state, 'covered');
  assert.equal(r.familyOnly, true);
  assert.match(r.note, /mode in use was not observed/);
});

test('not_covered: a validated module that never had the algorithm tested', () => {
  // RHEL 9 OpenSSL FIPS provider: no EdDSA and no ML-KEM on its list. OpenSSL 3.5 has both.
  for (const algorithm of ['Ed25519', 'X25519MLKEM768']) {
    const rhel = cavpCoverage(['5573'], { algorithm });
    assert.equal(rhel.state, 'not_covered', algorithm);
    assert.equal(rhel.missing.length, 1);
    assert.match(rhel.note, /not shown as tested/);
    assert.equal(cavpCoverage(['5586'], { algorithm }).state, 'covered', algorithm);
  }
  // Every part of a suite must be on the list: one missing part is enough.
  const suite = cavpCoverage(['5410'], { algorithm: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', purpose: 'key_establishment' });
  assert.equal(suite.state, 'not_covered');
  assert.deepEqual(suite.missing, ['Triple-DES']);
  assert.ok(suite.matched.length >= 1);
});

test('unknown: no certificate, no list for the certificate, or an unmappable algorithm', () => {
  assert.equal(cavpCoverage([], { algorithm: 'AES-256-GCM' }).state, 'unknown');
  assert.equal(cavpCoverage(undefined, { algorithm: 'AES-256-GCM' }).state, 'unknown');
  const noList = cavpCoverage(['4811'], { algorithm: 'AES-256-GCM' });   // FIPS 140-2 page, no structured list
  assert.equal(noList.state, 'unknown');
  assert.match(noList.note, /#4811/);
  assert.equal(cavpCoverage(['4884'], { algorithm: 'SM2' }).state, 'unknown');
  assert.equal(cavpCoverage(['999999'], { algorithm: 'Ed25519' }).state, 'unknown');
});

test('several certificates: one that covers is enough; a missing list blocks not_covered', () => {
  assert.equal(cavpCoverage(['4811', '5573'], { algorithm: 'AES-256-GCM' }).state, 'covered');
  assert.equal(cavpCoverage(['5573', '5586'], { algorithm: 'Ed25519' }).certId, '5586');
  assert.equal(cavpCoverage(['5573', '5438'], { algorithm: 'Ed25519' }).state, 'not_covered');
  // #4811 has no list, so "not on #5573's list" cannot be generalised to the module.
  assert.equal(cavpCoverage(['4811', '5573'], { algorithm: 'Ed25519' }).state, 'unknown');
});

test('validation numbers are de-duplicated and capped for display', () => {
  const r = cavpCoverage(['5573'], { algorithm: 'ECDHE-RSA-AES128-GCM-SHA256', purpose: 'key_establishment' });
  const ids = cavpValidationsOf(r, 5);
  assert.ok(ids.length <= 5 && new Set(ids).size === ids.length);
});

// ---- The verdict refinement -----------------------------------------------------

test('only not_covered refines compliant; covered and unknown change nothing', () => {
  assert.ok(VERDICT_ORDER.includes('compliant_module_algo_unverified'));
  for (const fips of ['approved', 'pq_approved', 'acceptable']) {
    const base = complianceVerdict(fips, 'active');
    assert.equal(complianceVerdict(fips, 'active', 'covered'), base);
    assert.equal(complianceVerdict(fips, 'active', 'unknown'), base);
    assert.equal(complianceVerdict(fips, 'active', undefined), base);
    assert.equal(complianceVerdict(fips, 'active', 'not_covered'), 'compliant_module_algo_unverified');
  }
});

test('coverage never improves a verdict and never touches a non-compliant one', () => {
  for (const fips of ['approved', 'pq_approved', 'acceptable', 'restricted', 'disallowed', 'non_fips', 'unknown', 'not_applicable']) {
    for (const cmvp of ['historical', 'revoked', 'none', 'unverified', 'not-assessed']) {
      for (const cavp of ['covered', 'not_covered', 'unknown']) {
        assert.equal(complianceVerdict(fips, cmvp, cavp), complianceVerdict(fips, cmvp), `${fips}/${cmvp}/${cavp}`);
      }
    }
  }
  for (const fips of ['restricted', 'disallowed', 'non_fips', 'unknown']) {
    assert.equal(complianceVerdict(fips, 'active', 'covered'), complianceVerdict(fips, 'active'));
    assert.equal(complianceVerdict(fips, 'active', 'not_covered'), complianceVerdict(fips, 'active'));
  }
});

// ---- End to end through the one assessment function, the CSV and the CBOM ---------

const kmsKey = (algorithm: string) => ({ id: 'k1', name: 'key', type: 'kms_key', algorithm, crypto_module: 'aws-kms-hsm', crypto_module_evidence: 'Origin=AWS_KMS' });

test('a cloud key in a validated HSM: covered stays compliant, ML-DSA (not on the list) is refined', () => {
  const aes = assessAsset(kmsKey('AES-256-GCM'));
  assert.equal(aes.cmvpStatus, 'active');
  assert.equal(aes.cavpCovered, 'covered');
  assert.equal(aes.verdict, 'compliant');
  assert.ok(aes.cavpValidations.length > 0);

  const pq = assessAsset(kmsKey('ML-DSA-65'));
  assert.equal(pq.cmvpStatus, 'active');
  assert.equal(pq.fipsStatus, 'pq_approved');
  assert.equal(pq.cavpCovered, 'not_covered');
  assert.equal(pq.verdict, 'compliant_module_algo_unverified');
});

test('an asset with no certificate reports unknown and keeps its Stage 5 verdict', () => {
  const a = assessAsset({ id: 'c', name: 'cert.pem', type: 'certificate', algorithm: 'RSA', key_size: 3072, hash_algorithm: 'sha256WithRSAEncryption' });
  assert.equal(a.cavpCovered, 'unknown');
  assert.equal(a.verdict, 'approved_unvalidated');
  assert.deepEqual(a.cavpValidations, []);
});

test('evidence CSV: stamped with the CAVP data version; coverage cells blank without a certificate', () => {
  const out = buildAttestationCsv('T', [
    kmsKey('ML-DSA-65'),
    { id: 'c', name: 'cert.pem', type: 'certificate', algorithm: 'RSA', key_size: 3072, hash_algorithm: 'sha256WithRSAEncryption' },
  ]);
  const lines = out.csv.split('\r\n');
  assert.ok(lines.some(l => l.startsWith('# CAVP algorithm lists,' + CAVP_MAP_VERSION)));
  const header = lines.find(l => l.startsWith('Asset,'))!.split(',');
  assert.deepEqual(header, [...ATTESTATION_COLUMNS]);
  const col = header.indexOf('Algorithm on module CAVP list');
  assert.ok(col > 0);
  assert.equal(out.counts.compliant_module_algo_unverified, 1);
  const kms = lines.find(l => l.startsWith('key,'))!;
  assert.match(kms, /not_covered/);
  assert.match(kms, /compliant_module_algo_unverified/);
  const cert = lines.find(l => l.startsWith('cert.pem,'))!;
  assert.doesNotMatch(cert, /unknown,|not_covered|covered/);
});

test('CBOM: coverage properties only where a certificate is reported, and the verdict uses them', () => {
  const pq = cbomComponent({ id: 'k', name: 'key', algorithm: 'ML-DSA-65', assetKind: 'kms_key', cryptoModule: 'aws-kms-hsm' } as any);
  assert.equal(prop(pq, 'quarkshield:cavpCovered'), 'not_covered');
  assert.equal(prop(pq, 'quarkshield:complianceVerdict'), 'compliant_module_algo_unverified');
  assert.equal(prop(pq, 'quarkshield:cavpMapVersion'), CAVP_MAP_VERSION);
  assert.equal(prop(pq, 'quarkshield:cavpValidations'), undefined);

  const aes = cbomComponent({ id: 'k', name: 'key', algorithm: 'AES-256-GCM', assetKind: 'kms_key', cryptoModule: 'aws-kms-hsm' } as any);
  assert.equal(prop(aes, 'quarkshield:cavpCovered'), 'covered');
  assert.equal(prop(aes, 'quarkshield:complianceVerdict'), 'compliant');
  assert.ok((prop(aes, 'quarkshield:cavpValidations') || '').length > 0);

  const plain = cbomComponent({ id: 'c', name: 'cert', algorithm: 'RSA', keySize: 3072, assetKind: 'certificate' } as any);
  for (const n of ['cavpCovered', 'cavpValidations', 'cavpNote', 'cavpMapVersion']) assert.equal(prop(plain, `quarkshield:${n}`), undefined, n);
});
