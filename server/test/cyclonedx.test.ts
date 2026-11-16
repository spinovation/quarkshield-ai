import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cbomComponent, quantumSecurityLevel } from '../src/lib/cyclonedx';
import { nistSecurityCategory, FIPS_TABLE_VERSION } from '../src/lib/fipsAlgorithmStatus';

const prop = (c: any, name: string): string | undefined => c.properties.find((p: any) => p.name === name)?.value;
const level = (c: any): unknown => c.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel;
// What a consumer actually receives: undefined fields do not survive serialisation.
const wire = (c: any): any => JSON.parse(JSON.stringify(c));

// ---- NIST security category (CMVP/FIPS Stage 2) ----------------------------

test('FIPS 203/204/205 parameter sets map to their real NIST category', () => {
  assert.deepEqual(['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'].map(a => nistSecurityCategory(a)), [1, 3, 5]);
  assert.deepEqual(['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'].map(a => nistSecurityCategory(a)), [2, 3, 5]);
  assert.deepEqual(['SLH-DSA-SHA2-128s', 'SLH-DSA-SHAKE-192f', 'SLH-DSA-SHA2-256s'].map(a => nistSecurityCategory(a)), [1, 3, 5]);
  assert.equal(nistSecurityCategory('MLKEM1024'), 5);
  assert.equal(nistSecurityCategory('X25519MLKEM768'), 3, 'a hybrid takes the category of its ML-KEM component');
});

test('the reference primitives the categories are defined by', () => {
  assert.deepEqual(['AES-128', 'AES-192-CBC', 'AES-256-GCM', 'AES256'].map(a => nistSecurityCategory(a)), [1, 3, 5, 5]);
  assert.equal(nistSecurityCategory('AES', 256), 5);
  assert.equal(nistSecurityCategory('AES-GCM', 128), 1);
  assert.deepEqual(['SHA-256', 'SHA256', 'SHA3-256', 'SHA-384', 'SHA3-384'].map(a => nistSecurityCategory(a)), [2, 2, 2, 4, 4]);
});

test('no category is invented when the name does not state one', () => {
  for (const a of [
    'ML-KEM', 'ML-DSA', 'SLH-DSA',            // family without a parameter set
    'Kyber768', 'Dilithium3', 'SPHINCS+',     // pre-standard names
    'LMS', 'XMSS', 'Falcon-512',              // not a FIPS 203/204/205 parameter set
    'AES', 'AES-GCM',                         // key size unknown
    'SHA-512', 'HMAC-SHA256', 'ChaCha20-Poly1305',
    'TLS_AES_256_GCM_SHA384',                 // a suite: its key exchange decides, not AES
    'TLS 1.3 / AES-256-GCM / SHA-384',
    'RSA-4096', 'ECDSA P-384', '', 'Unknown',
  ]) {
    assert.equal(nistSecurityCategory(a), undefined, `"${a}" must not be given a category`);
  }
  assert.equal(nistSecurityCategory('AES', 512), undefined);
  assert.equal(nistSecurityCategory('ML-KEM-7680'), undefined, 'a longer number is not a parameter set');
});

// ---- nistQuantumSecurityLevel in the CBOM ----------------------------------

test('flagged assets are level 0; an unflagged classical public-key row gets no level', () => {
  assert.equal(quantumSecurityLevel({ algorithm: 'RSA', keySize: 2048, isVulnerable: true }), 0);
  assert.equal(quantumSecurityLevel({ algorithm: 'MD5', isVulnerable: true }), 0);
  // The scanner's verdict is not overridden (console counts must match the export), but a
  // classical public-key algorithm can never be given a positive category either.
  assert.equal(quantumSecurityLevel({ algorithm: 'RSA', keySize: 4096, isVulnerable: false }), undefined);
  assert.equal(quantumSecurityLevel({ algorithm: 'ECDSA / RSA', isVulnerable: false }), undefined);
  assert.equal(quantumSecurityLevel({ algorithm: 'TLS 1.3 / AES-256-GCM / SHA-256 / Classical RSA-ECC', isVulnerable: false }), undefined);
  const c = cbomComponent({ id: 't', name: 'trust anchor', algorithm: 'RSA', keySize: 4096, isVulnerable: false, assetKind: 'ca_root' });
  assert.equal(prop(c, 'quarkshield:quantumVulnerable'), 'false');
});

test('descriptive labels the scanner writes carry no parameter set, so no category', () => {
  for (const a of ['ML-KEM (Kyber)', 'ML-DSA (Dilithium)', 'SLH-DSA (SPHINCS+)', 'Security runtime (OS package)', 'TLS 1.3', 'AES-256-GCM96']) {
    assert.equal(quantumSecurityLevel({ algorithm: a, isVulnerable: false }), undefined, a);
  }
});

test('the old blanket "level 3" is gone: real category or omitted', () => {
  const lv = (algorithm: string, keySize?: number) =>
    level(cbomComponent({ id: 'x', name: 'x', algorithm, keySize, isVulnerable: false, assetKind: 'algorithm' }));
  assert.equal(lv('ML-KEM-1024'), 5);
  assert.equal(lv('ML-KEM-512'), 1);
  assert.equal(lv('AES-128'), 1, 'AES-128 used to be exported as category 3');
  assert.equal(lv('AES', 256), 5);
  assert.equal(lv('SHA-512'), undefined);
  assert.equal(lv('ChaCha20-Poly1305'), undefined);

  const c = wire(cbomComponent({ id: 'x', name: 'x', algorithm: 'SHA-512', isVulnerable: false, assetKind: 'algorithm' }));
  assert.equal('nistQuantumSecurityLevel' in c.cryptoProperties.algorithmProperties, false, 'omitted on the wire, not null or 0');
  assert.equal(prop(c, 'quarkshield:quantumVulnerable'), 'false', 'vulnerability stays explicit when the level is omitted');
});

test('level is set the same way for certificates and key material', () => {
  const cert = cbomComponent({ id: 'c', name: 'CN=web', algorithm: 'RSA', keySize: 2048, hashAlgorithm: 'SHA-256', isVulnerable: true, assetKind: 'certificate' });
  assert.equal(cert.cryptoProperties.assetType, 'certificate');
  assert.equal(level(cert), 0);
  const key = cbomComponent({ id: 'k', name: 'id_mldsa', algorithm: 'ML-DSA-65', isVulnerable: false, assetKind: 'private_key' });
  assert.equal(key.cryptoProperties.assetType, 'related-crypto-material');
  assert.equal(level(key), 3);
});

// ---- FIPS properties -------------------------------------------------------

test('components carry FIPS algorithm status, standard, sunset and table version', () => {
  const rsa = cbomComponent({ id: 'r', name: 'CN=web', algorithm: 'RSA', keySize: 2048, hashAlgorithm: 'SHA-256', purpose: 'tls_certificate', isVulnerable: true, assetKind: 'certificate' });
  assert.equal(prop(rsa, 'quarkshield:fipsStatus'), 'acceptable');
  assert.equal(prop(rsa, 'quarkshield:fipsStandard'), 'SP 800-131A Rev. 2');
  assert.equal(prop(rsa, 'quarkshield:fipsDeprecatedAfter'), '2030-12-31');
  assert.equal(prop(rsa, 'quarkshield:transitionDate'), '2035-12-31');
  assert.equal(prop(rsa, 'quarkshield:fipsDraftGuidance'), 'true', 'IR 8547 dates are draft and must say so');
  assert.equal(prop(rsa, 'quarkshield:fipsTableVersion'), FIPS_TABLE_VERSION);
  assert.equal(prop(rsa, 'quarkshield:quantumVulnerable'), 'true');

  const kem = cbomComponent({ id: 'm', name: 'kex', algorithm: 'ML-KEM-768', purpose: 'key_establishment', isVulnerable: false, assetKind: 'algorithm' });
  assert.equal(prop(kem, 'quarkshield:fipsStatus'), 'pq_approved');
  assert.equal(prop(kem, 'quarkshield:fipsStandard'), 'FIPS 203');
  assert.equal(prop(kem, 'quarkshield:transitionDate'), undefined);
  assert.equal(prop(kem, 'quarkshield:fipsDraftGuidance'), undefined);
});

test('purpose and hash reach the resolver: a SHA-1-signed certificate is disallowed', () => {
  const c = cbomComponent({ id: 's', name: 'CN=old', algorithm: 'RSA', keySize: 2048, hashAlgorithm: 'SHA-1', isVulnerable: true, assetKind: 'certificate' });
  assert.equal(prop(c, 'quarkshield:fipsStatus'), 'disallowed');
});

test('an unrecognised algorithm is "unknown" with no standard, never approved', () => {
  const c = cbomComponent({ id: 'u', name: 'thing', algorithm: 'FrobnicateCipher', assetKind: 'algorithm' });
  assert.equal(prop(c, 'quarkshield:fipsStatus'), 'unknown');
  assert.equal(prop(c, 'quarkshield:fipsStandard'), undefined);
  assert.equal(prop(c, 'quarkshield:quantumVulnerable'), undefined, 'no flag when the scanner gave none');
  assert.equal(level(c), undefined);
});

test('algorithm approval is never presented as module validation', () => {
  for (const algorithm of ['ML-KEM-768', 'AES-256-GCM', 'RSA']) {
    const c = cbomComponent({ id: 'a', name: 'a', algorithm, keySize: 2048, assetKind: 'algorithm' });
    assert.equal(prop(c, 'quarkshield:cmvpStatus'), 'not-assessed');
    assert.equal(c.properties.some((p: any) => /cmvpCert/i.test(p.name)), false);
    assert.equal(c.properties.some((p: any) => /validated|compliant/i.test(String(p.value)) && /fips|cmvp/i.test(p.name)), false);
    // The verdict exists (Stage 5) but with no module observed it can never read compliant.
    assert.ok(['approved_unvalidated', 'noncompliant', 'not_determined'].includes(String(prop(c, 'quarkshield:complianceVerdict'))));
  }
});

test('existing fields that QSG and the console read are unchanged', () => {
  const c = cbomComponent({ id: 'id-1', name: 'CN=web', algorithm: 'RSA', keySize: 2048, isVulnerable: true, assetKind: 'certificate', status: 'Quantum-vulnerable', hostname: 'web01', riskLevel: 'high' });
  assert.equal(c['bom-ref'], 'id-1');
  assert.equal(c.type, 'cryptographic-asset');
  assert.equal(prop(c, 'quarkshield:algorithm'), 'RSA');
  assert.equal(prop(c, 'quarkshield:keyLength'), '2048');
  assert.equal(prop(c, 'quarkshield:quantumStatus'), 'Quantum-vulnerable');
  assert.equal(prop(c, 'quarkshield:hostname'), 'web01');
  assert.equal(prop(c, 'quarkshield:riskLevel'), 'high');
});
