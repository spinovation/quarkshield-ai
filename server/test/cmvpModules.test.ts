import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CMVP_MODULES, CMVP_MAP_VERSION, awsKmsModule, azureKeyVaultModule, gcpKmsModule, vaultModule,
  resolveCmvpModule, cmvpForConsole,
} from '../src/lib/cmvpModules';
import { cbomComponent } from '../src/lib/cyclonedx';

const prop = (c: any, name: string): string | undefined => c.properties.find((p: any) => p.name === name)?.value;

// ---- Observation: only what the provider's API said ------------------------

test('AWS KMS: Origin and region decide the module', () => {
  assert.equal(awsKmsModule({ origin: 'AWS_KMS', region: 'us-east-1' })?.key, 'aws-kms-hsm');
  assert.equal(awsKmsModule({ origin: 'AWS_KMS', region: 'us-gov-west-1' })?.key, 'aws-kms-hsm');
  const imported = awsKmsModule({ origin: 'EXTERNAL', region: 'eu-west-1' });
  assert.equal(imported?.key, 'aws-kms-hsm');
  assert.match(imported!.evidence, /imported/, 'imported key material is said, not hidden');
  assert.equal(awsKmsModule({ origin: 'AWS_KMS', region: 'cn-north-1' })?.key, 'aws-kms-china');
  assert.equal(awsKmsModule({ origin: 'AWS_CLOUDHSM', region: 'us-east-1' })?.key, 'aws-cloudhsm-key-store');
  assert.equal(awsKmsModule({ origin: 'EXTERNAL_KEY_STORE', region: 'us-east-1' })?.key, 'aws-external-key-store');
});

test('AWS KMS: nothing is recorded without an Origin or a region', () => {
  assert.equal(awsKmsModule({ region: 'us-east-1' }), undefined);
  assert.equal(awsKmsModule({ origin: 'SOMETHING_NEW', region: 'us-east-1' }), undefined);
  assert.equal(awsKmsModule({ origin: 'AWS_KMS' }), undefined, 'the certificate depends on where the service runs');
});

test('Azure: host, key type and hsmPlatform decide the module', () => {
  const v = 'https://corp.vault.azure.net';
  assert.equal(azureKeyVaultModule({ vaultUrl: v, keyType: 'RSA' })?.key, 'azure-kv-software');
  assert.equal(azureKeyVaultModule({ vaultUrl: v, keyType: 'EC', hsmPlatform: '0' })?.key, 'azure-kv-software');
  assert.equal(azureKeyVaultModule({ vaultUrl: v, keyType: 'RSA-HSM', hsmPlatform: '2' })?.key, 'azure-kv-hsm-platform2');
  assert.equal(azureKeyVaultModule({ vaultUrl: v, keyType: 'EC-HSM', hsmPlatform: '1' })?.key, 'azure-kv-hsm-platform1');
  assert.equal(azureKeyVaultModule({ vaultUrl: v, keyType: 'RSA-HSM' })?.key, 'azure-kv-hsm', 'platform not reported');
  assert.equal(azureKeyVaultModule({ vaultUrl: 'https://corp.managedhsm.azure.net', keyType: 'RSA-HSM' })?.key, 'azure-managed-hsm');
  assert.equal(azureKeyVaultModule({ vaultUrl: 'https://corp.managedhsm.usgovcloudapi.net/', keyType: 'oct-HSM' })?.key, 'azure-managed-hsm');
  assert.equal(azureKeyVaultModule({ vaultUrl: v, keyType: '' }), undefined, 'no key type means the key could not be read');
  // A vault merely NAMED like a managed HSM is still a vault.
  assert.equal(azureKeyVaultModule({ vaultUrl: 'https://managedhsm.vault.azure.net', keyType: 'RSA' })?.key, 'azure-kv-software');
});

test('Google Cloud KMS: protectionLevel decides the module', () => {
  assert.equal(gcpKmsModule('SOFTWARE')?.key, 'gcp-kms-software');
  assert.equal(gcpKmsModule('HSM')?.key, 'gcp-kms-hsm');
  assert.equal(gcpKmsModule('HSM_SINGLE_TENANT')?.key, 'gcp-kms-hsm-single-tenant');
  assert.equal(gcpKmsModule('EXTERNAL')?.key, 'gcp-kms-external');
  assert.equal(gcpKmsModule('EXTERNAL_VPC')?.key, 'gcp-kms-external');
  assert.equal(gcpKmsModule(undefined), undefined);
  assert.equal(gcpKmsModule('PROTECTION_LEVEL_UNSPECIFIED'), undefined);
});

test('Vault: the version string decides the module', () => {
  assert.equal(vaultModule({ version: '1.19.4+ent.fips1403' })?.key, 'vault-enterprise-fips1403');
  assert.equal(vaultModule({ version: '1.19.4+ent.hsm.fips1403' })?.key, 'vault-enterprise-fips1403');
  assert.equal(vaultModule({ version: '1.16.1+ent.fips1402' })?.key, 'vault-enterprise-fips1402');
  assert.equal(vaultModule({ version: '1.17.0+ent' })?.key, 'vault-enterprise-non-fips');
  assert.equal(vaultModule({ version: '1.19.0', sealType: 'shamir' })?.key, 'vault-community');
  assert.match(vaultModule({ version: '1.19.0', sealType: 'shamir' })!.evidence, /seal type shamir/);
  assert.equal(vaultModule({}), undefined);
});

test('every module key an observer can return exists in the map', () => {
  const keys = [
    awsKmsModule({ origin: 'AWS_KMS', region: 'us-east-1' }), awsKmsModule({ origin: 'AWS_KMS', region: 'cn-north-1' }),
    awsKmsModule({ origin: 'AWS_CLOUDHSM', region: 'x' }), awsKmsModule({ origin: 'EXTERNAL_KEY_STORE', region: 'x' }),
    azureKeyVaultModule({ vaultUrl: 'https://a.vault.azure.net', keyType: 'RSA' }),
    azureKeyVaultModule({ vaultUrl: 'https://a.vault.azure.net', keyType: 'RSA-HSM' }),
    azureKeyVaultModule({ vaultUrl: 'https://a.vault.azure.net', keyType: 'RSA-HSM', hsmPlatform: 1 }),
    azureKeyVaultModule({ vaultUrl: 'https://a.vault.azure.net', keyType: 'RSA-HSM', hsmPlatform: 2 }),
    azureKeyVaultModule({ vaultUrl: 'https://a.managedhsm.azure.net', keyType: 'RSA-HSM' }),
    gcpKmsModule('SOFTWARE'), gcpKmsModule('HSM'), gcpKmsModule('HSM_SINGLE_TENANT'), gcpKmsModule('EXTERNAL'),
    vaultModule({ version: '1+ent.fips1403' }), vaultModule({ version: '1+ent.fips1402' }), vaultModule({ version: '1+ent' }), vaultModule({ version: '1' }),
  ].map(o => o!.key);
  for (const k of keys) assert.ok(CMVP_MODULES[k], `missing map entry for ${k}`);
  assert.deepEqual([...new Set(keys)].sort(), Object.keys(CMVP_MODULES).sort(), 'no map entry is unreachable');
});

// ---- Resolution ------------------------------------------------------------

test('a module with a published, active certificate resolves to it', () => {
  const r = resolveCmvpModule('aws-kms-hsm');
  assert.equal(r.status, 'active');
  assert.deepEqual(r.certIds, ['4884']);
  assert.equal(r.standard, 'FIPS 140-3');
  assert.equal(r.level, 3);
  assert.equal(r.sunsetDate, '2029-11-17');
  assert.equal(r.mapVersion, CMVP_MAP_VERSION);
});

test('a historical certificate is reported as historical, never as active', () => {
  const r = resolveCmvpModule('vault-enterprise-fips1402');
  assert.equal(r.status, 'historical');
  assert.deepEqual(r.certIds, ['3678']);
});

test('no certificate is ever emitted for a module the provider publishes none for', () => {
  for (const [key, entry] of Object.entries(CMVP_MODULES)) {
    const r = resolveCmvpModule(key);
    if (entry.certificates.length === 0) {
      assert.deepEqual(r.certIds, [], key);
      assert.ok(r.status === 'none' || r.status === 'unverified', `${key} -> ${r.status}`);
      assert.equal(r.standard, undefined, `${key}: no level without a certificate`);
      assert.equal(r.level, undefined, key);
    } else {
      assert.ok(['active', 'historical', 'revoked'].includes(r.status), key);
    }
    assert.ok(r.note && r.note.length > 20, `${key} needs a plain-language note`);
  }
  assert.equal(resolveCmvpModule('gcp-kms-hsm').status, 'unverified');
  assert.equal(resolveCmvpModule('aws-kms-china').status, 'none');
  assert.equal(resolveCmvpModule('vault-community').status, 'none');
});

test('no module recorded is not-assessed; an unknown key is unverified with no certificate', () => {
  for (const k of [undefined, null, '', '  ']) assert.equal(resolveCmvpModule(k as any).status, 'not-assessed');
  for (const k of ['some-future-module', 'constructor', '__proto__', 'toString']) {
    const r = resolveCmvpModule(k);
    assert.equal(r.status, 'unverified', k);
    assert.deepEqual(r.certIds, [], k);
  }
});

test('map data is well-formed', () => {
  assert.match(CMVP_MAP_VERSION, /^\d{4}-\d{2}-\d{2}$/);
  for (const [key, e] of Object.entries(CMVP_MODULES)) {
    for (const c of e.certificates) {
      assert.match(c.certId, /^\d{3,5}$/, `${key} cert id`);
      assert.ok(c.level >= 1 && c.level <= 4, key);
      if (c.sunsetDate) assert.match(c.sunsetDate, /^\d{4}-\d{2}-\d{2}$/, key);
      if (c.status === 'active') assert.ok(c.sunsetDate, `${key}: an active certificate has a sunset date`);
      assert.ok(e.source, `${key}: a certificate claim needs its provider source`);
    }
  }
});

// ---- CBOM and console ------------------------------------------------------

test('CBOM carries the module axis for a connector asset', () => {
  const c = cbomComponent({ id: 'k', name: 'alias/payments', algorithm: 'AES-256-GCM', keySize: 256, isVulnerable: false, assetKind: 'symmetric_key', cryptoModule: 'aws-kms-hsm', cryptoModuleEvidence: 'AWS KMS Origin=AWS_KMS, region us-east-1' });
  assert.equal(prop(c, 'quarkshield:cmvpStatus'), 'active');
  assert.equal(prop(c, 'quarkshield:cmvpCertId'), '4884');
  assert.equal(prop(c, 'quarkshield:cmvpModule'), 'AWS KMS HSM');
  assert.equal(prop(c, 'quarkshield:cmvpFipsLevel'), 'FIPS 140-3 Level 3');
  assert.equal(prop(c, 'quarkshield:cmvpSunsetDate'), '2029-11-17');
  assert.equal(prop(c, 'quarkshield:cmvpBasis'), 'provider-reported');
  assert.equal(prop(c, 'quarkshield:cmvpEvidence'), 'AWS KMS Origin=AWS_KMS, region us-east-1');
  assert.equal(prop(c, 'quarkshield:cmvpMapVersion'), CMVP_MAP_VERSION);
  assert.match(prop(c, 'quarkshield:cmvpCertUrl')!, /csrc\.nist\.gov.*\/certificate\/4884$/);
});

test('CBOM: unverified module names the module but no certificate or level', () => {
  const c = cbomComponent({ id: 'g', name: 'ring/key', algorithm: 'RSA-4096', keySize: 4096, isVulnerable: true, assetKind: 'asymmetric_key', cryptoModule: 'gcp-kms-hsm' });
  assert.equal(prop(c, 'quarkshield:cmvpStatus'), 'unverified');
  assert.equal(prop(c, 'quarkshield:cmvpModule'), 'Google Cloud HSM key');
  for (const n of ['cmvpCertId', 'cmvpCertUrl', 'cmvpFipsLevel', 'cmvpSunsetDate']) assert.equal(prop(c, `quarkshield:${n}`), undefined, n);
});

test('CBOM: an asset with no recorded module is unchanged from Stage 2', () => {
  const c = cbomComponent({ id: 'h', name: 'CN=web', algorithm: 'RSA', keySize: 2048, isVulnerable: true, assetKind: 'certificate' });
  assert.equal(prop(c, 'quarkshield:cmvpStatus'), 'not-assessed');
  assert.equal(c.properties.some((p: any) => /^quarkshield:cmvp(?!Status)/.test(p.name)), false);
});

test('the module axis never states a compliance verdict, and never the word validated/compliant as a status', () => {
  for (const key of Object.keys(CMVP_MODULES)) {
    const c = cbomComponent({ id: 'v', name: 'v', algorithm: 'AES-256', assetKind: 'symmetric_key', cryptoModule: key });
    assert.equal(c.properties.some((p: any) => /complianceVerdict/i.test(p.name)), false);
    assert.equal(/^(validated|compliant)$/i.test(String(prop(c, 'quarkshield:cmvpStatus'))), false);
  }
});

test('console shape', () => {
  const a = cmvpForConsole('azure-managed-hsm', 'Azure Managed HSM host, key type RSA-HSM');
  assert.equal(a.status, 'active');
  assert.deepEqual(a.certIds, ['4700']);
  assert.equal(a.evidence, 'Azure Managed HSM host, key type RSA-HSM');
  assert.equal(cmvpForConsole('gcp-kms-software').certIds.length, 0);
});
