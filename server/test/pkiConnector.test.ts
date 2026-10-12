// =============================================================================
// ENTERPRISE PKI/KMS CONNECTOR — CREDENTIAL PLUMBING UNIT TESTS
// -----------------------------------------------------------------------------
// Locks in the 2026-10-09 connector fix: the UI now collects real credentials
// (AWS access key/secret, Azure client secret, Vault token / AppRole) and the
// server seals them at rest and unseals them for discovery, without ever
// returning or logging plaintext.
//
// Pure/unit level: no live DB and no cloud calls. These exercise the exact
// seal -> store -> parse round-trip the controller performs, plus the quantum
// classification the peer validated live against a dev Vault.
//
// Run:  cd server && npm test
// =============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { seal, open as unseal, isSealed } from '../src/utils/secretbox';
import {
  sealConnectorSecrets,
  parseKmsConfig,
  parseAzureConfig,
  parseVaultConfig,
  publicConnector,
} from '../src/controllers/pkiConnectorConfig';
import { mapTransitType } from '../src/lib/hashiVault';

// A connector row as createPkiConnector would have written it: secrets sealed in
// config_summary (a JSON string), non-secret hints in the clear.
const sealedRow = (provider: string, config: Record<string, any>, endpoint_url = '') => ({
  provider,
  endpoint_url,
  config_summary: JSON.stringify(sealConnectorSecrets(config)),
});

// ---- secretbox round-trip ----------------------------------------------------
test('secretbox: seal/unseal round-trips and never embeds the plaintext', () => {
  const plain = 'AKIA_super_secret_value_/+xyz';
  const sealed = seal(plain);
  assert.ok(isSealed(sealed), 'sealed value lacks the v1: envelope');
  assert.ok(!sealed.includes(plain), 'ciphertext leaks the plaintext');
  assert.equal(unseal(sealed), plain, 'round-trip did not recover the plaintext');
  // Tamper-evident + tolerant of junk.
  assert.equal(unseal('v1:bad:bad:bad'), null, 'tampered ciphertext should not decrypt');
  assert.equal(unseal(null), null);
  assert.equal(unseal('not-sealed'), null);
});

// ---- AWS static keys: config -> awsKms --------------------------------------
test('AWS: static access keys seal at rest and unseal into KmsConfig (no fake role)', () => {
  const row = sealedRow('aws_kms', {
    region: 'ap-south-1',
    accessKeyId: 'AKIAEXAMPLE1234567',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  }, 'https://kms.ap-south-1.amazonaws.com');

  // Secrets are sealed in the stored blob, not plaintext.
  assert.ok(!row.config_summary.includes('AKIAEXAMPLE1234567'), 'accessKeyId stored in plaintext');
  assert.ok(!row.config_summary.includes('wJalrXUtnFEMI'), 'secretAccessKey stored in plaintext');

  const cfg = parseKmsConfig(row);
  assert.equal(cfg.accessKeyId, 'AKIAEXAMPLE1234567', 'accessKeyId did not round-trip to the KMS client');
  assert.equal(cfg.secretAccessKey, 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'secretAccessKey did not round-trip');
  assert.equal(cfg.region, 'ap-south-1', 'region not threaded to KmsConfig');
  // No ARN supplied -> genuinely optional, no placeholder role.
  assert.equal(cfg.roleArn, undefined, 'a role ARN was injected when none was provided');
  // The displayed/stored endpoint reflects the chosen region, not us-east-1.
  assert.equal(cfg.endpointUrl, 'https://kms.ap-south-1.amazonaws.com');
  assert.ok(!cfg.endpointUrl!.includes('us-east-1'), 'endpoint still hardcoded to us-east-1');
});

test('AWS: optional role ARN is honored for AssumeRole when provided', () => {
  const row = sealedRow('aws_kms', {
    region: 'us-east-1',
    roleArn: 'arn:aws:iam::210987654321:role/RealDiscoveryRole',
    externalId: 'qs-ext-1',
    accessKeyId: 'AKIABASECREDS000000',
    secretAccessKey: 'baseSecret/value',
  });
  const cfg = parseKmsConfig(row);
  assert.equal(cfg.roleArn, 'arn:aws:iam::210987654321:role/RealDiscoveryRole');
  assert.equal(cfg.externalId, 'qs-ext-1');
  assert.equal(cfg.accessKeyId, 'AKIABASECREDS000000', 'base creds for AssumeRole did not round-trip');
});

// ---- Azure service principal: config -> azureKeyVault -----------------------
test('Azure: SP client secret seals at rest and unseals into AzureConfig', () => {
  const row = sealedRow('azure_keyvault', {
    tenantId: '11111111-2222-3333-4444-555555555555',
    clientId: '66666666-7777-8888-9999-000000000000',
    clientSecret: 'aZ~client.secret.VALUE-9000',
  }, 'https://prod.vault.azure.net');

  assert.ok(!row.config_summary.includes('aZ~client.secret.VALUE-9000'), 'clientSecret stored in plaintext');

  const cfg = parseAzureConfig(row);
  assert.equal(cfg.tenantId, '11111111-2222-3333-4444-555555555555');
  assert.equal(cfg.clientId, '66666666-7777-8888-9999-000000000000');
  assert.equal(cfg.clientSecret, 'aZ~client.secret.VALUE-9000', 'clientSecret did not round-trip to the Azure client');
  assert.equal(cfg.vaultUrl, 'https://prod.vault.azure.net');
  // credentialFor() picks the ClientSecretCredential (service-principal) path only
  // when all three are present — which is exactly what parse produced here.
  assert.ok(cfg.tenantId && cfg.clientId && cfg.clientSecret, 'SP client-credentials flow not fully wired');
});

// ---- HashiCorp Vault: token + AppRole + PKI mount ---------------------------
test('Vault: token and AppRole secret_id seal at rest and unseal into VaultConfig', () => {
  const row = sealedRow('hashicorp_vault', {
    token: 'hvs.CLEARTEXTtokenVALUE',
    roleId: 'role-abc',
    secretId: 'secret-xyz-id',
    pkiMount: 'pki_int',
  }, 'https://vault.example.com:8200');

  assert.ok(!row.config_summary.includes('hvs.CLEARTEXTtokenVALUE'), 'vault token stored in plaintext');
  assert.ok(!row.config_summary.includes('secret-xyz-id'), 'AppRole secret_id stored in plaintext');

  const cfg = parseVaultConfig(row);
  assert.equal(cfg.token, 'hvs.CLEARTEXTtokenVALUE', 'vault token did not round-trip');
  assert.equal(cfg.secretId, 'secret-xyz-id', 'AppRole secret_id did not round-trip');
  assert.equal(cfg.roleId, 'role-abc');
  assert.equal(cfg.pkiMount, 'pki_int', 'PKI mount (drives trust edges) not threaded through');
  assert.equal(cfg.address, 'https://vault.example.com:8200');
});

// ---- Secrets never leave the server -----------------------------------------
test('publicConnector strips every secret but keeps non-secret hints', () => {
  const stored = {
    id: 'conn-1', name: 'Prod KMS', provider: 'aws_kms', tenant_name: 'ACME', endpoint_url: 'https://kms.ap-south-1.amazonaws.com',
    config_summary: JSON.stringify(sealConnectorSecrets({
      region: 'ap-south-1', roleArn: 'arn:aws:iam::1:role/r',
      accessKeyId: 'AKIAPUBLICLEAK0000', secretAccessKey: 'leak-me-secret', clientSecret: 'leak-azure', token: 'leak-token', secretId: 'leak-sid',
    })),
  };
  const pub = publicConnector(stored);
  const asText = JSON.stringify(pub);
  for (const secret of ['AKIAPUBLICLEAK0000', 'leak-me-secret', 'leak-azure', 'leak-token', 'leak-sid']) {
    assert.ok(!asText.includes(secret), `secret '${secret}' leaked through the public connector response`);
  }
  // config_summary itself must be gone; non-secret hints survive.
  assert.equal((pub as any).config_summary, undefined, 'raw config_summary (holds sealed secrets) returned to client');
  assert.equal(pub.config.region, 'ap-south-1', 'non-secret region hint was dropped');
  assert.equal(pub.config.roleArn, 'arn:aws:iam::1:role/r', 'non-secret roleArn hint was dropped');
  assert.equal(pub.config.accessKeyId, undefined, 'accessKeyId exposed as a public hint');
});

// ---- Quantum classification (peer-validated dev-Vault scenario) -------------
test('Vault transit classification matches the validated 3-key scenario', () => {
  // rsa-2048 + ed25519 -> quantum-vulnerable; aes256-gcm96 -> PQC-ready.
  const rsa = mapTransitType('rsa-2048');
  assert.equal(rsa.vuln, true, 'RSA-2048 must be flagged Shor-vulnerable');
  assert.equal(rsa.algo, 'RSA-2048');

  const ed = mapTransitType('ed25519');
  assert.equal(ed.vuln, true, 'Ed25519 must be flagged quantum-vulnerable');

  const aes = mapTransitType('aes256-gcm96');
  assert.equal(aes.vuln, false, 'AES-256 must be PQC-ready (Grover only)');
  assert.equal(aes.type, 'symmetric_key');

  // A connector syncing exactly these three keys => total 3, 2 vulnerable, 1 ready.
  const scenario = ['rsa-2048', 'ed25519', 'aes256-gcm96'].map(mapTransitType);
  assert.equal(scenario.length, 3);
  assert.equal(scenario.filter(k => k.vuln).length, 2, 'expected 2 vulnerable keys');
  assert.equal(scenario.filter(k => !k.vuln).length, 1, 'expected 1 PQC-ready key');
});
