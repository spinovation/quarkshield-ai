// =============================================================================
// GOOGLE CLOUD KMS CONNECTOR — unit tests (no network, no DB)
// Discovery runs against an in-memory fake of the Cloud KMS + OAuth endpoints.
// =============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import {
  mapGcpAlgorithm, parseServiceAccount, buildJwtAssertion, discoverGcpKeys, pingGcp,
  GOOGLE_TOKEN_URL, GCP_KMS_BASE,
} from '../src/lib/gcpKms';
import { sealConnectorSecrets, parseGcpConfig, publicConnector } from '../src/controllers/pkiConnectorConfig';
import { isSealed } from '../src/utils/secretbox';
import { fipsAlgorithmStatus } from '../src/lib/fipsAlgorithmStatus';
import { classifyPurpose } from '../src/lib/threatGraph/cryptoPurpose';

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const SA = {
  type: 'service_account', project_id: 'acme-prod-123', client_email: 'qs-reader@acme-prod-123.iam.gserviceaccount.com',
  private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), token_uri: GOOGLE_TOKEN_URL,
};
const SA_JSON = JSON.stringify(SA);

// ---- algorithm mapping (and agreement with the FIPS resolver) ---------------

test('GCP algorithms map to labels the FIPS resolver classifies correctly', () => {
  const cases: Array<[string, string, string]> = [
    ['GOOGLE_SYMMETRIC_ENCRYPTION', 'AES-256-GCM', 'approved'],
    ['AES_128_CBC', 'AES-128-CBC', 'approved'],
    ['HMAC_SHA256', 'HMAC-SHA256', 'approved'],
    ['RSA_SIGN_PSS_2048_SHA256', 'RSA-2048', 'acceptable'],
    ['RSA_DECRYPT_OAEP_4096_SHA256', 'RSA-4096', 'acceptable'],
    ['EC_SIGN_P256_SHA256', 'ECDSA-P256', 'acceptable'],
    ['EC_SIGN_SECP256K1_SHA256', 'ECDSA-secp256k1', 'non_fips'],
    ['EC_SIGN_ED25519', 'Ed25519', 'acceptable'],
    ['PQ_SIGN_ML_DSA_65', 'ML-DSA-65', 'pq_approved'],
    ['PQ_SIGN_SLH_DSA_SHA2_128S', 'SLH-DSA-SHA2-128s', 'pq_approved'],
    ['ML_KEM_768', 'ML-KEM-768', 'pq_approved'],
    ['KEM_XWING', 'X-Wing (ML-KEM-768 + X25519 hybrid)', 'pq_approved'],
  ];
  for (const [alg, label, fips] of cases) {
    const m = mapGcpAlgorithm(alg);
    assert.equal(m.algo, label, alg);
    assert.equal(fipsAlgorithmStatus({ algorithm: m.algo, key_size: m.size || null, type: m.type }).status, fips, `${alg} FIPS status`);
  }
  assert.equal(mapGcpAlgorithm('RSA_SIGN_PKCS1_2048_SHA256').risk, 'critical');
  assert.equal(mapGcpAlgorithm('RSA_SIGN_PKCS1_3072_SHA256').risk, 'high');
});

test('unknown algorithms fail safe (vulnerable, reviewed) — never "secure"', () => {
  const m = mapGcpAlgorithm('SOME_FUTURE_ALG');
  assert.equal(m.vuln, true);
  assert.notEqual(m.risk, 'secure');
  assert.match(m.threat, /review/);
});

test('threat text lets classifyPurpose separate RSA key transport from signing', () => {
  const dec = mapGcpAlgorithm('RSA_DECRYPT_OAEP_2048_SHA256');
  const sig = mapGcpAlgorithm('RSA_SIGN_PSS_2048_SHA256');
  assert.equal(classifyPurpose({ type: dec.type, name: 'k', algorithm: dec.algo, key_size: dec.size, description: dec.threat }), 'rsa_key_transport');
  assert.equal(classifyPurpose({ type: sig.type, name: 'k', algorithm: sig.algo, key_size: sig.size, description: sig.threat }), 'code_or_data_signing');
});

test('HSM protection level is recorded without claiming a CMVP certificate', () => {
  const m = mapGcpAlgorithm('EC_SIGN_P384_SHA384', 'HSM');
  assert.match(m.threat, /Protection level: HSM/);
  assert.doesNotMatch(m.threat, /CMVP|cert(ificate)? #|validated/i);
});

// ---- service-account parsing + SSRF guard + JWT ------------------------------

test('service-account key: token_uri must be Google, required fields enforced', () => {
  assert.equal(parseServiceAccount(SA_JSON).client_email, SA.client_email);
  assert.throws(() => parseServiceAccount(JSON.stringify({ ...SA, token_uri: 'http://169.254.169.254/token' })), /token_uri/);
  assert.throws(() => parseServiceAccount(JSON.stringify({ ...SA, private_key: undefined })), /private_key/);
  assert.throws(() => parseServiceAccount(JSON.stringify({ ...SA, type: 'authorized_user' })), /service_account/);
  assert.throws(() => parseServiceAccount('not json'), /valid JSON/);
  assert.throws(() => parseServiceAccount(''), /required/);
});

test('JWT assertion is RS256-signed by the service account key with read-only scope', () => {
  const jwt = buildJwtAssertion(parseServiceAccount(SA_JSON), Date.UTC(2026, 10, 14));
  const [h, c, sig] = jwt.split('.');
  const v = crypto.createVerify('RSA-SHA256'); v.update(`${h}.${c}`);
  assert.equal(v.verify(publicKey, Buffer.from(sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64')), true);
  const claims = JSON.parse(Buffer.from(c, 'base64').toString());
  assert.equal(claims.aud, GOOGLE_TOKEN_URL);
  assert.equal(claims.iss, SA.client_email);
  assert.match(claims.scope, /read-only/);
  assert.equal(claims.exp - claims.iat, 3600);
});

// ---- discovery against an in-memory fake of Google's APIs --------------------

const fakeGoogle = () => {
  const calls: string[] = [];
  const P = 'projects/acme-prod-123';
  const responses: Record<string, any> = {
    [`${GCP_KMS_BASE}/${P}/locations`]: { locations: [{ locationId: 'us-east1' }, { locationId: 'global' }] },
    [`${GCP_KMS_BASE}/${P}/locations/us-east1/keyRings`]: { keyRings: [{ name: `${P}/locations/us-east1/keyRings/payments` }, { name: 'projects/OTHER/locations/us-east1/keyRings/evil' }] },
    [`${GCP_KMS_BASE}/${P}/locations/global/keyRings`]: { keyRings: [] },
  };
  const ring = `${GCP_KMS_BASE}/${P}/locations/us-east1/keyRings/payments/cryptoKeys`;
  const fetch = async (url: string, init: any = {}) => {
    calls.push(url);
    const host = new URL(url).host;
    assert.ok(['oauth2.googleapis.com', 'cloudkms.googleapis.com'].includes(host), `unexpected host ${host}`);
    if (url === GOOGLE_TOKEN_URL) {
      assert.match(String(init.body), /grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer/);
      return { ok: true, status: 200, json: async () => ({ access_token: 'ya29.test' }), text: async () => '' };
    }
    assert.equal(init.headers?.Authorization, 'Bearer ya29.test');
    const base = url.split('?')[0];
    let body: any = responses[base];
    if (base === ring) {
      body = /pageToken=p2/.test(url)
        ? { cryptoKeys: [{ name: `${ring}/legacy-signer`, versionTemplate: { algorithm: 'EC_SIGN_SECP256K1_SHA256', protectionLevel: 'HSM' } }] }
        : { nextPageToken: 'p2', cryptoKeys: [
            { name: `${ring}/envelope`, primary: { algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION', state: 'ENABLED', protectionLevel: 'SOFTWARE' }, rotationPeriod: '7776000s' },
            { name: `${ring}/old-key`, primary: { algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION', state: 'DISABLED' } },
            { name: `${ring}/jwt-signer`, versionTemplate: { algorithm: 'RSA_SIGN_PKCS1_2048_SHA256' } },
          ] };
    }
    if (!body) return { ok: false, status: 404, json: async () => ({ error: { message: 'not found' } }), text: async () => '' };
    return { ok: true, status: 200, json: async () => body, text: async () => '' };
  };
  return { fetch, calls };
};

test('discovery walks locations → key rings → keys (with pagination), metadata only', async () => {
  const g = fakeGoogle();
  const assets = await discoverGcpKeys({ serviceAccountJson: SA_JSON }, { fetch: g.fetch });
  const byName = Object.fromEntries(assets.map(a => [a.name, a]));
  assert.deepEqual(Object.keys(byName).sort(), ['us-east1/payments/envelope', 'us-east1/payments/jwt-signer', 'us-east1/payments/legacy-signer', 'us-east1/payments/old-key']);
  assert.equal(byName['us-east1/payments/envelope'].algo, 'AES-256-GCM');
  assert.equal(byName['us-east1/payments/envelope'].rot, true);
  assert.equal(byName['us-east1/payments/old-key'].risk, 'low', 'disabled primary version is not in active use');
  assert.equal(byName['us-east1/payments/jwt-signer'].algo, 'RSA-2048');
  assert.equal(byName['us-east1/payments/legacy-signer'].algo, 'ECDSA-secp256k1', 'second page was fetched');
  assert.ok(!assets.some(a => a.name.includes('evil')), 'key rings outside the configured project are ignored');
  assert.ok(g.calls.every(u => !/:(get|asymmetricSign|decrypt|encrypt)/i.test(u)), 'never a crypto operation');
});

test('an explicit location allow-list skips location discovery', async () => {
  const g = fakeGoogle();
  await discoverGcpKeys({ serviceAccountJson: SA_JSON, locations: ['global'] }, { fetch: g.fetch });
  assert.ok(!g.calls.some(u => u.split('?')[0].endsWith('/locations')), 'did not list all locations');
  assert.ok(g.calls.some(u => u.includes('/locations/global/keyRings')));
});

test('unsafe project / location values are rejected before any request', async () => {
  const g = fakeGoogle();
  await assert.rejects(discoverGcpKeys({ serviceAccountJson: SA_JSON, projectId: '../../evil' }, { fetch: g.fetch }), /project ID/);
  await assert.rejects(discoverGcpKeys({ serviceAccountJson: SA_JSON, locations: ['us-east1/../../x'] }, { fetch: g.fetch }), /Invalid Cloud KMS location/);
});

test('ping authenticates and reports the project and identity', async () => {
  const g = fakeGoogle();
  const r = await pingGcp({ serviceAccountJson: SA_JSON }, { fetch: g.fetch });
  assert.equal(r.ok, true);
  assert.match(r.message, /acme-prod-123/);
});

test('a failed token exchange surfaces Google\'s reason, not the assertion', async () => {
  const fetch = async () => ({ ok: false, status: 400, json: async () => ({ error: 'invalid_grant', error_description: 'Invalid JWT Signature.' }), text: async () => '' });
  await assert.rejects(pingGcp({ serviceAccountJson: SA_JSON }, { fetch }), (e: any) => /\(HTTP 400\): Invalid JWT Signature/.test(e.message) && !/eyJ/.test(e.message));
});

// ---- credential plumbing (seal at rest, never returned) ----------------------

test('service-account key is sealed at rest, unsealed for discovery, never exposed', () => {
  const sealed = sealConnectorSecrets({ projectId: 'acme-prod-123', locations: ['us-east1'], serviceAccountJson: SA_JSON });
  assert.ok(isSealed(sealed.serviceAccountJson));
  const row = { provider: 'gcp_kms', endpoint_url: 'https://cloudkms.googleapis.com', config_summary: JSON.stringify(sealed) };
  const parsed = parseGcpConfig(row);
  assert.equal(parsed.serviceAccountJson, SA_JSON);
  assert.deepEqual(parsed.locations, ['us-east1']);
  const pub = publicConnector(row);
  assert.deepEqual(pub.config, { projectId: 'acme-prod-123', locations: ['us-east1'] });
  assert.ok(!JSON.stringify(pub).includes('PRIVATE KEY'));
});

test('locations may also be stored as a comma-separated string', () => {
  const row = { config_summary: JSON.stringify({ projectId: 'acme-prod-123', locations: 'us-east1, europe-west1' }) };
  assert.deepEqual(parseGcpConfig(row).locations, ['us-east1', 'europe-west1']);
});
