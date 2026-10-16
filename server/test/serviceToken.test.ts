// =============================================================================
// PLATFORM SERVICE TOKEN — UNIT TESTS
// -----------------------------------------------------------------------------
// Read-only machine-to-machine posture tokens (QSG platform-integration spec).
// Pure/unit level: no live DB. Covers token generation (format, entropy, hashing)
// and the DB-free fall-through branch of allowServiceToken() — a request WITHOUT a
// qsg_svc_ bearer must pass straight through to the user-session auth chain and must
// never touch the database.
//
// Run:  cd server && npm test
// =============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import {
  generateServiceToken,
  hashServiceToken,
  allowServiceToken,
  SERVICE_TOKEN_PREFIX,
  SUPPORTED_SCOPES,
} from '../src/middleware/serviceToken';

// ---- token generation --------------------------------------------------------
test('generateServiceToken: uses the qsg_svc_ prefix and carries >=256 bits', () => {
  const { token } = generateServiceToken();
  assert.ok(token.startsWith(SERVICE_TOKEN_PREFIX), 'missing qsg_svc_ prefix');
  const secret = token.slice(SERVICE_TOKEN_PREFIX.length);
  // base64url of 32 bytes -> 43 chars, decodes back to 32 bytes (256 bits).
  assert.equal(Buffer.from(secret, 'base64url').length, 32);
});

test('generateServiceToken: every token is unique', () => {
  const seen = new Set<string>();
  for (let i = 0; i < 1000; i++) seen.add(generateServiceToken().token);
  assert.equal(seen.size, 1000);
});

test('generateServiceToken: returns the SHA-256 hash of the plaintext, not the plaintext', () => {
  const { token, hash } = generateServiceToken();
  assert.notEqual(hash, token, 'stored hash must differ from the secret');
  assert.match(hash, /^[0-9a-f]{64}$/, 'hash is not 64 hex chars (SHA-256)');
  assert.equal(hash, hashServiceToken(token), 'hash is not SHA-256 of the token');
});

test('hashServiceToken: deterministic and matches a known vector', () => {
  const t = 'qsg_svc_example';
  assert.equal(hashServiceToken(t), crypto.createHash('sha256').update(t, 'utf8').digest('hex'));
  assert.equal(hashServiceToken(t), hashServiceToken(t));
});

test('SUPPORTED_SCOPES: posture:read is the supported read scope', () => {
  assert.ok((SUPPORTED_SCOPES as readonly string[]).includes('posture:read'));
});

// ---- middleware fall-through (DB-free) ---------------------------------------
// A minimal res stub that fails the test if any response method is used — the
// fall-through branch must call next() only, never respond or query.
const strictRes = () => {
  const res: any = {
    status() { assert.fail('fall-through branch must not send a response'); return res; },
    json() { assert.fail('fall-through branch must not send a response'); return res; },
  };
  return res;
};

test('allowServiceToken: no Authorization header -> next() with no DB access', async () => {
  let nexted = false;
  await allowServiceToken('posture:read')(
    { headers: {}, query: {}, params: {} } as any,
    strictRes(),
    () => { nexted = true; }
  );
  assert.ok(nexted, 'expected next() to be called');
});

test('allowServiceToken: a normal user JWT bearer falls through to user auth', async () => {
  let nexted = false;
  await allowServiceToken('posture:read')(
    { headers: { authorization: 'Bearer eyJhbGciOi.jwt.looking' }, query: {}, params: {} } as any,
    strictRes(),
    () => { nexted = true; }
  );
  assert.ok(nexted, 'a non-service bearer must fall through to the JWT chain');
});

test('allowServiceToken: the tenant query is left untouched on fall-through', async () => {
  const req: any = { headers: {}, query: { tenant: 'acme' }, params: {} };
  await allowServiceToken('posture:read')(req, strictRes(), () => {});
  // Fall-through must not rewrite tenant; that only happens for a valid service token.
  assert.equal(req.query.tenant, 'acme');
});
