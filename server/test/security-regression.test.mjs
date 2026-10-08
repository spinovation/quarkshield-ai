// =============================================================================
// SECURITY REGRESSION CANARIES
// -----------------------------------------------------------------------------
// These tests lock in the 2026-10-07 critical/high security hotfix so a future
// "enhancement" cannot silently REOPEN one of the closed holes. Each test asserts
// either that a guard is still PRESENT, or that a dangerous pattern is still ABSENT.
//
// If a test here fails, DO NOT just edit the test to make it pass — you are almost
// certainly reintroducing a vulnerability. Re-read the referenced finding first.
//
// Run:  cd server && npm run test:security       (zero dependencies; Node >= 18)
// =============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (rel) => readFileSync(resolve(ROOT, rel), 'utf8');
const has = (s, needle) => s.includes(needle);

// ---- #1 Privilege escalation to platform superadmin --------------------------
test('C1: tenant role is sanitized (no tenant->superadmin escalation)', () => {
  const auth = read('server/src/middleware/auth.ts');
  assert.ok(has(auth, 'export const sanitizeTenantRole'), 'sanitizeTenantRole helper removed');
  assert.ok(has(auth, 'if (isSuperRole(r)) return fallback'), 'sanitizeTenantRole no longer blocks super roles');
  assert.ok(has(auth, 'export const requireTenantAdmin'), 'requireTenantAdmin middleware removed');

  const admin = read('server/src/controllers/adminController.ts');
  assert.ok(has(admin, 'sanitizeTenantRole(req.body.role)'), 'createTenantUser no longer sanitizes role');
  assert.ok(!has(admin, "role = 'secops' } = req.body"), 'raw role destructure from body reintroduced');

  const routes = read('server/src/routes/routes.ts');
  const guarded = (routes.match(/requireTenantAdmin/g) || []).length;
  assert.ok(guarded >= 5, `tenant user-mgmt routes lost requireTenantAdmin (found ${guarded}, expect >=5)`);
});

// ---- #2 Tenant password reset must not touch platform admins -----------------
test('C2: resetTenantUserPassword does not cross-write admin_users', () => {
  const admin = read('server/src/controllers/adminController.ts');
  assert.ok(has(admin, 'do NOT mirror this reset into admin_users'), 'security note removed from resetTenantUserPassword');
  // The super-only resetUserPassword legitimately writes admin_users; there must be
  // exactly those legit occurrences and none inside the tenant reset path. We assert the
  // tenant handler body (between its signature and the next export) has no admin_users write.
  const start = admin.indexOf('export const resetTenantUserPassword');
  const end = admin.indexOf('export const', start + 10);
  const body = admin.slice(start, end === -1 ? undefined : end);
  assert.ok(!/UPDATE admin_users/.test(body), 'resetTenantUserPassword cross-writes admin_users again');
});

// ---- #3 Report scope pinned for non-super ------------------------------------
test('C3: report resolveScope pins non-super sessions to own tenant', () => {
  const rep = read('server/src/controllers/reportController.ts');
  const start = rep.indexOf('const resolveScope');
  const body = rep.slice(start, start + 600);
  assert.ok(has(body, 'if (!isSuperRole(req.user?.role))'), 'resolveScope no longer pins non-super to own tenant');
});

// ---- #4 AI Copilot tenant-scoped assets + API keys ---------------------------
test('C4: AI copilot scopes assets and API keys to the caller tenant', () => {
  const ai = read('server/src/controllers/aiController.ts');
  assert.ok(has(ai, 'FROM assets WHERE LOWER(tenant_name) = LOWER($1)'), 'copilot asset query no longer tenant-scoped');
  assert.ok(has(ai, "LOWER(tenant_name) = LOWER($1) AND key IN ('gemini_api_key'"), 'copilot API-key query no longer tenant-scoped');
  assert.ok(!has(ai, "FROM tenant_settings WHERE key IN ('gemini_api_key', 'anthropic_api_key')"), 'unscoped tenant_settings key query reintroduced');
});

// ---- #5 Install-script token sanitized (no curl|sudo bash RCE) ---------------
test('C5: install script token is stripped to a safe charset', () => {
  const fleet = read('server/src/controllers/fleetController.ts');
  const n = (fleet.match(/replace\(\/\[\^A-Za-z0-9_-\]\/g, ''\)/g) || []).length;
  assert.ok(n >= 2, `install/powershell token sanitizer missing (found ${n}, expect >=2 for sh + ps1)`);
});

// ---- #6 No weak/placeholder secrets can boot prod ----------------------------
test('C6: weak/placeholder secrets are rejected', () => {
  const auth = read('server/src/middleware/auth.ts');
  assert.ok(has(auth, 'PLACEHOLDER_SECRET_RE'), 'placeholder-secret check removed from getSecret');
  assert.ok(has(auth, "throw new Error('JWT_SECRET is missing"), 'getSecret no longer fails closed on weak secret');
  const boot = read('server/src/config/bootstrap.ts');
  assert.ok(has(boot, 'PLACEHOLDER_PW_RE'), 'placeholder-password check removed from bootstrap');
  const dep = read('deploy.sh');
  assert.ok(has(dep, 'Refusing to deploy') && has(dep, 'openssl rand -hex 32'), 'deploy.sh no longer generates/validates secrets');
});

// ---- H1/H4/H5/H6 Cross-tenant substring leaks (exact match only) -------------
test('H1/H4/H5/H6: fleet queries use EXACT tenant match, not %substring%', () => {
  const fleet = read('server/src/controllers/fleetController.ts');
  assert.ok(!has(fleet, '`%${tenant}%`'), 'cross-tenant %tenant% substring match reintroduced');
  assert.ok(!has(fleet, '`%${effectiveTenant}%`'), 'cross-tenant %effectiveTenant% substring match reintroduced');
  assert.ok(has(fleet, "LOWER(COALESCE(t.tenant_name, '')) = LOWER($1)"), 'getFleetTokens exact-match guard removed');
});

// ---- H2 Fleet token tenant pinned --------------------------------------------
test('H2: createFleetToken pins tenant via resolveWriteTenant', () => {
  const fleet = read('server/src/controllers/fleetController.ts');
  assert.ok(has(fleet, 'resolveWriteTenant(req, tenantName)'), 'createFleetToken trusts body tenantName again');
});

// ---- H3 Checkout cannot hijack an existing tenant ----------------------------
test('H3: Stripe fulfillment aborts on cross-customer tenant conflict', () => {
  const bill = read('server/src/controllers/billingController.ts');
  assert.ok(has(bill, 'blocked checkout-hijack'), 'checkout-hijack guard removed from fulfillPaidRegistration');
});

// ---- H8 License key not exposed by public endpoint ---------------------------
test('H8: public registration-status does not return the license key', () => {
  const bill = read('server/src/controllers/billingController.ts');
  assert.ok(!has(bill, 'licenseKey: reg.result_license_key'), 'registration-status leaks the license key again');
  assert.ok(has(bill, 'licenseIssued: !!reg.result_license_key'), 'licenseIssued flag removed');
});

// ---- M1/M2 Webhook hardening -------------------------------------------------
test('M1/M2: webhook fails closed by default and is idempotent', () => {
  const bill = read('server/src/controllers/billingController.ts');
  assert.ok(has(bill, 'const isDevLike ='), 'webhook no longer fails closed by default (isDevLike guard removed)');
  assert.ok(has(bill, 'already completed (idempotency)'), 'webhook idempotency guard removed');
});

// ---- M3 Entitlement fails closed ---------------------------------------------
test('M3: entitlement check fails CLOSED on DB error', () => {
  const auth = read('server/src/middleware/auth.ts');
  assert.ok(!has(auth, "return { integrations: true, tier: 'unknown', seats: 0 };"), 'entitlement fail-OPEN reintroduced');
  assert.ok(has(auth, "return { integrations: false, tier: 'unknown', seats: 0 };"), 'entitlement fail-closed return removed');
});

// ---- M4 No silent default tenant on writes -----------------------------------
test('M4: connector/proxy/git writes reject an empty tenant', () => {
  for (const f of ['pqcProxyController.ts', 'pkiConnectorController.ts', 'gitScanController.ts']) {
    const src = read(`server/src/controllers/${f}`);
    assert.ok(!has(src, "|| 'SPINOVATIONCORP')"), `${f} silently defaults the write tenant to SPINOVATIONCORP again`);
  }
});
