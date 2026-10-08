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

// =============================================================================
// 2026-10-07 hardening pass (second wave)
// =============================================================================
test('W2: change-password requires a session and verifies via verifyPassword/bcrypt', () => {
  const routes = read('server/src/routes/routes.ts');
  assert.ok(has(routes, "router.post('/auth/change-password', requireAuth, changePassword);"), 'change-password lost requireAuth');
  const admin = read('server/src/controllers/adminController.ts');
  const start = admin.indexOf('export const changePassword');
  const body = admin.slice(start, admin.indexOf('export const', start + 10));
  assert.ok(has(body, 'verifyPassword('), 'changePassword no longer uses verifyPassword');
  assert.ok(has(body, 'hashPassword('), 'changePassword no longer writes bcrypt');
  assert.ok(!has(body, "createHash('sha256')"), 'changePassword writes legacy sha256 again');
  assert.ok(!has(body, 'LOWER(email) = LOWER($'), 'changePassword matches by email again (must be by session id)');
});

test('W2: no legacy sha256 password writes remain', () => {
  const admin = read('server/src/controllers/adminController.ts');
  assert.ok(!/createHash\('sha256'\)\.update\(\w+ \+ salt\)/.test(admin), 'a sha256(password+salt) write was reintroduced');
});

test('W2: sessions are revocable server-side', () => {
  const auth = read('server/src/middleware/auth.ts');
  assert.ok(has(auth, 'export const revokeUserSessions'), 'revokeUserSessions removed');
  assert.ok(has(auth, 'sessions_revoked_at'), 'attachUser no longer checks sessions_revoked_at');
  const schema = read('server/src/models/schema.sql');
  assert.ok(has(schema, 'ADD COLUMN IF NOT EXISTS sessions_revoked_at'), 'sessions_revoked_at column removed from schema');
});

test('W2: destructive admin routes require a platform admin, not any operator role', () => {
  const routes = read('server/src/routes/routes.ts');
  for (const r of ["router.delete('/admin/clients/:id'", "router.delete('/admin/users/:id'", "router.post('/admin/users/:id/role'", "router.post('/admin/licenses/generate'", "router.post('/admin/operators/invite'"]) {
    const line = routes.split('\n').find(l => l.startsWith(r));
    assert.ok(line && line.includes('requirePlatformAdmin'), `${r} is not guarded by requirePlatformAdmin`);
  }
  assert.ok(has(routes, "router.put('/tenants/:tenant/2fa-policy', requireAuth, requireTenantAccess, requireTenantAdmin, updateTenant2FAPolicy);"), '2fa-policy write lost requireTenantAdmin');
});

test('W2: tenant user create / operator invite are create-only (no password-resetting upsert)', () => {
  const admin = read('server/src/controllers/adminController.ts');
  assert.ok(!has(admin, 'ON CONFLICT (tenant_name, email) DO UPDATE SET role = $6'), 'createTenantUser upsert reintroduced');
  // The super-admin onboarding upsert must never overwrite an existing password.
  assert.ok(!/ON CONFLICT \(tenant_name, email\) DO UPDATE SET[^;]*password_hash = \$\d/.test(admin.replace(/COALESCE\(tenant_users\.password_hash, \$\d\)/g, '')), 'a tenant_users upsert overwrites password_hash');
  assert.ok(!has(admin, 'ON CONFLICT (email) DO UPDATE SET password_hash'), 'inviteOperator upsert reintroduced');
});

test('W2: no seeded/hardcoded license keys or partner credentials', () => {
  for (const f of ['server/src/controllers/fleetController.ts', 'server/src/controllers/adminController.ts']) {
    const src = read(f);
    assert.ok(!has(src, '6C894B76-DA9EF3D8'), `${f} still references the public SPINOVATIONCORP key`);
    assert.ok(!has(src, 'QS-Amberoon7033'), `${f} still contains a hardcoded customer password`);
    assert.ok(!has(src, 'shirish.netke'), `${f} still contains hardcoded customer PII`);
  }
  const schema = read('server/src/models/schema.sql');
  assert.ok(!/INSERT INTO admin_licenses[\s\S]*6C894B76/.test(schema), 'schema seeds the public license key again');
  assert.ok(!has(schema, "'gate-pr-104', 'SPINOVATIONCORP'"), 'schema seeds fabricated CI gates again');
  assert.ok(!has(schema, "DEFAULT 'SPINOVATIONCORP'"), 'schema defaults tenant_name to a real tenant again');
});

test('W2: remaining substring tenant filters and client-asserted admin are gone', () => {
  const roadmap = read('server/src/lib/roadmapReport.ts');
  assert.ok(!has(roadmap, '`%${scope.tenant}%`'), 'roadmapReport %tenant% substring match reintroduced');
  const sbom = read('server/src/controllers/sbomController.ts');
  assert.ok(!has(sbom, "x-admin-role"), 'sbomController trusts x-admin-role header again');
  assert.ok(!has(sbom, "return 'SPINOVATIONCORP';"), 'sbomController defaults to SPINOVATIONCORP again');
  const ci = read('server/src/controllers/ciGateController.ts');
  assert.ok(!has(ci, "tenant = 'SPINOVATIONCORP'"), 'ciGate policies default to SPINOVATIONCORP again');
  assert.ok(!has(ci, 'OR is_default = TRUE'), 'ciGate policies leak other tenants is_default rows again');
});

test('W2: PKI connector SSRF guard covers config-supplied endpoints; git clone is hardened', () => {
  const pki = read('server/src/controllers/pkiConnectorController.ts');
  assert.ok(has(pki, 'const assertConnectorTargetsPublic'), 'assertConnectorTargetsPublic removed');
  assert.ok((pki.match(/assertConnectorTargetsPublic\(/g) || []).length >= 3, 'not every connector path checks config endpoints');
  const git = read('server/src/controllers/gitScanController.ts');
  assert.ok(has(git, 'http.followRedirects=false'), 'git clone follows redirects again');
  assert.ok(!has(git, '...process.env'), 'git inherits the full server environment again');
  assert.ok(!has(git, 'if (result.rows && result.rows.length > 0) {\n      return res.json(result.rows);'), 'git history falls back to the global cache on empty results again');
});

test('W2: 2FA setup requires a current code when already enabled; handlers are wrapped', () => {
  const tfa = read('server/src/controllers/twoFactorController.ts');
  assert.ok(has(tfa, 'Enter your current code to re-enroll'), '2fa/setup no longer requires a current code when enabled');
  assert.ok(has(tfa, 'export const twoFactorSetupSafe'), '2FA async wrappers removed');
  const idx = read('server/src/index.ts');
  assert.ok(has(idx, "process.on('unhandledRejection'"), 'unhandledRejection handler removed');
});

test('W2: ingest is transactional and bounded; install token + CORS + health are safe', () => {
  const fleet = read('server/src/controllers/fleetController.ts');
  assert.ok(has(fleet, 'MAX_ASSETS_PER_SYNC'), 'ingest asset cap removed');
  assert.ok(has(fleet, "await txn.query('BEGIN')"), 'ingest delete+insert is no longer transactional');
  assert.ok(has(fleet, "WHERE REPLACE(LOWER(COALESCE(fleet_machines.tenant_name, '')), ' ', '') IN ('', REPLACE(LOWER(EXCLUDED.tenant_name), ' ', ''))"), 'machine upsert can re-home a machine across tenants again');
  const idx = read('server/src/index.ts');
  assert.ok(has(idx, 'if (allowedOrigins.length === 0) return cb(null, !isProduction);'), 'CORS reflects any origin in production again');
  assert.ok(has(idx, "await pool.query('SELECT 1')"), '/health no longer checks the database');
  assert.ok(has(idx, "app.use('/api/git/ci-gate/evaluate', perIpLimiter("), 'ci-gate evaluate lost its rate limit');
  assert.ok(has(idx, "app.use('/api/scan/agent/ingest', agentLimiter);"), 'agent ingest lost its (token-keyed) rate limit');
  assert.ok(has(idx, 'keyGenerator: agentKey'), 'agent limiter is no longer keyed by token (NAT fleets would throttle each other)');
  const sbomCtl = read('server/src/controllers/sbomController.ts');
  assert.ok(has(sbomCtl, 'SAFE_CMD_RE.test(cmd)'), 'fix script emits telemetry-supplied commands unchecked again');
  assert.ok(has(sbomCtl, "if (normTenant !== 'quarkshield.ai') return;"), 'fabricated SBOM template is seeded into real tenants again');
  const routes2 = read('server/src/routes/routes.ts');
  assert.ok(has(routes2, "router.get('/fleet/tokens', requireAuth, requireTenantAccess, requireTenantAdmin, getFleetTokens);"), 'fleet tokens readable by any tenant role again');
});

test('W2: UI never infers privilege from an email address and does not persist the JWT', () => {
  const app = read('ui/src/App.tsx');
  assert.ok(!has(app, "sridhargs@gmail.com"), 'App.tsx hardcodes a personal email as superadmin again');
  assert.ok(!has(app, "email.includes('@quarkshield.ai')"), 'App.tsx infers superadmin from the email domain again');
  assert.ok(has(app, "fetch('/api/auth/me'"), 'App.tsx no longer syncs the session from /api/auth/me');
  const landing = read('ui/src/components/LandingPage.tsx');
  assert.ok(!has(landing, "setItem('quarkshield_token'"), 'LandingPage persists the JWT to web storage again');
  const tp = read('ui/src/components/TenantPortal.tsx');
  assert.ok(!has(tp, 'completeTenantLogin();'), 'TenantPortal fallback login (login on 5xx) reintroduced');
  const sbom = read('ui/src/components/SbomInventory.tsx');
  assert.ok(!has(sbom, 'x-admin-role'), 'SbomInventory sends x-admin-role again');
  const signup = read('ui/public/signup-result.html');
  assert.ok(!has(signup, 'detailsEl.innerHTML'), 'signup-result builds innerHTML from server JSON again');
});

test('W2: agent local API gates every method and never returns the gate token', () => {
  const gui = read('agent/gui.go');
  assert.ok(has(gui, 'subtle.ConstantTimeCompare([]byte(c.Value), []byte(apiToken))'), 'agent localGuard no longer checks the token on all methods');
  assert.ok(!/case http\.MethodPost, http\.MethodPut, http\.MethodPatch, http\.MethodDelete:\n\s*if apiToken != ""/.test(gui), 'agent token check is POST-only again');
  assert.ok(has(gui, 'cfg.LocalAPIToken = "" // never expose the API gate token over HTTP'), 'agent /api/enrollment returns localApiToken again');
  const lic = read('agent/license.go');
  assert.ok(has(lic, 'if LicenseSigningSecret == defaultLicenseSigningSecret {'), 'agent offline activation accepts the public default secret again');
  assert.ok(has(lic, 'errors.As(srvErr, &rejected)'), 'agent re-activates a server-rejected license offline again');
  for (const f of ['build_all_and_sign.sh', 'agent/build_and_sign.sh', 'agent/build_macos.sh']) {
    assert.ok(has(read(f), '-X main.LicenseSigningSecret='), `${f} builds without injecting the license secret`);
    assert.ok(!has(read(f), '-pass fedmitigate'), `${f} hardcodes the p12 password again`);
  }
  const main = read('agent/main.go');
  assert.ok(has(main, 'readScanFile(path)'), 'agent scanner reads candidate files without the bounded/stat-checked reader again');
  assert.ok(!has(main, 'contentBytes, err := os.ReadFile(path)'), 'agent scanner uses unbounded os.ReadFile on candidates again');
  const sbom = read('agent/sbom_scanner.go');
  assert.ok(has(sbom, 'readScanFile(filePath)'), 'SBOM manifest parser uses unbounded os.ReadFile again');
  const client = read('agent/client.go');
  assert.ok((client.match(/validateServerURL\(serverURL\)/g) || []).length >= 3, 'not every token-bearing agent request validates the server URL');
});

test('W2: deploy/compose/docker defaults are safe', () => {
  const compose = read('docker-compose.yml');
  assert.ok(has(compose, '${DB_PASSWORD:?'), 'compose falls back to the postgres default password again');
  assert.ok(!has(compose, './.env:/app/.env'), 'compose mounts the whole .env into the container again');
  const docker = read('Dockerfile');
  assert.ok(has(docker, 'USER node'), 'Dockerfile runs as root again');
  assert.ok(!has(docker, 'RUN mkdir -p /app/certs && openssl req'), 'Dockerfile bakes a TLS private key into the image again');
  const db = read('server/src/config/db.ts');
  assert.ok(has(db, "throw new Error('DB_PASSWORD is not set (required in production).')"), 'db.ts connects with a default password in production again');
  const inst = read('agent/install-linux.sh');
  assert.ok(has(inst, 'EnvironmentFile=-/etc/quarkshield/env'), 'install-linux.sh puts the token on the ExecStart line again');
  assert.ok(!has(inst, '--token $QS_TOKEN'), 'install-linux.sh puts the token in the unit file again');
});

// =============================================================================
// 2026-10-08 third wave (residuals from the re-review)
// =============================================================================
test('W3: outbound probes connect to the pre-verified address (no DNS rebinding window)', () => {
  const ssrf = read('server/src/utils/ssrf.ts');
  assert.ok(has(ssrf, 'export const resolvePublicHost'), 'resolvePublicHost removed');
  const admin = read('server/src/controllers/adminController.ts');
  assert.ok(has(admin, 'host: pinnedAddress,'), 'probeEndpoint connects by hostname again (rebinding window reopened)');
  const proxy = read('server/src/controllers/pqcProxyController.ts');
  assert.ok(has(proxy, 'tls.connect({ host: connectTo,'), 'proxy test connects by hostname again');
  assert.ok(!has(admin, "cleanTenant.includes('spinovation') || cleanTenant === 'corp-9812'"), 'synthetic Spinovation client fallback reintroduced');
  assert.ok(!has(admin, "u.email === 'sridhargs@gmail.com'"), 'root status inferred from a personal email again');
  assert.ok(!has(admin, 'This account has no password set'), 'login reveals password-less accounts again (enumeration)');
});

test('W3: report emailing is admin-only; spreadsheet cells are formula-safe; raw proxy headers untrusted', () => {
  const routes = read('server/src/routes/routes.ts');
  assert.ok(has(routes, "router.post('/reports/executive/send', requireAuth, requireTenantAccess, requireTenantAdmin, sendRoadmapReport);"), 'any tenant role can email reports again');
  const poam = read('server/src/lib/poamExcel.ts');
  assert.ok(has(poam, 'const safeCell'), 'POA&M export writes raw formula-capable cells again');
  const dl = read('server/src/lib/downloadTracker.ts');
  assert.ok(!has(dl, "req.headers['cf-connecting-ip']"), 'downloadTracker trusts spoofable client-IP headers again');
  const schema = read('server/src/models/schema.sql');
  assert.ok(has(schema, 'uq_tenant_users_ci'), 'case-insensitive tenant_users uniqueness removed');
  assert.ok(!has(schema, "'snap-spinovation-'"), 'owner-specific boot-time snapshot reintroduced');
});
