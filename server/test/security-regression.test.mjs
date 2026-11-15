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

// ---- Roadmap/report data layer (cross-tenant leaks) --------------------------
test('R1: PQC roadmap uses exact tenant match and scoped narrative keys', () => {
  const rm = read('server/src/lib/roadmapReport.ts');
  assert.ok(!has(rm, '`%${scope.tenant}%`'), 'roadmap buildRoadmapReport reintroduced %tenant% substring leak');
  assert.ok(has(rm, "LOWER(COALESCE(${col}, '')) = LOWER($1)"), 'roadmap exact-match tenant predicate removed');
  // generateNarrative must not read tenant_settings keys without a tenant filter.
  assert.ok(!has(rm, "SELECT key, value FROM tenant_settings WHERE key IN ('gemini_api_key','anthropic_api_key')"), 'roadmap narrative reads API keys across all tenants again');
  assert.ok(has(rm, "LOWER(tenant_name) = LOWER($1) AND key IN ('gemini_api_key'"), 'roadmap narrative API-key query no longer tenant-scoped');
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

test('W3: no fabricated fleet/CBOM/license data is rendered when the API fails', () => {
  const app = read('ui/src/App.tsx');
  assert.ok(!has(app, 'using sample fleet data'), 'App.tsx injects sample machines again');
  assert.ok(!has(app, 'using sample CBOM data'), 'App.tsx injects a sample CBOM again');
  assert.ok(!has(app, "currentCustomerId || 'PART-4421'"), 'App.tsx shows a hardcoded customer id again');
  const ap = read('ui/src/components/AdminPanel.tsx');
  assert.ok(!has(ap, 'loading simulated licenses'), 'AdminPanel injects simulated licenses again');
  assert.ok(!has(ap, 'QS-CORP-SPINOVATIONCORP-6C894B76-DA9EF3D8'), 'AdminPanel ships the revoked public license key again');
  const idx = read('server/src/index.ts');
  assert.ok(has(idx, 'Refusing to start:'), 'server no longer refuses to boot on weak production secrets');
});

// ---- Fleet Probe: admin-only, SSRF-constrained, re-validated, actually uploads ----
// Locks in agent/FLEET-PROBE-PLAN.md §5. The probe drives outbound connections
// across the fleet, so these guards must not silently regress.
test('FP1: probe routes require tenant admin on top of tenant access', () => {
  const routes = read('server/src/routes/routes.ts');
  assert.ok(
    has(routes, "router.post('/fleet/machines/:machineId/probe', requireAuth, requireTenantAccess, requireTenantAdmin, enqueueProbeCommand);"),
    'per-machine probe route lost requireTenantAdmin'
  );
  assert.ok(
    has(routes, "router.post('/fleet/probe-bulk', requireAuth, requireTenantAccess, requireTenantAdmin, enqueueBulkProbeCommand);"),
    'bulk probe route lost requireTenantAdmin'
  );
  assert.ok(
    has(routes, "router.put('/fleet/probe-policy', requireAuth, requireTenantAccess, requireTenantAdmin, setProbePolicy);"),
    'probe kill-switch write lost requireTenantAdmin'
  );
});

test('FP2: probe target validator blocks loopback/link-local/metadata but allows private infra', () => {
  const v = read('server/src/utils/probeTargets.ts');
  // Always-block set must still contain the metadata/loopback/reserved ranges.
  assert.ok(has(v, "'169.254.0.0/16'"), 'link-local + cloud metadata no longer blocked');
  assert.ok(has(v, "'127.0.0.0/8'"), 'loopback no longer blocked');
  assert.ok(has(v, "'224.0.0.0/4'"), 'multicast no longer blocked');
  // Private ranges must NOT be in the always-block set (internal topology is the point).
  assert.ok(!/ALWAYS_BLOCKED_V4[\s\S]*'10\.0\.0\.0\/8'/.test(v), '10/8 wrongly added to always-block (breaks internal probing)');
  assert.ok(!/ALWAYS_BLOCKED_V4[\s\S]*'192\.168\.0\.0\/16'/.test(v), '192.168/16 wrongly added to always-block');
  // URL/credential/path smuggling rejected.
  assert.ok(has(v, "t.includes('@')"), 'credential-bearing targets no longer rejected');
});

test('FP3: server enforces per-command cap, per-machine rate limit, and tenant kill switch', () => {
  const ctrl = read('server/src/controllers/fleetController.ts');
  assert.ok(has(ctrl, 'validateProbeTargets'), 'probe enqueue no longer validates targets');
  assert.ok(has(ctrl, 'PROBE_RATE_MAX_PER_WINDOW'), 'per-machine probe rate limit removed');
  assert.ok(has(ctrl, 'recentProbeCount'), 'probe rate-limit counter removed');
  assert.ok(has(ctrl, 'probeEnabledForTenant'), 'tenant probe kill switch removed');
  assert.ok(has(ctrl, "'fleet_probe_enqueue'"), 'probe audit-trail write removed');
});

test('FP4: agent re-validates targets, honors local opt-out, and UPLOADS probe findings', () => {
  const pt = read('agent/probe_targets.go');
  assert.ok(has(pt, 'func ValidateProbeTargets'), 'agent-side target re-validation removed');
  assert.ok(has(pt, 'func ProbeDisabledLocally'), 'agent per-host probe opt-out removed');
  assert.ok(has(pt, '"169.254.0.0/16"'), 'agent no longer blocks link-local/metadata');
  const main = read('agent/main.go');
  // The probe dispatch must call SendFleetTelemetry — not just print like the --probe CLI.
  assert.ok(has(main, 'runProbe'), 'daemon probe dispatch removed');
  const start = main.indexOf('runProbe := func');
  const body = main.slice(start, start + 1200);
  assert.ok(/SendFleetTelemetry/.test(body), 'daemon probe no longer uploads findings (regressed to print-only)');
});

// ---- Support-access gate: super admin sees aggregates only without a tenant grant ----
// Owner rule 2026-11-15. Behaviour is proven in test/supportAccessGate.test.ts; these
// canaries stop the gate from being bypassed or removed by a later edit.
test('SA1: requireTenantAccess no longer waves super sessions through', () => {
  const auth = read('server/src/middleware/auth.ts');
  const start = auth.indexOf('export const requireTenantAccess');
  const body = auth.slice(start, auth.indexOf('\n};', start));
  assert.ok(has(body, 'superAdminSupportGate(req, res, next)'), 'super sessions no longer go through the support-access gate');
  assert.ok(!/if \(isSuperRole\(req\.user\.role\)\) \{\s*next\(\);/.test(body), 'super sessions are passed straight to next() again');
  assert.ok(has(auth, 'await hasActiveSupportGrant(target)'), 'gate no longer checks the tenant grant');
  assert.ok(has(auth, "'support_access_read'"), 'granted reads are no longer audit-logged');
  assert.ok(has(auth, 'denySupportAccess(res, target)'), 'gate no longer refuses detail without a grant');
  assert.ok(has(auth, "return 'detail';"), 'unlisted routes no longer default to detail (fail closed)');
});

test('SA2: only management routes are exempt; host/asset routes are never "manage"', () => {
  const auth = read('server/src/middleware/auth.ts');
  const start = auth.indexOf('const SUPER_MANAGE_ROUTES');
  const manage = auth.slice(start, auth.indexOf(']);', start));
  for (const bad of ['/fleet/machines', '/fleet/cbom', '/fleet/drift', 'portal-data', '/threat-graph', '/pki', '/proxy', '/projects', '/scan', '/sbom', '/ai/chat', '/reports', '/git/']) {
    assert.ok(!has(manage, bad), `${bad} must not be a grant-exempt management route`);
  }
  const aStart = auth.indexOf('const SUPER_AGGREGATE_ROUTES');
  const aggregate = auth.slice(aStart, auth.indexOf(']);', aStart));
  for (const bad of ['/fleet/cbom', '/fleet/drift', '/threat-graph', '/pki', '/proxy', '/projects', '/scan', '/git/', '/fleet/groups', '/fleet/machines/']) {
    assert.ok(!has(aggregate, bad), `${bad} has no aggregate answer and must stay grant-only`);
  }
});

test('SA3: row-level guard and aggregate controllers honour the support scope', () => {
  const auth = read('server/src/middleware/auth.ts');
  const start = auth.indexOf('export const canAccessTenant');
  const body = auth.slice(start, auth.indexOf('\n};', start));
  assert.ok(!has(body, 'if (isSuperRole(req.user.role)) return true;'), 'canAccessTenant lets super sessions touch any tenant row again');
  assert.ok(has(body, "scope.mode === 'granted'"), 'canAccessTenant no longer requires the granted tenant');

  const fleet = read('server/src/controllers/fleetController.ts');
  const fm = fleet.slice(fleet.indexOf('export const getFleetMachines'), fleet.indexOf('export const deleteFleetMachine'));
  assert.ok(fm.indexOf('superNeedsGrant(req)') > -1 && fm.indexOf('superNeedsGrant(req)') < fm.indexOf('m.hostname'), 'getFleetMachines selects host rows before the support-access check');

  const admin = read('server/src/controllers/adminController.ts');
  const pd = admin.slice(admin.indexOf('export const getTenantPortalData'));
  assert.ok(pd.indexOf('superNeedsGrant(req)') > -1 && pd.indexOf('superNeedsGrant(req)') < pd.indexOf('m.hardware_uuid'), 'portal-data selects machines before the support-access check');
  const agg = admin.slice(admin.indexOf('const aggregatePortalData'), admin.indexOf('GET /api/admin/fleet/summary'));
  for (const bad of ['hostname', 'hardware_uuid', 'public_ip', 'FROM assets', 'FROM fleet_tokens']) {
    assert.ok(!has(agg, bad), `aggregate portal payload must not read ${bad}`);
  }
  const lib = read('server/src/lib/tenantAggregates.ts');
  const sql = lib.slice(lib.indexOf('pool.query(`'), lib.indexOf('GROUP BY'));
  for (const bad of ['hostname', 'm.ip', 'public_ip', 'hardware_uuid', 'computer_name', 'geo_']) {
    assert.ok(!has(sql, bad), `tenant aggregates must not select ${bad}`);
  }

  const ai = read('server/src/controllers/aiController.ts');
  const cs = ai.slice(ai.indexOf('export const chatInventoryScope'), ai.indexOf('const NO_TENANT_INVENTORY_NOTE'));
  assert.ok(has(cs, "scope?.mode === 'granted'"), 'Copilot gives a super session tenant inventory without a grant');
});

test('SA4: a support grant is always time-boxed and cannot be self-granted', () => {
  const lib = read('server/src/lib/supportAccess.ts');
  assert.ok(has(lib, 'export const MAX_GRANT_HOURS = 72;'), 'max grant window changed — review before raising it');
  assert.ok(has(lib, "expires_at <= created_at + interval '${MAX_GRANT_HOURS} hours'"), 'active-grant predicate no longer bounds the window');
  assert.ok(has(lib, 'revoked_at IS NULL AND expires_at > now()'), 'active-grant predicate no longer checks revoked/expired');
  assert.ok(!/revoked_at IS NULL\s+AND expires_at > now\(\)\s+LIMIT/.test(lib), 'a grant lookup bypasses ACTIVE_GRANT_SQL');
  const schema = read('server/src/models/schema.sql');
  assert.ok(has(schema, 'expires_at TIMESTAMP WITH TIME ZONE NOT NULL,\n  revoked_at'), 'support_access_grants.expires_at is no longer NOT NULL');
  const ctl = read('server/src/controllers/supportAccessController.ts');
  const g = ctl.slice(ctl.indexOf('export async function grantSupportAccess'), ctl.indexOf('export async function revokeSupportAccess'));
  assert.ok(g.indexOf('isSuperRole(req.user?.role)') > -1 && g.indexOf('isSuperRole(req.user?.role)') < g.indexOf('createGrant('), 'a platform session can grant itself support access');
  assert.ok(!has(ctl, 'active: grants'), 'status endpoint returns a list as `active` again (card showed ACTIVE with no expiry)');
});

// ---- No per-tenant special treatment ------------------------------------------
// Every tenant is matched by its own name and nothing else. Queries used to widen one
// tenant's reach with a hand-written alias (a literal name list, a LIKE on its name, a
// literal enrollment-token name): any tenant whose token or name happened to collide
// was pulled into that tenant's data. Old rows are fixed by the generic backfill in
// schema.sql, never by naming a tenant in code.
test('TN1: no query or resolver hard-codes a tenant, token name or email domain', () => {
  const files = [
    'server/src/controllers/fleetController.ts', 'server/src/controllers/adminController.ts',
    'server/src/controllers/reportController.ts', 'server/src/controllers/sbomController.ts',
    'server/src/controllers/aiController.ts', 'server/src/controllers/gitScanController.ts',
    'server/src/controllers/pkiConnectorController.ts', 'server/src/controllers/pqcProxyController.ts',
    'server/src/controllers/ciGateController.ts', 'server/src/controllers/threatGraphController.ts',
    'server/src/lib/roadmapReport.ts', 'server/src/lib/tenantAggregates.ts', 'server/src/middleware/auth.ts',
  ];
  const banned = [
    [/LOWER\(\$\{?\$?[\w.]*\}?\d*\)\s+IN\s*\(\s*'/i, 'compares the requested tenant to a literal name list'],
    [/tenant_name[^\n]{0,40}\bI?LIKE\s+'%[a-z]/i, 'matches tenant_name with a literal LIKE'],
    [/LOWER\((t\.)?name\)\s*=\s*'[a-z]/i, 'matches an enrollment token by a literal name'],
    [/REPLACE\(LOWER\(\$\d\),\s*'@/i, 'rewrites one email domain to another'],
    [/tenantName\s*=\s*'[A-Za-z]/, 'defaults a write to a literal tenant'],
    [/toLowerCase\(\)\s*===\s*'engg'/, 'infers a tenant from a token named engg'],
  ];
  for (const f of files) {
    const src = read(f);
    for (const [re, why] of banned) assert.ok(!re.test(src), `${f} ${why}`);
  }
});

test('TN2: the schema seeds no tenant and backfills tenant_name generically', () => {
  const schema = read('server/src/models/schema.sql');
  assert.ok(!/INSERT INTO admin_clients/i.test(schema), 'schema seeds a client organization again');
  assert.ok(!/INSERT INTO tenant_users/i.test(schema), 'schema seeds a tenant admin again');
  const bf = schema.slice(schema.indexOf('TENANT ATTRIBUTION BACKFILL'));
  assert.ok(bf.length > 200, 'tenant attribution backfill removed');
  assert.ok(!/'[A-Za-z][A-Za-z0-9 _-]{2,}'/.test(bf.replace(/'\[\^a-zA-Z0-9\]'|'g'/g, '')), 'backfill names a specific tenant or token');
});

test('TN3: the console resolves a workspace from the session, not from a per-tenant table', () => {
  const app = read('ui/src/App.tsx');
  assert.ok(!/sub\s*===\s*'/.test(app), 'App.tsx aliases a specific subdomain again');
  assert.ok(!/port\s*===\s*'50/.test(app), 'App.tsx maps a port to a specific tenant again');
  assert.ok(!/includes\('[a-z]+'\)\s*\?\s*'[a-z]+'/.test(app), 'App.tsx guesses a workspace from an email again');
  assert.ok(!/QS-(CORP|PARTNER)-[A-Z]+-[0-9A-F]{8}/.test(app), 'App.tsx ships a literal licence key');
  const portal = read('ui/src/components/TenantPortal.tsx');
  assert.ok(!/cleanSlug\.includes\('(?!partner)[a-z]+'\)/.test(portal), 'TenantPortal special-cases a tenant slug again');
  const landing = read('ui/src/components/LandingPage.tsx');
  assert.ok(!/cleanEmail\.includes\('/.test(landing), 'LandingPage guesses a workspace from an email again');
});

// ---------------------------------------------------------------------------
// ISO: no data crosses from one tenant to another.
// ---------------------------------------------------------------------------
test('ISO1: tenant-data reads have no unfiltered ("all tenants") variant', () => {
  const ai = read('server/src/controllers/aiController.ts');
  assert.ok(!/FROM assets'\s*\)/.test(ai), 'Copilot has an assets query with no tenant filter again');
  assert.ok(!/FROM assets ORDER BY/.test(ai), 'Copilot report/deck query has a fleet-wide variant again');
  assert.ok(!/whereTenant = scopeTenant \?/.test(ai), 'Copilot inventory filter is optional again');
  for (const [file, fn] of [
    ['server/src/controllers/pkiConnectorController.ts', 'getPkiConnectors'],
    ['server/src/controllers/pkiConnectorController.ts', 'getPkiSyncedAssets'],
    ['server/src/controllers/pqcProxyController.ts', 'getProxies'],
    ['server/src/controllers/gitScanController.ts', 'getGitScanHistory'],
    ['server/src/controllers/ciGateController.ts', 'getCIGateHistory'],
    ['server/src/controllers/fleetController.ts', 'getFleetMachines'],
    ['server/src/controllers/fleetController.ts', 'getFleetCBOM'],
    ['server/src/controllers/fleetController.ts', 'getFleetDrift'],
  ]) {
    const src = read(file);
    const at = src.indexOf(`export const ${fn} = `);
    assert.ok(at >= 0, `${fn} not found`);
    const next = src.indexOf('\nexport const ', at + 10);
    const body = src.slice(at, next > 0 ? next : undefined);
    assert.ok(/denyUnscoped\(res\)/.test(body), `${fn} no longer refuses a request with no tenant scope`);
  }
});

test('ISO2: connector assets are removed by connector AND tenant, never by name alone', () => {
  const pki = read('server/src/controllers/pkiConnectorController.ts');
  assert.ok(!/FROM assets WHERE source (IN \([^)]*\)|= '[a-z_]+') AND \(source_ref = \$1 OR source_ref = \$2\)"/.test(pki),
    'a connector asset query is scoped by name only again');
  assert.ok(/CONNECTOR_ASSETS =[\s\S]{0,200}tenant_name[\s\S]{0,40}\$3/.test(pki), 'CONNECTOR_ASSETS lost its tenant filter');
});

test('ISO3: an enrollment token never takes its tenant from its own name', () => {
  const fleet = read('server/src/controllers/fleetController.ts');
  assert.ok(!/assignedTenant = name\.trim\(\)/.test(fleet), 'token creation falls back to the token name again');
  assert.ok(!/tokenRow\.name \|\| ''\)\.trim\(\) \|\| 'DEFAULT_FLEET'/.test(fleet), 'ingest files a tenant-less token under its name again');
  assert.ok(!/tenant_name \|\| owner\.rows\[0\]\.name/.test(fleet), 'token ownership falls back to the token name again');
});

test('ISO4: a tenant portal finds its client by name only, and licences by tenant only', () => {
  const admin = read('server/src/controllers/adminController.ts');
  const at = admin.indexOf('export const getTenantPortalData');
  const body = admin.slice(admin.lastIndexOf('const aggregatePortalData', at));
  assert.ok(!/display_name[^\n]*= \$1/.test(body), 'portal-data matches a client by display name again');
  assert.ok(!/LOWER\(customer_id\) = \$1|LOWER\(admin_email\) = \$1/.test(body), 'portal-data matches a client by customer id / email again');
  assert.ok(!/customer_id = \$2::text/.test(body), 'portal-data returns licences by customer id again');
});

test('ISO5: every tenant-creation path applies the tenant-name rules', () => {
  const admin = read('server/src/controllers/adminController.ts');
  for (const fn of ['deployInlineClient', 'createClient', 'onboardPartnerTenant', 'onboardUser']) {
    const at = admin.indexOf(`export const ${fn} = `);
    const body = admin.slice(at, admin.indexOf('\nexport const ', at + 10));
    assert.ok(/tenantNameProblem\(/.test(body), `${fn} creates a tenant without the name rules`);
  }
  const billing = read('server/src/controllers/billingController.ts');
  assert.ok((billing.match(/isReservedTenantName\(/g) || []).length >= 2, 'checkout no longer refuses reserved tenant names');
  assert.ok(!/Math\.random\(\) \* 9000/.test(admin + billing), 'customer ids are drawn without a uniqueness check again');
});

test('ISO6: Copilot chat history in the browser belongs to the signed-in tenant + user', () => {
  const portal = read('ui/src/components/TenantPortal.tsx');
  assert.ok(!/copilotStorageKey = `quarkshield_copilot_sessions_\$\{cleanSlug\}`/.test(portal), 'Copilot history is keyed by workspace only again');
  assert.ok(/copilotLoadedFor !== copilotStorageKey\) return;/.test(portal), 'Copilot history can be saved under another owner again');
});
