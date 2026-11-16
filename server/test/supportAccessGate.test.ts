// =============================================================================
// SUPPORT ACCESS GATE — platform (super-admin) sessions vs tenant data
// -----------------------------------------------------------------------------
// Owner rule: a platform admin manages tenants / licensing / onboarding and sees
// AGGREGATE metadata only. Tenant detail (hostnames, IPs, CBOM assets, portal
// data, …) is reachable only under that tenant's active, time-boxed
// support-access grant, and each such request is audit-logged.
//
// No live DB: pool.query is replaced with an in-memory fake that models the
// support_access_grants / audit_logs tables and records every statement, so the
// tests can also assert that a host-row query was never even issued.
//
// Run:  cd server && npm test
// =============================================================================
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import pool from '../src/config/db';
import {
  requireTenantAccess, canAccessTenant, resolveWriteTenant, superRouteMode, superNeedsGrant,
} from '../src/middleware/auth';
import {
  ACTIVE_GRANT_SQL, clampGrantHours, MAX_GRANT_HOURS, MIN_GRANT_HOURS, DEFAULT_GRANT_HOURS,
} from '../src/lib/supportAccess';
import { foldTenantAggregates } from '../src/lib/tenantAggregates';
import { getFleetMachines } from '../src/controllers/fleetController';
import { getTenantPortalData } from '../src/controllers/adminController';
import { grantSupportAccess, getSupportAccessStatus } from '../src/controllers/supportAccessController';
import { exportExecutiveReport } from '../src/controllers/reportController';

// ---- in-memory fake DB -------------------------------------------------------
type Grant = { tenant_name: string; granted_by: string; reason: string | null; created_at: Date; expires_at: Date; revoked_at: Date | null };
const HOUR = 3600_000;
const key = (s: string) => (s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
let grants: Grant[] = [];
let audits: { action: string; actor: string; details: string }[] = [];
let statements: string[] = [];

const SECRET_HOST = 'fin-db-prod-07.acme.internal';
const SECRET_IP = '10.42.7.19';
const SECRET_UUID = '4C4C4544-0042-3510-8057-B7C04F4D4732';
const SECRET_ASSET = '/etc/ssl/private/acme-payments.key';

/** Mirrors ACTIVE_GRANT_SQL: not revoked, unexpired, and window <= MAX_GRANT_HOURS. */
const isActive = (g: Grant) =>
  !g.revoked_at && g.expires_at.getTime() > Date.now() &&
  g.expires_at.getTime() <= g.created_at.getTime() + MAX_GRANT_HOURS * HOUR;

(pool as any).query = async (sql: string, params: any[] = []) => {
  statements.push(sql);
  const rows = (r: any[]) => ({ rows: r, rowCount: r.length });
  if (/INSERT INTO audit_logs/.test(sql)) {
    audits.push({ action: params[1], actor: params[2], details: params[3] });
    return rows([]);
  }
  if (/FROM support_access_grants/.test(sql)) {
    assert.ok(sql.includes(ACTIVE_GRANT_SQL), 'grant lookup must use the active + time-boxed predicate');
    const active = grants.filter(isActive);
    const hit = params.length ? active.filter(g => key(g.tenant_name) === params[0]) : active;
    return rows(hit);
  }
  if (/UPDATE support_access_grants/.test(sql)) return rows([]);
  if (/INSERT INTO support_access_grants/.test(sql)) {
    const hours = Number(params[4]);
    const g: Grant = { tenant_name: params[1], granted_by: params[2], reason: params[3], created_at: new Date(), expires_at: new Date(Date.now() + hours * HOUR), revoked_at: null };
    grants.push(g);
    return rows([g]);
  }
  // Aggregate roll-up (lib/tenantAggregates) — GROUP BY, no host columns.
  if (/FROM fleet_machines m/.test(sql) && /GROUP BY/.test(sql)) {
    return rows([{ tenant_name: 'acme', agent_version: '2.3.1', os: 'linux', license_key: 'QS-ACME-1', machines: 3, online: 2, assets: 120, vulnerable: 40, risk_sum: 180, risk_n: 3, last_seen: new Date() }]);
  }
  // Host rows (fleet directory / portal machines).
  if (/FROM fleet_machines m/.test(sql)) {
    return rows([{ id: 'm1', hostname: SECRET_HOST, ip: SECRET_IP, hardwareUuid: SECRET_UUID, tenantName: 'acme', status: 'online', assetCount: 120, vulnerableCount: 40, quantumRiskScore: 60 }]);
  }
  if (/FROM assets a/.test(sql)) {
    return rows([{ id: 'a1', name: 'payments key', path: SECRET_ASSET, algorithm: 'RSA', keySize: 2048, isVulnerable: true, hostname: SECRET_HOST, source: 'endpoint' }]);
  }
  if (/FROM fleet_tokens/.test(sql)) return rows([{ id: 't1', name: 'default', token: 'qs_enroll_SECRET', tenantName: 'acme' }]);
  if (/FROM admin_clients/.test(sql)) return rows([{ id: 'c1', name: 'acme', displayName: 'Acme', customerId: 'CORP-1', mcaLimit: 50 }]);
  if (/FROM admin_licenses/.test(sql)) return rows([{ id: 'l1', licenseKey: 'QS-ACME-1', tenantName: 'acme', seats: 50, status: 'active' }]);
  return rows([]);
};

beforeEach(() => { grants = []; audits = []; statements = []; });

const grant = (tenant: string, opts: Partial<Grant> = {}) => {
  grants.push({ tenant_name: tenant, granted_by: 'admin@acme.test', reason: null, created_at: new Date(), expires_at: new Date(Date.now() + 24 * HOUR), revoked_at: null, ...opts });
};

const SUPER = { sub: 'u1', email: 'ops@quarkshield.ai', role: 'superadmin', accountType: 'superadmin', tenant: null };
const TENANT_ADMIN = { sub: 'u2', email: 'admin@acme.test', role: 'admin', accountType: 'tenant', tenant: 'acme' };

const mkRes = () => {
  const res: any = { statusCode: 200, body: undefined as any };
  res.status = (c: number) => { res.statusCode = c; return res; };
  res.json = (b: any) => { res.body = b; return res; };
  res.send = (b: any) => { res.body = b; return res; };
  res.setHeader = () => res;
  return res;
};
const mkReq = (user: any, route: string, o: { method?: string; query?: any; params?: any; headers?: any; body?: any } = {}) => ({
  user, route: { path: route }, method: o.method || 'GET', path: route, ip: '203.0.113.9',
  query: { ...(o.query || {}) }, params: { ...(o.params || {}) }, headers: { ...(o.headers || {}) }, body: o.body,
} as any);

/** Run the real middleware; resolves once it has called next() or written a response. */
const gate = async (req: any) => {
  const res = mkRes();
  let nextCalled = false;
  requireTenantAccess(req, res, () => { nextCalled = true; });
  for (let i = 0; i < 20 && !nextCalled && res.body === undefined; i++) await new Promise(r => setImmediate(r));
  return { res, nextCalled };
};
const hostQueried = () => statements.some(s => /FROM fleet_machines m/.test(s) && !/GROUP BY/.test(s));
const assetQueried = () => statements.some(s => /FROM assets a/.test(s));
const leaks = (body: any) => {
  const j = JSON.stringify(body);
  return [SECRET_HOST, SECRET_IP, SECRET_UUID, SECRET_ASSET, 'qs_enroll_SECRET'].filter(x => j.includes(x));
};

// ---- route classification ----------------------------------------------------
test('route policy: unlisted tenant routes default to detail (fail closed)', () => {
  assert.equal(superRouteMode('/fleet/cbom'), 'detail');
  assert.equal(superRouteMode('/threat-graph/graph'), 'detail');
  assert.equal(superRouteMode('/pki/assets'), 'detail');
  assert.equal(superRouteMode('/some/future/route'), 'detail');
  assert.equal(superRouteMode(undefined), 'detail');
  assert.equal(superRouteMode('/fleet/machines'), 'aggregate');
  assert.equal(superRouteMode('/tenant/:tenant/portal-data'), 'aggregate');
  assert.equal(superRouteMode('/fleet/tokens'), 'manage');
  assert.equal(superRouteMode('/tenants/:tenant/users'), 'manage');
  // Host-level writes are NOT management: deleting / rescanning a machine needs a grant.
  assert.equal(superRouteMode('/fleet/machines/:id'), 'detail');
  assert.equal(superRouteMode('/fleet/machines/:machineId/pull'), 'detail');
});

// ---- NO GRANT ----------------------------------------------------------------
test('no grant: detail routes are refused for a super admin, with no audit row', async () => {
  for (const route of ['/fleet/cbom', '/threat-graph/graph', '/pki/assets', '/scan/remote-git/history', '/fleet/drift', '/projects']) {
    const { res, nextCalled } = await gate(mkReq(SUPER, route, { query: { tenant: 'acme' } }));
    assert.equal(nextCalled, false, `${route} must not reach the controller`);
    assert.equal(res.statusCode, 403);
    assert.equal(res.body.supportAccessRequired, true);
    assert.equal(res.body.tenant, 'acme');
  }
  assert.equal(audits.length, 0);
});

test('no grant: a super admin naming NO tenant cannot get fleet-wide detail', async () => {
  const { res, nextCalled } = await gate(mkReq(SUPER, '/fleet/cbom'));
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.supportAccessRequired, true);
  const all = await gate(mkReq(SUPER, '/fleet/cbom', { query: { tenant: 'all' } }));
  assert.equal(all.res.statusCode, 403);
});

test('no grant: GET /fleet/machines returns per-tenant aggregates and no host rows', async () => {
  const req = mkReq(SUPER, '/fleet/machines');
  const g = await gate(req);
  assert.equal(g.nextCalled, true);
  assert.deepEqual(req.supportScope, { mode: 'aggregate', tenant: null });
  assert.equal(superNeedsGrant(req), true);
  const res = mkRes();
  await getFleetMachines(req, res);
  assert.equal(res.body.aggregateOnly, true);
  assert.equal(res.body.supportAccessRequired, true);
  assert.deepEqual(res.body.machines, []);
  assert.equal(res.body.tenants[0].tenantName, 'acme');
  assert.equal(res.body.tenants[0].machineCount, 3);
  assert.equal(res.body.tenants[0].avgRiskScore, 60);
  assert.deepEqual(res.body.tenants[0].agentVersions, { '2.3.1': 3 });
  assert.deepEqual(res.body.tenants[0].seatsByLicense, { 'QS-ACME-1': 3 });
  assert.equal(hostQueried(), false, 'the host-row query must not even run');
  assert.deepEqual(leaks(res.body), []);
});

test('no grant: GET /tenant/:tenant/portal-data returns stats/licences, never machines/assets/tokens', async () => {
  const req = mkReq(SUPER, '/tenant/:tenant/portal-data', { params: { tenant: 'acme' } });
  const g = await gate(req);
  assert.equal(g.nextCalled, true);
  assert.equal(req.supportScope.mode, 'aggregate');
  const res = mkRes();
  await getTenantPortalData(req, res);
  assert.equal(res.body.aggregateOnly, true);
  assert.equal(res.body.supportAccessRequired, true);
  assert.deepEqual(res.body.machines, []);
  assert.deepEqual(res.body.assets, []);
  assert.deepEqual(res.body.tokens, []);
  assert.equal(res.body.stats.totalMachines, 3);
  assert.equal(res.body.stats.totalSeats, 50);
  assert.equal(res.body.licenses.length, 1);
  assert.equal(hostQueried(), false);
  assert.equal(assetQueried(), false);
  assert.deepEqual(leaks(res.body), []);
  assert.equal(audits.length, 0);
});

test('no grant: a per-tenant executive report is refused; only the collective roll-up is not gated here', async () => {
  const req = mkReq(SUPER, '/reports/executive', { query: { tenant: 'acme', format: 'json' } });
  assert.equal((await gate(req)).nextCalled, true); // aggregate-mode route: controller decides
  const res = mkRes();
  await exportExecutiveReport(req, res);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.supportAccessRequired, true);
});

test('no grant: management routes still work (onboarding / licensing is the operator\'s job)', async () => {
  for (const route of ['/fleet/tokens', '/tenants/:tenant/users', '/tenants/:tenant/2fa-policy', '/billing/portal-session']) {
    const req = mkReq(SUPER, route, { params: { tenant: 'acme' } });
    const g = await gate(req);
    assert.equal(g.nextCalled, true, route);
    assert.equal(req.supportScope.mode, 'manage');
  }
  assert.equal(audits.length, 0);
});

// ---- ACTIVE GRANT ------------------------------------------------------------
test('active grant: detail is allowed, the tenant is pinned, and an audit row is written', async () => {
  grant('acme');
  const req = mkReq(SUPER, '/fleet/cbom', { query: { tenant: 'acme' }, headers: { 'x-tenant-id': 'acme' } });
  const g = await gate(req);
  assert.equal(g.nextCalled, true);
  assert.deepEqual(req.supportScope, { mode: 'granted', tenant: 'acme' });
  assert.equal(req.query.tenant, 'acme');
  assert.equal(req.headers['x-tenant-id'], undefined);
  assert.equal(audits.length, 1);
  assert.equal(audits[0].action, 'support_access_read');
  assert.equal(audits[0].actor, 'ops@quarkshield.ai');
  assert.match(audits[0].details, /tenant=acme route=GET \/fleet\/cbom/);
});

test('active grant: /fleet/machines and portal-data return real host/asset detail (+ audit rows)', async () => {
  grant('Acme'); // granted under the display name; matched on the normalized key
  const req = mkReq(SUPER, '/fleet/machines', { query: { tenant: 'acme' } });
  assert.equal((await gate(req)).nextCalled, true);
  assert.equal(superNeedsGrant(req), false);
  const res = mkRes();
  await getFleetMachines(req, res);
  assert.ok(Array.isArray(res.body));
  assert.equal(res.body[0].hostname, SECRET_HOST);

  const preq = mkReq(SUPER, '/tenant/:tenant/portal-data', { params: { tenant: 'acme' } });
  assert.equal((await gate(preq)).nextCalled, true);
  const pres = mkRes();
  await getTenantPortalData(preq, pres);
  assert.equal(pres.body.aggregateOnly, undefined);
  assert.equal(pres.body.machines[0].hostname, SECRET_HOST);
  assert.equal(pres.body.assets[0].path, SECRET_ASSET);
  assert.equal(audits.length, 2);
  assert.ok(audits.every(a => a.action === 'support_access_read'));
});

test('active grant: a write is audited as an action and attributed to the granted tenant', async () => {
  grant('acme');
  const req = mkReq(SUPER, '/fleet/pull-bulk', { method: 'POST', query: { tenant: 'acme' }, body: {} });
  assert.equal((await gate(req)).nextCalled, true);
  assert.equal(audits[0].action, 'support_access_action');
  assert.equal(resolveWriteTenant(req, 'othercorp'), 'acme');
});

test('active grant for A cannot be spent on B', async () => {
  grant('acme');
  // B named directly → refused.
  const b = await gate(mkReq(SUPER, '/fleet/cbom', { query: { tenant: 'othercorp' } }));
  assert.equal(b.res.statusCode, 403);
  // A in the query, B smuggled in the body / header → refused as ambiguous.
  const mixedBody = await gate(mkReq(SUPER, '/projects', { method: 'POST', query: { tenant: 'acme' }, body: { tenantName: 'othercorp' } }));
  assert.equal(mixedBody.nextCalled, false);
  assert.equal(mixedBody.res.statusCode, 400);
  const mixedHdr = await gate(mkReq(SUPER, '/fleet/cbom', { query: { tenant: 'acme' }, headers: { 'x-tenant-id': 'othercorp' } }));
  assert.equal(mixedHdr.res.statusCode, 400);
  const arr = await gate(mkReq(SUPER, '/fleet/cbom', { query: { tenant: ['acme', 'othercorp'] } }));
  assert.equal(arr.res.statusCode, 400);
  // Row-level guard (id-keyed resources): only rows of the granted tenant.
  const req = mkReq(SUPER, '/fleet/machines/:id', { method: 'DELETE', query: { tenant: 'acme' } });
  assert.equal((await gate(req)).nextCalled, true);
  assert.equal(canAccessTenant(req, 'ACME'), true);
  assert.equal(canAccessTenant(req, 'othercorp'), false);
  assert.equal(audits.filter(a => /othercorp/.test(a.details)).length, 0);
});

// ---- EXPIRED / REVOKED / NOT TIME-BOXED --------------------------------------
test('expired grant: blocked again', async () => {
  grant('acme', { created_at: new Date(Date.now() - 25 * HOUR), expires_at: new Date(Date.now() - 1000) });
  const d = await gate(mkReq(SUPER, '/fleet/cbom', { query: { tenant: 'acme' } }));
  assert.equal(d.nextCalled, false);
  assert.equal(d.res.statusCode, 403);
  const req = mkReq(SUPER, '/fleet/machines', { query: { tenant: 'acme' } });
  await gate(req);
  const res = mkRes();
  await getFleetMachines(req, res);
  assert.equal(res.body.aggregateOnly, true);
  assert.deepEqual(leaks(res.body), []);
  assert.equal(audits.length, 0);
});

test('revoked grant: blocked immediately, even though it has not expired', async () => {
  grant('acme', { revoked_at: new Date() });
  const d = await gate(mkReq(SUPER, '/fleet/cbom', { query: { tenant: 'acme' } }));
  assert.equal(d.res.statusCode, 403);
  const req = mkReq(SUPER, '/tenant/:tenant/portal-data', { params: { tenant: 'acme' } });
  await gate(req);
  const res = mkRes();
  await getTenantPortalData(req, res);
  assert.deepEqual(res.body.machines, []);
  assert.equal(audits.length, 0);
});

test('a grant is always time-boxed: an over-long window is not honoured and durations are clamped', async () => {
  // Hand-inserted row that "never" expires (10 years) → not an active grant.
  grant('acme', { expires_at: new Date(Date.now() + 10 * 365 * 24 * HOUR) });
  assert.equal((await gate(mkReq(SUPER, '/fleet/cbom', { query: { tenant: 'acme' } }))).res.statusCode, 403);
  assert.match(ACTIVE_GRANT_SQL, /revoked_at IS NULL/);
  assert.match(ACTIVE_GRANT_SQL, /expires_at > now\(\)/);
  assert.match(ACTIVE_GRANT_SQL, new RegExp(`expires_at <= created_at \\+ interval '${MAX_GRANT_HOURS} hours'`));
  assert.equal(clampGrantHours(24), 24);
  assert.equal(clampGrantHours(100000), MAX_GRANT_HOURS);
  assert.equal(clampGrantHours(Infinity), DEFAULT_GRANT_HOURS);
  assert.equal(clampGrantHours(0), DEFAULT_GRANT_HOURS);
  assert.equal(clampGrantHours(-5), DEFAULT_GRANT_HOURS);
  assert.equal(clampGrantHours('forever'), DEFAULT_GRANT_HOURS);
  assert.equal(clampGrantHours(undefined), DEFAULT_GRANT_HOURS);
  assert.equal(clampGrantHours(0.2), MIN_GRANT_HOURS);
});

test('grant API: only the tenant can open the window, and it always carries an expiry', async () => {
  // A platform session cannot grant itself access.
  const sres = mkRes();
  await grantSupportAccess(mkReq(SUPER, '/support-access/grant', { method: 'POST', body: { durationHours: 72 } }), sres);
  assert.equal(sres.statusCode, 403);
  assert.equal(grants.length, 0);
  // Tenant admin, absurd duration → clamped to the maximum, expires_at present.
  const tres = mkRes();
  await grantSupportAccess(mkReq(TENANT_ADMIN, '/support-access/grant', { method: 'POST', body: { durationHours: 999999 } }), tres);
  assert.equal(tres.body.success, true);
  const ms = new Date(tres.body.grant.expires_at).getTime() - Date.now();
  assert.ok(ms > 0 && ms <= MAX_GRANT_HOURS * HOUR + 1000, 'expiry must be within the maximum window');
  assert.equal(audits[0].action, 'support_access_granted');
});

test('status API: `active` is a boolean for every caller (was a list → "ACTIVE · Expires —")', async () => {
  // Super session, no tenant named, no grants: must NOT read as active.
  let res = mkRes();
  await getSupportAccessStatus(mkReq(SUPER, '/support-access/status'), res);
  assert.equal(res.body.active, false);
  assert.equal(res.body.grant, null);
  assert.deepEqual(res.body.grants, []);
  grant('acme');
  res = mkRes();
  await getSupportAccessStatus(mkReq(SUPER, '/support-access/status'), res);
  assert.equal(res.body.active, false);
  assert.equal(res.body.grants.length, 1);
  res = mkRes();
  await getSupportAccessStatus(mkReq(SUPER, '/support-access/status', { query: { tenant: 'acme' } }), res);
  assert.equal(res.body.active, true);
  assert.ok(res.body.grant.expires_at, 'an active grant always reports its expiry');
  res = mkRes();
  await getSupportAccessStatus(mkReq(TENANT_ADMIN, '/support-access/status'), res);
  assert.equal(res.body.active, true);
  assert.ok(res.body.grant.expires_at);
});

// ---- TENANT USERS / SERVICE TOKEN UNCHANGED ----------------------------------
test('tenant user: unchanged — own data, synchronously, with no grant lookup and no audit', async () => {
  const req = mkReq(TENANT_ADMIN, '/fleet/machines');
  const res = mkRes();
  let nextCalled = false;
  requireTenantAccess(req, res, () => { nextCalled = true; });
  assert.equal(nextCalled, true, 'tenant path stays synchronous');
  assert.equal(req.query.tenant, 'acme');
  assert.equal(req.supportScope, undefined);
  assert.equal(superNeedsGrant(req), false);
  assert.equal(statements.length, 0, 'no grant lookup for a tenant session');
  const out = mkRes();
  await getFleetMachines(req, out);
  assert.ok(Array.isArray(out.body));
  assert.equal(out.body[0].hostname, SECRET_HOST);

  const preq = mkReq(TENANT_ADMIN, '/tenant/:tenant/portal-data', { params: { tenant: 'acme' } });
  assert.equal((await gate(preq)).nextCalled, true);
  const pres = mkRes();
  await getTenantPortalData(preq, pres);
  assert.equal(pres.body.aggregateOnly, undefined);
  assert.equal(pres.body.machines[0].hardwareUuid, SECRET_UUID);
  assert.equal(pres.body.tokens[0].token, 'qs_enroll_SECRET');
  assert.equal(audits.length, 0);
  assert.equal(canAccessTenant(req, 'acme'), true);
  assert.equal(canAccessTenant(req, 'othercorp'), false);
  // …and still cannot reach another tenant.
  const other = await gate(mkReq(TENANT_ADMIN, '/fleet/cbom', { query: { tenant: 'othercorp' } }));
  assert.equal(other.res.statusCode, 403);
  assert.equal(other.res.body.supportAccessRequired, undefined);
});

test('qsg_svc_ service token (posture:read on /fleet/cbom): unchanged', async () => {
  // allowServiceToken binds role "service" + the token's tenant before requireTenantAccess.
  const req = mkReq({ sub: 'svc:1', email: 'svc:1', role: 'service', accountType: 'service', tenant: 'acme' }, '/fleet/cbom', { query: { tenant: 'acme' } });
  const res = mkRes();
  let nextCalled = false;
  requireTenantAccess(req, res, () => { nextCalled = true; });
  assert.equal(nextCalled, true);
  assert.equal(superNeedsGrant(req), false);
  assert.equal(statements.length, 0);
  assert.equal(audits.length, 0);
});

// ---- misc --------------------------------------------------------------------
test('a failed grant lookup denies (never opens the data)', async () => {
  const real = (pool as any).query;
  (pool as any).query = async () => { throw new Error('db down'); };
  try {
    const d = await gate(mkReq(SUPER, '/fleet/cbom', { query: { tenant: 'acme' } }));
    assert.equal(d.nextCalled, false);
    assert.equal(d.res.statusCode, 503);
  } finally { (pool as any).query = real; }
});

test('canAccessTenant: a super session with no scope (route never gated) is refused', () => {
  assert.equal(canAccessTenant(mkReq(SUPER, '/x'), 'acme'), false);
});

test('aggregates fold: one row per tenant, case-insensitive, with grant status', () => {
  const out = foldTenantAggregates([
    { tenant_name: 'ACME', agent_version: '2.3.1', os: 'linux', license_key: 'K1', machines: 2, online: 1, assets: 10, vulnerable: 4, risk_sum: 100, risk_n: 2, last_seen: '2026-11-14T00:00:00Z' },
    { tenant_name: 'acme', agent_version: '2.3.0', os: 'windows', license_key: 'K1', machines: 1, online: 1, assets: 5, vulnerable: 1, risk_sum: 80, risk_n: 1, last_seen: '2026-11-15T00:00:00Z' },
    { tenant_name: 'beta', agent_version: '', os: '', license_key: '', machines: 1, online: 0, assets: 0, vulnerable: 0, risk_sum: 0, risk_n: 0, last_seen: null },
  ], [{ tenant_name: 'Acme', expires_at: '2026-11-16T00:00:00Z' }]);
  assert.equal(out.length, 2);
  const acme = out[0];
  assert.equal(acme.machineCount, 3);
  assert.equal(acme.avgRiskScore, 60);
  assert.deepEqual(acme.agentVersions, { '2.3.1': 2, '2.3.0': 1 });
  assert.deepEqual(acme.seatsByLicense, { K1: 3 });
  assert.equal(acme.lastSeen, '2026-11-15T00:00:00.000Z');
  assert.deepEqual(acme.supportAccess, { active: true, expiresAt: '2026-11-16T00:00:00.000Z' });
  assert.deepEqual(out[1].supportAccess, { active: false, expiresAt: null });
  assert.deepEqual(Object.keys(acme).sort(), ['agentVersions', 'assetCount', 'avgRiskScore', 'lastSeen', 'machineCount', 'onlineCount', 'osCounts', 'seatsByLicense', 'supportAccess', 'tenantName', 'vulnerableCount']);
});
