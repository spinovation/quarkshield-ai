import { test } from 'node:test';
import assert from 'node:assert/strict';
import { requireTenantAccess } from '../src/middleware/auth';

// requireTenantAccess guards ~71 tenant-data routes (/fleet/cbom, /ai/chat, /reports/*,
// /threat-graph/*, /tenant/:tenant/portal-data, …). These tests pin its contract, in
// particular that a NON-super session with no tenant can never fall through to "all tenants".

const run = (user: any, opts: { query?: any; params?: any; headers?: any } = {}) => {
  const req: any = { user, query: { ...(opts.query || {}) }, params: { ...(opts.params || {}) }, headers: { ...(opts.headers || {}) } };
  let status = 200; let body: any; let nextCalled = false;
  const res: any = { status(c: number) { status = c; return this; }, json(b: any) { body = b; return this; } };
  requireTenantAccess(req, res, () => { nextCalled = true; });
  return { status, body, nextCalled, query: req.query };
};

test('no session → 401', () => {
  const r = run(undefined);
  assert.equal(r.status, 401);
  assert.equal(r.nextCalled, false);
});

test('non-super session with NO tenant and no requested tenant → 403 (was: fell through to all tenants)', () => {
  const r = run({ role: 'user', tenant: null });
  assert.equal(r.status, 403);
  assert.equal(r.nextCalled, false);
  assert.match(r.body.error, /No tenant/);
});

test('non-super session with NO tenant cannot pick a tenant via query / header / param', () => {
  assert.equal(run({ role: 'user', tenant: '' }, { query: { tenant: 'acme' } }).status, 403);
  assert.equal(run({ role: 'user', tenant: '' }, { headers: { 'x-tenant-id': 'acme' } }).status, 403);
  assert.equal(run({ role: 'user', tenant: '' }, { params: { tenant: 'acme' } }).status, 403);
});

test('tenant session with no requested tenant is pinned to its own tenant', () => {
  const r = run({ role: 'admin', tenant: 'acme' });
  assert.equal(r.nextCalled, true);
  assert.equal(r.query.tenant, 'acme');
});

test('tenant session may name its own tenant (normalized) but not another', () => {
  assert.equal(run({ role: 'admin', tenant: 'Acme Corp' }, { query: { tenant: 'acmecorp' } }).nextCalled, true);
  const other = run({ role: 'admin', tenant: 'acme' }, { query: { tenant: 'othercorp' } });
  assert.equal(other.status, 403);
  assert.equal(other.nextCalled, false);
});

test('super sessions are NOT waved through any more: they go to the support-access gate', () => {
  // Was: next() for any super session on any tenant route. Now the gate decides
  // (asynchronously), so nothing has been allowed by the time the call returns.
  // Full behaviour is covered in supportAccessGate.test.ts.
  assert.equal(run({ role: 'superadmin', tenant: null }).nextCalled, false);
  assert.equal(run({ role: 'secops_lead', tenant: null }, { query: { tenant: 'acme' } }).nextCalled, false);
});

test('QSG service-token identity (tenant bound from the token record) still passes', () => {
  // allowServiceToken sets user.tenant and query.tenant from the token row, role 'service'.
  const r = run({ role: 'service', accountType: 'service', tenant: 'acme' }, { query: { tenant: 'acme' } });
  assert.equal(r.nextCalled, true);
});

// ---- Advisor chat inventory scope (POST /api/ai/chat) -------------------------

import { chatInventoryScope } from '../src/controllers/aiController';

const chatReq = (user: any, query: any = {}) => ({ user, query, body: {} } as any);

test('chat scope: a non-super session with no tenant gets NO inventory (not the fleet)', () => {
  assert.deepEqual(chatInventoryScope(chatReq({ role: 'user', tenant: '' })), { allowed: false, tenant: null });
  assert.deepEqual(chatInventoryScope(chatReq({ role: 'user' })), { allowed: false, tenant: null });
  assert.deepEqual(chatInventoryScope(chatReq({ role: 'admin', tenant: 'acme' }, { tenant: 'othercorp' })), { allowed: true, tenant: 'acme' });
});

test('chat scope: a super session gets inventory only under an active support grant', () => {
  // No grant (no supportScope / aggregate scope) → no inventory, and never the whole fleet.
  assert.deepEqual(chatInventoryScope(chatReq({ role: 'superadmin' }, { tenant: 'acme' })), { allowed: false, tenant: null });
  assert.deepEqual(chatInventoryScope(chatReq({ role: 'superadmin', tenant: '' }, { tenant: 'all' })), { allowed: false, tenant: null });
  const granted: any = chatReq({ role: 'superadmin' }, { tenant: 'acme' });
  granted.supportScope = { mode: 'granted', tenant: 'acme' };
  assert.deepEqual(chatInventoryScope(granted), { allowed: true, tenant: 'acme' });
});

// ---------------------------------------------------------------------------
// Every place a request names a tenant must name the session's own tenant.
// ---------------------------------------------------------------------------
const runFull = (user: any, opts: { query?: any; params?: any; headers?: any; body?: any } = {}) => {
  const req: any = {
    user, query: { ...(opts.query || {}) }, params: { ...(opts.params || {}) },
    headers: { ...(opts.headers || {}) }, body: opts.body,
  };
  let status = 200; let nextCalled = false;
  const res: any = { status(c: number) { status = c; return this; }, json() { return this; } };
  requireTenantAccess(req, res, () => { nextCalled = true; });
  return { status, nextCalled, req };
};
const acme = { role: 'admin', tenant: 'acme', accountType: 'tenant' };

test('own :tenant with a foreign ?tenant is refused (was: checked the param, answered for the query)', () => {
  const r = runFull(acme, { params: { tenant: 'acme' }, query: { tenant: 'globex' } });
  assert.equal(r.status, 403);
  assert.equal(r.nextCalled, false);
});

test('own ?tenant with a foreign X-Tenant-Id / X-Tenant-Slug is refused', () => {
  for (const h of ['x-tenant-id', 'x-tenant-slug']) {
    const r = runFull(acme, { query: { tenant: 'acme' }, headers: { [h]: 'globex' } });
    assert.equal(r.status, 403, h);
    assert.equal(r.nextCalled, false, h);
  }
});

test('?tenant=all, an array or an object is never the session tenant', () => {
  for (const t of ['all', ['acme', 'globex'], { a: 'acme' }]) {
    const r = runFull(acme, { query: { tenant: t } });
    assert.equal(r.status, 403, JSON.stringify(t));
    assert.equal(r.nextCalled, false);
  }
});

test('after the check the request names only the session tenant', () => {
  const r = runFull(acme, { headers: { 'x-tenant-id': 'ACME' }, body: { tenantName: 'globex', tenant: 'globex', tenant_name: 'globex', other: 1 } });
  assert.equal(r.nextCalled, true);
  assert.equal(r.req.query.tenant, 'acme');
  assert.equal(r.req.headers['x-tenant-id'], undefined);
  assert.deepEqual(r.req.body, { tenantName: 'acme', tenant: 'acme', tenant_name: 'acme', other: 1 });
});

test('a body tenant that already is the session tenant is left as sent', () => {
  const r = runFull(acme, { body: { tenantName: 'Acme' } });
  assert.equal(r.nextCalled, true);
  assert.equal(r.req.body.tenantName, 'Acme');
});
