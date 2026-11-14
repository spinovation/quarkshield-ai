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

test('super sessions are unaffected (fleet view and any tenant)', () => {
  assert.equal(run({ role: 'superadmin', tenant: null }).nextCalled, true);
  assert.equal(run({ role: 'secops_lead', tenant: null }, { query: { tenant: 'acme' } }).nextCalled, true);
});

test('QSG service-token identity (tenant bound from the token record) still passes', () => {
  // allowServiceToken sets user.tenant and query.tenant from the token row, role 'service'.
  const r = run({ role: 'service', accountType: 'service', tenant: 'acme' }, { query: { tenant: 'acme' } });
  assert.equal(r.nextCalled, true);
});
