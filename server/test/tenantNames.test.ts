import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isReservedTenantName, tenantKey } from '../src/lib/tenantNames';
import { normTenant, scopedTenant } from '../src/middleware/auth';

test('tenantKey is the same normalisation the access check uses', () => {
  for (const s of ['Acme-Corp', 'ACME CORP', 'acme.corp_1', '', 'quarkshield.ai']) {
    assert.equal(tenantKey(s), normTenant(s), s);
  }
});

test('platform bucket names cannot be tenant names, in any spelling', () => {
  for (const s of ['system', 'SYSTEM', 'global', 'Community', 'all', 'DEFAULT_FLEET', 'default', 'collective',
    'quarkshield.ai', 'QuarkShield', 'www', 'api', 'admin']) {
    assert.equal(isReservedTenantName(s), true, s);
  }
});

test('ordinary names are not reserved', () => {
  for (const s of ['acme', 'globex', 'systemsinc', 'allstate', 'defaultco', 'apiary']) {
    assert.equal(isReservedTenantName(s), false, s);
  }
});

test('scopedTenant never yields "every tenant"', () => {
  const q = (tenant: any) => scopedTenant({ query: { tenant } } as any);
  assert.equal(q('acme'), 'acme');
  assert.equal(q(' acme '), 'acme');
  for (const t of [undefined, '', '  ', 'all', 'ALL', ['acme'], { a: 1 }]) assert.equal(q(t), null, JSON.stringify(t));
});
