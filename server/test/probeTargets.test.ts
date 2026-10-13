import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateProbeTargets, MAX_TARGETS_PER_COMMAND } from '../src/utils/probeTargets';

// ---- Shape / normalization --------------------------------------------------

test('accepts valid host:port targets and normalizes/de-dupes them', () => {
  const r = validateProbeTargets(['api.internal:443', '  API.internal:443 ', 'gateway.example.com:8443']);
  assert.equal(r.ok, true);
  // lowercased host + de-duped
  assert.deepEqual(r.targets, ['api.internal:443', 'gateway.example.com:8443']);
});

test('allows PRIVATE / RFC1918 targets (internal fleet topology is the whole point)', () => {
  const r = validateProbeTargets(['10.0.0.5:443', '192.168.1.10:5432', '172.16.4.4:443']);
  assert.equal(r.ok, true, r.error);
  assert.equal(r.targets.length, 3);
});

test('allows non-443 TLS ports (e.g. Postgres TLS on 5432)', () => {
  const r = validateProbeTargets(['db.internal:5432']);
  assert.equal(r.ok, true);
  assert.deepEqual(r.targets, ['db.internal:5432']);
});

test('accepts bracketed public IPv6 with port', () => {
  const r = validateProbeTargets(['[2606:4700:4700::1111]:443']);
  assert.equal(r.ok, true, r.error);
});

// ---- SSRF / abuse rejection (the sharp edge) --------------------------------

test('rejects the cloud metadata endpoint (169.254.169.254)', () => {
  const r = validateProbeTargets(['169.254.169.254:80']);
  assert.equal(r.ok, false);
  assert.match(r.error || '', /loopback\/link-local\/metadata|reserved/i);
});

test('rejects loopback literals and localhost', () => {
  for (const t of ['127.0.0.1:443', '[::1]:443', 'localhost:443', 'foo.localhost:443', '0.0.0.0:443']) {
    const r = validateProbeTargets([t]);
    assert.equal(r.ok, false, `expected ${t} to be rejected`);
  }
});

test('rejects multicast and reserved ranges', () => {
  for (const t of ['224.0.0.1:443', '240.0.0.1:443', '255.255.255.255:443']) {
    const r = validateProbeTargets([t]);
    assert.equal(r.ok, false, `expected ${t} to be rejected`);
  }
});

test('rejects targets carrying a scheme, credentials, path, or query (no data smuggling)', () => {
  for (const t of ['https://api.internal:443', 'user:pass@api.internal:443', 'api.internal:443/secret', 'api.internal:443?x=1']) {
    const r = validateProbeTargets([t]);
    assert.equal(r.ok, false, `expected ${t} to be rejected`);
  }
});

test('requires an explicit port', () => {
  const r = validateProbeTargets(['api.internal']);
  assert.equal(r.ok, false);
  assert.match(r.error || '', /port required/i);
});

test('rejects out-of-range and non-numeric ports', () => {
  for (const t of ['api.internal:0', 'api.internal:70000', 'api.internal:https']) {
    const r = validateProbeTargets([t]);
    assert.equal(r.ok, false, `expected ${t} to be rejected`);
  }
});

test('rejects a bare (unbracketed) IPv6 literal', () => {
  const r = validateProbeTargets(['2606:4700:4700::1111:443']);
  assert.equal(r.ok, false);
});

// ---- Caps / empties ---------------------------------------------------------

test('enforces the per-command target cap', () => {
  const many = Array.from({ length: MAX_TARGETS_PER_COMMAND + 1 }, (_, i) => `h${i}.internal:443`);
  const r = validateProbeTargets(many);
  assert.equal(r.ok, false);
  assert.match(r.error || '', /too many targets/i);
});

test('rejects an empty or all-blank list', () => {
  assert.equal(validateProbeTargets([]).ok, false);
  assert.equal(validateProbeTargets(['', '   ']).ok, false);
});

test('rejects a non-array input', () => {
  assert.equal(validateProbeTargets('api.internal:443' as any).ok, false);
  assert.equal(validateProbeTargets(null as any).ok, false);
});

// ---- Optional per-tenant allowlist (Phase-5 hardening) ----------------------

test('allowlist (when provided) restricts to attested targets', () => {
  const policy = { allowlist: ['api.internal:443', 'db.internal'] };
  assert.equal(validateProbeTargets(['api.internal:443'], policy).ok, true);
  // host-only allowlist entry matches any port on that host
  assert.equal(validateProbeTargets(['db.internal:5432'], policy).ok, true);
  // not attested -> rejected
  const r = validateProbeTargets(['evil.example.com:443'], policy);
  assert.equal(r.ok, false);
  assert.match(r.error || '', /allowlist/i);
});

test('absent/empty allowlist means free-form (still subject to always-block rules)', () => {
  assert.equal(validateProbeTargets(['anything.example.com:443'], { allowlist: [] }).ok, true);
  assert.equal(validateProbeTargets(['anything.example.com:443'], {}).ok, true);
});
