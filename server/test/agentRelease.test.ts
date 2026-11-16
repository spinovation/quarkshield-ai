import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  parseAgentRelease, loadAgentRelease, cmpAgentVersion, upgradeStateFor, releaseHasBuildFor,
  MIN_PUSH_UPGRADE_VERSION,
} from '../src/lib/agentRelease';

// A syntactically valid 64-byte signature (the server never verifies it — agents do).
const SIG = Buffer.alloc(64, 7).toString('base64');
const manifestFor = (version: string, artifacts: Record<string, unknown> = {
  'windows/amd64': { path: '/downloads/quarkshield-scanner-windows-amd64.exe', sha256: 'a'.repeat(64) },
  'linux/amd64': { path: '/downloads/quarkshield-scanner-linux-amd64', sha256: 'b'.repeat(64) },
  'darwin/app': { path: '/downloads/quarkshield-scanner-macos.zip', sha256: 'c'.repeat(64) },
}) => JSON.stringify({ product: 'quarkshield-agent', version, artifacts }, null, 2) + '\n';

test('parseAgentRelease keeps the manifest bytes exactly as published', () => {
  const m = manifestFor('2.4.0');
  const r = parseAgentRelease(m, SIG + '\n');
  assert.ok(r);
  assert.equal(r!.manifest, m, 'the signed bytes must be forwarded unmodified');
  assert.equal(r!.signature, SIG);
  assert.equal(r!.version, '2.4.0');
});

test('parseAgentRelease rejects unusable input', () => {
  assert.equal(parseAgentRelease(manifestFor('2.4.0'), ''), null, 'missing signature');
  assert.equal(parseAgentRelease(manifestFor('2.4.0'), 'not a signature'), null);
  assert.equal(parseAgentRelease('{not json', SIG), null);
  assert.equal(parseAgentRelease(JSON.stringify({ product: 'other', version: '2.4.0', artifacts: {} }), SIG), null);
  assert.equal(parseAgentRelease(manifestFor('2.4'), SIG), null, 'version must be MAJOR.MINOR.PATCH');
  assert.equal(parseAgentRelease(manifestFor('2.4.0; drop table'), SIG), null);
  assert.equal(parseAgentRelease(JSON.stringify({ product: 'quarkshield-agent', version: '2.4.0' }), SIG), null, 'no artifacts');
});

test('loadAgentRelease needs BOTH the manifest and its signature', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qs-rel-'));
  try {
    assert.equal(loadAgentRelease([dir]), null, 'empty directory');
    fs.writeFileSync(path.join(dir, 'agent-manifest.json'), manifestFor('2.4.0'));
    assert.equal(loadAgentRelease([dir]), null, 'a manifest without a signature is not a release');
    fs.writeFileSync(path.join(dir, 'agent-manifest.json.sig'), SIG + '\n');
    assert.equal(loadAgentRelease([dir])?.version, '2.4.0');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('cmpAgentVersion orders versions numerically', () => {
  assert.equal(cmpAgentVersion('2.3.2', '2.3.1'), 1);
  assert.equal(cmpAgentVersion('2.3.1', '2.3.2'), -1);
  assert.equal(cmpAgentVersion('2.10.0', '2.9.9'), 1);
  assert.equal(cmpAgentVersion('v2.3.1', '2.3.1'), 0);
  assert.equal(cmpAgentVersion('', '2.3.1'), -1);
});

test('upgradeStateFor classifies endpoints', () => {
  const release = parseAgentRelease(manifestFor('2.4.0'), SIG)!;
  const win = { os: 'windows', arch: 'amd64' };
  assert.equal(upgradeStateFor(null, { ...win, agentVersion: '2.3.2' }), 'unknown', 'no release published');
  assert.equal(upgradeStateFor(release, { ...win, agentVersion: '2.4.0' }), 'current');
  assert.equal(upgradeStateFor(release, { ...win, agentVersion: '2.5.0' }), 'current', 'never offer a downgrade');
  assert.equal(upgradeStateFor(release, { ...win, agentVersion: MIN_PUSH_UPGRADE_VERSION }), 'pushable');
  // Agents older than the first push-capable release ignore the command entirely.
  assert.equal(upgradeStateFor(release, { ...win, agentVersion: '2.3.1' }), 'manual');
  assert.equal(upgradeStateFor(release, { ...win, agentVersion: '' }), 'manual');
  assert.equal(upgradeStateFor(release, { ...win, agentVersion: null }), 'manual');
  assert.equal(upgradeStateFor(release, { os: 'linux', arch: 'arm64', agentVersion: '2.3.2' }), 'unsupported');
  // force = re-install of the SAME version only; it never makes a newer agent pushable.
  assert.equal(upgradeStateFor(release, { ...win, agentVersion: '2.4.0' }, true), 'pushable');
  assert.equal(upgradeStateFor(release, { ...win, agentVersion: '2.5.0' }, true), 'current');
});

test('releaseHasBuildFor: macOS accepts the app archive or a bare binary', () => {
  const app = parseAgentRelease(manifestFor('2.4.0'), SIG)!;
  assert.equal(releaseHasBuildFor(app, 'darwin', 'arm64'), true);
  const bare = parseAgentRelease(manifestFor('2.4.0', { 'darwin/arm64': { path: '/downloads/x', sha256: 'd'.repeat(64) } }), SIG)!;
  assert.equal(releaseHasBuildFor(bare, 'darwin', 'arm64'), true);
  assert.equal(releaseHasBuildFor(bare, 'darwin', 'amd64'), false);
  assert.equal(releaseHasBuildFor(bare, 'Windows', 'AMD64'), false);
});
