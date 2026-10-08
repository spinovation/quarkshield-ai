import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildThreatGraph } from '../src/lib/threatGraph/engine';
import { classifyPurpose, isHndlRelevant } from '../src/lib/threatGraph/cryptoPurpose';
import { parseHostPort, isPrivateHost } from '../src/lib/threatGraph/topology';
import { riskLevel } from '../src/lib/threatGraph/scoring';
import { SourceData } from '../src/lib/threatGraph/types';

const fixture = (): SourceData => ({
  tenant: 'ACME',
  machines: [
    { id: 'm-web', hostname: 'web-prod-01', ip: '10.0.0.5', public_ip: '203.0.113.10', group_name: 'prod-servers' },
    { id: 'm-ws', hostname: 'alice-mbp', ip: '10.0.1.20', public_ip: '203.0.113.10', group_name: 'prod-servers' },
  ],
  cryptoFindings: [
    { id: 'a1', machine_id: 'm-ws', type: 'network_probe', name: 'api.example.com - TLS Key Exchange', path: 'api.example.com:443',
      algorithm: 'X25519 (Classical ECDH)', key_size: 256, is_vulnerable: true, risk_level: 'critical' },
    { id: 'a2', machine_id: 'm-ws', type: 'ssh_key', name: '~/.ssh/id_rsa', algorithm: 'RSA', key_size: 1024, is_vulnerable: true, risk_level: 'high' },
    { id: 'a3', machine_id: 'm-web', type: 'certificate', name: 'TLS certificate CN=api.example.com', algorithm: 'RSA-2048', key_size: 2048,
      is_vulnerable: true, risk_level: 'high' },
  ],
  components: [
    { id: 'c1', source: 'endpoint', source_ref: 'web-prod-01', name: 'jsonwebtoken', version: '8.5.1', ecosystem: 'npm',
      vulnerabilities: [{ cveId: 'CVE-2022-23529', cvssScore: 9.8, severity: 'critical', fixedVersion: '9.0.0', remediationCmd: 'npm i jsonwebtoken@9', cwe: 'CWE-502' }] },
    { id: 'c2', source: 'endpoint', source_ref: 'web-prod-01', name: 'postgresql15-server', version: '15.4', ecosystem: 'os_pkg', vulnerabilities: [] },
    { id: 'c3', source: 'endpoint', source_ref: 'web-prod-01', name: 'express', version: '4.19.2', ecosystem: 'npm',
      vulnerabilities: [{ cveId: 'CLEAN', cvssScore: 0, severity: 'low' }] },
  ],
  gitScans: [
    { id: 'g1', repo_url: 'https://github.com/acme/api.git', repo_name: 'acme/api', findings: [
      { id: 'f1', category: 'private_key', filePath: 'deploy/id_ed25519', assetName: 'Committed SSH private key', algorithm: 'Ed25519', isVulnerable: true, riskLevel: 'critical' },
    ] },
  ],
  pkiConnectors: [{ id: 'k1', name: 'Prod Vault', provider: 'hashicorp_vault' }],
  pkiAssets: [{ id: 'p1', connector_id: 'k1', asset_name: 'issuing-ca', asset_type: 'ca_root', algorithm: 'RSA-4096', key_size: 4096, is_vulnerable: true, risk_level: 'high' }],
  proxies: [{ id: 'x1', name: 'edge-proxy', listen_port: 443, upstream_url: 'https://web-prod-01:8443', tls_curve: 'X25519MLKEM768' }],
  overrides: [],
});

test('crypto purpose is preserved (design doc §13)', () => {
  assert.equal(classifyPurpose({ type: 'ssh_key', name: 'id_rsa', algorithm: 'RSA' }), 'ssh_authentication');
  assert.equal(classifyPurpose({ type: 'network_probe', name: 'h - TLS Key Exchange', algorithm: 'X25519' }), 'key_establishment');
  assert.equal(classifyPurpose({ type: 'certificate', name: 'CN=x', algorithm: 'RSA-2048' }), 'tls_certificate');
  assert.equal(classifyPurpose({ type: 'asymmetric_key', name: 'k', algorithm: 'RSA-2048', key_usage: 'ENCRYPT_DECRYPT key transport' }), 'rsa_key_transport');
  assert.equal(isHndlRelevant('key_establishment', true), true);
  assert.equal(isHndlRelevant('ssh_authentication', true), false);
});

test('host parsing and exposure', () => {
  assert.deepEqual(parseHostPort('https://Web-Prod-01:8443/x'), { host: 'web-prod-01', port: 8443 });
  assert.deepEqual(parseHostPort('api.example.com:443'), { host: 'api.example.com', port: 443 });
  assert.equal(isPrivateHost('10.1.2.3'), true);
  assert.equal(isPrivateHost('web-prod-01'), true);
  assert.equal(isPrivateHost('api.example.com'), false);
});

test('risk matrix matches design doc §11 table', () => {
  assert.equal(riskLevel(1 * 1), 'low');
  assert.equal(riskLevel(2 * 3), 'high');
  assert.equal(riskLevel(3 * 4), 'critical');
});

test('topology is inferred with no manual links', () => {
  const g = buildThreatGraph(fixture());
  const rel = (from: string, to: string, kind: string) =>
    g.relationships.find(r => r.from_asset === from && r.to_asset === to && r.kind === kind);
  assert.equal(rel('proxy:x1', 'host:m-web', 'connects_to')?.confidence, 'high', 'R1 proxy → upstream host');
  assert.equal(rel('host:m-ws', 'ep:api.example.com:443', 'connects_to')?.confidence, 'medium', 'R3 probe');
  assert.ok(rel('host:m-web', 'ep:api.example.com:443', 'serves'), 'R2 cert DNS name ↔ endpoint');
  assert.ok(rel('host:m-web', 'svc:m-web:postgresql', 'runs'), 'R8 database service from SBOM');
  assert.ok(g.relationships.some(r => r.rule_id === 'R6' && r.confidence === 'low'), 'R6 segment');
  const db = g.assets.find(a => a.id === 'svc:m-web:postgresql')!;
  assert.equal(db.type, 'database');
  assert.equal(db.data_classification, 'sensitive');
  assert.equal(g.assets.find(a => a.id === 'proxy:x1')!.internet_exposed, true);
  assert.equal(g.assets.find(a => a.id === 'ep:api.example.com:443')!.internet_exposed, true);
  for (const r of g.relationships) assert.ok(r.rule_id && r.evidence, 'every edge carries evidence');
});

test('threats carry STRIDE, ATT&CK and kill-chain tags from their rule', () => {
  const g = buildThreatGraph(fixture());
  const byRule = (id: string) => g.threats.filter(t => t.rule_id === id);
  const exploit = byRule('TR-01')[0];
  assert.ok(exploit, 'CVE threat');
  assert.deepEqual(exploit.stride.sort(), ['E', 'T'], 'STRIDE from CWE-502');
  assert.ok(byRule('TR-04').some(t => t.asset_id === 'ep:api.example.com:443'), 'HNDL on exposed endpoint');
  assert.ok(byRule('TR-06').some(t => t.asset_id.startsWith('repo:')), 'committed key');
  assert.ok(byRule('TR-06').some(t => t.asset_id === 'host:m-ws'), 'weak SSH key');
  assert.ok(byRule('TR-07').some(t => t.asset_id === 'kms:k1'), 'quantum signature risk on CA');
  assert.ok(!g.vulns.some(v => v.cve === 'CLEAN'), 'clean placeholders ignored');
  for (const t of g.threats) {
    assert.ok(g.tags.some(x => x.object_id === t.id && x.framework === 'killchain'));
    if (t.attack.length) assert.ok(g.tags.some(x => x.object_id === t.id && x.framework === 'attack'));
  }
});

test('first milestone: an end-to-end path from vulnerable asset to sensitive data, scored and remediable', () => {
  const g = buildThreatGraph(fixture());
  const p = g.paths.find(x => x.goal_asset_id === 'svc:m-web:postgresql' && x.entry_threat_id === 'thr:TR-01:host:m-web');
  assert.ok(p, 'path web host → database');
  // The web server is published by the PQC proxy, so the path enters through it.
  assert.deepEqual(p!.hops.map(h => h.asset_id), ['proxy:x1', 'host:m-web', 'svc:m-web:postgresql']);
  assert.ok(g.threats.find(t => t.id === p!.entry_threat_id)!.attack.includes('T1190'), 'exploit public-facing app');
  const web = g.assets.find(a => a.id === 'host:m-web')!;
  assert.equal(web.type, 'server');
  assert.equal(web.exposed_via, 'proxy:x1');
  assert.equal(g.assets.find(a => a.id === 'host:m-ws')!.type, 'endpoint');
  assert.equal(p!.hops[p!.hops.length - 1].kill_chain, 'actions_on_objectives');
  const risk = g.risks.find(r => r.attack_path_id === p!.id)!;
  assert.equal(risk.impact, 4);
  assert.ok(['high', 'critical'].includes(risk.level));
  const rem = g.remediations.find(r => r.id === 'rem:patch:cmp:c1')!;
  assert.ok(rem && risk.remediation_ids.includes(rem.id));
  assert.ok(rem.breaks_paths >= 1);
  assert.ok(g.threats.some(t => t.rule_id === 'TR-08' && t.asset_id === 'svc:m-web:postgresql'), 'exfiltration goal threat');
  // Workstation → api.example.com (probe, medium) → web host serving it → database:
  // preferred over the low-confidence shared-segment hypothesis.
  const lateral = g.paths.find(x => x.entry_threat_id === 'thr:TR-06:host:m-ws' && x.goal_asset_id === 'svc:m-web:postgresql');
  assert.ok(lateral);
  assert.equal(lateral!.confidence, 'medium');
  assert.deepEqual(lateral!.hops.map(h => h.asset_id), ['host:m-ws', 'ep:api.example.com:443', 'host:m-web', 'svc:m-web:postgresql']);
});

test('residual risk drops only when remediation is done', () => {
  const base = buildThreatGraph(fixture());
  const risk = base.risks.find(r => r.remediation_ids.includes('rem:patch:cmp:c1') && r.attack_path_id)!;
  const inProg = buildThreatGraph(fixture(), [{ id: 'rem:patch:cmp:c1', status: 'in_progress' }]);
  assert.equal(inProg.risks.find(r => r.id === risk.id)!.residual_score, risk.inherent_score);
  const done = buildThreatGraph(fixture(), [{ id: 'rem:patch:cmp:c1', status: 'done' }]);
  const after = done.risks.find(r => r.id === risk.id)!;
  assert.ok(after.residual_score < after.inherent_score);
  assert.equal(after.inherent_score, risk.inherent_score);
});

test('context overrides adjust impact but never create links', () => {
  const src = fixture();
  const before = buildThreatGraph(src).relationships.length;
  src.overrides.push({ asset_id: 'host:m-ws', criticality: 4, data_classification: 'cui' });
  const g = buildThreatGraph(src);
  const ws = g.assets.find(a => a.id === 'host:m-ws')!;
  assert.equal(ws.context_origin, 'override');
  assert.equal(ws.data_classification, 'cui');
  assert.equal(g.relationships.length, before);
});
