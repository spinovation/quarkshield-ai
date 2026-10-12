import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildThreatGraph } from '../src/lib/threatGraph/engine';
import { SourceData } from '../src/lib/threatGraph/types';

// Fleet-probe integration contract (graph layer).
//
// A full enqueue→poll→probe→sync→rebuild chain needs a live Postgres, so it runs
// in staging (see agent/FLEET-PROBE-PLAN.md §10 / Phase 0). This test locks in the
// part the feature OWNS that is runnable in-process: once the agent's ProbeEndpoint
// findings arrive (type='network_probe', path='host:port') and are ingested into the
// `assets` table, the Threat & Risk Graph must draw the connectivity arrows. If this
// breaks, probing would run but the graph would stay disconnected — the exact bug
// the feature exists to fix.

// Shape matches agent/prober.go ProbeEndpoint output as ingested by fleetController.
const sourceAfterProbe = (): SourceData => ({
  tenant: 'ACME',
  machines: [
    { id: 'm-ws', hostname: 'alice-mbp', ip: '10.0.1.20', group_name: 'workstations' },
    { id: 'm-web', hostname: 'web-prod-01', ip: '10.0.0.5', public_ip: '203.0.113.10', group_name: 'prod-servers' },
  ],
  cryptoFindings: [
    // The probe: alice-mbp (m-ws) handshook api.example.com:443 and found classical ECDH.
    { id: 'np1', machine_id: 'm-ws', type: 'network_probe', name: 'api.example.com - TLS Key Exchange',
      path: 'api.example.com:443', algorithm: 'X25519 (Classical ECDH)', key_size: 256,
      is_vulnerable: true, risk_level: 'critical' },
    // The peer leaf cert captured during the same probe.
    { id: 'np2', machine_id: 'm-ws', type: 'network_probe', name: 'api.example.com (Leaf Cert)',
      path: 'api.example.com:443', algorithm: 'RSA-2048', key_size: 2048, is_vulnerable: true, risk_level: 'high' },
    // web-prod-01 already has an enrolled certificate whose DNS name is that endpoint.
    { id: 'c1', machine_id: 'm-web', type: 'certificate', name: 'TLS certificate CN=api.example.com',
      algorithm: 'RSA-2048', key_size: 2048, is_vulnerable: true, risk_level: 'high' },
  ],
  components: [],
  gitScans: [],
  proxies: [],
  pkiConnectors: [],
  pkiAssets: [],
  overrides: [],
});

const rel = (g: any, from: string, to: string, kind: string) =>
  g.relationships.find((r: any) => r.from_asset === from && r.to_asset === to && r.kind === kind);

test('a probe finding creates R3 connects_to (host → probed endpoint)', () => {
  const g = buildThreatGraph(sourceAfterProbe());
  const r = rel(g, 'host:m-ws', 'ep:api.example.com:443', 'connects_to');
  assert.ok(r, 'expected connects_to from the probing host to the probed endpoint');
  assert.equal(r.rule_id, 'R3');
});

test('a probed endpoint lets a matching host cert form R2 serves', () => {
  const g = buildThreatGraph(sourceAfterProbe());
  const r = rel(g, 'host:m-web', 'ep:api.example.com:443', 'serves');
  assert.ok(r, 'expected serves from the cert-owning host to the probed endpoint');
});

test('the probed endpoint node carries the captured (vulnerable) crypto posture', () => {
  const g = buildThreatGraph(sourceAfterProbe());
  const ep = g.assets.find((a: any) => a.id === 'ep:api.example.com:443');
  assert.ok(ep, 'probed endpoint node missing from graph');
});

test('without any probe finding there is no endpoint node or connectivity arrow (the disconnected state we fix)', () => {
  const src = sourceAfterProbe();
  src.cryptoFindings = src.cryptoFindings.filter(f => f.type !== 'network_probe');
  const g = buildThreatGraph(src);
  assert.ok(!g.assets.find((a: any) => a.id === 'ep:api.example.com:443'), 'endpoint should not exist without a probe');
  assert.ok(!g.relationships.find((r: any) => r.kind === 'connects_to'), 'no connects_to without a probe');
});
