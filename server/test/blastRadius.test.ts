import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cryptoBlastRadius } from '../src/lib/threatGraph/blastRadius';
import { CryptoNode, TrAsset, TrRelationship, RelKind, Confidence } from '../src/lib/threatGraph/types';

const asset = (id: string, name = id, type = 'service'): TrAsset => ({
  id, type: type as TrAsset['type'], name, environment: null, criticality: 2,
  data_classification: 'internal', internet_exposed: false, context_origin: 'inferred',
  source_table: 'derived', source_id: id, inference: [],
});

const rel = (from: string, to: string, kind: RelKind, confidence: Confidence = 'medium', rule_id = 'R?'): TrRelationship =>
  ({ id: `rel:${kind}:${from}>${to}`, from_asset: from, to_asset: to, kind, protocol: null, port: null, confidence, rule_id, evidence: {} });

const crypto = (asset_id: string): CryptoNode => ({
  id: 'cf:cert-1', asset_id, name: 'web TLS cert', algorithm: 'RSA-2048', key_size: 2048,
  purpose: 'tls_certificate', quantum_vulnerable: true, classically_weak: false,
  hndl_relevant: false, risk_level: 'high', recommendation: 'migrate to ML-DSA',
});

const mapOf = (...a: TrAsset[]) => new Map(a.map(x => [x.id, x]));

test('serves(host→client) and trusts(client→host) count the OTHER end as a consumer', () => {
  const r = cryptoBlastRadius(
    crypto('host'),
    mapOf(asset('host', 'web-host', 'server'), asset('client-a'), asset('ca-client')),
    [rel('host', 'client-a', 'serves', 'high', 'R2'), rel('ca-client', 'host', 'trusts', 'medium', 'R4')],
  );
  assert.equal(r.affected_count, 2);
  assert.equal(r.consumer_count, 2);
  assert.ok(r.affected.every(e => e.relies_on_host_key));
});

test('an upstream the host merely connects_to does NOT rely on the host key', () => {
  const r = cryptoBlastRadius(
    crypto('host'),
    mapOf(asset('host'), asset('upstream')),
    [rel('host', 'upstream', 'connects_to', 'high', 'R1')],
  );
  assert.equal(r.affected_count, 1);
  assert.equal(r.consumer_count, 0);
  assert.equal(r.affected[0].relies_on_host_key, false);
});

test('consumers sort before non-consumers, then by confidence', () => {
  const r = cryptoBlastRadius(
    crypto('host'),
    mapOf(asset('host'), asset('peer'), asset('client-lo'), asset('client-hi')),
    [
      rel('host', 'peer', 'network_adjacent', 'low', 'R6'),        // non-consumer
      rel('host', 'client-lo', 'serves', 'low', 'R2'),             // consumer, low
      rel('host', 'client-hi', 'serves', 'high', 'R2'),            // consumer, high
    ],
  );
  assert.deepEqual(r.affected.map(e => e.asset_id), ['client-hi', 'client-lo', 'peer']);
  assert.equal(r.consumer_count, 2);
});

test('direction matters: host as the serving side vs the served side', () => {
  const served = cryptoBlastRadius(crypto('host'), mapOf(asset('host'), asset('n')), [rel('host', 'n', 'serves')]);
  assert.equal(served.affected[0].relies_on_host_key, true);   // host serves n → n relies on host cert
  const servedBy = cryptoBlastRadius(crypto('host'), mapOf(asset('host'), asset('n')), [rel('n', 'host', 'serves')]);
  assert.equal(servedBy.affected[0].relies_on_host_key, false); // n serves host → host relies on n
});

test('edges not touching the host are ignored; self-edges skipped', () => {
  const r = cryptoBlastRadius(
    crypto('host'),
    mapOf(asset('host'), asset('x'), asset('y')),
    [rel('x', 'y', 'connects_to'), rel('host', 'host', 'runs')],
  );
  assert.equal(r.affected_count, 0);
  assert.match(r.note, /No consuming assets/);
});

test('higher-confidence duplicate edge wins for the same neighbour+kind+direction', () => {
  const r = cryptoBlastRadius(
    crypto('host'),
    mapOf(asset('host'), asset('n')),
    [rel('host', 'n', 'serves', 'low'), rel('host', 'n', 'serves', 'high')],
  );
  assert.equal(r.affected_count, 1);
  assert.equal(r.affected[0].confidence, 'high');
});

test('note names the purpose and flags the inferred-topology limitation', () => {
  const r = cryptoBlastRadius(crypto('host'), mapOf(asset('host'), asset('n')), [rel('host', 'n', 'serves')]);
  assert.match(r.note, /tls certificate/);
  assert.match(r.note, /agent cert-parsing/);
});
