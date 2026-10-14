/**
 * Crypto blast-radius (dependency-map P1b) — pure, no I/O.
 *
 * Answers "what breaks if I rotate/replace THIS key or cert?" by walking the
 * relationships QuarkShield already infers (topology.ts R1–R9) out from the
 * asset that HOLDS the crypto finding. This is a REVERSE-DEPENDENCY view over
 * existing edges — it does NOT invent relationships, and it does NOT claim the
 * dedicated cert-SAN / issuer edges (secured_by / chains_to) that still require
 * agent cert-parsing (see docs/CRYPTO_USAGE_DEPENDENCY_MAP_AND_IMPACT_ANALYSIS.md
 * §7). Every affected asset carries the edge kind, direction, confidence and
 * evidence that put it in the radius, so the UI can explain each inclusion.
 */
import { CryptoNode, TrAsset, TrRelationship, RelKind, Confidence } from './types';

export interface BlastRadiusEdge {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  relationship: string;      // human phrase, from the host's point of view
  kind: RelKind;
  host_is_from: boolean;     // direction of the underlying edge
  relies_on_host_key: boolean; // true = this asset depends on the host's crypto (a consumer that breaks on rotation)
  confidence: Confidence;
  rule_id: string;
  evidence: Record<string, unknown>;
}

export interface CryptoBlastRadius {
  crypto_id: string;
  host_asset_id: string;
  host_asset_name: string;
  algorithm: string;
  purpose: CryptoNode['purpose'];
  quantum_vulnerable: boolean;
  hndl_relevant: boolean;
  affected_count: number;     // total 1-hop neighbours of the host
  consumer_count: number;     // of those, the ones that rely on the host's key (break on rotation)
  affected: BlastRadiusEdge[];// consumers first, then by confidence
  note: string;               // honest scope statement
}

// Per edge kind: given whether the HOST is the `from` end, what is the OTHER
// end's relationship to the host's crypto, and does it RELY ON that crypto
// (i.e. would it break if the key/cert is rotated)?
type EdgeSense = { phrase: string; relies: boolean };
const REL_SEMANTICS: Record<RelKind, { hostFrom: EdgeSense; hostTo: EdgeSense }> = {
  connects_to:      { hostFrom: { phrase: 'host initiates a connection to {n}', relies: false }, hostTo: { phrase: '{n} connects to host over its TLS', relies: true } },
  serves:           { hostFrom: { phrase: '{n} is served by host (relies on its certificate)', relies: true }, hostTo: { phrase: 'host is served by {n}', relies: false } },
  trusts:           { hostFrom: { phrase: 'host trusts {n}', relies: false }, hostTo: { phrase: '{n} trusts host as a trust anchor', relies: true } },
  runs:             { hostFrom: { phrase: 'host runs service {n} (service relies on host crypto)', relies: true }, hostTo: { phrase: '{n} runs host', relies: false } },
  ssh_to:           { hostFrom: { phrase: 'host connects via SSH to {n}', relies: false }, hostTo: { phrase: '{n} connects via SSH to host (host-key dependency)', relies: true } },
  authenticates_via:{ hostFrom: { phrase: 'host authenticates via {n}', relies: false }, hostTo: { phrase: '{n} authenticates via host', relies: true } },
  deployed_from:    { hostFrom: { phrase: 'host is deployed from {n}', relies: false }, hostTo: { phrase: '{n} is deployed from host (signing/provenance dependency)', relies: true } },
  stores_data_in:   { hostFrom: { phrase: 'host stores data in {n}', relies: false }, hostTo: { phrase: '{n} stores data in host', relies: false } },
  network_adjacent: { hostFrom: { phrase: 'network-adjacent to {n}', relies: false }, hostTo: { phrase: 'network-adjacent to {n}', relies: false } },
};

const CONF_RANK: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

export const cryptoBlastRadius = (
  crypto: CryptoNode,
  assetsById: Map<string, TrAsset>,
  relationships: TrRelationship[],
): CryptoBlastRadius => {
  const hostId = crypto.asset_id;
  const host = assetsById.get(hostId);
  const byKey = new Map<string, BlastRadiusEdge>();

  for (const r of relationships) {
    const hostIsFrom = r.from_asset === hostId;
    const hostIsTo = r.to_asset === hostId;
    if (!hostIsFrom && !hostIsTo) continue;
    const neighborId = hostIsFrom ? r.to_asset : r.from_asset;
    if (neighborId === hostId) continue;
    const n = assetsById.get(neighborId);
    const sense = REL_SEMANTICS[r.kind];
    if (!sense) continue;
    const e = hostIsFrom ? sense.hostFrom : sense.hostTo;
    const name = n?.name || neighborId;
    // One row per (neighbour, kind, direction); keep the higher-confidence
    // duplicate (mirrors topology.ts addRel, which also prefers higher confidence).
    const dedupeKey = `${neighborId}|${r.kind}|${hostIsFrom}`;
    const existing = byKey.get(dedupeKey);
    if (existing && CONF_RANK[existing.confidence] >= CONF_RANK[r.confidence]) continue;
    byKey.set(dedupeKey, {
      asset_id: neighborId,
      asset_name: name,
      asset_type: n?.type || 'unknown',
      relationship: e.phrase.replace('{n}', name),
      kind: r.kind,
      host_is_from: hostIsFrom,
      relies_on_host_key: e.relies,
      confidence: r.confidence,
      rule_id: r.rule_id,
      evidence: r.evidence || {},
    });
  }
  const affected: BlastRadiusEdge[] = [...byKey.values()];

  // Consumers (break on rotation) first, then by edge confidence, then name.
  affected.sort((a, b) =>
    Number(b.relies_on_host_key) - Number(a.relies_on_host_key) ||
    CONF_RANK[b.confidence] - CONF_RANK[a.confidence] ||
    a.asset_name.localeCompare(b.asset_name));

  const consumer_count = affected.filter(a => a.relies_on_host_key).length;
  const note = consumer_count
    ? `${consumer_count} asset(s) rely on this ${crypto.purpose.replace(/_/g, ' ')} key/cert and may break if it is rotated or replaced. Derived from inferred topology (1-hop); confidence is per-edge. Dedicated certificate-SAN and issuer-chain edges require agent cert-parsing (not yet collected).`
    : `No consuming assets were found in the inferred topology for this finding. Absence of edges is not proof of no dependents — topology is inferred from collected signals (1-hop).`;

  return {
    crypto_id: crypto.id,
    host_asset_id: hostId,
    host_asset_name: host?.name || hostId,
    algorithm: crypto.algorithm,
    purpose: crypto.purpose,
    quantum_vulnerable: crypto.quantum_vulnerable,
    hndl_relevant: crypto.hndl_relevant,
    affected_count: affected.length,
    consumer_count,
    affected,
    note,
  };
};
