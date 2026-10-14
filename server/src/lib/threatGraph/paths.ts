/**
 * Attack-path construction (plan rev 2 §5). Bounded BFS over the auto-discovered
 * topology from ENTRY threats (initial-access–capable weaknesses) to high-impact GOAL
 * assets. Each path keeps the weakest edge confidence; low-confidence (lateral
 * hypothesis) edges are allowed but lower the path's likelihood and confidence.
 */
import crypto from 'crypto';
import {
  TrAsset, TrRelationship, TrThreat, TrAttackPath, PathHop, Confidence, RelKind,
} from './types';
import { impactOf, riskLevel } from './scoring';

const MAX_DEPTH = 6;
const MAX_PATHS = 60;

const FORWARD: RelKind[] = ['connects_to', 'ssh_to', 'stores_data_in', 'deployed_from', 'trusts'];
const BOTH: RelKind[] = ['serves', 'runs', 'network_adjacent', 'authenticates_via'];
const CONF_FACTOR: Record<Confidence, number> = { high: 1, medium: 0.85, low: 0.6 };
const CONF_ORDER: Confidence[] = ['low', 'medium', 'high'];

/** Threats that give an attacker an initial foothold. */
const isEntryThreat = (t: TrThreat, a: TrAsset): boolean => {
  switch (t.rule_id) {
    case 'TR-01':
    case 'TR-09': return a.internet_exposed || a.type === 'endpoint';
    case 'TR-03': return true;
    case 'TR-05': return a.internet_exposed;
    case 'TR-06': return true;
    default: return false;
  }
};

interface Step { to: string; rel: TrRelationship }

export const buildAttackPaths = (
  assets: TrAsset[], rels: TrRelationship[], threats: TrThreat[],
): TrAttackPath[] => {
  const byId = new Map(assets.map(a => [a.id, a]));
  const adj = new Map<string, Step[]>();
  const push = (from: string, s: Step) => { const l = adj.get(from) || []; l.push(s); adj.set(from, l); };
  for (const r of rels) {
    if (FORWARD.includes(r.kind) || BOTH.includes(r.kind)) push(r.from_asset, { to: r.to_asset, rel: r });
    if (BOTH.includes(r.kind)) push(r.to_asset, { to: r.from_asset, rel: r });
  }
  // At equal hop count, discover higher-confidence routes first.
  for (const l of adj.values()) l.sort((a, b) => CONF_FACTOR[b.rel.confidence] - CONF_FACTOR[a.rel.confidence]);
  const threatsByAsset = new Map<string, TrThreat[]>();
  for (const t of threats) { const l = threatsByAsset.get(t.asset_id) || []; l.push(t); threatsByAsset.set(t.asset_id, l); }
  const isGoal = (a: TrAsset) => a.type !== 'network_segment' && impactOf(a) >= 3;

  const paths: TrAttackPath[] = [];
  const seen = new Set<string>();

  for (const entry of threats) {
    const start = byId.get(entry.asset_id);
    if (!start || !isEntryThreat(entry, start)) continue;

    // BFS keeping the parent step to reconstruct the shortest path to each goal.
    const parent = new Map<string, { prev: string; rel: TrRelationship } | null>([[start.id, null]]);
    let frontier = [start.id];
    for (let depth = 0; depth <= MAX_DEPTH && frontier.length; depth++) {
      const next: string[] = [];
      for (const node of frontier) {
        const a = byId.get(node)!;
        if (isGoal(a)) {
          const key = `${entry.id}>${node}`;
          if (!seen.has(key)) { seen.add(key); paths.push(materialize(entry, node, parent, byId, threatsByAsset)); }
        }
        if (depth === MAX_DEPTH) continue;
        for (const s of adj.get(node) || []) {
          if (parent.has(s.to)) continue;
          parent.set(s.to, { prev: node, rel: s.rel });
          next.push(s.to);
        }
      }
      frontier = next;
    }
  }
  return paths.sort((a, b) => b.path_risk - a.path_risk || a.hops.length - b.hops.length).slice(0, MAX_PATHS);
};

const materialize = (
  entry: TrThreat, goalId: string,
  parent: Map<string, { prev: string; rel: TrRelationship } | null>,
  byId: Map<string, TrAsset>, threatsByAsset: Map<string, TrThreat[]>,
): TrAttackPath => {
  const chain: { asset: string; rel?: TrRelationship }[] = [];
  let cur: string | undefined = goalId;
  while (cur) {
    const p = parent.get(cur);
    chain.unshift({ asset: cur, rel: p?.rel });
    cur = p?.prev;
  }
  let factor = 1;
  let confidence: Confidence = 'high';
  // An asset published by a reverse proxy is reached THROUGH the proxy: show that hop.
  const start = byId.get(chain[0].asset)!;
  const proxyHop: PathHop | null = start.exposed_via && byId.has(start.exposed_via)
    ? { asset_id: start.exposed_via, threat_ids: [], kill_chain: 'delivery' }
    : null;
  const hops: PathHop[] = chain.map((c, i) => {
    if (c.rel) {
      factor *= CONF_FACTOR[c.rel.confidence];
      if (CONF_ORDER.indexOf(c.rel.confidence) < CONF_ORDER.indexOf(confidence)) confidence = c.rel.confidence;
    }
    const hopThreats = i === 0 ? [entry.id] : (threatsByAsset.get(c.asset) || []).map(t => t.id);
    const a = byId.get(c.asset)!;
    // Pivoting through a hop with no known weakness is harder.
    if (i > 0 && i < chain.length - 1 && !hopThreats.length && a.type !== 'network_segment') factor *= 0.75;
    return {
      asset_id: c.asset, via: c.rel?.id, threat_ids: hopThreats,
      kill_chain: i === 0 ? entry.kill_chain : i === chain.length - 1 ? 'actions_on_objectives' : 'installation',
    };
  });
  if (proxyHop) {
    hops[0].via = `rel:connects_to:${proxyHop.asset_id}>${start.id}`;
    hops.unshift(proxyHop);
  }
  const goal = byId.get(goalId)!;
  const likelihood = Math.max(1, Math.min(4, Math.round(entry.likelihood * factor)));
  const impact = impactOf(goal);
  const id = `path:${crypto.createHash('sha1').update(`${entry.id}|${chain.map(c => c.asset).join('>')}`).digest('hex').slice(0, 16)}`;
  return {
    id, entry_threat_id: entry.id, goal_asset_id: goalId, hops, confidence,
    likelihood, impact, path_risk: likelihood * impact, level: riskLevel(likelihood * impact),
  };
};
