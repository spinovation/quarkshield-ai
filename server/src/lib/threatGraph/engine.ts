/**
 * Threat & Risk Graph engine — pure function, no I/O:
 *   ASSET → COMPONENT → VULNERABILITY / EXPOSURE → THREAT → ATTACK PATH → RISK → REMEDIATION
 * store.ts loads SourceData and persists the GraphResult; this module is unit-tested.
 */
import {
  SourceData, GraphResult, TrThreat, TrRisk, TrRemediation, FrameworkTag, RemediationState,
  CryptoNode, RemediationType,
} from './types';
import { inferTopology } from './topology';
import { deriveThreats } from './rules';
import { buildAttackPaths } from './paths';
import { impactOf, riskLevel, residualLikelihood, overallRiskScore } from './scoring';
import { controlsForRisk } from './controlMap';

const CRYPTO_REMEDIATION: Record<CryptoNode['purpose'], RemediationType> = {
  ssh_authentication: 'rotate_key',
  tls_certificate: 'replace_certificate',
  ca_trust_anchor: 'replace_certificate',
  key_establishment: 'migrate_crypto',
  rsa_key_transport: 'migrate_crypto',
  code_or_data_signing: 'migrate_crypto',
  symmetric: 'migrate_crypto',
  configuration: 'harden_config',
  unknown: 'migrate_crypto',
};

export const buildThreatGraph = (src: SourceData, remediationState: RemediationState[] = []): GraphResult => {
  const topo = inferTopology(src);
  const assetsById = new Map(topo.assets.map(a => [a.id, a]));
  const threats: TrThreat[] = deriveThreats(topo);
  const paths = buildAttackPaths(topo.assets, topo.relationships, threats);

  // Data-exfiltration threat on every goal reached by at least one attack path.
  const pathsByGoal = new Map<string, string[]>();
  for (const p of paths) { const l = pathsByGoal.get(p.goal_asset_id) || []; l.push(p.id); pathsByGoal.set(p.goal_asset_id, l); }
  for (const [goalId, pids] of pathsByGoal) {
    const g = assetsById.get(goalId)!;
    threats.push({
      id: `thr:TR-08:${goalId}`, rule_id: 'TR-08', rule_version: 1, category: 'data_exfiltration',
      actor: 'Attacker who completes an attack path', intent: 'Collect and exfiltrate data held by this asset',
      title: `Data exfiltration from ${g.name}`,
      description: `${g.name} (${g.data_classification}) is reachable through ${pids.length} attack path(s).`,
      asset_id: goalId, driver_ids: pids, likelihood: Math.max(...paths.filter(p => p.goal_asset_id === goalId).map(p => p.likelihood)),
      stride: ['I'], attack: ['T1213', 'T1041'], kill_chain: 'actions_on_objectives',
      rationale: 'Goal-level threat: a sensitive/high-criticality asset is reachable by a computed attack path.',
    });
  }
  const threatById = new Map(threats.map(t => [t.id, t]));

  // ---- Remediations (one per fixable driver; state survives rebuilds) --------
  const remediations = new Map<string, TrRemediation>();
  const driverToRem = new Map<string, string>();
  const compById = new Map(topo.components.map(c => [c.id, c]));
  for (const v of topo.vulns) {
    const c = compById.get(v.component_id)!;
    const id = `rem:patch:${v.component_id}`;
    const r = remediations.get(id) || {
      id, action_type: 'patch' as RemediationType, target_id: v.component_id, asset_id: v.asset_id,
      action: `Upgrade ${c.name} ${c.version}${v.fixed_version ? ` → ${v.fixed_version}` : ' to a fixed release'}`,
      command: v.remediation_cmd, risk_ids: [], breaks_paths: 0,
    };
    remediations.set(id, r);
    driverToRem.set(v.id, id);
  }
  for (const c of topo.crypto) {
    const committedKey = assetsById.get(c.asset_id)?.type === 'repo' && (c.purpose === 'ssh_authentication' || /private|key/i.test(c.name));
    if (!c.quantum_vulnerable && !c.classically_weak && !committedKey) continue;
    const type = committedKey || (c.classically_weak && c.purpose === 'ssh_authentication') ? 'rotate_key' : CRYPTO_REMEDIATION[c.purpose];
    const id = `rem:${type}:${c.id}`;
    remediations.set(id, {
      id, action_type: type, target_id: c.id, asset_id: c.asset_id,
      action: committedKey
        ? `${c.name} (${c.algorithm}): remove the key from the repository and its history, revoke it wherever it is trusted, and issue a replacement kept in a secrets manager.`
        : `${c.name} (${c.algorithm}): ${c.recommendation}`,
      command: null, risk_ids: [], breaks_paths: 0,
    });
    driverToRem.set(c.id, id);
  }
  const stateById = new Map(remediationState.map(s => [s.id, s]));

  // ---- Risks -----------------------------------------------------------------
  const risks: TrRisk[] = [];
  const mkRisk = (id: string, assetId: string, threat: TrThreat, pathId: string | null, likelihood: number, impact: number, drivers: string[]) => {
    const remIds = [...new Set(drivers.map(d => driverToRem.get(d)).filter((x): x is string => !!x))];
    const statuses = remIds.map(r => stateById.get(r)?.status || 'open');
    const resL = residualLikelihood(likelihood, statuses);
    for (const r of remIds) remediations.get(r)!.risk_ids.push(id);
    risks.push({
      id, asset_id: assetId, threat_id: threat.id, attack_path_id: pathId, likelihood, impact,
      inherent_score: likelihood * impact, residual_score: resL * impact,
      level: riskLevel(likelihood * impact), residual_level: riskLevel(resL * impact),
      priority: 0, drivers, remediation_ids: remIds, controls: controlsForRisk(threat.rule_id, !!pathId),
    });
  };
  for (const t of threats) {
    if (t.rule_id === 'TR-08') continue;
    const a = assetsById.get(t.asset_id)!;
    mkRisk(`risk:${t.id}`, a.id, t, null, t.likelihood, impactOf(a), t.driver_ids);
  }
  for (const p of paths) {
    const drivers = [...new Set(p.hops.flatMap(h => h.threat_ids).flatMap(tid => threatById.get(tid)?.driver_ids || []))];
    mkRisk(`risk:${p.id}`, p.goal_asset_id, threatById.get(p.entry_threat_id)!, p.id, p.likelihood, p.impact, drivers);
    // A fix on the entry hop breaks the path (Phase 3 replaces this with a minimal cut set).
    const entryDrivers = threatById.get(p.entry_threat_id)!.driver_ids;
    for (const r of new Set(entryDrivers.map(d => driverToRem.get(d)).filter((x): x is string => !!x))) {
      remediations.get(r)!.breaks_paths += 1;
    }
  }
  risks.sort((a, b) => b.residual_score - a.residual_score || b.inherent_score - a.inherent_score || b.impact - a.impact);
  risks.forEach((r, i) => { r.priority = i + 1; });

  // ---- Framework tags (STRIDE / ATT&CK / kill chain from day one) ------------
  const tags: FrameworkTag[] = [];
  for (const t of threats) {
    for (const s of t.stride) tags.push({ object_type: 'threat', object_id: t.id, framework: 'stride', ref: s, rationale: t.rationale, rule_id: t.rule_id });
    for (const k of t.attack) tags.push({ object_type: 'threat', object_id: t.id, framework: 'attack', ref: k, rationale: t.rationale, rule_id: t.rule_id });
    tags.push({ object_type: 'threat', object_id: t.id, framework: 'killchain', ref: t.kill_chain, rationale: t.rationale, rule_id: t.rule_id });
  }
  for (const p of paths) {
    p.hops.forEach((h, i) => tags.push({
      object_type: 'path_hop', object_id: `${p.id}#${i}`, framework: 'killchain', ref: h.kill_chain,
      rationale: i === 0 ? 'Entry hop' : i === p.hops.length - 1 ? 'Goal hop' : 'Pivot hop', rule_id: 'PATH',
    }));
  }

  const quantumAssets = new Set(topo.crypto.filter(c => c.quantum_vulnerable).map(c => c.asset_id));
  return {
    tenant: src.tenant,
    ...topo,
    threats, paths, risks,
    remediations: [...remediations.values()].filter(r => r.risk_ids.length > 0),
    tags,
    stats: {
      overall_risk_score: overallRiskScore(risks.map(r => r.residual_score)),
      exposed_assets: topo.assets.filter(a => a.internet_exposed).length,
      quantum_exposed_assets: quantumAssets.size,
    },
  };
};
