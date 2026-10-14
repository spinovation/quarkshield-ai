import { Request, Response } from 'express';
import pool from '../config/db';
import { isSuperRole, normTenant } from '../middleware/auth';
import { rebuildTenant, scheduleRebuild, scheduleRebuildForAllTenants } from '../lib/threatGraph/store';
import { feedStatus, syncThreatIntel } from '../lib/threatIntel/feeds';
import { RULE_CATALOG } from '../lib/threatGraph/rules';
import { ATTACK_TECHNIQUES, KILL_CHAIN, STRIDE_LABELS, THREAT_CATEGORY_LABELS } from '../lib/threatGraph/frameworkRef';
import { PURPOSE_LABELS } from '../lib/threatGraph/cryptoPurpose';
import { FRAMEWORKS, CONTROL_TITLES } from '../lib/threatGraph/controlMap';
import { RemediationStatus } from '../lib/threatGraph/types';

/**
 * Threat & Risk Graph API (Risk Assurance plan). Four MVP screens: Overview, Graph,
 * Threat Scenario, Asset Risk Detail — plus the remediation workflow, inferred-context
 * overrides, manual rebuild and rebuild history. All reads come from the tr_* tables
 * written by lib/threatGraph/store.ts; nothing here invents relationships.
 */

const resolveTenant = (req: Request): string => {
  if (isSuperRole(req.user?.role)) {
    return String(req.query.tenant || req.body?.tenantName || req.user?.tenant || '').trim();
  }
  return String(req.user?.tenant || '').trim();
};

const withTenant = (handler: (req: Request, res: Response, tenant: string, key: string) => Promise<void>) =>
  async (req: Request, res: Response): Promise<void> => {
    const tenant = resolveTenant(req);
    const key = normTenant(tenant);
    if (!key) { res.status(400).json({ error: 'Tenant is required (?tenant=…)' }); return; }
    try {
      await handler(req, res, tenant, key);
    } catch (e) {
      console.error('threat-graph error:', e);
      res.status(500).json({ error: 'Threat & Risk Graph request failed.' });
    }
  };

const data = <T = any>(rows: { data: T }[]): T[] => rows.map(r => r.data);

/** First view of a tenant builds the graph synchronously; afterwards rebuilds are event-driven. */
const ensureBuilt = async (tenant: string, key: string): Promise<void> => {
  const r = await pool.query(`SELECT 1 FROM tr_rebuild_runs WHERE tenant_key = $1 AND status = 'success' LIMIT 1`, [key]);
  if (!r.rowCount) await rebuildTenant(tenant, 'first_view');
};

const remState = async (key: string): Promise<Map<string, any>> => new Map(
  (await pool.query(
    `SELECT id, owner, TO_CHAR(target_date, 'YYYY-MM-DD') AS target_date, status, notes, updated_by, updated_at
       FROM tr_remediation_state WHERE tenant_key = $1`, [key],
  )).rows.map((r: any) => [r.id, r]),
);

/** Attach the residual risk (from the path's risk row) so paths read consistently with KPIs. */
const withResidual = async (key: string, paths: any[]): Promise<any[]> => {
  if (!paths.length) return paths;
  const r = await pool.query(
    `SELECT attack_path_id, residual_score, data->>'residual_level' AS residual_level
       FROM tr_risks WHERE tenant_key = $1 AND attack_path_id = ANY($2)`, [key, paths.map(p => p.id)]);
  const m = new Map(r.rows.map((x: any) => [x.attack_path_id, x]));
  return paths.map(p => {
    const x: any = m.get(p.id);
    return { ...p, residual_score: x?.residual_score ?? p.path_risk, residual_level: x?.residual_level ?? p.level };
  });
};

const assetNames = async (key: string, ids: string[]): Promise<Record<string, { name: string; type: string }>> => {
  if (!ids.length) return {};
  const r = await pool.query(`SELECT id, name, type FROM tr_assets WHERE tenant_key = $1 AND id = ANY($2)`, [key, [...new Set(ids)]]);
  return Object.fromEntries(r.rows.map((x: any) => [x.id, { name: x.name, type: x.type }]));
};

// ---------------------------------------------------------------------------
// 1. Threat & Risk Overview (scope-aware: entire environment, internet-facing, or a
//    Workstation Group; Compliance Projects / RMF systems join later)
// ---------------------------------------------------------------------------
const LEVEL_RANK: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const levelOfScore = (s: number) => (s >= 12 ? 'critical' : s >= 6 ? 'high' : s >= 3 ? 'medium' : 'low');

/** Aggregate remediation states into a scenario status. */
const scenarioStatus = (states: { status: string; target_date?: string | null }[]): string => {
  if (!states.length) return 'needs_attention';
  if (states.every(s => s.status === 'done' || s.status === 'verified')) return 'mitigated';
  if (states.every(s => s.status === 'risk_accepted' || s.status === 'done' || s.status === 'verified')) return 'risk_accepted';
  if (states.some(s => s.status === 'in_progress' || s.status === 'done' || s.status === 'verified')) return 'in_progress';
  if (states.some(s => s.target_date)) return 'planned';
  return 'needs_attention';
};

export const getThreatOverview = withTenant(async (req, res, tenant, key) => {
  await ensureBuilt(tenant, key);
  const q = async (sql: string, p: unknown[] = [key]) => (await pool.query(sql, p)).rows;
  const [assets, threats, risks, paths, rems, cryptoRows, runs, vulnRows, intelStatus] = await Promise.all([
    q(`SELECT data FROM tr_assets WHERE tenant_key = $1`).then(r => data<any>(r)),
    q(`SELECT data FROM tr_threats WHERE tenant_key = $1`).then(r => data<any>(r)),
    q(`SELECT data FROM tr_risks WHERE tenant_key = $1 ORDER BY priority`).then(r => data<any>(r)),
    q(`SELECT data FROM tr_attack_paths WHERE tenant_key = $1 ORDER BY path_risk DESC`).then(r => data<any>(r)),
    q(`SELECT data FROM tr_remediations WHERE tenant_key = $1`).then(r => data<any>(r)),
    q(`SELECT asset_id, data FROM tr_nodes WHERE tenant_key = $1 AND node_type = 'crypto'`),
    q(`SELECT finished_at, stats FROM tr_rebuild_runs WHERE tenant_key = $1 AND status = 'success' ORDER BY started_at DESC LIMIT 30`),
    q(`SELECT asset_id, data FROM tr_nodes WHERE tenant_key = $1 AND node_type = 'vuln'`),
    feedStatus().catch(() => null),
  ]);
  const vulnById = new Map(vulnRows.map((r: any) => [r.data.id, r.data]));
  /** KEV / EPSS signal across a set of driver ids. */
  const intelOf = (driverIds: string[]) => {
    const vs = driverIds.map(d => vulnById.get(d)).filter(Boolean) as any[];
    const epss = vs.map(v => v.epss).filter((x: any) => typeof x === 'number');
    return {
      kev: vs.some(v => v.kev), ransomware: vs.some(v => v.kev?.ransomware_use),
      epss_max: epss.length ? Math.max(...epss) : null,
      kev_cves: vs.filter(v => v.kev).map(v => v.cve),
    };
  };
  const state = await remState(key);
  const assetById = new Map(assets.map((a: any) => [a.id, a]));

  // ---- Scope ---------------------------------------------------------------
  const groups = [...new Set(assets.flatMap((a: any) => a.groups || []))].sort();
  const scopes = [
    { id: 'all', label: 'Entire environment' },
    { id: 'exposed', label: 'Internet-facing assets' },
    ...groups.map(g => ({ id: `group:${g}`, label: `Group: ${g}` })),
  ];
  const scopeId = String(req.query.scope || 'all');
  const scope = scopes.find(x => x.id === scopeId) || scopes[0];
  const inScopeAsset = (id: string): boolean => {
    if (scope.id === 'all') return true;
    const a: any = assetById.get(id);
    if (!a) return false;
    if (scope.id === 'exposed') return !!a.internet_exposed;
    return (a.groups || []).includes(scope.id.slice(6));
  };
  const pathById = new Map(paths.map((p: any) => [p.id, p]));
  const sPaths = paths.filter((p: any) => p.hops.some((h: any) => inScopeAsset(h.asset_id)));
  const sPathIds = new Set(sPaths.map((p: any) => p.id));
  const sRisks = risks.filter((r: any) => (r.attack_path_id ? sPathIds.has(r.attack_path_id) : inScopeAsset(r.asset_id)));
  const sThreatIds = new Set(sRisks.map((r: any) => r.threat_id));
  const sThreats = threats.filter((t: any) => inScopeAsset(t.asset_id) || sThreatIds.has(t.id));
  const sAssetIds = new Set<string>([
    ...assets.filter((a: any) => a.type !== 'network_segment' && inScopeAsset(a.id)).map((a: any) => a.id),
    ...sPaths.flatMap((p: any) => p.hops.map((h: any) => h.asset_id)),
  ]);
  const threatById = new Map(threats.map((t: any) => [t.id, t]));
  const remById = new Map(rems.map((m: any) => [m.id, m]));
  const remByTarget = new Map(rems.map((m: any) => [m.target_id, m.id]));

  // ---- KPIs ----------------------------------------------------------------
  const highCrit = sRisks.filter((r: any) => LEVEL_RANK[r.residual_level] >= 3).length;
  const inherentSum = sRisks.reduce((x: number, r: any) => x + r.inherent_score, 0);
  const residualSum = sRisks.reduce((x: number, r: any) => x + r.residual_score, 0);
  const openRisks = sRisks.filter((r: any) => r.residual_score >= 3);
  const affectedControls = [...new Set(openRisks.flatMap((r: any) => r.controls || []))].sort();
  const top10 = [...sRisks].sort((a: any, b: any) => b.residual_score - a.residual_score).slice(0, 10).map((r: any) => r.residual_score);
  const residualIndex = top10.length ? top10.reduce((x: number, y: number) => x + y, 0) / top10.length : 0;
  const prev = runs[1]?.stats;
  const quantumAssets = new Set(cryptoRows.filter((c: any) => c.data.quantum_vulnerable && sAssetIds.has(c.asset_id)).map((c: any) => c.asset_id));

  // ---- Risk by threat type ---------------------------------------------------
  const catCount = new Map<string, number>();
  for (const t of sThreats) catCount.set(t.category, (catCount.get(t.category) || 0) + 1);
  const riskByThreatType = [...catCount.entries()].sort((a, b) => b[1] - a[1]).map(([category, n]) => ({
    category, n, pct: sThreats.length ? Math.round((100 * n) / sThreats.length) : 0,
    label: THREAT_CATEGORY_LABELS[category as keyof typeof THREAT_CATEGORY_LABELS] || category,
  }));

  // ---- Compliance mapping (indicative: controls touched by open risks) -------
  const complianceMapping = FRAMEWORKS.map(f => {
    const ids = [...new Set(affectedControls.flatMap(c => f.map(c)))];
    return { framework: f.id, label: f.label, controls: ids, gaps: ids.length };
  }).filter(f => f.controls.length);

  // ---- Top threat scenarios (one row per threat, worst risk) ----------------
  const worstByThreat = new Map<string, any>();
  for (const r of sRisks) {
    const tid = r.threat_id;
    if (!worstByThreat.has(tid) || worstByThreat.get(tid).residual_score < r.residual_score) worstByThreat.set(tid, r);
  }
  const topScenarios = [...worstByThreat.entries()]
    .sort((a, b) => b[1].residual_score - a[1].residual_score || b[1].inherent_score - a[1].inherent_score)
    .slice(0, 8)
    .map(([tid, r], i) => {
      const t: any = threatById.get(tid);
      // Status reflects the fixes for THIS threat's own findings (not downstream path hops).
      // A CVE driver (vuln:<sbomId>:<cve>) is fixed by patching its component (cmp:<sbomId>).
      const own = (t?.driver_ids || [])
        .map((d: string) => remByTarget.get(d.startsWith('vuln:') ? `cmp:${d.slice(5, d.lastIndexOf(':'))}` : d))
        .filter(Boolean);
      const remIds = own.length ? [...new Set(own)] : [...new Set(sRisks.filter((x: any) => x.threat_id === tid).flatMap((x: any) => x.remediation_ids))];
      const goal = r.attack_path_id ? (assetById.get((pathById.get(r.attack_path_id) as any)?.goal_asset_id) as any)?.name : null;
      return {
        rank: i + 1, id: tid, title: t?.title, category: t?.category, asset_name: (assetById.get(t?.asset_id) as any)?.name,
        via_path_to: goal, likelihood: r.likelihood, impact: r.impact,
        score: r.residual_score, level: r.residual_level, inherent_score: r.inherent_score,
        controls: r.controls || [],
        status: scenarioStatus(remIds.map(id => state.get(id) || { status: 'open' })),
        intel: intelOf(t?.driver_ids || []),
      };
    });

  // ---- Recommended actions ---------------------------------------------------
  const remRisk = new Map<string, number>();
  for (const r of sRisks) for (const m of r.remediation_ids) remRisk.set(m, Math.max(remRisk.get(m) || 0, r.residual_score));
  const recommendedActions = [...remRisk.entries()]
    .map(([id, score]) => ({ m: remById.get(id) as any, score }))
    .filter(x => x.m)
    .sort((a, b) => b.score - a.score || b.m.breaks_paths - a.m.breaks_paths)
    .slice(0, 10)
    .map(({ m, score }) => {
      const st = state.get(m.id) || { status: 'open' };
      return {
        // A fix for a CISA KEV (exploited-in-the-wild) vulnerability is always P1.
        ...m, max_risk: score, priority: m.kev || score >= 12 ? 'P1' : score >= 6 ? 'P2' : 'P3',
        owner: st.owner || null, target_date: st.target_date || null, state: st,
        asset_name: (assetById.get(m.asset_id) as any)?.name,
      };
    });

  // ---- Heat map, crypto exposure, framework coverage, sources ---------------
  const heatCells = new Map<string, number>();
  for (const r of sRisks) { const k = `${r.likelihood}|${r.impact}`; heatCells.set(k, (heatCells.get(k) || 0) + 1); }
  const cryptoAgg = new Map<string, any>();
  for (const c of cryptoRows) {
    if (!sAssetIds.has(c.asset_id)) continue;
    const p = c.data.purpose;
    const e = cryptoAgg.get(p) || { purpose: p, total: 0, quantum_vulnerable: 0, hndl: 0, weak: 0 };
    e.total++; if (c.data.quantum_vulnerable) e.quantum_vulnerable++; if (c.data.hndl_relevant) e.hndl++; if (c.data.classically_weak) e.weak++;
    cryptoAgg.set(p, e);
  }
  const countRefs = (sel: (t: any) => string[]) => {
    const m = new Map<string, number>();
    for (const t of sThreats) for (const r of sel(t)) m.set(r, (m.get(r) || 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  };
  const names = Object.fromEntries(assets.map((a: any) => [a.id, { name: a.name, type: a.type }]));

  // Data lineage: which QuarkShield inputs this (scoped) model was built from.
  const nodeCounts = (await q(
    `SELECT node_type, asset_id, COUNT(*)::int AS n FROM tr_nodes WHERE tenant_key = $1 GROUP BY node_type, asset_id`))
    .filter((r: any) => sAssetIds.has(r.asset_id));
  const countNodes = (t: string) => nodeCounts.filter((r: any) => r.node_type === t).reduce((x: number, r: any) => x + r.n, 0);
  const countAssets = (tables: string[]) => [...sAssetIds].filter(id => tables.includes((assetById.get(id) as any)?.source_table)).length;
  const dataSources = [
    { id: 'fleet', label: 'Fleet agents', n: countAssets(['fleet_machines']), detail: 'Enrolled QuarkShield agents (endpoints and servers): host identity, OS, IP, Workstation Group. Feeds assets and the network-segment hypothesis (R6, R9).' },
    { id: 'sbom', label: 'SBOM components', n: countNodes('component'), detail: 'Software Bill of Materials from agents, CI and repo scans. Server packages reveal services and databases (R8); package versions are matched to CVEs.' },
    { id: 'cve', label: 'CVE matches', n: countNodes('vuln'), detail: 'Known vulnerabilities matched to SBOM component versions (CVSS, fixed version, CWE). Drives TR-01/02/03 threats and patch actions.' },
    { id: 'cbom', label: 'Crypto findings (CBOM)', n: countNodes('crypto'), detail: 'Keys, certificates, TLS key exchange, SSH and crypto configuration from agents, TLS probes, repos, PKI and proxies — classified by purpose for PQC/HNDL analysis (TR-04/05/06/07).' },
    { id: 'repos', label: 'Git repositories', n: countAssets(['git_scans']), detail: 'Latest Git/CI crypto scan per repository: committed keys and in-code crypto. Linked to hosts by SBOM fingerprint (R5).' },
    { id: 'pki', label: 'PKI / KMS connectors', n: countAssets(['pki_connectors']), detail: 'AWS KMS, Azure Key Vault, HashiCorp Vault, AD CS key and certificate inventory. Trust links to hosts (R4).' },
    { id: 'proxy', label: 'PQC proxies', n: countAssets(['pqc_proxies']), detail: 'Hybrid-PQC reverse proxies: the internet front door. Their upstreams become internet-reachable (R1, R7).' },
    {
      id: 'intel', label: 'KEV / EPSS matches',
      n: vulnRows.filter((r: any) => sAssetIds.has(r.asset_id) && (r.data.kev || r.data.epss !== null)).length,
      detail: `Exploitation intelligence matched to your CVEs: CISA Known Exploited Vulnerabilities (exploited in the wild, ransomware use, CISA due dates) and FIRST EPSS (probability of exploitation in the next 30 days). Adjusts likelihood only. `
        + (intelStatus?.lastSuccess?.kev ? `KEV synced ${new Date(intelStatus.lastSuccess.kev.finished_at).toLocaleDateString()} (${intelStatus.lastSuccess.kev.records} entries). ` : 'KEV not synced yet. ')
        + (intelStatus?.lastSuccess?.epss ? `EPSS synced ${new Date(intelStatus.lastSuccess.epss.finished_at).toLocaleDateString()} (${intelStatus.lastSuccess.epss.feed_version || ''}).` : 'EPSS not synced yet.'),
    },
    { id: 'probe', label: 'TLS endpoints', n: [...sAssetIds].filter(id => (assetById.get(id) as any)?.type === 'tls_endpoint').length, detail: 'Endpoints observed by agent TLS probes or proxy upstreams; public names are treated as internet-exposed (R3, R7).' },
  ];
  const topPaths = (await withResidual(key, sPaths.slice(0, 8)))
    .map((p: any) => ({ ...p, hops: p.hops.map((h: any) => ({ ...h, name: names[h.asset_id]?.name, type: names[h.asset_id]?.type })) }));

  res.json({
    tenant,
    scope, scopes,
    scopeAssetIds: scope.id === 'all' ? null : [...sAssetIds],
    lastBuiltAt: runs[0]?.finished_at || null,
    kpis: {
      threats: sThreats.length,
      threats_delta: scope.id === 'all' && prev ? (runs[0]?.stats?.threats ?? 0) - (prev.threats ?? 0) : null,
      high_critical: highCrit,
      risks_total: sRisks.length,
      high_critical_pct: sRisks.length ? Math.round((100 * highCrit) / sRisks.length) : 0,
      affected_controls: affectedControls.length,
      controls_framework: 'NIST SP 800-53 r5',
      residual_level: levelOfScore(residualIndex),
      residual_reduction_pct: inherentSum ? Math.round((100 * (inherentSum - residualSum)) / inherentSum) : 0,
      frameworks_mapped: complianceMapping.length,
      frameworks: complianceMapping.map(f => f.label),
      attack_paths: sPaths.length,
      exposed_assets: [...sAssetIds].filter(id => (assetById.get(id) as any)?.internet_exposed).length,
      quantum_exposed_assets: quantumAssets.size,
      assets: sAssetIds.size,
      overall_risk_score: scope.id === 'all' ? runs[0]?.stats?.overall_risk_score ?? 0 : Math.round((100 * residualIndex) / 16),
    },
    riskByThreatType,
    complianceMapping,
    affectedControls: affectedControls.map(c => ({ id: c, title: CONTROL_TITLES[c] })),
    topScenarios,
    heatPoints: topScenarios.slice(0, 5).map(s => ({ label: `T${s.rank}`, id: s.id, title: s.title, likelihood: s.likelihood, impact: s.impact, level: s.level })),
    heatMap: [...heatCells.entries()].map(([k, n]) => { const [l, i] = k.split('|').map(Number); return { likelihood: l, impact: i, n }; }),
    recommendedActions,
    attackPaths: topPaths,
    cryptoExposure: [...cryptoAgg.values()].sort((a, b) => b.quantum_vulnerable - a.quantum_vulnerable)
      .map(c => ({ ...c, label: PURPOSE_LABELS[c.purpose as keyof typeof PURPOSE_LABELS] || c.purpose })),
    stride: countRefs(t => t.stride).map(([ref, n]) => ({ ref, n, label: STRIDE_LABELS[ref as keyof typeof STRIDE_LABELS] })),
    attack: countRefs(t => t.attack).map(([ref, n]) => ({ ref, n, name: ATTACK_TECHNIQUES[ref]?.name, tactics: ATTACK_TECHNIQUES[ref]?.tactics })),
    trend: [...runs].reverse().map((t: any) => ({ at: t.finished_at, ...t.stats })),
    dataSources,
  });
});

// ---------------------------------------------------------------------------
// 2. Threat Graph (nodes + edges for the interactive view)
// ---------------------------------------------------------------------------
interface GNode { id: string; kind: string; label: string; subtype?: string; level?: string; exposed?: boolean; meta?: any }
interface GEdge { id: string; source: string; target: string; kind: string; confidence?: string; rule?: string }

export const getThreatGraph = withTenant(async (req, res, tenant, key) => {
  await ensureBuilt(tenant, key);
  const pathId = req.query.path ? String(req.query.path) : null;
  const focus = req.query.focus ? String(req.query.focus) : null;
  const depth = Math.min(3, Math.max(1, Number(req.query.depth) || 1));
  const nodes = new Map<string, GNode>();
  const edges = new Map<string, GEdge>();
  const addEdge = (e: GEdge) => edges.set(e.id, e);

  const riskByAsset = new Map<string, string>(
    (await pool.query(
      `SELECT asset_id, (ARRAY_AGG(data->>'residual_level' ORDER BY residual_score DESC))[1] AS level
         FROM tr_risks WHERE tenant_key = $1 GROUP BY asset_id`, [key])).rows.map((r: any) => [r.asset_id, r.level]),
  );
  const addAssets = async (ids: string[]) => {
    const missing = ids.filter(i => !nodes.has(i));
    if (!missing.length) return;
    const r = await pool.query(`SELECT data FROM tr_assets WHERE tenant_key = $1 AND id = ANY($2)`, [key, missing]);
    // Findings each asset carries, per data source (SBOM, CVE, CBOM, KEV/EPSS) — links the
    // "Data sources" strip to the boxes in the diagram.
    const f = await pool.query(
      `SELECT asset_id,
              COUNT(*) FILTER (WHERE node_type = 'component')::int AS components,
              COUNT(*) FILTER (WHERE node_type = 'vuln')::int AS vulns,
              COUNT(*) FILTER (WHERE node_type = 'crypto')::int AS crypto,
              COALESCE(JSONB_AGG(JSONB_BUILD_OBJECT('cve', data->>'cve', 'kev', (data->'kev') IS NOT NULL AND data->'kev' <> 'null'::jsonb,
                                                    'ransomware', COALESCE((data->'kev'->>'ransomware_use')::boolean, false),
                                                    'epss', data->'epss'))
                       FILTER (WHERE node_type = 'vuln' AND ((data->'kev') IS NOT NULL AND data->'kev' <> 'null'::jsonb OR data->'epss' <> 'null'::jsonb)), '[]'::jsonb) AS intel
         FROM tr_nodes WHERE tenant_key = $1 AND asset_id = ANY($2) GROUP BY asset_id`, [key, missing]);
    const findings = new Map(f.rows.map((x: any) => [x.asset_id, x]));
    for (const a of data<any>(r.rows)) {
      const fx: any = findings.get(a.id) || { components: 0, vulns: 0, crypto: 0, intel: [] };
      nodes.set(a.id, {
        id: a.id, kind: 'asset', subtype: a.type, label: a.name, exposed: a.internet_exposed,
        level: riskByAsset.get(a.id),
        // Lineage for hover explanations: where the asset came from and why it is typed/scored this way.
        meta: {
          criticality: a.criticality, classification: a.data_classification, source_table: a.source_table,
          inference: a.inference || [], groups: a.groups || [], context_origin: a.context_origin,
          findings: { components: fx.components, vulns: fx.vulns, crypto: fx.crypto, intel: fx.intel },
        },
      });
    }
  };

  if (pathId) {
    const r = await pool.query(`SELECT data FROM tr_attack_paths WHERE tenant_key = $1 AND id = $2`, [key, pathId]);
    const p: any = r.rows[0]?.data;
    if (!p) { res.status(404).json({ error: 'Attack path not found' }); return; }
    await addAssets(p.hops.map((h: any) => h.asset_id));
    const threatIds = [...new Set<string>(p.hops.flatMap((h: any) => h.threat_ids))];
    const threats = data<any>((await pool.query(`SELECT data FROM tr_threats WHERE tenant_key = $1 AND id = ANY($2)`, [key, threatIds])).rows);
    const entry = threats.find(t => t.id === p.entry_threat_id);
    nodes.set('actor', { id: 'actor', kind: 'actor', label: entry?.actor || 'Threat actor' });
    addEdge({ id: 'actor>entry', source: 'actor', target: p.hops[0].asset_id, kind: entry?.category || 'entry' });
    const driverIds = threats.flatMap(t => t.driver_ids).filter((d: string) => !d.startsWith('path:'));
    const drivers = (await pool.query(`SELECT id, node_type, data FROM tr_nodes WHERE tenant_key = $1 AND id = ANY($2)`, [key, driverIds])).rows;
    const onPath = new Set(p.hops.map((h: any) => h.asset_id));
    for (const d of drivers) {
      if (!onPath.has(d.data.asset_id)) continue;
      nodes.set(d.id, {
        id: d.id, kind: d.node_type, label: d.node_type === 'vuln' ? `${d.data.cve} (${d.data.cvss})` : `${d.data.algorithm}`,
        subtype: d.node_type === 'crypto' ? d.data.purpose : d.data.severity, meta: d.data,
      });
      addEdge({ id: `${d.data.asset_id}>${d.id}`, source: d.data.asset_id, target: d.id, kind: 'has_weakness' });
    }
    for (let i = 1; i < p.hops.length; i++) {
      const rel = p.hops[i].via
        ? (await pool.query(`SELECT data FROM tr_relationships WHERE tenant_key = $1 AND id = $2`, [key, p.hops[i].via])).rows[0]?.data
        : null;
      addEdge({
        id: p.hops[i].via || `hop${i}`, source: p.hops[i - 1].asset_id, target: p.hops[i].asset_id,
        kind: rel?.kind || 'path', confidence: rel?.confidence, rule: rel?.rule_id,
      });
    }
    const goal = p.hops[p.hops.length - 1].asset_id;
    nodes.set('impact', { id: 'impact', kind: 'impact', label: 'Data exfiltration / impact', level: p.level });
    addEdge({ id: 'goal>impact', source: goal, target: 'impact', kind: 'data_exfiltration' });
    const [pathWithResidual] = await withResidual(key, [p]);
    res.json({ mode: 'path', path: pathWithResidual, nodes: [...nodes.values()], edges: [...edges.values()] });
    return;
  }

  let rels: any[];
  if (focus) {
    let frontier = new Set([focus]);
    const seen = new Set([focus]);
    rels = [];
    for (let d = 0; d < depth; d++) {
      const r = data<any>((await pool.query(
        `SELECT data FROM tr_relationships WHERE tenant_key = $1 AND (from_asset = ANY($2) OR to_asset = ANY($2))`,
        [key, [...frontier]])).rows);
      frontier = new Set();
      for (const e of r) {
        rels.push(e);
        for (const x of [e.from_asset, e.to_asset]) if (!seen.has(x)) { seen.add(x); frontier.add(x); }
      }
    }
    await addAssets([...seen]);
  } else {
    // Overview graph: assets on an attack path or carrying a threat (or, with ?all=1, every
    // discovered asset for the architecture / data-flow views), and the edges among them.
    const ids = (await pool.query(
      req.query.all
        ? `SELECT id AS asset_id FROM tr_assets WHERE tenant_key = $1 AND type <> 'network_segment' ORDER BY criticality DESC LIMIT 300`
        : `SELECT DISTINCT asset_id FROM tr_threats WHERE tenant_key = $1
           UNION SELECT DISTINCT h->>'asset_id' FROM tr_attack_paths, jsonb_array_elements(data->'hops') h WHERE tenant_key = $1
           LIMIT 200`, [key])).rows.map((r: any) => r.asset_id);
    rels = data<any>((await pool.query(
      `SELECT data FROM tr_relationships WHERE tenant_key = $1 AND from_asset = ANY($2) AND to_asset = ANY($2)`, [key, ids])).rows);
    // Keep segment hubs only when they connect ≥2 displayed assets.
    const segs = data<any>((await pool.query(
      `SELECT data FROM tr_relationships WHERE tenant_key = $1 AND kind = 'network_adjacent' AND from_asset = ANY($2)`, [key, ids])).rows);
    const segCount = new Map<string, number>();
    for (const s of segs) segCount.set(s.to_asset, (segCount.get(s.to_asset) || 0) + 1);
    for (const s of segs) if ((segCount.get(s.to_asset) || 0) >= 2) rels.push(s);
    await addAssets([...ids, ...[...segCount.entries()].filter(([, n]) => n >= 2).map(([s]) => s)]);
  }
  for (const e of rels) {
    if (nodes.has(e.from_asset) && nodes.has(e.to_asset)) {
      addEdge({ id: e.id, source: e.from_asset, target: e.to_asset, kind: e.kind, confidence: e.confidence, rule: e.rule_id });
    }
  }
  // Threat actor node feeding every entry asset in view.
  const entries = (await pool.query(
    `SELECT DISTINCT data->'hops'->0->>'asset_id' AS a FROM tr_attack_paths WHERE tenant_key = $1`, [key])).rows.map((r: any) => r.a);
  const visibleEntries = entries.filter((a: string) => nodes.has(a));
  if (visibleEntries.length) {
    nodes.set('actor', { id: 'actor', kind: 'actor', label: 'Threat actors' });
    for (const a of visibleEntries) addEdge({ id: `actor>${a}`, source: 'actor', target: a, kind: 'entry' });
  }
  res.json({ mode: focus ? 'focus' : 'overview', nodes: [...nodes.values()], edges: [...edges.values()] });
});

export const getRelationshipEvidence = withTenant(async (req, res, _tenant, key) => {
  const r = await pool.query(
    `SELECT data, first_seen, last_seen FROM tr_relationships WHERE tenant_key = $1 AND id = $2`, [key, req.params.id]);
  if (!r.rowCount) { res.status(404).json({ error: 'Relationship not found' }); return; }
  const rel = r.rows[0].data;
  const names = await assetNames(key, [rel.from_asset, rel.to_asset]);
  res.json({ ...rel, from_name: names[rel.from_asset]?.name, to_name: names[rel.to_asset]?.name, first_seen: r.rows[0].first_seen, last_seen: r.rows[0].last_seen });
});

// ---------------------------------------------------------------------------
// 3. Threat Scenario
// ---------------------------------------------------------------------------
export const listThreatScenarios = withTenant(async (_req, res, tenant, key) => {
  await ensureBuilt(tenant, key);
  const r = await pool.query(
    `SELECT t.data, a.name AS asset_name, a.type AS asset_type,
            COALESCE(MAX(r.residual_score), 0)::int AS max_risk, COUNT(r.attack_path_id)::int AS paths
       FROM tr_threats t
       JOIN tr_assets a ON a.tenant_key = t.tenant_key AND a.id = t.asset_id
       -- Data-exfiltration (TR-08) threats are scored by the attack paths that reach their asset.
       LEFT JOIN tr_risks r ON r.tenant_key = t.tenant_key AND (
         (t.rule_id <> 'TR-08' AND r.threat_id = t.id) OR
         (t.rule_id = 'TR-08' AND r.asset_id = t.asset_id AND r.attack_path_id IS NOT NULL))
      WHERE t.tenant_key = $1 GROUP BY t.id, t.data, a.name, a.type ORDER BY max_risk DESC, paths DESC`, [key]);
  res.json(r.rows.map((x: any) => ({ ...x.data, asset_name: x.asset_name, asset_type: x.asset_type, max_risk: x.max_risk, paths: x.paths })));
});

export const getThreatScenario = withTenant(async (req, res, _tenant, key) => {
  const id = req.params.id;
  const t = (await pool.query(`SELECT data FROM tr_threats WHERE tenant_key = $1 AND id = $2`, [key, id])).rows[0]?.data;
  if (!t) { res.status(404).json({ error: 'Threat scenario not found' }); return; }
  const [asset] = data((await pool.query(`SELECT data FROM tr_assets WHERE tenant_key = $1 AND id = $2`, [key, t.asset_id])).rows);
  const drivers = data((await pool.query(`SELECT data FROM tr_nodes WHERE tenant_key = $1 AND id = ANY($2)`, [key, t.driver_ids])).rows);
  const risks = data<any>((await pool.query(
    t.rule_id === 'TR-08'
      ? `SELECT data FROM tr_risks WHERE tenant_key = $1 AND asset_id = $2 AND attack_path_id IS NOT NULL ORDER BY residual_score DESC`
      : `SELECT data FROM tr_risks WHERE tenant_key = $1 AND threat_id = $2 ORDER BY residual_score DESC`,
    [key, t.rule_id === 'TR-08' ? t.asset_id : id])).rows);
  const pathIds = [...new Set([...risks.map(r => r.attack_path_id), ...t.driver_ids.filter((d: string) => d.startsWith('path:'))].filter(Boolean))];
  const paths = await withResidual(key, data<any>((await pool.query(`SELECT data FROM tr_attack_paths WHERE tenant_key = $1 AND id = ANY($2) ORDER BY path_risk DESC`, [key, pathIds])).rows));
  const names = await assetNames(key, paths.flatMap(p => p.hops.map((h: any) => h.asset_id)));
  const remIds = [...new Set(risks.flatMap(r => r.remediation_ids))];
  const state = await remState(key);
  const rems = data<any>((await pool.query(`SELECT data FROM tr_remediations WHERE tenant_key = $1 AND id = ANY($2) ORDER BY breaks_paths DESC`, [key, remIds])).rows);
  const tags = (await pool.query(
    `SELECT framework, ref, rationale FROM tr_framework_tags WHERE tenant_key = $1 AND object_type = 'threat' AND object_id = $2`, [key, id])).rows;
  res.json({
    threat: { ...t, category_label: THREAT_CATEGORY_LABELS[t.category as keyof typeof THREAT_CATEGORY_LABELS] },
    asset, drivers, risks,
    paths: paths.map(p => ({ ...p, hops: p.hops.map((h: any) => ({ ...h, name: names[h.asset_id]?.name, type: names[h.asset_id]?.type })) })),
    remediations: rems.map(r => ({ ...r, state: state.get(r.id) || { status: 'open' } })),
    frameworks: {
      stride: tags.filter((x: any) => x.framework === 'stride').map((x: any) => ({ ref: x.ref, label: STRIDE_LABELS[x.ref as keyof typeof STRIDE_LABELS] })),
      attack: tags.filter((x: any) => x.framework === 'attack').map((x: any) => ({ ref: x.ref, ...ATTACK_TECHNIQUES[x.ref] })),
      killchain: tags.filter((x: any) => x.framework === 'killchain').map((x: any) => KILL_CHAIN.find(k => k.id === x.ref)),
      rationale: t.rationale,
    },
  });
});

// ---------------------------------------------------------------------------
// 4. Asset Risk Detail
// ---------------------------------------------------------------------------
export const listRiskAssets = withTenant(async (_req, res, tenant, key) => {
  await ensureBuilt(tenant, key);
  const r = await pool.query(
    `SELECT a.data, COALESCE(MAX(r.residual_score), 0)::int AS max_risk, COUNT(DISTINCT r.id)::int AS risks,
            (SELECT COUNT(*) FROM tr_nodes n WHERE n.tenant_key = a.tenant_key AND n.asset_id = a.id AND n.node_type = 'vuln')::int AS vulns,
            (SELECT COUNT(*) FROM tr_nodes n WHERE n.tenant_key = a.tenant_key AND n.asset_id = a.id AND n.node_type = 'crypto' AND (n.data->>'quantum_vulnerable')::boolean)::int AS quantum
       FROM tr_assets a LEFT JOIN tr_risks r ON r.tenant_key = a.tenant_key AND r.asset_id = a.id
      WHERE a.tenant_key = $1 AND a.type <> 'network_segment'
      GROUP BY a.tenant_key, a.id, a.data ORDER BY max_risk DESC, a.criticality DESC, a.name`, [key]);
  res.json(r.rows.map((x: any) => ({ ...x.data, max_risk: x.max_risk, risks: x.risks, vulns: x.vulns, quantum: x.quantum })));
});

export const getAssetRiskDetail = withTenant(async (req, res, _tenant, key) => {
  const id = req.params.id;
  const asset = (await pool.query(`SELECT data FROM tr_assets WHERE tenant_key = $1 AND id = $2`, [key, id])).rows[0]?.data;
  if (!asset) { res.status(404).json({ error: 'Asset not found' }); return; }
  const nodes = (await pool.query(`SELECT node_type, data FROM tr_nodes WHERE tenant_key = $1 AND asset_id = $2`, [key, id])).rows;
  const vulnsByComp = new Map<string, any[]>();
  for (const n of nodes) if (n.node_type === 'vuln') {
    const l = vulnsByComp.get(n.data.component_id) || []; l.push(n.data); vulnsByComp.set(n.data.component_id, l);
  }
  const components = nodes.filter((n: any) => n.node_type === 'component')
    .map((n: any) => ({ ...n.data, vulnerabilities: (vulnsByComp.get(n.data.id) || []).sort((a, b) => b.cvss - a.cvss) }))
    .sort((a: any, b: any) => (b.vulnerabilities[0]?.cvss || 0) - (a.vulnerabilities[0]?.cvss || 0));
  const cryptoFindings = nodes.filter((n: any) => n.node_type === 'crypto').map((n: any) => ({ ...n.data, purpose_label: PURPOSE_LABELS[n.data.purpose as keyof typeof PURPOSE_LABELS] }));
  const rels = data<any>((await pool.query(
    `SELECT data FROM tr_relationships WHERE tenant_key = $1 AND (from_asset = $2 OR to_asset = $2)`, [key, id])).rows);
  const threats = data<any>((await pool.query(`SELECT data FROM tr_threats WHERE tenant_key = $1 AND asset_id = $2`, [key, id])).rows);
  const paths = await withResidual(key, data<any>((await pool.query(
    `SELECT data FROM tr_attack_paths WHERE tenant_key = $1 AND data->'hops' @> $2::jsonb ORDER BY path_risk DESC LIMIT 25`,
    [key, JSON.stringify([{ asset_id: id }])])).rows));
  const risks = data<any>((await pool.query(`SELECT data FROM tr_risks WHERE tenant_key = $1 AND asset_id = $2 ORDER BY residual_score DESC`, [key, id])).rows);
  const remIds = [...new Set(risks.flatMap(r => r.remediation_ids))];
  const state = await remState(key);
  const rems = data<any>((await pool.query(
    `SELECT data FROM tr_remediations WHERE tenant_key = $1 AND (asset_id = $2 OR id = ANY($3)) ORDER BY breaks_paths DESC`, [key, id, remIds])).rows);
  const names = await assetNames(key, [...rels.flatMap(r => [r.from_asset, r.to_asset]), ...paths.flatMap(p => p.hops.map((h: any) => h.asset_id))]);
  const override = (await pool.query(`SELECT criticality, data_classification, environment, updated_by, updated_at FROM tr_context_overrides WHERE tenant_key = $1 AND asset_id = $2`, [key, id])).rows[0] || null;
  res.json({
    asset, override, components, crypto: cryptoFindings,
    relationships: rels.map(r => ({ ...r, direction: r.from_asset === id ? 'out' : 'in', peer_id: r.from_asset === id ? r.to_asset : r.from_asset, peer_name: names[r.from_asset === id ? r.to_asset : r.from_asset]?.name })),
    threats: threats.map(t => ({ ...t, category_label: THREAT_CATEGORY_LABELS[t.category as keyof typeof THREAT_CATEGORY_LABELS] })),
    paths: paths.map(p => ({ ...p, hops: p.hops.map((h: any) => ({ ...h, name: names[h.asset_id]?.name, type: names[h.asset_id]?.type })) })),
    risks,
    remediations: rems.map(r => ({ ...r, state: state.get(r.id) || { status: 'open' } })),
  });
});

// ---------------------------------------------------------------------------
// Remediation workflow, inferred-context overrides, rebuild, history, catalog
// ---------------------------------------------------------------------------
const STATUSES: RemediationStatus[] = ['open', 'in_progress', 'done', 'verified', 'risk_accepted'];

export const updateRemediation = withTenant(async (req, res, tenant, key) => {
  const id = req.params.id;
  const exists = await pool.query(`SELECT 1 FROM tr_remediations WHERE tenant_key = $1 AND id = $2`, [key, id]);
  if (!exists.rowCount) { res.status(404).json({ error: 'Remediation not found' }); return; }
  const { status, owner, target_date, notes } = req.body || {};
  if (status !== undefined && !STATUSES.includes(status)) { res.status(400).json({ error: `status must be one of ${STATUSES.join(', ')}` }); return; }
  if (target_date && !/^\d{4}-\d{2}-\d{2}$/.test(String(target_date))) { res.status(400).json({ error: 'target_date must be YYYY-MM-DD' }); return; }
  await pool.query(
    `INSERT INTO tr_remediation_state (tenant_key, id, owner, target_date, status, notes, updated_by, updated_at)
     VALUES ($1, $2, $3, $4, COALESCE($5, 'open'), $6, $7, NOW())
     ON CONFLICT (tenant_key, id) DO UPDATE SET
       owner = COALESCE($3, tr_remediation_state.owner),
       target_date = COALESCE($4, tr_remediation_state.target_date),
       status = COALESCE($5, tr_remediation_state.status),
       notes = COALESCE($6, tr_remediation_state.notes),
       updated_by = $7, updated_at = NOW()`,
    [key, id, owner ?? null, target_date || null, status ?? null, notes ?? null, req.user?.email || 'unknown'],
  );
  // Residual risk depends on remediation state: recompute now.
  const stats = await rebuildTenant(tenant, 'remediation_update');
  res.json({ success: true, stats });
});

const CLASSES = ['public', 'internal', 'sensitive', 'cui'];

export const overrideAssetContext = withTenant(async (req, res, tenant, key) => {
  const id = req.params.id;
  const exists = await pool.query(`SELECT 1 FROM tr_assets WHERE tenant_key = $1 AND id = $2`, [key, id]);
  if (!exists.rowCount) { res.status(404).json({ error: 'Asset not found' }); return; }
  const { criticality, data_classification, environment, clear } = req.body || {};
  if (clear) {
    await pool.query(`DELETE FROM tr_context_overrides WHERE tenant_key = $1 AND asset_id = $2`, [key, id]);
  } else {
    const crit = criticality === undefined || criticality === null ? null : Number(criticality);
    if (crit !== null && !(crit >= 1 && crit <= 4)) { res.status(400).json({ error: 'criticality must be 1–4' }); return; }
    if (data_classification && !CLASSES.includes(data_classification)) { res.status(400).json({ error: `data_classification must be one of ${CLASSES.join(', ')}` }); return; }
    await pool.query(
      `INSERT INTO tr_context_overrides (tenant_key, asset_id, criticality, data_classification, environment, updated_by, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW())
       ON CONFLICT (tenant_key, asset_id) DO UPDATE SET criticality = $3, data_classification = $4, environment = $5, updated_by = $6, updated_at = NOW()`,
      [key, id, crit, data_classification || null, environment || null, req.user?.email || 'unknown'],
    );
  }
  const stats = await rebuildTenant(tenant, 'context_override');
  res.json({ success: true, stats });
});

export const rebuildThreatGraph = withTenant(async (_req, res, tenant) => {
  res.json({ success: true, stats: await rebuildTenant(tenant, 'manual') });
});

export const listRebuildRuns = withTenant(async (_req, res, _tenant, key) => {
  const r = await pool.query(
    `SELECT id, trigger, status, stats, error, started_at, finished_at FROM tr_rebuild_runs WHERE tenant_key = $1 ORDER BY started_at DESC LIMIT 50`, [key]);
  res.json(r.rows);
});

export const getThreatGraphCatalog = (_req: Request, res: Response): void => {
  res.json({
    rules: RULE_CATALOG,
    inference: [
      { id: 'R1', summary: 'PQC proxy upstream URL → enrolled host / TLS endpoint', kind: 'connects_to', confidence: 'high' },
      { id: 'R2', summary: 'Certificate DNS names on a host ↔ probed/upstream endpoint', kind: 'serves', confidence: 'medium–high' },
      { id: 'R3', summary: 'Agent TLS probe: host connected to target', kind: 'connects_to', confidence: 'medium' },
      { id: 'R4', summary: 'Host certificates reference a PKI/KMS-managed asset', kind: 'trusts', confidence: 'medium' },
      { id: 'R5', summary: 'Repository ↔ host SBOM fingerprint overlap', kind: 'deployed_from', confidence: 'medium / low' },
      { id: 'R6', summary: 'Same Workstation Group or egress IP (lateral-movement hypothesis)', kind: 'network_adjacent', confidence: 'low' },
      { id: 'R7', summary: 'Internet exposure: public endpoint or reverse proxy', kind: 'asset flag', confidence: 'high' },
      { id: 'R8', summary: 'Server packages (PostgreSQL, nginx, sshd …) in a host SBOM', kind: 'runs', confidence: 'high' },
    ],
    stride: STRIDE_LABELS,
    attack: ATTACK_TECHNIQUES,
    killChain: KILL_CHAIN,
    categories: THREAT_CATEGORY_LABELS,
    attribution: 'MITRE ATT&CK® techniques are potential techniques derived from discovered exposures, not observed activity. © The MITRE Corporation.',
  });
};

export { scheduleRebuild };

// ---------------------------------------------------------------------------
// Exploitation-likelihood intelligence (CISA KEV, FIRST EPSS)
// ---------------------------------------------------------------------------
export const getThreatIntelStatus = async (_req: Request, res: Response): Promise<void> => {
  try {
    const st = await feedStatus();
    const counts = (await pool.query(`SELECT (SELECT COUNT(*) FROM ti_kev)::int AS kev, (SELECT COUNT(*) FROM ti_kev WHERE ransomware_use)::int AS kev_ransomware, (SELECT COUNT(*) FROM ti_epss)::int AS epss`)).rows[0];
    res.json({ ...st, counts });
  } catch (e) {
    res.status(500).json({ error: (e as Error).message });
  }
};

/** Super-admin: sync KEV + EPSS now, then re-score every tenant graph. */
export const syncThreatIntelNow = async (_req: Request, res: Response): Promise<void> => {
  const results = await syncThreatIntel();
  const tenants = results.some(r => r.status === 'success') ? await scheduleRebuildForAllTenants('threat_intel_sync') : 0;
  res.json({ results, tenantsRescheduled: tenants });
};
