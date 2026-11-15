// Per-tenant AGGREGATE metadata — everything a platform (super) admin may see about
// a tenant without that tenant's support-access grant: counts, risk score, licence /
// seat usage, last-seen and agent versions. Deliberately contains NO hostnames, IPs,
// hardware UUIDs, asset names/paths or algorithm rows. See middleware/auth.ts
// (SUPPORT ACCESS GATE) for where this is the mandated answer.

import pool from '../config/db';
import { listActiveGrants } from './supportAccess';

export interface TenantAggregate {
  tenantName: string;
  machineCount: number;
  onlineCount: number;          // seen in the last 24h
  assetCount: number;
  vulnerableCount: number;
  avgRiskScore: number;
  lastSeen: string | null;
  agentVersions: Record<string, number>;
  osCounts: Record<string, number>;
  /** Enrolled endpoints per licence key (seat usage). */
  seatsByLicense: Record<string, number>;
  supportAccess: { active: boolean; expiresAt: string | null };
}

const keyOf = (s?: string | null): string => (s || '').toLowerCase().replace(/[^a-z0-9]/g, '');

const TENANT_EXPR = `COALESCE(NULLIF(m.tenant_name, ''), NULLIF(t.tenant_name, ''), t.name, 'Default Fleet')`;

/** Fold raw GROUP BY rows into one aggregate per tenant. Pure — unit-tested. */
export const foldTenantAggregates = (
  rows: Array<Record<string, any>>,
  grants: Array<{ tenant_name: string; expires_at: string }> = [],
): TenantAggregate[] => {
  const byKey = new Map<string, TenantAggregate & { _riskSum: number; _riskN: number }>();
  for (const r of rows) {
    const k = keyOf(r.tenant_name);
    let a = byKey.get(k);
    if (!a) {
      a = {
        tenantName: String(r.tenant_name || 'Default Fleet'),
        machineCount: 0, onlineCount: 0, assetCount: 0, vulnerableCount: 0, avgRiskScore: 0,
        lastSeen: null, agentVersions: {}, osCounts: {}, seatsByLicense: {},
        supportAccess: { active: false, expiresAt: null },
        _riskSum: 0, _riskN: 0,
      };
      byKey.set(k, a);
    }
    const n = Number(r.machines) || 0;
    a.machineCount += n;
    a.onlineCount += Number(r.online) || 0;
    a.assetCount += Number(r.assets) || 0;
    a.vulnerableCount += Number(r.vulnerable) || 0;
    a._riskSum += Number(r.risk_sum) || 0;
    a._riskN += Number(r.risk_n) || 0;
    const seen = r.last_seen ? new Date(r.last_seen).toISOString() : null;
    if (seen && (!a.lastSeen || seen > a.lastSeen)) a.lastSeen = seen;
    const ver = String(r.agent_version || 'unknown');
    a.agentVersions[ver] = (a.agentVersions[ver] || 0) + n;
    const os = String(r.os || 'unknown');
    a.osCounts[os] = (a.osCounts[os] || 0) + n;
    const lic = String(r.license_key || '');
    if (lic) a.seatsByLicense[lic] = (a.seatsByLicense[lic] || 0) + n;
  }
  const grantByKey = new Map(grants.map(g => [keyOf(g.tenant_name), g]));
  // A tenant with a grant but no machines yet still shows up, so its window is visible.
  for (const [k, g] of grantByKey) {
    if (!byKey.has(k)) {
      byKey.set(k, {
        tenantName: g.tenant_name, machineCount: 0, onlineCount: 0, assetCount: 0, vulnerableCount: 0,
        avgRiskScore: 0, lastSeen: null, agentVersions: {}, osCounts: {}, seatsByLicense: {},
        supportAccess: { active: false, expiresAt: null }, _riskSum: 0, _riskN: 0,
      });
    }
  }
  return [...byKey.entries()].map(([k, a]) => {
    const { _riskSum, _riskN, ...out } = a;
    out.avgRiskScore = _riskN > 0 ? Math.round(_riskSum / _riskN) : 0;
    const g = grantByKey.get(k);
    if (g) out.supportAccess = { active: true, expiresAt: new Date(g.expires_at).toISOString() };
    return out;
  }).sort((x, y) => y.machineCount - x.machineCount || x.tenantName.localeCompare(y.tenantName));
};

/** Aggregates for every tenant, or just `tenant` (normalized match) when given. */
export async function getTenantAggregates(tenant?: string | null): Promise<TenantAggregate[]> {
  const r = await pool.query(`
    SELECT ${TENANT_EXPR} AS tenant_name,
           COALESCE(NULLIF(m.agent_version, ''), 'unknown') AS agent_version,
           COALESCE(NULLIF(m.os, ''), 'unknown') AS os,
           COALESCE(NULLIF(m.license_key, ''), NULLIF(t.license_key, ''), '') AS license_key,
           COUNT(*)::int AS machines,
           (COUNT(*) FILTER (WHERE m.last_seen > NOW() - INTERVAL '24 hours'))::int AS online,
           COALESCE(SUM(m.asset_count), 0)::int AS assets,
           COALESCE(SUM(m.vulnerable_count), 0)::int AS vulnerable,
           COALESCE(SUM(m.quantum_risk_score) FILTER (WHERE m.quantum_risk_score > 0), 0)::int AS risk_sum,
           (COUNT(*) FILTER (WHERE m.quantum_risk_score > 0))::int AS risk_n,
           MAX(m.last_seen) AS last_seen
      FROM fleet_machines m
      LEFT JOIN fleet_tokens t ON m.token_id = t.id
     GROUP BY 1, 2, 3, 4
  `);
  const all = foldTenantAggregates(r.rows, await listActiveGrants());
  const k = keyOf(tenant);
  return k ? all.filter(a => keyOf(a.tenantName) === k) : all;
}

/** Fleet-wide totals across a set of tenant aggregates. */
export const totalsOf = (tenants: TenantAggregate[]) => ({
  tenants: tenants.length,
  machines: tenants.reduce((s, t) => s + t.machineCount, 0),
  online: tenants.reduce((s, t) => s + t.onlineCount, 0),
  assets: tenants.reduce((s, t) => s + t.assetCount, 0),
  vulnerable: tenants.reduce((s, t) => s + t.vulnerableCount, 0),
});
