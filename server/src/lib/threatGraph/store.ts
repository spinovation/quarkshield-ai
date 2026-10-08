/**
 * Threat & Risk Graph persistence: load SourceData from the existing tables, run the
 * pure engine, and atomically replace the tenant's derived tr_* rows. Rebuilds are
 * debounced per tenant so a burst of agent ingests triggers one recompute, and every
 * run is recorded in tr_rebuild_runs (the Continuous Monitoring time series).
 */
import crypto from 'crypto';
import { PoolClient } from 'pg';
import pool from '../../config/db';
import { normTenant, getTenantEntitlement } from '../../middleware/auth';
import { buildThreatGraph } from './engine';
import { GraphResult, RemediationState, SourceData, ContextOverride } from './types';

const T = `LOWER(REGEXP_REPLACE(COALESCE(tenant_name,''), '[^a-zA-Z0-9]', '', 'g')) = $1`;

export const loadSource = async (tenant: string): Promise<SourceData> => {
  const key = normTenant(tenant);
  const q = async <R>(sql: string, params: unknown[] = [key]): Promise<R[]> => (await pool.query(sql, params)).rows as R[];
  const [machines, cryptoFindings, components, gitScans, pkiConnectors, pkiAssets, proxies, overrides] = await Promise.all([
    q<SourceData['machines'][number]>(`SELECT id, hostname, computer_name, os, ip, public_ip, group_name FROM fleet_machines WHERE ${T}`),
    q<SourceData['cryptoFindings'][number]>(
      `SELECT id, machine_id, type, name, algorithm, key_size, hash_algorithm, is_vulnerable, risk_level,
              description, recommendation, explainer, path, source, source_ref
         FROM assets
        WHERE ${T} OR machine_id IN (SELECT id FROM fleet_machines WHERE ${T})`),
    q<SourceData['components'][number]>(
      `SELECT id, source, source_ref, file_path, name, version, ecosystem, purl, COALESCE(vulnerabilities, '[]'::jsonb) AS vulnerabilities
         FROM sbom_components WHERE ${T}`),
    q<SourceData['gitScans'][number]>(
      `SELECT DISTINCT ON (repo_url) id, repo_url, repo_name, branch, COALESCE(findings, '[]'::jsonb) AS findings
         FROM git_scans WHERE ${T} ORDER BY repo_url, created_at DESC`),
    q<SourceData['pkiConnectors'][number]>(`SELECT id, name, provider, endpoint_url FROM pki_connectors WHERE ${T}`),
    q<SourceData['pkiAssets'][number]>(
      `SELECT id, connector_id, asset_name, asset_type, algorithm, key_size, is_vulnerable, risk_level, raw_metadata
         FROM pki_synced_assets WHERE ${T}`),
    q<SourceData['proxies'][number]>(`SELECT id, name, listen_port, upstream_url, tls_curve, status FROM pqc_proxies WHERE ${T}`),
    q<ContextOverride>(`SELECT asset_id, criticality, data_classification, environment FROM tr_context_overrides WHERE tenant_key = $1`),
  ]);
  return { tenant, machines, cryptoFindings, components, gitScans, pkiConnectors, pkiAssets, proxies, overrides };
};

export const loadRemediationState = async (tenantKey: string): Promise<RemediationState[]> =>
  (await pool.query(
    `SELECT id, owner, TO_CHAR(target_date, 'YYYY-MM-DD') AS target_date, status FROM tr_remediation_state WHERE tenant_key = $1`,
    [tenantKey],
  )).rows;

/** Bulk insert rows via jsonb_to_recordset (one round-trip per table). */
const bulk = async (db: PoolClient, table: string, cols: Record<string, string>, rows: Record<string, unknown>[], onConflict = ''): Promise<void> => {
  const CHUNK = 2000;
  const names = Object.keys(cols);
  const defs = names.map(n => `${n} ${cols[n]}`).join(', ');
  for (let i = 0; i < rows.length; i += CHUNK) {
    await db.query(
      `INSERT INTO ${table} (${names.join(', ')}) SELECT ${names.join(', ')} FROM jsonb_to_recordset($1::jsonb) AS x(${defs}) ${onConflict}`,
      [JSON.stringify(rows.slice(i, i + CHUNK))],
    );
  }
};

const persist = async (tenantKey: string, g: GraphResult): Promise<void> => {
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    // Preserve first_seen for relationships that are re-observed.
    const prevSeen = new Map<string, string>(
      (await db.query('SELECT id, first_seen FROM tr_relationships WHERE tenant_key = $1', [tenantKey])).rows
        .map((r: any) => [r.id, new Date(r.first_seen).toISOString()]),
    );
    for (const t of ['tr_assets', 'tr_relationships', 'tr_nodes', 'tr_threats', 'tr_attack_paths', 'tr_risks', 'tr_remediations', 'tr_framework_tags']) {
      await db.query(`DELETE FROM ${t} WHERE tenant_key = $1`, [tenantKey]);
    }
    // Rule-derived risk → control links are recomputed; assessor-made links are kept.
    await db.query(`DELETE FROM tr_risk_controls WHERE tenant_key = $1 AND origin = 'rule'`, [tenantKey]);
    const tk = { tenant_key: tenantKey };
    await bulk(db, 'tr_assets', {
      tenant_key: 'text', id: 'text', type: 'text', name: 'text', environment: 'text', criticality: 'smallint',
      data_classification: 'text', internet_exposed: 'boolean', context_origin: 'text', source_table: 'text', source_id: 'text', data: 'jsonb',
    }, g.assets.map(a => ({ ...tk, ...a, data: a })));
    const now = new Date().toISOString();
    await bulk(db, 'tr_relationships', {
      tenant_key: 'text', id: 'text', from_asset: 'text', to_asset: 'text', kind: 'text', confidence: 'text', rule_id: 'text',
      data: 'jsonb', first_seen: 'timestamptz', last_seen: 'timestamptz',
    }, g.relationships.map(r => ({ ...tk, ...r, data: r, first_seen: prevSeen.get(r.id) || now, last_seen: now })));
    await bulk(db, 'tr_nodes', { tenant_key: 'text', id: 'text', node_type: 'text', asset_id: 'text', data: 'jsonb' }, [
      ...g.components.map(c => ({ ...tk, id: c.id, node_type: 'component', asset_id: c.asset_id, data: c })),
      ...g.vulns.map(v => ({ ...tk, id: v.id, node_type: 'vuln', asset_id: v.asset_id, data: v })),
      ...g.crypto.map(c => ({ ...tk, id: c.id, node_type: 'crypto', asset_id: c.asset_id, data: c })),
    ]);
    await bulk(db, 'tr_threats', {
      tenant_key: 'text', id: 'text', rule_id: 'text', category: 'text', asset_id: 'text', likelihood: 'smallint', data: 'jsonb',
    }, g.threats.map(t => ({ ...tk, ...t, data: t })));
    await bulk(db, 'tr_attack_paths', {
      tenant_key: 'text', id: 'text', entry_threat_id: 'text', goal_asset_id: 'text', path_risk: 'smallint', level: 'text', data: 'jsonb',
    }, g.paths.map(p => ({ ...tk, ...p, data: p })));
    await bulk(db, 'tr_risks', {
      tenant_key: 'text', id: 'text', asset_id: 'text', threat_id: 'text', attack_path_id: 'text', likelihood: 'smallint',
      impact: 'smallint', inherent_score: 'smallint', residual_score: 'smallint', level: 'text', priority: 'integer', data: 'jsonb',
    }, g.risks.map(r => ({ ...tk, ...r, data: r })));
    await bulk(db, 'tr_remediations', {
      tenant_key: 'text', id: 'text', action_type: 'text', asset_id: 'text', breaks_paths: 'integer', data: 'jsonb',
    }, g.remediations.map(r => ({ ...tk, ...r, data: r })));
    await bulk(db, 'tr_risk_controls', { tenant_key: 'text', risk_id: 'text', control_ref: 'text', origin: 'text' },
      g.risks.flatMap(r => r.controls.map(c => ({ ...tk, risk_id: r.id, control_ref: c, origin: 'rule' }))), 'ON CONFLICT DO NOTHING');
    const seenTag = new Set<string>();
    await bulk(db, 'tr_framework_tags', {
      tenant_key: 'text', object_type: 'text', object_id: 'text', framework: 'text', ref: 'text', rule_id: 'text', rationale: 'text',
    }, g.tags.filter(t => {
      const k = `${t.object_type}|${t.object_id}|${t.framework}|${t.ref}`;
      if (seenTag.has(k)) return false;
      seenTag.add(k); return true;
    }).map(t => ({ ...tk, ...t })));
    await db.query('COMMIT');
  } catch (e) {
    await db.query('ROLLBACK');
    throw e;
  } finally {
    db.release();
  }
};

export interface RebuildStats {
  assets: number; relationships: number; threats: number; attack_paths: number; risks: number;
  critical_risks: number; high_risks: number; remediations: number; overall_risk_score: number;
  exposed_assets: number; quantum_exposed_assets: number; duration_ms: number;
}

const inFlight = new Map<string, Promise<RebuildStats>>();

/** Recompute the tenant's graph now. Concurrent calls for the same tenant share one run. */
export const rebuildTenant = (tenant: string, trigger = 'manual'): Promise<RebuildStats> => {
  const key = normTenant(tenant);
  const running = inFlight.get(key);
  if (running) return running;
  const run = (async () => {
    const runId = `trr-${crypto.randomUUID()}`;
    const started = Date.now();
    await pool.query(
      `INSERT INTO tr_rebuild_runs (id, tenant_key, tenant_name, trigger, status) VALUES ($1, $2, $3, $4, 'running')`,
      [runId, key, tenant, trigger],
    );
    try {
      const [src, state] = await Promise.all([loadSource(tenant), loadRemediationState(key)]);
      const g = buildThreatGraph(src, state);
      await persist(key, g);
      const stats: RebuildStats = {
        assets: g.assets.length, relationships: g.relationships.length, threats: g.threats.length,
        attack_paths: g.paths.length, risks: g.risks.length,
        critical_risks: g.risks.filter(r => r.residual_level === 'critical').length,
        high_risks: g.risks.filter(r => r.residual_level === 'high').length,
        remediations: g.remediations.length, ...g.stats, duration_ms: Date.now() - started,
      };
      await pool.query(
        `UPDATE tr_rebuild_runs SET status = 'success', stats = $2, finished_at = NOW() WHERE id = $1`,
        [runId, JSON.stringify(stats)],
      );
      return stats;
    } catch (e) {
      await pool.query(
        `UPDATE tr_rebuild_runs SET status = 'error', error = $2, finished_at = NOW() WHERE id = $1`,
        [runId, (e as Error).message],
      ).catch(() => undefined);
      throw e;
    } finally {
      inFlight.delete(key);
    }
  })();
  inFlight.set(key, run);
  return run;
};

const DEBOUNCE_MS = Number(process.env.TR_REBUILD_DEBOUNCE_MS || 20000);
const timers = new Map<string, NodeJS.Timeout>();

/**
 * Fire-and-forget rebuild after new data lands (agent ingest, git scan, PKI sync,
 * proxy change), only for tenants on the Risk Assurance plan. Never throws into the
 * caller's request path.
 */
export const scheduleRebuild = (tenant: string | null | undefined, trigger: string): void => {
  if (!tenant) return;
  const key = normTenant(tenant);
  if (!key) return;
  const prev = timers.get(key);
  if (prev) clearTimeout(prev);
  const timer = setTimeout(async () => {
    timers.delete(key);
    try {
      if (!(await getTenantEntitlement(tenant)).riskAssurance) return;
      await rebuildTenant(tenant, trigger);
    } catch (e) {
      console.warn(`threat-graph rebuild failed for ${tenant}:`, (e as Error).message);
    }
  }, DEBOUNCE_MS);
  timer.unref?.();
  timers.set(key, timer);
};
