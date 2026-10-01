import { Request, Response } from 'express';
import crypto from 'crypto';
import pool from '../config/db';
import { resolveWriteTenant, canAccessTenant } from '../middleware/auth';
import { buildSSP, buildPOAM, ProjectRecord, ControlRow, Posture } from '../lib/oscal';
import {
  FRAMEWORKS, isFramework, controlsForFramework, autoStatus, CRYPTO_CONTROLS, Framework, ControlStatus,
} from '../lib/controlCatalog';

/**
 * Projects (BILL-4 / BILL-4b). A Project is an authorization boundary assessed against a
 * NIST framework (800-53 r5 / 800-171 r2 / r3). On creation we seed its crypto controls
 * from the catalog with a CBOM-derived status; the assessor edits status/owner/%/target,
 * and the SSP/POA&M are generated from those control rows.
 */

const cleanArr = (v: any): string[] | null => {
  if (!Array.isArray(v)) return null;
  const a = v.map(x => String(x).trim()).filter(Boolean);
  return a.length ? a : null;
};

const STATUSES: ControlStatus[] = ['compliant', 'non_compliant', 'in_progress', 'not_applicable'];

// Catalog lookups by stable 800-53 key (for fips/kind at read/export time).
const catalogByKey = new Map(CRYPTO_CONTROLS.map(c => [c.key, c]));

const scopeClause = () =>
  `(LOWER(tenant_name) = LOWER($1) OR LOWER(REPLACE(tenant_name,' ','')) = LOWER(REPLACE($1,' ','')))
   AND ($2::text[] IS NULL OR machine_id = ANY($2::text[]))
   AND ($3::text[] IS NULL OR source = ANY($3::text[]))`;

const computePosture = async (project: any): Promise<Posture> => {
  const machineIds = project.scope_machine_ids?.length ? project.scope_machine_ids : null;
  const sources = project.scope_sources?.length ? project.scope_sources : null;
  const totals = await pool.query(
    `SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE is_vulnerable)::int AS vulnerable
     FROM assets WHERE ${scopeClause()}`,
    [project.tenant_name, machineIds, sources]
  );
  const byAlgo = await pool.query(
    `SELECT UPPER(COALESCE(algorithm,'UNKNOWN')) AS algo, COUNT(*)::int AS count,
            COUNT(*) FILTER (WHERE is_vulnerable)::int AS vulnerable
     FROM assets WHERE ${scopeClause()} GROUP BY 1 ORDER BY count DESC LIMIT 50`,
    [project.tenant_name, machineIds, sources]
  );
  return {
    total: totals.rows[0]?.total || 0,
    vulnerable: totals.rows[0]?.vulnerable || 0,
    byAlgo: byAlgo.rows,
  };
};

// ---- Catalog / frameworks (for the UI) ----
export const getFrameworks = async (_req: Request, res: Response) => {
  res.json({
    frameworks: FRAMEWORKS,
    controls: CRYPTO_CONTROLS.map(c => ({ key: c.key, title: c.title, kind: c.kind, ids: c.ids, fips: c.fips })),
    statuses: STATUSES,
  });
};

// ---- Projects CRUD ----
export const listProjects = async (req: Request, res: Response) => {
  try {
    const tenant = resolveWriteTenant(req, (req.query.tenant as string) || null);
    const r = await pool.query(
      `SELECT p.id, p.tenant_name AS "tenantName", p.name, p.description, p.framework,
              p.system_id AS "systemId", p.impact_level AS "impactLevel",
              p.scope_machine_ids AS "scopeMachineIds", p.scope_sources AS "scopeSources",
              p.created_at AS "createdAt",
              (SELECT COUNT(*)::int FROM project_controls c WHERE c.project_id = p.id) AS "controlCount",
              (SELECT COUNT(*)::int FROM project_controls c WHERE c.project_id = p.id AND c.status = 'compliant') AS "compliantCount"
       FROM projects p
       WHERE LOWER(p.tenant_name) = LOWER($1) OR LOWER(REPLACE(p.tenant_name,' ','')) = LOWER(REPLACE($1,' ',''))
       ORDER BY p.created_at DESC`,
      [tenant]
    );
    res.json(r.rows);
  } catch (e: any) {
    res.status(500).json({ error: e.message || 'Failed to list projects' });
  }
};

export const createProject = async (req: Request, res: Response) => {
  const db = await pool.connect();
  try {
    const tenant = resolveWriteTenant(req, req.body.tenantName || null);
    if (!tenant) return res.status(400).json({ error: 'Tenant could not be resolved' });
    const name = (req.body.name || '').toString().trim();
    if (!name) return res.status(400).json({ error: 'Project name is required' });
    const framework: Framework = isFramework(req.body.framework) ? req.body.framework : 'nist-800-53r5';
    const impact = ['low', 'moderate', 'high'].includes((req.body.impactLevel || '').toLowerCase())
      ? (req.body.impactLevel as string).toLowerCase() : 'moderate';
    const id = 'proj-' + crypto.randomBytes(8).toString('hex');
    const machineIds = cleanArr(req.body.scopeMachineIds);
    const sources = cleanArr(req.body.scopeSources);

    await db.query('BEGIN');
    await db.query(
      `INSERT INTO projects (id, tenant_name, name, description, framework, system_id, impact_level, scope_machine_ids, scope_sources)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [id, tenant, name, (req.body.description || '').toString() || null, framework,
       (req.body.systemId || '').toString() || null, impact, machineIds, sources]
    );

    // Seed controls with CBOM-derived auto status.
    const posture = await computePosture({ tenant_name: tenant, scope_machine_ids: machineIds, scope_sources: sources });
    for (const c of controlsForFramework(framework)) {
      const st = autoStatus(c, posture);
      await db.query(
        `INSERT INTO project_controls (id, project_id, control_key, control_id, title, kind, status, auto_status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        ['pc-' + crypto.randomBytes(8).toString('hex'), id, c.key, c.controlId, c.title, c.kind, st, st]
      );
    }
    await db.query('COMMIT');
    res.status(201).json({ id, name, framework, impactLevel: impact });
  } catch (e: any) {
    await db.query('ROLLBACK');
    res.status(500).json({ error: e.message || 'Failed to create project' });
  } finally {
    db.release();
  }
};

const fetchProject = async (id: string) => {
  const r = await pool.query('SELECT * FROM projects WHERE id = $1', [id]);
  return r.rows[0] || null;
};

export const deleteProject = async (req: Request, res: Response) => {
  try {
    const p = await fetchProject(req.params.id);
    if (!p) return res.status(404).json({ error: 'Project not found' });
    if (!canAccessTenant(req, p.tenant_name)) return res.status(403).json({ error: 'Access to this project is not permitted' });
    await pool.query('DELETE FROM projects WHERE id = $1', [p.id]); // cascades to project_controls
    res.json({ ok: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message || 'Failed to delete project' });
  }
};

// ---- Controls ----
export const listControls = async (req: Request, res: Response) => {
  try {
    const p = await fetchProject(req.params.id);
    if (!p) return res.status(404).json({ error: 'Project not found' });
    if (!canAccessTenant(req, p.tenant_name)) return res.status(403).json({ error: 'Access not permitted' });
    const r = await pool.query(
      `SELECT control_key AS "controlKey", control_id AS "controlId", title, kind, status,
              auto_status AS "autoStatus", owner, percent_complete AS "percentComplete",
              target_date AS "targetDate", comments
       FROM project_controls WHERE project_id = $1 ORDER BY control_key`,
      [p.id]
    );
    const rows = r.rows.map((row: any) => ({ ...row, fips: catalogByKey.get(row.controlKey)?.fips || '' }));
    res.json({ framework: p.framework, controls: rows });
  } catch (e: any) {
    res.status(500).json({ error: e.message || 'Failed to list controls' });
  }
};

export const updateControl = async (req: Request, res: Response) => {
  try {
    const p = await fetchProject(req.params.id);
    if (!p) return res.status(404).json({ error: 'Project not found' });
    if (!canAccessTenant(req, p.tenant_name)) return res.status(403).json({ error: 'Access not permitted' });
    const key = req.params.controlKey;
    const status = STATUSES.includes((req.body.status || '').toLowerCase()) ? req.body.status.toLowerCase() : undefined;
    const pct = req.body.percentComplete != null ? Math.max(0, Math.min(100, Math.floor(Number(req.body.percentComplete)))) : undefined;
    const r = await pool.query(
      `UPDATE project_controls SET
         status = COALESCE($3, status),
         owner = $4,
         percent_complete = COALESCE($5, percent_complete),
         target_date = $6,
         comments = $7,
         updated_at = CURRENT_TIMESTAMP
       WHERE project_id = $1 AND control_key = $2
       RETURNING control_key AS "controlKey", status, owner, percent_complete AS "percentComplete", target_date AS "targetDate", comments`,
      [p.id, key, status ?? null, (req.body.owner ?? null) || null, pct ?? null,
       (req.body.targetDate ?? null) || null, (req.body.comments ?? null) || null]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'Control not found on this project' });
    res.json(r.rows[0]);
  } catch (e: any) {
    res.status(500).json({ error: e.message || 'Failed to update control' });
  }
};

// Re-run the CBOM auto-assessment and apply it to controls still at their auto value.
export const reassessControls = async (req: Request, res: Response) => {
  try {
    const p = await fetchProject(req.params.id);
    if (!p) return res.status(404).json({ error: 'Project not found' });
    if (!canAccessTenant(req, p.tenant_name)) return res.status(403).json({ error: 'Access not permitted' });
    const posture = await computePosture(p);
    for (const c of controlsForFramework(p.framework as Framework)) {
      const st = autoStatus(c, posture);
      // Only overwrite rows the assessor hasn't manually changed (status still == auto_status).
      await pool.query(
        `UPDATE project_controls SET status = $3, auto_status = $3, updated_at = CURRENT_TIMESTAMP
         WHERE project_id = $1 AND control_key = $2 AND status = auto_status`,
        [p.id, c.key, st]
      );
      await pool.query(`UPDATE project_controls SET auto_status = $3 WHERE project_id = $1 AND control_key = $2`, [p.id, c.key, st]);
    }
    res.json({ ok: true, posture });
  } catch (e: any) {
    res.status(500).json({ error: e.message || 'Failed to reassess' });
  }
};

// ---- OSCAL export (control-driven) ----
const projectRecord = (p: any): ProjectRecord => ({
  id: p.id, tenant_name: p.tenant_name, name: p.name, description: p.description,
  system_id: p.system_id, impact_level: p.impact_level, framework: p.framework,
});

const controlRows = async (projectId: string): Promise<ControlRow[]> => {
  const r = await pool.query(
    `SELECT control_key, control_id, title, kind, status, owner, percent_complete, target_date, comments
     FROM project_controls WHERE project_id = $1 ORDER BY control_key`, [projectId]
  );
  return r.rows.map((row: any) => ({ ...row, fips: catalogByKey.get(row.control_key)?.fips || '', implicit: row.status === 'not_applicable' }));
};

const sendOscal = (res: Response, filename: string, doc: any) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(JSON.stringify(doc, null, 2));
};
const slug = (s: string) => (s || 'project').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);

export const exportProjectSSP = async (req: Request, res: Response) => {
  try {
    const p = await fetchProject(req.params.id);
    if (!p) return res.status(404).json({ error: 'Project not found' });
    if (!canAccessTenant(req, p.tenant_name)) return res.status(403).json({ error: 'Access not permitted' });
    const [controls, posture] = await Promise.all([controlRows(p.id), computePosture(p)]);
    sendOscal(res, `oscal-ssp-${slug(p.name)}.json`, buildSSP(projectRecord(p), controls, posture));
  } catch (e: any) {
    res.status(500).json({ error: e.message || 'Failed to export SSP' });
  }
};

export const exportProjectPOAM = async (req: Request, res: Response) => {
  try {
    const p = await fetchProject(req.params.id);
    if (!p) return res.status(404).json({ error: 'Project not found' });
    if (!canAccessTenant(req, p.tenant_name)) return res.status(403).json({ error: 'Access not permitted' });
    const [controls, posture] = await Promise.all([controlRows(p.id), computePosture(p)]);
    sendOscal(res, `oscal-poam-${slug(p.name)}.json`, buildPOAM(projectRecord(p), controls, posture));
  } catch (e: any) {
    res.status(500).json({ error: e.message || 'Failed to export POA&M' });
  }
};
