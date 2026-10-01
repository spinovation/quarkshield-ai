import { Request, Response } from 'express';
import crypto from 'crypto';
import pool from '../config/db';
import { resolveWriteTenant, canAccessTenant } from '../middleware/auth';
import { buildSSP, buildPOAM, ProjectRecord, AssetRecord } from '../lib/oscal';

/**
 * Projects (BILL-4). A Project is an authorization boundary — a Program of Record,
 * a location/region, or a business unit. Every tenant can create them; each Project
 * produces its own OSCAL SSP + POA&M from a scoped set of the tenant's assets.
 * Scope: scope_machine_ids / scope_sources; empty = all of the tenant's assets.
 */

const cleanArr = (v: any): string[] | null => {
  if (!Array.isArray(v)) return null;
  const a = v.map((x) => String(x).trim()).filter(Boolean);
  return a.length ? a : null;
};

export const listProjects = async (req: Request, res: Response) => {
  try {
    const tenant = resolveWriteTenant(req, (req.query.tenant as string) || null);
    const r = await pool.query(
      `SELECT id, tenant_name AS "tenantName", name, description, system_id AS "systemId",
              impact_level AS "impactLevel", scope_machine_ids AS "scopeMachineIds",
              scope_sources AS "scopeSources", created_at AS "createdAt", updated_at AS "updatedAt"
       FROM projects
       WHERE LOWER(tenant_name) = LOWER($1) OR LOWER(REPLACE(tenant_name,' ','')) = LOWER(REPLACE($1,' ',''))
       ORDER BY created_at DESC`,
      [tenant]
    );
    res.json(r.rows);
  } catch (e: any) {
    res.status(500).json({ error: e.message || 'Failed to list projects' });
  }
};

export const createProject = async (req: Request, res: Response) => {
  try {
    const tenant = resolveWriteTenant(req, req.body.tenantName || null);
    if (!tenant) return res.status(400).json({ error: 'Tenant could not be resolved' });
    const name = (req.body.name || '').toString().trim();
    if (!name) return res.status(400).json({ error: 'Project name is required' });
    const id = 'proj-' + crypto.randomBytes(8).toString('hex');
    const impact = ['low', 'moderate', 'high'].includes((req.body.impactLevel || '').toLowerCase())
      ? (req.body.impactLevel as string).toLowerCase()
      : 'moderate';
    const r = await pool.query(
      `INSERT INTO projects (id, tenant_name, name, description, system_id, impact_level, scope_machine_ids, scope_sources)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id, tenant_name AS "tenantName", name, description, system_id AS "systemId",
                 impact_level AS "impactLevel", scope_machine_ids AS "scopeMachineIds",
                 scope_sources AS "scopeSources", created_at AS "createdAt"`,
      [
        id,
        tenant,
        name,
        (req.body.description || '').toString() || null,
        (req.body.systemId || '').toString() || null,
        impact,
        cleanArr(req.body.scopeMachineIds),
        cleanArr(req.body.scopeSources),
      ]
    );
    res.status(201).json(r.rows[0]);
  } catch (e: any) {
    res.status(500).json({ error: e.message || 'Failed to create project' });
  }
};

const fetchProject = async (id: string) => {
  const r = await pool.query(`SELECT * FROM projects WHERE id = $1`, [id]);
  return r.rows[0] || null;
};

export const getProject = async (req: Request, res: Response) => {
  try {
    const p = await fetchProject(req.params.id);
    if (!p) return res.status(404).json({ error: 'Project not found' });
    if (!canAccessTenant(req, p.tenant_name)) return res.status(403).json({ error: 'Access to this project is not permitted' });
    res.json(p);
  } catch (e: any) {
    res.status(500).json({ error: e.message || 'Failed to fetch project' });
  }
};

export const updateProject = async (req: Request, res: Response) => {
  try {
    const p = await fetchProject(req.params.id);
    if (!p) return res.status(404).json({ error: 'Project not found' });
    if (!canAccessTenant(req, p.tenant_name)) return res.status(403).json({ error: 'Access to this project is not permitted' });
    const name = req.body.name != null ? String(req.body.name).trim() : p.name;
    const impact = ['low', 'moderate', 'high'].includes((req.body.impactLevel || '').toLowerCase())
      ? (req.body.impactLevel as string).toLowerCase()
      : p.impact_level;
    const r = await pool.query(
      `UPDATE projects SET name=$2, description=$3, system_id=$4, impact_level=$5,
              scope_machine_ids=$6, scope_sources=$7, updated_at=CURRENT_TIMESTAMP
       WHERE id=$1 RETURNING id, tenant_name AS "tenantName", name, description,
              system_id AS "systemId", impact_level AS "impactLevel",
              scope_machine_ids AS "scopeMachineIds", scope_sources AS "scopeSources", updated_at AS "updatedAt"`,
      [
        p.id,
        name,
        req.body.description != null ? String(req.body.description) : p.description,
        req.body.systemId != null ? String(req.body.systemId) : p.system_id,
        impact,
        req.body.scopeMachineIds !== undefined ? cleanArr(req.body.scopeMachineIds) : p.scope_machine_ids,
        req.body.scopeSources !== undefined ? cleanArr(req.body.scopeSources) : p.scope_sources,
      ]
    );
    res.json(r.rows[0]);
  } catch (e: any) {
    res.status(500).json({ error: e.message || 'Failed to update project' });
  }
};

export const deleteProject = async (req: Request, res: Response) => {
  try {
    const p = await fetchProject(req.params.id);
    if (!p) return res.status(404).json({ error: 'Project not found' });
    if (!canAccessTenant(req, p.tenant_name)) return res.status(403).json({ error: 'Access to this project is not permitted' });
    await pool.query(`DELETE FROM projects WHERE id = $1`, [p.id]);
    res.json({ ok: true });
  } catch (e: any) {
    res.status(500).json({ error: e.message || 'Failed to delete project' });
  }
};

/** Fetch the assets that fall within a project's scope (empty scope = all tenant assets). */
const fetchScopedAssets = async (project: any): Promise<AssetRecord[]> => {
  const machineIds: string[] | null = project.scope_machine_ids && project.scope_machine_ids.length ? project.scope_machine_ids : null;
  const sources: string[] | null = project.scope_sources && project.scope_sources.length ? project.scope_sources : null;
  const r = await pool.query(
    `SELECT id, type, name, algorithm, key_size, hash_algorithm, is_vulnerable, risk_level,
            status, description, recommendation, explainer, compliance_violations, path, source, source_ref
     FROM assets
     WHERE (LOWER(tenant_name) = LOWER($1) OR LOWER(REPLACE(tenant_name,' ','')) = LOWER(REPLACE($1,' ','')))
       AND ($2::text[] IS NULL OR machine_id = ANY($2::text[]))
       AND ($3::text[] IS NULL OR source = ANY($3::text[]))`,
    [project.tenant_name, machineIds, sources]
  );
  return r.rows as AssetRecord[];
};

const projectRecord = (p: any): ProjectRecord => ({
  id: p.id,
  tenant_name: p.tenant_name,
  name: p.name,
  description: p.description,
  system_id: p.system_id,
  impact_level: p.impact_level,
});

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
    if (!canAccessTenant(req, p.tenant_name)) return res.status(403).json({ error: 'Access to this project is not permitted' });
    const assets = await fetchScopedAssets(p);
    sendOscal(res, `oscal-ssp-${slug(p.name)}.json`, buildSSP(projectRecord(p), assets));
  } catch (e: any) {
    res.status(500).json({ error: e.message || 'Failed to export SSP' });
  }
};

export const exportProjectPOAM = async (req: Request, res: Response) => {
  try {
    const p = await fetchProject(req.params.id);
    if (!p) return res.status(404).json({ error: 'Project not found' });
    if (!canAccessTenant(req, p.tenant_name)) return res.status(403).json({ error: 'Access to this project is not permitted' });
    const assets = await fetchScopedAssets(p);
    sendOscal(res, `oscal-poam-${slug(p.name)}.json`, buildPOAM(projectRecord(p), assets));
  } catch (e: any) {
    res.status(500).json({ error: e.message || 'Failed to export POA&M' });
  }
};
