/**
 * Tenant-admin CRUD for read-only posture service tokens (QSG platform integration).
 *
 * Tokens are shown in full exactly once, at creation. Afterwards only metadata is
 * returned (never the secret or its hash). All operations are scoped to the caller's
 * own tenant via getEffectiveTenant() — a tenant admin can never see or revoke another
 * tenant's tokens.
 */
import crypto from 'crypto';
import { Request, Response } from 'express';
import pool from '../config/db';
import { getEffectiveTenant } from './fleetController';
import { generateServiceToken, SUPPORTED_SCOPES } from '../middleware/serviceToken';
import { localTenantEntitlement, QSG_ADDON } from '../middleware/auth';

/** True when the tenant's license holds the QSG posture add-on. */
const tenantHasQsg = async (tenant: string): Promise<boolean> => {
  const ent = await localTenantEntitlement(tenant);
  return Array.isArray(ent?.addons) && ent.addons.includes(QSG_ADDON);
};

const writeAudit = (action: string, actor: string, details: unknown, ip: string): void => {
  pool.query(
    `INSERT INTO audit_logs (id, action, actor, details, ip_address) VALUES ($1, $2, $3, $4, $5)`,
    [`aud-${crypto.randomBytes(8).toString('hex')}`, action, actor, JSON.stringify(details), ip]
  ).catch(() => { /* best-effort */ });
};

// ---- shared, tenant-explicit helpers ----------------------------------------
// Each handler (tenant-admin, scoped by getEffectiveTenant; or superadmin, scoped by
// :name) resolves the tenant its own way, then delegates here. Minting is gated on the
// tenant holding the QSG posture add-on so an unlicensed tenant can never get a token.

const listForTenant = async (tenant: string, res: Response): Promise<void> => {
  try {
    const r = await pool.query(
      `SELECT id, name, scopes, created_by, created_at, expires_at, last_used_at, revoked
         FROM service_tokens
        WHERE LOWER(tenant_name) = LOWER($1)
        ORDER BY created_at DESC`,
      [tenant]
    );
    res.json({ tokens: r.rows });
  } catch (err) {
    console.error('listForTenant failed:', err);
    res.status(500).json({ error: 'Failed to list service tokens.' });
  }
};

const mintForTenant = async (tenant: string, req: Request, res: Response): Promise<void> => {
  if (!(await tenantHasQsg(tenant))) {
    res.status(403).json({ error: 'QSG posture access is not enabled for this tenant. Enable the QSG add-on on their license first.' });
    return;
  }
  const name = String(req.body?.name || '').trim();
  if (!name) {
    res.status(400).json({ error: 'A token name is required.' });
    return;
  }

  // Scopes: default posture:read; reject anything unsupported.
  const requested: string[] = Array.isArray(req.body?.scopes) && req.body.scopes.length
    ? req.body.scopes.map((s: unknown) => String(s))
    : ['posture:read'];
  const invalid = requested.filter((s) => !(SUPPORTED_SCOPES as readonly string[]).includes(s));
  if (invalid.length) {
    res.status(400).json({ error: `Unsupported scope(s): ${invalid.join(', ')}` });
    return;
  }

  // Optional expiry in days.
  let expiresAt: Date | null = null;
  if (req.body?.expiresInDays != null) {
    const days = Number(req.body.expiresInDays);
    if (!Number.isFinite(days) || days <= 0 || days > 3650) {
      res.status(400).json({ error: 'expiresInDays must be between 1 and 3650.' });
      return;
    }
    expiresAt = new Date(Date.now() + days * 86_400_000);
  }

  const { token, hash } = generateServiceToken();
  const id = `svc-${crypto.randomBytes(12).toString('hex')}`;
  const createdBy = req.user?.email || req.user?.sub || 'unknown';

  try {
    await pool.query(
      `INSERT INTO service_tokens (id, tenant_name, name, token_hash, scopes, created_by, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [id, tenant, name, hash, requested, createdBy, expiresAt]
    );
    writeAudit('service_token_created', createdBy, { id, tenant, name, scopes: requested }, req.ip || '');
    // Plaintext returned exactly once — never retrievable again.
    res.status(201).json({
      id,
      name,
      tenant,
      scopes: requested,
      expires_at: expiresAt,
      token,
      warning: 'Store this token now. It will not be shown again.',
    });
  } catch (err) {
    console.error('mintForTenant failed:', err);
    res.status(500).json({ error: 'Failed to create service token.' });
  }
};

const revokeForTenant = async (tenant: string, id: string, req: Request, res: Response): Promise<void> => {
  try {
    const r = await pool.query(
      `UPDATE service_tokens SET revoked = true
        WHERE id = $1 AND LOWER(tenant_name) = LOWER($2) AND revoked = false
        RETURNING id`,
      [id, tenant]
    );
    if (!r.rows.length) {
      res.status(404).json({ error: 'Token not found or already revoked.' });
      return;
    }
    writeAudit('service_token_revoked', req.user?.email || req.user?.sub || 'unknown', { id, tenant }, req.ip || '');
    res.json({ ok: true, id });
  } catch (err) {
    console.error('revokeForTenant failed:', err);
    res.status(500).json({ error: 'Failed to revoke service token.' });
  }
};

// ---- tenant-admin handlers (scoped to the caller's own tenant) ---------------
/** GET /api/service-tokens — list the caller tenant's tokens (metadata only). */
export const listServiceTokens = async (req: Request, res: Response): Promise<void> => {
  const tenant = getEffectiveTenant(req);
  if (!tenant) { res.status(400).json({ error: 'Tenant could not be determined.' }); return; }
  await listForTenant(tenant, res);
};

/** POST /api/service-tokens — mint a token for the caller's tenant; plaintext ONCE. */
export const createServiceToken = async (req: Request, res: Response): Promise<void> => {
  const tenant = getEffectiveTenant(req);
  if (!tenant) { res.status(400).json({ error: 'Tenant could not be determined.' }); return; }
  await mintForTenant(tenant, req, res);
};

/** DELETE /api/service-tokens/:id — revoke one of the caller tenant's tokens. */
export const revokeServiceToken = async (req: Request, res: Response): Promise<void> => {
  const tenant = getEffectiveTenant(req);
  if (!tenant) { res.status(400).json({ error: 'Tenant could not be determined.' }); return; }
  await revokeForTenant(tenant, String(req.params.id || ''), req, res);
};

// ---- superadmin handlers (tenant from :name, for the License Panel) ----------
/** GET /api/admin/clients/:name/service-tokens — list a tenant's tokens (platform admin). */
export const adminListServiceTokens = async (req: Request, res: Response): Promise<void> => {
  const tenant = String(req.params.name || '').trim();
  if (!tenant) { res.status(400).json({ error: 'Tenant name is required.' }); return; }
  await listForTenant(tenant, res);
};

/** POST /api/admin/clients/:name/service-tokens — mint a token for a tenant (platform admin). */
export const adminCreateServiceToken = async (req: Request, res: Response): Promise<void> => {
  const tenant = String(req.params.name || '').trim();
  if (!tenant) { res.status(400).json({ error: 'Tenant name is required.' }); return; }
  await mintForTenant(tenant, req, res);
};

/** DELETE /api/admin/clients/:name/service-tokens/:id — revoke a tenant's token (platform admin). */
export const adminRevokeServiceToken = async (req: Request, res: Response): Promise<void> => {
  const tenant = String(req.params.name || '').trim();
  if (!tenant) { res.status(400).json({ error: 'Tenant name is required.' }); return; }
  await revokeForTenant(tenant, String(req.params.id || ''), req, res);
};
