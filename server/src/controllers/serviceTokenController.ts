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

const writeAudit = (action: string, actor: string, details: unknown, ip: string): void => {
  pool.query(
    `INSERT INTO audit_logs (id, action, actor, details, ip_address) VALUES ($1, $2, $3, $4, $5)`,
    [`aud-${crypto.randomBytes(8).toString('hex')}`, action, actor, JSON.stringify(details), ip]
  ).catch(() => { /* best-effort */ });
};

/** GET /api/service-tokens — list the tenant's tokens (metadata only). */
export const listServiceTokens = async (req: Request, res: Response): Promise<void> => {
  const tenant = getEffectiveTenant(req);
  if (!tenant) {
    res.status(400).json({ error: 'Tenant could not be determined.' });
    return;
  }
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
    console.error('listServiceTokens failed:', err);
    res.status(500).json({ error: 'Failed to list service tokens.' });
  }
};

/** POST /api/service-tokens — create a token; returns the plaintext ONCE. */
export const createServiceToken = async (req: Request, res: Response): Promise<void> => {
  const tenant = getEffectiveTenant(req);
  if (!tenant) {
    res.status(400).json({ error: 'Tenant could not be determined.' });
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
      scopes: requested,
      expires_at: expiresAt,
      token,
      warning: 'Store this token now. It will not be shown again.',
    });
  } catch (err) {
    console.error('createServiceToken failed:', err);
    res.status(500).json({ error: 'Failed to create service token.' });
  }
};

/** DELETE /api/service-tokens/:id — revoke (soft) one of the tenant's tokens. */
export const revokeServiceToken = async (req: Request, res: Response): Promise<void> => {
  const tenant = getEffectiveTenant(req);
  if (!tenant) {
    res.status(400).json({ error: 'Tenant could not be determined.' });
    return;
  }
  const id = String(req.params.id || '');
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
    console.error('revokeServiceToken failed:', err);
    res.status(500).json({ error: 'Failed to revoke service token.' });
  }
};
