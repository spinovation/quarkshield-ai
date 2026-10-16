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
import { generateServiceToken, hashServiceToken, SUPPORTED_SCOPES } from '../middleware/serviceToken';
import { localTenantEntitlement, QSG_ADDON } from '../middleware/auth';
import { sendSupportEmail } from './adminController';

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

/**
 * POST /api/admin/clients/:name/service-tokens/email — email a just-minted QSG token to
 * the customer (platform admin). The token is hash-only at rest, so the plaintext must be
 * supplied by the caller (it is held once in the Generate-token modal). We verify the hash
 * matches a live, non-revoked token for this tenant before sending, so we never email a
 * value that isn't actually a valid token for them.
 */
export const adminEmailServiceToken = async (req: Request, res: Response): Promise<void> => {
  const tenant = String(req.params.name || '').trim();
  if (!tenant) { res.status(400).json({ error: 'Tenant name is required.' }); return; }
  const token = String(req.body?.token || '').trim();
  if (!token) { res.status(400).json({ error: 'The token value is required (it is only available at creation).' }); return; }

  // Confirm the token is a live one for THIS tenant before emailing it.
  let tokenRow: { id: string; name: string; expires_at: string | null } | undefined;
  try {
    const r = await pool.query(
      `SELECT id, name, expires_at FROM service_tokens
        WHERE token_hash = $1 AND LOWER(tenant_name) = LOWER($2) AND revoked = false
        LIMIT 1`,
      [hashServiceToken(token), tenant]
    );
    tokenRow = r.rows[0];
  } catch (err) {
    console.error('adminEmailServiceToken lookup failed:', err);
    res.status(500).json({ error: 'Failed to validate the token.' });
    return;
  }
  if (!tokenRow) {
    res.status(400).json({ error: 'That token is not a current token for this tenant (it may have been revoked or regenerated).' });
    return;
  }

  // Recipient: explicit contactEmail, else the tenant's admin_email on record.
  let recipient = String(req.body?.contactEmail || '').trim();
  if (!recipient) {
    try {
      const c = await pool.query(
        `SELECT admin_email FROM admin_clients
          WHERE LOWER(name) = LOWER($1) OR LOWER(REPLACE(name,'-','')) = LOWER(REPLACE($1,'-','')) LIMIT 1`,
        [tenant]
      );
      recipient = String(c.rows[0]?.admin_email || '').trim();
    } catch { /* fall through to the missing-recipient error */ }
  }
  if (!recipient) {
    res.status(400).json({ error: 'No recipient email on record for this tenant. Provide contactEmail.' });
    return;
  }

  const expLine = tokenRow.expires_at
    ? `Expires: ${new Date(tokenRow.expires_at).toISOString().slice(0, 10)}`
    : 'Expires: never';
  const subject = `QuarkShield Quantum Security Gateway — posture access token [${tenant.toUpperCase()}]`;
  const text =
`Your QuarkShield Quantum Security Gateway (QSG) posture access token for ${tenant} has been generated.

Token (store securely — it is shown only once and is not recoverable):
${token}

Scope: posture:read (read-only crypto posture)
${expLine}

Set it up on your QSG control host:
  1. Export it as an environment variable (do not put it in the config file):
       QSG_PLATFORM_TOKEN=${token}
     e.g. a systemd EnvironmentFile with mode 0600.
  2. In control.toml set:
       posture_source.kind = "quarkshield_api"
       base_url = "https://quarkshield.ai"
       token_env = "QSG_PLATFORM_TOKEN"

This token is read-only and can be revoked at any time from the QuarkShield License Panel.
If you did not expect this, contact Support@quarkshield.ai.`;
  const html =
`<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:560px;margin:auto;color:#0f172a">
  <h2 style="color:#0ea5e9;margin-bottom:0.25rem">QuarkShield Quantum Security Gateway</h2>
  <p>Your <strong>posture access token</strong> for <strong>${tenant}</strong> has been generated.</p>
  <p style="margin:0.5rem 0;color:#b45309"><strong>Store this securely — it is shown only once and cannot be recovered.</strong></p>
  <pre style="background:#0f172a;color:#4ade80;padding:12px;border-radius:6px;word-break:break-all;white-space:pre-wrap">${token}</pre>
  <p style="font-size:0.9rem">Scope: <code>posture:read</code> (read-only) &middot; ${expLine}</p>
  <ol style="font-size:0.9rem;line-height:1.5">
    <li>Export it on your QSG control host (not in the config file):<br>
      <code>QSG_PLATFORM_TOKEN=&lt;token&gt;</code> (e.g. a systemd EnvironmentFile, mode 0600)</li>
    <li>In <code>control.toml</code>: <code>posture_source.kind="quarkshield_api"</code>,
      <code>base_url="https://quarkshield.ai"</code>, <code>token_env="QSG_PLATFORM_TOKEN"</code></li>
  </ol>
  <p style="font-size:0.85rem;color:#64748b">Read-only; revocable anytime from the QuarkShield License Panel.
  If you did not expect this, contact Support@quarkshield.ai.</p>
</div>`;

  const sent = await sendSupportEmail({ to: recipient, subject, html, text });
  if (!sent.success) {
    res.status(502).json({ error: `Failed to send email: ${sent.error || 'mailer unavailable'}` });
    return;
  }
  writeAudit('service_token_emailed', req.user?.email || req.user?.sub || 'unknown',
    { id: tokenRow.id, tenant, recipient }, req.ip || '');
  res.json({ ok: true, recipient });
};
