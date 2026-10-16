/**
 * Read-only machine-to-machine posture tokens (QSG platform-integration spec).
 *
 * Auth: `Authorization: Bearer qsg_svc_<secret>`. The token carries ≥256 bits of
 * entropy and is stored ONLY as its SHA-256 hash. It is bound to exactly one tenant
 * (the token record), so any caller-supplied `?tenant`, `x-tenant-*` header or
 * subdomain is ignored, and there is no super-role bypass. Scopes are explicit
 * (today only `posture:read`). Every use is rate-limited and audited.
 *
 * `allowServiceToken(scope)` is attached ONLY to the posture endpoints. Requests
 * that carry a `qsg_svc_` bearer are validated strictly here; requests without one
 * fall through to the normal user-session auth (requireAuth). Because the service
 * token is not a JWT, it fails verification on every other route → 401.
 */
import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import type { Pool } from 'pg';

// Lazy pool access: importing this module must not open the DB config (and its
// production-password guard), so the pure token helpers and the service-token
// fall-through path stay usable in unit tests without a database.
let _pool: Pool | null = null;
const db = (): Pool => {
  if (!_pool) _pool = require('../config/db').default as Pool;
  return _pool;
};

export const SERVICE_TOKEN_PREFIX = 'qsg_svc_';
export const SUPPORTED_SCOPES = ['posture:read'] as const;

/** Generate a fresh token (returned once) plus the hash we persist. */
export const generateServiceToken = (): { token: string; hash: string } => {
  const token = SERVICE_TOKEN_PREFIX + crypto.randomBytes(32).toString('base64url'); // 256-bit secret
  return { token, hash: hashServiceToken(token) };
};

export const hashServiceToken = (token: string): string =>
  crypto.createHash('sha256').update(token, 'utf8').digest('hex');

// Per-token sliding-window rate limit (in-memory; best-effort across a single node).
const RL_MAX = 120;
const RL_WINDOW_MS = 60_000;
const rlHits = new Map<string, number[]>();

const auditUse = (tokenId: string, route: string, tenant: string, rowCount: number, ip: string): void => {
  db().query(
    `INSERT INTO audit_logs (id, action, actor, details, ip_address) VALUES ($1, $2, $3, $4, $5)`,
    [
      `aud-${crypto.randomBytes(8).toString('hex')}`,
      'service_token_posture_read',
      `svc:${tokenId}`,
      JSON.stringify({ route, tenant, rowCount }),
      ip,
    ]
  ).catch(() => { /* audit is best-effort */ });
};

/**
 * Gate a posture endpoint for read-only service tokens. Falls through to user-session
 * auth when no service-token bearer is present; rejects an invalid/forbidden token.
 */
export const allowServiceToken = (requiredScope: string) =>
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
    // Not a service token → let the normal user-session auth chain handle it.
    if (!token || !token.startsWith(SERVICE_TOKEN_PREFIX)) {
      next();
      return;
    }

    let row: { id: string; tenant_name: string; scopes: string[]; revoked: boolean; expires_at: string | null } | undefined;
    try {
      const r = await db().query(
        `SELECT id, tenant_name, scopes, revoked, expires_at FROM service_tokens WHERE token_hash = $1 LIMIT 1`,
        [hashServiceToken(token)]
      );
      row = r.rows[0];
    } catch {
      res.status(500).json({ error: 'Service token validation failed.' });
      return;
    }

    if (!row || row.revoked) {
      res.status(401).json({ error: 'Invalid or revoked service token.' });
      return;
    }
    if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) {
      res.status(401).json({ error: 'Service token has expired.' });
      return;
    }
    const scopes: string[] = Array.isArray(row.scopes) ? row.scopes : [];
    if (!scopes.includes(requiredScope)) {
      res.status(403).json({ error: `Service token lacks the required scope: ${requiredScope}` });
      return;
    }

    // Per-token rate limit.
    const now = Date.now();
    const hits = (rlHits.get(row.id) || []).filter((t) => now - t < RL_WINDOW_MS);
    if (hits.length >= RL_MAX) {
      res.status(429).json({ error: 'Rate limit exceeded for this service token.' });
      return;
    }
    hits.push(now);
    rlHits.set(row.id, hits);

    // Bind the tenant from the TOKEN RECORD only — strip any caller-supplied tenant
    // hints so a token can never read another tenant's posture. No super-role.
    const tenant = row.tenant_name;
    req.query.tenant = tenant;
    delete (req.params as Record<string, unknown>).tenant;
    delete req.headers['x-tenant-id'];
    delete req.headers['x-tenant-slug'];
    (req as Request & { user?: unknown }).user = {
      sub: `svc:${row.id}`,
      email: `svc:${row.id}`,
      role: 'service',
      accountType: 'service',
      tenant,
    };
    (req as Request & { serviceToken?: unknown }).serviceToken = { id: row.id, tenant, scopes };

    db().query(`UPDATE service_tokens SET last_used_at = NOW() WHERE id = $1`, [row.id]).catch(() => { /* best-effort */ });

    // Audit with the response row count (CBOM components / asset rows).
    const ip = (req.headers['x-forwarded-for'] as string) || req.ip || '';
    const originalJson = res.json.bind(res);
    res.json = (body: unknown) => {
      let rowCount = 0;
      try {
        if (Array.isArray(body)) rowCount = body.length;
        else if (body && typeof body === 'object') {
          const b = body as Record<string, unknown>;
          rowCount = (Array.isArray(b.components) ? b.components.length
            : Array.isArray(b.assets) ? b.assets.length
            : Array.isArray(b.rows) ? b.rows.length : 0);
        }
      } catch { /* ignore */ }
      auditUse(row!.id, req.path, tenant, rowCount, ip);
      return originalJson(body);
    };

    next();
  };
