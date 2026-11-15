// Time-boxed "support access" grants.
//
// GDPR posture: a super-admin must NOT see a customer tenant's component-level
// inventory (package/algorithm names, versions, host identifiers, CVE rows) by
// default — only numeric/metadata aggregates filtered by tenant name. To
// troubleshoot a specific tenant's data, that tenant's admin grants a
// time-boxed, auto-expiring, audit-logged support window. Full drill-down is
// unlocked only while an active grant exists.
//
// A grant is ACTIVE when: revoked_at IS NULL AND expires_at > now() AND its window is
// no longer than MAX_GRANT_HOURS. A grant is therefore ALWAYS time-boxed: expires_at is
// NOT NULL in the schema, createGrant clamps the duration, and a row whose window
// exceeds the maximum (hand-edited / legacy) is simply not honoured.
//
// Tenants are matched on the normalized key (lowercase, alphanumerics only) — the same
// normalization requireTenantAccess uses — so a grant made by "Acme Corp" unlocks the
// slug "acmecorp" and nothing else.

import crypto from 'crypto';
import pool from '../config/db';

export const MIN_GRANT_HOURS = 1;
export const MAX_GRANT_HOURS = 72;
export const DEFAULT_GRANT_HOURS = 24;

const tenantKey = (s?: string | null): string => (s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
const KEY_SQL = `regexp_replace(LOWER(tenant_name), '[^a-z0-9]', '', 'g')`;
/** SQL predicate for "this row is an active, time-boxed grant". */
export const ACTIVE_GRANT_SQL =
  `revoked_at IS NULL AND expires_at > now() AND expires_at <= created_at + interval '${MAX_GRANT_HOURS} hours'`;

/** Clamp a requested duration to a whole number of hours in [MIN, MAX]; junk → default. */
export const clampGrantHours = (durationHours: unknown): number => {
  const n = Number(durationHours);
  const h = Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_GRANT_HOURS;
  return Math.max(MIN_GRANT_HOURS, Math.min(MAX_GRANT_HOURS, h));
};

export interface ActiveGrant {
  tenant_name: string;
  granted_by: string;
  reason: string | null;
  created_at: string;
  expires_at: string;
}

/** True if the tenant currently has an active (non-revoked, unexpired) grant. */
export async function hasActiveSupportGrant(tenant?: string | null): Promise<boolean> {
  const key = tenantKey(tenant);
  if (!key) return false;
  const r = await pool.query(
    `SELECT 1 FROM support_access_grants
      WHERE ${KEY_SQL} = $1
        AND ${ACTIVE_GRANT_SQL}
      LIMIT 1`,
    [key]
  );
  return (r.rowCount ?? 0) > 0;
}

/** The tenant's current active grant, or null. */
export async function getActiveGrant(tenant?: string | null): Promise<ActiveGrant | null> {
  const key = tenantKey(tenant);
  if (!key) return null;
  const r = await pool.query(
    `SELECT tenant_name, granted_by, reason, created_at, expires_at
       FROM support_access_grants
      WHERE ${KEY_SQL} = $1
        AND ${ACTIVE_GRANT_SQL}
      ORDER BY expires_at DESC
      LIMIT 1`,
    [key]
  );
  return r.rows[0] || null;
}

/** All active grants (for the super-admin console to know which tenants are unlocked). */
export async function listActiveGrants(): Promise<ActiveGrant[]> {
  const r = await pool.query(
    `SELECT tenant_name, granted_by, reason, created_at, expires_at
       FROM support_access_grants
      WHERE ${ACTIVE_GRANT_SQL}
      ORDER BY expires_at DESC`
  );
  return r.rows;
}

/** Create a grant. Clamps duration to [MIN, MAX] hours. */
export async function createGrant(tenant: string, grantedBy: string, durationHours: number, reason?: string): Promise<ActiveGrant> {
  const hours = clampGrantHours(durationHours);
  // Supersede any existing active grant for this tenant so there is one window.
  await pool.query(
    `UPDATE support_access_grants SET revoked_at = now()
      WHERE ${KEY_SQL} = $1 AND revoked_at IS NULL AND expires_at > now()`,
    [tenantKey(tenant)]
  );
  const id = 'sag-' + crypto.randomBytes(9).toString('hex');
  const r = await pool.query(
    `INSERT INTO support_access_grants (id, tenant_name, granted_by, reason, expires_at)
     VALUES ($1, $2, $3, $4, now() + ($5 || ' hours')::interval)
     RETURNING tenant_name, granted_by, reason, created_at, expires_at`,
    [id, tenant, grantedBy, reason || null, String(hours)]
  );
  return r.rows[0];
}

/** Revoke any active grant(s) for the tenant. Returns how many were revoked. */
export async function revokeGrants(tenant: string): Promise<number> {
  const r = await pool.query(
    `UPDATE support_access_grants SET revoked_at = now()
      WHERE ${KEY_SQL} = $1 AND revoked_at IS NULL AND expires_at > now()`,
    [tenantKey(tenant)]
  );
  return r.rowCount ?? 0;
}

/** Append an audit-log entry (same shape used across the platform). */
export async function auditSupportEvent(action: string, actor: string, details: string, ip?: string): Promise<void> {
  try {
    const id = 'aud-' + crypto.randomBytes(9).toString('hex');
    await pool.query(
      `INSERT INTO audit_logs (id, action, actor, details, ip_address) VALUES ($1, $2, $3, $4, $5)`,
      [id, action, actor || 'unknown', details, ip || null]
    );
  } catch {
    // auditing must never block the request
  }
}
