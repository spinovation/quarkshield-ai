// Time-boxed "support access" grants.
//
// GDPR posture: a super-admin must NOT see a customer tenant's component-level
// inventory (package/algorithm names, versions, host identifiers, CVE rows) by
// default — only numeric/metadata aggregates filtered by tenant name. To
// troubleshoot a specific tenant's data, that tenant's admin grants a
// time-boxed, auto-expiring, audit-logged support window. Full drill-down is
// unlocked only while an active grant exists.
//
// A grant is ACTIVE when: revoked_at IS NULL AND expires_at > now().

import crypto from 'crypto';
import pool from '../config/db';

export const MIN_GRANT_HOURS = 1;
export const MAX_GRANT_HOURS = 72;
export const DEFAULT_GRANT_HOURS = 24;

export interface ActiveGrant {
  tenant_name: string;
  granted_by: string;
  reason: string | null;
  created_at: string;
  expires_at: string;
}

/** True if the tenant currently has an active (non-revoked, unexpired) grant. */
export async function hasActiveSupportGrant(tenant?: string | null): Promise<boolean> {
  if (!tenant) return false;
  const r = await pool.query(
    `SELECT 1 FROM support_access_grants
      WHERE LOWER(tenant_name) = LOWER($1)
        AND revoked_at IS NULL
        AND expires_at > now()
      LIMIT 1`,
    [tenant]
  );
  return (r.rowCount ?? 0) > 0;
}

/** The tenant's current active grant, or null. */
export async function getActiveGrant(tenant?: string | null): Promise<ActiveGrant | null> {
  if (!tenant) return null;
  const r = await pool.query(
    `SELECT tenant_name, granted_by, reason, created_at, expires_at
       FROM support_access_grants
      WHERE LOWER(tenant_name) = LOWER($1)
        AND revoked_at IS NULL
        AND expires_at > now()
      ORDER BY expires_at DESC
      LIMIT 1`,
    [tenant]
  );
  return r.rows[0] || null;
}

/** All active grants (for the super-admin console to know which tenants are unlocked). */
export async function listActiveGrants(): Promise<ActiveGrant[]> {
  const r = await pool.query(
    `SELECT tenant_name, granted_by, reason, created_at, expires_at
       FROM support_access_grants
      WHERE revoked_at IS NULL AND expires_at > now()
      ORDER BY expires_at DESC`
  );
  return r.rows;
}

/** Create a grant. Clamps duration to [MIN, MAX] hours. */
export async function createGrant(tenant: string, grantedBy: string, durationHours: number, reason?: string): Promise<ActiveGrant> {
  const hours = Math.max(MIN_GRANT_HOURS, Math.min(MAX_GRANT_HOURS, Math.floor(durationHours || DEFAULT_GRANT_HOURS)));
  // Supersede any existing active grant for this tenant so there is one window.
  await pool.query(
    `UPDATE support_access_grants SET revoked_at = now()
      WHERE LOWER(tenant_name) = LOWER($1) AND revoked_at IS NULL AND expires_at > now()`,
    [tenant]
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
      WHERE LOWER(tenant_name) = LOWER($1) AND revoked_at IS NULL AND expires_at > now()`,
    [tenant]
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
