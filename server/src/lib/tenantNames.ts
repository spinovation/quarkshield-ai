import pool from '../config/db';

/**
 * Tenant-name rules, applied the same way to every tenant at every place a tenant can
 * be created (console, onboarding, self-registration checkout).
 *
 * The auth layer compares tenants with case and punctuation stripped (normTenant), so:
 *  - two clients whose names collapse to the same key ("acme-corp" / "acmecorp") would be
 *    ONE tenant to the access check — each could read the other's data;
 *  - a client named after a platform bucket ("system", "global", "community", …) would be
 *    handed the rows the platform keeps under that name.
 * Both are refused here, before the client row exists.
 */

/** Same normalisation as middleware/auth normTenant (kept local to avoid an import cycle). */
export const tenantKey = (s?: string | null): string => (s || '').toLowerCase().replace(/[^a-z0-9]/g, '');

/** SQL expression that normalises a tenant-name column the same way as tenantKey(). */
export const sqlTenantKey = (col: string): string =>
  `LOWER(REGEXP_REPLACE(COALESCE(${col}, ''), '[^a-zA-Z0-9]', '', 'g'))`;

/**
 * Names the platform uses for its own rows or routing. Compared as tenantKey().
 *  system        tenant_settings scope for platform mail / AI keys
 *  global        platform CI-gate policy templates
 *  community     CI-gate evaluations sent without a tenant token
 *  collective    fleet-wide report scope
 *  all           "every tenant" in tenant filters
 *  default, defaultfleet, unassigned   buckets for unattributed enrollment data
 *  quarkshieldai, quarkshield          the platform's own software inventory
 *  www, api, scanner, admin, console, app, support   platform hostnames
 */
const RESERVED_TENANT_KEYS = new Set<string>([
  'system', 'global', 'community', 'collective', 'all',
  'default', 'defaultfleet', 'unassigned',
  'quarkshieldai', 'quarkshield',
  'www', 'api', 'scanner', 'admin', 'console', 'app', 'support',
]);

export const isReservedTenantName = (name?: string | null): boolean => RESERVED_TENANT_KEYS.has(tenantKey(name));

/**
 * Why `name` cannot be used for a client, or null when it can. A client that already
 * has exactly this name is NOT a clash (the onboarding paths upsert it); a different
 * client whose name collapses to the same key is.
 */
export const tenantNameProblem = async (name: string): Promise<string | null> => {
  const key = tenantKey(name);
  if (!key) return 'Tenant name must contain letters or digits.';
  if (RESERVED_TENANT_KEYS.has(key)) return `"${name}" is reserved by the platform and cannot be used as a tenant name.`;
  const clash = await pool.query(
    `SELECT name FROM admin_clients WHERE ${sqlTenantKey('name')} = $1 AND name <> $2 LIMIT 1`,
    [key, name],
  );
  if (clash.rowCount) return `A tenant with an equivalent name already exists (${clash.rows[0].name}).`;
  return null;
};

/**
 * A customer id no other client holds. Customer ids link licences to clients, so a
 * repeated id would attach one tenant's licence keys to another tenant's record. The
 * old generator drew 4 random digits with no uniqueness check.
 */
export const newCustomerId = async (prefix: 'CORP-' | 'PART-'): Promise<string> => {
  for (let i = 0; i < 20; i++) {
    const digits = i < 10 ? 4 : 8;
    const n = Math.floor(Math.random() * 9 * 10 ** (digits - 1)) + 10 ** (digits - 1);
    const id = `${prefix}${n}`;
    const taken = await pool.query(
      `SELECT 1 FROM admin_clients WHERE customer_id = $1
       UNION ALL SELECT 1 FROM admin_licenses WHERE customer_id = $1 LIMIT 1`,
      [id],
    );
    if (!taken.rowCount) return id;
  }
  return `${prefix}${Date.now()}`;
};
