import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import pool from '../config/db';

/** Constant-time string compare for shared secrets / service tokens. */
export const safeEqual = (a: string, b: string): boolean => {
  const ba = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  if (ba.length === 0 || ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
};

/**
 * Session authentication and authorization.
 *
 * A signed JWT is issued on login and stored in an httpOnly cookie scoped to
 * COOKIE_DOMAIN (e.g. `.quarkshield.ai`) so the session survives the redirect
 * from the apex to a tenant subdomain. A Bearer token is also accepted for API
 * clients and tests. Identity and role come only from the verified token, never
 * from client-supplied fields (fixes the localStorage-forgeable-role problem).
 */

export const SESSION_COOKIE = 'qs_session';
// Session lifetime. 12h was too short and caused frequent mid-use expiry (the recurring
// ?session=expired). 7 days with the httpOnly cookie is a reasonable tenant-portal TTL.
const DEFAULT_TTL = '7d';
const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

// A value is a placeholder/weak secret if it is short OR matches a known template
// string. Length alone is insufficient: the committed .env.example placeholders are
// 40-60 chars long and would otherwise pass, letting a server boot on a PUBLIC secret.
const PLACEHOLDER_SECRET_RE = /replace-with|change[-_ ]?me|changeme|example|dev-insecure|your[-_]|placeholder|xxxx|secret-here|<.*>/i;
export const isWeakSecret = (s?: string): boolean =>
  !s || s.length < 32 || PLACEHOLDER_SECRET_RE.test(s);

const getSecret = (): string => {
  const s = process.env.JWT_SECRET;
  if (!isWeakSecret(s)) return s as string;
  // Fail closed in production: never sign/verify sessions with a weak or
  // placeholder JWT secret (that lets anyone forge a superadmin session).
  if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT_SECRET is missing, too short (<32), or a placeholder — refusing to start. Set a strong random JWT_SECRET.');
  }
  return 'dev-insecure-secret-change-me';
};

export interface SessionUser {
  sub: string;        // user id
  email: string;
  role: string;       // superadmin | root_admin | admin | secops | auditor | user ...
  accountType: string; // superadmin | partner | corporate | tenant
  tenant: string | null; // tenant slug this session is scoped to (null for super admin)
  pending2fa?: boolean; // true = tenant policy requires 2FA but the user has not enrolled;
                        // the session may only reach the 2FA enrollment endpoints until then.
}

// Endpoints a pending-2FA session may still reach so the user can finish enrollment.
// Matched against the path with any leading "/api" stripped, because req.path is
// relative to the router's mount point ("/2fa/setup", not "/api/2fa/setup").
const PENDING_2FA_ALLOWED = new Set<string>([
  '/2fa/status', '/2fa/setup', '/2fa/verify',
  '/auth/me', '/auth/logout',
]);
const isPending2faAllowed = (p: string): boolean =>
  PENDING_2FA_ALLOWED.has(p.replace(/^\/api/, ''));

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: SessionUser;
    }
  }
}

// Platform operator roles. All of them may VIEW across tenants (the fleet console);
// only PLATFORM_ADMIN_ROLES may perform destructive/privilege-changing operations
// (delete tenants/users, change roles, mint licenses, invite operators, change mail
// settings, run custom checkouts). Previously every operator role was a full
// superadmin, so a "read-only" compliance auditor could delete a tenant.
const PLATFORM_ADMIN_ROLES = ['superadmin', 'root_admin'];
const SUPER_ROLES = [...PLATFORM_ADMIN_ROLES, 'secops_lead', 'support_engineer', 'compliance_auditor'];

export const isSuperRole = (role?: string): boolean => !!role && SUPER_ROLES.includes(role);
export const isPlatformAdmin = (role?: string): boolean => !!role && PLATFORM_ADMIN_ROLES.includes(role);

/** Require a platform ADMIN (superadmin/root_admin) — for destructive admin operations. */
export const requirePlatformAdmin = (req: Request, res: Response, next: NextFunction): void => {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  if (!isPlatformAdmin(req.user.role)) {
    res.status(403).json({ error: 'Platform administrator access required' });
    return;
  }
  next();
};

// ---------------------------------------------------------------------------
// Session revocation. JWTs are stateless, so locking/deleting a user or resetting
// a password used to leave existing 7-day tokens valid. Every authenticated
// request now checks the user row: it must still exist, not be locked/disabled,
// and the token must have been issued AFTER `sessions_revoked_at`. Results are
// cached briefly to keep this to one indexed PK lookup per user per 30s.
// ---------------------------------------------------------------------------
interface UserState { exists: boolean; locked: boolean; revokedAt: number }
const USER_STATE_TTL_MS = 30 * 1000;
const userStateCache = new Map<string, { at: number; val: UserState }>();

const tableForAccount = (accountType: string): 'admin_users' | 'tenant_users' =>
  accountType === 'tenant' ? 'tenant_users' : 'admin_users';

const loadUserState = async (accountType: string, id: string): Promise<UserState> => {
  const key = `${accountType}:${id}`;
  const cached = userStateCache.get(key);
  if (cached && Date.now() - cached.at < USER_STATE_TTL_MS) return cached.val;
  const table = tableForAccount(accountType);
  const r = table === 'admin_users'
    ? await pool.query('SELECT row_locked AS locked, sessions_revoked_at FROM admin_users WHERE id = $1', [id])
    : await pool.query("SELECT (status IS NOT NULL AND status <> 'active') AS locked, sessions_revoked_at FROM tenant_users WHERE id = $1", [id]);
  const row = r.rows[0];
  const val: UserState = row
    ? { exists: true, locked: !!row.locked, revokedAt: row.sessions_revoked_at ? new Date(row.sessions_revoked_at).getTime() : 0 }
    : { exists: false, locked: true, revokedAt: 0 };
  userStateCache.set(key, { at: Date.now(), val });
  return val;
};

/** Invalidate the cached state for a user (call after lock/delete/revoke). */
export const forgetUserState = (accountType: 'tenant' | 'admin', id: string): void => {
  userStateCache.delete(`${accountType === 'tenant' ? 'tenant' : 'admin'}:${id}`);
  // admin accountType is 'superadmin' | 'operator' in tokens; clear both spellings.
  userStateCache.delete(`superadmin:${id}`);
  userStateCache.delete(`operator:${id}`);
};

/**
 * Revoke every existing session for a user. Call on lock, password reset, 2FA
 * reset, role change, and logout. Tokens issued before now are rejected.
 */
export const revokeUserSessions = async (table: 'admin_users' | 'tenant_users', id: string): Promise<void> => {
  await pool.query(`UPDATE ${table} SET sessions_revoked_at = CURRENT_TIMESTAMP WHERE id = $1`, [id]).catch(() => {});
  forgetUserState(table === 'tenant_users' ? 'tenant' : 'admin', id);
};

// Roles a TENANT user may legitimately hold. Critically this list contains NO
// platform/super role, so a tenant-scoped write can never mint a role that
// isSuperRole() would honour (tenant login signs this role straight into the JWT).
const TENANT_ROLES = ['admin', 'secops', 'analyst', 'auditor', 'viewer', 'user'];

/**
 * Coerce a client-supplied role for a tenant user into a safe tenant role.
 * Any platform/super role (or unknown value) collapses to the fallback — this is
 * the hard stop against tenant→superadmin privilege escalation.
 */
export const sanitizeTenantRole = (role?: string, fallback = 'secops'): string => {
  const r = (role || '').toLowerCase().trim();
  if (!r) return fallback;
  if (isSuperRole(r)) return fallback;          // never allow a platform role
  return TENANT_ROLES.includes(r) ? r : fallback;
};

/**
 * Require that the session is a tenant ADMINISTRATOR (or a platform super role).
 * Gate tenant user-management writes with this so an ordinary tenant member
 * cannot create/alter users, reset passwords, or reset 2FA.
 */
export const requireTenantAdmin = (req: Request, res: Response, next: NextFunction): void => {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  if (isSuperRole(req.user.role) || req.user.role === 'admin' || req.user.role === 'owner') {
    next();
    return;
  }
  res.status(403).json({ error: 'Tenant administrator access required' });
};

export const signSession = (user: SessionUser): string =>
  jwt.sign(user, getSecret(), { expiresIn: DEFAULT_TTL });

export const setSessionCookie = (res: Response, token: string): void => {
  const domain = process.env.COOKIE_DOMAIN || undefined; // undefined = host-only (localhost)
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    domain,
    maxAge: SESSION_MAX_AGE_MS,
    path: '/',
  });
};

export const clearSessionCookie = (res: Response): void => {
  const domain = process.env.COOKIE_DOMAIN || undefined;
  res.clearCookie(SESSION_COOKIE, { domain, path: '/' });
};

const extractToken = (req: Request): string | null => {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) {
    const t = auth.slice(7).trim();
    if (t && t !== 'null' && t !== 'undefined') return t;
  }
  const cookieToken = (req as any).cookies?.[SESSION_COOKIE];
  if (cookieToken) return cookieToken;
  return null;
};

/** Populate req.user if a valid, non-revoked session is present; never rejects. */
export const attachUser = async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
  const token = extractToken(req);
  if (token) {
    try {
      const decoded = jwt.verify(token, getSecret()) as SessionUser & { iat?: number };
      // Server-side liveness check: user must still exist, not be locked/disabled,
      // and the token must post-date any revocation.
      const state = await loadUserState(decoded.accountType, decoded.sub);
      // iat has 1s granularity and is stamped by the Node clock while the revocation
      // is stamped by Postgres; allow a few seconds of tolerance so a reset-then-login
      // (or modest clock skew between hosts) does not bounce the user.
      const issuedAtMs = (decoded.iat || 0) * 1000 + 3000;
      if (state.exists && !state.locked && issuedAtMs >= state.revokedAt) {
        req.user = decoded;
      }
    } catch {
      // invalid/expired token or DB error -> treat as anonymous
    }
  }
  next();
};

/** Require any authenticated user. */
export const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  // A pending-2FA session (tenant policy requires 2FA, user not yet enrolled) may
  // only reach the enrollment endpoints until it completes setup.
  if (req.user.pending2fa && !isPending2faAllowed(req.path)) {
    res.status(403).json({ error: 'Two-factor enrollment required', mustEnroll2FA: true });
    return;
  }
  next();
};

/** Require a platform (super/root) role. */
export const requireSuperAdmin = (req: Request, res: Response, next: NextFunction): void => {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  if (!isSuperRole(req.user.role)) {
    res.status(403).json({ error: 'Super administrator access required' });
    return;
  }
  next();
};

/** Require one of the given roles. */
export const requireRole = (...roles: string[]) => (req: Request, res: Response, next: NextFunction): void => {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  if (isSuperRole(req.user.role) || roles.includes(req.user.role)) {
    next();
    return;
  }
  res.status(403).json({ error: 'Insufficient permissions' });
};

export const normTenant = (s: string): string => (s || '').toLowerCase().replace(/[^a-z0-9]/g, '');

/**
 * Row-level tenant guard. Returns true if the current session may act on a
 * resource owned by `rowTenant`. Super roles may act on any tenant; a tenant
 * session may act only on its own. Call this AFTER fetching a resource by id
 * (e.g. a connector/proxy/machine) to prevent cross-tenant IDOR — route
 * middleware alone cannot, because these resources are keyed by id, not tenant.
 */
export const canAccessTenant = (req: Request, rowTenant?: string | null): boolean => {
  if (!req.user) return false;
  if (isSuperRole(req.user.role)) return true;
  return !!req.user.tenant && normTenant(rowTenant || '') === normTenant(req.user.tenant);
};

/**
 * The tenant a WRITE must be attributed to. A tenant session is always pinned to
 * its own session tenant, so a body-supplied `tenantName` cannot poison another
 * tenant's inventory. Super roles (the fleet console acting on behalf of tenants)
 * may target the requested tenant. Never trust a client-supplied tenant for a
 * non-super session.
 */
export const resolveWriteTenant = (req: Request, requested?: string | null): string => {
  if (req.user && !isSuperRole(req.user.role)) {
    return (req.user.tenant || '').toString();
  }
  return (requested || req.user?.tenant || '').toString();
};

/**
 * Require that the session may act on the tenant named in the request
 * (route param :tenant, or ?tenant / X-Tenant-Id). Super admins may act on any
 * tenant. A tenant session may act only on its own tenant.
 */
export const requireTenantAccess = (req: Request, res: Response, next: NextFunction): void => {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  if (isSuperRole(req.user.role)) {
    next();
    return;
  }
  const requested =
    (req.params.tenant as string) ||
    (req.query.tenant as string) ||
    (req.headers['x-tenant-id'] as string) ||
    (req.headers['x-tenant-slug'] as string) ||
    '';
  if (!requested) {
    // No explicit tenant requested: pin the query to the session's own tenant so
    // downstream controllers cannot fall back to "all tenants" or a hardcoded default.
    if (req.user.tenant) {
      req.query.tenant = req.user.tenant;
    }
    next();
    return;
  }
  if (req.user.tenant && normTenant(requested) === normTenant(req.user.tenant)) {
    next();
    return;
  }
  res.status(403).json({ error: 'Access to this tenant is not permitted' });
};

/**
 * Plan-tier entitlement for Integrations & Gateways (BILL-2).
 * Integrations (Git/CI, PKI/Vault connectors, PQC proxy Gateways) are a paid-tier
 * feature. A tenant is entitled when it holds an active Growth/Enterprise license
 * OR its client record is on a Growth/Enterprise subscription. (admin_clients
 * defaults subscription_tier to 'growth', so existing tenants stay entitled; only
 * explicit 'entry' tenants are gated.)
 */
// Paid tiers that unlock Integrations & Gateways. Two vocabularies coexist:
//   admin_clients.subscription_tier = entry | growth | enterprise
//   admin_licenses.tier             = partner | corporate | corp  (enterprise license keys)
// Everything paid is entitled; only the base 'entry' tier is gated.
export const INTEGRATION_TIERS = new Set(['growth', 'enterprise', 'corporate', 'corp', 'partner']);
// Rank for choosing the "best" tier when a tenant has both a license and a subscription.
const TIER_RANK: Record<string, number> = { entry: 1, growth: 2, partner: 3, corporate: 4, corp: 4, enterprise: 5 };

export interface EntitlementRecord {
  integrations: boolean;
  tier: string;
  seats: number;
}

// BILL-3: the CENTRAL plane is the single source of truth for a tenant's plan.
// A tenant pod (separate DB) resolves entitlement by asking central and caching the
// answer briefly, falling back to its own DB if central is unreachable/unconfigured.
// The central plane leaves QS_CENTRAL_URL unset and always answers from its own DB.
const CENTRAL_URL = (process.env.QS_CENTRAL_URL || '').replace(/\/+$/, '');
const CENTRAL_SERVICE_TOKEN = process.env.QS_CENTRAL_SERVICE_TOKEN || '';
const ENT_TTL_MS = 5 * 60 * 1000;
const entCache = new Map<string, { at: number; val: EntitlementRecord }>();

/** Resolve a tenant's entitlement from THIS instance's own database. */
export const localTenantEntitlement = async (tenant?: string | null): Promise<EntitlementRecord> => {
  if (!tenant) return { integrations: false, tier: 'none', seats: 0 };
  try {
    const r = await pool.query(
      `SELECT
         (SELECT tier FROM admin_licenses
            WHERE (LOWER(tenant_name)=LOWER($1) OR LOWER(REPLACE(tenant_name,' ',''))=LOWER(REPLACE($1,' ','')))
              AND status <> 'revoked'
            ORDER BY CASE LOWER(COALESCE(tier,'')) WHEN 'enterprise' THEN 3 WHEN 'growth' THEN 2 ELSE 1 END DESC
            LIMIT 1) AS lic_tier,
         (SELECT MAX(seats) FROM admin_licenses
            WHERE (LOWER(tenant_name)=LOWER($1) OR LOWER(REPLACE(tenant_name,' ',''))=LOWER(REPLACE($1,' ','')))
              AND status <> 'revoked') AS lic_seats,
         (SELECT subscription_tier FROM admin_clients
            WHERE (LOWER(name)=LOWER($1) OR LOWER(REPLACE(name,'-',''))=LOWER(REPLACE($1,'-',''))) LIMIT 1) AS cli_tier,
         (SELECT mca_limit FROM admin_clients
            WHERE (LOWER(name)=LOWER($1) OR LOWER(REPLACE(name,'-',''))=LOWER(REPLACE($1,'-',''))) LIMIT 1) AS cli_seats`,
      [tenant]
    );
    const row = r.rows[0] || {};
    const licTier = String(row.lic_tier || '').toLowerCase();
    const cliTier = String(row.cli_tier || '').toLowerCase();
    // Entitled if EITHER source is a paid tier (vocabularies differ between the two tables).
    const integrations = INTEGRATION_TIERS.has(licTier) || INTEGRATION_TIERS.has(cliTier);
    // Display the highest-ranked tier the tenant holds (so a panel-set 'enterprise' beats an older 'corp' license).
    const tier = [licTier, cliTier].filter(Boolean).sort((a, b) => (TIER_RANK[b] || 0) - (TIER_RANK[a] || 0))[0] || 'entry';
    const seats = Math.max(Number(row.lic_seats || 0), Number(row.cli_seats || 0)) || 0;
    return { integrations, tier, seats };
  } catch (e) {
    // Fail CLOSED: a DB error must not silently grant paid entitlements to an
    // unentitled tenant (the old fail-open handed every tenant the integrations
    // surface on any transient hiccup). Briefly withholding a paid feature is the
    // safer failure mode than leaking it.
    console.warn('localTenantEntitlement failed; denying entitlement (fail-closed):', (e as Error).message);
    return { integrations: false, tier: 'unknown', seats: 0 };
  }
};

const fetchCentralEntitlement = async (tenant: string): Promise<EntitlementRecord | null> => {
  const key = tenant.toLowerCase();
  const cached = entCache.get(key);
  if (cached && Date.now() - cached.at < ENT_TTL_MS) return cached.val;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 3000);
  try {
    const resp = await fetch(`${CENTRAL_URL}/api/central/entitlement?tenant=${encodeURIComponent(tenant)}`, {
      headers: { 'x-qs-service-token': CENTRAL_SERVICE_TOKEN },
      signal: ctrl.signal,
    });
    if (!resp.ok) return cached?.val ?? null;
    const data = (await resp.json()) as EntitlementRecord;
    entCache.set(key, { at: Date.now(), val: data });
    return data;
  } catch (e) {
    console.warn('central entitlement fetch failed:', (e as Error).message);
    return cached?.val ?? null; // serve stale cache if available
  } finally {
    clearTimeout(timer);
  }
};

/** Resolve entitlement: central-first on tenant pods, local on the central plane. */
export const getTenantEntitlement = async (tenant?: string | null): Promise<EntitlementRecord> => {
  if (!tenant) return { integrations: false, tier: 'none', seats: 0 };
  if (CENTRAL_URL && CENTRAL_SERVICE_TOKEN) {
    const remote = await fetchCentralEntitlement(tenant);
    if (remote) return remote;
    // central unreachable and nothing cached → fall back to local (fail-safe)
  }
  return localTenantEntitlement(tenant);
};

export const tenantHasIntegrations = async (tenant?: string | null): Promise<boolean> =>
  (await getTenantEntitlement(tenant)).integrations;

/**
 * Route guard for integration WRITE/active operations (create/test/sync/scan/toggle).
 * Super roles (the fleet console operating on behalf of tenants) always pass.
 * GET (list) and DELETE are intentionally NOT gated — a downgraded tenant can still
 * see and remove its connectors.
 */
export const requireIntegrationsEntitlement = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  if (isSuperRole(req.user.role)) {
    next();
    return;
  }
  if (await tenantHasIntegrations(req.user.tenant)) {
    next();
    return;
  }
  res.status(403).json({
    error: 'Integrations & Gateways require a Growth or Enterprise plan.',
    code: 'UPGRADE_REQUIRED',
  });
};
