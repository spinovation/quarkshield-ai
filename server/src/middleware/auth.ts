import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import pool from '../config/db';

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
const DEFAULT_TTL = '12h';

const getSecret = (): string => {
  const s = process.env.JWT_SECRET;
  if (s && s.length >= 16) return s;
  // Fail closed in production; only fall back in non-production for local runs.
  if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT_SECRET is not set (required in production)');
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

const SUPER_ROLES = ['superadmin', 'root_admin', 'secops_lead', 'support_engineer', 'compliance_auditor'];

export const isSuperRole = (role?: string): boolean => !!role && SUPER_ROLES.includes(role);

export const signSession = (user: SessionUser): string =>
  jwt.sign(user, getSecret(), { expiresIn: DEFAULT_TTL });

export const setSessionCookie = (res: Response, token: string): void => {
  const domain = process.env.COOKIE_DOMAIN || undefined; // undefined = host-only (localhost)
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    domain,
    maxAge: 12 * 60 * 60 * 1000,
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

/** Populate req.user if a valid session is present; never rejects. */
export const attachUser = (req: Request, _res: Response, next: NextFunction): void => {
  const token = extractToken(req);
  if (token) {
    try {
      req.user = jwt.verify(token, getSecret()) as SessionUser;
    } catch {
      // invalid/expired token -> treat as anonymous
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
    // Fail-open: never block a paying tenant on a transient DB hiccup.
    console.warn('localTenantEntitlement failed, assuming entitled:', (e as Error).message);
    return { integrations: true, tier: 'unknown', seats: 0 };
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
