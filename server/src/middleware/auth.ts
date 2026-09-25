import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

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

const normTenant = (s: string): string => (s || '').toLowerCase().replace(/[^a-z0-9]/g, '');

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
