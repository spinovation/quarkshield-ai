// Platform (super-admin) console ↔ tenant data.
//
// The server only releases a tenant's detail (hosts, CBOM assets, findings…) to a
// platform session while that tenant has an active, time-boxed support-access grant,
// and only when the request names exactly that tenant. Everything else is per-tenant
// AGGREGATES. This module is the console's side of that contract.

export interface TenantAggregate {
  tenantName: string;
  machineCount: number;
  onlineCount: number;
  assetCount: number;
  vulnerableCount: number;
  avgRiskScore: number;
  lastSeen: string | null;
  agentVersions: Record<string, number>;
  osCounts: Record<string, number>;
  seatsByLicense: Record<string, number>;
  supportAccess: { active: boolean; expiresAt: string | null };
}
export interface FleetSummary {
  tenants: TenantAggregate[];
  totals: { tenants: number; machines: number; online: number; assets: number; vulnerable: number };
}
export interface GrantStatus { active: boolean; expiresAt: string | null; grantedBy?: string | null }

export const normTenant = (s?: string | null): string => (s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
/** The platform's own stack is not customer data and is never gated. */
export const isPlatformTenant = (s?: string | null): boolean => normTenant(s) === 'quarkshieldai';

export async function fetchFleetSummary(): Promise<FleetSummary | null> {
  try {
    const r = await fetch('/api/admin/fleet/summary', { credentials: 'include' });
    if (!r.ok) return null;
    const d = await r.json();
    return { tenants: Array.isArray(d.tenants) ? d.tenants : [], totals: d.totals || { tenants: 0, machines: 0, online: 0, assets: 0, vulnerable: 0 } };
  } catch { return null; }
}

/** Authoritative: asks the server whether `tenant` currently has an active grant. */
export async function fetchGrantStatus(tenant: string): Promise<GrantStatus> {
  try {
    const r = await fetch(`/api/support-access/status?tenant=${encodeURIComponent(tenant)}`, { credentials: 'include' });
    if (!r.ok) return { active: false, expiresAt: null };
    const d = await r.json();
    const expiresAt = d?.grant?.expires_at || null;
    // An "active" answer with no expiry is not a grant — a window is always time-boxed.
    return { active: d?.active === true && !!expiresAt, expiresAt, grantedBy: d?.grant?.granted_by || null };
  } catch { return { active: false, expiresAt: null }; }
}

// ---------------------------------------------------------------------------
// Tenant naming for a support session.
//
// Many console/mirror components call tenant-scoped APIs without a tenant (they were
// written for a tenant session, where the server pins the tenant itself). While a
// platform admin is working under a tenant's support grant, setSupportTenant(name)
// makes every same-origin /api/ call carry `X-Tenant-Id: <name>`, so the server can
// match it to the grant. It names the tenant — it grants nothing: with no active grant
// the server answers 403 / aggregates regardless of this header.
// ---------------------------------------------------------------------------
let supportTenant: string | null = null;
let installed = false;

const isApiCall = (url: string): boolean => {
  try { const u = new URL(url, window.location.origin); return u.origin === window.location.origin && u.pathname.startsWith('/api/'); }
  catch { return false; }
};

export function setSupportTenant(tenant: string | null): void {
  supportTenant = tenant && tenant.trim() ? tenant.trim() : null;
  if (installed || typeof window === 'undefined') return;
  installed = true;
  const original = window.fetch.bind(window);
  window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    if (!supportTenant) return original(input, init);
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    if (!isApiCall(url)) return original(input, init);
    // A call that already names its tenant keeps that name (the server refuses two).
    if (/[?&]tenant=/.test(url)) return original(input, init);
    const headers = new Headers(init?.headers || (input instanceof Request ? input.headers : undefined));
    if (!headers.has('X-Tenant-Id')) headers.set('X-Tenant-Id', supportTenant);
    return original(input, { ...init, headers });
  };
}

export const formatExpiry = (iso?: string | null): string => {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? '' : d.toLocaleString();
};
