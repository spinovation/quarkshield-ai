/** Threat & Risk Graph API client (Risk Assurance plan). */

const token = () => sessionStorage.getItem('quarkshield_token') || localStorage.getItem('quarkshield_token') || '';
const headers = () => ({ 'Content-Type': 'application/json', Authorization: `Bearer ${token()}` });

export class UpgradeRequiredError extends Error {
  constructor(message: string, public eligible: boolean) { super(message); }
}

/** Risk Assurance add-on offer (per tenant, monthly; Enterprise only). */
export const riskAssuranceOffer = async (tenant?: string): Promise<any> => {
  const r = await fetch(`/api/billing/risk-assurance${tenant ? `?tenant=${encodeURIComponent(tenant)}` : ''}`, { headers: headers() });
  return r.ok ? r.json() : null;
};

export const startRiskAssuranceCheckout = async (tenant?: string): Promise<string> => {
  const r = await fetch('/api/billing/risk-assurance/checkout', {
    method: 'POST', headers: headers(), body: JSON.stringify(tenant ? { tenantName: tenant } : {}),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.checkoutUrl) throw new Error(j.error || `Checkout failed (${r.status})`);
  return j.checkoutUrl;
};

export const makeApi = (tenant?: string) => {
  const withTenant = (path: string) => {
    if (!tenant) return path;
    return `${path}${path.includes('?') ? '&' : '?'}tenant=${encodeURIComponent(tenant)}`;
  };
  const request = async <T,>(method: string, path: string, body?: unknown): Promise<T> => {
    const r = await fetch(`/api/threat-graph${withTenant(path)}`, {
      method, headers: headers(), body: body === undefined ? undefined : JSON.stringify(body),
    });
    const j = await r.json().catch(() => ({}));
    if (r.status === 403 && j?.code === 'UPGRADE_REQUIRED') throw new UpgradeRequiredError(j.error, !!j.eligible);
    if (!r.ok) throw new Error(j?.error || `Request failed (${r.status})`);
    return j as T;
  };
  return {
    overview: (scope?: string) => request<any>('GET', `/overview${scope && scope !== 'all' ? `?scope=${encodeURIComponent(scope)}` : ''}`),
    graph: (q: { path?: string; focus?: string; depth?: number; all?: boolean } = {}) => {
      const p = new URLSearchParams();
      if (q.all) p.set('all', '1');
      if (q.path) p.set('path', q.path);
      if (q.focus) p.set('focus', q.focus);
      if (q.depth) p.set('depth', String(q.depth));
      const qs = p.toString();
      return request<any>('GET', `/graph${qs ? `?${qs}` : ''}`);
    },
    relationship: (id: string) => request<any>('GET', `/relationships/${encodeURIComponent(id)}`),
    scenarios: () => request<any[]>('GET', '/scenarios'),
    scenario: (id: string) => request<any>('GET', `/scenarios/${encodeURIComponent(id)}`),
    assets: () => request<any[]>('GET', '/assets'),
    asset: (id: string) => request<any>('GET', `/assets/${encodeURIComponent(id)}`),
    setContext: (id: string, body: unknown) => request<any>('PUT', `/assets/${encodeURIComponent(id)}/context`, body),
    updateRemediation: (id: string, body: unknown) => request<any>('PATCH', `/remediations/${encodeURIComponent(id)}`, body),
    rebuild: () => request<any>('POST', '/rebuild'),
    runs: () => request<any[]>('GET', '/runs'),
  };
};

export type ThreatApi = ReturnType<typeof makeApi>;
