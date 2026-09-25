/**
 * Global 401 interceptor (DEF-55).
 *
 * The app has many data loaders that fall back to demo data when an API call
 * fails, which hides an expired/absent session behind fake content. This wraps
 * window.fetch once: any 401 from an /api call (other than the auth endpoints,
 * where a 401 is an expected "wrong credentials" result) clears the local
 * session and sends the user to the sign-in page, so a logged-out state is
 * surfaced instead of masked. Responses are otherwise passed through unchanged,
 * and all /api requests are sent with credentials so the session cookie flows.
 */

const SESSION_KEYS = [
  'quarkshield_user', 'quarkshield_account_type', 'quarkshield_role',
  'quarkshield_customer_id', 'quarkshield_customer_name', 'quarkshield_license_tier',
  'quarkshield_tenant_slug', 'quarkshield_workspace', 'quarkshield_view_mode',
  'quarkshield_token',
];

let redirecting = false;

const isApiUrl = (url: string): boolean => url.includes('/api/');
const isAuthEndpoint = (url: string): boolean =>
  /\/api\/auth\/(login|forgot-password|reset-password|change-password)\b/.test(url) ||
  url.includes('/api/2fa/');
const onResetPage = (): boolean =>
  window.location.pathname.toLowerCase().startsWith('/reset-password');

export function installAuthInterceptor(): void {
  if (typeof window === 'undefined' || (window as any).__qsAuthInterceptor) return;
  (window as any).__qsAuthInterceptor = true;

  const originalFetch = window.fetch.bind(window);

  window.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : (input instanceof URL ? input.toString() : (input as Request).url);

    // Ensure the session cookie is always sent on same-origin API calls.
    let nextInit = init;
    if (isApiUrl(url) && (!init || init.credentials === undefined)) {
      nextInit = { ...(init || {}), credentials: 'include' };
    }

    const res = await originalFetch(input as any, nextInit);

    if (res.status === 401 && isApiUrl(url) && !isAuthEndpoint(url) && !onResetPage() && !redirecting) {
      redirecting = true;
      try {
        SESSION_KEYS.forEach(k => { localStorage.removeItem(k); sessionStorage.removeItem(k); });
      } catch { /* ignore storage errors */ }
      // Send the user to the sign-in (landing) page.
      const base = window.location.protocol + '//' + window.location.host + '/';
      window.location.replace(base + '?session=expired');
    }

    return res;
  };
}
