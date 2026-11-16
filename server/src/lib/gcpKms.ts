import crypto from 'crypto';
import type { DiscoveredAsset } from './awsKms';
import { gcpKmsModule } from './cmvpModules';

/**
 * Google Cloud KMS key discovery (DEF-51 family, alongside AWS KMS / Azure Key Vault /
 * HashiCorp Vault).
 *
 * Read-only by design: lists locations → key rings → crypto keys and maps each key's
 * algorithm (versionTemplate / primary version) to the shared DiscoveredAsset shape.
 * Never requests key material and never performs a cryptographic operation.
 *
 * Auth: a Google service-account JSON key (sealed at rest by the controller) exchanged
 * for a short-lived OAuth2 token via the JWT-bearer grant, signed locally with Node's
 * crypto — no Google SDK dependency.
 *
 * SECURITY:
 *  - Only fixed Google endpoints are ever contacted (cloudkms.googleapis.com and
 *    oauth2.googleapis.com). A service-account file whose `token_uri` points anywhere
 *    else is rejected, so a pasted key cannot be used to make the server call an
 *    internal/metadata host (SSRF).
 *  - projectId / location values are validated before being placed in a URL path.
 *  - The token is requested with the cloud-platform.read-only scope; grant the service
 *    account `roles/cloudkms.viewer` (Cloud KMS Viewer) — list/get metadata only.
 */

export interface GcpConfig {
  projectId?: string;
  locations?: string[];          // optional allow-list; default = every location in the project
  serviceAccountJson?: string;   // the SA key file contents (sealed at rest by the caller)
}

export const GCP_KMS_BASE = 'https://cloudkms.googleapis.com/v1';
export const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const SCOPE = 'https://www.googleapis.com/auth/cloud-platform.read-only';
const REQUEST_TIMEOUT_MS = 15000;
const MAX_PAGES = 100;          // per listing — guards against a pathological pageToken loop
const LOCATION_CONCURRENCY = 6;

type FetchFn = (input: string, init?: any) => Promise<{ ok: boolean; status: number; json: () => Promise<any>; text: () => Promise<string> }>;
export interface GcpDeps { fetch?: FetchFn; now?: () => number }

const PROJECT_ID_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const LOCATION_RE = /^[a-z0-9-]{1,40}$/;

interface ServiceAccountKey { client_email: string; private_key: string; project_id?: string }

/** Parse + validate a service-account key. Throws a user-facing error on anything unsafe. */
export const parseServiceAccount = (json?: string): ServiceAccountKey => {
  if (!json || !json.trim()) throw new Error('A Google service-account JSON key is required');
  let k: any;
  try { k = JSON.parse(json); } catch { throw new Error('Service-account key is not valid JSON'); }
  if (k.type && k.type !== 'service_account') throw new Error(`Expected a service_account key, got "${k.type}"`);
  if (typeof k.client_email !== 'string' || !k.client_email.includes('@')) throw new Error('Service-account key has no client_email');
  if (typeof k.private_key !== 'string' || !k.private_key.includes('PRIVATE KEY')) throw new Error('Service-account key has no private_key');
  // SSRF guard: the token exchange always goes to Google's fixed token endpoint.
  if (k.token_uri && k.token_uri !== GOOGLE_TOKEN_URL) {
    throw new Error(`Service-account token_uri must be ${GOOGLE_TOKEN_URL}`);
  }
  return { client_email: k.client_email, private_key: k.private_key, project_id: k.project_id };
};

const b64url = (buf: Buffer | string): string =>
  Buffer.from(buf).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');

/** Build the RS256-signed JWT assertion for the OAuth2 JWT-bearer grant. */
export const buildJwtAssertion = (sa: ServiceAccountKey, nowMs: number): string => {
  const iat = Math.floor(nowMs / 1000);
  const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = b64url(JSON.stringify({ iss: sa.client_email, scope: SCOPE, aud: GOOGLE_TOKEN_URL, iat, exp: iat + 3600 }));
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(`${header}.${claims}`);
  return `${header}.${claims}.${b64url(signer.sign(sa.private_key))}`;
};

const withTimeout = async (f: FetchFn, url: string, init: any = {}) => {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
  try { return await f(url, { ...init, signal: ctrl.signal }); } finally { clearTimeout(t); }
};

const getAccessToken = async (sa: ServiceAccountKey, f: FetchFn, nowMs: number): Promise<string> => {
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: buildJwtAssertion(sa, nowMs),
  }).toString();
  const res = await withTimeout(f, GOOGLE_TOKEN_URL, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
  });
  if (!res.ok) {
    // Google returns {error, error_description}; never echo the assertion itself.
    let detail = '';
    try { const j = await res.json(); detail = j.error_description || j.error || ''; } catch { /* ignore */ }
    throw new Error(`Google OAuth token exchange failed (HTTP ${res.status})${detail ? `: ${detail}` : ''}`);
  }
  const j = await res.json();
  if (!j.access_token) throw new Error('Google OAuth token response had no access_token');
  return j.access_token;
};

/** GET a paginated Cloud KMS collection, following nextPageToken (capped). */
const listAll = async (f: FetchFn, token: string, url: string, field: string): Promise<any[]> => {
  const out: any[] = [];
  let pageToken = '';
  for (let page = 0; page < MAX_PAGES; page++) {
    const u = `${url}${url.includes('?') ? '&' : '?'}pageSize=1000${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ''}`;
    const res = await withTimeout(f, u, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) {
      let detail = '';
      try { const j = await res.json(); detail = j.error?.message || ''; } catch { /* ignore */ }
      throw new Error(`Cloud KMS request failed (HTTP ${res.status})${detail ? `: ${detail}` : ''}`);
    }
    const j = await res.json();
    out.push(...(Array.isArray(j[field]) ? j[field] : []));
    if (!j.nextPageToken) return out;
    pageToken = j.nextPageToken;
  }
  return out;
};

/**
 * Map a Cloud KMS CryptoKeyVersionAlgorithm to the shared asset shape. The algorithm
 * label is written in the vocabulary the FIPS resolver (lib/fipsAlgorithmStatus.ts)
 * and the purpose classifier understand; the threat text carries the key's use so
 * classifyPurpose() can tell signing keys from RSA key-transport keys.
 */
export const mapGcpAlgorithm = (alg: string, protectionLevel?: string): Omit<DiscoveredAsset, 'name' | 'rot' | 'expiresAt' | 'module'> => {
  const a = String(alg || '').toUpperCase();
  const hsm = protectionLevel && protectionLevel !== 'SOFTWARE' ? ` Protection level: ${protectionLevel}.` : '';
  const sym = (algo: string, size: number, note: string) =>
    ({ type: 'symmetric_key', algo, size, vuln: false, risk: 'secure', threat: `${note}${hsm}` });

  if (a === 'GOOGLE_SYMMETRIC_ENCRYPTION') return sym('AES-256-GCM', 256, 'Google symmetric encryption (AES-256-GCM); quantum-resistant (Grover only halves the strength).');
  let m = a.match(/^AES_(128|256)_(GCM|CBC|CTR)$/);
  if (m) return sym(`AES-${m[1]}-${m[2]}`, Number(m[1]), `AES-${m[1]}-${m[2]} raw symmetric key; quantum-resistant (Grover only halves the strength).`);
  if (a.startsWith('EXTERNAL_SYMMETRIC')) return sym('External symmetric (Cloud EKM)', 0, 'Key material held in an external key manager (Cloud EKM); algorithm not reported by Cloud KMS.');
  m = a.match(/^HMAC_(SHA\d+)$/);
  if (m) return sym(`HMAC-${m[1]}`, 0, `HMAC-${m[1]} MAC key; quantum-resistant.`);

  // e.g. RSA_SIGN_PSS_2048_SHA256, RSA_SIGN_PKCS1_3072_SHA256 (note the digit in PKCS1),
  // RSA_SIGN_RAW_PKCS1_4096, RSA_DECRYPT_OAEP_2048_SHA1 — the modulus is the 4-digit field.
  m = a.match(/^RSA_(SIGN|DECRYPT)_.*?_(\d{4})(?:_|$)/);
  if (m) {
    const size = Number(m[2]);
    const decrypt = m[1] === 'DECRYPT';
    return {
      type: 'asymmetric_key', algo: `RSA-${size}`, size, vuln: true, risk: size <= 2048 ? 'critical' : 'high',
      threat: decrypt
        ? `RSA key transport (asymmetric decrypt) — data encrypted to this key today can be decrypted once a CRQC exists (Harvest-Now-Decrypt-Later).${hsm}`
        : `RSA signing key — signatures become forgeable once a CRQC runs Shor's algorithm.${hsm}`,
    };
  }
  if (a === 'EC_SIGN_P256_SHA256') return { type: 'asymmetric_key', algo: 'ECDSA-P256', size: 256, vuln: true, risk: 'critical', threat: `ECDSA P-256 signing key — signatures become forgeable once a CRQC exists.${hsm}` };
  if (a === 'EC_SIGN_P384_SHA384') return { type: 'asymmetric_key', algo: 'ECDSA-P384', size: 384, vuln: true, risk: 'critical', threat: `ECDSA P-384 signing key — signatures become forgeable once a CRQC exists.${hsm}` };
  if (a === 'EC_SIGN_SECP256K1_SHA256') return { type: 'asymmetric_key', algo: 'ECDSA-secp256k1', size: 256, vuln: true, risk: 'critical', threat: `ECDSA secp256k1 signing key (not a NIST curve) — signatures become forgeable once a CRQC exists.${hsm}` };
  if (a === 'EC_SIGN_ED25519') return { type: 'asymmetric_key', algo: 'Ed25519', size: 256, vuln: true, risk: 'critical', threat: `Ed25519 signing key — signatures become forgeable once a CRQC exists.${hsm}` };

  m = a.match(/^PQ_SIGN_ML_DSA_(44|65|87)$/);
  if (m) return { type: 'asymmetric_key', algo: `ML-DSA-${m[1]}`, size: 0, vuln: false, risk: 'secure', threat: `ML-DSA-${m[1]} signing key (NIST FIPS 204) — post-quantum.${hsm}` };
  m = a.match(/^PQ_SIGN_(?:HASH_)?SLH_DSA_(SHA2|SHAKE)_(\d{3})([SF])/);
  if (m) return { type: 'asymmetric_key', algo: `SLH-DSA-${m[1]}-${m[2]}${m[3].toLowerCase()}`, size: 0, vuln: false, risk: 'secure', threat: `SLH-DSA signing key (NIST FIPS 205) — post-quantum.${hsm}` };
  m = a.match(/^ML_KEM_(512|768|1024)$/);
  if (m) return { type: 'asymmetric_key', algo: `ML-KEM-${m[1]}`, size: 0, vuln: false, risk: 'secure', threat: `ML-KEM-${m[1]} key encapsulation (NIST FIPS 203) — post-quantum key establishment.${hsm}` };
  if (a === 'KEM_XWING') return { type: 'asymmetric_key', algo: 'X-Wing (ML-KEM-768 + X25519 hybrid)', size: 0, vuln: false, risk: 'secure', threat: `X-Wing hybrid key encapsulation (ML-KEM-768 + X25519) — post-quantum key establishment.${hsm}` };

  // Unknown → fail safe (treated as quantum-vulnerable until reviewed), never "secure".
  return { type: 'asymmetric_key', algo: a ? a.replace(/_/g, '-') : 'unknown', size: 0, vuln: true, risk: 'high', threat: `Unrecognized Cloud KMS algorithm '${alg || 'unknown'}' — review.${hsm}` };
};

const resolveProject = (cfg: GcpConfig, sa: ServiceAccountKey): string => {
  const p = (cfg.projectId || sa.project_id || '').trim();
  if (!PROJECT_ID_RE.test(p)) throw new Error('A valid Google Cloud project ID is required (6–30 chars: lowercase letters, digits, hyphens)');
  return p;
};

/** Authenticate and make one real KMS call (list locations, 1 page). */
export const pingGcp = async (cfg: GcpConfig, deps: GcpDeps = {}): Promise<{ ok: boolean; message: string }> => {
  const f = deps.fetch || (fetch as unknown as FetchFn);
  const sa = parseServiceAccount(cfg.serviceAccountJson);
  const project = resolveProject(cfg, sa);
  const token = await getAccessToken(sa, f, (deps.now || Date.now)());
  const res = await withTimeout(f, `${GCP_KMS_BASE}/projects/${project}/locations?pageSize=1`, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) {
    let detail = '';
    try { const j = await res.json(); detail = j.error?.message || ''; } catch { /* ignore */ }
    throw new Error(`Cloud KMS request failed (HTTP ${res.status})${detail ? `: ${detail}` : ''}`);
  }
  return { ok: true, message: `Authenticated to Google Cloud KMS for project ${project} as ${sa.client_email}.` };
};

/** Discover every crypto key (metadata only) across the project's locations. */
export const discoverGcpKeys = async (cfg: GcpConfig, deps: GcpDeps = {}): Promise<DiscoveredAsset[]> => {
  const f = deps.fetch || (fetch as unknown as FetchFn);
  const sa = parseServiceAccount(cfg.serviceAccountJson);
  const project = resolveProject(cfg, sa);
  const token = await getAccessToken(sa, f, (deps.now || Date.now)());

  let locations = (cfg.locations || []).map(l => String(l).trim()).filter(Boolean);
  for (const l of locations) if (!LOCATION_RE.test(l)) throw new Error(`Invalid Cloud KMS location "${l}"`);
  if (!locations.length) {
    const locs = await listAll(f, token, `${GCP_KMS_BASE}/projects/${project}/locations`, 'locations');
    locations = locs.map((l: any) => String(l.locationId || '')).filter(l => LOCATION_RE.test(l));
  }

  const assets: DiscoveredAsset[] = [];
  for (let i = 0; i < locations.length; i += LOCATION_CONCURRENCY) {
    const batch = locations.slice(i, i + LOCATION_CONCURRENCY);
    const perLocation = await Promise.all(batch.map(async (loc) => {
      const found: DiscoveredAsset[] = [];
      const rings = await listAll(f, token, `${GCP_KMS_BASE}/projects/${project}/locations/${loc}/keyRings`, 'keyRings');
      for (const ring of rings) {
        const ringName = String(ring.name || '');
        if (!ringName.startsWith(`projects/${project}/locations/${loc}/keyRings/`)) continue; // only paths we asked for
        const keys = await listAll(f, token, `${GCP_KMS_BASE}/${ringName}/cryptoKeys`, 'cryptoKeys');
        const ringShort = ringName.split('/').pop();
        for (const k of keys) {
          const alg = k.primary?.algorithm || k.versionTemplate?.algorithm || '';
          const level = k.primary?.protectionLevel || k.versionTemplate?.protectionLevel;
          const mapped = mapGcpAlgorithm(alg, level);
          const state = k.primary?.state;
          found.push({
            ...mapped,
            name: `${loc}/${ringShort}/${String(k.name || '').split('/').pop()}`,
            // A disabled / destroyed primary version is not in active use.
            risk: state && state !== 'ENABLED' ? 'low' : mapped.risk,
            rot: !!k.rotationPeriod,
            expiresAt: null, // Cloud KMS keys do not expire (rotation is separate)
            module: gcpKmsModule(level),
          });
        }
      }
      return found;
    }));
    for (const list of perLocation) assets.push(...list);
  }
  return assets;
};
