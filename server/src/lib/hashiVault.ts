import { DiscoveredAsset } from './awsKms';

/**
 * Real HashiCorp Vault key discovery (DEF-51, Phase 2).
 *
 * Uses the Vault HTTP API (no SDK). Auth is a token or AppRole (role_id +
 * secret_id -> short-lived token). Discovers Transit engine keys and, when a
 * PKI mount is given, classifies its issuer CA certificates. Secrets
 * (token / secret_id) are stored encrypted at rest by the caller.
 */

export interface VaultConfig {
  address?: string;        // e.g. https://vault.example.com:8200
  token?: string;
  roleId?: string;
  secretId?: string;
  namespace?: string;
  transitMount?: string;   // default 'transit'
  pkiMount?: string;       // optional
}

const trimBase = (a?: string) => (a || '').replace(/\/+$/, '');

const headers = (token: string, ns?: string): Record<string, string> => {
  const h: Record<string, string> = { 'X-Vault-Token': token };
  if (ns) h['X-Vault-Namespace'] = ns;
  return h;
};

const vaultFetch = async (base: string, path: string, token: string, ns?: string, opts: RequestInit = {}) => {
  const res = await fetch(`${base}/v1/${path}`, { ...opts, headers: { ...headers(token, ns), ...(opts.headers || {}) } });
  return res;
};

/** Resolve a usable token: explicit token, or AppRole login. */
const resolveToken = async (cfg: VaultConfig): Promise<string> => {
  const base = trimBase(cfg.address);
  if (cfg.token) return cfg.token;
  if (cfg.roleId && cfg.secretId) {
    const res = await fetch(`${base}/v1/auth/approle/login`, {
      method: 'POST',
      headers: cfg.namespace ? { 'X-Vault-Namespace': cfg.namespace } : {},
      body: JSON.stringify({ role_id: cfg.roleId, secret_id: cfg.secretId }),
    });
    if (!res.ok) throw new Error(`AppRole login failed (${res.status})`);
    const j: any = await res.json();
    const t = j?.auth?.client_token;
    if (!t) throw new Error('AppRole login returned no token');
    return t;
  }
  throw new Error('No Vault token or AppRole credentials provided');
};

const mapTransitType = (type: string): { type: string; algo: string; size: number; vuln: boolean; risk: string; threat: string } => {
  const t = (type || '').toLowerCase();
  if (t.startsWith('rsa-')) { const size = parseInt(t.replace('rsa-', ''), 10) || 2048; return { type: 'asymmetric_key', algo: `RSA-${size}`, size, vuln: true, risk: size <= 2048 ? 'critical' : 'high', threat: "Shor's algorithm factors the RSA modulus on a CRQC." }; }
  if (t.startsWith('ecdsa-')) { const size = t.includes('p384') ? 384 : t.includes('p521') ? 521 : 256; return { type: 'asymmetric_key', algo: `ECDSA-P${size}`, size, vuln: true, risk: 'critical', threat: "Elliptic-curve discrete log solved by Shor's algorithm." }; }
  if (t === 'ed25519') return { type: 'asymmetric_key', algo: 'Ed25519', size: 256, vuln: true, risk: 'critical', threat: "Edwards-curve signatures are quantum-vulnerable (Shor's algorithm)." };
  if (t.startsWith('aes')) { const size = t.includes('128') ? 128 : 256; return { type: 'symmetric_key', algo: `AES-${size}-GCM`, size, vuln: false, risk: 'secure', threat: 'AES is quantum-resistant (Grover only halves the strength).' }; }
  if (t.includes('chacha20')) return { type: 'symmetric_key', algo: 'ChaCha20-Poly1305', size: 256, vuln: false, risk: 'secure', threat: 'Stream AEAD; quantum-resistant.' };
  if (t.startsWith('hmac')) return { type: 'symmetric_key', algo: 'HMAC', size: 256, vuln: false, risk: 'secure', threat: 'Symmetric MAC; quantum-resistant.' };
  return { type: 'asymmetric_key', algo: type || 'unknown', size: 0, vuln: false, risk: 'low', threat: `Vault transit key type '${type}'.` };
};

export const pingVault = async (cfg: VaultConfig): Promise<{ ok: boolean; message: string }> => {
  const base = trimBase(cfg.address);
  if (!base) throw new Error('Vault address is required');
  const token = await resolveToken(cfg);
  const res = await vaultFetch(base, 'auth/token/lookup-self', token, cfg.namespace);
  if (!res.ok) throw new Error(`Vault auth check failed (${res.status})`);
  return { ok: true, message: `Authenticated to Vault at ${base}.` };
};

export const discoverVaultKeys = async (cfg: VaultConfig): Promise<DiscoveredAsset[]> => {
  const base = trimBase(cfg.address);
  if (!base) throw new Error('Vault address is required');
  const token = await resolveToken(cfg);
  const ns = cfg.namespace;
  const assets: DiscoveredAsset[] = [];

  // Transit engine keys
  const transitMount = (cfg.transitMount || 'transit').replace(/\/+$/, '');
  const listRes = await vaultFetch(base, `${transitMount}/keys?list=true`, token, ns);
  if (listRes.ok) {
    const listed: any = await listRes.json();
    const names: string[] = listed?.data?.keys || [];
    for (const name of names) {
      const kr = await vaultFetch(base, `${transitMount}/keys/${encodeURIComponent(name)}`, token, ns);
      if (!kr.ok) continue;
      const kd: any = await kr.json();
      const m = mapTransitType(kd?.data?.type || '');
      const rot = !!(kd?.data?.auto_rotate_period && kd.data.auto_rotate_period > 0);
      assets.push({ name: `${transitMount}/${name}`, type: m.type, algo: m.algo, size: m.size, vuln: m.vuln, risk: m.risk, threat: m.threat, rot, expiresAt: null });
    }
  } else if (listRes.status !== 404) {
    throw new Error(`Vault transit list failed (${listRes.status})`);
  }

  // Optional PKI issuers -> classify CA certificates
  if (cfg.pkiMount) {
    const pki = cfg.pkiMount.replace(/\/+$/, '');
    const iss = await vaultFetch(base, `${pki}/issuers?list=true`, token, ns);
    if (iss.ok) {
      const ij: any = await iss.json();
      const keyInfo = ij?.data?.key_info || {};
      const ids: string[] = ij?.data?.keys || [];
      for (const id of ids) {
        try {
          const ir = await vaultFetch(base, `${pki}/issuer/${encodeURIComponent(id)}`, token, ns);
          if (!ir.ok) continue;
          const idata: any = await ir.json();
          const pem = idata?.data?.certificate;
          const { X509Certificate } = await import('crypto');
          const cert = new X509Certificate(pem);
          const pk: any = cert.publicKey.asymmetricKeyDetails || {};
          const kt = cert.publicKey.asymmetricKeyType;
          let m;
          if (kt === 'rsa') m = mapTransitType(`rsa-${pk.modulusLength || 2048}`);
          else if (kt === 'ec') m = mapTransitType(`ecdsa-${(pk.namedCurve || 'p256').replace('prime256v1', 'p256')}`);
          else if (kt === 'ed25519') m = mapTransitType('ed25519');
          else m = mapTransitType(kt || 'unknown');
          assets.push({ name: `${pki}/issuer/${keyInfo[id]?.issuer_name || id}`, type: 'ca_root', algo: m.algo, size: m.size, vuln: m.vuln, risk: m.risk, threat: `PKI issuer CA. ${m.threat}`, rot: false, expiresAt: cert.validTo ? new Date(cert.validTo) : null });
        } catch { /* skip unparseable issuer */ }
      }
    }
  }

  return assets;
};
