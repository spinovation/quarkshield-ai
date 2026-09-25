import { KeyClient } from '@azure/keyvault-keys';
import { ClientSecretCredential, DefaultAzureCredential, TokenCredential } from '@azure/identity';
import { DiscoveredAsset } from './awsKms';

/**
 * Real Azure Key Vault key discovery (DEF-51, Phase 2).
 *
 * Keyless-first: if no client secret is supplied we use DefaultAzureCredential
 * (managed identity / workload identity / az login). A service principal
 * (tenantId + clientId + clientSecret) is supported as a fallback; the secret is
 * stored encrypted at rest by the caller. Reads key metadata only (type, size,
 * curve, expiry) — never private key material.
 */

export interface AzureConfig {
  vaultUrl?: string;        // https://<name>.vault.azure.net
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;    // optional; keyless when omitted
  authorityHost?: string;   // for emulator/sovereign clouds
}

const credentialFor = (cfg: AzureConfig): TokenCredential => {
  if (cfg.tenantId && cfg.clientId && cfg.clientSecret) {
    return new ClientSecretCredential(cfg.tenantId, cfg.clientId, cfg.clientSecret,
      cfg.authorityHost ? { authorityHost: cfg.authorityHost } : undefined);
  }
  return new DefaultAzureCredential();
};

const clientFor = (cfg: AzureConfig): KeyClient => {
  if (!cfg.vaultUrl) throw new Error('Azure vault URL is required');
  // disableChallengeResourceVerification helps against emulators/non-standard hosts.
  return new KeyClient(cfg.vaultUrl, credentialFor(cfg), { disableChallengeResourceVerification: true } as any);
};

export const mapKeyType = (keyType: string, sizeBits: number, curve?: string): { type: string; algo: string; size: number; vuln: boolean; risk: string; threat: string } => {
  const kt = (keyType || '').toUpperCase();
  if (kt.startsWith('RSA')) {
    const size = sizeBits || 2048;
    return { type: 'asymmetric_key', algo: `RSA-${size}`, size, vuln: true, risk: size <= 2048 ? 'critical' : 'high',
      threat: "Shor's algorithm factors the RSA modulus on a CRQC." };
  }
  if (kt.startsWith('EC')) {
    const c = (curve || 'P-256');
    const size = c.includes('384') ? 384 : c.includes('521') ? 521 : c.includes('256K') ? 256 : 256;
    return { type: 'asymmetric_key', algo: `ECDSA-${c}`, size, vuln: true, risk: 'critical',
      threat: "Elliptic-curve discrete log solved by Shor's algorithm." };
  }
  if (kt.startsWith('OCT')) {
    return { type: 'symmetric_key', algo: `AES-${sizeBits || 256}`, size: sizeBits || 256, vuln: false, risk: 'secure',
      threat: 'Symmetric AES key; quantum-resistant (Grover only halves the strength).' };
  }
  return { type: 'asymmetric_key', algo: keyType || 'unknown', size: sizeBits || 0, vuln: false, risk: 'low', threat: `Azure key type '${keyType}'.` };
};

/** Bit length of an RSA modulus given as a byte array. */
const bitsFromModulus = (n?: Uint8Array): number => {
  if (!n || !n.length) return 0;
  // strip a leading zero sign byte if present
  let bytes = n.length;
  if (n[0] === 0) bytes -= 1;
  return bytes * 8;
};

export const pingAzure = async (cfg: AzureConfig): Promise<{ ok: boolean; message: string }> => {
  const client = clientFor(cfg);
  const it = client.listPropertiesOfKeys().byPage({ maxPageSize: 1 });
  await it.next(); // triggers auth + a real call
  return { ok: true, message: `Authenticated to Azure Key Vault ${cfg.vaultUrl}.` };
};

export const discoverAzureKeys = async (cfg: AzureConfig): Promise<DiscoveredAsset[]> => {
  const client = clientFor(cfg);
  const assets: DiscoveredAsset[] = [];
  for await (const prop of client.listPropertiesOfKeys()) {
    if (!prop.name) continue;
    let keyType = ''; let sizeBits = 0; let curve: string | undefined;
    try {
      const k = await client.getKey(prop.name);
      keyType = (k.keyType as string) || '';
      curve = k.key?.crv as string | undefined;
      if (keyType.toUpperCase().startsWith('RSA')) sizeBits = bitsFromModulus(k.key?.n as Uint8Array | undefined);
      if (keyType.toUpperCase().startsWith('OCT')) sizeBits = 256;
    } catch { /* fall back to properties only */ }
    const m = mapKeyType(keyType, sizeBits, curve);
    assets.push({
      name: prop.name,
      type: m.type, algo: m.algo, size: m.size, vuln: m.vuln,
      risk: prop.enabled === false ? 'low' : m.risk,
      threat: m.threat, rot: false,
      expiresAt: prop.expiresOn ? new Date(prop.expiresOn) : null,
    });
  }
  return assets;
};
