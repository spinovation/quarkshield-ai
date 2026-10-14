import { seal, open as unseal } from '../utils/secretbox';
// Type-only imports: these pull NO runtime code (so this module does not load the
// AWS / Azure SDKs), which keeps credential-plumbing unit tests fast and isolated.
import type { KmsConfig } from '../lib/awsKms';
import type { VaultConfig } from '../lib/hashiVault';
import type { AzureConfig } from '../lib/azureKeyVault';

/**
 * Pure config helpers for the Enterprise PKI/KMS connectors: sealing credentials
 * at rest, parsing a stored connector row back into a provider client config, and
 * deriving the secret-free view returned to API clients. Kept dependency-light
 * (secretbox + types only) so it is unit-testable without a DB or cloud SDKs.
 */

/** Parse the JSON config_summary blob from a connector row (tolerant of junk). */
export const rawConfig = (row: any): any => {
  try { return typeof row.config_summary === 'string' ? JSON.parse(row.config_summary) : (row.config_summary || {}); }
  catch { return {}; }
};

/**
 * Encrypt the credential-bearing fields of a connector config before it is
 * persisted, so no plaintext secret ever lands in the database. AWS keys and the
 * Vault token / AppRole secret_id / Azure client secret are recoverable (needed
 * for discovery), so they are AES-256-GCM sealed rather than masked; the matching
 * parse*Config() readers unseal them. Non-secret fields pass through untouched.
 * Returns a new object; the input is not mutated.
 */
export const sealConnectorSecrets = (config: Record<string, any> = {}): Record<string, any> => {
  const out = { ...config };
  for (const k of ['token', 'secretId', 'clientSecret', 'accessKeyId', 'secretAccessKey', 'secretKey']) {
    if (out[k]) out[k] = seal(String(out[k]));
  }
  return out;
};

export const parseKmsConfig = (row: any): KmsConfig => {
  const cfg = rawConfig(row);
  return {
    roleArn: cfg.roleArn || cfg.role_arn,
    externalId: cfg.externalId || cfg.external_id,
    regions: cfg.regions || (cfg.region ? [cfg.region] : undefined),
    region: cfg.region,
    endpointUrl: row.endpoint_url || cfg.endpointUrl || undefined,
    // Sealed at rest by createPkiConnector; fall back to a raw value for any
    // legacy row written before sealing was added.
    accessKeyId: unseal(cfg.accessKeyId) || cfg.accessKeyId,
    secretAccessKey: unseal(cfg.secretAccessKey) || cfg.secretAccessKey,
  };
};

export const parseVaultConfig = (row: any): VaultConfig => {
  const cfg = rawConfig(row);
  return {
    address: row.endpoint_url || cfg.address,
    token: unseal(cfg.token) || undefined,
    roleId: cfg.roleId,
    secretId: unseal(cfg.secretId) || undefined,
    namespace: cfg.namespace,
    transitMount: cfg.transitMount,
    pkiMount: cfg.pkiMount,
  };
};

export const parseAzureConfig = (row: any): AzureConfig => {
  const cfg = rawConfig(row);
  return {
    vaultUrl: row.endpoint_url || cfg.vaultUrl,
    tenantId: cfg.tenantId,
    clientId: cfg.clientId,
    clientSecret: unseal(cfg.clientSecret) || undefined,
    authorityHost: cfg.authorityHost,
  };
};

// Config keys safe to return to the client. Everything else (tokens, client/
// AWS secrets, access keys) is withheld from API responses.
export const PUBLIC_CONFIG_KEYS = ['region', 'regions', 'roleArn', 'externalId', 'namespace', 'transitMount', 'pkiMount', 'roleId', 'clientId', 'tenantId', 'vaultUrl', 'authorityHost', 'endpointUrl'];

/** Strip config_summary (which holds secrets) and expose only non-secret hints. */
export const publicConnector = (row: any): any => {
  const cfg = rawConfig(row);
  const safeCfg: any = {};
  for (const k of PUBLIC_CONFIG_KEYS) if (cfg[k] !== undefined) safeCfg[k] = cfg[k];
  const { config_summary, ...rest } = row;
  return { ...rest, config: safeCfg };
};
