import { Request, Response } from 'express';
import pool from '../config/db';
import crypto from 'crypto';
import { discoverKmsKeys, pingKms, DiscoveredAsset, KmsConfig } from '../lib/awsKms';
import { discoverVaultKeys, pingVault, VaultConfig } from '../lib/hashiVault';
import { discoverAzureKeys, pingAzure, AzureConfig } from '../lib/azureKeyVault';
import { seal, open as unseal } from '../utils/secretbox';

// Providers with a real backend implemented. Others return clearly-labeled
// preview (simulated) data until their integrations land (DEF-51).
const REAL_PROVIDERS = new Set(['aws_kms', 'hashicorp_vault', 'azure_keyvault']);

const rawConfig = (row: any): any => {
  try { return typeof row.config_summary === 'string' ? JSON.parse(row.config_summary) : (row.config_summary || {}); }
  catch { return {}; }
};

const parseKmsConfig = (row: any): KmsConfig => {
  const cfg = rawConfig(row);
  return {
    roleArn: cfg.roleArn || cfg.role_arn,
    externalId: cfg.externalId || cfg.external_id,
    regions: cfg.regions || (cfg.region ? [cfg.region] : undefined),
    region: cfg.region,
    endpointUrl: row.endpoint_url || cfg.endpointUrl || undefined,
    accessKeyId: cfg.accessKeyId,
    secretAccessKey: cfg.secretAccessKey,
  };
};

const parseVaultConfig = (row: any): VaultConfig => {
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

const parseAzureConfig = (row: any): AzureConfig => {
  const cfg = rawConfig(row);
  return {
    vaultUrl: row.endpoint_url || cfg.vaultUrl,
    tenantId: cfg.tenantId,
    clientId: cfg.clientId,
    clientSecret: unseal(cfg.clientSecret) || undefined,
    authorityHost: cfg.authorityHost,
  };
};

export const getPkiConnectors = async (req: Request, res: Response) => {
  try {
    const { tenant } = req.query;
    let query = 'SELECT * FROM pki_connectors';
    const params: any[] = [];

    if (tenant && typeof tenant === 'string' && tenant.trim()) {
      query += ' WHERE LOWER(tenant_name) = LOWER($1)';
      params.push(tenant.trim());
    }

    query += ' ORDER BY created_at DESC';
    const result = await pool.query(query, params);

    // Auto-syndicate connectors into CBOM assets if not already syndicated
    for (const c of result.rows) {
      pool.query("SELECT COUNT(*) FROM assets WHERE source IN ('cloud_kms', 'enterprise_pki') AND (source_ref = $1 OR source_ref = $2)", [c.id, c.name])
        .then(chk => {
          if (parseInt(chk.rows[0]?.count || '0', 10) === 0) {
            executeDiscoverySync(c.id, c.tenant_name, c.provider, c.name).catch(() => {});
          }
        }).catch(() => {});
    }

    res.json(result.rows);
  } catch (err: any) {
    console.error('Error fetching PKI connectors:', err);
    res.status(500).json({ error: 'Failed to retrieve PKI connectors.' });
  }
};

export const createPkiConnector = async (req: Request, res: Response) => {
  try {
    const {
      tenantName = 'SPINOVATIONCORP',
      name,
      provider, // 'aws_kms', 'azure_keyvault', 'hashicorp_vault', 'ad_cs'
      endpointUrl,
      authType = 'token',
      config = {}
    } = req.body;

    if (!name || !provider) {
      return res.status(400).json({ error: 'Connector name and provider type are required.' });
    }

    const id = 'conn-' + crypto.randomUUID().substring(0, 10);
    const cleanTenant = tenantName.toUpperCase().trim();

    // Credentials that real discovery needs (Vault token / AppRole secret_id,
    // Azure client secret) are encrypted at rest; other secret-ish fields are
    // masked. Prefer keyless auth (AWS role, Azure managed identity) and omit
    // secrets entirely where possible.
    const sanitizedConfig = { ...config };
    if (sanitizedConfig.token) sanitizedConfig.token = seal(String(sanitizedConfig.token));
    if (sanitizedConfig.secretId) sanitizedConfig.secretId = seal(String(sanitizedConfig.secretId));
    if (sanitizedConfig.clientSecret) sanitizedConfig.clientSecret = seal(String(sanitizedConfig.clientSecret));
    if (sanitizedConfig.secretKey) sanitizedConfig.secretKey = '••••••••' + String(sanitizedConfig.secretKey).slice(-4);

    await pool.query(`
      INSERT INTO pki_connectors (
        id, tenant_name, name, provider, endpoint_url, auth_type, config_summary, 
        sync_status, total_keys_discovered, vulnerable_keys_count, pqc_ready_count, last_sync_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', 0, 0, 0, NOW())
    `, [id, cleanTenant, name, provider, endpointUrl || '', authType, JSON.stringify(sanitizedConfig)]);

    // Trigger initial discovery sync. If it fails (e.g. bad credentials), keep the
    // connector (marked errored by executeDiscoverySync) rather than failing the
    // whole create, and report the warning.
    try {
      const result = await executeDiscoverySync(id, cleanTenant, provider, name);
      return res.status(201).json({
        success: true,
        connectorId: id,
        totalKeysDiscovered: result.total,
        message: `Connector '${name}' (${provider}) enrolled; discovered ${result.total} keys.`
      });
    } catch (syncErr: any) {
      return res.status(201).json({
        success: true,
        connectorId: id,
        warning: `Connector saved, but initial discovery failed: ${syncErr.message}. Fix the configuration and re-sync.`
      });
    }
  } catch (err: any) {
    console.error('Error creating PKI connector:', err);
    res.status(500).json({ error: 'Failed to create PKI connector: ' + err.message });
  }
};

export const testPkiConnector = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const lookup = await pool.query('SELECT * FROM pki_connectors WHERE id = $1', [id]);
    if (lookup.rowCount === 0) {
      return res.status(404).json({ error: 'Connector not found.' });
    }
    const c = lookup.rows[0];

    // Real reachability + auth check for implemented providers.
    if (REAL_PROVIDERS.has(c.provider)) {
      const started = Date.now();
      try {
        let r: { message: string; region?: string };
        if (c.provider === 'aws_kms') r = await pingKms(parseKmsConfig(c));
        else if (c.provider === 'hashicorp_vault') r = await pingVault(parseVaultConfig(c));
        else r = await pingAzure(parseAzureConfig(c));
        return res.json({
          success: true, connectorId: id, provider: c.provider, endpoint: c.endpoint_url,
          status: 'HEALTHY', latencyMs: Date.now() - started, region: (r as any).region, message: r.message,
        });
      } catch (e: any) {
        return res.status(502).json({
          success: false, connectorId: id, provider: c.provider, status: 'UNREACHABLE',
          error: `${c.provider} check failed: ${e.name || 'Error'}: ${e.message}`,
        });
      }
    }

    // AD CS is push-based (the on-prem agent reports). Report its ingest status.
    if (c.provider === 'ad_cs') {
      return res.json({
        success: true, connectorId: id, provider: c.provider, status: 'AGENT-REPORTED',
        lastReportAt: c.last_sync_at,
        keysDiscovered: c.total_keys_discovered,
        message: c.total_keys_discovered > 0
          ? `AD CS inventory last reported by the host agent at ${c.last_sync_at}.`
          : 'Awaiting the first AD CS report from an enrolled host agent (run the agent with --adcs on a domain-joined Windows host).',
      });
    }

    // Preview providers: not yet implemented. Be honest rather than fake healthy.
    res.json({
      success: true, connectorId: id, provider: c.provider, endpoint: c.endpoint_url,
      status: 'PREVIEW',
      message: `${c.provider} is a preview connector; live reachability testing is not yet implemented for it.`,
    });
  } catch (err: any) {
    console.error('Error testing connector:', err);
    res.status(500).json({ error: 'Connector diagnostic test failed: ' + err.message });
  }
};

export const syncPkiConnector = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const lookup = await pool.query('SELECT * FROM pki_connectors WHERE id = $1', [id]);
    if (lookup.rowCount === 0) {
      return res.status(404).json({ error: 'Connector not found.' });
    }
    const c = lookup.rows[0];

    // Execute synchronization
    const result = await executeDiscoverySync(id, c.tenant_name, c.provider, c.name);

    res.json({
      success: true,
      connectorId: id,
      totalKeysDiscovered: result.total,
      vulnerableKeys: result.vulnerable,
      pqcReadyKeys: result.pqcReady,
      message: `Successfully synchronized ${c.name}. Cataloged ${result.total} cryptographic keys (${result.vulnerable} vulnerable to Shor's algorithm).`
    });
  } catch (err: any) {
    console.error('Error syncing connector:', err);
    res.status(500).json({ error: 'Failed to synchronize connector: ' + err.message });
  }
};

export const deletePkiConnector = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const lookup = await pool.query('SELECT * FROM pki_connectors WHERE id = $1', [id]);
    if (lookup.rowCount === 0) {
      return res.status(404).json({ error: 'Connector not found.' });
    }
    const c = lookup.rows[0];

    await pool.query('DELETE FROM pki_synced_assets WHERE connector_id = $1', [id]);
    await pool.query("DELETE FROM assets WHERE source IN ('cloud_kms', 'enterprise_pki') AND (source_ref = $1 OR source_ref = $2)", [c.id, c.name]).catch(() => {});
    await pool.query('DELETE FROM pki_connectors WHERE id = $1', [id]);

    res.json({ success: true, message: 'Connector and all associated cryptographic assets deleted.' });
  } catch (err: any) {
    console.error('Error deleting connector:', err);
    res.status(500).json({ error: 'Failed to delete connector.' });
  }
};

export const getPkiSyncedAssets = async (req: Request, res: Response) => {
  try {
    const { tenant, connectorId, limit = 100 } = req.query;
    let query = 'SELECT a.*, c.name as connector_name, c.provider FROM pki_synced_assets a JOIN pki_connectors c ON c.id = a.connector_id';
    const params: any[] = [];

    if (tenant && typeof tenant === 'string' && tenant.trim()) {
      query += ' WHERE LOWER(a.tenant_name) = LOWER($' + (params.length + 1) + ')';
      params.push(tenant.trim());
    }

    if (connectorId && typeof connectorId === 'string' && connectorId.trim()) {
      query += (params.length > 0 ? ' AND' : ' WHERE') + ' a.connector_id = $' + (params.length + 1);
      params.push(connectorId.trim());
    }

    query += ' ORDER BY a.is_vulnerable DESC, a.created_at DESC LIMIT $' + (params.length + 1);
    params.push(Number(limit) || 100);

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err: any) {
    console.error('Error fetching PKI assets:', err);
    res.status(500).json({ error: 'Failed to retrieve synced cryptographic assets.' });
  }
};

// ==============================================================================
// AD CS AGENT REPORT (Phase 3): on-prem Windows agent pushes CA inventory here.
// Authenticated by a fleet enrollment token (resolves the tenant); persists the
// reported CA certs / templates as real assets under a per-tenant ad_cs connector.
// ==============================================================================
const resolveTenantFromToken = async (token: string): Promise<string | null> => {
  if (!token) return null;
  const t = token.trim();
  const ft = await pool.query('SELECT tenant_name FROM fleet_tokens WHERE token = $1', [t]);
  if (ft.rowCount && ft.rows[0].tenant_name) return ft.rows[0].tenant_name;
  const lic = await pool.query("SELECT tenant_name FROM admin_licenses WHERE UPPER(TRIM(license_key)) = UPPER(TRIM($1)) AND status != 'revoked'", [t]);
  if (lic.rowCount && lic.rows[0].tenant_name) return lic.rows[0].tenant_name;
  return null;
};

export const reportAdcs = async (req: Request, res: Response) => {
  try {
    let token = (req.headers['x-connector-token'] as string) || '';
    const auth = req.headers['authorization'];
    if (!token && auth && auth.startsWith('Bearer ')) token = auth.slice(7);
    if (!token && req.body.token) token = req.body.token;
    if (!token) return res.status(401).json({ error: 'Fleet enrollment token required.' });

    const tenant = await resolveTenantFromToken(token);
    if (!tenant) return res.status(401).json({ error: 'Invalid or unrecognized enrollment token.' });

    const { caName, assets } = req.body;
    if (!Array.isArray(assets)) return res.status(400).json({ error: 'Expected an assets array.' });

    // Find-or-create the tenant's AD CS connector (one per reported CA host).
    const connName = `AD CS: ${caName || 'Enterprise CA'}`;
    const existing = await pool.query(
      "SELECT id FROM pki_connectors WHERE provider = 'ad_cs' AND LOWER(tenant_name) = LOWER($1) AND name = $2 LIMIT 1",
      [tenant, connName]
    );
    let connectorId: string;
    if (existing.rowCount && existing.rows[0].id) {
      connectorId = existing.rows[0].id;
    } else {
      connectorId = 'conn-' + crypto.randomUUID().substring(0, 10);
      await pool.query(
        `INSERT INTO pki_connectors (id, tenant_name, name, provider, endpoint_url, auth_type, config_summary,
           sync_status, total_keys_discovered, vulnerable_keys_count, pqc_ready_count, last_sync_at)
         VALUES ($1, $2, $3, 'ad_cs', $4, 'agent', '{}', 'active', 0, 0, 0, NOW())`,
        [connectorId, tenant, connName, caName || '']
      );
    }

    // Normalize agent-reported assets to the DiscoveredAsset shape and persist.
    const norm: DiscoveredAsset[] = assets.map((a: any) => ({
      name: String(a.name || 'Unknown AD CS object'),
      type: a.type || (a.isTemplate ? 'template' : 'ca_root'),
      algo: String(a.algo || a.algorithm || 'unknown'),
      size: Number(a.size || a.keySize || 0),
      vuln: a.vuln !== undefined ? !!a.vuln : /^(rsa|ecdsa|ecc|ec|dsa|ed25519)/i.test(String(a.algo || '')),
      risk: a.risk || 'high',
      threat: String(a.threat || 'AD CS-issued classical key; vulnerable to a CRQC.'),
      rot: !!a.rot,
      expiresAt: a.expiresAt ? new Date(a.expiresAt) : null,
    }));

    // A fresh report replaces the connector's inventory (idempotent re-reports).
    await pool.query('DELETE FROM pki_synced_assets WHERE connector_id = $1', [connectorId]);
    await pool.query("DELETE FROM assets WHERE source = 'enterprise_pki' AND (source_ref = $1 OR source_ref = $2)", [connectorId, connName]).catch(() => {});

    const result = await persistAssets(connectorId, tenant, 'ad_cs', connName, norm);
    return res.json({ success: true, connectorId, tenant, ...result, message: `Ingested ${result.total} AD CS objects.` });
  } catch (err: any) {
    console.error('Error ingesting AD CS report:', err);
    res.status(500).json({ error: 'Failed to ingest AD CS report: ' + err.message });
  }
};

/** Recompute a connector's summary counts from its currently-stored assets. */
async function recomputeConnectorCounts(connectorId: string) {
  const r = await pool.query(
    `SELECT COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE is_vulnerable)::int AS vuln,
            COUNT(*) FILTER (WHERE NOT is_vulnerable)::int AS pqc
     FROM pki_synced_assets WHERE connector_id = $1`,
    [connectorId]
  );
  const { total = 0, vuln = 0, pqc = 0 } = r.rows[0] || {};
  await pool.query(
    `UPDATE pki_connectors SET total_keys_discovered = $1, vulnerable_keys_count = $2, pqc_ready_count = $3, sync_status = 'active' WHERE id = $4`,
    [total, vuln, pqc, connectorId]
  );
  return { total, vulnerable: vuln, pqcReady: pqc };
}

// ==============================================================================
// DISCOVERY WORKER ENGINE
// ==============================================================================
async function executeDiscoverySync(connectorId: string, tenantName: string, provider: string, connectorName: string) {
  // AD CS is discovered on-prem by the host agent and pushed to the server
  // (POST /api/scan/adcs/report). There is no server-side pull, so a "sync" here
  // must NOT clear or fabricate data — it recomputes counts from whatever the
  // agent last reported.
  if (provider === 'ad_cs') {
    return recomputeConnectorCounts(connectorId);
  }

  // Clear old assets for this connector
  await pool.query('DELETE FROM pki_synced_assets WHERE connector_id = $1', [connectorId]);
  await pool.query("DELETE FROM assets WHERE source IN ('cloud_kms', 'enterprise_pki') AND (source_ref = $1 OR source_ref = $2)", [connectorId, connectorName]).catch(() => {});

  // Real discovery for implemented providers (AWS KMS). On error we record the
  // failure on the connector and surface zero assets rather than faking success.
  if (REAL_PROVIDERS.has(provider)) {
    const row = (await pool.query('SELECT config_summary, endpoint_url FROM pki_connectors WHERE id = $1', [connectorId])).rows[0] || {};
    try {
      let assets: DiscoveredAsset[] = [];
      if (provider === 'aws_kms') assets = await discoverKmsKeys(parseKmsConfig(row));
      else if (provider === 'hashicorp_vault') assets = await discoverVaultKeys(parseVaultConfig(row));
      else if (provider === 'azure_keyvault') assets = await discoverAzureKeys(parseAzureConfig(row));
      return await persistAssets(connectorId, tenantName, provider, connectorName, assets);
    } catch (e: any) {
      await pool.query(
        `UPDATE pki_connectors SET sync_status = 'error', last_error = $1, last_sync_at = NOW() WHERE id = $2`,
        [`${e.name || 'Error'}: ${e.message}`.slice(0, 480), connectorId]
      );
      throw e;
    }
  }

  // Preview providers: simulated inventory (clearly labeled downstream).
  const mockAssets = mockAssetsFor(provider);
  return persistAssets(connectorId, tenantName, provider, connectorName, mockAssets);
}

function mockAssetsFor(provider: string): DiscoveredAsset[] {
  let mockAssets: any[] = [];

  if (provider === 'aws_kms') {
    mockAssets = [
      { name: 'alias/prod-payment-envelope-key', type: 'asymmetric_key', algo: 'RSA-2048', size: 2048, vuln: true, risk: 'critical', threat: "Shor's algorithm factorization. Threat to envelope encryption.", rot: false },
      { name: 'alias/user-auth-jwt-signing-key', type: 'asymmetric_key', algo: 'ECDSA-P256', size: 256, vuln: true, risk: 'critical', threat: "Discrete logarithm factorization on CRQC. Signature forgery risk.", rot: true },
      { name: 'alias/database-storage-ebs-master', type: 'symmetric_key', algo: 'AES-256-GCM', size: 256, vuln: false, risk: 'secure', threat: "Grover resistant (128-bit quantum security strength).", rot: true },
      { name: 'alias/pqc-kem-hybrid-channel', type: 'asymmetric_key', algo: 'ML-KEM-768 + X25519', size: 768, vuln: false, risk: 'secure', threat: "NIST FIPS 203 Post-Quantum Resilient.", rot: true },
      { name: 'alias/backup-glacier-vault-key', type: 'asymmetric_key', algo: 'RSA-4096', size: 4096, vuln: true, risk: 'high', threat: "Shor factorization on CRQC. Archive HNDL risk.", rot: false }
    ];
  } else if (provider === 'azure_keyvault') {
    mockAssets = [
      { name: 'ssl-public-ingress-cert', type: 'certificate', algo: 'RSA-2048', size: 2048, vuln: true, risk: 'critical', threat: "Web ingress certificate breakable by Shor's algorithm.", rot: true },
      { name: 'data-lake-encryption-key', type: 'symmetric_key', algo: 'AES-256-CBC', size: 256, vuln: false, risk: 'secure', threat: "Quantum safe against Grover attacks.", rot: true },
      { name: 'azure-ad-saml-signing-cert', type: 'certificate', algo: 'ECDSA-P384', size: 384, vuln: true, risk: 'critical', threat: "Identity token forgery by Shor CRQC.", rot: false },
      { name: 'azure-pqc-composite-sig', type: 'asymmetric_key', algo: 'ML-DSA-65', size: 1952, vuln: false, risk: 'secure', threat: "NIST FIPS 204 Post-Quantum Digital Signature.", rot: true }
    ];
  } else if (provider === 'hashicorp_vault') {
    mockAssets = [
      { name: 'pki_v1/ca/intermediate-pki-ca', type: 'ca_root', algo: 'RSA-4096', size: 4096, vuln: true, risk: 'critical', threat: "Intermediate CA private key compromisable by CRQC.", rot: false },
      { name: 'transit/keys/customer-credit-card-token', type: 'symmetric_key', algo: 'AES-256-GCM96', size: 256, vuln: false, risk: 'secure', threat: "Quantum resistant symmetric cipher.", rot: true },
      { name: 'transit/keys/api-webhook-hmac', type: 'symmetric_key', algo: 'HMAC-SHA256', size: 256, vuln: false, risk: 'secure', threat: "Quantum safe MAC construction.", rot: true },
      { name: 'pki_v1/issue/internal-microservices', type: 'template', algo: 'RSA-2048', size: 2048, vuln: true, risk: 'critical', threat: "Issues short-lived classical RSA certs to fleet.", rot: false }
    ];
  } else {
    // ad_cs
    mockAssets = [
      { name: 'Active Directory Root Certification Authority', type: 'ca_root', algo: 'RSA-4096', size: 4096, vuln: true, risk: 'critical', threat: "Enterprise trust root breakable by Shor's algorithm.", rot: false },
      { name: 'Kerberos KDC Authentication Template', type: 'template', algo: 'RSA-2048', size: 2048, vuln: true, risk: 'critical', threat: "Domain Controller authentication forgery.", rot: false },
      { name: 'Code Signing Enterprise Policy Template', type: 'template', algo: 'RSA-2048', size: 2048, vuln: true, risk: 'critical', threat: "Allows malicious binary signature forgery by quantum actors.", rot: false },
      { name: 'Workstation Computer Enrollment Template', type: 'template', algo: 'ECDSA-P256', size: 256, vuln: true, risk: 'high', threat: "Client certificate authentication compromised.", rot: true }
    ];
  }

  return mockAssets.map(a => ({ ...a, expiresAt: null })) as DiscoveredAsset[];
}

async function persistAssets(connectorId: string, tenantName: string, provider: string, connectorName: string, assets: DiscoveredAsset[]) {
  let vuln = 0;
  let pqc = 0;
  const sourceType = provider === 'ad_cs' ? 'enterprise_pki' : 'cloud_kms';

  for (const a of assets) {
    if (a.vuln) vuln++;
    else pqc++;

    const pkiAssetId = 'ast-' + crypto.randomUUID().substring(0, 8);
    const cbomAssetId = ('ast-pki-' + crypto.randomUUID()).substring(0, 64);

    await pool.query(`
      INSERT INTO pki_synced_assets (
        id, connector_id, tenant_name, asset_name, asset_type, algorithm,
        key_size, is_vulnerable, risk_level, quantum_threat, status, rotation_enabled, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'Active', $11, COALESCE($12, NOW() + INTERVAL '365 days'))
    `, [
      pkiAssetId,
      connectorId,
      tenantName,
      a.name,
      a.type,
      a.algo,
      a.size,
      a.vuln,
      a.risk,
      a.threat,
      a.rot,
      a.expiresAt || null
    ]);

    // Syndicate into central assets inventory for unified CBOM & source filtering
    await pool.query(`
      INSERT INTO assets (
        id, type, name, path, algorithm, key_size, is_vulnerable, risk_level, status, description, recommendation, source, source_ref, tenant_name
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, $10, $11, $12, $13)
      ON CONFLICT (id) DO UPDATE SET 
        name = EXCLUDED.name,
        path = EXCLUDED.path,
        algorithm = EXCLUDED.algorithm,
        tenant_name = EXCLUDED.tenant_name
    `, [
      cbomAssetId,
      a.type,
      a.name,
      `${provider.toUpperCase()}://${a.name}`,
      a.algo,
      a.size,
      a.vuln,
      a.risk,
      a.threat,
      a.vuln ? "Rotate to Post-Quantum Kyber / Dilithium (FIPS 203/204) immediately." : "Quantum safe. Meets CNSA 2.0 / FIPS standards.",
      sourceType,
      connectorName,
      tenantName
    ]).catch(err => {
      console.warn('Failed to syndicate PKI asset to CBOM:', err);
    });
  }

  // Update connector summary
  await pool.query(`
    UPDATE pki_connectors
    SET 
      total_keys_discovered = $1,
      vulnerable_keys_count = $2,
      pqc_ready_count = $3,
      sync_status = 'active',
      last_sync_at = NOW(),
      last_error = NULL
    WHERE id = $4
  `, [assets.length, vuln, pqc, connectorId]);

  return { total: assets.length, vulnerable: vuln, pqcReady: pqc };
}
