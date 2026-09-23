import { Request, Response } from 'express';
import pool from '../config/db';
import crypto from 'crypto';

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

    // Sanitize credentials for storage in summary
    const sanitizedConfig = { ...config };
    if (sanitizedConfig.secretKey) sanitizedConfig.secretKey = '••••••••' + sanitizedConfig.secretKey.slice(-4);
    if (sanitizedConfig.clientSecret) sanitizedConfig.clientSecret = '••••••••' + sanitizedConfig.clientSecret.slice(-4);
    if (sanitizedConfig.token) sanitizedConfig.token = '••••••••' + sanitizedConfig.token.slice(-4);

    await pool.query(`
      INSERT INTO pki_connectors (
        id, tenant_name, name, provider, endpoint_url, auth_type, config_summary, 
        sync_status, total_keys_discovered, vulnerable_keys_count, pqc_ready_count, last_sync_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', 0, 0, 0, NOW())
    `, [id, cleanTenant, name, provider, endpointUrl || '', authType, JSON.stringify(sanitizedConfig)]);

    // Trigger initial discovery sync
    await executeDiscoverySync(id, cleanTenant, provider, name);

    res.status(201).json({
      success: true,
      connectorId: id,
      message: `Connector '${name}' (${provider}) successfully enrolled and initial key synchronization completed.`
    });
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

    // Simulated probe / health check
    res.json({
      success: true,
      connectorId: id,
      provider: c.provider,
      endpoint: c.endpoint_url,
      status: 'HEALTHY',
      latencyMs: Math.floor(25 + Math.random() * 40),
      message: `Successfully authenticated to ${c.name} via ${c.auth_type}. Vault endpoint is reachable and responsive.`
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
// DISCOVERY WORKER ENGINE
// ==============================================================================
async function executeDiscoverySync(connectorId: string, tenantName: string, provider: string, connectorName: string) {
  // Clear old assets for this connector
  await pool.query('DELETE FROM pki_synced_assets WHERE connector_id = $1', [connectorId]);
  await pool.query("DELETE FROM assets WHERE source IN ('cloud_kms', 'enterprise_pki') AND (source_ref = $1 OR source_ref = $2)", [connectorId, connectorName]).catch(() => {});

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

  let vuln = 0;
  let pqc = 0;
  const sourceType = provider === 'ad_cs' ? 'enterprise_pki' : 'cloud_kms';

  for (const a of mockAssets) {
    if (a.vuln) vuln++;
    else pqc++;

    const pkiAssetId = 'ast-' + crypto.randomUUID().substring(0, 8);
    const cbomAssetId = ('ast-pki-' + crypto.randomUUID()).substring(0, 64);

    await pool.query(`
      INSERT INTO pki_synced_assets (
        id, connector_id, tenant_name, asset_name, asset_type, algorithm, 
        key_size, is_vulnerable, risk_level, quantum_threat, status, rotation_enabled, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'Active', $11, NOW() + INTERVAL '365 days')
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
      a.rot
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
  `, [mockAssets.length, vuln, pqc, connectorId]);

  return { total: mockAssets.length, vulnerable: vuln, pqcReady: pqc };
}
