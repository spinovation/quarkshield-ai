import React, { useState, useEffect } from 'react';
import { 
  Server, 
  Key, 
  RefreshCw, 
  Plus, 
  Trash2, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldAlert, 
  ShieldCheck, 
  ExternalLink, 
  Search, 
  Cpu, 
  Lock, 
  Database,
  Cloud,
  ChevronRight,
  Info
} from 'lucide-react';

interface PkiConnector {
  id: string;
  tenant_name: string;
  name: string;
  provider: 'aws_kms' | 'azure_keyvault' | 'hashicorp_vault' | 'ad_cs';
  endpoint_url: string;
  auth_type: string;
  config_summary: any;
  sync_status: string;
  total_keys_discovered: number;
  vulnerable_keys_count: number;
  pqc_ready_count: number;
  last_sync_at: string;
  last_error?: string;
}

interface SyncedAsset {
  id: string;
  connector_id: string;
  connector_name: string;
  provider: string;
  asset_name: string;
  asset_type: string;
  algorithm: string;
  key_size?: number;
  is_vulnerable: boolean;
  risk_level: string;
  quantum_threat: string;
  status: string;
  rotation_enabled: boolean;
  expires_at?: string;
}

export const EnterprisePkiVaults: React.FC<{ tenantName?: string; onAssetsChanged?: () => void }> = ({ onAssetsChanged }) => {
  const [connectors, setConnectors] = useState<PkiConnector[]>([]);
  const [assets, setAssets] = useState<SyncedAsset[]>([]);
  const [loading, setLoading] = useState(false);
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedProvider, setSelectedProvider] = useState<string>('all');
  const [showAddModal, setShowAddModal] = useState(false);
  const [notification, setNotification] = useState<{ msg: string; type: 'success' | 'error' } | null>(null);

  // Form State for new connector
  const [connName, setConnName] = useState('');
  const [connProvider, setConnProvider] = useState<'aws_kms' | 'azure_keyvault' | 'hashicorp_vault' | 'ad_cs'>('aws_kms');
  const [connEndpoint, setConnEndpoint] = useState('');
  const [connAuthType, setConnAuthType] = useState('iam_role');
  const [awsRegion, setAwsRegion] = useState('us-east-1');
  const [awsRoleArn, setAwsRoleArn] = useState('');
  const [awsAccessKeyId, setAwsAccessKeyId] = useState('');
  const [awsSecretAccessKey, setAwsSecretAccessKey] = useState('');
  const [azureTenantId, setAzureTenantId] = useState('');
  const [azureClientId, setAzureClientId] = useState('');
  const [azureClientSecret, setAzureClientSecret] = useState('');
  const [vaultToken, setVaultToken] = useState('');
  const [vaultRoleId, setVaultRoleId] = useState('');
  const [vaultSecretId, setVaultSecretId] = useState('');
  const [vaultPkiMount, setVaultPkiMount] = useState('');
  const [adCsCaName, setAdCsCaName] = useState('');

  // Clear any entered secrets from component state (hygiene: never keep plaintext
  // creds in memory longer than the submit that sends them).
  const resetConnectorForm = () => {
    setConnName('');
    setConnEndpoint('');
    setAwsRoleArn('');
    setAwsAccessKeyId('');
    setAwsSecretAccessKey('');
    setAzureTenantId('');
    setAzureClientId('');
    setAzureClientSecret('');
    setVaultToken('');
    setVaultRoleId('');
    setVaultSecretId('');
    setVaultPkiMount('');
    setAdCsCaName('');
  };

  const fetchConnectors = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/pki/connectors');
      if (res.ok) {
        const data = await res.json();
        setConnectors(data);
      }
    } catch (err) {
      console.error('Error fetching connectors:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchAssets = async () => {
    try {
      const res = await fetch('/api/pki/assets');
      if (res.ok) {
        const data = await res.json();
        setAssets(data);
      }
    } catch (err) {
      console.error('Error fetching PKI assets:', err);
    }
  };

  useEffect(() => {
    fetchConnectors();
    fetchAssets();
  }, []);

  const handleSync = async (id: string, name: string) => {
    try {
      setSyncingId(id);
      const res = await fetch(`/api/pki/connectors/${id}/sync`, { method: 'POST' });
      const data = await res.json();
      if (res.ok && data.success) {
        setNotification({ msg: `Synchronized ${name}: Discovered ${data.totalKeysDiscovered} keys (${data.vulnerableKeys} vulnerable).`, type: 'success' });
        fetchConnectors();
        fetchAssets();
        onAssetsChanged?.(); // Refresh parent CBOM (synced keys/certs persisted with source='enterprise_pki'/'cloud_kms')
      } else {
        throw new Error(data.error || 'Sync failed');
      }
    } catch (err: any) {
      setNotification({ msg: err.message, type: 'error' });
    } finally {
      setSyncingId(null);
      setTimeout(() => setNotification(null), 4000);
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!window.confirm(`Are you sure you want to delete connector '${name}'? This will remove all associated inventory assets.`)) return;
    try {
      const res = await fetch(`/api/pki/connectors/${id}`, { method: 'DELETE' });
      if (res.ok) {
        setNotification({ msg: `Connector '${name}' deleted.`, type: 'success' });
        fetchConnectors();
        fetchAssets();
        onAssetsChanged?.(); // Connector delete removes its inventory assets from CBOM too
      }
    } catch (err: any) {
      setNotification({ msg: err.message, type: 'error' });
    }
  };

  const handleCreateConnector = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!connName) return;

    // AD CS is agent-based (pushed by a domain-joined host agent), not an
    // agentless pull connector — the backend rejects a console enrollment. Guard
    // here too so the form never POSTs a connector that would look successful but
    // sync to zero keys.
    if (connProvider === 'ad_cs') {
      alert('Microsoft AD CS is agent-based. Run the QuarkShield agent with --adcs on the CA host; it reports its inventory automatically and the connector appears here once it does.');
      return;
    }

    try {
      // Credential/config keys must match the server-side parsers
      // (parseKmsConfig / parseAzureConfig / parseVaultConfig), which read
      // camelCase. Only send secrets the user actually provided — the backend
      // seal()-encrypts accessKeyId/secretAccessKey/clientSecret/token/secretId
      // at rest and never logs them.
      const config: any = {};
      // Endpoint is derived per provider (see below), not hardcoded.
      let endpointUrl = connEndpoint.trim();

      if (connProvider === 'aws_kms') {
        const region = awsRegion.trim() || 'us-east-1';
        config.region = region;
        // role_arn is genuinely optional now — only sent when the user supplies
        // one (no fake placeholder). Static access keys authenticate the plain VPS
        // pod, which has no AWS identity of its own.
        if (awsRoleArn.trim()) config.roleArn = awsRoleArn.trim();
        if (awsAccessKeyId.trim()) config.accessKeyId = awsAccessKeyId.trim();
        if (awsSecretAccessKey.trim()) config.secretAccessKey = awsSecretAccessKey.trim();
        // Display the real regional endpoint derived from the selected region,
        // not a hardcoded us-east-1 URL (which also wrongly pinned the SDK call).
        endpointUrl = `https://kms.${region}.amazonaws.com`;
      } else if (connProvider === 'azure_keyvault') {
        config.tenantId = azureTenantId.trim();
        config.clientId = azureClientId.trim();
        if (azureClientSecret.trim()) config.clientSecret = azureClientSecret.trim();
        // The vault URL IS the endpoint for Azure.
        endpointUrl = connEndpoint.trim();
      } else if (connProvider === 'hashicorp_vault') {
        if (vaultToken.trim()) config.token = vaultToken.trim();
        // AppRole is an alternative to a static token (role_id + secret_id).
        if (vaultRoleId.trim()) config.roleId = vaultRoleId.trim();
        if (vaultSecretId.trim()) config.secretId = vaultSecretId.trim();
        // Optional PKI mount: classifies issuer CA certs, which is what actually
        // drives `trusts` edges to hosts (transit keys alone do not).
        if (vaultPkiMount.trim()) config.pkiMount = vaultPkiMount.trim();
        endpointUrl = connEndpoint.trim();
      }

      const res = await fetch('/api/pki/connectors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: connName,
          provider: connProvider,
          endpointUrl,
          authType: connAuthType,
          config
        })
      });

      const data = await res.json();
      if (res.ok) {
        setShowAddModal(false);
        setNotification({ msg: data.warning || data.message, type: data.warning ? 'error' : 'success' });
        resetConnectorForm();
        fetchConnectors();
        fetchAssets();
      } else {
        throw new Error(data.error || 'Failed to create connector');
      }
    } catch (err: any) {
      alert('Error creating connector: ' + err.message);
    }
  };

  // Connectors that synced keys but no CA/issuer certificates. Trust (`trusts`)
  // edges in the Threat & Risk Graph only form from CA/issuer certs that hosts'
  // certificates chain to, so a key-only sync legitimately produces zero arrows.
  const CA_ASSET_TYPES = new Set(['ca_root', 'certificate']);
  const connectorHasCaCert = (connectorId: string): boolean =>
    assets.some(a => a.connector_id === connectorId && CA_ASSET_TYPES.has(a.asset_type));

  // Metrics
  const totalKeys = connectors.reduce((acc, c) => acc + (c.total_keys_discovered || 0), 0);
  const totalVulnerable = connectors.reduce((acc, c) => acc + (c.vulnerable_keys_count || 0), 0);
  const totalPqc = connectors.reduce((acc, c) => acc + (c.pqc_ready_count || 0), 0);

  // Filtered assets
  const filteredAssets = assets.filter(a => {
    const matchSearch = searchQuery === '' || 
      a.asset_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.algorithm.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.connector_name.toLowerCase().includes(searchQuery.toLowerCase());
    const matchProv = selectedProvider === 'all' || a.provider === selectedProvider;
    return matchSearch && matchProv;
  });

  const getProviderIcon = (provider: string) => {
    switch (provider) {
      case 'aws_kms': return <Cloud size={16} color="#f59e0b" />;
      case 'azure_keyvault': return <Cloud size={16} color="#0284c7" />;
      case 'hashicorp_vault': return <Lock size={16} color="#a855f7" />;
      case 'ad_cs': return <Server size={16} color="#3b82f6" />;
      default: return <Database size={16} color="var(--accent-cyan)" />;
    }
  };

  const getProviderLabel = (provider: string) => {
    switch (provider) {
      case 'aws_kms': return 'AWS KMS & Secrets';
      case 'azure_keyvault': return 'Azure Key Vault';
      case 'hashicorp_vault': return 'HashiCorp Vault';
      case 'ad_cs': return 'Microsoft AD CS';
      default: return provider;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header Banner */}
      <div className="glass-panel" style={{ padding: '1.5rem 1.75rem', border: '1px solid rgba(0, 242, 254, 0.2)', position: 'relative', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', top: 0, left: 0, bottom: 0, width: '4px', background: 'var(--accent-cyan)' }} />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
              <Server size={22} color="var(--accent-cyan)" />
              <h2 style={{ margin: 0, fontSize: '1.35rem', color: '#ffffff', fontWeight: 700 }}>
                Enterprise PKI &amp; Cloud Vault Connectors
              </h2>
              <span style={{ fontSize: '0.7rem', padding: '0.15rem 0.5rem', borderRadius: '4px', background: 'rgba(0, 242, 254, 0.15)', color: 'var(--accent-cyan)', border: '1px solid rgba(0, 242, 254, 0.3)', fontWeight: 600 }}>
                AGENTLESS CRYPTO DISCOVERY
              </span>
            </div>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.86rem', maxWidth: '850px', lineHeight: 1.5 }}>
              Agentless cryptographic discovery for <strong>AWS KMS</strong>, <strong>Azure Key Vault</strong>, and <strong>HashiCorp Vault</strong>, plus agent-reported <strong>Microsoft AD CS</strong>. Continuously catalogs enterprise roots of trust, asymmetric key pairs, and certificate templates to evaluate quantum risk.
            </p>
            <div style={{ marginTop: '0.75rem', display: 'flex', gap: '0.45rem', alignItems: 'flex-start', fontSize: '0.74rem', color: 'var(--text-muted)', lineHeight: 1.5, maxWidth: '850px' }}>
              <Info size={13} style={{ flexShrink: 0, marginTop: '0.1rem' }} />
              <span>
                The cloud console reaches <strong>public cloud endpoints</strong> (AWS/Azure/public Vault). On-prem or firewalled KMS/Vault/AD CS behind a private network can&apos;t be reached from the console — those require agent-side collection. A successful sync populates the inventory and PKI box; <strong>trust</strong> arrows to hosts in the Threat &amp; Risk Graph appear only once the connector syncs the CA/issuer certificates that your hosts&apos; certificates chain to (e.g. a Vault PKI mount or AD CS CA), not from app-level transit/KMS keys alone.
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
            <button
              onClick={() => { fetchConnectors(); fetchAssets(); }}
              className="btn btn-secondary"
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', padding: '0.55rem 0.9rem' }}
            >
              <RefreshCw size={14} className={loading ? 'spin-animation' : ''} /> Refresh
            </button>
            <button
              onClick={() => setShowAddModal(true)}
              className="btn btn-primary"
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', padding: '0.55rem 1rem' }}
            >
              <Plus size={15} /> Add Vault Connector
            </button>
          </div>
        </div>
      </div>

      {/* Notifications */}
      {notification && (
        <div style={{
          padding: '0.75rem 1rem',
          borderRadius: '6px',
          background: notification.type === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
          border: `1px solid ${notification.type === 'success' ? '#10b981' : '#ef4444'}`,
          color: '#ffffff',
          fontSize: '0.85rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}>
          {notification.type === 'success' ? <CheckCircle2 size={16} color="#10b981" /> : <AlertTriangle size={16} color="#ef4444" />}
          {notification.msg}
        </div>
      )}

      {/* Top Metrics Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
        <div className="glass-panel" style={{ padding: '1.25rem', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
            Connected Vaults
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#ffffff', marginTop: '0.35rem' }}>
            {connectors.length}
          </div>
          <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: '0.3rem' }}>
            AWS KMS, Azure KV, HashiCorp &amp; AD CS
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '1.25rem', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
            Discovered Keys &amp; Certs
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--accent-cyan)', marginTop: '0.35rem' }}>
            {totalKeys}
          </div>
          <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: '0.3rem' }}>
            Total centralized cryptographic assets
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '1.25rem', border: '1px solid rgba(239, 68, 68, 0.25)', background: 'rgba(239, 68, 68, 0.03)' }}>
          <div style={{ fontSize: '0.75rem', color: '#f87171', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
            Quantum Vulnerable (Shor)
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#ef4444', marginTop: '0.35rem' }}>
            {totalVulnerable}
          </div>
          <div style={{ fontSize: '0.76rem', color: '#fca5a5', marginTop: '0.3rem' }}>
            Classical RSA/ECC breakable on CRQC
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '1.25rem', border: '1px solid rgba(16, 185, 129, 0.25)', background: 'rgba(16, 185, 129, 0.03)' }}>
          <div style={{ fontSize: '0.75rem', color: '#34d399', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
            PQC Hybrid Resilient
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#10b981', marginTop: '0.35rem' }}>
            {totalPqc}
          </div>
          <div style={{ fontSize: '0.76rem', color: '#6ee7b7', marginTop: '0.3rem' }}>
            NIST FIPS 203/204 &amp; AES-256 compliant
          </div>
        </div>
      </div>

      {/* Connected Vaults Grid */}
      <div>
        <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.05rem', color: '#ffffff', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Database size={17} color="var(--accent-cyan)" /> Configured Enterprise Connectors ({connectors.length})
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '1rem' }}>
          {connectors.map(c => (
            <div key={c.id} className="glass-panel" style={{ padding: '1.25rem', border: '1px solid rgba(255, 255, 255, 0.08)', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {getProviderIcon(c.provider)}
                    <span style={{ fontSize: '0.76rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      {getProviderLabel(c.provider)}
                    </span>
                  </div>
                  <span style={{ 
                    fontSize: '0.68rem', 
                    fontWeight: 700, 
                    padding: '0.15rem 0.5rem', 
                    borderRadius: '12px',
                    background: c.sync_status === 'active' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                    color: c.sync_status === 'active' ? '#34d399' : '#f87171',
                    border: `1px solid ${c.sync_status === 'active' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`
                  }}>
                    {c.sync_status.toUpperCase()}
                  </span>
                </div>

                <div style={{ fontSize: '1rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.35rem' }}>
                  {c.name}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'monospace', wordBreak: 'break-all', marginBottom: '0.85rem' }}>
                  {c.endpoint_url || 'Cloud Default Endpoint'}
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem', background: 'rgba(0,0,0,0.25)', padding: '0.65rem', borderRadius: '6px', marginBottom: '0.85rem', textAlign: 'center' }}>
                  <div>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>TOTAL KEYS</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#ffffff' }}>{c.total_keys_discovered}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.65rem', color: '#f87171' }}>VULNERABLE</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#ef4444' }}>{c.vulnerable_keys_count}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.65rem', color: '#34d399' }}>PQC READY</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#10b981' }}>{c.pqc_ready_count}</div>
                  </div>
                </div>

                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                  Last sync: {c.last_sync_at ? new Date(c.last_sync_at).toLocaleString() : 'Never'}
                </div>

                {c.last_error && c.sync_status !== 'active' && (
                  <div style={{ marginTop: '0.6rem', fontSize: '0.7rem', color: '#fca5a5', background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.25)', borderRadius: '5px', padding: '0.4rem 0.55rem', lineHeight: 1.45, display: 'flex', gap: '0.35rem', alignItems: 'flex-start', wordBreak: 'break-word' }}>
                    <AlertTriangle size={12} style={{ flexShrink: 0, marginTop: '0.1rem' }} />
                    <span>{c.last_error}</span>
                  </div>
                )}

                {c.sync_status === 'active' && c.total_keys_discovered > 0 && c.provider !== 'ad_cs' && !connectorHasCaCert(c.id) && (
                  <div style={{ marginTop: '0.6rem', fontSize: '0.7rem', color: 'var(--text-secondary)', background: 'rgba(59, 130, 246, 0.07)', border: '1px solid rgba(59, 130, 246, 0.22)', borderRadius: '5px', padding: '0.4rem 0.55rem', lineHeight: 1.45, display: 'flex', gap: '0.35rem', alignItems: 'flex-start' }}>
                    <Info size={12} color="#60a5fa" style={{ flexShrink: 0, marginTop: '0.1rem' }} />
                    <span>No CA/issuer certs found — trust relationships to hosts require a PKI/CA source{c.provider === 'hashicorp_vault' ? ' (set a PKI mount on this connector)' : ''}.</span>
                  </div>
                )}
              </div>

              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem', borderTop: '1px solid rgba(255, 255, 255, 0.05)', paddingTop: '0.85rem' }}>
                <button
                  onClick={() => handleSync(c.id, c.name)}
                  disabled={syncingId === c.id}
                  className="btn btn-secondary"
                  style={{ flex: 1, fontSize: '0.78rem', padding: '0.45rem', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '0.35rem' }}
                >
                  <RefreshCw size={13} className={syncingId === c.id ? 'spin-animation' : ''} />
                  {syncingId === c.id ? 'Syncing...' : 'Sync Now'}
                </button>
                <button
                  onClick={() => handleDelete(c.id, c.name)}
                  className="btn btn-secondary"
                  style={{ color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.3)', padding: '0.45rem 0.65rem' }}
                  title="Delete connector"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Discovered Cryptographic Inventory Table */}
      <div className="glass-panel" style={{ padding: '1.5rem', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '1.05rem', color: '#ffffff', fontWeight: 600 }}>
              Discovered Cryptographic Key &amp; Certificate Inventory ({filteredAssets.length})
            </h3>
            <p style={{ margin: '0.2rem 0 0 0', color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
              Real-time catalog of certificates, root CAs, and asymmetric keys discovered across connected vaults.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', width: '220px' }}>
              <Search size={14} style={{ position: 'absolute', left: '10px', top: '10px', color: 'var(--text-muted)' }} />
              <input
                type="text"
                placeholder="Search keys, algorithms..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                style={{
                  width: '100%',
                  padding: '0.45rem 0.75rem 0.45rem 2rem',
                  fontSize: '0.8rem',
                  borderRadius: '6px',
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  color: '#ffffff'
                }}
              />
            </div>

            <select
              value={selectedProvider}
              onChange={e => setSelectedProvider(e.target.value)}
              style={{
                padding: '0.45rem 0.75rem',
                fontSize: '0.8rem',
                borderRadius: '6px',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                color: '#ffffff'
              }}
            >
              <option value="all">All Vault Providers</option>
              <option value="aws_kms">AWS KMS</option>
              <option value="azure_keyvault">Azure Key Vault</option>
              <option value="hashicorp_vault">HashiCorp Vault</option>
              <option value="ad_cs">Microsoft AD CS</option>
            </select>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '0.75rem 0.5rem' }}>Asset / Key Name</th>
                <th style={{ padding: '0.75rem 0.5rem' }}>Vault Source</th>
                <th style={{ padding: '0.75rem 0.5rem' }}>Type</th>
                <th style={{ padding: '0.75rem 0.5rem' }}>Algorithm</th>
                <th style={{ padding: '0.75rem 0.5rem' }}>Quantum Status</th>
                <th style={{ padding: '0.75rem 0.5rem' }}>Threat &amp; Migration Guidance</th>
                <th style={{ padding: '0.75rem 0.5rem' }}>Auto-Rotation</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No keys found matching your search criteria.
                  </td>
                </tr>
              ) : (
                filteredAssets.map(a => (
                  <tr key={a.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                    <td style={{ padding: '0.75rem 0.5rem', fontWeight: 600, color: '#ffffff', fontFamily: 'monospace' }}>
                      {a.asset_name}
                    </td>
                    <td style={{ padding: '0.75rem 0.5rem', color: 'var(--text-secondary)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                        {getProviderIcon(a.provider)}
                        <span>{a.connector_name}</span>
                      </div>
                    </td>
                    <td style={{ padding: '0.75rem 0.5rem', color: 'var(--text-muted)', textTransform: 'capitalize' }}>
                      {a.asset_type.replace('_', ' ')}
                    </td>
                    <td style={{ padding: '0.75rem 0.5rem', fontWeight: 600, color: a.is_vulnerable ? '#f87171' : '#34d399' }}>
                      {a.algorithm} {a.key_size ? `(${a.key_size}-bit)` : ''}
                    </td>
                    <td style={{ padding: '0.75rem 0.5rem' }}>
                      <span style={{
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        padding: '0.15rem 0.5rem',
                        borderRadius: '4px',
                        background: a.is_vulnerable ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                        color: a.is_vulnerable ? '#ef4444' : '#10b981',
                        border: `1px solid ${a.is_vulnerable ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`
                      }}>
                        {a.is_vulnerable ? 'SHOR VULNERABLE' : 'PQC RESILIENT'}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem 0.5rem', color: 'var(--text-secondary)', fontSize: '0.78rem', maxWidth: '340px' }}>
                      {a.quantum_threat}
                    </td>
                    <td style={{ padding: '0.75rem 0.5rem', color: a.rotation_enabled ? '#34d399' : 'var(--text-muted)' }}>
                      {a.rotation_enabled ? 'Enabled' : 'Disabled'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal: Add Connector */}
      {showAddModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(5px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div className="glass-panel" style={{ width: '540px', padding: '2rem', border: '1px solid rgba(0, 242, 254, 0.4)' }}>
            <h3 style={{ margin: '0 0 0.5rem 0', color: '#ffffff', fontSize: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Plus size={18} color="var(--accent-cyan)" /> Add Enterprise Vault Connector
            </h3>
            <p style={{ margin: '0 0 1.5rem 0', color: 'var(--text-secondary)', fontSize: '0.84rem' }}>
              Connect a centralized key management system or certification authority for automated cryptographic inventory.
            </p>

            <form onSubmit={handleCreateConnector} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                  Provider Type
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.5rem' }}>
                  {[
                    { id: 'aws_kms', label: 'AWS KMS & Secrets' },
                    { id: 'azure_keyvault', label: 'Azure Key Vault' },
                    { id: 'hashicorp_vault', label: 'HashiCorp Vault' },
                    { id: 'ad_cs', label: 'Microsoft AD CS · agent' }
                  ].map(p => (
                    <button
                      type="button"
                      key={p.id}
                      onClick={() => setConnProvider(p.id as any)}
                      style={{
                        padding: '0.65rem 0.5rem',
                        borderRadius: '6px',
                        fontSize: '0.8rem',
                        fontWeight: 600,
                        background: connProvider === p.id ? 'rgba(0, 242, 254, 0.15)' : 'rgba(255, 255, 255, 0.03)',
                        border: `1px solid ${connProvider === p.id ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.08)'}`,
                        color: connProvider === p.id ? '#ffffff' : 'var(--text-secondary)',
                        cursor: 'pointer'
                      }}
                    >
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                  Connector Label / Display Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Production AWS KMS (us-east-1)"
                  value={connName}
                  onChange={e => setConnName(e.target.value)}
                  style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff' }}
                />
              </div>

              {connProvider === 'aws_kms' && (
                <>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '0.75rem' }}>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>AWS Region</label>
                      <input type="text" placeholder="ap-south-1" value={awsRegion} onChange={e => setAwsRegion(e.target.value)} style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff' }} />
                    </div>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>IAM Role ARN (Optional)</label>
                      <input type="text" placeholder="arn:aws:iam::123456789012:role/... (leave blank to use keys directly)" value={awsRoleArn} onChange={e => setAwsRoleArn(e.target.value)} style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff' }} />
                    </div>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>Access Key ID</label>
                      <input type="text" autoComplete="off" placeholder="AKIA..." value={awsAccessKeyId} onChange={e => setAwsAccessKeyId(e.target.value)} style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff', fontFamily: 'monospace' }} />
                    </div>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>Secret Access Key</label>
                      <input type="password" autoComplete="new-password" placeholder="••••••••••••••••••••" value={awsSecretAccessKey} onChange={e => setAwsSecretAccessKey(e.target.value)} style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff', fontFamily: 'monospace' }} />
                    </div>
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', lineHeight: 1.5, display: 'flex', gap: '0.4rem' }}>
                    <Info size={13} style={{ flexShrink: 0, marginTop: '0.1rem' }} />
                    <span>Provide an Access Key ID + Secret for a read-only IAM user (<code>kms:ListKeys</code>, <code>DescribeKey</code>, <code>ListAliases</code>, <code>GetKeyRotationStatus</code>). If you also supply a Role ARN, the keys are used to AssumeRole. Keys are AES-256-GCM encrypted at rest and never returned by the API.</span>
                  </div>
                </>
              )}

              {connProvider === 'azure_keyvault' && (
                <>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>Vault URL</label>
                    <input type="text" placeholder="https://my-prod-vault.vault.azure.net" value={connEndpoint} onChange={e => setConnEndpoint(e.target.value)} style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff' }} />
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>Tenant ID</label>
                      <input type="text" placeholder="Azure Directory UUID" value={azureTenantId} onChange={e => setAzureTenantId(e.target.value)} style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff' }} />
                    </div>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>Client ID</label>
                      <input type="text" placeholder="Service Principal App ID" value={azureClientId} onChange={e => setAzureClientId(e.target.value)} style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff' }} />
                    </div>
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>Client Secret</label>
                    <input type="password" autoComplete="new-password" placeholder="Service Principal secret value" value={azureClientSecret} onChange={e => setAzureClientSecret(e.target.value)} style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff', fontFamily: 'monospace' }} />
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', lineHeight: 1.5, display: 'flex', gap: '0.4rem' }}>
                    <Info size={13} style={{ flexShrink: 0, marginTop: '0.1rem' }} />
                    <span>Service-principal (client-credentials) auth. The app registration needs <code>Key Vault Reader</code> / list+get key permissions on the vault. The secret is AES-256-GCM encrypted at rest and never returned by the API.</span>
                  </div>
                </>
              )}

              {connProvider === 'hashicorp_vault' && (
                <>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>Vault Server URL</label>
                    <input type="text" placeholder="https://vault.example.com:8200" value={connEndpoint} onChange={e => setConnEndpoint(e.target.value)} style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff' }} />
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>Vault Token</label>
                    <input type="password" autoComplete="new-password" placeholder="hvs.••••••••••••••••" value={vaultToken} onChange={e => setVaultToken(e.target.value)} style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff', fontFamily: 'monospace' }} />
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    — or authenticate with AppRole instead of a static token —
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>AppRole Role ID (Optional)</label>
                      <input type="text" autoComplete="off" placeholder="role_id" value={vaultRoleId} onChange={e => setVaultRoleId(e.target.value)} style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff', fontFamily: 'monospace' }} />
                    </div>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>AppRole Secret ID (Optional)</label>
                      <input type="password" autoComplete="new-password" placeholder="secret_id" value={vaultSecretId} onChange={e => setVaultSecretId(e.target.value)} style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff', fontFamily: 'monospace' }} />
                    </div>
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>PKI Mount (Optional)</label>
                    <input type="text" placeholder="pki (classifies issuer CA certs — drives trust arrows)" value={vaultPkiMount} onChange={e => setVaultPkiMount(e.target.value)} style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff', fontFamily: 'monospace' }} />
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', lineHeight: 1.5, display: 'flex', gap: '0.4rem' }}>
                    <Info size={13} style={{ flexShrink: 0, marginTop: '0.1rem' }} />
                    <span>Supply a <strong>Token</strong> or <strong>AppRole</strong> (Role ID + Secret ID). Transit-engine keys populate the inventory; add a <strong>PKI mount</strong> to also catalog issuer CA certificates — those are what link to hosts in the Threat &amp; Risk Graph. Token / Secret ID are AES-256-GCM encrypted at rest.</span>
                  </div>
                </>
              )}

              {connProvider === 'ad_cs' && (
                <div style={{ padding: '1rem', borderRadius: '6px', background: 'rgba(59, 130, 246, 0.08)', border: '1px solid rgba(59, 130, 246, 0.3)', display: 'flex', gap: '0.6rem', alignItems: 'flex-start' }}>
                  <Info size={16} color="#3b82f6" style={{ flexShrink: 0, marginTop: '0.1rem' }} />
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                    <div style={{ fontWeight: 700, color: '#93c5fd', marginBottom: '0.3rem' }}>Agent-based — no console enrollment</div>
                    Microsoft AD CS inventory is collected on-prem by a domain-joined host agent and pushed to QuarkShield automatically; it cannot be pulled from the cloud console (the CA lives behind your firewall). Run the QuarkShield agent with <code>--adcs</code> on the CA host. Once it reports, an <strong>AD CS</strong> connector appears here with the discovered CA certificates and templates.
                  </div>
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1rem' }}>
                <button type="button" onClick={() => setShowAddModal(false)} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={connProvider === 'ad_cs'} style={connProvider === 'ad_cs' ? { opacity: 0.5, cursor: 'not-allowed' } : undefined}>
                  Save &amp; Execute Initial Sync
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
