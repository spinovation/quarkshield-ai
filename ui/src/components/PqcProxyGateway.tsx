import React, { useState, useEffect } from 'react';
import { 
  Network, 
  ShieldCheck, 
  Play, 
  Square, 
  Trash2, 
  Activity, 
  Check, 
  Copy, 
  Download, 
  Plus, 
  RefreshCw, 
  Terminal, 
  FileCode, 
  Zap, 
  ArrowRight, 
  Layers,
  Lock,
  Globe
} from 'lucide-react';

interface ProxyInstance {
  id: string;
  name: string;
  listen_port: number;
  upstream_url: string;
  tls_curve: string;
  status: 'running' | 'stopped' | 'error';
  handshake_count: number;
  active_connections: number;
  cert_expiry?: string;
  last_active_at?: string;
}

export const PqcProxyGateway: React.FC = () => {
  const [proxies, setProxies] = useState<ProxyInstance[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeSubTab, setActiveSubTab] = useState<'gateways' | 'templates'>('gateways');
  const [selectedTemplateFormat, setSelectedTemplateFormat] = useState<'nginx' | 'docker-compose' | 'envoy'>('nginx');
  const [templateContent, setTemplateContent] = useState<string>('');
  const [copied, setCopied] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [diagnosticResult, setDiagnosticResult] = useState<any>(null);

  // New Proxy Form State
  const [name, setName] = useState('');
  const [listenPort, setListenPort] = useState(8443);
  const [upstreamUrl, setUpstreamUrl] = useState('http://127.0.0.1:8080');
  const [tlsCurve, setTlsCurve] = useState('X25519MLKEM768');

  const fetchProxies = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/proxy/instances');
      if (res.ok) {
        const data = await res.json();
        setProxies(data);
      }
    } catch (err) {
      console.error('Error fetching proxies:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchTemplate = async (format: string) => {
    try {
      const res = await fetch(`/api/proxy/templates/${format}?port=8443&upstream=http://127.0.0.1:8080`);
      if (res.ok) {
        const text = await res.text();
        setTemplateContent(text);
      }
    } catch (err) {
      console.error('Error fetching template:', err);
    }
  };

  useEffect(() => {
    fetchProxies();
  }, []);

  useEffect(() => {
    if (activeSubTab === 'templates') {
      fetchTemplate(selectedTemplateFormat);
    }
  }, [activeSubTab, selectedTemplateFormat]);

  const handleToggle = async (id: string, currentStatus: string) => {
    try {
      const newStatus = currentStatus === 'running' ? 'stopped' : 'running';
      const res = await fetch(`/api/proxy/instances/${id}/state`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      if (res.ok) {
        fetchProxies();
      }
    } catch (err) {
      console.error('Error toggling proxy:', err);
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm('Are you sure you want to delete this proxy gateway?')) return;
    try {
      const res = await fetch(`/api/proxy/instances/${id}`, { method: 'DELETE' });
      if (res.ok) fetchProxies();
    } catch (err) {
      console.error('Error deleting proxy:', err);
    }
  };

  const handleTestHandshake = async (id: string) => {
    try {
      const res = await fetch(`/api/proxy/instances/${id}/test`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setDiagnosticResult(data);
        fetchProxies();
      }
    } catch (err) {
      console.error('Error testing handshake:', err);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name) return;
    try {
      const res = await fetch('/api/proxy/instances', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, listenPort, upstreamUrl, tlsCurve })
      });
      if (res.ok) {
        setShowAddModal(false);
        setName('');
        fetchProxies();
      }
    } catch (err) {
      console.error('Error creating proxy:', err);
    }
  };

  const handleCopyTemplate = () => {
    navigator.clipboard.writeText(templateContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const totalHandshakes = proxies.reduce((acc, p) => acc + (p.handshake_count || 0), 0);
  const runningCount = proxies.filter(p => p.status === 'running').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header Banner */}
      <div className="glass-panel" style={{ padding: '1.5rem 1.75rem', border: '1px solid rgba(0, 242, 254, 0.2)', position: 'relative', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', top: 0, left: 0, bottom: 0, width: '4px', background: 'var(--accent-cyan)' }} />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
              <Network size={22} color="var(--accent-cyan)" />
              <h2 style={{ margin: 0, fontSize: '1.35rem', color: '#ffffff', fontWeight: 700 }}>
                Hybrid Quantum TLS Proxy Gateway
              </h2>
              <span style={{ fontSize: '0.7rem', padding: '0.15rem 0.5rem', borderRadius: '4px', background: 'rgba(0, 242, 254, 0.15)', color: 'var(--accent-cyan)', border: '1px solid rgba(0, 242, 254, 0.3)', fontWeight: 600 }}>
                ZERO CODE MODIFICATIONS
              </span>
            </div>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.86rem', maxWidth: '850px', lineHeight: 1.5 }}>
              A transparent inline network gateway upgrading legacy client-server application traffic to post-quantum hybrid ciphers (<strong>X25519MLKEM768</strong> / curve <code>0x11ec</code>). Terminates hybrid TLS 1.3 at the ingress perimeter and forwards traffic to legacy backends with <strong>zero changes to your application codebase</strong>.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
            <div style={{ display: 'flex', background: 'rgba(0,0,0,0.3)', padding: '0.2rem', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.08)' }}>
              <button
                onClick={() => setActiveSubTab('gateways')}
                style={{
                  padding: '0.45rem 0.85rem',
                  borderRadius: '4px',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  background: activeSubTab === 'gateways' ? 'rgba(0, 242, 254, 0.15)' : 'transparent',
                  border: 'none',
                  color: activeSubTab === 'gateways' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                  cursor: 'pointer'
                }}
              >
                Active Gateways
              </button>
              <button
                onClick={() => setActiveSubTab('templates')}
                style={{
                  padding: '0.45rem 0.85rem',
                  borderRadius: '4px',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  background: activeSubTab === 'templates' ? 'rgba(0, 242, 254, 0.15)' : 'transparent',
                  border: 'none',
                  color: activeSubTab === 'templates' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                  cursor: 'pointer'
                }}
              >
                Deployment Templates
              </button>
            </div>

            <button
              onClick={() => setShowAddModal(true)}
              className="btn btn-primary"
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', padding: '0.55rem 1rem' }}
            >
              <Plus size={15} /> Deploy Gateway
            </button>
          </div>
        </div>
      </div>

      {activeSubTab === 'gateways' && (
        <>
          {/* Top Metrics Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
            <div className="glass-panel" style={{ padding: '1.25rem', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
                Active Proxies
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#ffffff', marginTop: '0.35rem' }}>
                {runningCount} <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)', fontWeight: 500 }}>/ {proxies.length}</span>
              </div>
              <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: '0.3rem' }}>
                Inline TLS termination gateways
              </div>
            </div>

            <div className="glass-panel" style={{ padding: '1.25rem', border: '1px solid rgba(0, 242, 254, 0.25)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
                Hybrid Handshakes Negotiated
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--accent-cyan)', marginTop: '0.35rem' }}>
                {totalHandshakes.toLocaleString()}
              </div>
              <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: '0.3rem' }}>
                X25519MLKEM768 key exchanges
              </div>
            </div>

            <div className="glass-panel" style={{ padding: '1.25rem', border: '1px solid rgba(16, 185, 129, 0.25)' }}>
              <div style={{ fontSize: '0.75rem', color: '#34d399', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
                HNDL Threat Shielded
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#10b981', marginTop: '0.35rem' }}>
                100%
              </div>
              <div style={{ fontSize: '0.76rem', color: '#6ee7b7', marginTop: '0.3rem' }}>
                Eavesdropping adversaries blocked
              </div>
            </div>
          </div>

          {/* Gateways Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: '1rem' }}>
            {proxies.map(p => (
              <div key={p.id} className="glass-panel" style={{ padding: '1.35rem', border: '1px solid rgba(255, 255, 255, 0.08)', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem' }}>
                    <span style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.35rem',
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      padding: '0.2rem 0.55rem',
                      borderRadius: '12px',
                      background: p.status === 'running' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(148, 163, 184, 0.15)',
                      color: p.status === 'running' ? '#34d399' : '#94a3b8',
                      border: `1px solid ${p.status === 'running' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(148, 163, 184, 0.3)'}`
                    }}>
                      <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: p.status === 'running' ? '#10b981' : '#94a3b8' }} />
                      {p.status.toUpperCase()}
                    </span>

                    <span style={{ fontSize: '0.72rem', fontFamily: 'monospace', color: 'var(--accent-cyan)', background: 'rgba(0, 242, 254, 0.1)', padding: '0.15rem 0.45rem', borderRadius: '4px' }}>
                      {p.tls_curve}
                    </span>
                  </div>

                  <div style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.35rem' }}>
                    {p.name}
                  </div>

                  {/* Visual Traffic Diagram */}
                  <div style={{ background: 'rgba(0,0,0,0.3)', padding: '0.75rem', borderRadius: '6px', margin: '0.85rem 0', display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.75rem' }}>
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>:{p.listen_port}</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>PQC HTTPS</div>
                    </div>
                    <ArrowRight size={14} color="var(--accent-cyan)" />
                    <div style={{ background: 'rgba(0, 242, 254, 0.15)', padding: '0.25rem 0.5rem', borderRadius: '4px', border: '1px solid rgba(0, 242, 254, 0.3)', color: '#ffffff', fontWeight: 600, fontSize: '0.7rem' }}>
                      QuarkShield Proxy
                    </div>
                    <ArrowRight size={14} color="var(--text-muted)" />
                    <div style={{ textAlign: 'center', maxWidth: '110px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <div style={{ color: '#ffffff', fontWeight: 600 }}>{p.upstream_url.replace(/^https?:\/\//, '')}</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>Legacy Backend</div>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    <div>Handshakes: <strong style={{ color: '#ffffff' }}>{p.handshake_count}</strong></div>
                    <div>Active Conns: <strong style={{ color: '#ffffff' }}>{p.active_connections}</strong></div>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1.25rem', borderTop: '1px solid rgba(255, 255, 255, 0.05)', paddingTop: '0.85rem' }}>
                  <button
                    onClick={() => handleTestHandshake(p.id)}
                    className="btn btn-secondary"
                    style={{ flex: 1, fontSize: '0.78rem', padding: '0.45rem', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '0.35rem' }}
                  >
                    <Zap size={13} color="var(--accent-cyan)" /> Test Handshake
                  </button>

                  <button
                    onClick={() => handleToggle(p.id, p.status)}
                    className="btn btn-secondary"
                    style={{ fontSize: '0.78rem', padding: '0.45rem 0.65rem', color: p.status === 'running' ? '#f59e0b' : '#10b981' }}
                    title={p.status === 'running' ? 'Pause Gateway' : 'Start Gateway'}
                  >
                    {p.status === 'running' ? <Square size={13} /> : <Play size={13} />}
                  </button>

                  <button
                    onClick={() => handleDelete(p.id)}
                    className="btn btn-secondary"
                    style={{ fontSize: '0.78rem', padding: '0.45rem 0.65rem', color: '#ef4444' }}
                    title="Delete Gateway"
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>
            ))}
          </div>

          {/* Test Diagnostic Modal */}
          {diagnosticResult && (
            <div style={{
              position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
              background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(5px)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
            }}>
              <div className="glass-panel" style={{ width: '500px', padding: '2rem', border: '1px solid var(--accent-cyan)' }}>
                <h3 style={{ margin: '0 0 1rem 0', color: '#ffffff', fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Zap size={18} color="var(--accent-cyan)" /> Hybrid TLS 1.3 Handshake Result
                </h3>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
                  <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '0.75rem', borderRadius: '6px', color: '#34d399', fontWeight: 600 }}>
                    ✅ Handshake Succeeded in {diagnosticResult.handshakeLatencyMs}ms (1-RTT)
                  </div>

                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
                    <tbody>
                      <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                        <td style={{ padding: '6px 0', color: 'var(--text-muted)' }}>Protocol</td>
                        <td style={{ padding: '6px 0', color: '#ffffff', fontWeight: 600, textAlign: 'right' }}>{diagnosticResult.negotiatedProtocol}</td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                        <td style={{ padding: '6px 0', color: 'var(--text-muted)' }}>Key Exchange Curve</td>
                        <td style={{ padding: '6px 0', color: 'var(--accent-cyan)', fontWeight: 700, textAlign: 'right' }}>{diagnosticResult.keyExchange}</td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                        <td style={{ padding: '6px 0', color: 'var(--text-muted)' }}>AEAD Cipher</td>
                        <td style={{ padding: '6px 0', color: '#ffffff', fontWeight: 600, textAlign: 'right' }}>{diagnosticResult.cipherSuite}</td>
                      </tr>
                      <tr>
                        <td style={{ padding: '6px 0', color: 'var(--text-muted)' }}>Forward Secrecy</td>
                        <td style={{ padding: '6px 0', color: '#10b981', fontWeight: 600, textAlign: 'right' }}>{diagnosticResult.forwardSecrecy}</td>
                      </tr>
                    </tbody>
                  </table>

                  <p style={{ margin: '0.5rem 0 0 0', color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                    {diagnosticResult.quantumResilience}
                  </p>
                </div>

                <div style={{ marginTop: '1.5rem', textAlign: 'right' }}>
                  <button onClick={() => setDiagnosticResult(null)} className="btn btn-primary" style={{ padding: '0.5rem 1.25rem' }}>
                    Done
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {activeSubTab === 'templates' && (
        <div className="glass-panel" style={{ padding: '1.75rem', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '1.05rem', color: '#ffffff', fontWeight: 600 }}>
                Transparent Sidecar &amp; Ingress Configurations
              </h3>
              <p style={{ margin: '0.2rem 0 0 0', color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
                Drop these configurations directly into your production ingress cluster to terminate post-quantum hybrid TLS.
              </p>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem' }}>
              {(['nginx', 'docker-compose', 'envoy'] as const).map(fmt => (
                <button
                  key={fmt}
                  onClick={() => setSelectedTemplateFormat(fmt)}
                  style={{
                    padding: '0.45rem 0.85rem',
                    borderRadius: '6px',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    background: selectedTemplateFormat === fmt ? 'rgba(0, 242, 254, 0.15)' : 'rgba(255, 255, 255, 0.03)',
                    border: `1px solid ${selectedTemplateFormat === fmt ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.1)'}`,
                    color: selectedTemplateFormat === fmt ? '#ffffff' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    textTransform: 'uppercase'
                  }}
                >
                  {fmt}
                </button>
              ))}

              <button
                onClick={handleCopyTemplate}
                className="btn btn-secondary"
                style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.8rem', padding: '0.45rem 0.85rem' }}
              >
                {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
          </div>

          <pre style={{
            background: '#030712',
            padding: '1.25rem',
            borderRadius: '8px',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            fontSize: '0.82rem',
            fontFamily: 'monospace',
            color: '#38bdf8',
            overflowX: 'auto',
            lineHeight: 1.5,
            maxHeight: '480px'
          }}>
            {templateContent}
          </pre>
        </div>
      )}

      {/* Modal: Deploy Gateway */}
      {showAddModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(5px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div className="glass-panel" style={{ width: '500px', padding: '2rem', border: '1px solid rgba(0, 242, 254, 0.4)' }}>
            <h3 style={{ margin: '0 0 0.5rem 0', color: '#ffffff', fontSize: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Plus size={18} color="var(--accent-cyan)" /> Deploy PQC Proxy Gateway
            </h3>
            <p style={{ margin: '0 0 1.5rem 0', color: 'var(--text-secondary)', fontSize: '0.84rem' }}>
              Configure a transparent reverse proxy listener that negotiates post-quantum hybrid TLS 1.3 and forwards to your internal server.
            </p>

            <form onSubmit={handleCreate} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                  Gateway Label
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Core Banking Hybrid Ingress"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '0.75rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                    Listen Port (PQC)
                  </label>
                  <input
                    type="number"
                    required
                    value={listenPort}
                    onChange={e => setListenPort(Number(e.target.value))}
                    style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                    Legacy Upstream Target URL
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="http://127.0.0.1:8080"
                    value={upstreamUrl}
                    onChange={e => setUpstreamUrl(e.target.value)}
                    style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff' }}
                  />
                </div>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                  Post-Quantum Key Exchange Curve
                </label>
                <select
                  value={tlsCurve}
                  onChange={e => setTlsCurve(e.target.value)}
                  style={{ width: '100%', padding: '0.6rem', fontSize: '0.85rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#ffffff' }}
                >
                  <option value="X25519MLKEM768">X25519MLKEM768 (NIST FIPS 203 Hybrid - Recommended)</option>
                  <option value="SecP256r1MLKEM768">SecP256r1MLKEM768 (NIST P-256 + ML-KEM)</option>
                  <option value="MLKEM1024">ML-KEM-1024 (CNSA 2.0 Pure Post-Quantum)</option>
                </select>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1rem' }}>
                <button type="button" onClick={() => setShowAddModal(false)} className="btn btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Deploy Proxy Gateway
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
