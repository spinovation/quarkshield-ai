import React, { useState, useEffect, useCallback } from 'react';
import { ShieldCheck, Plus, FileDown, Trash2, FolderKanban, Loader2 } from 'lucide-react';

/**
 * Compliance (OSCAL) — Projects (BILL-4 UI).
 * A Project is an authorization boundary (a Program of Record, location, region, or BU).
 * Each produces its own OSCAL v1.2.2 SSP + POA&M from its cryptographic assets.
 */

interface Project {
  id: string;
  name: string;
  description?: string | null;
  impactLevel?: string | null;
  createdAt?: string;
}

const authToken = () =>
  sessionStorage.getItem('quarkshield_token') || localStorage.getItem('quarkshield_token') || '';

export const ComplianceProjects: React.FC<{ tenantName?: string }> = ({ tenantName }) => {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [impactLevel, setImpactLevel] = useState<'low' | 'moderate' | 'high'>('moderate');

  const headers = useCallback(() => ({ 'Content-Type': 'application/json', Authorization: `Bearer ${authToken()}` }), []);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/projects', { headers: headers() });
      if (!res.ok) throw new Error(`Failed to load projects (${res.status})`);
      setProjects(await res.json());
    } catch (e: any) {
      setError(e.message || 'Failed to load projects');
    } finally {
      setLoading(false);
    }
  }, [headers]);

  useEffect(() => { load(); }, [load]);

  const create = async () => {
    if (!name.trim()) { setError('Project name is required'); return; }
    setCreating(true);
    setError(null);
    try {
      const res = await fetch('/api/projects', {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({ name: name.trim(), description: description.trim(), impactLevel }),
      });
      if (!res.ok) throw new Error(`Failed to create project (${res.status})`);
      setName(''); setDescription(''); setImpactLevel('moderate'); setShowForm(false);
      await load();
    } catch (e: any) {
      setError(e.message || 'Failed to create project');
    } finally {
      setCreating(false);
    }
  };

  const remove = async (id: string, pname: string) => {
    if (!window.confirm(`Delete project "${pname}"? Its OSCAL exports will no longer be available.`)) return;
    try {
      const res = await fetch(`/api/projects/${id}`, { method: 'DELETE', headers: headers() });
      if (!res.ok) throw new Error(`Failed to delete (${res.status})`);
      await load();
    } catch (e: any) {
      setError(e.message || 'Failed to delete project');
    }
  };

  const download = async (id: string, kind: 'ssp' | 'poam', pname: string) => {
    setDownloading(`${id}-${kind}`);
    setError(null);
    try {
      const res = await fetch(`/api/projects/${id}/oscal/${kind}`, { headers: { Authorization: `Bearer ${authToken()}` } });
      if (!res.ok) throw new Error(`Export failed (${res.status})`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `oscal-${kind}-${pname.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.json`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      setError(e.message || 'Export failed');
    } finally {
      setDownloading(null);
    }
  };

  const card: React.CSSProperties = { background: 'rgba(15,23,42,0.5)', border: '1px solid var(--border-normal, rgba(148,163,184,0.2))', borderRadius: '12px', padding: '1.1rem 1.25rem' };
  const btn = (primary = false): React.CSSProperties => ({
    display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', fontWeight: 600,
    padding: '0.5rem 0.9rem', borderRadius: '8px', cursor: 'pointer',
    background: primary ? '#7c3aed' : 'rgba(56,189,248,0.1)',
    border: `1px solid ${primary ? '#8b5cf6' : 'rgba(56,189,248,0.3)'}`,
    color: primary ? '#fff' : 'var(--accent-cyan, #38bdf8)',
  });
  const input: React.CSSProperties = { width: '100%', padding: '0.55rem 0.7rem', borderRadius: '8px', background: 'rgba(15,23,42,0.8)', border: '1px solid rgba(148,163,184,0.3)', color: '#e2e8f0', fontSize: '0.85rem' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', width: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
            <ShieldCheck size={22} color="var(--accent-cyan, #38bdf8)" /> Compliance (OSCAL)
          </h2>
          <p style={{ color: 'var(--text-secondary, #94a3b8)', fontSize: '0.88rem', marginTop: '0.35rem', maxWidth: '720px' }}>
            A <strong>Project</strong> is an authorization boundary — a Program of Record, location, region, or business unit.
            Each generates its own NIST <strong>OSCAL</strong> System Security Plan (SSP) and Plan of Action &amp; Milestones (POA&amp;M)
            from {tenantName ? `${tenantName}'s` : 'your'} cryptographic assets, mapped to SP 800‑53 controls (SC‑8/12/13/17, IA‑5/7, SI‑2).
          </p>
        </div>
        <button style={btn(true)} onClick={() => setShowForm(s => !s)}><Plus size={16} /> New Project</button>
      </div>

      {error && (
        <div style={{ ...card, borderColor: 'rgba(239,68,68,0.4)', color: '#fca5a5', fontSize: '0.85rem' }}>{error}</div>
      )}

      {showForm && (
        <div style={{ ...card, display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 160px', gap: '0.75rem' }}>
            <div>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Project / boundary name *</label>
              <input style={input} value={name} onChange={e => setName(e.target.value)} placeholder="e.g. HQ — Sterling VA, or Payments Program of Record" />
            </div>
            <div>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>FIPS‑199 impact</label>
              <select style={input as any} value={impactLevel} onChange={e => setImpactLevel(e.target.value as any)}>
                <option value="low">Low</option>
                <option value="moderate">Moderate</option>
                <option value="high">High</option>
              </select>
            </div>
          </div>
          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Description (optional)</label>
            <input style={input} value={description} onChange={e => setDescription(e.target.value)} placeholder="What this authorization boundary covers" />
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button style={btn(true)} onClick={create} disabled={creating}>
              {creating ? <Loader2 size={16} className="spin" /> : <Plus size={16} />} Create Project
            </button>
            <button style={btn()} onClick={() => setShowForm(false)}>Cancel</button>
          </div>
        </div>
      )}

      {loading ? (
        <div style={{ ...card, display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)' }}>
          <Loader2 size={16} className="spin" /> Loading projects…
        </div>
      ) : projects.length === 0 ? (
        <div style={{ ...card, textAlign: 'center', color: 'var(--text-muted)', padding: '2.5rem 1rem' }}>
          <FolderKanban size={32} style={{ opacity: 0.5, marginBottom: '0.5rem' }} />
          <div>No projects yet. Create your first authorization boundary to generate OSCAL SSP / POA&amp;M.</div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {projects.map(p => (
            <div key={p.id} style={{ ...card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
                  <span style={{ fontWeight: 600, color: '#e2e8f0' }}>{p.name}</span>
                  <span style={{ fontSize: '0.68rem', textTransform: 'uppercase', padding: '0.1rem 0.45rem', borderRadius: '4px', background: 'rgba(56,189,248,0.12)', color: 'var(--accent-cyan)', border: '1px solid rgba(56,189,248,0.25)' }}>
                    {(p.impactLevel || 'moderate')} impact
                  </span>
                </div>
                {p.description && <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>{p.description}</div>}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                <button style={btn()} onClick={() => download(p.id, 'ssp', p.name)} disabled={downloading === `${p.id}-ssp`}>
                  {downloading === `${p.id}-ssp` ? <Loader2 size={15} className="spin" /> : <FileDown size={15} />} SSP
                </button>
                <button style={btn()} onClick={() => download(p.id, 'poam', p.name)} disabled={downloading === `${p.id}-poam`}>
                  {downloading === `${p.id}-poam` ? <Loader2 size={15} className="spin" /> : <FileDown size={15} />} POA&amp;M
                </button>
                <button style={{ ...btn(), background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#fca5a5' }} onClick={() => remove(p.id, p.name)} title="Delete project">
                  <Trash2 size={15} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ComplianceProjects;
