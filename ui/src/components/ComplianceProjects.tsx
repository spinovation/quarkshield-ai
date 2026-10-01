import React, { useState, useEffect, useCallback } from 'react';
import { ShieldCheck, Plus, FileDown, Trash2, FolderKanban, Loader2, ChevronDown, ChevronRight, RefreshCw, Save } from 'lucide-react';

/**
 * Compliance (OSCAL) — framework-based projects with per-control assessment (BILL-4b).
 * Pick a NIST standard → QuarkShield seeds the crypto controls (SC-13 / 3.13.11 …) with a
 * CBOM-derived status → assess each control (Compliant / Non-Compliant / In Progress / N/A,
 * owner, % complete, target, notes) → export OSCAL SSP + POA&M.
 */

interface Framework { id: string; label: string; short: string }
interface Project { id: string; name: string; framework: string; impactLevel?: string; description?: string; controlCount?: number; compliantCount?: number }
interface Control {
  controlKey: string; controlId: string; title: string; kind?: string;
  status: string; autoStatus?: string; owner?: string | null;
  percentComplete?: number | null; targetDate?: string | null; comments?: string | null; fips?: string;
}

const token = () => sessionStorage.getItem('quarkshield_token') || localStorage.getItem('quarkshield_token') || '';
const H = () => ({ 'Content-Type': 'application/json', Authorization: `Bearer ${token()}` });

const STATUS_META: Record<string, { label: string; color: string; bg: string }> = {
  compliant:      { label: 'Compliant',     color: '#4ade80', bg: 'rgba(34,197,94,0.12)' },
  in_progress:    { label: 'In Progress',   color: '#fbbf24', bg: 'rgba(251,191,36,0.12)' },
  non_compliant:  { label: 'Non-Compliant', color: '#f87171', bg: 'rgba(239,68,68,0.12)' },
  not_applicable: { label: 'N/A',           color: '#94a3b8', bg: 'rgba(148,163,184,0.12)' },
};

export const ComplianceProjects: React.FC<{ tenantName?: string }> = ({ tenantName }) => {
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [framework, setFramework] = useState('nist-800-53r5');
  const [impactLevel, setImpactLevel] = useState<'low' | 'moderate' | 'high'>('moderate');
  const [description, setDescription] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [controls, setControls] = useState<Record<string, Control[]>>({});
  const [loadingControls, setLoadingControls] = useState(false);
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);

  const loadFrameworks = useCallback(async () => {
    try {
      const r = await fetch('/api/compliance/frameworks', { headers: H() });
      if (r.ok) { const d = await r.json(); setFrameworks(d.frameworks || []); }
    } catch { /* ignore */ }
  }, []);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const r = await fetch('/api/projects', { headers: H() });
      if (!r.ok) throw new Error(`Failed to load projects (${r.status})`);
      setProjects(await r.json());
    } catch (e: any) { setError(e.message); } finally { setLoading(false); }
  }, []);

  useEffect(() => { loadFrameworks(); load(); }, [loadFrameworks, load]);

  const create = async () => {
    if (!name.trim()) { setError('Project name is required'); return; }
    setCreating(true); setError(null);
    try {
      const r = await fetch('/api/projects', { method: 'POST', headers: H(), body: JSON.stringify({ name: name.trim(), framework, impactLevel, description: description.trim() }) });
      if (!r.ok) throw new Error(`Failed to create project (${r.status})`);
      setName(''); setDescription(''); setShowForm(false);
      await load();
    } catch (e: any) { setError(e.message); } finally { setCreating(false); }
  };

  const remove = async (id: string, pname: string) => {
    if (!window.confirm(`Delete project "${pname}" and its control assessment?`)) return;
    try {
      const r = await fetch(`/api/projects/${id}`, { method: 'DELETE', headers: H() });
      if (!r.ok) throw new Error(`Delete failed (${r.status})`);
      await load();
    } catch (e: any) { setError(e.message); }
  };

  const toggle = async (id: string) => {
    if (expanded === id) { setExpanded(null); return; }
    setExpanded(id);
    if (!controls[id]) {
      setLoadingControls(true);
      try {
        const r = await fetch(`/api/projects/${id}/controls`, { headers: H() });
        if (r.ok) { const d = await r.json(); setControls(c => ({ ...c, [id]: d.controls || [] })); }
      } catch { /* ignore */ } finally { setLoadingControls(false); }
    }
  };

  const patchControl = (pid: string, key: string, patch: Partial<Control>) =>
    setControls(c => ({ ...c, [pid]: (c[pid] || []).map(ct => ct.controlKey === key ? { ...ct, ...patch } : ct) }));

  const needsAction = (status: string) => status === 'in_progress' || status === 'non_compliant';

  const saveControl = async (pid: string, ct: Control) => {
    // Conditional requirement: a control that isn't Compliant/N-A needs owner, target date, and a comment.
    if (needsAction(ct.status) && (!(ct.owner || '').trim() || !(ct.targetDate || '') || !(ct.comments || '').trim())) {
      setError(`${ct.controlId} (${STATUS_META[ct.status].label}): Owner (SME), estimated completion date, and a comment are required.`);
      return;
    }
    setSavingKey(`${pid}-${ct.controlKey}`); setError(null);
    try {
      const r = await fetch(`/api/projects/${pid}/controls/${ct.controlKey}`, {
        method: 'PATCH', headers: H(),
        body: JSON.stringify({ status: ct.status, owner: ct.owner, percentComplete: ct.percentComplete, targetDate: ct.targetDate, comments: ct.comments }),
      });
      if (!r.ok) throw new Error(`Save failed (${r.status})`);
      await load(); // refresh compliant counts
    } catch (e: any) { setError(e.message); } finally { setSavingKey(null); }
  };

  const reassess = async (pid: string) => {
    setLoadingControls(true);
    try {
      await fetch(`/api/projects/${pid}/reassess`, { method: 'POST', headers: H() });
      const r = await fetch(`/api/projects/${pid}/controls`, { headers: H() });
      if (r.ok) { const d = await r.json(); setControls(c => ({ ...c, [pid]: d.controls || [] })); }
      await load();
    } catch (e: any) { setError(e.message); } finally { setLoadingControls(false); }
  };

  const download = async (id: string, kind: 'ssp' | 'poam', pname: string) => {
    setDownloading(`${id}-${kind}`); setError(null);
    try {
      const r = await fetch(`/api/projects/${id}/oscal/${kind}`, { headers: { Authorization: `Bearer ${token()}` } });
      if (!r.ok) throw new Error(`Export failed (${r.status})`);
      const blob = await r.blob(); const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url;
      a.download = `oscal-${kind}-${pname.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.json`;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    } catch (e: any) { setError(e.message); } finally { setDownloading(null); }
  };

  const fwLabel = (id: string) => frameworks.find(f => f.id === id)?.short || id;
  const card: React.CSSProperties = { background: 'rgba(15,23,42,0.5)', border: '1px solid var(--border-normal, rgba(148,163,184,0.2))', borderRadius: '12px' };
  const btn = (primary = false): React.CSSProperties => ({ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', fontWeight: 600, padding: '0.45rem 0.8rem', borderRadius: '8px', cursor: 'pointer', background: primary ? '#7c3aed' : 'rgba(56,189,248,0.1)', border: `1px solid ${primary ? '#8b5cf6' : 'rgba(56,189,248,0.3)'}`, color: primary ? '#fff' : 'var(--accent-cyan,#38bdf8)' });
  const input: React.CSSProperties = { width: '100%', padding: '0.5rem 0.65rem', borderRadius: '8px', background: 'rgba(15,23,42,0.8)', border: '1px solid rgba(148,163,184,0.3)', color: '#e2e8f0', fontSize: '0.84rem' };
  const cell: React.CSSProperties = { padding: '0.4rem 0.5rem', verticalAlign: 'top', fontSize: '0.78rem' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem', width: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}><ShieldCheck size={22} color="var(--accent-cyan,#38bdf8)" /> Compliance (OSCAL)</h2>
          <p style={{ color: 'var(--text-secondary,#94a3b8)', fontSize: '0.86rem', marginTop: '0.35rem', maxWidth: '760px' }}>
            Create a project against a NIST standard (800‑53 r5 / 800‑171 r2 / r3). QuarkShield seeds the quantum‑relevant
            controls and auto‑assesses each from {tenantName ? `${tenantName}'s` : 'your'} CBOM. Assess, then export OSCAL <strong>SSP</strong> + <strong>POA&amp;M</strong>.
          </p>
        </div>
        <button style={btn(true)} onClick={() => setShowForm(s => !s)}><Plus size={16} /> New Project</button>
      </div>

      {error && <div style={{ ...card, padding: '0.75rem 1rem', borderColor: 'rgba(239,68,68,0.4)', color: '#fca5a5', fontSize: '0.84rem' }}>{error}</div>}

      {showForm && (
        <div style={{ ...card, padding: '1.1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 150px', gap: '0.75rem' }}>
            <div>
              <label style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>Project / boundary name *</label>
              <input style={input} value={name} onChange={e => setName(e.target.value)} placeholder="e.g. DoW Program X, HQ — Sterling VA" />
            </div>
            <div>
              <label style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>Standard *</label>
              <select style={input as any} value={framework} onChange={e => setFramework(e.target.value)}>
                {frameworks.map(f => <option key={f.id} value={f.id}>{f.label}</option>)}
              </select>
            </div>
            <div>
              <label style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>FIPS‑199 impact</label>
              <select style={input as any} value={impactLevel} onChange={e => setImpactLevel(e.target.value as any)}>
                <option value="low">Low</option><option value="moderate">Moderate</option><option value="high">High</option>
              </select>
            </div>
          </div>
          <input style={input} value={description} onChange={e => setDescription(e.target.value)} placeholder="Description / scoping boundary (optional)" />
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button style={btn(true)} onClick={create} disabled={creating}>{creating ? <Loader2 size={15} className="spin" /> : <Plus size={15} />} Create &amp; Seed Controls</button>
            <button style={btn()} onClick={() => setShowForm(false)}>Cancel</button>
          </div>
        </div>
      )}

      {loading ? (
        <div style={{ ...card, padding: '1rem', display: 'flex', gap: '0.5rem', color: 'var(--text-secondary)' }}><Loader2 size={16} className="spin" /> Loading…</div>
      ) : projects.length === 0 ? (
        <div style={{ ...card, padding: '2.5rem 1rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          <FolderKanban size={32} style={{ opacity: 0.5, marginBottom: '0.5rem' }} /><div>No projects yet. Create one to assess crypto controls and generate OSCAL SSP / POA&amp;M.</div>
        </div>
      ) : projects.map(p => {
        const isOpen = expanded === p.id;
        const list = controls[p.id] || [];
        return (
          <div key={p.id} style={card}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem', padding: '0.9rem 1.1rem', cursor: 'pointer' }} onClick={() => toggle(p.id)}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', minWidth: 0 }}>
                {isOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                <span style={{ fontWeight: 600, color: '#e2e8f0' }}>{p.name}</span>
                <span style={{ fontSize: '0.68rem', padding: '0.1rem 0.45rem', borderRadius: '4px', background: 'rgba(124,58,237,0.15)', color: '#c084fc', border: '1px solid rgba(124,58,237,0.3)' }}>{fwLabel(p.framework)}</span>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{p.compliantCount ?? 0}/{p.controlCount ?? 0} compliant</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }} onClick={e => e.stopPropagation()}>
                <button style={btn()} onClick={() => download(p.id, 'ssp', p.name)} disabled={downloading === `${p.id}-ssp`}>{downloading === `${p.id}-ssp` ? <Loader2 size={14} className="spin" /> : <FileDown size={14} />} SSP</button>
                <button style={btn()} onClick={() => download(p.id, 'poam', p.name)} disabled={downloading === `${p.id}-poam`}>{downloading === `${p.id}-poam` ? <Loader2 size={14} className="spin" /> : <FileDown size={14} />} POA&amp;M</button>
                <button style={{ ...btn(), background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#fca5a5' }} onClick={() => remove(p.id, p.name)}><Trash2 size={14} /></button>
              </div>
            </div>

            {isOpen && (
              <div style={{ borderTop: '1px solid rgba(148,163,184,0.15)', padding: '0.75rem 1.1rem 1.1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '0.5rem' }}>
                  <button style={btn()} onClick={() => reassess(p.id)} title="Re-run CBOM auto-assessment"><RefreshCw size={13} /> Reassess from CBOM</button>
                </div>
                {loadingControls && !list.length ? (
                  <div style={{ color: 'var(--text-secondary)', display: 'flex', gap: '0.5rem', padding: '0.5rem' }}><Loader2 size={14} className="spin" /> Loading controls…</div>
                ) : (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                      <thead>
                        <tr style={{ textAlign: 'left', color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', borderBottom: '1px solid var(--border-normal)' }}>
                          <th style={cell}>Control</th><th style={cell}>Title</th><th style={cell}>Status</th><th style={cell}>%</th><th style={cell}>Owner (SME)</th><th style={cell}>Target</th><th style={cell}>Comments</th><th style={cell}></th>
                        </tr>
                      </thead>
                      <tbody>
                        {list.map(ct => {
                          const m = STATUS_META[ct.status] || STATUS_META.in_progress;
                          const needs = needsAction(ct.status);
                          // Required-field styling: red when empty & required; dimmed when not applicable.
                          const req = (empty: boolean): React.CSSProperties => needs
                            ? (empty ? { border: '1px solid #f87171', background: 'rgba(239,68,68,0.07)' } : {})
                            : { opacity: 0.4 };
                          return (
                            <tr key={ct.controlKey} style={{ borderBottom: '1px solid rgba(148,163,184,0.1)' }}>
                              <td style={{ ...cell, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', whiteSpace: 'nowrap', fontWeight: 600 }}>{ct.controlId}</td>
                              <td style={{ ...cell, maxWidth: '260px' }}>
                                <div style={{ fontWeight: 500, color: '#e2e8f0' }}>{ct.title}</div>
                                {ct.fips && <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '0.2rem', lineHeight: 1.35 }}>{ct.fips}</div>}
                              </td>
                              <td style={cell}>
                                <select value={ct.status} onChange={e => patchControl(p.id, ct.controlKey, { status: e.target.value })}
                                  style={{ ...input, padding: '0.25rem 0.4rem', fontWeight: 600, color: m.color, background: m.bg, border: `1px solid ${m.color}55` }}>
                                  {Object.entries(STATUS_META).map(([v, meta]) => <option key={v} value={v} style={{ color: '#e2e8f0', background: '#0f172a' }}>{meta.label}</option>)}
                                </select>
                              </td>
                              <td style={cell}><input type="number" min={0} max={100} value={ct.percentComplete ?? 0} disabled={!needs} onChange={e => patchControl(p.id, ct.controlKey, { percentComplete: Number(e.target.value) })} style={{ ...input, width: '56px', padding: '0.25rem 0.35rem', ...(needs ? {} : { opacity: 0.4 }) }} /></td>
                              <td style={cell}><input value={ct.owner ?? ''} placeholder={needs ? 'SME *' : '—'} disabled={!needs} onChange={e => patchControl(p.id, ct.controlKey, { owner: e.target.value })} style={{ ...input, minWidth: '120px', padding: '0.25rem 0.4rem', ...req(!(ct.owner || '').trim()) }} /></td>
                              <td style={cell}><input type="date" value={(ct.targetDate || '').slice(0, 10)} disabled={!needs} onChange={e => patchControl(p.id, ct.controlKey, { targetDate: e.target.value })} style={{ ...input, padding: '0.25rem 0.35rem', ...req(!(ct.targetDate || '')) }} /></td>
                              <td style={cell}><input value={ct.comments ?? ''} placeholder={needs ? 'Required *' : '—'} disabled={!needs} onChange={e => patchControl(p.id, ct.controlKey, { comments: e.target.value })} style={{ ...input, minWidth: '140px', padding: '0.25rem 0.4rem', ...req(!(ct.comments || '').trim()) }} /></td>
                              <td style={cell}>
                                <button style={{ ...btn(true), padding: '0.3rem 0.55rem' }} onClick={() => saveControl(p.id, ct)} disabled={savingKey === `${p.id}-${ct.controlKey}`}>
                                  {savingKey === `${p.id}-${ct.controlKey}` ? <Loader2 size={13} className="spin" /> : <Save size={13} />}
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default ComplianceProjects;
