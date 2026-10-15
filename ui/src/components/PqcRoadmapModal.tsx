import React, { useEffect, useState } from 'react';
import { X, FileText, AlertTriangle, ShieldCheck, Layers, RefreshCw } from 'lucide-react';

/**
 * In-app PQC Executive Roadmap (interactive). Renders the same deterministic
 * report the PDF/DOCX/HTML exports use (GET /api/reports/executive?format=json),
 * including the crypto Purpose Breakdown (P1) and the "what breaks" Migration
 * Size Impact (P2). Downloads reuse the parent's handler.
 */

type Urgency = 'immediate_hndl' | 'forgery_planned' | 'hardening' | 'review';

interface PurposeBreakdown { purpose: string; label: string; count: number; urgency: Urgency; urgencyLabel: string; standard: string; }
interface MigrationFriction { signingAssets: number; kexAssets: number; firmwareOrRootAssets: number; headline: string; detail: string; }
interface SizeImpactFinding { constraint_label: string; limit_bytes: number; size_after: number; severity: string; rationale: string; remediation: string; }
interface SizeImpact { from_algo: string; to_algo: string; size_before: number; size_after: number; blowup: number | null; findings: SizeImpactFinding[]; note: string; }
interface Priority { rank: number; title: string; severity: string; exposure: string; rationale: string; purposeLabel?: string; sizeImpact?: SizeImpact; }
interface Remediation { finding: string; replacement: string; standard: string; effort: string; how: string; }
interface RoadmapPhase { phase: string; window: string; mandate: string; status: string; actions: string[]; }
interface RoadmapReport {
  scopeLabel: string; collective: boolean; generatedAt: string; reportId: string; riskGrade: string;
  totals: { tenants: number; machines: number; assets: number; vulnerable: number; pqcReady: number; avgRisk: number; vulnPct: number };
  mosca: { verdict: string; detail: string };
  priorities: Priority[]; remediation: Remediation[]; roadmap: RoadmapPhase[];
  purposeBreakdown: PurposeBreakdown[]; migrationFriction: MigrationFriction; summary: string;
}

const URGENCY_COLOR: Record<Urgency, string> = {
  immediate_hndl: '#f87171', forgery_planned: '#fbbf24', hardening: '#60a5fa', review: '#94a3b8',
};
const SEV_COLOR: Record<string, string> = { critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#94a3b8' };
const IMPACT_SEV_COLOR: Record<string, string> = { blocker: '#f87171', degraded: '#fb923c', advisory: '#fbbf24' };

export interface PqcRoadmapModalProps {
  tenantFilter: string;                       // 'all' = fleet-wide (collective)
  onClose: () => void;
  onDownload: (format: 'pdf' | 'docx' | 'html') => void;
}

const card = (bg = '#0d1322'): React.CSSProperties => ({ background: bg, border: '1px solid rgba(255,255,255,0.1)', borderRadius: '10px', padding: '0.9rem 1rem' });
const h2: React.CSSProperties = { fontSize: '0.95rem', fontWeight: 700, margin: '1.4rem 0 0.6rem', color: '#e2e8f0', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '0.4rem' };

const PqcRoadmapModal: React.FC<PqcRoadmapModalProps> = ({ tenantFilter, onClose, onDownload }) => {
  const [report, setReport] = useState<RoadmapReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedPriority, setExpandedPriority] = useState<number | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    (async () => {
      setLoading(true); setError(null);
      try {
        const isFleet = tenantFilter === 'all';
        const qs = isFleet ? 'scope=collective&format=json' : `tenant=${encodeURIComponent(tenantFilter)}&format=json`;
        const res = await fetch(`/api/reports/executive?${qs}`, { credentials: 'include', signal: ctrl.signal });
        if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.error || `HTTP ${res.status}`); }
        setReport(await res.json());
      } catch (err: any) {
        if (err.name !== 'AbortError') setError(err.message || 'Failed to load roadmap');
      } finally {
        setLoading(false);
      }
    })();
    return () => ctrl.abort();
  }, [tenantFilter]);

  const friction = report?.migrationFriction;
  const showFriction = !!friction && (friction.signingAssets > 0 || friction.kexAssets > 0);

  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(6px)', display: 'flex', alignItems: 'flex-start', justifyContent: 'center', zIndex: 1000, padding: '2rem 1.5rem', overflowY: 'auto' }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div style={{ background: '#0a0f1c', border: '1px solid rgba(255,255,255,0.14)', borderRadius: '14px', width: '100%', maxWidth: '880px', boxShadow: '0 24px 60px rgba(0,0,0,0.6)', color: '#cbd5e1', fontSize: '0.85rem', lineHeight: 1.55 }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', padding: '1.4rem 1.6rem', borderBottom: '2px solid var(--accent-cyan, #22d3ee)' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '1.15rem', fontWeight: 800, color: '#fff' }}>
              <FileText size={20} color="#34d399" /> PQC Executive Roadmap
            </div>
            {report && (
              <div style={{ color: '#94a3b8', fontSize: '0.78rem', marginTop: '0.3rem' }}>
                {report.scopeLabel}{report.collective ? ` · ${report.totals.tenants} tenants` : ''} · {report.generatedAt} · {report.reportId}
              </div>
            )}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            {report && (
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.9rem', fontWeight: 800, lineHeight: 1, color: report.riskGrade[0] === 'F' ? '#f87171' : report.riskGrade[0] === 'A' ? '#34d399' : '#fbbf24' }}>{report.riskGrade}</div>
                <div style={{ fontSize: '0.6rem', letterSpacing: '0.08em', color: '#94a3b8', textTransform: 'uppercase' }}>Risk Grade</div>
              </div>
            )}
            <button onClick={onClose} aria-label="Close" style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '0.3rem' }}><X size={20} /></button>
          </div>
        </div>

        <div style={{ padding: '1.2rem 1.6rem 1.6rem' }}>
          {loading && <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#94a3b8', padding: '2rem 0' }}><RefreshCw size={16} className="spin" /> Building roadmap from the cryptographic inventory…</div>}
          {error && <div style={{ ...card('rgba(239,68,68,0.12)'), borderColor: '#f87171', color: '#fca5a5' }}>Could not load the roadmap: {error}</div>}

          {report && !loading && (
            <>
              {/* Executive summary */}
              {report.summary && <p style={{ marginTop: 0, color: '#cbd5e1' }}>{report.summary}</p>}

              {/* Mosca verdict */}
              <div style={{ ...card(report.mosca.verdict === 'ON TRACK' ? 'rgba(16,185,129,0.12)' : 'rgba(239,68,68,0.12)'), borderColor: report.mosca.verdict === 'ON TRACK' ? '#34d399' : '#f87171', marginTop: '0.8rem' }}>
                <div style={{ fontWeight: 700, color: report.mosca.verdict === 'ON TRACK' ? '#34d399' : '#fca5a5' }}>Mosca verdict (X + Y &gt; Z): {report.mosca.verdict}</div>
                <div style={{ color: '#94a3b8', fontSize: '0.8rem', marginTop: '0.3rem' }}>{report.mosca.detail}</div>
              </div>

              {/* KPIs */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(110px,1fr))', gap: '0.7rem', marginTop: '0.9rem' }}>
                {[['Endpoints', report.totals.machines], ['Assets', report.totals.assets], ['Vulnerable', `${report.totals.vulnerable} (${report.totals.vulnPct}%)`], ['PQC / Secure', report.totals.pqcReady], ['Avg risk', `${report.totals.avgRisk}/100`]].map(([l, v]) => (
                  <div key={String(l)} style={card()}>
                    <div style={{ fontSize: '1.25rem', fontWeight: 800, color: '#fff' }}>{v}</div>
                    <div style={{ fontSize: '0.68rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.04em' }}>{l}</div>
                  </div>
                ))}
              </div>

              {/* Cryptographic Purpose Breakdown (P1) */}
              {report.purposeBreakdown?.length > 0 && (
                <>
                  <div style={h2}><Layers size={14} style={{ verticalAlign: '-2px', marginRight: 6 }} />Cryptographic Purpose Breakdown</div>
                  <div style={{ color: '#94a3b8', fontSize: '0.78rem', marginBottom: '0.5rem' }}>What the quantum-vulnerable crypto is <em>used for</em> — key establishment is an immediate Harvest-Now-Decrypt-Later concern; signatures and trust anchors are a planned forgery concern.</div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
                    <thead><tr>{['Purpose', 'Vulnerable', 'Threat urgency', 'NIST target'].map(th => <th key={th} style={{ textAlign: 'left', padding: '0.4rem 0.5rem', background: 'rgba(255,255,255,0.04)', color: '#e2e8f0', fontWeight: 600 }}>{th}</th>)}</tr></thead>
                    <tbody>
                      {report.purposeBreakdown.map(p => (
                        <tr key={p.purpose} style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                          <td style={{ padding: '0.4rem 0.5rem', fontWeight: 600, color: '#e2e8f0' }}>{p.label}</td>
                          <td style={{ padding: '0.4rem 0.5rem' }}>{p.count}</td>
                          <td style={{ padding: '0.4rem 0.5rem', color: URGENCY_COLOR[p.urgency] }}>{p.urgencyLabel}</td>
                          <td style={{ padding: '0.4rem 0.5rem', color: '#94a3b8' }}>{p.standard}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}

              {/* Migration Size Impact — What Breaks (P2) */}
              {showFriction && friction && (
                <>
                  <div style={h2}><AlertTriangle size={14} style={{ verticalAlign: '-2px', marginRight: 6 }} />Migration Size Impact — “What Breaks”</div>
                  <div style={{ ...card('rgba(239,68,68,0.1)'), borderColor: 'rgba(248,113,113,0.5)' }}>
                    <div style={{ fontWeight: 700, color: '#fca5a5' }}>{friction.headline}</div>
                    <div style={{ color: '#94a3b8', fontSize: '0.8rem', marginTop: '0.4rem' }}>{friction.detail}</div>
                    <div style={{ display: 'flex', gap: '0.6rem', marginTop: '0.7rem', flexWrap: 'wrap' }}>
                      {[['Signature-bearing', friction.signingAssets], ['Key-establishment', friction.kexAssets], ['Firmware / root-of-trust', friction.firmwareOrRootAssets]].map(([l, v]) => (
                        <div key={String(l)} style={{ ...card('rgba(0,0,0,0.25)'), padding: '0.5rem 0.75rem' }}>
                          <div style={{ fontSize: '1.1rem', fontWeight: 800, color: Number(v) > 0 ? '#fbbf24' : '#64748b' }}>{v}</div>
                          <div style={{ fontSize: '0.64rem', color: '#94a3b8', textTransform: 'uppercase' }}>{l}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}

              {/* Top priorities */}
              <div style={h2}>Top Migration Priorities</div>
              {report.priorities.length === 0 ? <div style={{ color: '#94a3b8' }}>No quantum-vulnerable assets identified.</div> :
                report.priorities.map(p => {
                  const si = p.sizeImpact;
                  const open = expandedPriority === p.rank;
                  const hasImpact = !!si && (si.findings.length > 0 || (si.blowup ?? 0) > 1);
                  return (
                  <div key={p.rank} style={{ ...card(), borderLeft: `3px solid ${SEV_COLOR[p.severity] || '#94a3b8'}`, marginBottom: '0.5rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', alignItems: 'baseline' }}>
                      <div style={{ fontWeight: 700, color: '#e2e8f0' }}>
                        <span style={{ fontSize: '0.64rem', fontWeight: 800, textTransform: 'uppercase', padding: '1px 6px', borderRadius: 4, background: 'rgba(255,255,255,0.08)', color: SEV_COLOR[p.severity] || '#94a3b8', marginRight: 8 }}>{p.severity}</span>
                        P{p.rank} · {p.title}
                      </div>
                      {hasImpact && (
                        <button onClick={() => setExpandedPriority(open ? null : p.rank)} style={{ background: 'transparent', border: 'none', color: '#67e8f9', cursor: 'pointer', fontSize: '0.74rem', whiteSpace: 'nowrap' }}>
                          {open ? 'Hide' : 'What breaks? →'}
                        </button>
                      )}
                    </div>
                    <div style={{ color: '#94a3b8', fontSize: '0.78rem', marginTop: '0.25rem' }}>{p.rationale}</div>
                    {open && si && (
                      <div style={{ marginTop: '0.6rem', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '0.6rem' }}>
                        <div style={{ fontSize: '0.78rem', color: '#e2e8f0', fontWeight: 600 }}>
                          {si.from_algo.toUpperCase()} → {si.to_algo.toUpperCase()}{si.blowup ? ` · ${si.blowup}× larger` : ''} ({si.size_before || '?'} B → {si.size_after} B)
                        </div>
                        {si.findings.length === 0 ? <div style={{ color: '#64748b', fontSize: '0.76rem', marginTop: 4 }}>No fixed-size constraints flagged for this migration.</div> :
                          si.findings.map((f, i) => (
                            <div key={i} style={{ fontSize: '0.76rem', borderLeft: `3px solid ${IMPACT_SEV_COLOR[f.severity] || '#94a3b8'}`, paddingLeft: 8, marginTop: 6 }}>
                              <div><span style={{ fontSize: '0.62rem', fontWeight: 800, textTransform: 'uppercase', color: IMPACT_SEV_COLOR[f.severity], marginRight: 6 }}>{f.severity}</span><strong style={{ color: '#e2e8f0' }}>{f.constraint_label}</strong> <span style={{ color: '#64748b' }}>· {f.size_after} B vs {f.limit_bytes} B nominal</span></div>
                              <div style={{ color: '#94a3b8', marginTop: 2 }}>{f.rationale}</div>
                              <div style={{ color: '#94a3b8', marginTop: 2, fontStyle: 'italic' }}>Fix: {f.remediation}</div>
                            </div>
                          ))}
                        <div style={{ color: '#64748b', fontSize: '0.7rem', marginTop: 6 }}>{si.note}</div>
                      </div>
                    )}
                  </div>
                );})}

              {/* Remediation */}
              {report.remediation.length > 0 && (
                <>
                  <div style={h2}>Remediation Recommendations</div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
                    <thead><tr>{['Finding', 'Replacement', 'Standard', 'Effort'].map(th => <th key={th} style={{ textAlign: 'left', padding: '0.4rem 0.5rem', background: 'rgba(255,255,255,0.04)', color: '#e2e8f0', fontWeight: 600 }}>{th}</th>)}</tr></thead>
                    <tbody>
                      {report.remediation.map((rem, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                          <td style={{ padding: '0.4rem 0.5rem' }}><strong style={{ color: '#e2e8f0' }}>{rem.finding}</strong><div style={{ color: '#64748b', fontSize: '0.72rem', marginTop: 2 }}>{rem.how}</div></td>
                          <td style={{ padding: '0.4rem 0.5rem', color: '#94a3b8' }}>{rem.replacement}</td>
                          <td style={{ padding: '0.4rem 0.5rem', color: '#94a3b8' }}>{rem.standard}</td>
                          <td style={{ padding: '0.4rem 0.5rem', color: '#94a3b8' }}>{rem.effort}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}

              {/* Roadmap phases */}
              <div style={h2}>Migration Roadmap</div>
              {report.roadmap.map((ph, i) => (
                <div key={i} style={{ ...card(), marginBottom: '0.5rem' }}>
                  <div style={{ fontWeight: 700, color: '#e2e8f0' }}>{ph.phase} <span style={{ fontSize: '0.64rem', fontWeight: 700, padding: '1px 8px', borderRadius: 999, background: 'rgba(34,211,238,0.15)', color: '#67e8f9', marginLeft: 6 }}>{ph.status}</span></div>
                  <div style={{ color: '#64748b', fontSize: '0.72rem', margin: '2px 0 6px' }}>{ph.window} · {ph.mandate}</div>
                  <ul style={{ margin: 0, paddingLeft: '1.1rem', color: '#94a3b8' }}>{ph.actions.map((a, j) => <li key={j}>{a}</li>)}</ul>
                </div>
              ))}

              {/* Export row — HTML is the printable/shareable copy (Print → Save as PDF) */}
              <div style={{ display: 'flex', gap: '0.6rem', marginTop: '1.4rem', flexWrap: 'wrap', alignItems: 'center', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '1rem' }}>
                <button onClick={() => onDownload('html')} className="btn-secondary" style={{ padding: '0.45rem 0.85rem', fontSize: '0.78rem', borderColor: '#34d399', color: '#34d399', background: 'rgba(16,185,129,0.12)' }}><FileText size={13} style={{ verticalAlign: '-2px', marginRight: 5 }} />Open printable report</button>
                <span style={{ color: '#64748b', fontSize: '0.72rem' }}>Use your browser’s <strong>Print → Save as PDF</strong> for a shareable copy.</span>
                <div style={{ flex: 1 }} />
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: '#64748b', fontSize: '0.72rem' }}><ShieldCheck size={13} /> Deterministic · computed from the CBOM</div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default PqcRoadmapModal;
