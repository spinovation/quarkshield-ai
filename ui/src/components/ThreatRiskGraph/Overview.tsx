import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, Crosshair, ShieldCheck, Link2, ArrowUp, ArrowDown, ArrowRight } from 'lucide-react';
import type { ThreatApi } from './api';
import { ArchitectureView } from './ArchitectureView';
import { EXPLAIN, SOURCE_ROLES } from './explain';
import {
  card, muted, LevelBadge, PathRiskBadge, SectionTitle, LinkButton, Empty, PathChain, LEVEL_META, Chip,
  tableStyle, th, td, InfoTip, IntelBadges, type TipContent,
} from './ui';

interface Props {
  api: ThreatApi;
  data: any;
  onOpenPath: (id: string) => void;
  onOpenScenario: (id: string) => void;
  onOpenAsset: (id: string) => void;
  onViewAllScenarios: () => void;
}

// ---------------------------------------------------------------------------
// KPI cards
// ---------------------------------------------------------------------------
const Kpi: React.FC<{
  icon: React.ElementType; tone: string; label: string; value: React.ReactNode; foot?: React.ReactNode; info?: TipContent;
}> = ({ icon: Icon, tone, label, value, foot, info }) => (
  <div style={{ ...card, display: 'flex', gap: 14, alignItems: 'flex-start', padding: '1rem' }}>
    <div style={{
      width: 46, height: 46, borderRadius: 23, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: `${tone}26`, border: `1px solid ${tone}66`,
    }}>
      <Icon size={22} color={tone} />
    </div>
    <div style={{ minWidth: 0, flex: 1 }}>
      <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary, #cbd5e1)', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 6 }}>
        <span>{label}</span>{info && <InfoTip tip={info} />}
      </div>
      <div style={{ fontSize: '1.65rem', fontWeight: 700, lineHeight: 1.25, color: 'var(--text-primary, #f8fafc)' }}>{value}</div>
      {foot && <div style={{ ...muted, fontSize: '0.72rem', marginTop: 2 }}>{foot}</div>}
    </div>
  </div>
);

// ---------------------------------------------------------------------------
// Risk heat map: gradient field with the top scenarios plotted as T1…T5
// ---------------------------------------------------------------------------
const AXIS = ['Low', 'Medium', 'High', 'Critical'];
const HeatMap: React.FC<{ points: any[]; onOpen: (id: string) => void }> = ({ points, onOpen }) => {
  const placed = new Map<string, number>();
  return (
    <div style={{ display: 'flex', gap: 14, alignItems: 'stretch', flexWrap: 'wrap' }}>
      <div style={{ display: 'flex', gap: 6, flex: '1 1 220px', minWidth: 200 }}>
        <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', alignItems: 'flex-end', paddingBottom: 18 }}>
          {[...AXIS].reverse().map(a => <span key={a} style={{ ...muted, fontSize: '0.66rem' }}>{a}</span>)}
        </div>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <div style={{
            position: 'relative', flex: 1, minHeight: 190, borderRadius: 6, border: '1px solid rgba(255,255,255,0.12)',
            background: 'linear-gradient(45deg, #14532d 0%, #3f6212 30%, #a16207 55%, #b45309 72%, #be123c 100%)',
          }}>
            {[1, 2, 3].map(i => (
              <React.Fragment key={i}>
                <div style={{ position: 'absolute', left: `${i * 25}%`, top: 0, bottom: 0, borderLeft: '1px dashed rgba(255,255,255,0.12)' }} />
                <div style={{ position: 'absolute', top: `${i * 25}%`, left: 0, right: 0, borderTop: '1px dashed rgba(255,255,255,0.12)' }} />
              </React.Fragment>
            ))}
            {points.map(p => {
              const k = `${p.likelihood}|${p.impact}`;
              const n = placed.get(k) || 0; placed.set(k, n + 1);
              const m = LEVEL_META[p.level] || LEVEL_META.low;
              return (
                <button key={p.label} title={p.title} onClick={() => onOpen(p.id)} style={{
                  position: 'absolute', left: `calc(${(p.likelihood - 0.5) * 25}% - 13px + ${n * 14}px)`,
                  top: `calc(${(4 - p.impact + 0.5) * 25}% - 13px - ${n * 6}px)`,
                  width: 26, height: 26, borderRadius: 13, border: `2px solid ${m.color}`, background: '#0b1020',
                  color: m.color, fontSize: 10, fontWeight: 800, cursor: 'pointer', padding: 0,
                }}>{p.label}</button>
              );
            })}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-around', marginTop: 4 }}>
            {AXIS.map(a => <span key={a} style={{ ...muted, fontSize: '0.66rem' }}>{a}</span>)}
          </div>
          <div style={{ ...muted, textAlign: 'center', fontSize: '0.7rem' }}>Likelihood →  ·  ↑ Impact</div>
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, justifyContent: 'center' }}>
        {points.length === 0 && <span style={muted}>No risks</span>}
        {points.map(p => {
          const m = LEVEL_META[p.level] || LEVEL_META.low;
          return (
            <div key={p.label} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.78rem' }}>
              <span style={{ background: m.color, color: '#0b1020', fontWeight: 800, fontSize: 10, borderRadius: 4, padding: '2px 5px' }}>{p.label}</span>
              <span style={{ color: 'var(--text-secondary)' }}>{m.label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

const STATUS_META: Record<string, { label: string; color: string }> = {
  needs_attention: { label: 'Needs Attention', color: '#ff3366' },
  in_progress: { label: 'In Progress', color: '#fbbf24' },
  planned: { label: 'Planned', color: '#60a5fa' },
  mitigated: { label: 'Mitigated', color: '#4ade80' },
  risk_accepted: { label: 'Risk Accepted', color: '#94a3b8' },
};
const StatusPill: React.FC<{ status: string }> = ({ status }) => {
  const m = STATUS_META[status] || STATUS_META.needs_attention;
  return <span style={{ border: `1px solid ${m.color}`, color: m.color, borderRadius: 5, padding: '1px 6px', fontSize: '0.68rem', whiteSpace: 'nowrap' }}>{m.label}</span>;
};
const PRIORITY_COLOR: Record<string, string> = { P1: '#e11d48', P2: '#ea580c', P3: '#2563eb' };

const barColor = (i: number) => ['#ef4444', '#f97316', '#f59e0b', '#eab308', '#facc15', '#22c55e', '#10b981'][Math.min(i, 6)];

export const Overview: React.FC<Props> = ({ api, data, onOpenPath, onOpenScenario, onOpenAsset, onViewAllScenarios }) => {
  const k = data.kpis;
  // Clicking a data-source chip highlights where that source shows up in the diagram.
  const [focusSource, setFocusSource] = useState<string | null>(null);
  const residualColor = (LEVEL_META[k.residual_level] || LEVEL_META.low).color;
  const row: React.CSSProperties = { display: 'grid', gap: '1rem' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {/* KPI row */}
      <div style={{ ...row, gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))' }}>
        <Kpi icon={ShieldAlert} tone="#ff3366" label="Total Threats Identified" value={k.threats} info={EXPLAIN.threats}
          foot={k.threats_delta ? <span style={{ color: k.threats_delta > 0 ? '#ff3366' : '#4ade80' }}>
            {k.threats_delta > 0 ? <ArrowUp size={11} /> : <ArrowDown size={11} />} {Math.abs(k.threats_delta)} {k.threats_delta > 0 ? 'new' : 'fewer'} since last run</span>
            : `${k.attack_paths} attack path${k.attack_paths === 1 ? '' : 's'}`} />
        <Kpi icon={AlertTriangle} tone="#f97316" label="High / Critical Risks" value={k.high_critical} info={EXPLAIN.highCritical}
          foot={`(${k.high_critical_pct}%) of ${k.risks_total} risks`} />
        <Kpi icon={Crosshair} tone="#38bdf8" label="Affected Controls" value={k.affected_controls} info={EXPLAIN.controls}
          foot={`${k.controls_framework} · touched by open risks`} />
        <Kpi icon={ShieldCheck} tone="#22c55e" label="Residual Risk (After Remediation)" info={EXPLAIN.residual}
          value={<span style={{ color: residualColor, textTransform: 'capitalize' }}>{k.residual_level}</span>}
          foot={k.residual_reduction_pct > 0
            ? <span style={{ color: '#4ade80' }}><ArrowDown size={11} /> {k.residual_reduction_pct}% from inherent</span>
            : 'no remediation credited yet'} />
        <Kpi icon={Link2} tone="#a855f7" label="Frameworks Mapped" value={k.frameworks_mapped} info={EXPLAIN.frameworks}
          foot={k.frameworks.join(' | ') || 'no open risks mapped'} />
      </div>

      {/* Data lineage: which inputs this model was built from */}
      {data.dataSources && (
        <div style={{ ...card, display: 'flex', flexDirection: 'column', gap: 8, padding: '0.6rem 0.9rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
              Data sources <InfoTip tip={EXPLAIN.dataSources} />
            </span>
            <span style={{ ...muted, fontSize: '0.72rem' }}>Click a source to highlight where it appears in the Threat Model Overview.</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            {(() => {
              const chip = (on: boolean): React.CSSProperties => ({
                display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 9px', borderRadius: 999, fontSize: '0.74rem',
                border: on ? '1px solid var(--accent-cyan, #00f2fe)' : '1px solid rgba(255,255,255,0.1)',
                background: on ? 'rgba(0,242,254,0.12)' : 'transparent', color: 'var(--text-secondary)',
              });
              const btn: React.CSSProperties = { background: 'none', border: 'none', padding: 0, color: 'inherit', font: 'inherit', cursor: 'pointer' };
              return (
                <>
                  {/* "All": nothing highlighted — the full diagram. */}
                  <span style={chip(!focusSource)}>
                    <button aria-pressed={!focusSource} onClick={() => setFocusSource(null)} title="Show every box (no highlight)" style={btn}>
                      <strong style={{ color: !focusSource ? 'var(--accent-cyan, #00f2fe)' : 'var(--text-secondary)' }}>All</strong>
                    </button>
                  </span>
                  {data.dataSources.map((d: any) => {
                    const on = focusSource === d.id;
                    return (
                      <span key={d.id} style={{ ...chip(on), color: d.n ? 'var(--text-secondary)' : 'var(--text-muted)', opacity: d.n ? 1 : 0.6 }}>
                        <button aria-pressed={on} disabled={!d.n} onClick={() => setFocusSource(on ? null : d.id)}
                          title={d.n ? `Highlight ${d.label} in the diagram` : 'No data from this source yet'}
                          style={{ ...btn, cursor: d.n ? 'pointer' : 'default' }}>
                          <strong style={{ color: d.n ? 'var(--accent-cyan, #00f2fe)' : 'inherit' }}>{d.n}</strong> {d.label}
                        </button>
                        <InfoTip tip={{ what: d.label, source: d.detail, how: SOURCE_ROLES[d.id]?.summary }} size={12} />
                      </span>
                    );
                  })}
                </>
              );
            })()}
          </div>
        </div>
      )}

      {/* Threat model overview (architecture / threat / data-flow views) */}
      <div style={{ ...card, minHeight: 400 }}>
        <ArchitectureView api={api} data={data} onOpenAsset={onOpenAsset}
          focusSource={focusSource} focusLabel={data.dataSources?.find((d: any) => d.id === focusSource)?.label} onClearFocus={() => setFocusSource(null)} />
      </div>

      {/* Risk by threat type · compliance mapping · heat map */}
      <div style={{ ...row, gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' }}>
        <div style={card}>
          <SectionTitle info={EXPLAIN.threatTypes}>Risk by Threat Type</SectionTitle>
          {data.riskByThreatType.length === 0 && <Empty>No threats in this scope.</Empty>}
          {data.riskByThreatType.map((c: any, i: number) => (
            <div key={c.category} style={{ marginBottom: 12 }}>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 4 }}>{c.label}</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ flex: 1, height: 9, borderRadius: 5, background: 'rgba(255,255,255,0.06)' }}>
                  <div style={{ width: `${Math.max(6, c.pct)}%`, height: '100%', borderRadius: 5, background: barColor(i) }} />
                </div>
                <span style={{ fontSize: '0.8rem', fontWeight: 700, width: 18, textAlign: 'right' }}>{c.n}</span>
                <span style={{ ...muted, fontSize: '0.72rem', width: 40 }}>({c.pct}%)</span>
              </div>
            </div>
          ))}
        </div>
        <div style={card}>
          <SectionTitle info={EXPLAIN.compliance}>Compliance Mapping</SectionTitle>
          {data.complianceMapping.length === 0 ? <Empty>No open risks touch mapped controls.</Empty> : (
            <table style={tableStyle}>
              <thead><tr><th style={th}>Framework</th><th style={th}>Relevant Controls</th><th style={th} /></tr></thead>
              <tbody>
                {data.complianceMapping.map((f: any) => (
                  <tr key={f.framework}>
                    <td style={{ ...td, fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap' }}>{f.label}</td>
                    <td style={{ ...td, ...muted }} title={f.controls.join(', ')}>
                      {f.controls.slice(0, 3).join(', ')}{f.controls.length > 3 ? '…' : ''}
                    </td>
                    <td style={td}>
                      <span title="Controls touched by open risks — indicative, not an assessment result" style={{
                        background: f.gaps >= 5 ? 'rgba(244,63,94,0.85)' : f.gaps >= 3 ? 'rgba(245,158,11,0.85)' : 'rgba(34,197,94,0.8)',
                        color: '#0b1020', fontWeight: 700, fontSize: '0.68rem', padding: '2px 7px', borderRadius: 5, whiteSpace: 'nowrap',
                      }}>{f.gaps} at risk</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div style={{ ...muted, fontSize: '0.68rem', marginTop: 8 }}>
            Indicative mapping of open risks to controls. Not a compliance determination — control effectiveness needs RMF assessment evidence.
          </div>
        </div>
        <div style={card}>
          <SectionTitle info={EXPLAIN.heatMap}>Risk Heat Map</SectionTitle>
          <HeatMap points={data.heatPoints} onOpen={onOpenScenario} />
        </div>

      </div>

      {/* Top threat scenarios · recommended actions */}
      <div style={{ ...row, gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))' }}>
        <div style={card}>
          <SectionTitle info={EXPLAIN.topScenarios}>Top Threat Scenarios</SectionTitle>
          {data.topScenarios.length === 0 ? <Empty>No threat scenarios in this scope.</Empty> : (
            <div style={{ overflowX: 'auto' }}>
              <table style={tableStyle}>
                <thead><tr><th style={th}>#</th><th style={th}>Threat Scenario</th><th style={th}>Risk</th><th style={th}>Controls</th><th style={th}>Status</th></tr></thead>
                <tbody>
                  {data.topScenarios.map((s: any) => (
                    <tr key={s.id}>
                      <td style={td}>{s.rank}</td>
                      <td style={td}>
                        <LinkButton onClick={() => onOpenScenario(s.id)}>{s.title}</LinkButton>
                        {(s.intel?.kev || s.intel?.ransomware || s.intel?.epss_max != null) && (
                          <div style={{ marginTop: 3 }}><IntelBadges kev={s.intel.kev} ransomware={s.intel.ransomware} epss={s.intel.epss_max} /></div>
                        )}
                        {s.via_path_to && <div style={{ ...muted, fontSize: '0.7rem' }}>path to {s.via_path_to}</div>}
                      </td>
                      <td style={td}><LevelBadge level={s.level} /></td>
                      <td style={{ ...td, ...muted, fontSize: '0.72rem' }}>{s.controls.slice(0, 2).join(', ')}</td>
                      <td style={td}><StatusPill status={s.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div style={card}>
          <SectionTitle info={EXPLAIN.actions} right={<LinkButton onClick={onViewAllScenarios}>View All <ArrowRight size={12} /></LinkButton>}>Recommended Actions</SectionTitle>
          {data.recommendedActions.length === 0 ? <Empty>No actions needed.</Empty> : (
            <div style={{ overflowX: 'auto' }}>
              <table style={tableStyle}>
                <thead><tr><th style={th}>Priority</th><th style={th}>Action</th><th style={th}>Owner</th><th style={th}>Target Date</th></tr></thead>
                <tbody>
                  {data.recommendedActions.map((m: any) => (
                    <tr key={m.id}>
                      <td style={td}>
                        <span style={{ background: PRIORITY_COLOR[m.priority], color: '#fff', fontWeight: 700, fontSize: '0.7rem', borderRadius: 5, padding: '3px 8px' }}>{m.priority}</span>
                      </td>
                      <td style={td} title={m.action}>
                        <LinkButton onClick={() => onOpenAsset(m.asset_id)}>
                          <span style={{ display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden', color: 'var(--text-secondary)' }}>{m.action}</span>
                        </LinkButton>
                        {(m.kev || m.epss_max != null) && <div style={{ marginTop: 3 }}><IntelBadges kev={m.kev} epss={m.epss_max} dueDate={m.kev_due_date} /></div>}
                      </td>
                      <td style={{ ...td, whiteSpace: 'nowrap' }}>{m.owner || <span style={muted}>Unassigned</span>}</td>
                      <td style={{ ...td, whiteSpace: 'nowrap' }}>{m.target_date ? new Date(`${m.target_date}T00:00:00`).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) : <span style={muted}>—</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* QuarkShield differentiators: attack paths, PQC/HNDL, framework coverage */}
      <div style={{ ...row, gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}>
        <div style={card}>
          <SectionTitle info={EXPLAIN.attackPaths}>Attack Paths</SectionTitle>
          {data.attackPaths.length === 0 && <Empty>No attack path reaches a sensitive asset in this scope.</Empty>}
          {data.attackPaths.map((p: any) => (
            <div key={p.id} style={{ padding: '0.5rem 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <PathRiskBadge path={p} /><Chip>{p.confidence} confidence</Chip>
                <span style={{ marginLeft: 'auto' }}><LinkButton onClick={() => onOpenPath(p.id)}><span style={{ whiteSpace: 'nowrap' }}>View graph →</span></LinkButton></span>
              </div>
              <PathChain hops={p.hops} onAsset={onOpenAsset} />
            </div>
          ))}
        </div>
        <div style={card}>
          <SectionTitle info={EXPLAIN.crypto}>Cryptographic Exposure · PQC / HNDL</SectionTitle>
          {data.cryptoExposure.length === 0 && <Empty>No cryptographic findings in this scope.</Empty>}
          {data.cryptoExposure.map((c: any) => (
            <div key={c.purpose} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: '0.8rem', padding: '0.35rem 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
              <span style={{ color: 'var(--text-secondary)' }}>{c.label}</span>
              <span style={muted}>
                {c.quantum_vulnerable}/{c.total} quantum-vulnerable{c.hndl ? <span style={{ color: LEVEL_META.critical.color }}> · {c.hndl} HNDL</span> : ''}{c.weak ? ` · ${c.weak} weak` : ''}
              </span>
            </div>
          ))}
          <div style={{ ...muted, fontSize: '0.7rem', marginTop: 8 }}>Key establishment → ML-KEM / hybrid (HNDL); signatures, SSH and certificates → ML-DSA migration.</div>
        </div>
        <div style={card}>
          <SectionTitle info={EXPLAIN.frameworksCoverage}>STRIDE &amp; MITRE ATT&amp;CK®</SectionTitle>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
            {['S', 'T', 'R', 'I', 'D', 'E'].map(l => {
              const s = data.stride.find((x: any) => x.ref === l);
              return <Chip key={l} title={s?.label} color={s ? 'var(--accent-cyan, #00f2fe)' : undefined}>{l} · {s?.n || 0}</Chip>;
            })}
          </div>
          {data.attack.slice(0, 6).map((a: any) => (
            <div key={a.ref} style={{ display: 'flex', gap: 8, fontSize: '0.76rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
              <Chip>{a.ref}</Chip><span style={{ flex: 1 }}>{a.name}</span><span style={muted}>{a.n}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
