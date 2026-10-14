import React, { useRef, useState } from 'react';
import { Info } from 'lucide-react';

/** Shared look for the Threat & Risk Graph screens (matches the console's dark/cyan theme). */

export const LEVEL_META: Record<string, { label: string; color: string; bg: string }> = {
  critical: { label: 'Critical', color: '#ff3366', bg: 'rgba(255,51,102,0.14)' },
  high: { label: 'High', color: '#ff8a3d', bg: 'rgba(255,138,61,0.14)' },
  medium: { label: 'Medium', color: '#ffaa00', bg: 'rgba(255,170,0,0.12)' },
  low: { label: 'Low', color: '#4ade80', bg: 'rgba(74,222,128,0.12)' },
};

export const levelOf = (score: number): string =>
  score >= 12 ? 'critical' : score >= 6 ? 'high' : score >= 3 ? 'medium' : 'low';

export const ASSET_TYPE_LABEL: Record<string, string> = {
  endpoint: 'User endpoint', server: 'Server', service: 'Service', database: 'Database',
  tls_endpoint: 'TLS endpoint', proxy: 'PQC proxy', kms: 'PKI / KMS', repo: 'Repository',
  network_segment: 'Network segment',
};

export const REL_LABEL: Record<string, string> = {
  connects_to: 'connects to', serves: 'serves', stores_data_in: 'stores data in', authenticates_via: 'authenticates via',
  trusts: 'trusts', ssh_to: 'SSH to', deployed_from: 'deployed from', network_adjacent: 'network-adjacent', runs: 'runs',
};

export const REM_STATUS: { id: string; label: string }[] = [
  { id: 'open', label: 'Open' }, { id: 'in_progress', label: 'In progress' }, { id: 'done', label: 'Done' },
  { id: 'verified', label: 'Verified' }, { id: 'risk_accepted', label: 'Risk accepted' },
];

export const card: React.CSSProperties = {
  background: 'var(--bg-card, rgba(13,19,33,0.75))',
  border: '1px solid var(--border-normal, rgba(255,255,255,0.07))',
  borderRadius: 10,
  padding: '1rem 1.1rem',
  minWidth: 0,
};

export const muted: React.CSSProperties = { color: 'var(--text-muted, #94a3b8)', fontSize: '0.78rem' };

export const LevelBadge: React.FC<{ level?: string; score?: number }> = ({ level, score }) => {
  const m = LEVEL_META[level || 'low'] || LEVEL_META.low;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4, padding: '0.12rem 0.5rem', borderRadius: 999,
      background: m.bg, color: m.color, fontSize: '0.7rem', fontWeight: 700, whiteSpace: 'nowrap',
    }}>
      {m.label}{score !== undefined ? ` · ${score}` : ''}
    </span>
  );
};

export const Chip: React.FC<{ children: React.ReactNode; title?: string; color?: string }> = ({ children, title, color }) => (
  <span title={title} style={{
    display: 'inline-block', padding: '0.1rem 0.45rem', borderRadius: 6, fontSize: '0.7rem',
    border: `1px solid ${color || 'rgba(255,255,255,0.12)'}`, color: color || 'var(--text-secondary, #cbd5e1)',
    fontFamily: 'var(--font-mono, monospace)', whiteSpace: 'nowrap',
  }}>{children}</span>
);

export interface TipContent { what: React.ReactNode; source?: React.ReactNode; how?: React.ReactNode }

/**
 * Hover / keyboard-focus explanation: what this is, where the data comes from, how it is
 * computed. Rendered with position:fixed so cards with overflow never clip it.
 */
export const InfoTip: React.FC<{ tip: TipContent; size?: number }> = ({ tip, size = 13 }) => {
  const ref = useRef<HTMLSpanElement>(null);
  const [pos, setPos] = useState<{ left: number; top: number; above: boolean } | null>(null);
  const show = () => {
    const r = ref.current?.getBoundingClientRect();
    if (!r) return;
    const W = 320;
    const left = Math.max(8, Math.min(window.innerWidth - W - 8, r.left + r.width / 2 - W / 2));
    const above = r.bottom + 230 > window.innerHeight;
    setPos({ left, top: above ? r.top - 8 : r.bottom + 8, above });
  };
  const hide = () => setPos(null);
  const row = (label: string, body: React.ReactNode) => body ? (
    <div style={{ marginTop: 6 }}>
      <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#7dd3fc', marginBottom: 2 }}>{label}</div>
      <div>{body}</div>
    </div>
  ) : null;
  return (
    <span ref={ref} tabIndex={0} role="button" aria-label="What is this?" onMouseEnter={show} onMouseLeave={hide} onFocus={show} onBlur={hide}
      style={{ display: 'inline-flex', alignItems: 'center', cursor: 'help', color: 'var(--text-muted, #94a3b8)', verticalAlign: 'middle', outline: 'none' }}>
      <Info size={size} />
      {pos && (
        <span role="tooltip" style={{
          position: 'fixed', left: pos.left, top: pos.top, transform: pos.above ? 'translateY(-100%)' : undefined, zIndex: 1000,
          width: 320, padding: '10px 12px', borderRadius: 8, background: '#0b1224', border: '1px solid rgba(56,189,248,0.35)',
          boxShadow: '0 10px 30px rgba(0,0,0,0.5)', color: '#e2e8f0', fontSize: 12, lineHeight: 1.45, fontWeight: 400,
          textTransform: 'none', letterSpacing: 'normal', whiteSpace: 'normal', textAlign: 'left', pointerEvents: 'none',
        }}>
          {row('What it is', tip.what)}
          {row('Data source', tip.source)}
          {row('How it is computed', tip.how)}
        </span>
      )}
    </span>
  );
};

export const SectionTitle: React.FC<{ children: React.ReactNode; right?: React.ReactNode; info?: TipContent }> = ({ children, right, info }) => (
  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: '0.7rem' }}>
    <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 600, color: 'var(--text-primary, #f8fafc)', display: 'flex', alignItems: 'center', gap: 6 }}>
      {children}{info && <InfoTip tip={info} />}
    </h3>
    {right}
  </div>
);

export const LinkButton: React.FC<{ onClick: () => void; children: React.ReactNode }> = ({ onClick, children }) => (
  <button onClick={onClick} style={{
    background: 'none', border: 'none', padding: 0, color: 'var(--accent-cyan, #00f2fe)', cursor: 'pointer',
    font: 'inherit', textAlign: 'left',
  }}>{children}</button>
);

export const Empty: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div style={{ ...muted, padding: '1.2rem 0.4rem', textAlign: 'center' }}>{children}</div>
);

export const tableStyle: React.CSSProperties = { width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' };
export const th: React.CSSProperties = {
  textAlign: 'left', padding: '0.45rem 0.6rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 600,
  fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.04em', borderBottom: '1px solid rgba(255,255,255,0.08)',
};
export const td: React.CSSProperties = {
  padding: '0.5rem 0.6rem', borderBottom: '1px solid rgba(255,255,255,0.05)', color: 'var(--text-secondary, #cbd5e1)', verticalAlign: 'top',
};

/** Residual path risk, with the inherent score in the tooltip. */
export const PathRiskBadge: React.FC<{ path: any }> = ({ path }) => (
  <span title={`Inherent ${path.path_risk} (L${path.likelihood} × I${path.impact}); residual reflects remediation progress`}>
    <LevelBadge level={path.residual_level || path.level} score={path.residual_score ?? path.path_risk} />
  </span>
);

/** Exploitation-intelligence badges: CISA KEV, known ransomware use, FIRST EPSS. */
export const IntelBadges: React.FC<{ kev?: boolean; ransomware?: boolean; epss?: number | null; percentile?: number | null; dueDate?: string | null }> =
  ({ kev, ransomware, epss, percentile, dueDate }) => {
    // Two decimals at the extremes so 0.9996 reads 99.96%, not a misleading 100.0%.
    const pct = (n: number) => `${(n * 100).toFixed(n < 0.01 || n >= 0.995 ? 2 : 1)}%`;
    const pill = (bg: string, text: string, title: string) => (
      <span title={title} style={{ background: bg, color: '#fff', fontSize: '0.64rem', fontWeight: 700, borderRadius: 4, padding: '1px 5px', whiteSpace: 'nowrap' }}>{text}</span>
    );
    return (
      <span style={{ display: 'inline-flex', gap: 4, flexWrap: 'wrap', verticalAlign: 'middle' }}>
        {kev && pill('#b91c1c', 'KEV', `Listed in CISA Known Exploited Vulnerabilities — exploited in the wild${dueDate ? `. CISA remediation due date (federal, BOD 22-01): ${dueDate}` : ''}`)}
        {ransomware && pill('#7c2d12', 'RANSOMWARE', 'CISA KEV: known use in ransomware campaigns')}
        {typeof epss === 'number' && pill(epss >= 0.5 ? '#c2410c' : epss >= 0.1 ? '#a16207' : '#334155', `EPSS ${pct(epss)}`,
          `FIRST EPSS: ${pct(epss)} probability of exploitation activity in the next 30 days${percentile != null ? ` (${Math.round(percentile * 100)}th percentile)` : ''}`)}
      </span>
    );
  };

/** Attack path rendered inline as a chain of hops. */
export const PathChain: React.FC<{ hops: any[]; onAsset?: (id: string) => void }> = ({ hops, onAsset }) => (
  <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 4, fontSize: '0.76rem' }}>
    <span style={{ color: '#ff8a3d' }}>Threat actor</span>
    {hops.map((h, i) => (
      <React.Fragment key={`${h.asset_id}-${i}`}>
        <span style={{ color: 'var(--text-muted, #94a3b8)' }}>→</span>
        {onAsset
          ? <LinkButton onClick={() => onAsset(h.asset_id)}>{h.name || h.asset_id}</LinkButton>
          : <span>{h.name || h.asset_id}</span>}
      </React.Fragment>
    ))}
    <span style={{ color: 'var(--text-muted, #94a3b8)' }}>→</span>
    <span style={{ color: '#ff3366' }}>Impact</span>
  </div>
);

export const selectStyle: React.CSSProperties = {
  background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 6,
  color: 'var(--text-primary, #f8fafc)', padding: '0.3rem 0.45rem', fontSize: '0.78rem',
};
