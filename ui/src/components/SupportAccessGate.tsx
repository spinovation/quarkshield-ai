import React from 'react';
import { Lock, ShieldCheck, Building } from 'lucide-react';
import { TenantAggregate, formatExpiry } from '../lib/supportScope';

/**
 * "Support access required" state for the platform console. Shown wherever the
 * console used to list a tenant's hosts / assets / findings: the server no longer
 * releases those to a platform admin without the tenant's time-boxed grant.
 */
export const SupportAccessRequired: React.FC<{ tenantLabel?: string | null; what?: string; compact?: boolean }> = ({ tenantLabel, what = 'host and asset detail', compact }) => (
  <div data-testid="support-access-required" style={{
    display: 'flex', gap: '0.85rem', alignItems: 'flex-start',
    background: 'rgba(245, 158, 11, 0.07)', border: '1px solid rgba(245, 158, 11, 0.35)',
    borderRadius: '10px', padding: compact ? '0.8rem 1rem' : '1.1rem 1.25rem',
  }}>
    <Lock size={18} color="#fbbf24" style={{ flexShrink: 0, marginTop: '0.1rem' }} />
    <div>
      <div style={{ fontWeight: 700, color: '#fde68a', fontSize: '0.92rem', marginBottom: '0.25rem' }}>
        Support access required
      </div>
      <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary, #cbd5e1)', lineHeight: 1.55, maxWidth: '760px' }}>
        {tenantLabel
          ? <>Tenant data belongs to the tenant. <strong style={{ color: '#fff' }}>{tenantLabel}</strong> has not opened a support-access window, so {what} is not available to platform administrators — only the aggregate metrics shown here.</>
          : <>Tenant data belongs to each tenant. Across the fleet you see aggregate metrics only. To view {what}, select one tenant that has opened a support-access window.</>}
        {' '}A tenant administrator enables it from the <em>QuarkShield Support Access</em> card in their own portal (24–72 hours, revocable, every access audit-logged).
      </div>
    </div>
  </div>
);

/** Small pill: the tenant's support window is open until … */
export const SupportAccessActive: React.FC<{ tenantLabel: string; expiresAt: string | null }> = ({ tenantLabel, expiresAt }) => (
  <div style={{
    display: 'flex', gap: '0.6rem', alignItems: 'center', flexWrap: 'wrap',
    background: 'rgba(34, 197, 94, 0.07)', border: '1px solid rgba(34, 197, 94, 0.35)',
    borderRadius: '10px', padding: '0.65rem 1rem', fontSize: '0.82rem', color: '#bbf7d0',
  }}>
    <ShieldCheck size={16} color="#4ade80" />
    <span><strong style={{ color: '#fff' }}>{tenantLabel}</strong> has granted support access — detail is visible until <strong>{formatExpiry(expiresAt)}</strong>. Every request you make is audit-logged.</span>
  </div>
);

const th: React.CSSProperties = { textAlign: 'left', padding: '0.6rem 0.75rem', fontSize: '0.7rem', color: 'var(--text-muted, #94a3b8)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 700, whiteSpace: 'nowrap' };
const td: React.CSSProperties = { padding: '0.65rem 0.75rem', fontSize: '0.84rem', color: 'var(--text-primary, #e2e8f0)', borderTop: '1px solid rgba(255,255,255,0.06)', verticalAlign: 'top' };

/** Per-tenant aggregates: counts, risk, seats, last-seen, agent versions. No host rows. */
export const TenantAggregateTable: React.FC<{
  tenants: TenantAggregate[];
  onSelect?: (tenantName: string) => void;
}> = ({ tenants, onSelect }) => {
  if (!tenants.length) {
    return <div style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)', fontSize: '0.9rem' }}>No enrolled endpoints yet.</div>;
  }
  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={th}>Tenant</th>
            <th style={th}>Endpoints</th>
            <th style={th}>Online (24h)</th>
            <th style={th}>Crypto assets</th>
            <th style={th}>Vulnerable</th>
            <th style={th}>Avg risk</th>
            <th style={th}>Last seen</th>
            <th style={th}>Agent versions</th>
            <th style={th}>Support access</th>
          </tr>
        </thead>
        <tbody>
          {tenants.map(t => (
            <tr key={t.tenantName}>
              <td style={td}>
                <span
                  onClick={onSelect ? () => onSelect(t.tenantName) : undefined}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '0.45rem', fontWeight: 700, color: '#fff', cursor: onSelect ? 'pointer' : 'default' }}
                >
                  <Building size={14} color="var(--accent-cyan)" /> {t.tenantName}
                </span>
              </td>
              <td style={td}>{t.machineCount}</td>
              <td style={td}>{t.onlineCount}</td>
              <td style={td}>{t.assetCount.toLocaleString()}</td>
              <td style={{ ...td, color: t.vulnerableCount > 0 ? '#fca5a5' : td.color }}>{t.vulnerableCount.toLocaleString()}</td>
              <td style={{ ...td, color: t.avgRiskScore > 60 ? '#fca5a5' : td.color }}>{t.avgRiskScore} / 100</td>
              <td style={td}>{t.lastSeen ? new Date(t.lastSeen).toLocaleString() : '—'}</td>
              <td style={{ ...td, fontFamily: 'monospace', fontSize: '0.78rem' }}>
                {Object.entries(t.agentVersions).map(([v, n]) => `${v} ×${n}`).join(', ') || '—'}
              </td>
              <td style={td}>
                {t.supportAccess.active ? (
                  <span style={{ color: '#4ade80', fontWeight: 600, fontSize: '0.78rem' }}>
                    Granted · until {formatExpiry(t.supportAccess.expiresAt)}
                  </span>
                ) : (
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', color: '#fbbf24', fontSize: '0.78rem' }}>
                    <Lock size={11} /> Not granted
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
