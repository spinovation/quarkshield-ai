import React, { useEffect, useState } from 'react';
import { ShieldCheck, ShieldAlert, Clock } from 'lucide-react';

/**
 * Tenant-admin control for the time-boxed "Support Access" window.
 * While active, a QuarkShield super-admin may view this tenant's component-level
 * SBOM for troubleshooting; otherwise they see only aggregate metrics. Every
 * super-admin access during the window is audit-logged.
 */
export default function SupportAccessCard({ apiUrl = '', canManage = true }: { apiUrl?: string; canManage?: boolean }) {
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [active, setActive] = useState(false);
  const [expiresAt, setExpiresAt] = useState<string | null>(null);
  const [grantedBy, setGrantedBy] = useState<string | null>(null);
  const [hours, setHours] = useState(24);
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const r = await fetch(`${apiUrl}/api/support-access/status`, { credentials: 'include' });
      if (r.ok) {
        const d = await r.json();
        setActive(!!d.active);
        setExpiresAt(d.grant?.expires_at || null);
        setGrantedBy(d.grant?.granted_by || null);
      }
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  };

  useEffect(() => { refresh(); }, []);

  const grant = async () => {
    setBusy(true); setError(null);
    try {
      const r = await fetch(`${apiUrl}/api/support-access/grant`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ durationHours: hours, reason: reason.trim() || undefined })
      });
      const d = await r.json();
      if (!r.ok || !d.success) throw new Error(d.error || 'Failed to enable support access.');
      await refresh();
    } catch (e: any) { setError(e.message || 'Failed to enable support access.'); }
    finally { setBusy(false); }
  };

  const revoke = async () => {
    setBusy(true); setError(null);
    try {
      const r = await fetch(`${apiUrl}/api/support-access/revoke`, { method: 'POST', credentials: 'include' });
      const d = await r.json();
      if (!r.ok || !d.success) throw new Error(d.error || 'Failed to revoke support access.');
      await refresh();
    } catch (e: any) { setError(e.message || 'Failed to revoke support access.'); }
    finally { setBusy(false); }
  };

  return (
    <div style={{
      background: active ? 'rgba(34, 197, 94, 0.06)' : 'rgba(255, 255, 255, 0.02)',
      border: `1px solid ${active ? 'rgba(34, 197, 94, 0.4)' : 'rgba(255, 255, 255, 0.1)'}`,
      borderRadius: '12px', padding: '1.2rem 1.4rem'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.5rem' }}>
        {active ? <ShieldCheck size={18} color="#4ade80" /> : <ShieldAlert size={18} color="#94a3b8" />}
        <h4 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 700, color: '#ffffff' }}>QuarkShield Support Access</h4>
        <span style={{
          fontSize: '0.66rem', padding: '0.12rem 0.5rem', borderRadius: '10px', fontWeight: 700,
          background: active ? 'rgba(34, 197, 94, 0.18)' : 'rgba(148, 163, 184, 0.15)',
          color: active ? '#4ade80' : '#94a3b8'
        }}>{active ? 'ACTIVE' : 'OFF'}</span>
      </div>
      <p style={{ margin: '0 0 0.9rem', fontSize: '0.8rem', color: 'var(--text-muted, #94a3b8)', lineHeight: 1.5, maxWidth: '640px' }}>
        By default QuarkShield support (super-admin) sees only aggregate metrics for your tenant — never your package
        names, versions, hosts or CVE detail. Enable a time-boxed window to let them view component-level data while
        troubleshooting. It auto-expires, you can revoke anytime, and every access is audit-logged.
      </p>

      {loading ? (
        <div style={{ fontSize: '0.8rem', color: '#64748b' }}>Loading…</div>
      ) : active ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', color: '#bbf7d0' }}>
            <Clock size={14} /> Expires {expiresAt ? new Date(expiresAt).toLocaleString() : '—'}
            {grantedBy ? ` · by ${grantedBy}` : ''}
          </span>
          {canManage && (
            <button onClick={revoke} disabled={busy} style={{
              background: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.4)', color: '#fca5a5',
              padding: '0.4rem 0.9rem', borderRadius: '6px', fontSize: '0.8rem', fontWeight: 600,
              cursor: busy ? 'not-allowed' : 'pointer'
            }}>{busy ? 'Revoking…' : 'Revoke now'}</button>
          )}
        </div>
      ) : canManage ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.7rem', flexWrap: 'wrap' }}>
          <select value={hours} onChange={e => setHours(Number(e.target.value))} style={{
            background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.15)', color: '#fff',
            padding: '0.4rem 0.6rem', borderRadius: '6px', fontSize: '0.8rem'
          }}>
            <option value={24}>24 hours</option>
            <option value={48}>48 hours</option>
            <option value={72}>72 hours</option>
          </select>
          <input value={reason} onChange={e => setReason(e.target.value)} placeholder="Reason (optional, e.g. ticket #)" style={{
            background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.15)', color: '#fff',
            padding: '0.4rem 0.7rem', borderRadius: '6px', fontSize: '0.8rem', flex: '1 1 240px', maxWidth: '360px'
          }} />
          <button onClick={grant} disabled={busy} style={{
            background: 'rgba(34, 197, 94, 0.15)', border: '1px solid rgba(34, 197, 94, 0.45)', color: '#4ade80',
            padding: '0.4rem 1rem', borderRadius: '6px', fontSize: '0.8rem', fontWeight: 600,
            cursor: busy ? 'not-allowed' : 'pointer'
          }}>{busy ? 'Enabling…' : 'Enable support access'}</button>
        </div>
      ) : (
        <div style={{ fontSize: '0.8rem', color: '#64748b' }}>Only a tenant administrator can enable support access.</div>
      )}

      {error && <div style={{ marginTop: '0.6rem', fontSize: '0.78rem', color: '#fca5a5' }}>{error}</div>}
    </div>
  );
}
