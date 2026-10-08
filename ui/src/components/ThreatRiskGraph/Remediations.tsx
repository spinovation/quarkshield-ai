import React, { useState } from 'react';
import { Loader2 } from 'lucide-react';
import type { ThreatApi } from './api';
import { Chip, muted, REM_STATUS, selectStyle, Empty, LEVEL_META } from './ui';

/**
 * Remediation workflow: owner, target date and status. Residual risk is recomputed
 * server-side only from status (done/verified) — never from configuration presence.
 */
export const Remediations: React.FC<{ api: ThreatApi; items: any[]; onChanged: () => void }> = ({ api, items, onChanged }) => {
  const [saving, setSaving] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<Record<string, { owner?: string; target_date?: string }>>({});

  const save = async (id: string, patch: Record<string, unknown>) => {
    setSaving(id); setError(null);
    try {
      await api.updateRemediation(id, patch);
      onChanged();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setSaving(null);
    }
  };

  if (!items.length) return <Empty>No remediation actions for this selection.</Empty>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {error && <div style={{ color: LEVEL_META.critical.color, fontSize: '0.8rem' }}>{error}</div>}
      {items.map(m => {
        const d = drafts[m.id] || {};
        const owner = d.owner ?? m.state.owner ?? '';
        const target = d.target_date ?? m.state.target_date ?? '';
        const dirty = d.owner !== undefined || d.target_date !== undefined;
        return (
          <div key={m.id} style={{ padding: '0.6rem 0.7rem', borderRadius: 8, border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.02)' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-primary, #f8fafc)', marginBottom: 4 }}>{m.action}</div>
            {m.command && <code style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-secondary)', marginBottom: 6, wordBreak: 'break-all' }}>{m.command}</code>}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
              <Chip>{m.action_type.replace(/_/g, ' ')}</Chip>
              {m.breaks_paths > 0 && <span style={muted}>breaks {m.breaks_paths} attack path{m.breaks_paths > 1 ? 's' : ''}</span>}
              <select aria-label="Remediation status" value={m.state.status} disabled={saving === m.id} style={selectStyle}
                onChange={e => save(m.id, { status: e.target.value })}>
                {REM_STATUS.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
              </select>
              <input aria-label="Owner" placeholder="Owner" value={owner} style={{ ...selectStyle, width: 130 }}
                onChange={e => setDrafts(p => ({ ...p, [m.id]: { ...p[m.id], owner: e.target.value } }))} />
              <input aria-label="Target date" type="date" value={target} style={selectStyle}
                onChange={e => setDrafts(p => ({ ...p, [m.id]: { ...p[m.id], target_date: e.target.value } }))} />
              {dirty && (
                <button disabled={saving === m.id} style={{ ...selectStyle, cursor: 'pointer', color: 'var(--accent-cyan, #00f2fe)' }}
                  onClick={async () => {
                    await save(m.id, { owner: owner || null, target_date: target || null });
                    setDrafts(p => { const n = { ...p }; delete n[m.id]; return n; });
                  }}>Save</button>
              )}
              {saving === m.id && <Loader2 size={14} className="spin" />}
            </div>
            {m.state.updated_by && <div style={{ ...muted, marginTop: 4, fontSize: '0.7rem' }}>Updated by {m.state.updated_by}</div>}
          </div>
        );
      })}
    </div>
  );
};
