import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Loader2, Search } from 'lucide-react';
import type { ThreatApi } from './api';
import { Remediations } from './Remediations';
import {
  card, muted, LevelBadge, PathRiskBadge, Chip, SectionTitle, LinkButton, Empty, PathChain, levelOf, LEVEL_META, ASSET_TYPE_LABEL,
  REL_LABEL, tableStyle, th, td, selectStyle,
} from './ui';

interface Props {
  api: ThreatApi;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onOpenScenario: (id: string) => void;
  onOpenPath: (id: string) => void;
  onFocusGraph: (id: string) => void;
  onChanged: () => void;
}

/** Admins may correct INFERRED context (impact inputs). Relationships are never edited. */
const ContextEditor: React.FC<{ api: ThreatApi; asset: any; override: any; onSaved: () => void }> = ({ api, asset, override, onSaved }) => {
  const [crit, setCrit] = useState<number>(asset.criticality);
  const [cls, setCls] = useState<string>(asset.data_classification);
  const [env, setEnv] = useState<string>(asset.environment || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { setCrit(asset.criticality); setCls(asset.data_classification); setEnv(asset.environment || ''); }, [asset]);
  const run = async (body: unknown) => {
    setSaving(true); setError(null);
    try { await api.setContext(asset.id, body); onSaved(); } catch (e: any) { setError(e.message); } finally { setSaving(false); }
  };
  const changed = crit !== asset.criticality || cls !== asset.data_classification || env !== (asset.environment || '');
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center', fontSize: '0.78rem' }}>
      <label style={muted}>Criticality</label>
      <select value={crit} onChange={e => setCrit(Number(e.target.value))} style={selectStyle}>
        {[1, 2, 3, 4].map(n => <option key={n} value={n}>{n}</option>)}
      </select>
      <label style={muted}>Classification</label>
      <select value={cls} onChange={e => setCls(e.target.value)} style={selectStyle}>
        {['public', 'internal', 'sensitive', 'cui'].map(c => <option key={c} value={c}>{c.toUpperCase() === 'CUI' ? 'CUI' : c}</option>)}
      </select>
      <label style={muted}>Environment</label>
      <select value={env} onChange={e => setEnv(e.target.value)} style={selectStyle}>
        <option value="">unknown</option>
        {['production', 'staging', 'development'].map(c => <option key={c} value={c}>{c}</option>)}
      </select>
      {changed && <button disabled={saving} onClick={() => run({ criticality: crit, data_classification: cls, environment: env || null })}
        style={{ ...selectStyle, cursor: 'pointer', color: 'var(--accent-cyan, #00f2fe)' }}>Save override</button>}
      {override && <button disabled={saving} onClick={() => run({ clear: true })}
        style={{ ...selectStyle, cursor: 'pointer' }}>Revert to inferred</button>}
      {saving && <Loader2 size={14} className="spin" />}
      {error && <span style={{ color: LEVEL_META.critical.color }}>{error}</span>}
    </div>
  );
};

export const AssetDetail: React.FC<Props> = ({ api, selectedId, onSelect, onOpenScenario, onOpenPath, onFocusGraph, onChanged }) => {
  const [list, setList] = useState<any[] | null>(null);
  const [detail, setDetail] = useState<any | null>(null);
  const [q, setQ] = useState('');
  const [error, setError] = useState<string | null>(null);

  const loadList = useCallback(() => {
    api.assets().then(setList).catch(e => setError(e.message));
  }, [api]);
  const loadDetail = useCallback(() => {
    if (!selectedId) return;
    api.asset(selectedId).then(setDetail).catch(e => setError(e.message));
  }, [api, selectedId]);
  useEffect(() => { loadList(); }, [loadList]);
  // Default to the highest-risk item once the list arrives.
  useEffect(() => { if (!selectedId && list?.length) onSelect(list[0].id); }, [list, selectedId, onSelect]);
  useEffect(() => { setDetail(null); loadDetail(); }, [loadDetail]);
  const refresh = () => { loadList(); loadDetail(); onChanged(); };

  const filtered = useMemo(() => (list || []).filter(a => !q || `${a.name} ${a.type}`.toLowerCase().includes(q.toLowerCase())), [list, q]);
  const a = detail?.asset;

  return (
    <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'flex-start' }}>
      <div style={{ ...card, flex: '1 1 260px', maxWidth: 360, maxHeight: 760, overflowY: 'auto', padding: '0.6rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, padding: '0 0.3rem' }}>
          <Search size={14} color="var(--text-muted)" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter assets" aria-label="Filter assets"
            style={{ ...selectStyle, flex: 1, minWidth: 0 }} />
        </div>
        {!list && <div style={{ padding: '1rem' }}><Loader2 size={16} className="spin" /></div>}
        {list && filtered.length === 0 && <Empty>No assets.</Empty>}
        {filtered.map(x => (
          <button key={x.id} onClick={() => onSelect(x.id)} style={{
            display: 'block', width: '100%', textAlign: 'left', padding: '0.5rem 0.6rem', marginBottom: 4, borderRadius: 7, cursor: 'pointer',
            background: x.id === selectedId ? 'rgba(0,242,254,0.1)' : 'transparent',
            border: x.id === selectedId ? '1px solid rgba(0,242,254,0.3)' : '1px solid transparent', color: 'inherit', font: 'inherit',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 6, alignItems: 'center' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-primary, #f8fafc)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{x.name}</span>
              {x.max_risk > 0 && <LevelBadge level={levelOf(x.max_risk)} score={x.max_risk} />}
            </div>
            <div style={muted}>{ASSET_TYPE_LABEL[x.type] || x.type}{x.internet_exposed ? ' · exposed' : ''}{x.vulns ? ` · ${x.vulns} CVE` : ''}{x.quantum ? ` · ${x.quantum} quantum` : ''}</div>
          </button>
        ))}
      </div>

      <div style={{ flex: '3 1 480px', minWidth: 0, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {error && <div style={{ ...card, color: LEVEL_META.critical.color }}>{error}</div>}
        {selectedId && !detail && !error && <div style={card}><Loader2 size={16} className="spin" /></div>}
        {a && (
          <>
            <div style={card}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
                <div style={{ minWidth: 0 }}>
                  <div style={muted}>{ASSET_TYPE_LABEL[a.type] || a.type}{a.environment ? ` · ${a.environment}` : ''}{a.internet_exposed ? ' · internet-exposed' : ''}</div>
                  <h2 style={{ margin: '0.2rem 0 0.4rem', fontSize: '1.05rem', wordBreak: 'break-word' }}>{a.name}</h2>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  {detail.risks[0] && <LevelBadge level={detail.risks[0].residual_level} score={detail.risks[0].residual_score} />}
                  <LinkButton onClick={() => onFocusGraph(a.id)}>Show in graph →</LinkButton>
                </div>
              </div>
              <ContextEditor api={api} asset={a} override={detail.override} onSaved={refresh} />
              <div style={{ ...muted, marginTop: 8 }}>
                {a.context_origin === 'override' ? `Context overridden by ${detail.override?.updated_by || 'an admin'}. ` : 'Context inferred: '}
                {(a.inference || []).join(' · ')}
              </div>
            </div>

            <div style={card}>
              <SectionTitle>Relationships (auto-discovered)</SectionTitle>
              {detail.relationships.length === 0 && <Empty>No relationships inferred for this asset yet.</Empty>}
              {detail.relationships.map((r: any) => {
                const peer = <LinkButton onClick={() => onSelect(r.peer_id)}>{r.peer_name || r.peer_id}</LinkButton>;
                const self = <strong style={{ fontWeight: 600 }}>this asset</strong>;
                return (
                  <div key={r.id} style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap', fontSize: '0.8rem', padding: '0.3rem 0' }}>
                    {r.direction === 'out' ? self : peer}
                    <span style={muted}>{REL_LABEL[r.kind] || r.kind}</span>
                    {r.direction === 'out' ? peer : self}
                    <Chip title={JSON.stringify(r.evidence)}>{r.rule_id}</Chip>
                    <Chip>{r.confidence}</Chip>
                  </div>
                );
              })}
            </div>

            <div style={card}>
              <SectionTitle>Threats &amp; risk</SectionTitle>
              {detail.threats.length === 0 && detail.risks.length === 0 && <Empty>No threats derived for this asset.</Empty>}
              {detail.threats.map((t: any) => {
                const r = detail.risks.find((x: any) => x.threat_id === t.id && !x.attack_path_id);
                return (
                  <div key={t.id} style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '0.35rem 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <LinkButton onClick={() => onOpenScenario(t.id)}>{t.title}</LinkButton>
                      <div style={muted}>{t.category_label} · STRIDE {t.stride.join('')} · {t.attack.join(', ')}</div>
                    </div>
                    {r && <LevelBadge level={r.residual_level} score={r.residual_score} />}
                  </div>
                );
              })}
              {detail.paths.length > 0 && (
                <div style={{ marginTop: 10 }}>
                  <div style={{ ...muted, marginBottom: 4 }}>Attack paths through this asset</div>
                  {detail.paths.map((p: any) => (
                    <div key={p.id} style={{ padding: '0.35rem 0' }}>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 2 }}>
                        <PathRiskBadge path={p} />
                        <LinkButton onClick={() => onOpenPath(p.id)}><span style={{ whiteSpace: 'nowrap' }}>View graph →</span></LinkButton>
                      </div>
                      <PathChain hops={p.hops} onAsset={onSelect} />
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div style={card}>
              <SectionTitle>Software components &amp; CVEs</SectionTitle>
              {detail.components.length === 0 ? <Empty>No SBOM components linked to this asset.</Empty> : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={tableStyle}>
                    <thead><tr><th style={th}>Component</th><th style={th}>Ecosystem</th><th style={th}>Vulnerabilities</th></tr></thead>
                    <tbody>
                      {detail.components.slice(0, 200).map((c: any) => (
                        <tr key={c.id}>
                          <td style={td}>{c.name}@{c.version}</td>
                          <td style={td}>{c.ecosystem}</td>
                          <td style={td}>
                            {c.vulnerabilities.length === 0 ? <span style={muted}>none known</span> : c.vulnerabilities.map((v: any) => (
                              <div key={v.id}><Chip color={v.cvss >= 9 ? LEVEL_META.critical.color : v.cvss >= 7 ? LEVEL_META.high.color : undefined}>{v.cve}</Chip> CVSS {v.cvss}{v.fixed_version ? ` · fix ${v.fixed_version}` : ''}</div>
                            ))}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div style={card}>
              <SectionTitle>Cryptography (by purpose)</SectionTitle>
              {detail.crypto.length === 0 ? <Empty>No cryptographic findings on this asset.</Empty> : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={tableStyle}>
                    <thead><tr><th style={th}>Finding</th><th style={th}>Purpose</th><th style={th}>Exposure</th><th style={th}>Recommendation</th></tr></thead>
                    <tbody>
                      {detail.crypto.map((c: any) => (
                        <tr key={c.id}>
                          <td style={td}>{c.name}<div style={muted}>{c.algorithm}{c.key_size ? ` · ${c.key_size}-bit` : ''}</div></td>
                          <td style={td}>{c.purpose_label}</td>
                          <td style={td}>
                            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                              {c.hndl_relevant && <Chip color={LEVEL_META.critical.color}>HNDL</Chip>}
                              {c.quantum_vulnerable && <Chip color={LEVEL_META.high.color}>quantum</Chip>}
                              {c.classically_weak && <Chip color={LEVEL_META.medium.color}>weak</Chip>}
                              {!c.hndl_relevant && !c.quantum_vulnerable && !c.classically_weak && <span style={muted}>OK</span>}
                            </div>
                          </td>
                          <td style={{ ...td, ...muted }}>{c.recommendation}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div style={card}>
              <SectionTitle>Recommended actions</SectionTitle>
              <Remediations api={api} items={detail.remediations} onChanged={refresh} />
            </div>
          </>
        )}
      </div>
    </div>
  );
};
