import React, { useCallback, useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import type { ThreatApi } from './api';
import { Remediations } from './Remediations';
import {
  card, muted, LevelBadge, PathRiskBadge, Chip, SectionTitle, LinkButton, Empty, PathChain, levelOf, LEVEL_META, ASSET_TYPE_LABEL,
  tableStyle, th, td,
} from './ui';

interface Props {
  api: ThreatApi;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onOpenAsset: (id: string) => void;
  onOpenPath: (id: string) => void;
  onChanged: () => void;
}

export const ScenarioView: React.FC<Props> = ({ api, selectedId, onSelect, onOpenAsset, onOpenPath, onChanged }) => {
  const [list, setList] = useState<any[] | null>(null);
  const [detail, setDetail] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadList = useCallback(() => {
    api.scenarios().then(setList).catch(e => setError(e.message));
  }, [api]);

  const loadDetail = useCallback(() => {
    if (!selectedId) return;
    setLoading(true);
    api.scenario(selectedId).then(setDetail).catch(e => setError(e.message)).finally(() => setLoading(false));
  }, [api, selectedId]);

  useEffect(() => { loadList(); }, [loadList]);
  // Default to the highest-risk item once the list arrives.
  useEffect(() => { if (!selectedId && list?.length) onSelect(list[0].id); }, [list, selectedId, onSelect]);
  useEffect(() => { loadDetail(); }, [loadDetail]);

  const refresh = () => { loadList(); loadDetail(); onChanged(); };

  return (
    <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'flex-start' }}>
      <div style={{ ...card, flex: '1 1 280px', maxWidth: 380, maxHeight: 720, overflowY: 'auto', padding: '0.6rem' }}>
        {!list && <div style={{ padding: '1rem' }}><Loader2 size={16} className="spin" /></div>}
        {list?.length === 0 && <Empty>No threat scenarios derived.</Empty>}
        {list?.map(t => (
          <button key={t.id} onClick={() => onSelect(t.id)} style={{
            display: 'block', width: '100%', textAlign: 'left', padding: '0.55rem 0.6rem', marginBottom: 4, borderRadius: 7, cursor: 'pointer',
            background: t.id === selectedId ? 'rgba(0,242,254,0.1)' : 'transparent',
            border: t.id === selectedId ? '1px solid rgba(0,242,254,0.3)' : '1px solid transparent', color: 'inherit', font: 'inherit',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 6, alignItems: 'center' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-primary, #f8fafc)' }}>{t.title}</span>
              <LevelBadge level={levelOf(t.max_risk)} score={t.max_risk} />
            </div>
            <div style={muted}>{t.rule_id} · {t.category.replace(/_/g, ' ')}{t.paths ? ` · ${t.paths} path${t.paths > 1 ? 's' : ''}` : ''}</div>
          </button>
        ))}
      </div>

      <div style={{ flex: '3 1 480px', minWidth: 0, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {error && <div style={{ ...card, color: LEVEL_META.critical.color }}>{error}</div>}
        {loading && !detail && <div style={card}><Loader2 size={16} className="spin" /></div>}
        {detail && (
          <>
            <div style={card}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
                <div>
                  <div style={muted}>{detail.threat.category_label} · rule {detail.threat.rule_id} v{detail.threat.rule_version}</div>
                  <h2 style={{ margin: '0.2rem 0 0.4rem', fontSize: '1.05rem' }}>{detail.threat.title}</h2>
                </div>
                {detail.risks[0] && <LevelBadge level={detail.risks[0].residual_level} score={detail.risks[0].residual_score} />}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.6rem', fontSize: '0.8rem' }}>
                <div><div style={muted}>Threat actor</div>{detail.threat.actor}</div>
                <div><div style={muted}>Intent</div>{detail.threat.intent}</div>
                <div><div style={muted}>Affected asset</div>
                  <LinkButton onClick={() => onOpenAsset(detail.asset.id)}>{detail.asset.name}</LinkButton>
                  <div style={muted}>{ASSET_TYPE_LABEL[detail.asset.type]} · {detail.asset.data_classification}{detail.asset.internet_exposed ? ' · internet-exposed' : ''}</div>
                </div>
                <div><div style={muted}>Likelihood × Impact</div>
                  {detail.threat.likelihood} × {detail.risks[0]?.impact ?? '—'} = {detail.risks[0]?.inherent_score ?? '—'} inherent
                  {detail.risks[0] && detail.risks[0].residual_score !== detail.risks[0].inherent_score && ` · ${detail.risks[0].residual_score} residual`}
                </div>
              </div>
              <p style={{ ...muted, marginBottom: 0 }}>{detail.threat.description}</p>
            </div>

            <div style={card}>
              <SectionTitle>Framework mapping</SectionTitle>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
                {detail.frameworks.stride.map((s: any) => <Chip key={s.ref} color="var(--accent-cyan, #00f2fe)">STRIDE {s.ref} · {s.label}</Chip>)}
                {detail.frameworks.killchain.filter(Boolean).map((k: any) => <Chip key={k.id} color="#a78bfa">Kill chain · {k.label}</Chip>)}
              </div>
              {detail.frameworks.attack.map((a: any) => (
                <div key={a.ref} style={{ fontSize: '0.8rem', marginBottom: 3 }}>
                  <Chip color="#ff8a3d">{a.ref}</Chip> {a.name} <span style={muted}>({(a.tactics || []).join(', ')})</span>
                </div>
              ))}
              <div style={{ ...muted, marginTop: 8 }}>{detail.frameworks.rationale} ATT&amp;CK techniques are potential techniques derived from the exposure, not observed activity.</div>
            </div>

            <div style={card}>
              <SectionTitle>Vulnerabilities &amp; exposures driving this threat</SectionTitle>
              {detail.drivers.length === 0 && <Empty>Driven by the attack paths below.</Empty>}
              {detail.drivers.length > 0 && (
                <div style={{ overflowX: 'auto' }}>
                  <table style={tableStyle}>
                    <thead><tr><th style={th}>Finding</th><th style={th}>Detail</th><th style={th}>Severity</th></tr></thead>
                    <tbody>
                      {detail.drivers.map((d: any) => (
                        <tr key={d.id}>
                          <td style={td}>{d.cve || d.name}</td>
                          <td style={td}>{d.cve ? d.title : `${d.algorithm}${d.key_size ? ` ${d.key_size}-bit` : ''} · ${String(d.purpose).replace(/_/g, ' ')}`}</td>
                          <td style={td}>{d.cve ? <>CVSS {d.cvss}</> : d.hndl_relevant ? 'HNDL' : d.classically_weak ? 'Weak' : d.quantum_vulnerable ? 'Quantum-vulnerable' : d.risk_level}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div style={card}>
              <SectionTitle>Attack paths</SectionTitle>
              {detail.paths.length === 0 && <Empty>This threat is a standalone risk on its asset (no path to a higher-impact asset).</Empty>}
              {detail.paths.map((p: any) => (
                <div key={p.id} style={{ padding: '0.5rem 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
                    <PathRiskBadge path={p} /><Chip>{p.confidence} confidence</Chip>
                    <span style={{ marginLeft: 'auto' }}><LinkButton onClick={() => onOpenPath(p.id)}><span style={{ whiteSpace: 'nowrap' }}>View graph →</span></LinkButton></span>
                  </div>
                  <PathChain hops={p.hops} onAsset={onOpenAsset} />
                </div>
              ))}
            </div>

            <div style={card}>
              <SectionTitle>Remediation</SectionTitle>
              <Remediations api={api} items={detail.remediations} onChanged={refresh} />
            </div>
          </>
        )}
      </div>
    </div>
  );
};
