import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ReactFlow, Background, Controls, MiniMap, MarkerType, Position, type Node, type Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Loader2, X, Crosshair } from 'lucide-react';
import type { ThreatApi } from './api';
import { card, muted, LevelBadge, PathRiskBadge, Chip, LinkButton, ASSET_TYPE_LABEL, REL_LABEL, LEVEL_META, selectStyle } from './ui';

interface Props {
  api: ThreatApi;
  paths: any[];
  initialPath?: string | null;
  initialFocus?: string | null;
  onOpenAsset: (id: string) => void;
}

type Mode = { kind: 'overview' } | { kind: 'path'; id: string } | { kind: 'focus'; id: string; depth: number };

const KIND_COLOR: Record<string, string> = {
  actor: '#ff8a3d', impact: '#ff3366', vuln: '#ff5c7a', crypto: '#a78bfa', component: '#94a3b8', asset: '#00f2fe',
};
const CONF_EDGE: Record<string, { stroke: string; dash?: string }> = {
  high: { stroke: '#00f2fe' }, medium: { stroke: '#38bdf8', dash: '6 3' }, low: { stroke: '#64748b', dash: '2 4' },
};

/** Layered left-to-right layout: rank = BFS distance from the threat actor over asset edges. */
const layout = (nodes: any[], edges: any[]): Record<string, { x: number; y: number }> => {
  const weakness = new Set(nodes.filter(n => n.kind === 'vuln' || n.kind === 'crypto' || n.kind === 'component').map(n => n.id));
  const adj = new Map<string, string[]>();
  for (const e of edges) {
    if (weakness.has(e.target) || weakness.has(e.source)) continue;
    adj.set(e.source, [...(adj.get(e.source) || []), e.target]);
    adj.set(e.target, [...(adj.get(e.target) || []), e.source]);
  }
  const rank = new Map<string, number>();
  const core = nodes.filter(n => !weakness.has(n.id));
  const roots = core.some(n => n.id === 'actor') ? ['actor']
    : core.length ? [core.slice().sort((a, b) => (adj.get(b.id)?.length || 0) - (adj.get(a.id)?.length || 0))[0].id] : [];
  const bfs = (start: string, base: number) => {
    rank.set(start, base);
    const q = [start];
    while (q.length) {
      const cur = q.shift()!;
      for (const nx of adj.get(cur) || []) if (!rank.has(nx)) { rank.set(nx, rank.get(cur)! + 1); q.push(nx); }
    }
  };
  roots.forEach(r => bfs(r, 0));
  // Disconnected components start in their own column band.
  for (const n of core) if (!rank.has(n.id)) bfs(n.id, 1);
  // The impact node always sits in the last column.
  const maxRank = Math.max(0, ...rank.values());
  if (rank.has('impact') && rank.get('impact')! < maxRank) rank.set('impact', maxRank + 1);

  const pos: Record<string, { x: number; y: number }> = {};
  const columns = new Map<number, string[]>();
  for (const n of core) { const r = rank.get(n.id) || 0; columns.set(r, [...(columns.get(r) || []), n.id]); }
  let maxY = 0;
  for (const [r, ids] of columns) {
    ids.forEach((id, i) => { pos[id] = { x: r * 270, y: i * 120 }; maxY = Math.max(maxY, i * 120); });
  }
  // Weakness nodes stacked under their asset.
  const perAsset = new Map<string, number>();
  for (const e of edges) {
    if (!weakness.has(e.target) || !pos[e.source]) continue;
    const k = perAsset.get(e.source) || 0;
    perAsset.set(e.source, k + 1);
    pos[e.target] = { x: pos[e.source].x + 10, y: maxY + 150 + k * 70 };
  }
  for (const n of nodes) if (!pos[n.id]) pos[n.id] = { x: 0, y: maxY + 300 };
  return pos;
};

const nodeLabel = (n: any) => (
  <div style={{ textAlign: 'left', lineHeight: 1.25 }}>
    <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.05em', opacity: 0.7 }}>
      {n.kind === 'asset' ? (ASSET_TYPE_LABEL[n.subtype] || n.subtype) : n.kind === 'crypto' ? `crypto · ${String(n.subtype || '').replace(/_/g, ' ')}` : n.kind}
      {n.exposed ? ' · exposed' : ''}
    </div>
    <div style={{ fontSize: 12, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 190 }}>{n.label}</div>
  </div>
);

export const GraphView: React.FC<Props> = ({ api, paths, initialPath, initialFocus, onOpenAsset }) => {
  const [mode, setMode] = useState<Mode>(() =>
    initialPath ? { kind: 'path', id: initialPath } : initialFocus ? { kind: 'focus', id: initialFocus, depth: 1 } : { kind: 'overview' });
  const [graph, setGraph] = useState<{ nodes: any[]; edges: any[]; path?: any } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<{ type: 'node'; node: any } | { type: 'edge'; edge: any; evidence?: any } | null>(null);

  useEffect(() => {
    if (initialPath) setMode({ kind: 'path', id: initialPath });
    else if (initialFocus) setMode({ kind: 'focus', id: initialFocus, depth: 1 });
  }, [initialPath, initialFocus]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true); setError(null); setSelected(null);
    const q = mode.kind === 'path' ? { path: mode.id } : mode.kind === 'focus' ? { focus: mode.id, depth: mode.depth } : {};
    api.graph(q).then(g => { if (!cancelled) setGraph(g); })
      .catch(e => { if (!cancelled) setError(e.message); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [api, mode]);

  const { rfNodes, rfEdges } = useMemo(() => {
    if (!graph) return { rfNodes: [] as Node[], rfEdges: [] as Edge[] };
    const pos = layout(graph.nodes, graph.edges);
    const rfNodes: Node[] = graph.nodes.map(n => {
      const accent = n.kind === 'asset' ? (n.level ? LEVEL_META[n.level]?.color : KIND_COLOR.asset) : KIND_COLOR[n.kind] || '#94a3b8';
      const isWeakness = n.kind === 'vuln' || n.kind === 'crypto' || n.kind === 'component';
      return {
        id: n.id, position: pos[n.id], data: { label: nodeLabel(n) },
        // Left-to-right layout: enter on the left, leave on the right; findings hang below.
        sourcePosition: Position.Right, targetPosition: isWeakness ? Position.Top : Position.Left,
        style: {
          width: 210, background: 'rgba(13,19,33,0.95)', color: '#eef1fa', borderRadius: 8, padding: '6px 9px',
          border: `1.5px solid ${accent}`, boxShadow: n.exposed ? `0 0 12px ${accent}55` : 'none', cursor: 'pointer',
        },
      };
    });
    const pathEdgeIds = new Set(graph.path ? graph.path.hops.map((h: any) => h.via).filter(Boolean) : []);
    const rfEdges: Edge[] = graph.edges.map(e => {
      const c = CONF_EDGE[e.confidence || 'high'] || CONF_EDGE.high;
      const weak = e.kind === 'has_weakness';
      return {
        id: e.id, source: e.source, target: e.target,
        label: weak ? undefined : (REL_LABEL[e.kind] || e.kind.replace(/_/g, ' ')),
        animated: pathEdgeIds.has(e.id) || e.source === 'actor',
        markerEnd: weak ? undefined : { type: MarkerType.ArrowClosed, color: c.stroke },
        style: { stroke: weak ? '#ff5c7a88' : c.stroke, strokeDasharray: weak ? '3 3' : c.dash, strokeWidth: 1.6 },
        labelStyle: { fill: '#cbd5e1', fontSize: 10 },
        labelBgStyle: { fill: '#0c1122' },
        data: e,
      };
    });
    return { rfNodes, rfEdges };
  }, [graph]);

  const onNodeClick = useCallback((_: unknown, n: Node) => {
    const node = graph?.nodes.find(x => x.id === n.id);
    if (node) setSelected({ type: 'node', node });
  }, [graph]);

  const onEdgeClick = useCallback((_: unknown, e: Edge) => {
    const edge = (e.data as any) || {};
    setSelected({ type: 'edge', edge });
    if (edge.rule) api.relationship(edge.id).then(ev => setSelected({ type: 'edge', edge, evidence: ev })).catch(() => undefined);
  }, [api]);

  const modeValue = mode.kind === 'path' ? `path:${mode.id}` : mode.kind === 'focus' ? `focus:${mode.id}` : 'overview';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <select value={modeValue} style={{ ...selectStyle, maxWidth: '100%' }} onChange={e => {
          const v = e.target.value;
          if (v === 'overview') setMode({ kind: 'overview' });
          else if (v.startsWith('path:')) setMode({ kind: 'path', id: v.slice(5) });
        }}>
          <option value="overview">All threatened assets &amp; relationships</option>
          {paths.map(p => (
            <option key={p.id} value={`path:${p.id}`}>
              Attack path ({p.residual_level || p.level}, {p.residual_score ?? p.path_risk}): {p.hops.map((h: any) => h.name || h.asset_id).join(' → ')}
            </option>
          ))}
          {mode.kind === 'focus' && <option value={modeValue}>Neighbourhood of {graph?.nodes.find(n => n.id === mode.id)?.label || mode.id}</option>}
        </select>
        {mode.kind === 'focus' && (
          <select value={mode.depth} style={selectStyle} onChange={e => setMode({ ...mode, depth: Number(e.target.value) })}>
            {[1, 2, 3].map(d => <option key={d} value={d}>{d} hop{d > 1 ? 's' : ''}</option>)}
          </select>
        )}
        <span style={{ ...muted, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <span><span style={{ color: CONF_EDGE.high.stroke }}>━</span> high</span>
          <span><span style={{ color: CONF_EDGE.medium.stroke }}>╍</span> medium</span>
          <span><span style={{ color: CONF_EDGE.low.stroke }}>┄</span> low (lateral hypothesis)</span>
          <span>All relationships auto-discovered — click an edge for its evidence.</span>
        </span>
      </div>

      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
        <div style={{ ...card, padding: 0, flex: '1 1 520px', height: 560, position: 'relative', overflow: 'hidden' }}>
          {loading && <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 5 }}><Loader2 className="spin" size={22} /></div>}
          {error && <div style={{ padding: '1rem', color: LEVEL_META.critical.color }}>{error}</div>}
          {!loading && graph && graph.nodes.length === 0 && <div style={{ padding: '1rem', ...muted }}>Nothing to draw yet — no threats or relationships were derived for this tenant.</div>}
          {graph && graph.nodes.length > 0 && (
            <ReactFlow
              nodes={rfNodes} edges={rfEdges} fitView colorMode="dark" minZoom={0.2}
              nodesDraggable nodesConnectable={false} onNodeClick={onNodeClick} onEdgeClick={onEdgeClick}
              proOptions={{ hideAttribution: true }}
            >
              <Background gap={22} color="#1c2540" />
              <Controls showInteractive={false} />
              <MiniMap pannable zoomable style={{ background: '#0c1122' }} nodeColor={() => '#26304f'} />
            </ReactFlow>
          )}
        </div>

        <div style={{ ...card, flex: '0 1 300px', minWidth: 260, maxHeight: 560, overflowY: 'auto' }}>
          {!selected && (
            <div style={muted}>
              {graph?.path ? (
                <>
                  <div style={{ marginBottom: 8 }}><PathRiskBadge path={graph.path} /> <Chip>{graph.path.confidence} confidence</Chip></div>
                  Likelihood {graph.path.likelihood} × Impact {graph.path.impact}. Kill chain:
                  <ol style={{ paddingLeft: 18, margin: '6px 0' }}>
                    {graph.path.hops.map((h: any, i: number) => (
                      <li key={i}>{graph.nodes.find(n => n.id === h.asset_id)?.label || h.asset_id} — {h.kill_chain.replace(/_/g, ' ')}</li>
                    ))}
                  </ol>
                </>
              ) : 'Select a node or relationship to see its findings, threats and evidence.'}
            </div>
          )}
          {selected?.type === 'node' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <strong style={{ fontSize: '0.9rem', wordBreak: 'break-word' }}>{selected.node.label}</strong>
                <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }} aria-label="Close"><X size={14} /></button>
              </div>
              {selected.node.kind === 'asset' && (
                <>
                  <div style={muted}>{ASSET_TYPE_LABEL[selected.node.subtype] || selected.node.subtype}{selected.node.exposed ? ' · internet-exposed' : ''}</div>
                  <div style={muted}>Criticality {selected.node.meta?.criticality} · {selected.node.meta?.classification}</div>
                  {selected.node.level && <div><LevelBadge level={selected.node.level} /> highest residual risk</div>}
                  <LinkButton onClick={() => onOpenAsset(selected.node.id)}>Open asset risk detail →</LinkButton>
                  <LinkButton onClick={() => setMode({ kind: 'focus', id: selected.node.id, depth: 1 })}><Crosshair size={12} /> Show neighbourhood</LinkButton>
                </>
              )}
              {selected.node.kind === 'vuln' && (
                <>
                  <div style={muted}>{selected.node.meta.title}</div>
                  <div>CVSS {selected.node.meta.cvss} · {selected.node.meta.severity}</div>
                  {selected.node.meta.fixed_version && <div style={muted}>Fixed in {selected.node.meta.fixed_version}</div>}
                  {selected.node.meta.remediation_cmd && <code style={{ fontSize: '0.72rem', wordBreak: 'break-all' }}>{selected.node.meta.remediation_cmd}</code>}
                </>
              )}
              {selected.node.kind === 'crypto' && (
                <>
                  <div style={muted}>{selected.node.meta.name}</div>
                  <div>{selected.node.meta.algorithm}{selected.node.meta.key_size ? ` · ${selected.node.meta.key_size}-bit` : ''}</div>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {selected.node.meta.quantum_vulnerable && <Chip color={LEVEL_META.high.color}>quantum-vulnerable</Chip>}
                    {selected.node.meta.hndl_relevant && <Chip color={LEVEL_META.critical.color}>HNDL</Chip>}
                    {selected.node.meta.classically_weak && <Chip color={LEVEL_META.medium.color}>classically weak</Chip>}
                  </div>
                  <div style={muted}>{selected.node.meta.recommendation}</div>
                </>
              )}
              {(selected.node.kind === 'actor' || selected.node.kind === 'impact') && (
                <div style={muted}>{selected.node.kind === 'actor' ? 'Threat source entering through the first asset of the path.' : 'Final impact: data held by the goal asset is collected and exfiltrated.'}</div>
              )}
            </div>
          )}
          {selected?.type === 'edge' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <strong style={{ fontSize: '0.9rem' }}>{REL_LABEL[selected.edge.kind] || selected.edge.kind}</strong>
                <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }} aria-label="Close"><X size={14} /></button>
              </div>
              {selected.evidence ? (
                <>
                  <div style={muted}>{selected.evidence.from_name} → {selected.evidence.to_name}</div>
                  <div><Chip>{selected.evidence.rule_id}</Chip> <Chip>{selected.evidence.confidence} confidence</Chip></div>
                  <div style={muted}>Evidence</div>
                  <pre style={{ fontSize: '0.7rem', whiteSpace: 'pre-wrap', wordBreak: 'break-word', margin: 0, color: 'var(--text-secondary)' }}>
                    {JSON.stringify(selected.evidence.evidence, null, 2)}
                  </pre>
                  <div style={muted}>First seen {new Date(selected.evidence.first_seen).toLocaleString()}<br />Last seen {new Date(selected.evidence.last_seen).toLocaleString()}</div>
                </>
              ) : (
                <div style={muted}>{selected.edge.rule ? 'Loading evidence…' : 'Derived edge (threat entry, weakness or impact).'}</div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
