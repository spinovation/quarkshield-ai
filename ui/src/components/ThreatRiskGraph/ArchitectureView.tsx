import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ReactFlow, Handle, Position, MarkerType, type Node, type Edge, type NodeProps, type ReactFlowInstance } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  Users, Server, Globe, Shield, Database, KeyRound, GitBranch, Boxes, Skull, Package, Radio, Lock, FileLock2,
  Fingerprint, Loader2,
} from 'lucide-react';
import type { ThreatApi } from './api';
import { muted, REL_LABEL } from './ui';

/**
 * "Threat Model Overview" panel — three views over the SAME auto-discovered topology:
 *   Architecture  external threats → entry tier → application tier → data tier → key data
 *   Threat View   same layout, attack-path edges highlighted, threat counts per node
 *   Data Flow     data-flow diagram: every inferred flow labelled with its kind/protocol
 * Tiers with many assets of one type are aggregated (e.g. "User endpoints ×12").
 */

type Mode = 'architecture' | 'threat' | 'dataflow';

const TYPE_META: Record<string, { label: string; plural: string; Icon: React.ElementType; color: string; tier: number }> = {
  // tier = column: 1 users & sources · 2 edge · 3 servers · 4 services · 5 data stores
  endpoint: { label: 'User endpoint', plural: 'User endpoints', Icon: Users, color: '#38bdf8', tier: 1 },
  repo: { label: 'Repository', plural: 'Repositories', Icon: GitBranch, color: '#a78bfa', tier: 1 },
  proxy: { label: 'PQC proxy', plural: 'PQC proxies', Icon: Shield, color: '#22d3ee', tier: 2 },
  tls_endpoint: { label: 'TLS endpoint', plural: 'TLS endpoints', Icon: Globe, color: '#60a5fa', tier: 2 },
  server: { label: 'Server', plural: 'Servers', Icon: Server, color: '#34d399', tier: 3 },
  service: { label: 'Service', plural: 'Services', Icon: Boxes, color: '#c084fc', tier: 4 },
  database: { label: 'Database', plural: 'Databases', Icon: Database, color: '#60a5fa', tier: 5 },
  kms: { label: 'PKI / KMS', plural: 'PKI / KMS', Icon: KeyRound, color: '#fbbf24', tier: 5 },
};

const THREAT_SOURCES: Record<string, { label: string; Icon: React.ElementType }> = {
  vulnerable_software_exploitation: { label: 'External attacker', Icon: Skull },
  man_in_the_middle: { label: 'On-path attacker', Icon: Radio },
  credential_theft: { label: 'Credential theft', Icon: Fingerprint },
  supply_chain_compromise: { label: 'Supply chain', Icon: Package },
  cryptographic_compromise: { label: 'Nation-state (HNDL)', Icon: Lock },
  privilege_escalation: { label: 'Privilege escalation', Icon: Skull },
  data_exfiltration: { label: 'Data exfiltration', Icon: FileLock2 },
};

// ---- custom nodes -----------------------------------------------------------
const AssetNode: React.FC<NodeProps> = ({ data }) => {
  const d = data as any;
  const Icon = d.Icon as React.ElementType;
  return (
    <div style={{ width: 120, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, textAlign: 'center', cursor: 'pointer' }}>
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <div style={{
        width: 52, height: 52, borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative',
        background: `${d.color}22`, border: `1.5px solid ${d.threatened ? '#ff3366' : d.color}`,
        boxShadow: d.exposed ? `0 0 14px ${d.color}66` : 'none',
      }}>
        <Icon size={24} color={d.color} />
        {d.badge > 0 && (
          <span style={{
            position: 'absolute', top: -7, right: -9, minWidth: 18, height: 18, borderRadius: 9, padding: '0 4px',
            background: '#ff3366', color: '#fff', fontSize: 10, fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>{d.badge}</span>
        )}
      </div>
      <div style={{ fontSize: 11, color: '#eef1fa', lineHeight: 1.2, maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.label}</div>
      <div style={{ fontSize: 9, color: '#94a3b8' }}>{d.sub}</div>
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  );
};

const ListBox: React.FC<NodeProps> = ({ data }) => {
  const d = data as any;
  return (
    <div style={{
      width: 150, padding: '8px 10px', borderRadius: 10, border: `1.5px solid ${d.color}`, background: `${d.color}14`,
    }}>
      {d.side === 'right' && <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />}
      <div style={{ fontSize: 11, fontWeight: 700, color: d.color, marginBottom: 6 }}>{d.title}</div>
      {d.items.length === 0 && <div style={{ fontSize: 10, color: '#94a3b8' }}>None derived</div>}
      {d.items.map((it: any) => {
        const Icon = it.Icon as React.ElementType;
        return (
          <div key={it.label} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10.5, color: '#e2e8f0', padding: '3px 0' }}>
            <Icon size={13} color={d.color} /> <span>{it.label}</span>
          </div>
        );
      })}
      {d.side === 'left' && <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />}
    </div>
  );
};

const nodeTypes = { asset: AssetNode, box: ListBox };

interface Props {
  api: ThreatApi;
  data: any;                     // overview payload (scope, attackPaths, riskByThreatType, topScenarios)
  onOpenAsset: (id: string) => void;
}

export const ArchitectureView: React.FC<Props> = ({ api, data, onOpenAsset }) => {
  const [mode, setMode] = useState<Mode>('architecture');
  const [graph, setGraph] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const rfRef = useRef<ReactFlowInstance | null>(null);

  // The panel width settles after neighbouring cards lay out; refit whenever it resizes.
  useEffect(() => {
    const el = wrapRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(() => rfRef.current?.fitView({ padding: 0.08 }));
    ro.observe(el);
    return () => ro.disconnect();
  }, [graph]);

  useEffect(() => {
    let cancelled = false;
    api.graph({ all: true }).then(g => { if (!cancelled) setGraph(g); }).catch(e => { if (!cancelled) setError(e.message); });
    return () => { cancelled = true; };
  }, [api]);

  const { nodes, edges } = useMemo(() => {
    if (!graph) return { nodes: [] as Node[], edges: [] as Edge[] };
    const scopeIds: Set<string> | null = data.scopeAssetIds ? new Set(data.scopeAssetIds) : null;
    const assets = graph.nodes.filter((n: any) => n.kind === 'asset' && TYPE_META[n.subtype] && (!scopeIds || scopeIds.has(n.id)));

    // Threat counts per asset, from the scoped top scenarios + attack paths.
    const pathEdgeIds = new Set<string>();
    const threatened = new Set<string>();
    for (const p of data.attackPaths || []) {
      for (const h of p.hops) { threatened.add(h.asset_id); if (h.via) pathEdgeIds.add(h.via); }
    }
    const levelCount = new Map<string, number>();
    for (const n of assets) if (n.level && n.level !== 'low') levelCount.set(n.id, (levelCount.get(n.id) || 0) + 1);

    // Aggregate per (tier, type) when there are many assets of one type.
    const byType = new Map<string, any[]>();
    for (const a of assets) byType.set(a.subtype, [...(byType.get(a.subtype) || []), a]);
    const memberOf = new Map<string, string>();
    const vnodes: { id: string; tier: number; data: any }[] = [];
    for (const [type, list] of byType) {
      const meta = TYPE_META[type];
      if (list.length > 2) {
        const id = `agg:${type}`;
        list.forEach(a => memberOf.set(a.id, id));
        vnodes.push({ id, tier: meta.tier, data: {
          label: `${meta.plural} ×${list.length}`, sub: list.some((a: any) => a.exposed) ? 'some internet-facing' : meta.label,
          Icon: meta.Icon, color: meta.color, exposed: list.some((a: any) => a.exposed),
          threatened: list.some((a: any) => threatened.has(a.id)), badge: list.filter((a: any) => levelCount.has(a.id)).length,
          members: list.map((a: any) => a.id),
        } });
      } else {
        for (const a of list) {
          memberOf.set(a.id, a.id);
          vnodes.push({ id: a.id, tier: meta.tier, data: {
            label: a.label, sub: `${meta.label}${a.exposed ? ' · exposed' : ''}`, Icon: meta.Icon, color: meta.color,
            exposed: a.exposed, threatened: threatened.has(a.id), badge: levelCount.has(a.id) ? 1 : 0, members: [a.id],
          } });
        }
      }
    }

    // Layout: one column per non-empty tier, left → right; a tier with more than ROWS
    // nodes wraps into extra sub-columns. Rows are centred vertically.
    const ROWS = 3, ROW_H = 100, SUB_W = 135, GAP = 45;
    const columns = new Map<number, typeof vnodes>();
    for (const v of vnodes) columns.set(v.tier, [...(columns.get(v.tier) || []), v]);
    const H = Math.min(ROWS, Math.max(1, ...[...columns.values()].map(c => c.length))) * ROW_H;
    const rfNodes: Node[] = [];
    let x = 190;
    for (const tier of [...columns.keys()].sort((a, b) => a - b)) {
      const col = columns.get(tier)!;
      const subCols = Math.ceil(col.length / ROWS);
      col.forEach((v, i) => {
        const sc = Math.floor(i / ROWS);
        const inThis = Math.min(ROWS, col.length - sc * ROWS);
        rfNodes.push({
          id: v.id, type: 'asset', data: v.data,
          position: { x: x + sc * SUB_W, y: (H - inThis * ROW_H) / 2 + (i % ROWS) * ROW_H },
        });
      });
      x += subCols * SUB_W + GAP;
    }
    const keyX = x;

    // External threats (left) and key data (right).
    const sources = (data.riskByThreatType || []).map((c: any) => THREAT_SOURCES[c.category]).filter(Boolean);
    const uniqSources = [...new Map(sources.map((s: any) => [s.label, s])).values()];
    const keyData: { label: string; Icon: React.ElementType }[] = [];
    const types = new Set(assets.map((a: any) => a.subtype));
    const classes = new Set(assets.map((a: any) => a.meta?.classification));
    if (classes.has('cui')) keyData.push({ label: 'CUI', Icon: FileLock2 });
    if (types.has('database') || classes.has('sensitive')) keyData.push({ label: 'Sensitive data', Icon: Database });
    if (types.has('kms')) keyData.push({ label: 'Keys & certificates', Icon: KeyRound });
    if ((data.riskByThreatType || []).some((c: any) => c.category === 'credential_theft')) keyData.push({ label: 'Credentials', Icon: Fingerprint });
    if ((data.riskByThreatType || []).some((c: any) => c.category === 'cryptographic_compromise')) keyData.push({ label: 'Encrypted traffic (HNDL)', Icon: Lock });
    if (mode !== 'dataflow') {
      rfNodes.push({ id: 'threats', type: 'box', position: { x: 0, y: H / 2 - 30 - uniqSources.length * 11 }, data: {
        title: 'External Threats', color: '#ff3366', side: 'left', items: uniqSources,
      } });
    }
    rfNodes.push({ id: 'keydata', type: 'box', position: { x: keyX, y: H / 2 - 30 - keyData.length * 11 }, data: {
      title: 'Key Data', color: '#2dd4bf', side: 'right', items: keyData,
    } });

    // Edges between (aggregated) nodes, from the inferred relationships.
    const rfEdges: Edge[] = [];
    const seen = new Set<string>();
    for (const e of graph.edges) {
      if (e.kind === 'network_adjacent' || e.source === 'actor') continue;
      const s = memberOf.get(e.source); const t = memberOf.get(e.target);
      if (!s || !t || s === t) continue;
      const k = `${s}>${t}`;
      const onPath = pathEdgeIds.has(e.id);
      if (seen.has(k)) { if (onPath) { const ex = rfEdges.find(x => x.id === k); if (ex) (ex.data as any).onPath = true; } continue; }
      seen.add(k);
      rfEdges.push({ id: k, source: s, target: t, data: { onPath, kind: e.kind } });
    }
    for (const ed of rfEdges) {
      const d = ed.data as any;
      const hot = mode === 'threat' && d.onPath;
      ed.animated = hot;
      ed.label = mode === 'dataflow' ? (REL_LABEL[d.kind] || d.kind) : undefined;
      ed.labelStyle = { fill: '#cbd5e1', fontSize: 9 };
      ed.labelBgStyle = { fill: '#0c1122' };
      ed.style = { stroke: hot ? '#ff3366' : '#38bdf8', strokeWidth: hot ? 2 : 1.3, strokeDasharray: hot ? '5 4' : undefined, opacity: mode === 'threat' && !hot ? 0.35 : 1 };
      ed.markerEnd = { type: MarkerType.ArrowClosed, color: hot ? '#ff3366' : '#38bdf8' };
    }
    // Threat entry edges and data edges.
    if (mode !== 'dataflow') {
      const entries = new Set((data.attackPaths || []).map((p: any) => memberOf.get(p.hops[0].asset_id)).filter(Boolean));
      for (const id of entries as Set<string>) rfEdges.push({
        id: `threats>${id}`, source: 'threats', target: id, animated: true,
        style: { stroke: '#ff3366', strokeDasharray: '5 4', strokeWidth: 1.6 }, markerEnd: { type: MarkerType.ArrowClosed, color: '#ff3366' },
      });
    }
    for (const v of vnodes.filter(v => v.tier === 5)) rfEdges.push({
      id: `${v.id}>keydata`, source: v.id, target: 'keydata',
      style: { stroke: '#2dd4bf', strokeDasharray: '3 3' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#2dd4bf' },
    });
    return { nodes: rfNodes, edges: rfEdges };
  }, [graph, data, mode]);

  // Switching view changes the node set (e.g. Data Flow drops the threats box): refit.
  useEffect(() => {
    const id = requestAnimationFrame(() => rfRef.current?.fitView({ padding: 0.08 }));
    return () => cancelAnimationFrame(id);
  }, [nodes]);

  const tab = (m: Mode, label: string) => (
    <button key={m} onClick={() => setMode(m)} style={{
      padding: '0.3rem 0.7rem', fontSize: '0.75rem', borderRadius: 6, cursor: 'pointer',
      background: mode === m ? 'rgba(56,189,248,0.18)' : 'transparent', color: mode === m ? '#e0f2fe' : 'var(--text-muted, #94a3b8)',
      border: mode === m ? '1px solid rgba(56,189,248,0.5)' : '1px solid transparent',
    }}>{label}</button>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 600 }}>Threat Model Overview</h3>
        <div style={{ display: 'flex', gap: 2, padding: 2, borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)' }}>
          {tab('architecture', 'Architecture View')}{tab('threat', 'Threat View')}{tab('dataflow', 'Data Flow')}
        </div>
      </div>
      <div ref={wrapRef} style={{ flex: 1, minHeight: 330, borderRadius: 8, background: 'rgba(0,0,0,0.15)', position: 'relative' }}>
        {!graph && !error && <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}><Loader2 size={18} className="spin" /></div>}
        {error && <div style={{ ...muted, padding: 12 }}>{error}</div>}
        {graph && (
          <ReactFlow
            nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.08 }} colorMode="dark" minZoom={0.2} maxZoom={1.4}
            nodesDraggable={false} nodesConnectable={false} panOnScroll={false} zoomOnScroll={false} preventScrolling={false}
            proOptions={{ hideAttribution: true }}
            onInit={inst => { rfRef.current = inst; }}
            onNodeClick={(_, n) => { const m = (n.data as any)?.members; if (m?.length) onOpenAsset(m[0]); }}
          />
        )}
      </div>
      <div style={{ ...muted, fontSize: '0.68rem' }}>
        {mode === 'dataflow'
          ? 'Data-flow diagram generated from auto-discovered relationships (no manual modelling).'
          : mode === 'threat' ? 'Red dashed edges are hops on computed attack paths; badges count assets with elevated residual risk.'
          : 'Architecture inferred from your fleet, SBOM, repositories, PKI and proxies. Click a node for its risk detail.'}
      </div>
    </div>
  );
};
