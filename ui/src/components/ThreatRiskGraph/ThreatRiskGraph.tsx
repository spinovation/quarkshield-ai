import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { LayoutDashboard, Network, Crosshair, Server, RefreshCw, Loader2, Lock, CalendarClock } from 'lucide-react';
import { makeApi, UpgradeRequiredError, riskAssuranceOffer, startRiskAssuranceCheckout } from './api';
import { Overview } from './Overview';
import { GraphView } from './GraphView';
import { ScenarioView } from './ScenarioView';
import { AssetDetail } from './AssetDetail';
import { card, muted, LEVEL_META } from './ui';

/**
 * QuarkShield Threat & Risk Graph (Risk Assurance plan) — four MVP screens:
 * Threat & Risk Overview · Threat Graph · Threat Scenario · Asset Risk Detail.
 * Connects assets, vulnerabilities, cryptography, threats and attack paths built
 * entirely from auto-discovered data; relationships are never entered by hand.
 */

type View = 'overview' | 'graph' | 'scenarios' | 'assets';

const TABS: { id: View; label: string; Icon: React.ElementType }[] = [
  { id: 'overview', label: 'Threat & Risk Overview', Icon: LayoutDashboard },
  { id: 'graph', label: 'Threat Graph', Icon: Network },
  { id: 'scenarios', label: 'Threat Scenarios', Icon: Crosshair },
  { id: 'assets', label: 'Asset Risk Detail', Icon: Server },
];

export const ThreatRiskGraph: React.FC<{ tenant?: string }> = ({ tenant }) => {
  const api = useMemo(() => makeApi(tenant), [tenant]);
  const [view, setView] = useState<View>('overview');
  const [scope, setScope] = useState<string>('all');
  const [overview, setOverview] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [locked, setLocked] = useState(false);
  const [offer, setOffer] = useState<any | null>(null);
  const [checkingOut, setCheckingOut] = useState(false);
  const [rebuilding, setRebuilding] = useState(false);
  const [graphPath, setGraphPath] = useState<string | null>(null);
  const [graphFocus, setGraphFocus] = useState<string | null>(null);
  const [scenarioId, setScenarioId] = useState<string | null>(null);
  const [assetId, setAssetId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setOverview(await api.overview(scope));
      setLocked(false);
    } catch (e: any) {
      if (e instanceof UpgradeRequiredError) {
        setLocked(true);
        riskAssuranceOffer(tenant).then(setOffer).catch(() => setOffer({ eligible: e.eligible }));
      }
      else setError(e.message);
    }
  }, [api, tenant, scope]);

  const subscribe = async () => {
    setCheckingOut(true); setError(null);
    try { window.location.href = await startRiskAssuranceCheckout(tenant); }
    catch (e: any) { setError(e.message); setCheckingOut(false); }
  };

  // Reset selections when the tenant changes; a scope change just reloads the overview.
  useEffect(() => { setScenarioId(null); setAssetId(null); setGraphPath(null); setGraphFocus(null); setScope('all'); }, [api]);
  useEffect(() => { load(); }, [load]);

  const rebuild = async () => {
    setRebuilding(true);
    try { await api.rebuild(); await load(); } catch (e: any) { setError(e.message); } finally { setRebuilding(false); }
  };

  const openPath = (id: string) => { setGraphFocus(null); setGraphPath(id); setView('graph'); };
  const openFocus = (id: string) => { setGraphPath(null); setGraphFocus(id); setView('graph'); };
  const openScenario = (id: string) => { setScenarioId(id); setView('scenarios'); };
  const openAsset = (id: string) => { setAssetId(id); setView('assets'); };

  if (locked) {
    return (
      <div style={{ ...card, maxWidth: 640, margin: '2rem auto', textAlign: 'center', padding: '2rem 1.5rem' }}>
        <Lock size={28} color="var(--accent-cyan, #00f2fe)" />
        <h2 style={{ fontSize: '1.15rem', margin: '0.8rem 0 0.4rem' }}>Threat &amp; Risk Graph is part of the Risk Assurance plan</h2>
        <p style={muted}>
          Risk Assurance connects your discovered assets, SBOM vulnerabilities, cryptography (CBOM, PQC/HNDL) and automatically
          inferred relationships into attack paths and prioritized risk — with STRIDE and MITRE ATT&amp;CK mapping, continuous
          monitoring and NIST RMF support.
        </p>
        {offer && !offer.eligible && (
          <p style={{ ...muted, color: 'var(--text-secondary)' }}>
            Risk Assurance is available to <strong>Enterprise</strong> subscribers{offer.tier ? ` (current plan: ${offer.tier})` : ''}. Upgrade to Enterprise to add it.
          </p>
        )}
        {offer?.eligible && (
          <div style={{ marginTop: '1rem' }}>
            {offer.monthlyAmountCents && (
              <div style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: 8 }}>
                ${(offer.monthlyAmountCents / 100).toLocaleString()} <span style={muted}>per tenant / month</span>
              </div>
            )}
            {offer.purchasable ? (
              <button onClick={subscribe} disabled={checkingOut} style={{
                display: 'inline-flex', alignItems: 'center', gap: 6, padding: '0.6rem 1.2rem', borderRadius: 8, cursor: 'pointer',
                background: 'var(--accent-purple, #7f00ff)', border: 'none', color: '#fff', fontWeight: 600,
              }}>
                {checkingOut && <Loader2 size={14} className="spin" />} Subscribe to Risk Assurance
              </button>
            ) : (
              <p style={muted}>Contact your QuarkShield account team to enable Risk Assurance.</p>
            )}
          </div>
        )}
        {error && <p style={{ color: LEVEL_META.critical.color, fontSize: '0.8rem' }}>{error}</p>}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', minWidth: 0 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: '1rem', flexWrap: 'wrap' }}>
        <div style={{ minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <h1 style={{ margin: 0, fontSize: '1.45rem', fontWeight: 700 }}>
              Threat Model — {overview?.scope?.label || 'Entire environment'}
            </h1>
            <span style={{ border: '1px solid rgba(74,222,128,0.5)', background: 'rgba(74,222,128,0.12)', color: '#4ade80', borderRadius: 999, padding: '2px 10px', fontSize: '0.72rem', fontWeight: 600 }}>
              Active
            </span>
          </div>
          <div style={{ ...muted, marginTop: 4 }}>
            End-to-end threat modeling built from your discovered assets, SBOM, cryptography and attack paths — mapped to NIST controls.
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'stretch', gap: 10, flexWrap: 'wrap' }}>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 2, padding: '0.35rem 0.7rem', borderRadius: 8, border: '1px solid rgba(255,255,255,0.12)', minWidth: 210 }}>
            <span style={{ ...muted, fontSize: '0.68rem' }}>Scope</span>
            <select value={scope} onChange={e => setScope(e.target.value)} style={{
              background: 'transparent', border: 'none', color: 'var(--text-primary, #f8fafc)', fontSize: '0.85rem', outline: 'none', padding: 0,
            }}>
              {(overview?.scopes || [{ id: 'all', label: 'Entire environment' }]).map((s: any) => (
                <option key={s.id} value={s.id} style={{ background: '#0c1122' }}>{s.label}</option>
              ))}
            </select>
          </label>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, padding: '0.35rem 0.7rem', borderRadius: 8, border: '1px solid rgba(255,255,255,0.12)' }}>
            <span style={{ ...muted, fontSize: '0.68rem' }}>Last Updated</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.85rem' }}>
              <CalendarClock size={14} color="var(--text-muted)" />
              {overview?.lastBuiltAt ? new Date(overview.lastBuiltAt).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }) : '—'}
            </span>
          </div>
          <button onClick={rebuild} disabled={rebuilding} title="Rebuild the threat model now" aria-label="Rebuild now" style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center', width: 44, borderRadius: 8, cursor: 'pointer',
            background: 'rgba(0,242,254,0.08)', border: '1px solid rgba(0,242,254,0.3)', color: 'var(--accent-cyan, #00f2fe)',
          }}>
            {rebuilding ? <Loader2 size={16} className="spin" /> : <RefreshCw size={16} />}
          </button>
        </div>
      </div>

      <div role="tablist" style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '0.75rem' }}>
        {TABS.map(({ id, label, Icon }) => (
          <button key={id} role="tab" aria-selected={view === id} onClick={() => setView(id)} style={{
            display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 0.9rem', borderRadius: 7, cursor: 'pointer',
            background: view === id ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
            border: view === id ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid rgba(255, 255, 255, 0.1)',
            color: view === id ? 'var(--accent-cyan, #38bdf8)' : 'var(--text-secondary, #94a3b8)', fontSize: '0.82rem', fontWeight: view === id ? 600 : 500,
          }}>
            <Icon size={15} /> {label}
          </button>
        ))}
      </div>

      {error && <div style={{ ...card, color: LEVEL_META.critical.color }}>{error}</div>}
      {!overview && !error && (
        <div style={{ ...card, display: 'flex', gap: 8, alignItems: 'center', ...muted }}>
          <Loader2 size={16} className="spin" /> Building the threat graph from your fleet, SBOM, CBOM, repositories and PKI…
        </div>
      )}

      {overview && view === 'overview' && (
        <Overview api={api} data={overview} onOpenPath={openPath} onOpenScenario={openScenario} onOpenAsset={openAsset}
          onViewAllScenarios={() => setView('scenarios')} />
      )}
      {overview && view === 'graph' && (
        <GraphView api={api} paths={overview.attackPaths} initialPath={graphPath} initialFocus={graphFocus} onOpenAsset={openAsset} />
      )}
      {overview && view === 'scenarios' && (
        <ScenarioView api={api} selectedId={scenarioId} onSelect={setScenarioId} onOpenAsset={openAsset} onOpenPath={openPath} onChanged={load} />
      )}
      {overview && view === 'assets' && (
        <AssetDetail api={api} selectedId={assetId} onSelect={setAssetId} onOpenScenario={openScenario} onOpenPath={openPath} onFocusGraph={openFocus} onChanged={load} />
      )}

      <div style={{ ...muted, fontSize: '0.7rem', lineHeight: 1.5 }}>
        Risk is derived from discovered exposures (Likelihood × Impact); identifying a risk does not establish compliance, and no control is
        treated as effective without evidence. MITRE ATT&amp;CK® techniques shown are potential techniques derived from exposures, not
        observed activity — © The MITRE Corporation. Cyber Kill Chain® is a registered trademark of Lockheed Martin. Exploitation
        intelligence: CISA Known Exploited Vulnerabilities Catalog; EPSS scores courtesy of FIRST.org — used to adjust likelihood only.
      </div>
    </div>
  );
};

export default ThreatRiskGraph;
