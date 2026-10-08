/**
 * Declarative threat-rule catalog (plan rev 2 §5). Every rule turns a REAL discovered
 * weakness into a threat and, in the same place, declares its STRIDE letters, ATT&CK
 * techniques and kill-chain phase — so every framework mapping traces back to exactly
 * one versioned rule. No rule fires without a driver (CVE, crypto finding).
 *
 * Categories with no deterministic signal in today's data (ransomware, API abuse,
 * insider) are intentionally not derived in Phase 1 rather than guessed.
 */
import { Topology } from './topology';
import {
  TrThreat, TrAsset, VulnNode, CryptoNode, StrideLetter, ThreatCategory, KillChainPhase,
} from './types';
import { PURPOSE_LABELS } from './cryptoPurpose';

export interface ThreatRule {
  id: string;
  version: number;
  category: ThreatCategory;
  summary: string;
  evaluate: (t: Topology, assets: Map<string, TrAsset>) => TrThreat[];
}

const clampL = (n: number): number => Math.max(1, Math.min(4, Math.round(n)));

/** Minimal CWE → STRIDE map; Phase 2 replaces it with the ref_cwe_stride table. */
const CWE_STRIDE: Record<string, StrideLetter[]> = {
  'CWE-77': ['T', 'E'], 'CWE-78': ['T', 'E'], 'CWE-94': ['T', 'E'], 'CWE-502': ['T', 'E'],
  'CWE-89': ['T', 'I'], 'CWE-79': ['T', 'I'], 'CWE-22': ['I', 'T'], 'CWE-200': ['I'],
  'CWE-287': ['S'], 'CWE-306': ['S', 'E'], 'CWE-347': ['S', 'T'], 'CWE-295': ['S', 'I'],
  'CWE-400': ['D'], 'CWE-770': ['D'], 'CWE-1333': ['D'], 'CWE-269': ['E'], 'CWE-250': ['E'],
  'CWE-327': ['I'], 'CWE-326': ['I'], 'CWE-918': ['I', 'S'], 'CWE-1321': ['T', 'E'],
};

const strideFromCwe = (vs: VulnNode[], fallback: StrideLetter[]): { letters: StrideLetter[]; why: string } => {
  const out = new Set<StrideLetter>();
  for (const v of vs) for (const c of v.cwe) for (const l of CWE_STRIDE[c.toUpperCase()] || []) out.add(l);
  return out.size
    ? { letters: [...out], why: 'STRIDE from CWE of driving CVEs' }
    : { letters: fallback, why: 'STRIDE default for this rule (no CWE on driving CVEs yet)' };
};

const byAsset = <T extends { asset_id: string }>(xs: T[]): Map<string, T[]> => {
  const m = new Map<string, T[]>();
  for (const x of xs) { const l = m.get(x.asset_id) || []; l.push(x); m.set(x.asset_id, l); }
  return m;
};

const mk = (
  rule: ThreatRule, asset: TrAsset, p: {
    actor: string; intent: string; title: string; description: string; drivers: string[];
    likelihood: number; stride: StrideLetter[]; attack: string[]; kill_chain: KillChainPhase; rationale: string;
  },
): TrThreat => ({
  id: `thr:${rule.id}:${asset.id}`, rule_id: rule.id, rule_version: rule.version, category: rule.category,
  actor: p.actor, intent: p.intent, title: p.title, description: p.description, asset_id: asset.id,
  driver_ids: p.drivers, likelihood: clampL(p.likelihood), stride: p.stride, attack: p.attack,
  kill_chain: p.kill_chain, rationale: p.rationale,
});

// ---------------------------------------------------------------------------
// Exploitation-likelihood from intelligence (CISA KEV, FIRST EPSS), falling back to CVSS.
// Intelligence adjusts LIKELIHOOD only — impact always comes from the asset.
// ---------------------------------------------------------------------------
/** A vulnerability matters if it is severe (CVSS ≥ 7) OR known to be exploited (KEV). */
const relevant = (v: VulnNode): boolean => v.cvss >= 7 || !!v.kev;

/** Per-vulnerability likelihood (1–4) before exposure. */
export const vulnLikelihood = (v: VulnNode): number => {
  const cvssBase = v.cvss >= 9 ? 3 : 2;
  if (v.kev) return 4;                                   // exploited in the wild
  if (v.epss === null) return cvssBase;                  // no EPSS score: CVSS only
  if (v.epss >= 0.5) return Math.max(3, cvssBase);       // very likely to be exploited soon
  if (v.epss >= 0.1) return cvssBase;
  if (v.epss < 0.01) return Math.max(1, cvssBase - 1);   // exploitation unlikely
  return cvssBase;
};

const pct = (n: number) => `${(n * 100).toFixed(n < 0.01 || n >= 0.995 ? 2 : 1)}%`;

/** Human-readable intelligence signal for a set of driving CVEs. */
export const intelSummary = (vs: VulnNode[]): string => {
  const kev = vs.filter(v => v.kev);
  const withEpss = vs.filter(v => v.epss !== null).sort((a, b) => (b.epss || 0) - (a.epss || 0));
  const parts: string[] = [];
  if (kev.length) {
    parts.push(`${kev.map(v => v.cve).join(', ')} ${kev.length > 1 ? 'are' : 'is'} in CISA KEV (exploited in the wild)` +
      (kev.some(v => v.kev?.ransomware_use) ? ', with known ransomware use' : ''));
  }
  if (withEpss.length) parts.push(`highest EPSS ${pct(withEpss[0].epss!)} (${withEpss[0].cve}, ${Math.round((withEpss[0].epss_percentile || 0) * 100)}th percentile)`);
  return parts.length ? `Likelihood from exploitation intelligence: ${parts.join('; ')}.` : 'Likelihood from CVSS (no KEV/EPSS signal).';
};

const LIB_ECOSYSTEMS = new Set(['npm', 'pypi', 'golang', 'go', 'maven', 'nuget', 'cargo', 'gem', 'rubygems', 'composer']);
const PRIVESC_PKGS = /^(sudo|polkit|pkexec|linux|linux-image.*|kernel|glibc|libc6|systemd|dbus|openssh)$/i;

export const RULES: ThreatRule[] = [];

RULES.push({
  id: 'TR-01', version: 1, category: 'vulnerable_software_exploitation',
  summary: 'High/critical CVE (CVSS ≥ 7) in a component of an asset',
  evaluate(t, assets) {
    const out: TrThreat[] = [];
    for (const [assetId, vs] of byAsset(t.vulns.filter(relevant))) {
      // Source repositories are not running services: their CVEs are supply-chain risk (TR-03).
      const a = assets.get(assetId); if (!a || a.type === 'repo') continue;
      const max = Math.max(...vs.map(v => v.cvss));
      const attack = a.internet_exposed ? ['T1190'] : a.type === 'endpoint' ? ['T1203'] : ['T1210'];
      const s = strideFromCwe(vs, ['T', 'E']);
      out.push(mk(this, a, {
        actor: a.internet_exposed ? 'External attacker' : 'Attacker with network access',
        intent: 'Gain code execution through a known software flaw',
        title: `Exploitation of ${vs.length} known vulnerabilit${vs.length > 1 ? 'ies' : 'y'} on ${a.name}`,
        description: `Highest CVSS ${max.toFixed(1)} (${vs.slice(0, 3).map(v => v.cve).join(', ')}${vs.length > 3 ? '…' : ''}).${vs.some(v => v.kev) ? ' Known exploited in the wild (CISA KEV).' : ''}`,
        drivers: vs.map(v => v.id), likelihood: Math.max(...vs.map(vulnLikelihood)) + (a.internet_exposed ? 1 : 0),
        stride: s.letters, attack, kill_chain: 'exploitation',
        rationale: `${s.why}; ATT&CK ${attack[0]} because the asset is ${a.internet_exposed ? (a.exposed_via ? 'published to the internet by a reverse proxy' : 'internet-exposed') : a.type === 'endpoint' ? 'a user endpoint' : 'reachable internally'}. ${intelSummary(vs)}`,
      }));
    }
    return out;
  },
});

RULES.push({
  id: 'TR-02', version: 1, category: 'privilege_escalation',
  summary: 'High/critical CVE in a local privilege boundary package (sudo, polkit, kernel, glibc …) on a host',
  evaluate(t, assets) {
    const comps = new Map(t.components.map(c => [c.id, c]));
    const out: TrThreat[] = [];
    const hits = t.vulns.filter(v => relevant(v) && PRIVESC_PKGS.test(comps.get(v.component_id)?.name || ''));
    for (const [assetId, vs] of byAsset(hits)) {
      const a = assets.get(assetId); if (!a || (a.type !== 'endpoint' && a.type !== 'server')) continue;
      out.push(mk(this, a, {
        actor: 'Attacker with a foothold on the host', intent: 'Escalate to root/SYSTEM',
        title: `Local privilege escalation on ${a.name}`,
        description: `Privilege-boundary package flaws: ${vs.map(v => v.cve).slice(0, 3).join(', ')}.`,
        // Needs a foothold first, so capped one below the exploitation signal.
        drivers: vs.map(v => v.id), likelihood: Math.max(2, Math.max(...vs.map(vulnLikelihood)) - 1), stride: ['E'], attack: ['T1068'], kill_chain: 'installation',
        rationale: `Flaw in a privilege-boundary package → STRIDE E, ATT&CK T1068. ${intelSummary(vs)}`,
      }));
    }
    return out;
  },
});

RULES.push({
  id: 'TR-03', version: 1, category: 'supply_chain_compromise',
  summary: 'High/critical CVE in a library dependency of a repository or application',
  evaluate(t, assets) {
    const comps = new Map(t.components.map(c => [c.id, c]));
    const out: TrThreat[] = [];
    const hits = t.vulns.filter(v => relevant(v) && LIB_ECOSYSTEMS.has((comps.get(v.component_id)?.ecosystem || '').toLowerCase()));
    for (const [assetId, vs] of byAsset(hits)) {
      const a = assets.get(assetId); if (!a || (a.type !== 'repo' && a.type !== 'service')) continue;
      const max = Math.max(...vs.map(v => v.cvss));
      out.push(mk(this, a, {
        actor: 'Supply-chain attacker', intent: 'Ship malicious or exploitable code through a dependency',
        title: `Vulnerable dependencies in ${a.name}`,
        description: `${vs.length} vulnerable library dependenc${vs.length > 1 ? 'ies' : 'y'} (max CVSS ${max.toFixed(1)}).`,
        drivers: vs.map(v => v.id), likelihood: Math.min(3, Math.max(...vs.map(vulnLikelihood))), stride: ['T'], attack: ['T1195.001'], kill_chain: 'delivery',
        rationale: `Third-party library weakness enters through the build → STRIDE T, ATT&CK T1195.001. ${intelSummary(vs)}`,
      }));
    }
    return out;
  },
});

RULES.push({
  id: 'TR-04', version: 1, category: 'cryptographic_compromise',
  summary: 'Quantum-vulnerable key establishment (HNDL) on an exposed or traffic-carrying asset',
  evaluate(t, assets) {
    const out: TrThreat[] = [];
    for (const [assetId, cs] of byAsset(t.crypto.filter(c => c.hndl_relevant))) {
      const a = assets.get(assetId); if (!a) continue;
      const carriesTraffic = a.internet_exposed || a.type === 'tls_endpoint' || a.type === 'proxy';
      out.push(mk(this, a, {
        actor: 'Nation-state collector (harvest now, decrypt later)',
        intent: 'Record encrypted traffic today and decrypt it with a future quantum computer',
        title: `HNDL exposure on ${a.name}`,
        description: `${cs.length} classical key-establishment finding(s): ${[...new Set(cs.map(c => c.algorithm))].slice(0, 3).join(', ')}.`,
        drivers: cs.map(c => c.id), likelihood: carriesTraffic ? 2 : 1, stride: ['I'], attack: ['T1040', 'T1557'],
        kill_chain: 'actions_on_objectives',
        rationale: 'Key establishment purpose + Shor-vulnerable algorithm → confidentiality (STRIDE I); collection via T1040/T1557. Harvest is possible now; decryption is future.',
      }));
    }
    return out;
  },
});

RULES.push({
  id: 'TR-05', version: 1, category: 'man_in_the_middle',
  summary: 'Classically weak TLS/key-exchange crypto or configuration (weak hash, short RSA, legacy protocol/cipher)',
  evaluate(t, assets) {
    const out: TrThreat[] = [];
    const weak = t.crypto.filter(c => c.classically_weak &&
      ['tls_certificate', 'key_establishment', 'configuration', 'rsa_key_transport'].includes(c.purpose));
    for (const [assetId, cs] of byAsset(weak)) {
      const a = assets.get(assetId); if (!a) continue;
      const cfg = cs.some(c => c.purpose === 'configuration');
      out.push(mk(this, a, {
        actor: 'On-path attacker', intent: 'Intercept or alter sessions protected by weak cryptography',
        title: `Weak transport cryptography on ${a.name}`,
        description: cs.slice(0, 3).map(c => c.name).join('; '),
        drivers: cs.map(c => c.id), likelihood: a.internet_exposed ? 3 : 2, stride: ['S', 'T', 'I'],
        attack: cfg ? ['T1557', 'T1600'] : ['T1557'], kill_chain: 'exploitation',
        rationale: 'Classically weak parameters are exploitable today (not a quantum-only concern) → STRIDE S/T/I, ATT&CK T1557.',
      }));
    }
    return out;
  },
});

RULES.push({
  id: 'TR-06', version: 1, category: 'credential_theft',
  summary: 'Weak SSH authentication keys, or private keys committed to a repository',
  evaluate(t, assets) {
    const out: TrThreat[] = [];
    const hits = t.crypto.filter(c => {
      const a = assets.get(c.asset_id);
      const committedKey = a?.type === 'repo' && (c.purpose === 'ssh_authentication' || /private/i.test(c.name) || c.id.startsWith('git:') && /key/i.test(c.name));
      return committedKey || (c.purpose === 'ssh_authentication' && c.classically_weak);
    });
    for (const [assetId, cs] of byAsset(hits)) {
      const a = assets.get(assetId); if (!a) continue;
      const repo = a.type === 'repo';
      out.push(mk(this, a, {
        actor: repo ? 'Anyone with repository read access' : 'Attacker with a foothold',
        intent: 'Steal or abuse key material to authenticate as a trusted identity',
        title: repo ? `Private key material committed to ${a.name}` : `Weak SSH authentication keys on ${a.name}`,
        description: cs.slice(0, 3).map(c => `${c.name} (${c.algorithm})`).join('; '),
        drivers: cs.map(c => c.id), likelihood: repo ? 3 : 2, stride: ['S'], attack: ['T1552.004', 'T1021.004'],
        kill_chain: repo ? 'delivery' : 'installation',
        rationale: 'Key material usable for authentication → STRIDE S; ATT&CK T1552.004 (private keys) and T1021.004 (SSH).',
      }));
    }
    return out;
  },
});

RULES.push({
  id: 'TR-07', version: 1, category: 'cryptographic_compromise',
  summary: 'Quantum-vulnerable signature / trust dependency on a high-value asset',
  evaluate(t, assets) {
    const out: TrThreat[] = [];
    const sig: CryptoNode['purpose'][] = ['ca_trust_anchor', 'tls_certificate', 'code_or_data_signing', 'ssh_authentication'];
    const hits = t.crypto.filter(c => c.quantum_vulnerable && sig.includes(c.purpose));
    for (const [assetId, cs] of byAsset(hits)) {
      const a = assets.get(assetId); if (!a || (a.criticality < 3 && a.type !== 'kms')) continue;
      const purposes = [...new Set(cs.map(c => PURPOSE_LABELS[c.purpose]))].join(', ');
      out.push(mk(this, a, {
        actor: 'Future adversary with a cryptographically relevant quantum computer',
        intent: 'Forge signatures or certificates trusted by this asset',
        title: `Quantum-era signature forgery risk on ${a.name}`,
        description: `${cs.length} Shor-vulnerable signature dependencies (${purposes}).`,
        drivers: cs.map(c => c.id), likelihood: 1, stride: ['S', 'T'], attack: ['T1649'], kill_chain: 'weaponization',
        rationale: 'Signature/trust purpose (not key establishment) → authenticity risk (STRIDE S/T), not HNDL. Likelihood is low until a CRQC exists.',
      }));
    }
    return out;
  },
});

RULES.push({
  id: 'TR-09', version: 1, category: 'ransomware_malware',
  summary: 'CVE known to be used in ransomware campaigns (CISA KEV) on a running asset',
  evaluate(t, assets) {
    const out: TrThreat[] = [];
    for (const [assetId, vs] of byAsset(t.vulns.filter(v => v.kev?.ransomware_use))) {
      const a = assets.get(assetId); if (!a || a.type === 'repo') continue;
      const entry = a.internet_exposed ? 'T1190' : a.type === 'endpoint' ? 'T1203' : 'T1210';
      out.push(mk(this, a, {
        actor: 'Ransomware operator', intent: 'Gain access through a known-exploited flaw, then encrypt or extort data',
        title: `Ransomware exposure on ${a.name}`,
        description: `${vs.map(v => v.cve).join(', ')} ${vs.length > 1 ? 'are' : 'is'} listed by CISA as used in ransomware campaigns.`,
        drivers: vs.map(v => v.id), likelihood: a.internet_exposed ? 4 : 3, stride: ['T', 'D'], attack: [entry, 'T1486'],
        kill_chain: 'actions_on_objectives',
        rationale: `CISA KEV marks ${vs.map(v => v.cve).join(', ')} with known ransomware campaign use → encryption for impact (ATT&CK T1486; STRIDE Tampering / Denial of Service). Derived from exploitation intelligence, not from observed activity in this environment.`,
      }));
    }
    return out;
  },
});

export const RULE_CATALOG = RULES.map(r => ({ id: r.id, version: r.version, category: r.category, summary: r.summary }));

export const deriveThreats = (t: Topology): TrThreat[] => {
  const assets = new Map(t.assets.map(a => [a.id, a]));
  return RULES.flatMap(r => r.evaluate(t, assets));
};
