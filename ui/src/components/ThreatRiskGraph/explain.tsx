import React from 'react';
import type { TipContent } from './ui';

/**
 * Hover explanations for every Threat & Risk Graph box: what it is, where its data
 * comes from, and how it is computed. Kept in one place so wording stays consistent
 * with the engine (server/src/lib/threatGraph).
 */

const B: React.FC<{ children: React.ReactNode }> = ({ children }) => <strong style={{ color: '#f8fafc' }}>{children}</strong>;

export const EXPLAIN: Record<string, TipContent> = {
  threats: {
    what: 'Threat scenarios QuarkShield derived for this scope — each one names an actor, an intent and the asset at stake.',
    source: 'SBOM CVE matches, CBOM crypto findings, PKI/KMS keys, PQC-proxy TLS settings and Git repository scans.',
    how: <>The rule catalog (<B>TR-01…TR-09</B>) fires only when a concrete finding exists (a CVE, a weak or quantum-vulnerable key, a committed private key…). CVEs count when CVSS ≥ 7 <B>or</B> they are in CISA KEV. The arrow compares with the previous rebuild.</>,
  },
  highCritical: {
    what: 'Risks whose residual level is High or Critical.',
    source: 'One risk per threat on its own asset, plus one per attack path reaching a sensitive asset.',
    how: <><B>Likelihood × Impact</B> (each 1–4). Likelihood comes from exploitation intelligence — <B>CISA KEV</B> (exploited in the wild → highest) and <B>FIRST EPSS</B> (probability of exploitation) — falling back to CVSS, plus exposure and path confidence. Impact comes from the asset’s criticality and data classification. ≥12 Critical, ≥6 High.</>,
  },
  controls: {
    what: 'NIST SP 800-53 Rev 5 controls touched by at least one open (Medium or higher) risk.',
    source: 'Rule-based risk → control map (e.g. CVE exploitation → SI-2, RA-5, CM-8; HNDL → SC-8, SC-12, SC-13).',
    how: 'Indicative only: it shows where risk concentrates, not whether a control is implemented or effective. That needs RMF assessment evidence.',
  },
  residual: {
    what: 'Overall risk remaining after the remediations you have completed.',
    source: 'Inherent risk scores plus the remediation workflow (owner, target date, status).',
    how: <>Level = average of the top-10 residual scores. The % is how much total risk dropped from inherent. Only <B>Done</B> or <B>Verified</B> remediations lower risk — configuration presence alone never does.</>,
  },
  frameworks: {
    what: 'Compliance frameworks the open risks map into.',
    source: 'NIST 800-53 r5 anchor; 800-171 r2 crosswalk from SP 800-171 Appendix D (CMMC Level 2 uses the same numbering); FedRAMP Moderate baseline membership.',
    how: 'A framework is counted when at least one open risk maps to one of its controls.',
  },
  architecture: {
    what: 'Your environment as QuarkShield discovered it: external threats → user endpoints & repositories → edge (proxies, TLS endpoints) → servers → services → data stores → key data.',
    source: <>Fleet agents, SBOM server packages, PQC proxies, agent TLS probes, Git scans and PKI connectors. <B>No relationship is entered by hand.</B></>,
    how: <>Relationships come from correlation rules <B>R1–R9</B> (proxy upstreams, certificate names, TLS probes, PKI references, SBOM fingerprints, shared segments, server packages, host role). Hover a node for its lineage; Threat View highlights attack-path hops, Data Flow labels each flow.</>,
  },
  threatTypes: {
    what: 'How the threats in this scope split across the V1 threat categories.',
    source: 'Derived threats (see Total Threats).',
    how: 'Count per category; the % is the share of all threats in scope. Ransomware is derived from CISA KEV’s “known ransomware campaign use” flag on your CVEs. API abuse and insider threats are not derived yet — no deterministic signal in today’s data.',
  },
  compliance: {
    what: 'Per framework, the controls that open risks touch.',
    source: 'Risk → NIST 800-53 map, crosswalked to FedRAMP Moderate, NIST 800-171 r2 and CMMC Level 2.',
    how: '“At risk” = number of that framework’s controls touched by open risks. It is not a gap or non-compliance finding.',
  },
  heatMap: {
    what: 'Where the top five threat scenarios sit on the likelihood × impact grid (T1 = highest residual risk).',
    source: 'Top Threat Scenarios.',
    how: 'Position uses the scenario’s likelihood and impact; the label colour is its residual level. Click a marker to open the scenario.',
  },
  topScenarios: {
    what: 'Threat scenarios ranked by residual risk.',
    source: 'Derived threats, their risks and attack paths, plus the remediation workflow.',
    how: 'Status comes from the remediations for the threat’s own findings: Needs Attention (none started), Planned (owner/date set), In Progress, Mitigated (all done) or Risk Accepted.',
  },
  actions: {
    what: 'Fixes that reduce the most risk first.',
    source: 'Patch actions from CVE fixed versions; purpose-aware crypto actions (ML-KEM for key establishment, ML-DSA for signatures/SSH, certificate migration); key rotation for leaked or weak keys.',
    how: 'P1 if the action fixes a CISA KEV (exploited-in-the-wild) vulnerability or reduces a Critical risk (≥12), P2 for High (≥6), otherwise P3. The KEV badge shows CISA’s remediation due date (binding for U.S. federal agencies under BOD 22-01). Owner and target date come from the remediation workflow.',
  },
  attackPaths: {
    what: 'Chains of weaknesses an attacker could follow from an entry point to a sensitive asset.',
    source: 'Inferred relationships plus derived threats.',
    how: 'Search from initial-access threats (exposed CVEs, supply chain, leaked/weak keys, weak TLS) to assets with high criticality or sensitive data, up to 6 hops, preferring higher-confidence links. Confidence = weakest link on the path.',
  },
  crypto: {
    what: 'Cryptographic findings grouped by what they are used for.',
    source: 'CBOM: agent trust stores, SSH keys, TLS probes, repository scans, PKI/KMS connectors, PQC proxies.',
    how: 'Quantum-vulnerable = classical RSA/ECC/DH. HNDL = quantum-vulnerable key establishment (traffic recorded today could be decrypted later). Weak = classically breakable today.',
  },
  frameworksCoverage: {
    what: 'STRIDE categories and MITRE ATT&CK® techniques across the threats in scope.',
    source: 'Declared by each threat rule (STRIDE refined from the CVE’s CWE when available).',
    how: 'ATT&CK techniques are potential techniques implied by an exposure — not observed adversary activity.',
  },
  dataSources: {
    what: 'The QuarkShield inputs this threat model was built from.',
    source: 'Agent ingest, SBOM/CVE matching, CBOM, Git/CI scans, PKI/KMS connectors and PQC proxies.',
    how: 'The model is rebuilt automatically when new data arrives (agent check-in, git scan, PKI sync, proxy change) and on demand with the refresh button.',
  },
};

/** Correlation rules shown in node lineage tooltips. */
export const RULE_TEXT: Record<string, string> = {
  R1: 'PQC proxy upstream URL matched to this host',
  R2: 'Certificate DNS name matched to a probed endpoint',
  R3: 'Agent TLS probe observed this connection',
  R4: 'Certificate references a PKI/KMS-managed asset',
  R5: 'Repository ↔ host software fingerprint overlap',
  R6: 'Shared Workstation Group / egress IP',
  R7: 'Internet exposure',
  R8: 'Server package found in host SBOM',
  R9: 'Host role (server vs user endpoint)',
};

export const SOURCE_LABEL: Record<string, string> = {
  fleet_machines: 'QuarkShield agent (fleet)',
  sbom_components: 'SBOM (server package / system)',
  git_scans: 'Git / CI repository scan',
  pki_connectors: 'PKI / KMS connector',
  pqc_proxies: 'PQC proxy configuration',
  derived: 'TLS probe / proxy upstream',
};

/**
 * How each "Data sources" chip relates to the boxes in the Threat Model Overview.
 * Some sources CREATE boxes (they discover assets); others ADD FINDINGS to existing boxes
 * (they are evidence about an asset, so they never get a box of their own).
 */
export interface SourceRole {
  role: 'creates' | 'enriches';
  summary: string;
  /** Does this member asset (graph node) carry data from the source? */
  match: (m: any) => boolean;
  /** One-line evidence for a matching member. */
  evidence: (m: any) => string;
}

const f = (m: any) => m.meta?.findings || { components: 0, vulns: 0, crypto: 0, intel: [] };
const epssPct = (n: number) => `${(n * 100).toFixed(n < 0.01 || n >= 0.995 ? 2 : 1)}%`;

export const SOURCE_ROLES: Record<string, SourceRole> = {
  fleet: {
    role: 'creates', summary: 'Each enrolled agent becomes a User endpoint or Server box.',
    match: m => m.meta?.source_table === 'fleet_machines', evidence: m => `${m.label} — enrolled agent`,
  },
  repos: {
    role: 'creates', summary: 'Each scanned repository becomes a Repository box.',
    match: m => m.meta?.source_table === 'git_scans', evidence: m => `${m.label} — Git/CI scan`,
  },
  pki: {
    role: 'creates', summary: 'Each PKI / KMS connector becomes a key-store box in the data tier.',
    match: m => m.meta?.source_table === 'pki_connectors', evidence: m => `${m.label} — key/certificate inventory`,
  },
  proxy: {
    role: 'creates', summary: 'Each PQC proxy becomes an edge box; its upstream becomes internet-reachable.',
    match: m => m.meta?.source_table === 'pqc_proxies', evidence: m => `${m.label} — proxy configuration`,
  },
  probe: {
    role: 'creates', summary: 'Endpoints seen by agent TLS probes or proxy upstreams become TLS endpoint boxes.',
    match: m => m.subtype === 'tls_endpoint', evidence: m => `${m.label}${m.exposed ? ' — public, internet-exposed' : ''}`,
  },
  sbom: {
    role: 'enriches', summary: 'Software components attach to the box they run on; server packages also create Service / Database boxes.',
    match: m => f(m).components > 0 || m.meta?.source_table === 'sbom_components',
    evidence: m => (f(m).components ? `${m.label} — ${f(m).components} component${f(m).components > 1 ? 's' : ''}` : `${m.label} — created from a server package`),
  },
  cve: {
    role: 'enriches', summary: 'CVEs matched to SBOM component versions attach to the same box.',
    match: m => f(m).vulns > 0, evidence: m => `${m.label} — ${f(m).vulns} CVE${f(m).vulns > 1 ? 's' : ''}`,
  },
  cbom: {
    role: 'enriches', summary: 'Keys, certificates and TLS/SSH crypto attach to the box where they were found.',
    match: m => f(m).crypto > 0, evidence: m => `${m.label} — ${f(m).crypto} crypto finding${f(m).crypto > 1 ? 's' : ''}`,
  },
  intel: {
    role: 'enriches', summary: 'KEV / EPSS has no box of its own: it enriches the CVEs inside boxes and raises their likelihood.',
    match: m => (f(m).intel || []).length > 0,
    evidence: m => `${m.label} — ${(f(m).intel as any[]).map(i => `${i.cve}${i.kev ? ' · KEV' : ''}${i.ransomware ? ' · ransomware' : ''}${typeof i.epss === 'number' ? ` · EPSS ${epssPct(i.epss)}` : ''}`).join('; ')}`,
  },
};
