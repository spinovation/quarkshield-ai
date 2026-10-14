import pool from '../config/db';

/**
 * PQC Executive Roadmap Report engine.
 *
 * Produces a structured, DETERMINISTIC assessment from the shared `assets`
 * inventory (all sources: endpoint / git_repo / cloud_kms / enterprise_pki /
 * pqc_proxy) for a single tenant OR the whole fleet (collective). All counts,
 * priorities, remediation mappings and roadmap actions are computed from data —
 * no AI-invented numbers. An optional AI-written executive-summary paragraph is
 * layered on top with a templated fallback (see generateNarrative()).
 */

export interface RoadmapScope {
  collective: boolean;      // true = fleet-wide across all tenants (super-admin)
  tenant?: string;          // tenant filter when not collective
}

export interface Priority {
  rank: number;
  title: string;            // e.g. "RSA-2048 key exchange"
  algorithm: string;
  count: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  exposure: string;         // human-readable dominant exposure
  score: number;
  rationale: string;
  purpose?: string;         // dominant CryptoPurpose for this algorithm group (CBOM purpose, P1)
  purposeLabel?: string;    // human label for the dominant purpose
}

/** Threat urgency a cryptographic PURPOSE implies (decouples HNDL from forgery). */
export type PurposeUrgency = 'immediate_hndl' | 'forgery_planned' | 'hardening' | 'review';

export interface PurposeBreakdown {
  purpose: string;          // raw CryptoPurpose value (key_establishment, tls_certificate, ...)
  label: string;
  count: number;            // vulnerable assets with this purpose
  urgency: PurposeUrgency;
  urgencyLabel: string;
  standard: string;         // dominant NIST target for this purpose
}

// Purpose → urgency/label/standard. Mirrors the HNDL-vs-forgery split in
// docs/PQC_FUNCTIONAL_ANALYSIS_AND_REMEDIATION.md: key establishment is an
// IMMEDIATE Harvest-Now-Decrypt-Later concern; signatures/trust are a PLANNED
// forgery concern that only activates once a CRQC exists.
const PURPOSE_META: Record<string, { label: string; urgency: PurposeUrgency; urgencyLabel: string; standard: string }> = {
  key_establishment:    { label: 'Key establishment',   urgency: 'immediate_hndl',  urgencyLabel: 'Immediate — Harvest-Now-Decrypt-Later', standard: 'FIPS 203 (ML-KEM)' },
  rsa_key_transport:    { label: 'RSA key transport',    urgency: 'immediate_hndl',  urgencyLabel: 'Immediate — Harvest-Now-Decrypt-Later', standard: 'FIPS 203 (ML-KEM)' },
  tls_certificate:      { label: 'TLS certificate',      urgency: 'forgery_planned', urgencyLabel: 'Planned — signature forgery risk',      standard: 'FIPS 204 (ML-DSA)' },
  code_or_data_signing: { label: 'Code / data signing',  urgency: 'forgery_planned', urgencyLabel: 'Planned — signature forgery risk',      standard: 'FIPS 204 / 205' },
  ca_trust_anchor:      { label: 'CA trust anchor',      urgency: 'forgery_planned', urgencyLabel: 'Planned — signature forgery risk',      standard: 'FIPS 204 (ML-DSA)' },
  ssh_authentication:   { label: 'SSH authentication',   urgency: 'forgery_planned', urgencyLabel: 'Planned — signature forgery risk',      standard: 'FIPS 204 (ML-DSA)' },
  symmetric:            { label: 'Symmetric encryption', urgency: 'hardening',       urgencyLabel: 'Hardening — ensure AES-256',            standard: 'CNSA 2.0' },
  configuration:        { label: 'Crypto configuration', urgency: 'hardening',       urgencyLabel: 'Hardening — disable legacy ciphers',    standard: 'CNSA 2.0' },
  unknown:              { label: 'Unclassified',         urgency: 'review',          urgencyLabel: 'Review — purpose not yet classified',   standard: '—' },
};
const URGENCY_RANK: Record<PurposeUrgency, number> = { immediate_hndl: 0, forgery_planned: 1, hardening: 2, review: 3 };

/** PQC size-impact ("what breaks") summary across the inventory (P2). */
export interface MigrationFriction {
  signingAssets: number;       // assets whose signatures grow (cert/code/CA/SSH)
  kexAssets: number;           // assets whose key exchange grows (key establishment / RSA transport)
  firmwareOrRootAssets: number;// code-signing + CA trust-anchor — the fixed-slot risk
  headline: string;
  detail: string;
}
/** Resolve purpose metadata, defaulting unknown/legacy (NULL purpose) rows safely. */
export const purposeMeta = (purpose?: string | null) => PURPOSE_META[(purpose || 'unknown')] || PURPOSE_META.unknown;

export interface Remediation {
  finding: string;          // classical primitive / config
  replacement: string;      // NIST PQC replacement
  standard: string;         // FIPS 203/204/205 etc.
  effort: 'Low' | 'Medium' | 'High';
  how: string;
}

export interface RoadmapPhase {
  phase: string;
  window: string;
  mandate: string;
  status: 'Complete' | 'In progress' | 'Planned';
  actions: string[];
}

export interface TenantBreakdown {
  tenant: string;
  assets: number;
  vulnerable: number;
  vulnPct: number;
  topRisk: string;
}

export interface RoadmapReport {
  scopeLabel: string;       // "SPINOVATIONCORP" or "All Tenants (Fleet)"
  collective: boolean;
  generatedAt: string;
  reportId: string;         // short human reference for the document
  riskGrade: string;        // A / B+ / C / D+ / F derived from vuln % + avg risk
  totals: { tenants: number; machines: number; assets: number; vulnerable: number; pqcReady: number; avgRisk: number; vulnPct: number };
  mosca: { verdict: string; detail: string };
  priorities: Priority[];
  remediation: Remediation[];
  roadmap: RoadmapPhase[];
  purposeBreakdown: PurposeBreakdown[];  // vulnerable assets grouped by crypto purpose (P1)
  migrationFriction: MigrationFriction;  // PQC size-impact ("what breaks") summary (P2)
  perTenant: TenantBreakdown[];   // populated for collective
  summary: string;                // narrative (AI or templated)
}

const SEVERITY_WEIGHT: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const EXPOSURE_WEIGHT: Record<string, number> = {
  git_repo: 1.3,        // hardcoded secrets in source = high leak exposure
  pqc_proxy: 1.3,       // in-flight / measured upstream TLS = HNDL wire exposure
  cloud_kms: 1.1,       // centralized cloud keys
  enterprise_pki: 1.1,  // centralized PKI keys
  endpoint: 1.0,
  endpoint_deploy: 1.0,
};
const SOURCE_LABEL: Record<string, string> = {
  git_repo: 'source repositories',
  pqc_proxy: 'in-flight TLS gateways',
  cloud_kms: 'cloud KMS vaults',
  enterprise_pki: 'enterprise PKI/vaults',
  endpoint: 'endpoints',
  endpoint_deploy: 'endpoints',
};

/** Normalize an algorithm string to a family used for remediation mapping. */
const algoFamily = (algo: string): string => {
  const a = (algo || '').toUpperCase();
  if (a.includes('ML-KEM') || a.includes('MLKEM') || a.includes('ML-DSA') || a.includes('MLDSA') || a.includes('SLH-DSA') || a.includes('KYBER') || a.includes('DILITHIUM')) return 'PQC';
  if (a.includes('RSA')) return 'RSA';
  if (a.includes('ECDSA')) return 'ECDSA';
  if (a.includes('ECDH')) return 'ECDH';
  if (a.includes('ECC') || a.includes('SECP') || a.includes('P-256') || a.includes('P-384') || a.includes('CURVE25519') || a.includes('X25519')) return 'ECC';
  if (a.includes('3DES') || a.includes('DES')) return '3DES';
  if (a.includes('MD5')) return 'MD5';
  if (a.includes('SHA-1') || a.includes('SHA1')) return 'SHA1';
  if (a.includes('TLS 1.2') || a.includes('TLSV1.2') || a.includes('TLS 1.0') || a.includes('TLS 1.1')) return 'TLS_LEGACY';
  if (a.includes('DH') || a.includes('DIFFIE')) return 'DH';
  if (a.includes('AES')) return 'AES';
  return 'OTHER';
};

const REMEDIATION_BY_FAMILY: Record<string, Remediation> = {
  RSA: { finding: 'RSA (key exchange & signatures)', replacement: 'ML-KEM-768 for key establishment; ML-DSA-65 for signatures', standard: 'NIST FIPS 203 / FIPS 204', effort: 'High', how: 'Re-issue certificates and rotate keys to composite/hybrid (X25519MLKEM768) TLS and ML-DSA signing; prioritize long-lived keys and externally reachable services.' },
  ECDSA: { finding: 'ECDSA signatures', replacement: 'ML-DSA-65 (or SLH-DSA for firmware/roots)', standard: 'NIST FIPS 204 / FIPS 205', effort: 'Medium', how: 'Migrate signing pipelines and code/firmware signing to ML-DSA; use SLH-DSA (stateless hash) for immutable roots of trust.' },
  ECDH: { finding: 'ECDH key exchange', replacement: 'Hybrid X25519MLKEM768 key establishment', standard: 'NIST FIPS 203', effort: 'Medium', how: 'Enable hybrid PQC key exchange on TLS 1.3 endpoints (OpenSSL 3.2+/BoringSSL) and VPN/IKEv2.' },
  ECC: { finding: 'Elliptic-curve keys', replacement: 'Hybrid X25519MLKEM768 (KEX) / ML-DSA (sig)', standard: 'NIST FIPS 203 / 204', effort: 'Medium', how: 'Replace classical ECC key exchange with hybrid ML-KEM; migrate ECDSA certs to ML-DSA.' },
  DH: { finding: 'Finite-field Diffie-Hellman', replacement: 'ML-KEM-768 (hybrid)', standard: 'NIST FIPS 203', effort: 'Medium', how: 'Retire classical DH groups; deploy hybrid ML-KEM key establishment.' },
  TLS_LEGACY: { finding: 'Legacy TLS (<1.3)', replacement: 'TLS 1.3 with hybrid X25519MLKEM768', standard: 'NIST FIPS 203 / NSA CNSA 2.0', effort: 'Medium', how: 'Enforce TLS 1.3 only and enable the hybrid PQC curve; front legacy backends with the QuarkShield hybrid TLS proxy where upgrades are blocked.' },
  '3DES': { finding: '3DES symmetric cipher', replacement: 'AES-256-GCM', standard: 'NIST SP 800-131A', effort: 'Low', how: 'Disable 3DES cipher suites; standardize on AES-256-GCM (quantum-resistant with 128-bit Grover margin).' },
  MD5: { finding: 'MD5 hashing', replacement: 'SHA-256 / SHA-3', standard: 'NIST FIPS 180-4 / 202', effort: 'Low', how: 'Replace MD5 in all integrity/signature contexts with SHA-256 or SHA-3.' },
  SHA1: { finding: 'SHA-1 hashing', replacement: 'SHA-256 / SHA-3', standard: 'NIST FIPS 180-4 / 202', effort: 'Low', how: 'Eliminate SHA-1 from certificates and signing; move to SHA-256/384.' },
};

const severityRank = (s: string): number => SEVERITY_WEIGHT[(s || 'high').toLowerCase()] ?? 3;
const worstSeverity = (a: string, b: string): string => (severityRank(a) >= severityRank(b) ? a : b);

/** Gather + compute the full roadmap report for a scope. */
export const buildRoadmapReport = async (scope: RoadmapScope): Promise<RoadmapReport> => {
  // SECURITY: EXACT tenant match (was `%tenant%` LIKE → a tenant whose slug is a substring
  // of another's would pull that tenant's assets/machines into this roadmap/report). The
  // spinovation/engg alias stays gated to that operator's own session.
  const tenantPred = (col: string) =>
    `WHERE (LOWER(COALESCE(${col}, '')) = LOWER($1) OR (LOWER($1) IN ('spinovation','spinovationcorp') AND LOWER(COALESCE(${col}, '')) LIKE '%spinovation%'))`;
  const where = scope.collective ? '' : tenantPred('tenant_name');
  const params: any[] = scope.collective ? [] : [scope.tenant];
  const mWhere = scope.collective ? '' : tenantPred('tenant_name');

  const totalsQ = await pool.query(
    `SELECT COUNT(*)::int AS assets,
            COUNT(*) FILTER (WHERE is_vulnerable)::int AS vulnerable,
            COUNT(*) FILTER (WHERE NOT is_vulnerable)::int AS pqc_ready,
            COUNT(DISTINCT NULLIF(tenant_name, ''))::int AS tenants
     FROM assets ${where}`, params);
  const machinesQ = await pool.query(`SELECT COUNT(*)::int AS machines, COALESCE(ROUND(AVG(quantum_risk_score)),0)::int AS avg_risk FROM fleet_machines ${mWhere}`, params);

  // Rows grouped by algorithm for priority scoring (vulnerable only), with dominant source.
  const groupQ = await pool.query(
    `SELECT COALESCE(algorithm,'Unknown') AS algorithm,
            COUNT(*)::int AS count,
            MODE() WITHIN GROUP (ORDER BY COALESCE(source,'endpoint')) AS dominant_source,
            MODE() WITHIN GROUP (ORDER BY COALESCE(NULLIF(purpose,''),'unknown')) AS dominant_purpose,
            (ARRAY_AGG(DISTINCT COALESCE(risk_level,'high')))::text[] AS risks
     FROM assets ${where}${where ? ' AND' : 'WHERE'} is_vulnerable
     GROUP BY algorithm ORDER BY count DESC LIMIT 40`, params);

  // Vulnerable assets grouped by crypto PURPOSE (P1 — "what is my crypto used FOR").
  const purposeQ = await pool.query(
    `SELECT COALESCE(NULLIF(purpose,''),'unknown') AS purpose, COUNT(*)::int AS count
     FROM assets ${where}${where ? ' AND' : 'WHERE'} is_vulnerable
     GROUP BY 1`, params);

  // Remediation families present (vulnerable).
  const t = totalsQ.rows[0] || {};
  const m = machinesQ.rows[0] || {};
  const assets = t.assets || 0;
  const vulnerable = t.vulnerable || 0;
  const vulnPct = assets > 0 ? Math.round((vulnerable / assets) * 100) : 0;

  // ---- Priorities (deterministic scoring) ----
  const scored = groupQ.rows.map((r: any) => {
    const fam = algoFamily(r.algorithm);
    const risks: string[] = r.risks || ['high'];
    const sev = risks.reduce((acc, x) => worstSeverity(acc, x), 'low');
    const src = r.dominant_source || 'endpoint';
    const exposureW = EXPOSURE_WEIGHT[src] ?? 1.0;
    const shorBreakable = ['RSA', 'ECDSA', 'ECDH', 'ECC', 'DH'].includes(fam);
    const shorMult = shorBreakable ? 1.25 : 1.0;
    const purpose = r.dominant_purpose || 'unknown';
    // HNDL purposes (key establishment / RSA key transport) are harvestable TODAY,
    // so they outrank an equally-breakable signing key of the same algorithm.
    const hndlMult = purposeMeta(purpose).urgency === 'immediate_hndl' ? 1.15 : 1.0;
    const score = Math.round(r.count * severityRank(sev) * exposureW * shorMult * hndlMult);
    return { algorithm: r.algorithm, fam, count: r.count, sev, src, score, shorBreakable, purpose };
  }).filter(x => x.fam !== 'PQC' && x.fam !== 'AES'); // exclude already-safe primitives

  scored.sort((a, b) => b.score - a.score);
  const priorities: Priority[] = scored.slice(0, 8).map((x, i) => {
    const meta = purposeMeta(x.purpose);
    const purposeNote = x.purpose && x.purpose !== 'unknown' ? ` Purpose: ${meta.label.toLowerCase()} (${meta.urgencyLabel}).` : '';
    return {
      rank: i + 1,
      title: x.algorithm,
      algorithm: x.algorithm,
      count: x.count,
      severity: (['critical', 'high', 'medium', 'low'].includes(x.sev.toLowerCase()) ? x.sev.toLowerCase() : 'high') as Priority['severity'],
      exposure: SOURCE_LABEL[x.src] || 'assets',
      score: x.score,
      rationale: `${x.count} ${x.algorithm} asset${x.count === 1 ? '' : 's'} on ${SOURCE_LABEL[x.src] || 'assets'}${x.shorBreakable ? ', breakable by Shor’s algorithm on a CRQC (Harvest-Now-Decrypt-Later risk today)' : ''}.${purposeNote}`,
      purpose: x.purpose,
      purposeLabel: meta.label,
    };
  });

  // ---- Purpose breakdown (vulnerable), ordered immediate-HNDL first ----
  const purposeBreakdown: PurposeBreakdown[] = purposeQ.rows
    .map((r: any) => {
      const meta = purposeMeta(r.purpose);
      return { purpose: r.purpose, label: meta.label, count: r.count, urgency: meta.urgency, urgencyLabel: meta.urgencyLabel, standard: meta.standard };
    })
    .sort((a, b) => URGENCY_RANK[a.urgency] - URGENCY_RANK[b.urgency] || b.count - a.count);

  // ---- Migration friction / "what breaks" size impact (P2) ----
  const pCount = (ps: string[]) => purposeBreakdown.filter(p => ps.includes(p.purpose)).reduce((n, p) => n + p.count, 0);
  const signingAssets = pCount(['tls_certificate', 'code_or_data_signing', 'ca_trust_anchor', 'ssh_authentication']);
  const kexAssets = pCount(['key_establishment', 'rsa_key_transport']);
  const firmwareOrRootAssets = pCount(['code_or_data_signing', 'ca_trust_anchor']);
  const frictionParts: string[] = [];
  if (signingAssets) frictionParts.push(`${signingAssets} signature-bearing asset(s) move to ML-DSA (~50× an Ed25519 / ~13× an RSA-2048 signature)`);
  if (kexAssets) frictionParts.push(`${kexAssets} key-establishment asset(s) move to ML-KEM (~35× an X25519 key share)`);
  const migrationFriction: MigrationFriction = {
    signingAssets, kexAssets, firmwareOrRootAssets,
    headline: frictionParts.length
      ? `Post-quantum objects are far larger: ${frictionParts.join('; ')}.`
      : 'No size-sensitive classical crypto detected.',
    detail: firmwareOrRootAssets
      ? `${firmwareOrRootAssets} code-signing / root-of-trust key(s) are the hardest: SLH-DSA firmware signatures are ≈7.9 KB, so systems with fixed secure-boot signature slots or smartcard/HSM storage may need header re-layout or hardware changes — not a config switch. Larger ML-KEM/ML-DSA objects can also stress TLS cert chains, QUIC anti-amplification and IKEv2/MTU fragmentation on constrained paths.`
      : (signingAssets || kexAssets)
        ? 'Larger ML-KEM/ML-DSA objects can stress TLS certificate chains, QUIC anti-amplification limits and IKEv2/MTU fragmentation on constrained paths; verify per-system before rollout.'
        : 'No material size-impact risk identified from the current inventory.',
  };

  // ---- Remediation (families actually present) ----
  const famsPresent = Array.from(new Set(scored.map(x => x.fam)));
  const remediation: Remediation[] = famsPresent
    .map(f => REMEDIATION_BY_FAMILY[f])
    .filter((r): r is Remediation => !!r);
  if (remediation.length === 0 && vulnerable > 0) {
    remediation.push(REMEDIATION_BY_FAMILY.RSA);
  }

  // ---- Migration roadmap (CNSA 2.0 / OMB M-23-02) populated with counts ----
  const rsaEcc = scored.filter(x => ['RSA', 'ECDSA', 'ECDH', 'ECC', 'DH'].includes(x.fam)).reduce((n, x) => n + x.count, 0);
  const tlsLegacy = scored.filter(x => x.fam === 'TLS_LEGACY').reduce((n, x) => n + x.count, 0);
  const weakHash = scored.filter(x => ['MD5', 'SHA1', '3DES'].includes(x.fam)).reduce((n, x) => n + x.count, 0);
  const roadmap: RoadmapPhase[] = [
    { phase: 'Phase 1 — Discovery & CBOM', window: '2024–2025', mandate: 'OMB M-23-02 (annual CBOM)', status: 'Complete', actions: [`Cryptographic inventory established: ${assets} assets across ${m.machines || 0} endpoints.`, `${vulnerable} quantum-vulnerable assets identified (${vulnPct}%).`] },
    { phase: 'Phase 2 — Crypto-agility & hybrid TLS', window: '2025–2027', mandate: 'NSA CNSA 2.0 (begin transition)', status: 'In progress', actions: [tlsLegacy ? `Enforce TLS 1.3 + hybrid X25519MLKEM768 on ${tlsLegacy} legacy-TLS asset(s).` : 'Enable hybrid X25519MLKEM768 on all TLS 1.3 ingress.', 'Deploy the QuarkShield hybrid TLS proxy in front of backends that cannot be upgraded.', weakHash ? `Retire ${weakHash} weak symmetric/hash primitive(s) (3DES/MD5/SHA-1).` : 'Confirm all symmetric crypto is AES-256.'] },
    { phase: 'Phase 3 — Signing, firmware & PKI', window: '2027–2030', mandate: 'CNSA 2.0 (software/firmware signing)', status: 'Planned', actions: [`Migrate ${rsaEcc} RSA/ECC key(s) to ML-KEM (FIPS 203) and ML-DSA (FIPS 204).`, 'Adopt SLH-DSA / LMS-XMSS for firmware and roots of trust.', 'Re-issue enterprise PKI and vault-held keys as composite/hybrid certificates.'] },
    { phase: 'Phase 4 — Full deprecation', window: 'by 2033', mandate: 'CNSA 2.0 (100% PQC)', status: 'Planned', actions: ['Remove all classical RSA/ECC key exchange and signatures.', 'Continuous CBOM attestation to prove and maintain PQC posture.'] },
  ];

  // ---- Mosca verdict ----
  // Migration time (Y) is longer than a config change when firmware/root keys are in scope.
  const frictionClause = vulnPct > 0 && firmwareOrRootAssets
    ? ` Migration time (Y) is longer than it looks: ${firmwareOrRootAssets} code-signing / root-of-trust key(s) may need firmware or hardware changes to fit larger PQC signatures, not just a config switch.`
    : '';
  const mosca = vulnPct > 0
    ? { verdict: 'ACTION REQUIRED', detail: `With ${vulnPct}% of assets quantum-vulnerable and multi-year migration timelines, data harvested today is at risk before migration completes (X + Y > Z). Begin Phase 2 now.${frictionClause}` }
    : { verdict: 'ON TRACK', detail: 'No quantum-vulnerable assets detected in the current inventory. Maintain continuous CBOM attestation.' };

  // ---- Per-tenant breakdown (collective) ----
  let perTenant: TenantBreakdown[] = [];
  if (scope.collective) {
    const ptQ = await pool.query(
      `SELECT COALESCE(NULLIF(tenant_name,''),'(unassigned)') AS tenant,
              COUNT(*)::int AS assets,
              COUNT(*) FILTER (WHERE is_vulnerable)::int AS vulnerable,
              (ARRAY_AGG(algorithm ORDER BY (CASE WHEN is_vulnerable THEN 0 ELSE 1 END), key_size DESC NULLS LAST))[1] AS top_risk
       FROM assets GROUP BY 1 ORDER BY vulnerable DESC, assets DESC LIMIT 50`);
    perTenant = ptQ.rows.map((r: any) => ({
      tenant: r.tenant,
      assets: r.assets,
      vulnerable: r.vulnerable,
      vulnPct: r.assets > 0 ? Math.round((r.vulnerable / r.assets) * 100) : 0,
      topRisk: r.top_risk || '-',
    }));
  }

  // Risk grade (A best … F worst) from vulnerable % blended with avg risk score.
  const blended = Math.round(vulnPct * 0.7 + (m.avg_risk || 0) * 0.3);
  const riskGrade = blended >= 65 ? 'F' : blended >= 50 ? 'D+' : blended >= 35 ? 'C' : blended >= 15 ? 'B+' : blended > 0 ? 'A-' : 'A';

  return {
    scopeLabel: scope.collective ? 'All Tenants (Fleet)' : (scope.tenant || ''),
    collective: scope.collective,
    generatedAt: new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC',
    reportId: `QS-PQCR-${(scope.collective ? 'FLEET' : (scope.tenant || 'T').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8))}-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}`,
    riskGrade,
    totals: { tenants: t.tenants || 0, machines: m.machines || 0, assets, vulnerable, pqcReady: t.pqc_ready || 0, avgRisk: m.avg_risk || 0, vulnPct },
    mosca,
    priorities,
    remediation,
    roadmap,
    purposeBreakdown,
    migrationFriction,
    perTenant,
    summary: '', // filled by generateNarrative()
  };
};

/**
 * Executive-summary narrative. Tries Gemini then Anthropic (keys from env or
 * tenant_settings); falls back to a deterministic template so the report always
 * has a professional summary even offline / without keys. Never invents numbers.
 */
export const generateNarrative = async (r: RoadmapReport, tenant?: string): Promise<string> => {
  const hndl = r.purposeBreakdown.filter(p => p.urgency === 'immediate_hndl').reduce((n, p) => n + p.count, 0);
  const sig = r.purposeBreakdown.filter(p => p.urgency === 'forgery_planned').reduce((n, p) => n + p.count, 0);
  const purposeFact = r.purposeBreakdown.length ? ` By purpose: ${hndl} key-establishment (immediate HNDL), ${sig} signature/trust (planned forgery risk).` : '';
  const facts = `Scope: ${r.scopeLabel}. Assets: ${r.totals.assets}. Quantum-vulnerable: ${r.totals.vulnerable} (${r.totals.vulnPct}%). Endpoints: ${r.totals.machines}. Avg risk: ${r.totals.avgRisk}/100. Top priorities: ${r.priorities.slice(0, 3).map(p => p.title).join(', ') || 'none'}. Mosca verdict: ${r.mosca.verdict}.${purposeFact}`;
  const template =
    `${r.scopeLabel} has ${r.totals.assets} catalogued cryptographic assets, of which ${r.totals.vulnerable} (${r.totals.vulnPct}%) are quantum-vulnerable classical primitives exposed to Harvest-Now-Decrypt-Later attacks. ` +
    `The highest-priority exposures are ${r.priorities.slice(0, 3).map(p => p.title).join(', ') || 'being assessed'}. ` +
    `Under NSA CNSA 2.0 and OMB M-23-02, migration to NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) must begin now; the phased roadmap below sequences remediation from hybrid TLS through full classical deprecation by 2033. Verdict: ${r.mosca.verdict}.`;

  let geminiKey = (process.env.GEMINI_API_KEY || '').trim();
  let anthropicKey = (process.env.ANTHROPIC_API_KEY || '').trim();
  // SECURITY: only a concrete tenant may override the platform keys with its OWN BYO keys.
  // The previous query had no tenant filter/ORDER BY, so the last row won — a report could
  // be generated with another tenant's API key. Collective/fleet reports use env keys only.
  if (tenant) {
    try {
      const s = await pool.query(
        "SELECT key, value FROM tenant_settings WHERE LOWER(tenant_name) = LOWER($1) AND key IN ('gemini_api_key','anthropic_api_key')",
        [tenant]
      );
      for (const row of s.rows) {
        if (row.key === 'gemini_api_key' && row.value?.trim()) geminiKey = row.value.trim();
        if (row.key === 'anthropic_api_key' && row.value?.trim()) anthropicKey = row.value.trim();
      }
    } catch { /* ignore */ }
  }

  const system = 'You are a principal post-quantum cryptography advisor writing the executive summary of a board-level PQC readiness report. Write ONE concise, professional paragraph (90-140 words). Use ONLY the facts provided — do not invent numbers, asset names, or dates. Tone: executive, factual, urgent but measured. Do not use markdown headings or bullet points.';
  const user = `Write the executive summary paragraph using these facts and nothing else:\n${facts}`;

  // Gemini
  if (geminiKey) {
    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${process.env.GEMINI_MODEL || 'gemini-2.5-flash'}:generateContent?key=${geminiKey}`;
      const ctrl = new AbortController(); const to = setTimeout(() => ctrl.abort(), 20000);
      const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contents: [{ role: 'user', parts: [{ text: system + '\n\n' + user }] }] }), signal: ctrl.signal });
      clearTimeout(to);
      if (res.ok) { const d: any = await res.json(); const txt = d?.candidates?.[0]?.content?.parts?.[0]?.text?.trim(); if (txt) return txt; }
    } catch { /* fall through */ }
  }
  // Anthropic
  if (anthropicKey) {
    try {
      const ctrl = new AbortController(); const to = setTimeout(() => ctrl.abort(), 20000);
      const res = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': anthropicKey, 'anthropic-version': '2023-06-01' }, body: JSON.stringify({ model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-5', max_tokens: 400, system, messages: [{ role: 'user', content: user }] }), signal: ctrl.signal });
      clearTimeout(to);
      if (res.ok) { const d: any = await res.json(); const txt = d?.content?.[0]?.text?.trim(); if (txt) return txt; }
    } catch { /* fall through */ }
  }
  return template;
};
