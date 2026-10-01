/**
 * OSCAL v1.2.2 generator (BILL-4).
 *
 * Builds a NIST OSCAL System Security Plan (SSP) and Plan of Action & Milestones
 * (POA&M) for a Project (an authorization boundary) from its cryptographic assets.
 * These are the artifacts federal PQC programs (OMB M-26-15 / DoW CIO) ask for in
 * OSCAL format, with crypto posture mapped to inheritable FISMA / SP 800-53 controls.
 *
 * This is deterministic, data-driven JSON — not a validator. It produces well-formed
 * OSCAL documents suitable for import into GRC tooling and as RFI/ATO evidence.
 */
import crypto from 'crypto';

const OSCAL_VERSION = '1.2.2';

export interface ProjectRecord {
  id: string;
  tenant_name: string;
  name: string;
  description?: string | null;
  system_id?: string | null;
  impact_level?: string | null; // low | moderate | high (FIPS 199)
}

export interface AssetRecord {
  id: string;
  type: string;
  name: string;
  algorithm: string;
  key_size?: number | null;
  hash_algorithm?: string | null;
  is_vulnerable: boolean;
  risk_level: string;        // critical | high | medium | low | secure
  status?: string | null;
  description?: string | null;
  recommendation?: string | null;
  explainer?: string | null;
  compliance_violations?: string[] | null;
  path?: string | null;
  source?: string | null;
  source_ref?: string | null;
}

const uuid = () => crypto.randomUUID();
const nowIso = () => new Date().toISOString();

// SP 800-53 crypto-relevant control families QuarkShield can speak to from a CBOM.
// Each maps to how cryptographic posture provides (or fails to provide) the objective.
const CRYPTO_CONTROLS: { id: string; title: string }[] = [
  { id: 'sc-8',  title: 'Transmission Confidentiality and Integrity' },
  { id: 'sc-12', title: 'Cryptographic Key Establishment and Management' },
  { id: 'sc-13', title: 'Cryptographic Protection' },
  { id: 'sc-17', title: 'Public Key Infrastructure Certificates' },
  { id: 'ia-5',  title: 'Authenticator Management' },
  { id: 'ia-7',  title: 'Cryptographic Module Authentication' },
  { id: 'si-2',  title: 'Flaw Remediation' },
];

const impact = (p: ProjectRecord): 'fips-199-low' | 'fips-199-moderate' | 'fips-199-high' => {
  const lvl = (p.impact_level || 'moderate').toLowerCase();
  if (lvl === 'low') return 'fips-199-low';
  if (lvl === 'high') return 'fips-199-high';
  return 'fips-199-moderate';
};

const metadata = (title: string, tenant: string) => ({
  title,
  'last-modified': nowIso(),
  version: '1.0.0',
  'oscal-version': OSCAL_VERSION,
  roles: [
    { id: 'system-owner', title: 'System Owner' },
    { id: 'tool-provider', title: 'Cryptographic Posture Tool Provider' },
  ],
  parties: [
    { uuid: uuid(), type: 'organization', name: tenant },
    { uuid: uuid(), type: 'organization', name: 'QuarkShield (FedMitigate LLC)' },
  ],
});

const systemIds = (p: ProjectRecord) => [
  { 'identifier-type': 'https://ietf.org/rfc/rfc4122', id: p.system_id || p.id },
];

/** Build the OSCAL System Security Plan for a project. */
export const buildSSP = (project: ProjectRecord, assets: AssetRecord[]): any => {
  const vulnerable = assets.filter(a => a.is_vulnerable);
  const total = assets.length;
  const imp = impact(project);

  // One OSCAL component per distinct algorithm found (the CBOM, summarized).
  const byAlgo = new Map<string, { count: number; vulnerable: number; example: AssetRecord }>();
  for (const a of assets) {
    const k = (a.algorithm || 'unknown').toUpperCase();
    const e = byAlgo.get(k) || { count: 0, vulnerable: 0, example: a };
    e.count += 1;
    if (a.is_vulnerable) e.vulnerable += 1;
    byAlgo.set(k, e);
  }
  const components = Array.from(byAlgo.entries()).map(([algo, info]) => ({
    uuid: uuid(),
    type: 'software',
    title: `Cryptographic algorithm: ${algo}`,
    description: `${info.count} instance(s) of ${algo} discovered in this boundary; ${info.vulnerable} assessed quantum-vulnerable.`,
    status: { state: 'operational' },
    props: [
      { name: 'algorithm', value: algo },
      { name: 'asset-count', value: String(info.count) },
      { name: 'quantum-vulnerable-count', value: String(info.vulnerable) },
    ],
  }));

  const implementedRequirements = CRYPTO_CONTROLS.map(ctrl => {
    const satisfied = vulnerable.length === 0;
    return {
      uuid: uuid(),
      'control-id': ctrl.id,
      props: [
        {
          name: 'implementation-status',
          value: satisfied ? 'implemented' : 'partial',
          ns: 'https://quarkshield.ai/ns/oscal',
        },
      ],
      remarks:
        `${ctrl.title}: ${total} cryptographic asset(s) in scope, ${vulnerable.length} quantum-vulnerable. ` +
        (satisfied
          ? 'No quantum-vulnerable cryptography detected for this objective.'
          : 'Quantum-vulnerable cryptography detected; see the associated POA&M for remediation toward CNSA 2.0 / NIST FIPS 203/204/205.'),
    };
  });

  return {
    'system-security-plan': {
      uuid: uuid(),
      metadata: metadata(`System Security Plan — ${project.name}`, project.tenant_name),
      'import-profile': {
        href: 'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json',
      },
      'system-characteristics': {
        'system-ids': systemIds(project),
        'system-name': project.name,
        description:
          project.description ||
          `Authorization boundary "${project.name}" for ${project.tenant_name}. Cryptographic posture and post-quantum readiness as assessed by QuarkShield.`,
        'security-sensitivity-level': imp,
        'system-information': {
          'information-types': [
            {
              uuid: uuid(),
              title: 'Cryptographic Material and Keying Data',
              description: 'Cryptographic algorithms, keys, and certificates in use within the boundary.',
              'confidentiality-impact': { base: imp },
              'integrity-impact': { base: imp },
              'availability-impact': { base: imp },
            },
          ],
        },
        'security-impact-level': {
          'security-objective-confidentiality': imp,
          'security-objective-integrity': imp,
          'security-objective-availability': imp,
        },
        status: { state: 'operational' },
        'authorization-boundary': {
          description:
            `Includes ${total} cryptographic asset(s) discovered across endpoints, code, and connected services within "${project.name}".`,
        },
      },
      'system-implementation': {
        users: [
          {
            uuid: uuid(),
            title: 'System Owner',
            'role-ids': ['system-owner'],
          },
        ],
        components:
          components.length > 0
            ? components
            : [
                {
                  uuid: uuid(),
                  type: 'software',
                  title: 'No cryptographic assets in scope',
                  description: 'No assets matched this project scope at generation time.',
                  status: { state: 'operational' },
                },
              ],
      },
      'control-implementation': {
        description:
          'Cryptographic control implementation derived from the QuarkShield cryptographic bill of materials (CBOM) for this authorization boundary.',
        'implemented-requirements': implementedRequirements,
      },
    },
  };
};

/** Build the OSCAL Plan of Action & Milestones for a project (one item per weakness). */
export const buildPOAM = (project: ProjectRecord, assets: AssetRecord[]): any => {
  const vulnerable = assets.filter(a => a.is_vulnerable);
  const MAX_ITEMS = 1000; // keep payloads bounded
  const targetDate = new Date();
  targetDate.setFullYear(2030, 11, 31); // CNSA 2.0 / M-26-15 civilian deadline

  const poamItems = vulnerable.slice(0, MAX_ITEMS).map(a => ({
    uuid: uuid(),
    title: `Quantum-vulnerable ${a.algorithm}${a.name ? ` in ${a.name}` : ''}`,
    description:
      (a.explainer || a.description || `${a.algorithm} is not quantum-resistant.`) +
      (a.path ? ` Location: ${a.path}.` : '') +
      (a.source ? ` Source: ${a.source}${a.source_ref ? ` (${a.source_ref})` : ''}.` : ''),
    props: [
      { name: 'severity', value: (a.risk_level || 'medium').toLowerCase(), ns: 'https://quarkshield.ai/ns/oscal' },
      { name: 'algorithm', value: a.algorithm || 'unknown', ns: 'https://quarkshield.ai/ns/oscal' },
      ...(a.key_size ? [{ name: 'key-size', value: String(a.key_size), ns: 'https://quarkshield.ai/ns/oscal' }] : []),
      { name: 'target-completion-date', value: targetDate.toISOString().slice(0, 10), ns: 'https://quarkshield.ai/ns/oscal' },
    ],
    remarks:
      (a.recommendation || 'Migrate to a NIST-standardized post-quantum algorithm (FIPS 203 ML-KEM / FIPS 204 ML-DSA / FIPS 205 SLH-DSA).') +
      (a.compliance_violations && a.compliance_violations.length
        ? ` Violates: ${a.compliance_violations.join(', ')}.`
        : ''),
  }));

  return {
    'plan-of-action-and-milestones': {
      uuid: uuid(),
      metadata: metadata(`Plan of Action & Milestones — ${project.name}`, project.tenant_name),
      'system-id': systemIds(project)[0],
      'local-definitions': {
        remarks: `Generated by QuarkShield from ${assets.length} assessed cryptographic asset(s); ${vulnerable.length} quantum-vulnerable.`,
      },
      'poam-items':
        poamItems.length > 0
          ? poamItems
          : [
              {
                uuid: uuid(),
                title: 'No open quantum-cryptography weaknesses',
                description: 'No quantum-vulnerable cryptographic assets were found in this authorization boundary at generation time.',
              },
            ],
    },
  };
};
