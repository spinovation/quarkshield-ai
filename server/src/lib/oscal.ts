/**
 * OSCAL v1.2.2 generator (BILL-4 / BILL-4b).
 *
 * Builds a NIST OSCAL System Security Plan (SSP) and Plan of Action & Milestones
 * (POA&M) for a Project (an authorization boundary assessed against a NIST framework).
 * Control-driven: the SSP's implemented-requirements and the POA&M items come from the
 * project's per-control assessment rows (status, owner, remediation), with the tenant's
 * cryptographic posture (CBOM) as supporting evidence.
 */
import crypto from 'crypto';
import { Framework, FRAMEWORKS } from './controlCatalog';

const OSCAL_VERSION = '1.2.2';
const uuid = () => crypto.randomUUID();
const nowIso = () => new Date().toISOString();

export interface ProjectRecord {
  id: string;
  tenant_name: string;
  name: string;
  description?: string | null;
  system_id?: string | null;
  impact_level?: string | null;
  framework?: string | null;
}

export interface ControlRow {
  control_key: string;
  control_id: string;
  title: string;
  kind?: string | null;
  status: string;          // compliant | non_compliant | in_progress | not_applicable
  owner?: string | null;
  percent_complete?: number | null;
  target_date?: string | null;
  comments?: string | null;
  fips?: string;           // joined from catalog for the statement text
  implicit?: boolean;
}

export interface Posture {
  total: number;
  vulnerable: number;
  byAlgo?: { algo: string; count: number; vulnerable: number }[];
}

const frameworkLabel = (fw?: string | null): string =>
  FRAMEWORKS.find(f => f.id === fw)?.label || 'NIST SP 800-53 Rev 5';

const impact = (p: ProjectRecord): 'fips-199-low' | 'fips-199-moderate' | 'fips-199-high' => {
  const lvl = (p.impact_level || 'moderate').toLowerCase();
  if (lvl === 'low') return 'fips-199-low';
  if (lvl === 'high') return 'fips-199-high';
  return 'fips-199-moderate';
};

// OSCAL implementation-status per our control status.
const implStatus = (status: string): string => {
  switch (status) {
    case 'compliant': return 'implemented';
    case 'non_compliant': return 'planned';
    case 'not_applicable': return 'not-applicable';
    default: return 'partial'; // in_progress
  }
};

const metadata = (title: string, tenant: string, fw?: string | null) => ({
  title,
  'last-modified': nowIso(),
  version: '1.0.0',
  'oscal-version': OSCAL_VERSION,
  props: [{ name: 'framework', value: frameworkLabel(fw), ns: 'https://quarkshield.ai/ns/oscal' }],
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

const profileHref = (fw?: string | null): string => {
  if (fw === 'nist-800-171r2' || fw === 'nist-800-171r3') {
    return 'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-171/rev2/json/NIST_SP-800-171_rev2_catalog.json';
  }
  return 'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json';
};

export const buildSSP = (project: ProjectRecord, controls: ControlRow[], posture: Posture): any => {
  const imp = impact(project);
  const components = (posture.byAlgo || []).map(a => ({
    uuid: uuid(),
    type: 'software',
    title: `Cryptographic algorithm: ${a.algo}`,
    description: `${a.count} instance(s); ${a.vulnerable} quantum-vulnerable.`,
    status: { state: 'operational' },
    props: [
      { name: 'algorithm', value: a.algo },
      { name: 'asset-count', value: String(a.count) },
      { name: 'quantum-vulnerable-count', value: String(a.vulnerable) },
    ],
  }));

  const implementedRequirements = controls.map(c => ({
    uuid: uuid(),
    'control-id': (c.control_id || c.control_key).toLowerCase(),
    props: [
      { name: 'implementation-status', value: implStatus(c.status), ns: 'https://quarkshield.ai/ns/oscal' },
      { name: 'control-ref', value: c.control_id, ns: 'https://quarkshield.ai/ns/oscal' },
      ...(c.owner ? [{ name: 'responsible-party', value: c.owner, ns: 'https://quarkshield.ai/ns/oscal' }] : []),
      ...(typeof c.percent_complete === 'number' ? [{ name: 'percent-complete', value: String(c.percent_complete), ns: 'https://quarkshield.ai/ns/oscal' }] : []),
    ],
    remarks:
      `${c.title} (${c.control_id}). Status: ${c.status.replace('_', ' ')}. ` +
      (c.fips ? `${c.fips} ` : '') +
      (c.comments ? `Notes: ${c.comments} ` : '') +
      `Cryptographic posture in scope: ${posture.total} asset(s), ${posture.vulnerable} quantum-vulnerable.`,
  }));

  return {
    'system-security-plan': {
      uuid: uuid(),
      metadata: metadata(`System Security Plan — ${project.name} (${frameworkLabel(project.framework)})`, project.tenant_name, project.framework),
      'import-profile': { href: profileHref(project.framework) },
      'system-characteristics': {
        'system-ids': systemIds(project),
        'system-name': project.name,
        description:
          project.description ||
          `Authorization boundary "${project.name}" for ${project.tenant_name}, assessed against ${frameworkLabel(project.framework)} for post-quantum cryptographic readiness.`,
        'security-sensitivity-level': imp,
        'system-information': {
          'information-types': [{
            uuid: uuid(),
            title: 'Cryptographic Material and Keying Data',
            description: 'Cryptographic algorithms, keys, and certificates in use within the boundary.',
            'confidentiality-impact': { base: imp },
            'integrity-impact': { base: imp },
            'availability-impact': { base: imp },
          }],
        },
        'security-impact-level': {
          'security-objective-confidentiality': imp,
          'security-objective-integrity': imp,
          'security-objective-availability': imp,
        },
        status: { state: 'operational' },
        'authorization-boundary': {
          description: `Includes ${posture.total} cryptographic asset(s) discovered across endpoints, code, and connected services within "${project.name}".`,
        },
      },
      'system-implementation': {
        users: [{ uuid: uuid(), title: 'System Owner', 'role-ids': ['system-owner'] }],
        components: components.length > 0 ? components : [{
          uuid: uuid(), type: 'software', title: 'No cryptographic assets in scope',
          description: 'No assets matched this project scope at generation time.', status: { state: 'operational' },
        }],
      },
      'control-implementation': {
        description: `Cryptographic control implementation for ${frameworkLabel(project.framework)}, derived from the QuarkShield CBOM and per-control assessment for this authorization boundary.`,
        'implemented-requirements': implementedRequirements,
      },
    },
  };
};

export const buildPOAM = (project: ProjectRecord, controls: ControlRow[], posture: Posture): any => {
  const open = controls.filter(c => c.status === 'non_compliant' || c.status === 'in_progress');
  const poamItems = open.map(c => ({
    uuid: uuid(),
    title: `${c.control_id} — ${c.title}`,
    description:
      `Control ${c.control_id} (${c.title}) is ${c.status.replace('_', ' ')}. ` +
      `${posture.vulnerable} quantum-vulnerable asset(s) in scope. ${c.fips || ''}`.trim(),
    props: [
      { name: 'severity', value: c.status === 'non_compliant' ? 'high' : 'medium', ns: 'https://quarkshield.ai/ns/oscal' },
      { name: 'control-ref', value: c.control_id, ns: 'https://quarkshield.ai/ns/oscal' },
      ...(c.owner ? [{ name: 'responsible-party', value: c.owner, ns: 'https://quarkshield.ai/ns/oscal' }] : []),
      ...(typeof c.percent_complete === 'number' ? [{ name: 'percent-complete', value: String(c.percent_complete), ns: 'https://quarkshield.ai/ns/oscal' }] : []),
      ...(c.target_date ? [{ name: 'target-completion-date', value: String(c.target_date).slice(0, 10), ns: 'https://quarkshield.ai/ns/oscal' }] : []),
    ],
    remarks: c.comments || 'Migrate affected cryptography to NIST-standardized post-quantum algorithms (FIPS 203 ML-KEM / FIPS 204 ML-DSA / FIPS 205 SLH-DSA).',
  }));

  return {
    'plan-of-action-and-milestones': {
      uuid: uuid(),
      metadata: metadata(`Plan of Action & Milestones — ${project.name} (${frameworkLabel(project.framework)})`, project.tenant_name, project.framework),
      'system-id': systemIds(project)[0],
      'local-definitions': {
        remarks: `${open.length} open control item(s) of ${controls.length} assessed; ${posture.vulnerable} quantum-vulnerable asset(s) in scope.`,
      },
      'poam-items': poamItems.length > 0 ? poamItems : [{
        uuid: uuid(),
        title: 'No open control items',
        description: 'All assessed cryptographic controls are compliant or not applicable for this authorization boundary.',
      }],
    },
  };
};
