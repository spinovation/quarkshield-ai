/**
 * FIPS / CMVP compliance evidence export
 * (docs/CMVP_AND_FIPS_COMPLIANCE_MAPPING.md §6.4, Stage 5).
 *
 * One row per asset: the algorithm verdict, the module (if one was observed), how the module
 * was matched, the FIPS-mode evidence, and the resulting verdict. Stamped with the versions
 * of both reference tables. It is evidence for a reviewer to read, not a certification:
 * the header says so, and nothing is filled in where nothing was observed.
 */
import { fipsAlgorithmStatus, FIPS_TABLE_VERSION } from './fipsAlgorithmStatus';
import { CMVP_MAP_VERSION, nistCertificateUrl } from './cmvpModules';
import { resolveAssetModule, isHostResolution } from './hostCryptoModules';
import { complianceVerdict, ComplianceVerdict, emptyVerdictCounts } from './complianceVerdict';

export interface AttestationAssetRow {
  id: string; name: string; type?: string | null; hostname?: string | null; path?: string | null;
  algorithm?: string | null; key_size?: number | null; hash_algorithm?: string | null; purpose?: string | null;
  crypto_module?: string | null; crypto_module_evidence?: string | null; crypto_module_detail?: unknown;
}

export interface AssetCompliance {
  verdict: ComplianceVerdict;
  fipsStatus: string; fipsStandard: string; fipsRuleId: string; fipsDisallowedAfter?: string; fipsDraft: boolean;
  cmvpStatus: string;
  moduleName?: string; moduleVersion?: string; environment?: string;
  certIds: string[]; cmvpStandard?: string; cmvpLevel?: number; cmvpSunsetDate?: string;
  basis?: 'provider-reported' | 'host-observed';
  candidateCertId?: string; candidateMatch?: string;
  fipsMode?: string; fipsModeEvidence?: string;
  note?: string;
}

/** The one place an asset's two axes are combined. Console, CBOM and the export all use it. */
export const assessAsset = (a: AttestationAssetRow): AssetCompliance => {
  const f = fipsAlgorithmStatus({ algorithm: a.algorithm || '', key_size: a.key_size, hash_algorithm: a.hash_algorithm, purpose: a.purpose, type: a.type });
  const m = resolveAssetModule(a.crypto_module, a.crypto_module_detail);
  const host = isHostResolution(m) ? m : undefined;
  return {
    verdict: complianceVerdict(f.status, m.status),
    fipsStatus: f.status, fipsStandard: f.standard, fipsRuleId: f.ruleId, fipsDisallowedAfter: f.disallowedAfter, fipsDraft: f.draft,
    cmvpStatus: m.status,
    moduleName: m.moduleName, moduleVersion: host?.moduleVersion, environment: host?.environment,
    certIds: m.certIds, cmvpStandard: m.standard, cmvpLevel: m.level, cmvpSunsetDate: m.sunsetDate,
    basis: m.moduleKey ? (host ? 'host-observed' : 'provider-reported') : undefined,
    candidateCertId: host?.candidate?.certId, candidateMatch: host?.candidate?.match,
    fipsMode: host?.fipsMode?.state, fipsModeEvidence: host?.fipsMode?.evidence,
    note: m.note,
  };
};

// A cell that a spreadsheet would run as a formula is neutralised; quotes are doubled.
const cell = (v: unknown): string => {
  let s = v === undefined || v === null ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

export const ATTESTATION_COLUMNS = [
  'Asset', 'Type', 'Host', 'Path', 'Algorithm', 'Key size',
  'FIPS algorithm status', 'Governing standard', 'Rule', 'Disallowed after', 'Draft guidance',
  'Module', 'Module version', 'Operating environment', 'Module basis',
  'CMVP status', 'CMVP certificate', 'Certificate URL', 'Standard / level', 'Certificate sunset',
  'Candidate certificate', 'Candidate match', 'FIPS mode', 'FIPS mode evidence', 'Module evidence',
  'Verdict', 'Note',
] as const;

export interface AttestationExport { csv: string; counts: Record<ComplianceVerdict, number>; total: number }

export const buildAttestationCsv = (tenant: string, assets: AttestationAssetRow[], generatedAt: Date = new Date()): AttestationExport => {
  const counts = emptyVerdictCounts();
  const lines: string[] = [];
  const meta = (k: string, v: string) => lines.push(`${cell(`# ${k}`)},${cell(v)}`);
  meta('Report', 'QuarkShield FIPS / CMVP compliance evidence');
  meta('Tenant', tenant);
  meta('Generated', generatedAt.toISOString());
  meta('FIPS algorithm table', FIPS_TABLE_VERSION);
  meta('CMVP module map', CMVP_MAP_VERSION);
  meta('Reading this report', 'Evidence as observed by QuarkShield, not a certification. "compliant" means an approved algorithm paired with a module whose current CMVP certificate was matched: for a cloud key the provider-published certificate, for a host an exact identity match with FIPS-approved mode confirmed from host facts. QuarkShield did not test any module. A blank cell means nothing was observed.');
  lines.push(ATTESTATION_COLUMNS.map(cell).join(','));
  for (const a of assets) {
    const c = assessAsset(a);
    counts[c.verdict]++;
    lines.push([
      a.name, a.type, a.hostname, a.path, a.algorithm, a.key_size || '',
      c.fipsStatus, c.fipsStandard === '—' ? '' : c.fipsStandard, c.fipsRuleId, c.fipsDisallowedAfter, c.fipsDraft ? 'yes' : '',
      c.moduleName, c.moduleVersion, c.environment, c.basis,
      c.cmvpStatus, c.certIds.map(id => `#${id}`).join(' '), c.certIds.map(nistCertificateUrl).join(' '),
      c.certIds.length && c.cmvpStandard ? `${c.cmvpStandard}${c.cmvpLevel ? ` Level ${c.cmvpLevel}` : ''}` : '', c.certIds.length ? c.cmvpSunsetDate : '',
      c.candidateCertId ? `#${c.candidateCertId}` : '', c.candidateMatch, c.fipsMode, c.fipsModeEvidence, a.crypto_module_evidence,
      c.verdict, c.note,
    ].map(cell).join(','));
  }
  return { csv: lines.join('\r\n') + '\r\n', counts, total: assets.length };
};
