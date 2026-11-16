/**
 * CMVP module axis on hosts: module identity
 * (docs/CMVP_AND_FIPS_COMPLIANCE_MAPPING.md, Stage 4, prerequisite P-a).
 *
 * The agent reports which cryptographic modules are on a host: name, exact version and
 * operating environment, each with the command or file the fact was read from. This file
 * holds the reference data those identities are compared against, and the comparison.
 *
 * What Stage 4 can and cannot say (non-negotiable):
 *  - Identity is not validation. A host module NEVER resolves to `active`, `historical` or
 *    `revoked` here. The most it gets is a CANDIDATE certificate: "this module's identity
 *    matches what certificate #N was issued for".
 *  - Whether the module actually runs in its FIPS-approved mode is not known at this stage
 *    (Stage 5). Every candidate says so.
 *  - A candidate states how close the match is. `exact`: module version and operating
 *    system release are both as tested. `release`: same operating system release, but this
 *    host's build is not the tested build. `version`: same module version, operating system
 *    or CPU architecture not on the tested list. The hardware model is never compared.
 *  - No row, no candidate. Nothing is guessed from a family name or a near version.
 *
 * Every certificate row was read from its NIST certificate page (and, where the page omits
 * versions, the NIST-hosted Security Policy) on the CMVP_MAP_VERSION date.
 */
import { CMVP_MAP_VERSION, CmvpCertificate, CmvpResolution, resolveCmvpModule } from './cmvpModules';

// ---- What the agent sends ---------------------------------------------------

export interface OperatingEnvironment { id: string; name?: string; version?: string; arch?: string }
export interface FipsProviderIdentity { present: 'yes' | 'no' | 'unknown'; name?: string; version?: string; path?: string }
export interface HostModule {
  ref: string;
  key: string;
  name: string;
  version?: string;
  fipsProvider?: FipsProviderIdentity;
  evidence?: string;
}
export interface HostModuleReport { environment: OperatingEnvironment; modules: HostModule[] }
/** Stored per asset (assets.crypto_module_detail): the module plus the environment it ran on. */
export interface HostModuleDetail extends Omit<HostModule, 'ref'> { environment: OperatingEnvironment }

const MAX_MODULES = 24;
const str = (v: unknown, max: number): string | undefined => {
  if (typeof v !== 'string') return undefined;
  // Printable text only: these strings are shown in the console and exported.
  const s = v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
  return s || undefined;
};

/**
 * Validate the agent's module report. The agent is not trusted: unknown shapes are dropped,
 * strings are bounded, and anything that is not plain identity text is ignored.
 */
export const sanitizeHostModuleReport = (raw: unknown): HostModuleReport | null => {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as any;
  const e = r.environment && typeof r.environment === 'object' ? r.environment : {};
  const environment: OperatingEnvironment = {
    id: (str(e.id, 40) || 'unknown').toLowerCase(),
    name: str(e.name, 160),
    version: str(e.version, 60),
    arch: str(e.arch, 20),
  };
  const modules: HostModule[] = [];
  const seen = new Set<string>();
  for (const m of Array.isArray(r.modules) ? r.modules.slice(0, MAX_MODULES) : []) {
    if (!m || typeof m !== 'object') continue;
    const ref = str(m.ref, 120);
    const key = str(m.key, 60);
    if (!ref || !key || !/^[a-z0-9-]+$/.test(key) || seen.has(ref)) continue;
    seen.add(ref);
    const mod: HostModule = { ref, key, name: str(m.name, 160) || key, version: str(m.version, 80), evidence: str(m.evidence, 400) };
    const fp = m.fipsProvider;
    if (fp && typeof fp === 'object' && ['yes', 'no', 'unknown'].includes(fp.present)) {
      mod.fipsProvider = { present: fp.present, name: str(fp.name, 160), version: str(fp.version, 80), path: str(fp.path, 260) };
    }
    modules.push(mod);
  }
  return { environment, modules };
};

/** The module a finding points at, joined with the host's environment. Null when the reference is unknown. */
export const moduleDetailFor = (report: HostModuleReport | null, ref: unknown): HostModuleDetail | null => {
  if (!report || typeof ref !== 'string' || !ref) return null;
  const m = report.modules.find(x => x.ref === ref);
  if (!m) return null;
  const { ref: _ref, ...rest } = m;
  return { ...rest, environment: report.environment };
};

// ---- Reference data ---------------------------------------------------------

export type CandidateMatch = 'exact' | 'release' | 'version';

export interface HostValidation extends CmvpCertificate {
  moduleKey: string;
  /** Module version strings exactly as NIST shows them. Equality with one of these is what `exact` and `version` mean. */
  versions: string[];
  /** For OpenSSL: the FIPS provider's self-reported name must equal this. */
  providerName?: string;
  /** Operating systems the certificate was tested on: os id + version prefix ("9" matches 9 and 9.4; "10.0.22621" matches that build line). */
  testedOn: { osId: string; versionPrefix: string }[];
  /** CPU architecture (Go GOARCH) when the certificate is for one CPU family only (Apple). */
  arch?: string;
  /** CPU architectures among the tested configurations, when the certificate lists them. A host
   *  on another architecture can match on version only. */
  testedArchs?: string[];
}

const MS = 'Microsoft Corporation';
const APPLE = 'Apple Inc.';
const CNG = 'Cryptographic Primitives Library';
const win = (...builds: string[]) => builds.map(b => ({ osId: 'windows', versionPrefix: b }));
const mac = (major: string) => [{ osId: 'macos', versionPrefix: major }];

export const HOST_VALIDATIONS: HostValidation[] = [
  // --- Microsoft Windows: Cryptographic Primitives Library (bcryptprimitives.dll) ---
  // Validated per Windows build. Builds with no row (Windows 10 21H2/22H2, Windows 11
  // 23H2/24H2, Server 2025 on the map date) have no certificate and get no candidate.
  { moduleKey: 'windows-cng', certId: '5410', moduleName: CNG, vendor: MS, standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2031-08-30',
    versions: ['10.0.22621.30001', '10.0.20348.30000'], testedOn: win('10.0.22621', '10.0.20348') },
  { moduleKey: 'windows-cng', certId: '4825', moduleName: CNG, vendor: MS, standard: 'FIPS 140-2', level: 1, status: 'historical',
    versions: ['10.0.19042', '10.0.19043', '10.0.20348', '10.0.22000'], testedOn: win('10.0.19042', '10.0.19043', '10.0.20348', '10.0.22000') },
  { moduleKey: 'windows-cng', certId: '4536', moduleName: CNG, vendor: MS, standard: 'FIPS 140-2', level: 1, status: 'historical',
    versions: ['10.0.18362', '10.0.18363', '10.0.19041'], testedOn: win('10.0.18362', '10.0.18363', '10.0.19041') },
  { moduleKey: 'windows-cng', certId: '3197', moduleName: CNG, vendor: MS, standard: 'FIPS 140-2', level: 1, status: 'historical',
    versions: ['10.0.15063.674', '10.0.15254', '10.0.16299', '10.0.17134', '10.0.17763'], testedOn: win('10.0.15063', '10.0.15254', '10.0.16299', '10.0.17134', '10.0.17763') },

  // --- Apple corecrypto, user space, macOS. One module per macOS release and CPU family. ---
  { moduleKey: 'apple-corecrypto', certId: '5184', moduleName: 'Apple corecrypto Module 18.3 [Apple silicon, User, Software, SL1]', vendor: APPLE, standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2031-03-10',
    versions: ['18.3'], testedOn: mac('15'), arch: 'arm64' },
  { moduleKey: 'apple-corecrypto', certId: '5217', moduleName: 'Apple corecrypto Module v18.3 [Intel, User, Software, SL1]', vendor: APPLE, standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2031-03-29',
    versions: ['18.3'], testedOn: mac('15'), arch: 'amd64' },
  { moduleKey: 'apple-corecrypto', certId: '5216', moduleName: 'Apple corecrypto Module v14.0 [Apple silicon, User, Software, SL1]', vendor: APPLE, standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2031-03-29',
    versions: ['14.0'], testedOn: mac('14'), arch: 'arm64' },
  { moduleKey: 'apple-corecrypto', certId: '5201', moduleName: 'Apple corecrypto Module v14.0 [Intel, User, Software, SL1]', vendor: APPLE, standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2031-03-18',
    versions: ['14.0'], testedOn: mac('14'), arch: 'amd64' },
  { moduleKey: 'apple-corecrypto', certId: '5065', moduleName: 'Apple corecrypto Module v13.0 [Apple silicon, User, Software, SL1]', vendor: APPLE, standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2030-09-21',
    versions: ['13.0'], testedOn: mac('13'), arch: 'arm64' },
  { moduleKey: 'apple-corecrypto', certId: '5348', moduleName: 'Apple corecrypto Module v13.0 [Intel, User, Software, SL1]', vendor: APPLE, standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2030-01-22',
    versions: ['13.0'], testedOn: mac('13'), arch: 'amd64' },
  { moduleKey: 'apple-corecrypto', certId: '4951', moduleName: 'Apple corecrypto Module v12 [Intel, User, Software]', vendor: APPLE, standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2027-01-26',
    versions: ['12'], testedOn: mac('12'), arch: 'amd64' },
  { moduleKey: 'apple-corecrypto', certId: '4817', moduleName: 'Apple corecrypto Module v12.0 [Apple silicon, User, Software, SL1]', vendor: APPLE, standard: 'FIPS 140-3', level: 1, status: 'historical',
    versions: ['12.0'], testedOn: mac('12'), arch: 'arm64' },

  // --- OpenSSL 3 FIPS provider modules, identified by the name and version the provider
  // itself reports (`openssl list -providers`). Only rows whose runtime name and version
  // string are documented (NIST page or Security Policy) are listed. Not listed, because the
  // module version is not what the provider reports at run time: RHEL 8, Ubuntu 20.04, SUSE.
  { moduleKey: 'openssl', certId: '5586', moduleName: 'OpenSSL FIPS Provider', vendor: 'The OpenSSL Corporation', standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2031-11-12',
    providerName: 'OpenSSL FIPS Provider', versions: ['3.5.9'], testedOn: [{ osId: 'ubuntu', versionPrefix: '22.04' }, { osId: 'ubuntu', versionPrefix: '24.04' }, { osId: 'debian', versionPrefix: '11' }, { osId: 'debian', versionPrefix: '12' }] , testedArchs: ['amd64'] },
  { moduleKey: 'openssl', certId: '4985', moduleName: 'OpenSSL FIPS Provider', vendor: 'The OpenSSL Project', standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2030-03-10',
    providerName: 'OpenSSL FIPS Provider', versions: ['3.1.2'], testedOn: [{ osId: 'ubuntu', versionPrefix: '22.04' }, { osId: 'debian', versionPrefix: '11' }] , testedArchs: ['amd64'] },
  { moduleKey: 'openssl', certId: '4811', moduleName: 'OpenSSL FIPS Provider', vendor: 'The OpenSSL Project', standard: 'FIPS 140-2', level: 1, status: 'historical',
    providerName: 'OpenSSL FIPS Provider', versions: ['3.0.8', '3.0.9'], testedOn: [{ osId: 'ubuntu', versionPrefix: '22.04' }, { osId: 'debian', versionPrefix: '11' }] , testedArchs: ['amd64'] },
  { moduleKey: 'openssl', certId: '5573', moduleName: 'Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider', vendor: 'Red Hat, Inc.', standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2029-10-28',
    providerName: 'Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider', versions: ['3.0.7-cda111b5812c30d4'], testedOn: [{ osId: 'rhel', versionPrefix: '9' }] , testedArchs: ['amd64', 's390x', 'ppc64le'] },
  { moduleKey: 'openssl', certId: '4857', moduleName: 'Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider', vendor: 'Red Hat, Inc.', standard: 'FIPS 140-3', level: 1, status: 'historical',
    providerName: 'Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider', versions: ['3.0.7-395c1a240fbfffd8'], testedOn: [{ osId: 'rhel', versionPrefix: '9' }] , testedArchs: ['amd64', 's390x', 'ppc64le'] },
  { moduleKey: 'openssl', certId: '4746', moduleName: 'Red Hat Enterprise Linux 9 OpenSSL FIPS Provider', vendor: 'Red Hat, Inc.', standard: 'FIPS 140-3', level: 1, status: 'historical',
    providerName: 'Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider', versions: ['3.0.1-3f45e68ee408cd9c'], testedOn: [{ osId: 'rhel', versionPrefix: '9' }] , testedArchs: ['amd64', 's390x', 'ppc64le'] },
  { moduleKey: 'openssl', certId: '4794', moduleName: 'Canonical Ltd. Ubuntu 22.04 OpenSSL Cryptographic Module', vendor: 'Canonical Ltd.', standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2029-09-10',
    providerName: 'Ubuntu 22.04 OpenSSL Cryptographic Module', versions: ['3.0.5-0ubuntu0.1+Fips2.1'], testedOn: [{ osId: 'ubuntu', versionPrefix: '22.04' }] , testedArchs: ['amd64', 'arm64', 's390x'] },
  { moduleKey: 'openssl', certId: '5115', moduleName: 'Canonical Ltd. Ubuntu 24.04 OpenSSL Cryptographic Module', vendor: 'Canonical Ltd.', standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2031-01-05',
    providerName: 'Ubuntu 24.04 OpenSSL Cryptographic Module', versions: ['3.0.13-0ubuntu3+Fips1'], testedOn: [{ osId: 'ubuntu', versionPrefix: '24.04' }] , testedArchs: ['amd64', 'arm64', 's390x'] },
  { moduleKey: 'openssl', certId: '5438', moduleName: 'Amazon Linux 2023 OpenSSL FIPS Provider', vendor: 'Amazon Web Services, Inc.', standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2031-07-26',
    providerName: 'Amazon Linux 2023 - OpenSSL FIPS Provider', versions: ['3.2.2-799901ad7ab41d45'], testedOn: [{ osId: 'amzn', versionPrefix: '2023' }] , testedArchs: ['amd64', 'arm64'] },
  { moduleKey: 'openssl', certId: '5021', moduleName: 'Amazon Linux 2023 OpenSSL FIPS Provider', vendor: 'Amazon Web Services, Inc.', standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2030-05-25',
    providerName: 'Amazon Linux 2023 - OpenSSL FIPS Provider', versions: ['3.0.8-d694bfa693b76001'], testedOn: [{ osId: 'amzn', versionPrefix: '2023' }] , testedArchs: ['amd64', 'arm64'] },
  { moduleKey: 'openssl', certId: '5294', moduleName: 'Oracle Linux 9 OpenSSL FIPS Provider', vendor: 'Oracle Corporation', standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2029-08-24',
    providerName: 'Oracle Linux 9 OpenSSL FIPS Provider', versions: ['3.0.7-b27cdeb3ba51be46'], testedOn: [{ osId: 'ol', versionPrefix: '9' }] , testedArchs: ['amd64', 'arm64', 'mips64'] },
];

/** Module families this map knows, with what to say when no certificate row matches. */
const FAMILIES: Record<string, { label: string; vendor?: string; noMatch: string }> = {
  'windows-cng': { label: 'Windows Cryptographic Primitives Library', vendor: MS, noMatch: 'No certificate for this Windows build is recorded in the map.' },
  'apple-corecrypto': { label: 'Apple corecrypto', vendor: APPLE, noMatch: 'No certificate for this macOS release is recorded in the map.' },
  'openssl': { label: 'OpenSSL', noMatch: 'No certificate for this FIPS provider version is recorded in the map.' },
  'libressl': { label: 'LibreSSL', noMatch: 'No CMVP certificate for LibreSSL is recorded in the map.' },
};

// ---- Resolution -------------------------------------------------------------

export interface ModuleCandidate {
  certId: string;
  /** Module name exactly as on the NIST certificate. */
  moduleName: string;
  vendor: string;
  standard: 'FIPS 140-2' | 'FIPS 140-3';
  level: number;
  /** Status of the CERTIFICATE on NIST. Not the status of this host. */
  certStatus: 'active' | 'historical' | 'revoked';
  sunsetDate?: string;
  match: CandidateMatch;
  /** One sentence: what matched and what did not. */
  matchNote: string;
}

export interface HostModuleResolution extends CmvpResolution {
  basis: 'host-observed';
  status: 'unverified' | 'none';
  moduleVersion?: string;
  environment?: string;
  candidate?: ModuleCandidate;
}

const prefixMatches = (value: string | undefined, prefix: string): boolean =>
  !!value && (value === prefix || value.startsWith(prefix + '.'));

const describeEnvironment = (e?: OperatingEnvironment): string | undefined => {
  if (!e) return undefined;
  const os = e.name || [e.id, e.version].filter(Boolean).join(' ');
  return [os, e.arch].filter(Boolean).join(' / ') || undefined;
};

const MATCH_RANK: CandidateMatch[] = ['exact', 'release', 'version'];
const STATUS_RANK = ['active', 'historical', 'revoked'];
const MODE_CAVEAT = 'Whether it runs in FIPS-approved mode was not checked.';

const candidateFor = (d: HostModuleDetail): ModuleCandidate | undefined => {
  const env = d.environment || { id: 'unknown' };
  const found: ModuleCandidate[] = [];
  for (const v of HOST_VALIDATIONS) {
    if (v.moduleKey !== d.key) continue;
    if (v.arch && v.arch !== env.arch) continue;
    const osTested = v.testedOn.some(t => t.osId === env.id && prefixMatches(env.version, t.versionPrefix))
      && (!v.testedArchs || (!!env.arch && v.testedArchs.includes(env.arch)));
    let match: CandidateMatch | null = null;
    let matchNote = '';
    if (d.key === 'openssl') {
      // The validated module is the FIPS provider, identified by its own name and version.
      const fp = d.fipsProvider;
      if (!fp || fp.present !== 'yes' || !fp.version || !v.versions.includes(fp.version)) continue;
      if (v.providerName && v.providerName !== fp.name) continue;
      match = osTested ? 'exact' : 'version';
      matchNote = osTested
        ? `The installed FIPS provider (${fp.version}), the operating system release and the CPU architecture are as tested for this certificate.`
        : `The installed FIPS provider version (${fp.version}) is the one on this certificate, but this operating system or CPU architecture is not on its tested list.`;
    } else {
      // Operating-system modules: the OS release identifies the module.
      if (!osTested) continue;
      if (d.key === 'apple-corecrypto') {
        // corecrypto has no version readable on the host; the macOS release stands in for it.
        match = 'release';
        matchNote = `Apple validates one corecrypto module per macOS release; this host runs macOS ${d.version || 'unknown'} and the certificate covers that release. The module's own version (${v.versions.join(', ')} on the certificate) cannot be read from the host.`;
      } else {
        const exact = !!d.version && v.versions.includes(d.version);
        match = exact ? 'exact' : 'release';
        matchNote = exact
          ? `This host's build (${d.version}) is the build tested for this certificate.`
          : `Same operating system release as this certificate, but this host's build (${d.version || 'unknown'}) is not the tested build (${v.versions.join(', ')}).`;
      }
    }
    found.push({ certId: v.certId, moduleName: v.moduleName, vendor: v.vendor, standard: v.standard, level: v.level, certStatus: v.status, sunsetDate: v.sunsetDate, match, matchNote });
  }
  // Closest match first; between equal matches, a current certificate before a superseded one.
  found.sort((a, b) => MATCH_RANK.indexOf(a.match) - MATCH_RANK.indexOf(b.match) || STATUS_RANK.indexOf(a.certStatus) - STATUS_RANK.indexOf(b.certStatus));
  return found[0];
};

export const resolveHostModule = (detail: HostModuleDetail): HostModuleResolution => {
  const family = Object.prototype.hasOwnProperty.call(FAMILIES, detail.key) ? FAMILIES[detail.key] : undefined;
  const fp = detail.fipsProvider;
  const providerNamed = detail.key === 'openssl' && fp?.present === 'yes' && fp.name;
  const base = {
    basis: 'host-observed' as const,
    moduleKey: detail.key,
    moduleName: providerNamed ? String(fp!.name) : (detail.name || family?.label || detail.key),
    moduleVersion: providerNamed ? fp!.version : detail.version,
    vendor: family?.vendor,
    environment: describeEnvironment(detail.environment),
    certIds: [] as string[],
    mapVersion: CMVP_MAP_VERSION,
  };
  if (!family) return { ...base, status: 'unverified', note: 'This module is not in the CMVP map version in use.' };

  if (detail.key === 'openssl' && /^3\./.test(detail.version || '') && fp?.present === 'no') {
    // The only CMVP-validated part of OpenSSL 3 is its FIPS provider module.
    return { ...base, status: 'none', note: 'No FIPS provider module is installed beside this OpenSSL. In OpenSSL 3 only the FIPS provider is a validated module.' };
  }
  const candidate = candidateFor(detail);
  if (!candidate) {
    const why = detail.key === 'openssl' && fp?.present !== 'yes'
      ? 'Whether a FIPS provider module is installed could not be determined.'
      : family.noMatch;
    return { ...base, status: 'unverified', note: why };
  }
  return {
    ...base,
    status: 'unverified',
    candidate,
    standard: undefined,
    note: `Candidate only, from the module's identity. ${candidate.matchNote} ${MODE_CAVEAT}`,
  };
};

/** One resolver for both kinds of asset: host modules carry a detail record, connector modules do not. */
export const resolveAssetModule = (moduleKey?: string | null, detail?: unknown): CmvpResolution | HostModuleResolution => {
  const d = parseDetail(detail);
  if (d && moduleKey) return resolveHostModule({ ...d, key: String(moduleKey) });
  return resolveCmvpModule(moduleKey);
};

const parseDetail = (detail: unknown): HostModuleDetail | null => {
  let d: any = detail;
  if (typeof d === 'string') { try { d = JSON.parse(d); } catch { return null; } }
  if (!d || typeof d !== 'object' || typeof d.environment !== 'object' || !d.environment) return null;
  return d as HostModuleDetail;
};

export const isHostResolution = (r: CmvpResolution | HostModuleResolution): r is HostModuleResolution =>
  (r as HostModuleResolution).basis === 'host-observed';

/** Shape the console API returns per asset. Extends the Stage 3 shape; a host module never carries certIds. */
export const moduleForConsole = (moduleKey: string, evidence?: string | null, detail?: unknown) => {
  const r = resolveAssetModule(moduleKey, detail);
  const host = isHostResolution(r) ? r : undefined;
  const d = host ? parseDetail(detail) : null;
  return {
    status: r.status,
    basis: host ? 'host-observed' : 'provider-reported',
    moduleName: r.moduleName || moduleKey,
    moduleVersion: host?.moduleVersion,
    environment: host?.environment,
    vendor: r.vendor,
    certIds: r.certIds,
    standard: r.standard,
    level: r.level,
    sunsetDate: r.sunsetDate,
    candidate: host?.candidate,
    // Why this asset is tied to the module, then how the module itself was identified.
    evidence: [evidence, d?.evidence].filter(Boolean).join(' ') || undefined,
    note: r.note,
    mapVersion: r.mapVersion,
  };
};

/** The host-level view: every module the agent reported for a machine, resolved. */
export const hostModulesForConsole = (stored: unknown) => {
  let raw: any = stored;
  if (typeof raw === 'string') { try { raw = JSON.parse(raw); } catch { raw = null; } }
  const report = sanitizeHostModuleReport(raw);
  if (!report) return [];
  return report.modules.map(m => {
    const detail = moduleDetailFor(report, m.ref)!;
    return moduleForConsole(m.key, undefined, detail);
  });
};
