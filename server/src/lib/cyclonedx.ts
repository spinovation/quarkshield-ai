import crypto from 'crypto';
import { fipsAlgorithmStatus, nistSecurityCategory, FIPS_TABLE_VERSION } from './fipsAlgorithmStatus';
import { isClassicalAsymmetric } from './threatGraph/cryptoPurpose';
import { nistCertificateUrl } from './cmvpModules';
import { resolveAssetModule, isHostResolution } from './hostCryptoModules';
import { complianceVerdict } from './complianceVerdict';

/**
 * CycloneDX 1.6 cryptographic-asset helpers (DEF-44 / DEF-45).
 *
 * Emits spec-conformant components: `bom-ref` (not `bomRef`), a valid
 * `cryptoProperties.assetType` enum, `nistQuantumSecurityLevel` (not the
 * invented `quantumSecurityLevel`), and vendor extras moved into `properties`
 * (the spec's escape hatch) rather than non-schema fields like `detectionContext`.
 *
 * The integrity seal is an honest HMAC-SHA384 (DEF-45): it is labeled as such
 * instead of masquerading as an ML-DSA-65 post-quantum signature, and the key
 * comes from CBOM_SIGNING_SECRET rather than a hardcoded value.
 *
 * FIPS honesty (docs/CMVP_AND_FIPS_COMPLIANCE_MAPPING.md §6.3, Stage 2):
 * `nistQuantumSecurityLevel` used to be a binary 0 / 3 derived from the scanner's
 * vulnerable flag, so AES-128 and ML-KEM-1024 both claimed "category 3". It is now 0 for
 * quantum-vulnerable assets, the real NIST category when the parameter set states one,
 * and OMITTED otherwise. Each component also carries its FIPS algorithm status as
 * `quarkshield:fips*` properties. Those describe the ALGORITHM only: CMVP module
 * validation is a separate axis, reported as `quarkshield:cmvp*` (Stage 3): `not-assessed`
 * unless a KMS / vault connector's API reported the module that holds the key.
 */

export interface CbomAssetInput {
  id: string;
  name: string;
  algorithm?: string;
  keySize?: number;
  hashAlgorithm?: string;
  purpose?: string | null;  // assets.purpose, when recorded — sharpens the FIPS verdict
  cryptoModule?: string | null;          // assets.crypto_module — module a connector's API reported (Stage 3)
  cryptoModuleEvidence?: string | null;  // the API fact it was derived from
  cryptoModuleDetail?: unknown;          // assets.crypto_module_detail — host module identity the agent reported (Stage 4)
  isVulnerable?: boolean;
  assetKind?: string;      // certificate | ssh_key | private_key | key | algorithm | ...
  status?: string;
  riskLevel?: string;
  recommendation?: string;
  explainer?: string;
  path?: string;
  hostname?: string;
  os?: string;
  source?: string;
  sourceRef?: string;
  complianceViolations?: any;
  tenant?: string;
}

const lc = (s?: string) => (s || '').toLowerCase();

/** CycloneDX cryptoProperties.assetType enum: algorithm|certificate|protocol|related-crypto-material */
const assetTypeFor = (kind?: string, algo?: string): string => {
  const k = lc(kind);
  if (k.includes('cert') || k === 'ca_root') return 'certificate';
  if (k.includes('key') || k === 'private_key' || k === 'public_key' || k === 'ssh_key' || k === 'related-crypto-material') return 'related-crypto-material';
  if (k === 'protocol' || lc(algo).includes('tls')) return 'protocol';
  return 'algorithm';
};

/** CycloneDX algorithmProperties.primitive enum. */
const primitiveFor = (algo?: string): string => {
  const a = lc(algo);
  if (a.includes('rsa')) return 'pke';
  if (a.includes('ecdsa') || a.includes('ed25519') || a.includes('dsa') || a.includes('ecc') || a.startsWith('ec-')) return 'signature';
  if (a.includes('ecdh') || a.includes('kem') || a.includes('mlkem') || a.includes('kyber') || a.includes('x25519')) return 'kem';
  if (a.includes('aes') || a.includes('chacha')) return 'ae';
  if (a.includes('hmac')) return 'mac';
  if (a.includes('sha') || a.includes('md5')) return 'hash';
  return 'unknown';
};

/**
 * CycloneDX `nistQuantumSecurityLevel`: 0 = not quantum-safe, 1-5 = NIST category.
 * Returns undefined (the field is then omitted) when no category can honestly be stated.
 *
 * The scanner's verdict is not overridden here: a row it did not flag (a trust anchor, a
 * list of supported algorithms) is never promoted to 0, or the export would disagree with
 * the console's counts. Such a row simply gets no level — and never a positive one if it
 * names a classical public-key algorithm.
 */
export const quantumSecurityLevel = (i: Pick<CbomAssetInput, 'algorithm' | 'keySize' | 'isVulnerable'>): number | undefined => {
  if (i.isVulnerable) return 0;
  if (isClassicalAsymmetric(i.algorithm || '')) return undefined;
  return nistSecurityCategory(i.algorithm || '', i.keySize);
};

const curveOf = (algo?: string): string | undefined => {
  const a = algo || '';
  if (a.includes('P-') || /P\d{3}/.test(a)) return a;
  if (a.includes('25519')) return a;
  return undefined;
};

/** Build one spec-valid CycloneDX 1.6 cryptographic-asset component. */
export const cbomComponent = (i: CbomAssetInput): any => {
  const assetType = assetTypeFor(i.assetKind, i.algorithm);
  const cryptoProperties: any = { assetType };
  // undefined is dropped by JSON.stringify, so an unknown level is absent from the export.
  const level = quantumSecurityLevel(i);
  const cmvp = resolveAssetModule(i.cryptoModule, i.cryptoModuleDetail);
  const host = isHostResolution(cmvp) ? cmvp : undefined;
  const fips = fipsAlgorithmStatus({
    algorithm: i.algorithm || '', key_size: i.keySize, hash_algorithm: i.hashAlgorithm,
    purpose: i.purpose, type: i.assetKind,
  });

  if (assetType === 'related-crypto-material') {
    cryptoProperties.relatedCryptoMaterialProperties = {
      type: lc(i.assetKind).includes('private') ? 'private-key' : lc(i.assetKind).includes('public') || lc(i.assetKind).includes('ssh') ? 'public-key' : 'key',
      size: i.keySize || undefined,
      state: 'active',
    };
    cryptoProperties.algorithmProperties = {
      primitive: primitiveFor(i.algorithm),
      curve: curveOf(i.algorithm),
      nistQuantumSecurityLevel: level,
    };
  } else if (assetType === 'certificate') {
    cryptoProperties.certificateProperties = {
      subjectName: i.name,
      signatureAlgorithmRef: i.algorithm || undefined,
    };
    cryptoProperties.algorithmProperties = {
      primitive: primitiveFor(i.algorithm),
      curve: curveOf(i.algorithm),
      nistQuantumSecurityLevel: level,
    };
  } else {
    cryptoProperties.algorithmProperties = {
      primitive: primitiveFor(i.algorithm),
      parameterSetIdentifier: i.hashAlgorithm || undefined,
      curve: curveOf(i.algorithm),
      nistQuantumSecurityLevel: level,
    };
  }

  const properties = [
    { name: 'quarkshield:algorithm', value: i.algorithm || 'Unknown' },
    i.keySize ? { name: 'quarkshield:keyLength', value: String(i.keySize) } : null,
    i.status ? { name: 'quarkshield:quantumStatus', value: String(i.status) } : null,
    // Explicit flag, so consumers need not infer vulnerability from the (now optional) level.
    typeof i.isVulnerable === 'boolean'
      ? { name: 'quarkshield:quantumVulnerable', value: String(i.isVulnerable) } : null,
    { name: 'quarkshield:fipsStatus', value: fips.status },
    fips.standard && fips.standard !== '—' ? { name: 'quarkshield:fipsStandard', value: fips.standard } : null,
    fips.deprecatedAfter ? { name: 'quarkshield:fipsDeprecatedAfter', value: fips.deprecatedAfter } : null,
    fips.disallowedAfter ? { name: 'quarkshield:transitionDate', value: fips.disallowedAfter } : null,
    fips.draft ? { name: 'quarkshield:fipsDraftGuidance', value: 'true' } : null,
    { name: 'quarkshield:fipsTableVersion', value: FIPS_TABLE_VERSION },
    // Algorithm approval is not module validation. The module axis is filled only where a KMS /
    // vault connector's API reported the module holding the key (Stage 3); every other asset
    // stays `not-assessed`. A certificate is the provider's published one, never inferred.
    { name: 'quarkshield:cmvpStatus', value: cmvp.status },
    cmvp.moduleName ? { name: 'quarkshield:cmvpModule', value: cmvp.moduleName } : null,
    cmvp.certIds.length ? { name: 'quarkshield:cmvpCertId', value: cmvp.certIds.join(',') } : null,
    cmvp.certIds.length ? { name: 'quarkshield:cmvpCertUrl', value: cmvp.certIds.map(nistCertificateUrl).join(' ') } : null,
    cmvp.certIds.length && cmvp.standard ? { name: 'quarkshield:cmvpFipsLevel', value: `${cmvp.standard}${cmvp.level ? ` Level ${cmvp.level}` : ''}` } : null,
    cmvp.certIds.length && cmvp.sunsetDate ? { name: 'quarkshield:cmvpSunsetDate', value: cmvp.sunsetDate } : null,
    cmvp.moduleKey ? { name: 'quarkshield:cmvpBasis', value: host ? 'host-observed' : 'provider-reported' } : null,
    // Host modules (Stage 4): identity, and at most a CANDIDATE certificate. Deliberately not
    // `cmvpCertId`: the module's FIPS mode is unconfirmed, so this is not a validation claim.
    host?.moduleVersion ? { name: 'quarkshield:cmvpModuleVersion', value: host.moduleVersion } : null,
    host?.environment ? { name: 'quarkshield:cmvpOperatingEnvironment', value: host.environment } : null,
    host?.candidate ? { name: 'quarkshield:cmvpCandidateId', value: host.candidate.certId } : null,
    host?.candidate ? { name: 'quarkshield:cmvpCandidateUrl', value: nistCertificateUrl(host.candidate.certId) } : null,
    host?.candidate ? { name: 'quarkshield:cmvpCandidateMatch', value: host.candidate.match } : null,
    host?.candidate ? { name: 'quarkshield:cmvpCandidateCertificateStatus', value: host.candidate.certStatus } : null,
    host ? { name: 'quarkshield:cmvpFipsMode', value: host.fipsMode.state } : null,
    host ? { name: 'quarkshield:cmvpFipsModeEvidence', value: host.fipsMode.evidence } : null,
    host?.note ? { name: 'quarkshield:cmvpNote', value: host.note } : null,
    cmvp.moduleKey && i.cryptoModuleEvidence ? { name: 'quarkshield:cmvpEvidence', value: String(i.cryptoModuleEvidence) } : null,
    cmvp.moduleKey ? { name: 'quarkshield:cmvpMapVersion', value: cmvp.mapVersion } : null,
    // Algorithm axis x module axis (Stage 5, one fixed table). `compliant` is reachable only
    // through a module whose current certificate was matched; see complianceVerdict.ts.
    { name: 'quarkshield:complianceVerdict', value: complianceVerdict(fips.status, cmvp.status) },
    i.riskLevel ? { name: 'quarkshield:riskLevel', value: String(i.riskLevel) } : null,
    i.recommendation ? { name: 'quarkshield:recommendation', value: String(i.recommendation) } : null,
    i.explainer ? { name: 'quarkshield:explainer', value: String(i.explainer) } : null,
    i.path ? { name: 'quarkshield:path', value: String(i.path) } : null,
    i.hostname ? { name: 'quarkshield:hostname', value: String(i.hostname) } : null,
    i.os ? { name: 'quarkshield:operatingSystem', value: String(i.os) } : null,
    i.source ? { name: 'quarkshield:assetSource', value: String(i.source) } : null,
    i.sourceRef ? { name: 'quarkshield:sourceReference', value: String(i.sourceRef) } : null,
    i.complianceViolations ? { name: 'quarkshield:complianceViolations', value: JSON.stringify(i.complianceViolations) } : null,
    i.tenant ? { name: 'quarkshield:tenant', value: String(i.tenant) } : null,
  ].filter(Boolean);

  return {
    type: 'cryptographic-asset',
    'bom-ref': i.id,
    name: i.name,
    cryptoProperties,
    properties,
  };
};

/** CycloneDX metadata.tools block. */
export const cbomTools = () => ({
  components: [
    { type: 'application', author: 'QuarkShield Security', name: 'desktop-pqc-scanner', version: '2.0.0' },
  ],
});

const signingSecret = (): string =>
  process.env.CBOM_SIGNING_SECRET || process.env.LICENSE_SIGNING_SECRET || process.env.JWT_SECRET || 'dev-insecure-cbom-secret';

/**
 * Honest integrity seal for an exported CBOM (DEF-45). This is an HMAC, not a
 * post-quantum signature; it is labeled accordingly so the document does not
 * misrepresent an ML-DSA signature.
 */
export const cbomSignature = (canonicalPayload: string, timestamp: string) => {
  const digestSha256 = crypto.createHash('sha256').update(canonicalPayload).digest('hex');
  const mac = crypto.createHmac('sha384', signingSecret()).update(digestSha256).digest('base64');
  return {
    algorithm: 'HMAC-SHA384',
    keyId: 'urn:quarkshield:cbom:integrity-key',
    value: mac,
    contentHash: `SHA-256:${digestSha256}`,
    note: 'Integrity MAC over the CBOM digest (not a post-quantum digital signature).',
    timestamp,
  };
};
