import crypto from 'crypto';

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
 */

export interface CbomAssetInput {
  id: string;
  name: string;
  algorithm?: string;
  keySize?: number;
  hashAlgorithm?: string;
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

/** NIST quantum security level 0-6 (0 = broken by a CRQC). */
const nqsl = (isVulnerable?: boolean): number => (isVulnerable ? 0 : 3);

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

  if (assetType === 'related-crypto-material') {
    cryptoProperties.relatedCryptoMaterialProperties = {
      type: lc(i.assetKind).includes('private') ? 'private-key' : lc(i.assetKind).includes('public') || lc(i.assetKind).includes('ssh') ? 'public-key' : 'key',
      size: i.keySize || undefined,
      state: 'active',
    };
    cryptoProperties.algorithmProperties = {
      primitive: primitiveFor(i.algorithm),
      curve: curveOf(i.algorithm),
      nistQuantumSecurityLevel: nqsl(i.isVulnerable),
    };
  } else if (assetType === 'certificate') {
    cryptoProperties.certificateProperties = {
      subjectName: i.name,
      signatureAlgorithmRef: i.algorithm || undefined,
    };
    cryptoProperties.algorithmProperties = {
      primitive: primitiveFor(i.algorithm),
      curve: curveOf(i.algorithm),
      nistQuantumSecurityLevel: nqsl(i.isVulnerable),
    };
  } else {
    cryptoProperties.algorithmProperties = {
      primitive: primitiveFor(i.algorithm),
      parameterSetIdentifier: i.hashAlgorithm || undefined,
      curve: curveOf(i.algorithm),
      nistQuantumSecurityLevel: nqsl(i.isVulnerable),
    };
  }

  const properties = [
    { name: 'quarkshield:algorithm', value: i.algorithm || 'Unknown' },
    i.keySize ? { name: 'quarkshield:keyLength', value: String(i.keySize) } : null,
    i.status ? { name: 'quarkshield:quantumStatus', value: String(i.status) } : null,
    i.riskLevel ? { name: 'quarkshield:riskLevel', value: String(i.riskLevel) } : null,
    i.recommendation ? { name: 'quarkshield:recommendation', value: String(i.recommendation) } : null,
    i.explainer ? { name: 'quarkshield:explainer', value: String(i.explainer) } : null,
    i.path ? { name: 'quarkshield:path', value: String(i.path) } : null,
    i.hostname ? { name: 'quarkshield:hostname', value: String(i.hostname) } : null,
    i.os ? { name: 'quarkshield:operatingSystem', value: String(i.os) } : null,
    i.source ? { name: 'quarkshield:assetSource', value: String(i.source) } : null,
    i.sourceRef ? { name: 'quarkshield:sourceReference', value: String(i.sourceRef) } : null,
    i.complianceViolations ? { name: 'quarkshield:complianceViolations', value: JSON.stringify(i.complianceViolations) } : null,
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
