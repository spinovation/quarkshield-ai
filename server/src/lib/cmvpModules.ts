/**
 * CMVP module axis for KMS / vault connector assets
 * (docs/CMVP_AND_FIPS_COMPLIANCE_MAPPING.md, Stage 3).
 *
 * Two separate things live here, and they must stay separate:
 *
 *  1. OBSERVATION — which cryptographic module holds a key, derived only from a fact the
 *     provider's own API returned for that key (AWS `Origin`, Azure key type / `hsmPlatform`,
 *     Google `protectionLevel`, Vault's version string). Stored on the asset as a stable
 *     module key plus the fact it came from.
 *
 *  2. REFERENCE DATA — the CMVP certificate(s) the provider publishes for that module, with
 *     status and sunset as shown on the NIST CMVP certificate page. Vendored and versioned
 *     (`CMVP_MAP_VERSION`), resolved on read, never stored on the asset: NIST moves
 *     certificates to Historical, and a stored copy would silently go stale.
 *
 * Honesty rules (non-negotiable):
 *  - A certificate number is emitted only for a module whose entry lists one. No entry, or an
 *    entry with no certificate, resolves to `unverified` or `none` — never a guessed number.
 *  - A certificate here is what the PROVIDER states for the service. A customer cannot see the
 *    HSM firmware behind a single key, so this is a service-level statement, labelled
 *    `provider-reported`. QuarkShield did not test the module.
 *  - This is the module axis only. It is not a compliance verdict: that needs the algorithm
 *    axis and, on hosts, FIPS-mode evidence (Stage 5).
 *  - Assets no connector reported a module for stay `not-assessed`.
 *
 * Same convention as fipsAlgorithmStatus.ts: a versioned TS constant, not a JSON file (the
 * server tsconfig has no resolveJsonModule, so tsc would not emit a .json into dist/).
 */

/** Bump on every change to CMVP_MODULES. Stamped on every export that carries a certificate. */
export const CMVP_MAP_VERSION = '2026-11-15';

export type CmvpCertStatus = 'active' | 'historical' | 'revoked';
/** `none` = the module is known and carries no FIPS validation. `unverified` = cannot tell from what the API exposes. */
export type CmvpStatus = CmvpCertStatus | 'none' | 'unverified' | 'not-assessed';

export interface CmvpCertificate {
  certId: string;
  /** Module name exactly as on the NIST certificate page. */
  moduleName: string;
  vendor: string;
  standard: 'FIPS 140-2' | 'FIPS 140-3';
  level: number;
  status: CmvpCertStatus;
  /** ISO date; absent when NIST shows none (historical certificates). */
  sunsetDate?: string;
}

export interface CmvpModuleEntry {
  /** Human name of the module / service tier the key lives in. */
  label: string;
  vendor: string;
  certificates: CmvpCertificate[];
  /** Status when no certificate is listed. */
  whenNoCertificate: 'none' | 'unverified';
  /** One plain sentence shown with the result: what is and is not known. */
  note: string;
  /** Where the certificate claim comes from (provider page). */
  source?: string;
}

export interface ModuleObservation {
  /** Key into CMVP_MODULES. */
  key: string;
  /** The API fact this was derived from, e.g. "Cloud KMS protectionLevel=HSM". */
  evidence: string;
}

export const nistCertificateUrl = (certId: string): string =>
  `https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/${certId}`;

// -----------------------------------------------------------------------------
// Reference data. Every certificate row was read from its NIST certificate page on
// the CMVP_MAP_VERSION date. Refresh = re-read those pages, update, bump the version.
// -----------------------------------------------------------------------------
export const CMVP_MODULES: Record<string, CmvpModuleEntry> = {
  // ---- AWS ------------------------------------------------------------------
  'aws-kms-hsm': {
    label: 'AWS KMS HSM',
    vendor: 'Amazon Web Services, Inc.',
    certificates: [
      { certId: '4884', moduleName: 'AWS Key Management Service HSM', vendor: 'Amazon Web Services, Inc.', standard: 'FIPS 140-3', level: 3, status: 'active', sunsetDate: '2029-11-17' },
    ],
    whenNoCertificate: 'unverified',
    note: 'AWS states that KMS keys in the default key store are used only inside its KMS HSMs. The HSM firmware behind a single key is not visible to a customer, and AWS describes its fleet as validated or in the process of validation.',
    source: 'https://docs.aws.amazon.com/kms/latest/developerguide/data-protection.html',
  },
  'aws-kms-china': {
    label: 'AWS KMS HSM (China Regions)',
    vendor: 'Amazon Web Services, Inc.',
    certificates: [],
    whenNoCertificate: 'none',
    note: 'AWS states that the KMS HSMs in its China Regions are OSCCA-certified and are not validated under the FIPS 140-3 CMVP.',
    source: 'https://docs.aws.amazon.com/kms/latest/developerguide/data-protection.html',
  },
  'aws-cloudhsm-key-store': {
    label: 'AWS CloudHSM custom key store',
    vendor: 'Amazon Web Services, Inc.',
    certificates: [],
    whenNoCertificate: 'unverified',
    note: 'The key lives in a customer CloudHSM cluster. Its certificate depends on the cluster\'s HSM type and on whether the cluster runs in FIPS mode, neither of which this connector reads.',
    source: 'https://docs.aws.amazon.com/cloudhsm/latest/userguide/fips-validation.html',
  },
  'aws-external-key-store': {
    label: 'External key store (outside AWS)',
    vendor: 'Customer-operated',
    certificates: [],
    whenNoCertificate: 'unverified',
    note: 'The key material is held in an external key manager outside AWS. No AWS certificate applies and the external module is not visible to this connector.',
  },

  // ---- Azure ----------------------------------------------------------------
  'azure-managed-hsm': {
    label: 'Azure Key Vault Managed HSM',
    vendor: 'Microsoft (Marvell LiquidSecurity HSM adapters)',
    certificates: [
      { certId: '4700', moduleName: 'NITROXIII CNN35XX-NFBE HSM Family', vendor: 'Marvell Semiconductor, Inc.', standard: 'FIPS 140-3', level: 3, status: 'active', sunsetDate: '2029-05-29' },
    ],
    whenNoCertificate: 'unverified',
    note: 'Microsoft links this certificate from its Managed HSM documentation. The firmware behind a single key is not visible to a customer.',
    source: 'https://learn.microsoft.com/azure/key-vault/managed-hsm/firmware-update',
  },
  'azure-kv-hsm-platform2': {
    label: 'Azure Key Vault HSM-protected key (HSM platform 2)',
    vendor: 'Microsoft',
    certificates: [],
    whenNoCertificate: 'unverified',
    note: 'Microsoft describes HSM platform 2 as its FIPS 140-3 Level 3 validated platform, but its Key Vault documentation does not tie vault keys on this platform to one certificate number, so none is reported here.',
    source: 'https://learn.microsoft.com/azure/key-vault/keys/about-keys-details',
  },
  'azure-kv-hsm-platform1': {
    label: 'Azure Key Vault HSM-protected key (HSM platform 1, legacy)',
    vendor: 'Microsoft',
    certificates: [],
    whenNoCertificate: 'unverified',
    note: 'Microsoft describes HSM platform 1 as its previous FIPS 140-2 Level 2 validated platform and publishes no certificate number for it in its documentation.',
    source: 'https://learn.microsoft.com/azure/key-vault/keys/about-keys-details',
  },
  'azure-kv-hsm': {
    label: 'Azure Key Vault HSM-protected key',
    vendor: 'Microsoft',
    certificates: [],
    whenNoCertificate: 'unverified',
    note: 'The key is HSM-protected, but the API did not report which HSM platform holds it.',
  },
  'azure-kv-software': {
    label: 'Azure Key Vault software-protected key',
    vendor: 'Microsoft',
    certificates: [],
    whenNoCertificate: 'unverified',
    note: 'Microsoft describes software-protected keys as using a FIPS 140-2 Level 1 software cryptographic module and publishes no certificate number for it.',
    source: 'https://learn.microsoft.com/azure/key-vault/keys/about-keys',
  },

  // ---- Google Cloud ---------------------------------------------------------
  'gcp-kms-software': {
    label: 'Google Cloud KMS software key',
    vendor: 'Google, LLC',
    certificates: [],
    whenNoCertificate: 'unverified',
    note: 'Google states that software keys use its BoringCrypto module, validated at FIPS 140-3 Level 1, but says its services run several BoringCrypto builds and does not tie Cloud KMS to one certificate, so none is reported here. Google makes no FIPS 140 statement for the post-quantum algorithms it offers at this protection level.',
    source: 'https://cloud.google.com/kms/docs/protection-levels',
  },
  'gcp-kms-hsm': {
    label: 'Google Cloud HSM key',
    vendor: 'Google, LLC',
    certificates: [],
    whenNoCertificate: 'unverified',
    note: 'Google states that Cloud HSM keys are held in HSMs validated at FIPS 140 Level 3 and publishes neither the HSM vendor nor a certificate number.',
    source: 'https://cloud.google.com/kms/docs/protection-levels',
  },
  'gcp-kms-hsm-single-tenant': {
    label: 'Google Cloud single-tenant HSM key',
    vendor: 'Google, LLC',
    certificates: [],
    whenNoCertificate: 'unverified',
    note: 'Google publishes no FIPS 140 statement or certificate number specific to single-tenant HSM keys.',
    source: 'https://cloud.google.com/kms/docs/protection-levels',
  },
  'gcp-kms-external': {
    label: 'External key manager (outside Google Cloud)',
    vendor: 'Customer-operated',
    certificates: [],
    whenNoCertificate: 'unverified',
    note: 'The key material is held in an external key manager outside Google Cloud. The external module is not visible to this connector.',
  },

  // ---- HashiCorp Vault ------------------------------------------------------
  'vault-enterprise-fips1403': {
    label: 'Vault Enterprise FIPS 140-3 Inside build',
    vendor: 'HashiCorp (BoringCrypto, Google, LLC)',
    certificates: [
      { certId: '4735', moduleName: 'BoringCrypto', vendor: 'Google, LLC', standard: 'FIPS 140-3', level: 1, status: 'active', sunsetDate: '2029-07-22' },
    ],
    whenNoCertificate: 'unverified',
    note: 'Vault itself holds no CMVP certificate. HashiCorp states that this build performs its cryptography with the named BoringCrypto module, on AMD64 only. Identified from the build suffix in the version string Vault reported.',
    source: 'https://developer.hashicorp.com/vault/docs/enterprise/fips/fips1403',
  },
  'vault-enterprise-fips1402': {
    label: 'Vault Enterprise FIPS 140-2 Inside build',
    vendor: 'HashiCorp (BoringCrypto, Google, LLC)',
    certificates: [
      { certId: '3678', moduleName: 'BoringCrypto', vendor: 'Google, LLC', standard: 'FIPS 140-2', level: 1, status: 'historical' },
    ],
    whenNoCertificate: 'unverified',
    note: 'Vault itself holds no CMVP certificate. HashiCorp states that this build performs its cryptography with the named BoringCrypto module, whose certificate NIST now lists as Historical. Identified from the build suffix in the version string Vault reported.',
    source: 'https://developer.hashicorp.com/vault/docs/v1.16.x/enterprise/fips/fips1402',
  },
  'vault-enterprise-non-fips': {
    label: 'Vault Enterprise (version string names no FIPS build)',
    vendor: 'HashiCorp',
    certificates: [],
    whenNoCertificate: 'unverified',
    note: 'The version string Vault reported does not name a FIPS Inside build. Whether a validated module performs the cryptography could not be confirmed.',
  },
  'vault-community': {
    label: 'Vault Community build',
    vendor: 'HashiCorp',
    certificates: [],
    whenNoCertificate: 'none',
    note: 'HashiCorp offers FIPS builds in Vault Enterprise only; a Community build carries no FIPS 140 validation.',
    source: 'https://developer.hashicorp.com/vault/tutorials/get-started/available-editions',
  },
};

// -----------------------------------------------------------------------------
// Observation: provider API fact -> module key. Unknown facts record nothing.
// -----------------------------------------------------------------------------

/** AWS KMS: DescribeKey `Origin` (+ region). */
export const awsKmsModule = (f: { origin?: string; region?: string; customKeyStoreId?: string }): ModuleObservation | undefined => {
  const origin = String(f.origin || '').toUpperCase();
  const region = String(f.region || '').toLowerCase();
  const where = region ? `, region ${region}` : '';
  if (origin === 'AWS_CLOUDHSM') return { key: 'aws-cloudhsm-key-store', evidence: `AWS KMS Origin=AWS_CLOUDHSM${where}` };
  if (origin === 'EXTERNAL_KEY_STORE') return { key: 'aws-external-key-store', evidence: `AWS KMS Origin=EXTERNAL_KEY_STORE${where}` };
  if (origin === 'AWS_KMS' || origin === 'EXTERNAL') {
    // The certificate is tied to where the service runs; without the region nothing is claimed.
    if (!region) return undefined;
    const key = region.startsWith('cn-') ? 'aws-kms-china' : 'aws-kms-hsm';
    const imported = origin === 'EXTERNAL' ? ' (key material imported; generated outside AWS KMS)' : '';
    return { key, evidence: `AWS KMS Origin=${origin}${where}${imported}` };
  }
  return undefined;
};

/** Azure Key Vault: vault host, key type (`RSA` vs `RSA-HSM`) and the `hsmPlatform` attribute. */
export const azureKeyVaultModule = (f: { vaultUrl?: string; keyType?: string; hsmPlatform?: string | number | null }): ModuleObservation | undefined => {
  const keyType = String(f.keyType || '');
  if (!keyType) return undefined;
  let host = '';
  try { host = new URL(String(f.vaultUrl || '')).hostname.toLowerCase(); } catch { /* no host */ }
  const platform = f.hsmPlatform === undefined || f.hsmPlatform === null ? '' : String(f.hsmPlatform).trim();
  const plat = platform ? `, hsmPlatform=${platform}` : '';
  if (/\.managedhsm\./.test(host)) return { key: 'azure-managed-hsm', evidence: `Azure Managed HSM host, key type ${keyType}${plat}` };
  if (/-HSM$/i.test(keyType)) {
    const key = platform === '2' ? 'azure-kv-hsm-platform2' : platform === '1' ? 'azure-kv-hsm-platform1' : 'azure-kv-hsm';
    return { key, evidence: `Azure Key Vault key type ${keyType}${plat}` };
  }
  return { key: 'azure-kv-software', evidence: `Azure Key Vault key type ${keyType} (software-protected)${plat}` };
};

/** Google Cloud KMS: CryptoKeyVersion `protectionLevel`. */
export const gcpKmsModule = (protectionLevel?: string): ModuleObservation | undefined => {
  const level = String(protectionLevel || '').toUpperCase();
  const evidence = `Cloud KMS protectionLevel=${level}`;
  if (level === 'SOFTWARE') return { key: 'gcp-kms-software', evidence };
  if (level === 'HSM') return { key: 'gcp-kms-hsm', evidence };
  if (level === 'HSM_SINGLE_TENANT') return { key: 'gcp-kms-hsm-single-tenant', evidence };
  if (level === 'EXTERNAL' || level === 'EXTERNAL_VPC') return { key: 'gcp-kms-external', evidence };
  return undefined;
};

/** HashiCorp Vault: the version string from sys/seal-status (a FIPS build names itself in it). */
export const vaultModule = (f: { version?: string; sealType?: string }): ModuleObservation | undefined => {
  const version = String(f.version || '').trim();
  if (!version) return undefined;
  const seal = f.sealType ? `, seal type ${String(f.sealType)}` : '';
  const evidence = `Vault version ${version}${seal}`;
  if (/fips1403/i.test(version)) return { key: 'vault-enterprise-fips1403', evidence };
  if (/fips1402/i.test(version)) return { key: 'vault-enterprise-fips1402', evidence };
  if (/\+ent\b/i.test(version)) return { key: 'vault-enterprise-non-fips', evidence };
  return { key: 'vault-community', evidence };
};

// -----------------------------------------------------------------------------
// Resolution: module key -> what can be said about its CMVP validation.
// -----------------------------------------------------------------------------

export interface CmvpResolution {
  status: CmvpStatus;
  moduleKey?: string;
  moduleName?: string;
  vendor?: string;
  /** Certificates carrying the resolved status. Empty unless status is active / historical / revoked. */
  certIds: string[];
  standard?: 'FIPS 140-2' | 'FIPS 140-3';
  level?: number;
  /** Earliest sunset among the reported certificates. */
  sunsetDate?: string;
  note?: string;
  source?: string;
  mapVersion: string;
}

const RANK: CmvpCertStatus[] = ['active', 'historical', 'revoked'];

export const resolveCmvpModule = (moduleKey?: string | null): CmvpResolution => {
  const key = String(moduleKey || '').trim();
  if (!key) return { status: 'not-assessed', certIds: [], mapVersion: CMVP_MAP_VERSION };
  const entry = Object.prototype.hasOwnProperty.call(CMVP_MODULES, key) ? CMVP_MODULES[key] : undefined;
  // A module key this map version does not know (older server, newer connector): say so, claim nothing.
  if (!entry) return { status: 'unverified', moduleKey: key, moduleName: key, certIds: [], note: 'This module is not in the CMVP map version in use.', mapVersion: CMVP_MAP_VERSION };

  const base = { moduleKey: key, moduleName: entry.label, vendor: entry.vendor, note: entry.note, source: entry.source, mapVersion: CMVP_MAP_VERSION };
  // Best status present wins; only the certificates carrying it are reported, so a current
  // certificate is never listed beside a superseded one as if they were equal.
  const status = RANK.find(s => entry.certificates.some(c => c.status === s));
  if (!status) return { ...base, status: entry.whenNoCertificate, certIds: [] };
  const certs = entry.certificates.filter(c => c.status === status);
  const standards = new Set(certs.map(c => c.standard));
  const levels = new Set(certs.map(c => c.level));
  const sunsets = certs.map(c => c.sunsetDate).filter(Boolean).sort() as string[];
  return {
    ...base,
    status,
    certIds: certs.map(c => c.certId),
    // Stated only when every reported certificate agrees.
    standard: standards.size === 1 ? certs[0].standard : undefined,
    level: levels.size === 1 ? certs[0].level : undefined,
    sunsetDate: sunsets[0],
  };
};

/** Shape the console API returns per asset (only for assets with a recorded module). */
export const cmvpForConsole = (moduleKey: string, evidence?: string | null) => {
  const r = resolveCmvpModule(moduleKey);
  return {
    status: r.status,
    moduleName: r.moduleName || moduleKey,
    vendor: r.vendor,
    certIds: r.certIds,
    standard: r.standard,
    level: r.level,
    sunsetDate: r.sunsetDate,
    evidence: evidence || undefined,
    note: r.note,
    mapVersion: r.mapVersion,
  };
};
