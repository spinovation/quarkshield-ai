/**
 * Crypto-purpose classification (design doc §13). Cryptographic PURPOSE is preserved
 * so that RSA/ECC findings are not all treated as the same migration problem:
 *   SSH authentication  → signature exposure      → evaluate ML-DSA
 *   TLS certificate     → auth/signature dependency → certificate/signature migration
 *   Key establishment   → confidentiality / HNDL  → ML-KEM or hybrid key establishment
 *   RSA key transport   → quantum-vulnerable KE   → PQ/hybrid replacement
 * Mirrors the KeyUsage triage the macOS agent already performs (agent/macos_store.go).
 */
import { CryptoPurpose } from './types';

const PQ_MARKERS = /(ML-?KEM|MLKEM|KYBER|ML-?DSA|MLDSA|DILITHIUM|SLH-?DSA|SPHINCS|FALCON|FN-?DSA|XMSS|LMS|HYBRID)/i;
const CLASSICAL_ASYM = /(RSA|ECDSA|ECDH|ECC|\bEC\b|\bDH\b|DHE|DIFFIE|\bDSA\b|ED25519|ED448|X25519|X448|P-?256|P-?384|P-?521|SECP|PRIME256|CURVE)/i;
const WEAK = /(\bMD5\b|SHA-?1\b|\b3DES\b|\bDES\b|RC4|TLS ?1\.0|TLS ?1\.1|SSLV3|LEGACY|WEAK|DEPRECATED|\bDSA\b)/i;

export interface PurposeInput {
  type: string;
  name: string;
  algorithm: string;
  key_size?: number | null;
  hash_algorithm?: string | null;
  description?: string | null;
  explainer?: string | null;
  key_usage?: string | null;
}

export const isPostQuantum = (algorithm: string): boolean => PQ_MARKERS.test(algorithm || '');

export const isClassicalAsymmetric = (algorithm: string): boolean =>
  !isPostQuantum(algorithm) && CLASSICAL_ASYM.test(algorithm || '');

export const classifyPurpose = (f: PurposeInput): CryptoPurpose => {
  const type = (f.type || '').toLowerCase();
  const text = `${f.name || ''} ${f.description || ''} ${f.explainer || ''} ${f.key_usage || ''}`.toLowerCase();
  const algo = (f.algorithm || '').toLowerCase();

  if (type === 'symmetric_key' || /^(aes|chacha|3des|des)\b/.test(algo)) return 'symmetric';
  if (type === 'ssh_key' || /\bssh\b/.test(text) && /(key|authorized|identity|host key)/.test(text) && type !== 'config') {
    return 'ssh_authentication';
  }
  if (type === 'ca_root' || /trust (store|anchor)|root ca|\bca root\b/.test(text)) return 'ca_trust_anchor';
  if (/rsa/.test(algo) && /(key transport|key encipherment|encrypt_decrypt|encrypt\/decrypt)/.test(text)) {
    return 'rsa_key_transport';
  }
  if (type === 'key_exchange' || type === 'tls_endpoint' ||
      /(key exchange|key establishment|key agreement|key share|kem\b|ecdhe|\bdhe\b)/.test(text)) {
    return 'key_establishment';
  }
  if (type === 'signature' || /(code sign|signing|sign_verify|signature)/.test(text)) return 'code_or_data_signing';
  if (type === 'certificate' || type === 'keystore' || /certificate/.test(text)) return 'tls_certificate';
  if (type === 'config' || type === 'template') return 'configuration';
  return 'unknown';
};

export const isClassicallyWeak = (f: PurposeInput): boolean => {
  const algo = f.algorithm || '';
  if (/rsa/i.test(algo) && f.key_size && f.key_size > 0 && f.key_size < 2048) return true;
  return WEAK.test(`${algo} ${f.hash_algorithm || ''} ${f.name || ''}`);
};

export const isHndlRelevant = (purpose: CryptoPurpose, quantumVulnerable: boolean): boolean =>
  quantumVulnerable && (purpose === 'key_establishment' || purpose === 'rsa_key_transport');

export const PURPOSE_LABELS: Record<CryptoPurpose, string> = {
  ssh_authentication: 'SSH authentication',
  tls_certificate: 'TLS certificate',
  key_establishment: 'Key establishment',
  rsa_key_transport: 'RSA key transport',
  code_or_data_signing: 'Code / data signing',
  ca_trust_anchor: 'CA trust anchor',
  symmetric: 'Symmetric encryption',
  configuration: 'Crypto configuration',
  unknown: 'Unclassified',
};

/** Purpose-specific recommendation (design doc §13 "Future Recommendation"). */
export const purposeRecommendation = (purpose: CryptoPurpose, weak: boolean): string => {
  const prefix = weak ? 'Replace classically weak parameters now; ' : '';
  switch (purpose) {
    case 'ssh_authentication':
      return `${prefix}signature/authentication exposure — rotate to a strong key and evaluate PQ signature migration (ML-DSA) where SSH implementations support it.`;
    case 'tls_certificate':
      return `${prefix}authentication/signature dependency — evaluate certificate and signature-chain migration (ML-DSA / hybrid certificates) with the issuing CA.`;
    case 'key_establishment':
      return `${prefix}confidentiality / HNDL concern — evaluate ML-KEM or hybrid key establishment (e.g. X25519MLKEM768) on this endpoint.`;
    case 'rsa_key_transport':
      return `${prefix}quantum-vulnerable key establishment — evaluate PQ/hybrid replacement for RSA key transport.`;
    case 'code_or_data_signing':
      return `${prefix}signature exposure — evaluate ML-DSA / SLH-DSA (or LMS/XMSS for firmware) signing.`;
    case 'ca_trust_anchor':
      return `${prefix}trust-anchor dependency — plan PQ/hybrid root and intermediate migration with the CA owner; do not remove trust anchors without a replacement chain.`;
    case 'symmetric':
      return `${prefix}symmetric primitive — ensure ≥128-bit security (AES-256 preferred for long-lived data).`;
    case 'configuration':
      return `${prefix}harden the cryptographic configuration (disable legacy ciphers/protocols, prefer hybrid PQ groups).`;
    default:
      return `${prefix}review this cryptographic dependency and its purpose before selecting a migration path.`;
  }
};
