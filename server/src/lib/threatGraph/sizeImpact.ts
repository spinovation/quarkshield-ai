/**
 * PQC "what-breaks" size-impact engine (dependency-map P2) — pure, no I/O, deterministic.
 *
 * A list of algorithms does not tell you whether the post-quantum replacement
 * physically FITS the systems that depend on it. ML-DSA signatures are ~50x an
 * Ed25519 signature; ML-KEM-768 keys/ciphertexts are ~35x X25519; SLH-DSA
 * firmware signatures are kilobytes where an ECDSA one was ~70 bytes. This
 * engine computes the real byte blow-up for a finding's purpose-appropriate
 * object and tests it against known system constraints.
 *
 * HONESTY CONTRACT: object sizes are exact (NIST FIPS 203/204/205 final params).
 * System LIMITS are NOMINAL — QuarkShield does not yet collect per-device limits
 * (actual secure-boot slot size, whether a key lives on a smartcard, path MTU),
 * so each constraint finding is CONDITIONAL ("applies if hosted on …") and the
 * severity reflects the size ratio, not a measured failure. See
 * docs/CRYPTO_USAGE_DEPENDENCY_MAP_AND_IMPACT_ANALYSIS.md §4.
 */
import { CryptoPurpose } from './types';

export const SIZE_TABLE_VERSION = 'nist-fips-203-204-205-final';

type ObjectKind = 'signature' | 'public_key' | 'kem_exchange';

// Exact object sizes in BYTES. kem_exchange = public key (ek) + ciphertext (ct),
// the bytes added to a TLS key-share round trip.
const SIG_BYTES: Record<string, number> = {
  'ed25519': 64, 'ecdsa-p256': 72, 'ecdsa-p384': 104, 'ecdsa-p521': 139,
  'rsa-2048': 256, 'rsa-3072': 384, 'rsa-4096': 512,
  'ml-dsa-44': 2420, 'ml-dsa-65': 3309, 'ml-dsa-87': 4627,
  'slh-dsa-128s': 7856, 'slh-dsa-128f': 17088, 'slh-dsa-192s': 16224, 'slh-dsa-256s': 29792,
};
const KEX_BYTES: Record<string, number> = {
  // classical: public key / key-share bytes
  'x25519': 32, 'ecdh-p256': 65, 'ecdh-p384': 97, 'rsa-2048': 256, 'rsa-3072': 384,
  // PQC: ek + ct (bytes added to the handshake)
  'ml-kem-512': 800 + 768, 'ml-kem-768': 1184 + 1088, 'ml-kem-1024': 1568 + 1568,
};

/** Does this purpose spend its bytes on a SIGNATURE or on KEY EXCHANGE? */
const kindForPurpose = (p: CryptoPurpose): ObjectKind => {
  switch (p) {
    case 'key_establishment':
    case 'rsa_key_transport':
      return 'kem_exchange';
    default:
      return 'signature'; // tls_certificate, code_or_data_signing, ca_trust_anchor, ssh_authentication, …
  }
};

/** Normalize a free-form algorithm string + key size to a size-table key. */
export const canonicalAlgo = (algorithm: string, keySize?: number | null): string => {
  const a = (algorithm || '').toLowerCase().replace(/\s+/g, '');
  if (/ed25519/.test(a)) return 'ed25519';
  if (/(p-?521|secp521)/.test(a)) return 'ecdsa-p521';
  if (/(p-?384|secp384)/.test(a)) return 'ecdsa-p384';
  if (/(p-?256|secp256|prime256)/.test(a)) return 'ecdsa-p256';
  if (/x25519|curve25519/.test(a)) return 'x25519';
  if (/(ecdh|ecdhe)/.test(a)) return 'ecdh-p256';
  if (/(ecdsa|ecc\b)/.test(a)) return 'ecdsa-p256';
  if (/rsa/.test(a)) {
    const n = keySize || (/(\d{3,4})/.exec(a)?.[1] ? Number(/(\d{3,4})/.exec(a)![1]) : 2048);
    return n >= 4096 ? 'rsa-4096' : n >= 3072 ? 'rsa-3072' : 'rsa-2048';
  }
  return 'unknown';
};

/** Default NIST PQC replacement per purpose (CNSA 2.0-aligned). */
export const pqcTargetFor = (purpose: CryptoPurpose): string => {
  switch (purpose) {
    case 'key_establishment':
    case 'rsa_key_transport':
      return 'ml-kem-768';
    case 'ca_trust_anchor':
      return 'slh-dsa-128s'; // stateless hash-based for long-lived roots of trust
    default:
      return 'ml-dsa-65';    // tls_certificate, code_or_data_signing, ssh_authentication
  }
};

export interface ImpactConstraint {
  id: string;
  label: string;
  limit_bytes: number;       // NOMINAL
  applies_to: ObjectKind[];
  purposes?: CryptoPurpose[];// further gate by purpose (e.g. firmware slot only for signing/CA)
  condition: string;         // the "applies if hosted on …" caveat
  remediation: string;
}

// Nominal, documented limits. Conservative so a 'breaks' verdict is defensible.
const CONSTRAINTS: ImpactConstraint[] = [
  { id: 'firmware_slot', label: 'Secure-boot signature slot', limit_bytes: 512, applies_to: ['signature'],
    purposes: ['code_or_data_signing', 'ca_trust_anchor'],
    condition: 'if this key signs firmware / secure-boot images with a fixed-size signature slot',
    remediation: 'Re-layout the secure-boot header, or adopt stateful hash-based signatures (LMS/XMSS) whose one-time use fits a boot chain; coordinate with the next firmware revision.' },
  { id: 'smartcard_apdu', label: 'Smartcard short APDU', limit_bytes: 255, applies_to: ['signature', 'public_key'],
    condition: 'if this key is stored on / used through a smartcard or PIV token without extended-APDU support',
    remediation: 'Use APDU chaining / extended APDU on verified readers, or move signing off-card.' },
  { id: 'cert_chain', label: 'Embedded TLS cert-chain buffer', limit_bytes: 16384, applies_to: ['signature'],
    purposes: ['tls_certificate', 'ca_trust_anchor'],
    condition: 'if a constrained/IoT TLS client must accept the full certificate chain',
    remediation: 'Enable TLS certificate compression (RFC 8879), shorten chains, suppress intermediates, or use ML-DSA-44 leaves.' },
  { id: 'quic_amp', label: 'QUIC 3x anti-amplification', limit_bytes: 3600, applies_to: ['signature', 'kem_exchange'],
    purposes: ['tls_certificate', 'key_establishment'],
    condition: 'if this endpoint serves QUIC/HTTP-3 before client address validation',
    remediation: 'Tune Retry/address-validation, enable cert compression, or defer the full chain past validation.' },
  { id: 'mtu_frag', label: 'Path MTU / IKEv2 fragmentation', limit_bytes: 1400, applies_to: ['kem_exchange'],
    purposes: ['key_establishment', 'rsa_key_transport'],
    condition: 'if used in IKEv2/IPsec or UDP transports that fragment poorly across middleboxes',
    remediation: 'Enable IKEv2 fragmentation (RFC 7383) and tune MTU.' },
];

export type ImpactVerdict = 'breaks' | 'tight' | 'ok';
export type ImpactSeverity = 'blocker' | 'degraded' | 'advisory';

export interface SizeImpactFinding {
  constraint_id: string;
  constraint_label: string;
  limit_bytes: number;
  size_after: number;
  verdict: ImpactVerdict;
  severity: ImpactSeverity;
  condition: string;
  rationale: string;
  remediation: string;
}

export interface SizeImpact {
  from_algo: string;
  to_algo: string;
  object_kind: ObjectKind;
  size_before: number;      // bytes (0 if the classical size is unknown)
  size_after: number;       // bytes
  blowup: number | null;    // size_after / size_before, 1 decimal; null if unknown
  size_table_version: string;
  findings: SizeImpactFinding[]; // constraints at risk (breaks|tight), worst first
  note: string;
}

const round1 = (n: number) => Math.round(n * 10) / 10;

/** Assess the migration size impact of ONE crypto finding. */
export const assessSizeImpact = (f: { algorithm: string; key_size?: number | null; purpose: CryptoPurpose; pqc_target?: string | null }): SizeImpact => {
  // Symmetric / configuration findings have no asymmetric object to grow — no size migration.
  if (f.purpose === 'symmetric' || f.purpose === 'configuration') {
    return {
      from_algo: canonicalAlgo(f.algorithm, f.key_size), to_algo: '—', object_kind: 'signature',
      size_before: 0, size_after: 0, blowup: null, size_table_version: SIZE_TABLE_VERSION, findings: [],
      note: 'Symmetric / configuration findings carry no asymmetric key or signature, so post-quantum migration does not change object sizes (ensure AES-256 / modern ciphers instead).',
    };
  }
  const kind = kindForPurpose(f.purpose);
  const table = kind === 'kem_exchange' ? KEX_BYTES : SIG_BYTES;
  const fromKey = canonicalAlgo(f.algorithm, f.key_size);
  const toKey = (f.pqc_target || pqcTargetFor(f.purpose)).toLowerCase();
  const size_before = table[fromKey] ?? 0;
  const size_after = table[toKey] ?? SIG_BYTES[toKey] ?? KEX_BYTES[toKey] ?? 0;
  const blowup = size_before > 0 && size_after > 0 ? round1(size_after / size_before) : null;

  const findings: SizeImpactFinding[] = [];
  for (const c of CONSTRAINTS) {
    if (!c.applies_to.includes(kind)) continue;
    if (c.purposes && !c.purposes.includes(f.purpose)) continue;
    if (size_after <= 0) continue;
    const verdict: ImpactVerdict = size_after > c.limit_bytes ? 'breaks' : size_after > 0.8 * c.limit_bytes ? 'tight' : 'ok';
    if (verdict === 'ok') continue;
    // A categorical overflow of a small fixed slot (firmware/smartcard) is a blocker;
    // a buffer/transport limit that is merely exceeded is degraded; 'tight' is advisory.
    const categorical = c.id === 'firmware_slot' || c.id === 'smartcard_apdu';
    const severity: ImpactSeverity = verdict === 'breaks' ? (categorical ? 'blocker' : 'degraded') : 'advisory';
    findings.push({
      constraint_id: c.id,
      constraint_label: c.label,
      limit_bytes: c.limit_bytes,
      size_after,
      verdict,
      severity,
      condition: c.condition,
      rationale: `${toKey.toUpperCase()} ${kind === 'kem_exchange' ? 'key+ciphertext' : 'signature'} is ${size_after} B vs a nominal ${c.limit_bytes} B ${c.label.toLowerCase()}${blowup ? ` (${blowup}x the ${fromKey.toUpperCase()} it replaces)` : ''} — ${c.condition}.`,
      remediation: c.remediation,
    });
  }
  const sevRank: Record<ImpactSeverity, number> = { blocker: 0, degraded: 1, advisory: 2 };
  findings.sort((a, b) => sevRank[a.severity] - sevRank[b.severity] || b.size_after - a.size_after);

  const note = size_before === 0
    ? `Classical object size for "${f.algorithm}" is not in the reference table, so the blow-up ratio is unknown; the post-quantum size and constraint checks are still shown. System limits are nominal and each finding is conditional on how the key is hosted.`
    : `Object sizes are exact (${SIZE_TABLE_VERSION}); system limits are NOMINAL and each finding is conditional on how/where the key is hosted — QuarkShield does not yet collect per-device slot sizes, smartcard capability, or path MTU.`;

  return { from_algo: fromKey, to_algo: toKey, object_kind: kind, size_before, size_after, blowup, size_table_version: SIZE_TABLE_VERSION, findings, note };
};
