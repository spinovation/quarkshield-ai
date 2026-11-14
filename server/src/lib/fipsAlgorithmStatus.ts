/**
 * FIPS algorithm-approval status — axis A1 of docs/CMVP_AND_FIPS_COMPLIANCE_MAPPING.md.
 *
 * Answers "is this ALGORITHM (with these parameters, for this use) FIPS-approved, and
 * until when?" — DETERMINISTICALLY, from a versioned reference table. It deliberately
 * says NOTHING about whether the algorithm runs inside a CMVP-validated MODULE (axis A2,
 * see docs/CMVP_CERT_CAPTURE_DESIGN.md). "Approved algorithm" ≠ "validated module".
 *
 * Basis:
 *   - NIST SP 800-131A Rev. 2 (2019) — current approval/transition status
 *   - FIPS 186-5 (2023)              — DSA retired for signature generation; EdDSA approved
 *   - FIPS 203 / 204 / 205 (2024)    — ML-KEM / ML-DSA / SLH-DSA approved
 *   - SP 800-208 (2020)              — LMS / XMSS stateful hash-based signatures
 *   - SP 800-52 Rev. 2 (2019)        — TLS 1.0 / 1.1 not permitted for federal use
 *   - NIST SHA-1 retirement announcement (Dec 2022) — SHA-1 phased out by 2030-12-31
 *   - NIST IR 8547 (initial public DRAFT, Nov 2024) — quantum-vulnerable public-key
 *     algorithms: 112-bit-strength deprecated after 2030, all disallowed after 2035.
 *     These dates are DRAFT guidance and every result that uses them says so (`draft`).
 *
 * Shipped as a TS constant (not JSON) so it is emitted by `tsc` without resolveJsonModule —
 * same convention as the size table in threatGraph/sizeImpact.ts. Bump FIPS_TABLE_VERSION
 * on every change; it is stamped on every report as provenance.
 */
import { CryptoPurpose } from './threatGraph/types';

export const FIPS_TABLE_VERSION = '2026-11-14';

export type FipsStatus =
  | 'pq_approved'     // approved post-quantum standard (FIPS 203/204/205, SP 800-208)
  | 'approved'        // approved, no published sunset
  | 'acceptable'      // approved today, but with a published (or draft) sunset date
  | 'restricted'      // legacy use only (e.g. verification of existing signatures)
  | 'disallowed'      // not approved for the detected parameters / use
  | 'non_fips'        // not a FIPS-approved algorithm at all
  | 'not_applicable'  // not an algorithm instance (a package/module row → axis A2)
  | 'unknown';        // cannot classify — renders "not determined", never pass/fail

export interface FipsInput {
  algorithm: string;
  key_size?: number | null;
  hash_algorithm?: string | null;
  purpose?: CryptoPurpose | string | null;
  type?: string | null;
}

export interface FipsResult {
  status: FipsStatus;
  standard: string;            // governing document for the deciding rule
  deprecatedAfter?: string;    // ISO date — status worsens to "deprecated" after this
  disallowedAfter?: string;    // ISO date — the hard sunset
  draft: boolean;              // true when any date relies on draft guidance (NIST IR 8547)
  rationale: string;
  ruleId: string;              // which rule fired — evidence trail
}

// Worst-first ordering used when one finding names several primitives (e.g. a cert's
// key algorithm + its signature hash, or a TLS cipher suite). `unknown` outranks the
// approved states: a finding with an undeterminable part can never be asserted approved.
// approved and pq_approved tie — a SHA-2 hash must not demote an ML-DSA cert's label.
const SEVERITY: Record<FipsStatus, number> = {
  disallowed: 7, non_fips: 6, restricted: 5, unknown: 4, acceptable: 3, approved: 2, pq_approved: 2, not_applicable: 0,
};

const IR8547_DEPRECATE_112 = '2030-12-31';
const IR8547_DISALLOW_ALL = '2035-12-31';
const SHA1_RETIRE = '2030-12-31';

const SIGNATURE_PURPOSES = new Set(['tls_certificate', 'code_or_data_signing', 'ca_trust_anchor', 'ssh_authentication']);
// Asset types that are signature-bearing by nature — used when `purpose` is missing (legacy rows
// pre-date the purpose column) so e.g. a SHA-1-signed certificate is still judged as a signature.
const SIGNATURE_TYPES = new Set(['certificate', 'ca_root', 'signature', 'ssh_key', 'keystore']);
// Rules that identify a KEY-ESTABLISHMENT primitive. A key_establishment finding with none of
// these (e.g. 'key-exchange group not reported / TLSv1.3 / TLS_AES_256_GCM_SHA384') has an
// undetermined key exchange and must not be reported as approved on the strength of its cipher.
const KEX_RULES = new Set(['pq.mlkem', 'pq.mlkem.hybrid', 'kex.xcurve', 'rsa', 'rsa.nosize', 'ecc', 'ecc.nosize', 'ecc.curve', 'dh', 'dh.nosize', 'pq.prestandard']);
const MODULE_TYPES = new Set(['package', 'library', 'dependency', 'sbom']);

const r = (status: FipsStatus, standard: string, ruleId: string, rationale: string,
  extra: Partial<Pick<FipsResult, 'deprecatedAfter' | 'disallowedAfter' | 'draft'>> = {}): FipsResult =>
  ({ status, standard, ruleId, rationale, draft: false, ...extra });

/** Quantum-vulnerable public-key algorithm at a given classical security strength (bits). */
const qvPublicKey = (family: string, strength: number, ruleId: string): FipsResult => {
  if (strength < 112) {
    return r('disallowed', 'SP 800-131A Rev. 2', ruleId, `${family} below 112-bit security strength is disallowed.`);
  }
  if (strength < 128) {
    return r('acceptable', 'SP 800-131A Rev. 2', ruleId,
      `${family} at 112-bit strength is approved today; NIST IR 8547 (draft) deprecates it after ${IR8547_DEPRECATE_112} and disallows it after ${IR8547_DISALLOW_ALL} (quantum-vulnerable).`,
      { deprecatedAfter: IR8547_DEPRECATE_112, disallowedAfter: IR8547_DISALLOW_ALL, draft: true });
  }
  return r('acceptable', 'SP 800-131A Rev. 2', ruleId,
    `${family} is approved today; NIST IR 8547 (draft) disallows all quantum-vulnerable public-key algorithms after ${IR8547_DISALLOW_ALL}.`,
    { disallowedAfter: IR8547_DISALLOW_ALL, draft: true });
};

/** SP 800-57 Pt.1 strength for IFC/FFC modulus sizes. */
const ifcStrength = (bits: number): number =>
  bits >= 15360 ? 256 : bits >= 7680 ? 192 : bits >= 3072 ? 128 : bits >= 2048 ? 112 : bits >= 1024 ? 80 : 0;

/** Curve → field size in bits (≈ 2× security strength). null = not a NIST-approved curve we know. */
const curveBits = (a: string, keySize?: number | null): { bits: number | null; approved: boolean } => {
  if (/SECP256K1/.test(a)) return { bits: 256, approved: false };
  if (/BRAINPOOL/.test(a)) return { bits: null, approved: false };
  // P-192 is a NIST curve that is merely too weak — the strength check makes it "disallowed".
  const m = a.match(/(?:P-?|SECP|PRIME)(192|224|256|384|521)/);
  if (m) return { bits: Number(m[1]), approved: true };
  // Only trust key_size as a curve size when it plausibly is one: on a cipher-suite row
  // ("ECDHE-RSA-…") key_size is the RSA modulus (e.g. 2048), not the EC curve.
  if (keySize && keySize >= 160 && keySize <= 571) return { bits: keySize, approved: true };
  return { bits: null, approved: true };
};

/** Evaluate a single primitive token. Returns null when the text names no known primitive. */
const evalPrimitive = (aRaw: string, f: FipsInput): FipsResult | null => {
  const a = aRaw.toUpperCase();
  const purpose = String(f.purpose || 'unknown');
  const isSig = SIGNATURE_PURPOSES.has(purpose) ||
    (purpose === 'unknown' && SIGNATURE_TYPES.has(String(f.type || '').toLowerCase()));
  const ks = f.key_size && f.key_size > 0 ? f.key_size : null;

  // ---- Post-quantum (check first: hybrid names also contain classical tokens) ----
  if (/ML-?KEM|MLKEM/.test(a)) {
    const hybrid = /X25519|X448|P-?256|P-?384|SECP|HYBRID/.test(a);
    return r('pq_approved', 'FIPS 203', hybrid ? 'pq.mlkem.hybrid' : 'pq.mlkem',
      hybrid ? 'Hybrid key establishment whose ML-KEM component is FIPS 203-approved (shared secrets combined per SP 800-56C).'
             : 'ML-KEM is the FIPS 203-approved key-encapsulation mechanism.');
  }
  if (/ML-?DSA|MLDSA/.test(a)) return r('pq_approved', 'FIPS 204', 'pq.mldsa', 'ML-DSA is the FIPS 204-approved signature scheme.');
  if (/SLH-?DSA/.test(a)) return r('pq_approved', 'FIPS 205', 'pq.slhdsa', 'SLH-DSA is the FIPS 205-approved stateless hash-based signature scheme.');
  if (/\bLMS\b|HSS|XMSS/.test(a)) return r('pq_approved', 'SP 800-208', 'pq.hbs', 'LMS/XMSS stateful hash-based signatures are approved under SP 800-208.');
  if (/KYBER|DILITHIUM|SPHINCS/.test(a)) {
    return r('unknown', 'FIPS 203 / 204 / 205', 'pq.prestandard',
      'Pre-standard name (Kyber/Dilithium/SPHINCS+). Only the final ML-KEM / ML-DSA / SLH-DSA are FIPS-approved — confirm the implementation is the final standard.');
  }
  if (/FALCON|FN-?DSA/.test(a)) {
    return r('unknown', 'FIPS 206 (pending)', 'pq.fndsa', 'FN-DSA (Falcon) is specified in FIPS 206; confirm its final publication status before treating it as approved.');
  }

  // ---- Protocol versions (SP 800-52 Rev. 2) ----
  if (/(?<!OPEN)SSL ?V?[23]\b|TLS ?V?1\.[01]\b/.test(a)) {
    return r('disallowed', 'SP 800-52 Rev. 2', 'proto.tls_legacy', 'SSL and TLS 1.0/1.1 are not permitted for federal systems; require TLS 1.2+ (TLS 1.3 preferred).');
  }

  // ---- Public-key ----
  if (/RSA/.test(a)) {
    if (!ks) return r('unknown', 'SP 800-131A Rev. 2', 'rsa.nosize', 'RSA key size was not captured, so its approval status cannot be determined.');
    return qvPublicKey(`RSA-${ks}`, ifcStrength(ks), 'rsa');
  }
  if (/ED25519|ED448|EDDSA/.test(a)) {
    return qvPublicKey(/ED448/.test(a) ? 'Ed448 (EdDSA, FIPS 186-5)' : 'Ed25519 (EdDSA, FIPS 186-5)', /ED448/.test(a) ? 224 : 128, 'eddsa');
  }
  if (/X25519|X448|CURVE25519/.test(a)) {
    return r('non_fips', 'SP 800-56A Rev. 3', 'kex.xcurve', 'X25519/X448 Diffie-Hellman is not an SP 800-56A Rev. 3 approved key-agreement scheme (it is approved only as part of a hybrid with ML-KEM).');
  }
  if (/\bDSA\b/.test(a) && !/ECDSA|ML-?DSA|SLH/.test(a)) {
    return r('restricted', 'FIPS 186-5', 'dsa', 'DSA is no longer approved for signature generation (FIPS 186-5); verification of existing signatures only.');
  }
  if (/ECDSA|ECDH|\bECC\b|\bEC\b|SECP|PRIME\d|P-?(192|224|256|384|521)|BRAINPOOL/.test(a)) {
    const c = curveBits(a, ks);
    if (!c.approved) return r('non_fips', 'SP 800-186', 'ecc.curve', 'Elliptic curve is not one of the NIST-approved curves in SP 800-186 for this use.');
    if (!c.bits) return r('unknown', 'SP 800-131A Rev. 2', 'ecc.nosize', 'Elliptic-curve size was not captured, so its approval status cannot be determined.');
    return qvPublicKey(`${/ECDH/.test(a) ? 'ECDH' : 'ECDSA'} P-${c.bits}`, Math.floor(c.bits / 2), 'ecc');
  }
  if (/DIFFIE|\bDHE?\b|FFDHE|MODP/.test(a)) {
    // On a cipher-suite row ("DHE-RSA-…") key_size is the authentication key's modulus, not
    // the DH group — never use it as the group size (a 1024-bit group would be masked).
    const authInSuite = /RSA|DSA|ECDSA/.test(String(f.algorithm || '').toUpperCase());
    if (!ks || authInSuite) return r('unknown', 'SP 800-131A Rev. 2', 'dh.nosize', 'Finite-field DH group size was not captured, so its approval status cannot be determined.');
    return qvPublicKey(`DH-${ks}`, ifcStrength(ks), 'dh');
  }

  // ---- Hashes ----
  if (/\bMD[245]\b/.test(a)) return r('disallowed', 'SP 800-131A Rev. 2', 'hash.md5', 'MD5 is not a FIPS-approved hash function.');
  if (/SHA-?1\b|SHA1/.test(a) || /^SHA$/.test(a)) {
    if (isSig) {
      return r('disallowed', 'SP 800-131A Rev. 2', 'hash.sha1.sig', 'SHA-1 is disallowed for digital-signature generation; legacy verification only.');
    }
    return r('acceptable', 'SP 800-131A Rev. 2', 'hash.sha1', `SHA-1 remains acceptable only for non-signature uses (e.g. HMAC); NIST has announced its retirement by ${SHA1_RETIRE}.`,
      { disallowedAfter: SHA1_RETIRE });
  }
  if (/SHA-?(224|256|384|512)|SHA2|SHA3|SHAKE|HMAC/.test(a)) {
    return r('approved', /SHA3|SHAKE/.test(a) ? 'FIPS 202' : 'FIPS 180-4', 'hash.sha2_3', 'SHA-2 / SHA-3 family hash (or HMAC) — FIPS-approved.');
  }

  // ---- Symmetric ----
  if (/3DES|TDEA|TRIPLE ?DES|DES-?EDE/.test(a)) {
    return r('disallowed', 'SP 800-131A Rev. 2', 'sym.tdea', 'Triple-DES encryption was disallowed after 2023-12-31; decryption of legacy data only.');
  }
  if (/\bDES\b/.test(a)) return r('disallowed', 'SP 800-131A Rev. 2', 'sym.des', 'Single DES is not FIPS-approved.');
  if (/\bAES/.test(a)) return r('approved', 'FIPS 197', 'sym.aes', 'AES is FIPS-approved (CNSA 2.0 additionally requires AES-256).');
  if (/\b(RC4|ARCFOUR|RC2|BLOWFISH|CAMELLIA|CHACHA\d*|SEED|IDEA|CAST5?)\b/.test(a)) {
    return r('non_fips', 'SP 800-131A Rev. 2', 'sym.nonfips', 'Not a FIPS-approved cipher (e.g. ChaCha20, RC4, Blowfish, Camellia are not approved).');
  }
  return null;
};

/**
 * Resolve the FIPS approval status of one finding. Several primitives in one finding
 * (key algorithm + signature hash, cipher-suite components) resolve to the WORST status,
 * because the finding is only as compliant as its weakest part.
 */
export const fipsAlgorithmStatus = (f: FipsInput): FipsResult => {
  if (MODULE_TYPES.has(String(f.type || '').toLowerCase())) {
    return r('not_applicable', '—', 'module.row',
      'This row is a software package / module, not an algorithm instance. Module validation is assessed by CMVP correlation (axis A2), not here.');
  }
  const algo = String(f.algorithm || '').trim();
  if (!algo || /^UNKNOWN$/i.test(algo)) {
    return r('unknown', '—', 'none', 'No algorithm recorded, so FIPS approval status cannot be determined.');
  }

  // Post-quantum names (X25519MLKEM768, SLH-DSA-SHA2-128s, ML-DSA-65) evaluate as one
  // unit — their embedded classical/hash tokens are parameters, not separate primitives.
  // Everything else is split on common separators so suites like
  // "ECDHE-RSA-AES128-GCM-SHA256", "sha256WithRSAEncryption" and
  // "TLS 1.3 / AES-256-GCM / SHA-256" are judged component by component.
  const isPqUnit = /ML-?KEM|MLKEM|ML-?DSA|MLDSA|SLH-?DSA|\bLMS\b|XMSS/i.test(algo);
  // IANA suite names use '_' ("TLS_ECDHE_RSA_WITH_RC4_128_SHA"); '_' is a regex word char, so
  // \bDES\b / \bRC4\b / \bAES could never match inside them. Normalize to '-' first.
  const norm = isPqUnit ? algo : algo.replace(/_/g, '-');
  const parts = isPqUnit ? [algo] : norm.split(
    /\s*[\/,+|]\s*|[-\s]*WITH[-\s]*|-(?=(?:RSA|ECDSA|ECDHE?|DHE?|AES|SHA|CHACHA|3DES|DES|RC4|MD5|CAMELLIA|ARIA|SEED|IDEA|NULL)(?![A-Z]))|-(?=(?:AES|SHA|RC4|DES)\d)/i);
  const results: FipsResult[] = parts.filter(Boolean).map(p => evalPrimitive(p, f)).filter((x): x is FipsResult => !!x);

  // A cert/key row's hash_algorithm (e.g. sha1WithRSAEncryption's SHA-1) is part of the finding.
  if (f.hash_algorithm) {
    const h = evalPrimitive(String(f.hash_algorithm), f);
    if (h) results.push(h);
  }
  if (String(f.purpose || '') === 'key_establishment' && !results.some(x => KEX_RULES.has(x.ruleId))) {
    results.push(r('unknown', 'SP 800-56A Rev. 3', 'kex.undetermined',
      'The key-exchange method was not identified, so this key-establishment finding cannot be assessed as approved.'));
  }
  if (results.length === 0) {
    return r('unknown', '—', 'unrecognized', `Algorithm "${algo}" is not recognized by FIPS table ${FIPS_TABLE_VERSION}; status not determined.`);
  }
  // Worst first; on an approved/pq_approved tie keep pq_approved (the algorithm, not its hash).
  results.sort((x, y) => SEVERITY[y.status] - SEVERITY[x.status] || (x.status === 'pq_approved' ? -1 : y.status === 'pq_approved' ? 1 : 0));
  return results[0];
};

/** Short console/report label for a status. */
export const FIPS_STATUS_LABEL: Record<FipsStatus, string> = {
  pq_approved: 'PQC approved',
  approved: 'FIPS approved',
  acceptable: 'Approved — sunset scheduled',
  restricted: 'Legacy use only',
  disallowed: 'Disallowed',
  non_fips: 'Not FIPS-approved',
  not_applicable: 'Module (see CMVP)',
  unknown: 'Not determined',
};
