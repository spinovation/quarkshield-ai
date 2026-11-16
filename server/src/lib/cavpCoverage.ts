/**
 * CAVP coverage: is the algorithm an asset uses on its module's approved-algorithm list?
 * (docs/CMVP_AND_FIPS_COMPLIANCE_MAPPING.md §3.2, Stage 6).
 *
 * CMVP validates a module; CAVP validates each algorithm implementation inside it. A module
 * can hold a current certificate and still never have had a given algorithm tested. This
 * file answers the narrower question for one asset, from the list NIST prints on the
 * module's certificate page (cavpData.ts).
 *
 * Rules that keep the answer honest:
 *  - `covered` / `not_covered` are only ever stated against a certificate that was actually
 *    reported for the asset's module (Stage 3 provider certificate, or a Stage 5 host module
 *    that passed the identity + FIPS-mode gate). No certificate, no answer.
 *  - A certificate with no list in cavpData.ts gives `unknown`, never `not_covered`.
 *  - An asset whose algorithm cannot be turned into a CAVP algorithm name gives `unknown`.
 *  - `unknown` never changes a verdict. Only `not_covered` refines `compliant`.
 *  - The check is at the level NIST's certificate page lists: algorithm and, where the asset
 *    states one, mode. Key sizes, curves and other tested capabilities live on the individual
 *    CAVP validations and are NOT checked here. Results say so.
 */
import { CAVP_BY_CERTIFICATE, CAVP_DATA_READ } from './cavpData';

/** Bump with cavpData.ts. Stamped on every export that carries a coverage result. */
export const CAVP_MAP_VERSION = CAVP_DATA_READ;

export type CavpState = 'covered' | 'not_covered' | 'unknown';

export interface CavpInput {
  algorithm?: string | null;
  hash_algorithm?: string | null;
  purpose?: string | null;
}

/** One thing the asset needs the module to have had validated. */
export interface CavpNeed {
  label: string;      // what the asset uses, in plain words ("AES-GCM", "RSA signature")
  pattern: RegExp;    // matches the NIST algorithm names that satisfy it
  family?: boolean;   // true when only the family is known (e.g. AES with no mode observed)
}

export interface CavpMatch { need: string; algorithms: string[]; validations: string[] }

export interface CavpResult {
  state: CavpState;
  certId?: string;          // the certificate whose list decided the result
  matched: CavpMatch[];
  missing: string[];        // needs with no entry on the list (only when not_covered)
  familyOnly: boolean;      // at least one need was matched on family, mode not observed
  note: string;
  mapVersion: string;
}

const need = (label: string, pattern: RegExp, family = false): CavpNeed => ({ label, pattern, family });

const HASH_NAMES: [RegExp, string][] = [
  [/SHA-?3-?(224|256|384|512)/g, 'SHA3-$1'],
  [/SHAKE-?(128|256)/g, 'SHAKE-$1'],
  [/SHA-?2?-?512[\/-](224|256)/g, 'SHA2-512/$1'],
  [/SHA-?2?-?(224|256|384|512)/g, 'SHA2-$1'],
];

// Hash functions named in a string, as NIST names them. "SHA" alone or "SHA1" is SHA-1.
const hashesIn = (s: string): string[] => {
  let rest = s;
  const out: string[] = [];
  for (const [re, name] of HASH_NAMES) {
    rest = rest.replace(re, (_m, n) => { out.push(name.replace('$1', n)); return ' '; });
  }
  if (/SHA-?1(?!\d)|SHA(?![-\dK])/.test(rest)) out.push('SHA-1');
  return [...new Set(out)];
};

const exact = (name: string): RegExp => new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&')}$`);

/**
 * What an asset needs from its module, derived from the recorded algorithm text.
 * Returns [] when nothing CAVP-testable can be recognised (the result is then `unknown`).
 */
export const cavpNeeds = (input: CavpInput): CavpNeed[] => {
  const a = String(input.algorithm || '').toUpperCase().replace(/_/g, '-');
  const h = String(input.hash_algorithm || '').toUpperCase().replace(/_/g, '-');
  const purpose = String(input.purpose || '');
  if (!a.trim()) return [];
  const needs: CavpNeed[] = [];

  // Post-quantum names are one unit; their embedded tokens (SHA2, 768, X25519) are parameters.
  if (/ML-?KEM/.test(a)) return [need('ML-KEM', /^ML-KEM /)];
  if (/ML-?DSA/.test(a)) return [need('ML-DSA', /^ML-DSA /)];
  if (/SLH-?DSA/.test(a)) return [need('SLH-DSA', /^SLH-DSA /)];
  if (/\bLMS\b|\bHSS\b/.test(a)) return [need('LMS', /^LMS /)];
  if (/XMSS/.test(a)) return [need('XMSS', /^XMSS/)];

  // Symmetric ciphers.
  if (/AES/.test(a)) {
    const mode = a.match(/AES-?(?:128|192|256)?-?(GCM|CCM|CBC|CTR|ECB|CFB|OFB|XTS|KWP|KW|CMAC|GMAC)/)?.[1];
    if (mode === 'KW') needs.push(need('AES-KW', /^AES-KW$/));
    else if (mode) needs.push(need(`AES-${mode}`, new RegExp(`^AES-${mode}`)));
    else needs.push(need('AES (mode not observed)', /^AES-/, true));
  }
  if (/3DES|TDES|TDEA|DES-?EDE|TRIPLE-?DES/.test(a)) needs.push(need('Triple-DES', /^TDES-/, true));

  // Public-key algorithms. Order matters: ECDSA / EDDSA / ECDH contain "DSA" / "DH".
  const kex = purpose === 'key_establishment';
  const hasEcdh = /ECDHE?(?![A-Z])/.test(a);
  const hasEcdsa = /ECDSA/.test(a);
  const hasEd = /ED25519|ED448|EDDSA/.test(a);
  if (hasEcdh) needs.push(need('ECDH key agreement', /^KAS-ECC/));
  if (hasEcdsa) needs.push(need('ECDSA', /^ECDSA /));
  if (hasEd) needs.push(need('EdDSA', /^EDDSA /));
  if (!hasEcdh && !hasEcdsa && /(^|[^A-Z])(EC|ECC)([^A-Z]|$)|P-?(256|384|521)|SECP(256|384|521)R1|PRIME256V1|NISTP(256|384|521)/.test(a)) {
    needs.push(kex ? need('ECDH key agreement', /^KAS-ECC/) : need('ECDSA', /^ECDSA /));
  }
  if (/RSA/.test(a)) {
    // RSA beside (EC)DHE in a suite is the signature; RSA alone for key establishment is transport.
    if (kex && !hasEcdh && !/(^|[^A-Z])DHE?([^A-Z]|$)/.test(a)) needs.push(need('RSA key transport', /^(KTS-IFC|KAS-IFC|RSA Decryption Primitive)/));
    else needs.push(need('RSA signature', /^RSA (SigGen|SigVer|KeyGen|Signature Primitive)/));
  }
  if (!hasEcdh && /(^|[^A-Z])DHE?([^A-Z]|$)|FFDHE|DIFFIE/.test(a)) needs.push(need('Diffie-Hellman key agreement', /^(KAS-FFC|Safe Primes)/));
  if (!hasEcdsa && !hasEd && /(^|[^A-Z])DSA([^A-Z]|$)|(^|[^A-Z])DSS([^A-Z]|$)/.test(a)) needs.push(need('DSA', /^DSA /));

  // Key derivation.
  if (/PBKDF/.test(a)) needs.push(need('PBKDF', /^PBKDF$/));
  if (/HKDF/.test(a)) needs.push(need('HKDF', /^(KDA HKDF|TLS v1\.3 KDF)/));

  // Hashes and MACs. A hash named beside HMAC is the HMAC's hash, not a second need.
  const hashes = [...new Set([...hashesIn(a), ...hashesIn(h)])];
  if (/HMAC/.test(a)) {
    if (hashes.length === 0) needs.push(need('HMAC (hash not observed)', /^HMAC-/, true));
    for (const x of hashes) needs.push(need(`HMAC-${x}`, exact(`HMAC-${x}`)));
  } else {
    for (const x of hashes) needs.push(need(x, exact(x)));
  }
  return needs;
};

const NO_CERT = 'No CMVP certificate is reported for this asset, so there is no approved-algorithm list to check against.';
const GRANULARITY = 'Checked against the algorithm list on the NIST certificate page: algorithm and mode only. Key sizes, curves and other tested capabilities are not checked.';

const unknown = (note: string, certId?: string): CavpResult =>
  ({ state: 'unknown', certId, matched: [], missing: [], familyOnly: false, note, mapVersion: CAVP_MAP_VERSION });

/**
 * Coverage of one asset against the certificate(s) reported for its module.
 * With several certificates, one that covers every need is enough; `not_covered` needs every
 * certificate to have a list and none of them to cover the asset.
 */
export const cavpCoverage = (certIds: string[] | undefined, input: CavpInput): CavpResult => {
  const ids = (certIds || []).filter(Boolean);
  if (ids.length === 0) return unknown(NO_CERT);
  const needs = cavpNeeds(input);
  if (needs.length === 0) {
    return unknown('The recorded algorithm could not be mapped to a CAVP algorithm name, so coverage was not determined.', ids[0]);
  }

  let best: CavpResult | undefined;
  let anyWithoutList = false;
  for (const certId of ids) {
    const list = CAVP_BY_CERTIFICATE[certId];
    if (!list) { anyWithoutList = true; continue; }
    const names = Object.keys(list);
    const matched: CavpMatch[] = [];
    const missing: string[] = [];
    for (const n of needs) {
      const hit = names.filter(x => n.pattern.test(x));
      if (hit.length === 0) { missing.push(n.label); continue; }
      matched.push({ need: n.label, algorithms: hit, validations: [...new Set(hit.flatMap(x => list[x]))] });
    }
    const familyOnly = needs.some(n => n.family);
    if (missing.length === 0) {
      return {
        state: 'covered', certId, matched, missing: [], familyOnly, mapVersion: CAVP_MAP_VERSION,
        note: `${familyOnly ? 'On the list of certificate' : 'Algorithm and mode are on the list of certificate'} #${certId}${familyOnly ? ' at family level; the mode in use was not observed' : ''}. ${GRANULARITY}`,
      };
    }
    if (!best || missing.length < best.missing.length) {
      best = {
        state: 'not_covered', certId, matched, missing, familyOnly, mapVersion: CAVP_MAP_VERSION,
        note: `Not on the approved-algorithm list of certificate #${certId}: ${missing.join(', ')}. The module is validated, but this algorithm is not shown as tested in it. ${GRANULARITY}`,
      };
    }
  }
  if (!best || anyWithoutList) {
    return unknown(`No approved-algorithm list is held for certificate ${ids.filter(i => !CAVP_BY_CERTIFICATE[i]).map(i => `#${i}`).join(', ')} (CAVP data ${CAVP_MAP_VERSION}), so coverage was not determined.`, ids[0]);
  }
  return best;
};

/** Short form for the console and CBOM: at most a handful of validation numbers. */
export const cavpValidationsOf = (r: CavpResult, max = 8): string[] =>
  [...new Set(r.matched.flatMap(m => m.validations))].slice(0, max);
