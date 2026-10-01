/**
 * Crypto control catalog (BILL-4b) — the quantum-relevant control set, cross-walked
 * across NIST frameworks, seeded from CryptoControlsMapping.xlsx. One catalog drives
 * project control assessment, SSP control-implementation, and POA&M generation.
 *
 * Frameworks here are the underlying NIST standards only (CMMC = 800-171 r2,
 * FedRAMP = 800-53 r5 are handled in the separate CMMC product).
 */

export type Framework = 'nist-800-53r5' | 'nist-800-171r2' | 'nist-800-171r3';

export const FRAMEWORKS: { id: Framework; label: string; short: string }[] = [
  { id: 'nist-800-53r5', label: 'NIST SP 800-53 Rev 5', short: '800-53 r5' },
  { id: 'nist-800-171r2', label: 'NIST SP 800-171 Rev 2', short: '800-171 r2' },
  { id: 'nist-800-171r3', label: 'NIST SP 800-171 Rev 3', short: '800-171 r3' },
];

export const isFramework = (s: any): s is Framework =>
  FRAMEWORKS.some(f => f.id === s);

// 'kind' drives the CBOM auto-assessment heuristic for each control.
export type ControlKind = 'protection' | 'transmission' | 'keymgmt' | 'pki' | 'authn' | 'authenticator' | 'flaw';

export interface CryptoControl {
  key: string;        // stable internal key (the 800-53 id)
  title: string;
  kind: ControlKind;
  fips: string;       // FIPS 203/204/205 application & relevance
  ids: Record<Framework, string>;
  implicit: Partial<Record<Framework, boolean>>; // control is "implicit/covered-under" in that framework
}

export const CRYPTO_CONTROLS: CryptoControl[] = [
  {
    key: 'SC-8', title: 'Transmission Confidentiality and Integrity', kind: 'transmission',
    fips: 'FIPS 203 (ML-KEM): secure communication tunnels (TLS 1.3, IPsec) via hybrid or native key encapsulation to prevent interception and "harvest now, decrypt later" attacks.',
    ids: { 'nist-800-53r5': 'SC-8', 'nist-800-171r2': '3.13.8', 'nist-800-171r3': '03.13.08' }, implicit: {},
  },
  {
    key: 'SC-12', title: 'Cryptographic Key Establishment and Management', kind: 'keymgmt',
    fips: 'FIPS 203 (ML-KEM): secure generation, exchange, distribution, and storage lifecycle of lattice-based shared secrets and asymmetric key pairs.',
    ids: { 'nist-800-53r5': 'SC-12', 'nist-800-171r2': '3.13.10', 'nist-800-171r3': '03.13.10' }, implicit: {},
  },
  {
    key: 'SC-13', title: 'Cryptographic Protection', kind: 'protection',
    fips: 'FIPS 203/204/205: core mandate — deployed cryptographic modules are FIPS-validated and support approved post-quantum algorithms.',
    ids: { 'nist-800-53r5': 'SC-13', 'nist-800-171r2': '3.13.11', 'nist-800-171r3': '03.13.11' }, implicit: {},
  },
  {
    key: 'SC-17', title: 'Public Key Infrastructure (PKI) Certificates', kind: 'pki',
    fips: 'FIPS 204 (ML-DSA) & 205 (SLH-DSA): issuance, validation, and chain of trust for X.509 certs, enterprise CAs, and device identity certs using quantum-resistant signatures.',
    ids: { 'nist-800-53r5': 'SC-17', 'nist-800-171r2': '3.13.11', 'nist-800-171r3': '03.13.11' },
    implicit: { 'nist-800-171r2': true, 'nist-800-171r3': true },
  },
  {
    key: 'IA-5', title: 'Authenticator Management', kind: 'authn',
    fips: 'FIPS 204 (ML-DSA): cryptographic credentials, public-key authenticators, and token backends resistant to quantum spoofing.',
    ids: { 'nist-800-53r5': 'IA-5', 'nist-800-171r2': '3.5.2', 'nist-800-171r3': '03.05.02' }, implicit: {},
  },
  {
    key: 'IA-7', title: 'Cryptographic Module Authentication', kind: 'authenticator',
    fips: 'FIPS 204 (ML-DSA): hardware tokens, smart cards, or cryptographic assertion mechanisms relying on digital-signature verification.',
    ids: { 'nist-800-53r5': 'IA-7', 'nist-800-171r2': '3.5.2', 'nist-800-171r3': '03.05.02' },
    implicit: { 'nist-800-171r2': true, 'nist-800-171r3': true },
  },
  {
    key: 'SI-2', title: 'Flaw Remediation', kind: 'flaw',
    fips: 'FIPS 204 (ML-DSA) & 205 (SLH-DSA): code signing of software updates, patches, and firmware so remediation payloads cannot be forged in transit.',
    ids: { 'nist-800-53r5': 'SI-2', 'nist-800-171r2': '3.14.2', 'nist-800-171r3': '03.014.02' }, implicit: {},
  },
];

export interface ResolvedControl {
  key: string;
  controlId: string;   // the id in the chosen framework
  base53: string;      // the 800-53 anchor id
  title: string;
  kind: ControlKind;
  fips: string;
  implicit: boolean;
}

export const controlsForFramework = (fw: Framework): ResolvedControl[] =>
  CRYPTO_CONTROLS.map(c => ({
    key: c.key,
    controlId: c.ids[fw],
    base53: c.ids['nist-800-53r5'],
    title: c.title,
    kind: c.kind,
    fips: c.fips,
    implicit: !!c.implicit[fw],
  }));

export type ControlStatus = 'compliant' | 'non_compliant' | 'in_progress' | 'not_applicable';

/**
 * CBOM-driven auto-assessment. Given a control and the tenant's cryptographic posture,
 * suggest a starting status the assessor can then adjust.
 */
export const autoStatus = (
  c: ResolvedControl,
  posture: { total: number; vulnerable: number }
): ControlStatus => {
  if (c.implicit) return 'not_applicable';
  if (posture.total === 0) return 'in_progress'; // not yet assessed / no data
  return posture.vulnerable > 0 ? 'in_progress' : 'compliant';
};
