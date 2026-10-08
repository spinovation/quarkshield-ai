/**
 * Risk → control mapping (RMF / MGC attach point). Rule-based and INDICATIVE: it says
 * which controls a risk touches, never that a control is (in)effective or that the
 * tenant is (non-)compliant — that requires assessment evidence (design doc §16).
 *
 * Anchor: NIST SP 800-53 Rev 5. Crosswalks:
 *   - NIST SP 800-171 Rev 2 (from SP 800-171 r2 Appendix D); CMMC Level 2 uses the
 *     same 800-171 r2 requirement numbering.
 *   - FedRAMP Moderate: every control below is in the Rev 5 Moderate baseline, so the
 *     800-53 identifiers apply directly.
 * Supply-chain (SR / SA-15) controls have no 800-171 r2 counterpart and are omitted there.
 */

export const RULE_CONTROLS: Record<string, string[]> = {
  'TR-01': ['SI-2', 'RA-5', 'CM-8'],
  'TR-02': ['SI-2', 'AC-6'],
  'TR-03': ['SR-3', 'SR-11', 'SA-15', 'SI-2'],
  'TR-04': ['SC-8', 'SC-12', 'SC-13'],
  'TR-05': ['SC-8', 'SC-13', 'SC-23'],
  'TR-06': ['IA-5', 'AC-17', 'SC-12'],
  'TR-07': ['SC-12', 'SC-17', 'IA-5(2)'],
  'TR-08': ['AC-4', 'SC-7', 'SI-4'],
  'TR-09': ['SI-2', 'CP-9', 'CP-10', 'IR-4'],
};

export const CONTROL_TITLES: Record<string, string> = {
  'SI-2': 'Flaw Remediation', 'RA-5': 'Vulnerability Monitoring and Scanning', 'CM-8': 'System Component Inventory',
  'AC-6': 'Least Privilege', 'SR-3': 'Supply Chain Controls and Processes', 'SR-11': 'Component Authenticity',
  'SA-15': 'Development Process, Standards, and Tools', 'SC-8': 'Transmission Confidentiality and Integrity',
  'SC-12': 'Cryptographic Key Establishment and Management', 'SC-13': 'Cryptographic Protection',
  'SC-23': 'Session Authenticity', 'IA-5': 'Authenticator Management', 'IA-5(2)': 'Public Key-Based Authentication',
  'AC-17': 'Remote Access', 'SC-17': 'Public Key Infrastructure Certificates', 'AC-4': 'Information Flow Enforcement',
  'SC-7': 'Boundary Protection', 'SI-4': 'System Monitoring',
  'CP-9': 'System Backup', 'CP-10': 'System Recovery and Reconstitution', 'IR-4': 'Incident Handling',
};

const NIST_171R2: Record<string, string[]> = {
  'SI-2': ['3.14.1'], 'RA-5': ['3.11.2', '3.11.3'], 'CM-8': ['3.4.1'], 'AC-6': ['3.1.5', '3.1.7'],
  'SC-8': ['3.13.8'], 'SC-12': ['3.13.10'], 'SC-13': ['3.13.11'], 'SC-23': ['3.13.15'],
  'IA-5': ['3.5.2'], 'IA-5(2)': ['3.5.2'], 'AC-17': ['3.1.12', '3.1.13'], 'SC-17': ['3.13.11'],
  'AC-4': ['3.1.3'], 'SC-7': ['3.13.1', '3.13.5'], 'SI-4': ['3.14.6', '3.14.7'],
  'IR-4': ['3.6.1'],   // CP-9 / CP-10 have no 800-171 r2 counterpart
};

export interface FrameworkDef { id: string; label: string; map: (c: string) => string[] }

export const FRAMEWORKS: FrameworkDef[] = [
  { id: 'nist-800-53r5', label: 'NIST 800-53 r5', map: c => [c] },
  { id: 'fedramp-moderate', label: 'FedRAMP Moderate', map: c => [c] },
  { id: 'nist-800-171r2', label: 'NIST 800-171 r2', map: c => NIST_171R2[c] || [] },
  { id: 'cmmc-l2', label: 'CMMC Level 2', map: c => NIST_171R2[c] || [] },
];

/** Path risks touch the entry threat's controls plus the exfiltration controls. */
export const controlsForRisk = (ruleId: string, isPath: boolean): string[] =>
  [...new Set([...(RULE_CONTROLS[ruleId] || []), ...(isPath ? RULE_CONTROLS['TR-08'] : [])])];
