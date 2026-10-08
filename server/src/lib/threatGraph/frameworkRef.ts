/**
 * Framework reference data used by the rule catalog.
 *
 * ATT&CK: a curated subset of MITRE ATT&CK® Enterprise techniques referenced by
 * rules.ts. Phase 2 replaces this with the full, pinned STIX bundle seeded into
 * ref_attack_techniques. Techniques are POTENTIAL techniques derived from a
 * discovered exposure — never a claim of observed adversary activity.
 * © The MITRE Corporation. Reproduced and distributed with the permission of
 * The MITRE Corporation (ATT&CK Terms of Use).
 */
import { KillChainPhase, StrideLetter, ThreatCategory } from './types';

export interface AttackTechnique { id: string; name: string; tactics: string[] }

export const ATTACK_TECHNIQUES: Record<string, AttackTechnique> = {
  T1190: { id: 'T1190', name: 'Exploit Public-Facing Application', tactics: ['initial-access'] },
  T1203: { id: 'T1203', name: 'Exploitation for Client Execution', tactics: ['execution'] },
  T1210: { id: 'T1210', name: 'Exploitation of Remote Services', tactics: ['lateral-movement'] },
  T1068: { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactics: ['privilege-escalation'] },
  'T1195.001': { id: 'T1195.001', name: 'Supply Chain Compromise: Compromise Software Dependencies and Development Tools', tactics: ['initial-access'] },
  T1557: { id: 'T1557', name: 'Adversary-in-the-Middle', tactics: ['credential-access', 'collection'] },
  T1040: { id: 'T1040', name: 'Network Sniffing', tactics: ['credential-access', 'discovery'] },
  'T1552.004': { id: 'T1552.004', name: 'Unsecured Credentials: Private Keys', tactics: ['credential-access'] },
  'T1021.004': { id: 'T1021.004', name: 'Remote Services: SSH', tactics: ['lateral-movement'] },
  T1649: { id: 'T1649', name: 'Steal or Forge Authentication Certificates', tactics: ['credential-access'] },
  T1600: { id: 'T1600', name: 'Weaken Encryption', tactics: ['defense-evasion'] },
  T1041: { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactics: ['exfiltration'] },
  T1213: { id: 'T1213', name: 'Data from Information Repositories', tactics: ['collection'] },
  T1486: { id: 'T1486', name: 'Data Encrypted for Impact', tactics: ['impact'] },
};

export const STRIDE_LABELS: Record<StrideLetter, string> = {
  S: 'Spoofing', T: 'Tampering', R: 'Repudiation',
  I: 'Information Disclosure', D: 'Denial of Service', E: 'Elevation of Privilege',
};

/** Lockheed Martin Cyber Kill Chain® phases, in order. */
export const KILL_CHAIN: { id: KillChainPhase; label: string }[] = [
  { id: 'reconnaissance', label: 'Reconnaissance' },
  { id: 'weaponization', label: 'Weaponization' },
  { id: 'delivery', label: 'Delivery' },
  { id: 'exploitation', label: 'Exploitation' },
  { id: 'installation', label: 'Installation' },
  { id: 'command_and_control', label: 'Command & Control' },
  { id: 'actions_on_objectives', label: 'Actions on Objectives' },
];

export const THREAT_CATEGORY_LABELS: Record<ThreatCategory, string> = {
  credential_theft: 'Credential theft',
  vulnerable_software_exploitation: 'Exploitation of vulnerable software',
  privilege_escalation: 'Privilege escalation',
  data_exfiltration: 'Data exfiltration',
  ransomware_malware: 'Ransomware / malware',
  api_abuse: 'API abuse',
  supply_chain_compromise: 'Supply-chain compromise',
  man_in_the_middle: 'Man-in-the-middle',
  cryptographic_compromise: 'Cryptographic compromise',
  insider_threat: 'Insider threat',
};
