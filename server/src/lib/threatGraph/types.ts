/**
 * Threat & Risk Graph — canonical object model (design doc §12, plan rev 2 §3).
 *
 * The engine is a pure function over SourceData (rows already collected by the
 * fleet agent, SBOM, git scans, PKI connectors and PQC proxies) and returns a
 * GraphResult. IDs are deterministic so that remediation state, context overrides,
 * framework tags and the future MGC/RMF control links survive every rebuild.
 */

// ---------------------------------------------------------------------------
// Source rows (what store.ts loads from the existing tables)
// ---------------------------------------------------------------------------

export interface SrcMachine {
  id: string;
  hostname: string;
  computer_name?: string | null;
  os?: string | null;
  ip?: string | null;
  public_ip?: string | null;
  group_name?: string | null;
}

/** A row of the existing `assets` table — a CBOM crypto finding, not an asset. */
export interface SrcCryptoFinding {
  id: string;
  machine_id?: string | null;
  type: string;
  name: string;
  algorithm: string;
  key_size?: number | null;
  hash_algorithm?: string | null;
  is_vulnerable: boolean;
  risk_level: string;
  description?: string | null;
  recommendation?: string | null;
  explainer?: string | null;
  path?: string | null;
  source?: string | null;
  source_ref?: string | null;
}

export interface SrcVuln {
  cveId: string;
  title?: string;
  cvssScore?: number;
  severity?: string;
  fixedVersion?: string;
  remediationCmd?: string;
  description?: string;
  cwe?: string | string[];
}

export interface SrcComponent {
  id: string;
  source?: string | null;
  source_ref?: string | null;
  file_path?: string | null;
  name: string;
  version: string;
  ecosystem: string;
  purl?: string | null;
  vulnerabilities: SrcVuln[];
}

export interface SrcGitScan {
  id: string;
  repo_url: string;
  repo_name: string;
  branch?: string | null;
  findings: Array<{
    id: string;
    category: string;
    filePath: string;
    assetName: string;
    algorithm: string;
    keySize?: number;
    isVulnerable: boolean;
    riskLevel: string;
    recommendation?: string;
  }>;
}

export interface SrcPkiConnector {
  id: string;
  name: string;
  provider: string;
  endpoint_url?: string | null;
}

export interface SrcPkiAsset {
  id: string;
  connector_id: string;
  asset_name: string;
  asset_type: string;
  algorithm: string;
  key_size?: number | null;
  is_vulnerable: boolean;
  risk_level: string;
  raw_metadata?: Record<string, unknown> | null;
}

export interface SrcProxy {
  id: string;
  name: string;
  listen_port: number;
  upstream_url: string;
  tls_curve?: string | null;
  status?: string | null;
}

export interface ContextOverride {
  asset_id: string;
  criticality?: number | null;
  data_classification?: DataClassification | null;
  environment?: string | null;
}

/** Exploitation-likelihood intelligence for the tenant's CVEs (CISA KEV, FIRST EPSS). */
export interface KevIntel {
  vulnerability_name?: string | null; date_added?: string | null; due_date?: string | null;
  ransomware_use: boolean; required_action?: string | null; cwes?: string[];
}
export interface ThreatIntel {
  kev: Record<string, KevIntel>;
  epss: Record<string, { epss: number; percentile: number }>;
}

export interface SourceData {
  tenant: string;
  intel?: ThreatIntel;
  machines: SrcMachine[];
  cryptoFindings: SrcCryptoFinding[];
  components: SrcComponent[];
  gitScans: SrcGitScan[];
  pkiConnectors: SrcPkiConnector[];
  pkiAssets: SrcPkiAsset[];
  proxies: SrcProxy[];
  overrides: ContextOverride[];
}

// ---------------------------------------------------------------------------
// Graph objects
// ---------------------------------------------------------------------------

export type AssetType =
  | 'endpoint' | 'server' | 'service' | 'database' | 'tls_endpoint' | 'proxy'
  | 'kms' | 'repo' | 'network_segment';

export type DataClassification = 'public' | 'internal' | 'sensitive' | 'cui';
export type Confidence = 'high' | 'medium' | 'low';
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface TrAsset {
  id: string;
  type: AssetType;
  name: string;
  environment: string | null;
  criticality: number;               // 1..4
  data_classification: DataClassification;
  internet_exposed: boolean;
  exposed_via?: string | null;       // proxy asset that publishes this asset to the internet
  groups?: string[];                 // Workstation Groups (scope filter); services inherit their host's
  context_origin: 'inferred' | 'override';
  source_table: string;
  source_id: string;
  inference: string[];               // human-readable reasons for type/context
}

export type RelKind =
  | 'connects_to' | 'serves' | 'stores_data_in' | 'authenticates_via' | 'trusts'
  | 'ssh_to' | 'deployed_from' | 'network_adjacent' | 'runs';

export interface TrRelationship {
  id: string;
  from_asset: string;
  to_asset: string;
  kind: RelKind;
  protocol: string | null;
  port: number | null;
  confidence: Confidence;
  rule_id: string;
  evidence: Record<string, unknown>;
}

export type CryptoPurpose =
  | 'ssh_authentication' | 'tls_certificate' | 'key_establishment'
  | 'rsa_key_transport' | 'code_or_data_signing' | 'ca_trust_anchor'
  | 'symmetric' | 'configuration' | 'unknown';

/** Normalized crypto finding (projection over assets / pki_synced_assets / git findings). */
export interface CryptoNode {
  id: string;                        // cf:<assets.id> | pki:<id> | git:<scan>:<finding>
  asset_id: string;
  name: string;
  algorithm: string;
  key_size: number | null;
  purpose: CryptoPurpose;
  quantum_vulnerable: boolean;
  classically_weak: boolean;
  hndl_relevant: boolean;
  risk_level: string;
  recommendation: string;
}

export interface ComponentNode {
  id: string;                        // cmp:<sbom.id>
  asset_id: string;
  name: string;
  version: string;
  ecosystem: string;
  purl: string | null;
}

export interface VulnNode {
  id: string;                        // vuln:<sbom.id>:<cveId>
  component_id: string;
  asset_id: string;
  cve: string;
  cvss: number;
  severity: string;
  title: string;
  fixed_version: string | null;
  remediation_cmd: string | null;
  cwe: string[];
  kev: KevIntel | null;              // listed in CISA KEV (exploited in the wild)
  epss: number | null;               // FIRST EPSS probability (next 30 days)
  epss_percentile: number | null;
}

export type ThreatCategory =
  | 'credential_theft' | 'vulnerable_software_exploitation' | 'privilege_escalation'
  | 'data_exfiltration' | 'ransomware_malware' | 'api_abuse' | 'supply_chain_compromise'
  | 'man_in_the_middle' | 'cryptographic_compromise' | 'insider_threat';

export type StrideLetter = 'S' | 'T' | 'R' | 'I' | 'D' | 'E';

export type KillChainPhase =
  | 'reconnaissance' | 'weaponization' | 'delivery' | 'exploitation'
  | 'installation' | 'command_and_control' | 'actions_on_objectives';

export interface TrThreat {
  id: string;
  rule_id: string;
  rule_version: number;
  category: ThreatCategory;
  actor: string;
  intent: string;
  title: string;
  description: string;
  asset_id: string;
  driver_ids: string[];              // vuln:/cf:/cmp: ids that justify the threat
  likelihood: number;                // 1..4 before path context
  stride: StrideLetter[];
  attack: string[];                  // ATT&CK technique ids (potential, derived from exposure)
  kill_chain: KillChainPhase;
  rationale: string;
}

export interface PathHop {
  asset_id: string;
  via?: string;                      // relationship id used to arrive here
  threat_ids: string[];
  kill_chain: KillChainPhase;
}

export interface TrAttackPath {
  id: string;
  entry_threat_id: string;
  goal_asset_id: string;
  hops: PathHop[];
  confidence: Confidence;
  likelihood: number;
  impact: number;
  path_risk: number;                 // 1..16
  level: RiskLevel;
}

export interface TrRisk {
  id: string;
  asset_id: string;                  // asset whose impact is at stake
  threat_id: string;
  attack_path_id: string | null;
  likelihood: number;
  impact: number;
  inherent_score: number;
  residual_score: number;
  level: RiskLevel;
  residual_level: RiskLevel;
  priority: number;                  // 1 = fix first
  drivers: string[];
  remediation_ids: string[];
  controls: string[];                // NIST SP 800-53 r5 controls this risk touches (indicative)
}

export type RemediationType = 'patch' | 'rotate_key' | 'migrate_crypto' | 'replace_certificate' | 'harden_config';
export type RemediationStatus = 'open' | 'in_progress' | 'done' | 'verified' | 'risk_accepted';

export interface TrRemediation {
  id: string;
  action: string;
  action_type: RemediationType;
  target_id: string;                 // driver it fixes
  asset_id: string;
  command: string | null;
  risk_ids: string[];
  breaks_paths: number;
  kev?: boolean;                     // fixes at least one CISA KEV vulnerability
  kev_due_date?: string | null;      // earliest CISA remediation due date among them
  epss_max?: number | null;
}

export interface RemediationState {
  id: string;
  owner?: string | null;
  target_date?: string | null;
  status: RemediationStatus;
}

export interface FrameworkTag {
  object_type: 'threat' | 'path_hop' | 'asset' | 'risk';
  object_id: string;
  framework: 'stride' | 'attack' | 'killchain';
  ref: string;
  rationale: string;
  rule_id: string;
}

export interface GraphResult {
  tenant: string;
  assets: TrAsset[];
  relationships: TrRelationship[];
  crypto: CryptoNode[];
  components: ComponentNode[];
  vulns: VulnNode[];
  threats: TrThreat[];
  paths: TrAttackPath[];
  risks: TrRisk[];
  remediations: TrRemediation[];
  tags: FrameworkTag[];
  stats: {
    overall_risk_score: number;      // 0..100
    exposed_assets: number;
    quantum_exposed_assets: number;
  };
}
