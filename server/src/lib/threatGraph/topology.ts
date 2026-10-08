/**
 * Automatic topology inference (plan rev 2 §4, Phase 1 = server-side rules over data
 * QuarkShield already collects). There is NO manual relationship entry: every asset
 * and edge is derived by a rule and carries its confidence + evidence so the UI can
 * explain why it exists.
 *
 *   R1  PQC proxy upstream_url → fleet host / TLS endpoint           connects_to  high
 *   R2  certificate DNS names on a host ↔ probed/upstream endpoint   serves       medium
 *   R3  network_probe finding: host probed target                   connects_to  medium
 *   R4  host trust store / certs reference a PKI-connector asset    trusts       medium
 *   R5  repo ↔ host SBOM fingerprint overlap                         deployed_from medium|low
 *   R6  same Workstation Group / same egress IP                      network_adjacent low
 *   R7  internet exposure (public endpoint, reverse proxy)           asset flag
 *   R8  server packages in a host SBOM (postgres, nginx, sshd …)     runs         high
 *   R9  host role: server (runs a service, server OS/naming) vs user endpoint
 */
import crypto from 'crypto';
import {
  SourceData, TrAsset, TrRelationship, CryptoNode, ComponentNode, VulnNode, AssetType,
  Confidence, RelKind, DataClassification, SrcCryptoFinding,
} from './types';
import {
  classifyPurpose, isClassicalAsymmetric, isClassicallyWeak, isHndlRelevant, purposeRecommendation,
} from './cryptoPurpose';

export interface Topology {
  assets: TrAsset[];
  relationships: TrRelationship[];
  crypto: CryptoNode[];
  components: ComponentNode[];
  vulns: VulnNode[];
}

const shortHash = (s: string): string => crypto.createHash('sha1').update(s).digest('hex').slice(0, 12);

export const hostKey = (h: string): string =>
  (h || '').trim().toLowerCase().replace(/\.$/, '').replace(/\.local$/, '');

/** Parse "https://host:443/x", "host:8443", "host" → { host, port }. */
export const parseHostPort = (raw: string): { host: string; port: number | null } | null => {
  const s = (raw || '').trim();
  if (!s) return null;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `tcp://${s}`);
    const host = hostKey(u.hostname.replace(/^\[|\]$/g, ''));
    if (!host) return null;
    const defaultPort = u.protocol === 'https:' ? 443 : u.protocol === 'http:' ? 80 : null;
    return { host, port: u.port ? Number(u.port) : defaultPort };
  } catch {
    return null;
  }
};

export const isPrivateHost = (h: string): boolean => {
  const host = hostKey(h);
  if (!host || host === 'localhost' || !host.includes('.') && !host.includes(':')) return true;
  if (/^(127\.|10\.|192\.168\.|169\.254\.)/.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
  if (host === '::1' || /^f[cd][0-9a-f]{2}:/.test(host)) return true;
  return /\.(internal|lan|corp|home|localdomain|intranet)$/.test(host);
};

const normRepo = (u: string): string =>
  (u || '').trim().toLowerCase().replace(/^git@([^:]+):/, 'https://$1/').replace(/\.git$/, '').replace(/\/+$/, '');

const inferEnvironment = (...hints: (string | null | undefined)[]): string | null => {
  const s = hints.filter(Boolean).join(' ').toLowerCase();
  if (/\b(prod|prd|production)\b|-prod|prod-/.test(s)) return 'production';
  if (/\b(stag|stg|staging|uat|preprod)\b|-stg|stg-/.test(s)) return 'staging';
  if (/\b(dev|test|qa|sandbox|lab)\b|-dev|dev-/.test(s)) return 'development';
  return null;
};

/** R8: server packages that indicate a network service running on the host. */
const SERVICE_SIGNATURES: { re: RegExp; svc: string; type: AssetType; label: string }[] = [
  { re: /^(postgresql(\d+)?(-server)?|postgres)$/i, svc: 'postgresql', type: 'database', label: 'PostgreSQL' },
  { re: /^(mysql-server|mysql-community-server|mariadb-server|mariadb)$/i, svc: 'mysql', type: 'database', label: 'MySQL / MariaDB' },
  { re: /^(mongodb-org-server|mongodb-server|mongod|mongodb)$/i, svc: 'mongodb', type: 'database', label: 'MongoDB' },
  { re: /^(redis|redis-server)$/i, svc: 'redis', type: 'database', label: 'Redis' },
  { re: /^(mssql-server)$/i, svc: 'mssql', type: 'database', label: 'SQL Server' },
  { re: /^(elasticsearch|opensearch)$/i, svc: 'search', type: 'database', label: 'Elasticsearch / OpenSearch' },
  { re: /^(nginx|nginx-core)$/i, svc: 'nginx', type: 'service', label: 'nginx web server' },
  { re: /^(httpd|apache2)$/i, svc: 'httpd', type: 'service', label: 'Apache httpd' },
  { re: /^(openssh-server)$/i, svc: 'sshd', type: 'service', label: 'OpenSSH server' },
];
const SERVER_ECOSYSTEMS = new Set(['os_pkg', 'deb', 'rpm', 'apk', 'brew', 'chocolatey', 'winget']);

const SERVER_HOSTNAME = /(^|[-_.])(srv|server|prod|prd|db|sql|web|www|api|app|node|vm|k8s|gw|proxy|mail|dc)\d*([-_.]|$)/i;

const CONF_RANK: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };
const DNS_TOKEN = /\b(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

export const inferTopology = (src: SourceData): Topology => {
  const assets = new Map<string, TrAsset>();
  const rels = new Map<string, TrRelationship>();
  const cryptoNodes = new Map<string, CryptoNode>();
  const components: ComponentNode[] = [];
  const vulns: VulnNode[] = [];
  const hostIndex = new Map<string, string>();        // hostname/ip → asset id
  const repoIndex = new Map<string, string>();        // normalized repo url → asset id
  const endpointByHost = new Map<string, string[]>(); // endpoint host → ep asset ids

  const addAsset = (a: Omit<TrAsset, 'environment' | 'context_origin' | 'inference'> & {
    environment?: string | null; inference?: string[];
  }): TrAsset => {
    const existing = assets.get(a.id);
    if (existing) {
      existing.internet_exposed = existing.internet_exposed || a.internet_exposed;
      if (a.inference) existing.inference.push(...a.inference);
      return existing;
    }
    const full: TrAsset = { environment: null, context_origin: 'inferred', inference: [], ...a } as TrAsset;
    full.inference = [...(a.inference || [])];
    assets.set(a.id, full);
    return full;
  };

  const addRel = (
    from: string, to: string, kind: RelKind, confidence: Confidence, rule_id: string,
    evidence: Record<string, unknown>, protocol: string | null = null, port: number | null = null,
  ): void => {
    if (from === to) return;
    const id = `rel:${kind}:${from}>${to}`;
    const prev = rels.get(id);
    if (prev && CONF_RANK[prev.confidence] >= CONF_RANK[confidence]) return;
    rels.set(id, { id, from_asset: from, to_asset: to, kind, protocol, port, confidence, rule_id, evidence });
  };

  const getEndpoint = (host: string, port: number | null, reason: string): TrAsset => {
    const id = `ep:${host}${port ? `:${port}` : ''}`;
    const exposed = !isPrivateHost(host);
    const ep = addAsset({
      id, type: 'tls_endpoint', name: `${host}${port ? `:${port}` : ''}`,
      criticality: 2, data_classification: 'internal', internet_exposed: exposed,
      source_table: 'derived', source_id: id,
      inference: [reason, ...(exposed ? ['R7: publicly resolvable host name/IP → internet-exposed'] : [])],
    });
    const list = endpointByHost.get(host) || [];
    if (!list.includes(id)) list.push(id);
    endpointByHost.set(host, list);
    return ep;
  };

  const addCrypto = (id: string, assetId: string, f: {
    type: string; name: string; algorithm: string; key_size?: number | null; hash_algorithm?: string | null;
    description?: string | null; explainer?: string | null; key_usage?: string | null;
    is_vulnerable: boolean; risk_level: string;
  }): void => {
    const purpose = classifyPurpose(f);
    const qv = isClassicalAsymmetric(f.algorithm) || (f.is_vulnerable && purpose !== 'symmetric' && purpose !== 'configuration' && !/ml-?kem|ml-?dsa|slh/i.test(f.algorithm));
    const weak = isClassicallyWeak(f);
    cryptoNodes.set(id, {
      id, asset_id: assetId, name: f.name, algorithm: f.algorithm, key_size: f.key_size ?? null,
      purpose, quantum_vulnerable: qv, classically_weak: weak,
      hndl_relevant: isHndlRelevant(purpose, qv), risk_level: f.risk_level || 'medium',
      recommendation: purposeRecommendation(purpose, weak),
    });
  };

  // ---- Fleet machines -------------------------------------------------------
  for (const m of src.machines) {
    const id = `host:${m.id}`;
    addAsset({
      id, type: 'endpoint', name: m.hostname || m.computer_name || m.id,
      environment: inferEnvironment(m.group_name, m.hostname),
      criticality: 2, data_classification: 'internal', internet_exposed: false,
      source_table: 'fleet_machines', source_id: m.id,
      inference: ['Enrolled QuarkShield agent'],
      groups: m.group_name && !/^(ungrouped|default|none)$/i.test(m.group_name) ? [m.group_name] : [],
    });
    for (const k of [m.hostname, m.computer_name, m.ip]) if (k) hostIndex.set(hostKey(k), id);
  }

  // ---- R1: PQC proxies → upstream ------------------------------------------
  for (const p of src.proxies) {
    const id = `proxy:${p.id}`;
    addAsset({
      id, type: 'proxy', name: p.name, criticality: 3, data_classification: 'internal',
      internet_exposed: true, source_table: 'pqc_proxies', source_id: p.id,
      inference: ['R7: hybrid-PQC reverse proxy is the TLS front door → internet-exposed'],
    });
    addCrypto(`proxy-kex:${p.id}`, id, {
      type: 'key_exchange', name: `${p.name} - TLS key exchange`, algorithm: p.tls_curve || 'unknown',
      is_vulnerable: !/mlkem|ml-kem/i.test(p.tls_curve || ''), risk_level: /mlkem|ml-kem/i.test(p.tls_curve || '') ? 'low' : 'high',
    });
    const up = parseHostPort(p.upstream_url);
    if (!up) continue;
    const host = hostIndex.get(up.host);
    const target = host || getEndpoint(up.host, up.port, 'R1: PQC proxy upstream target').id;
    addRel(id, target, 'connects_to', 'high', 'R1', { proxy: p.name, upstream_url: p.upstream_url }, 'tls', up.port);
    // R7: the reverse proxy publishes its upstream to the internet.
    const t = assets.get(target)!;
    if (!t.internet_exposed) {
      t.internet_exposed = true;
      t.exposed_via = id;
      t.inference.push(`R7: internet-reachable through reverse proxy ${p.name}`);
    }
  }

  // ---- Crypto findings (existing `assets` table) -----------------------------
  const certFindingsByHost: { assetId: string; f: SrcCryptoFinding }[] = [];
  for (const f of src.cryptoFindings) {
    const machineAsset = f.machine_id ? `host:${f.machine_id}` : null;
    if (f.type === 'network_probe' && f.path) {
      // R3: the agent probed this target; the probe's crypto belongs to the endpoint.
      const hp = parseHostPort(f.path);
      if (!hp) continue;
      const ep = getEndpoint(hp.host, hp.port, 'R3: TLS endpoint probed by an agent');
      addCrypto(`cf:${f.id}`, ep.id, f);
      if (machineAsset && assets.has(machineAsset)) {
        addRel(machineAsset, ep.id, 'connects_to', 'medium', 'R3', { finding: f.name, target: f.path }, 'tls', hp.port);
      }
      const owner = hostIndex.get(hp.host);
      if (owner) addRel(owner, ep.id, 'serves', 'high', 'R2', { matched: 'endpoint host = enrolled host', host: hp.host }, 'tls', hp.port);
      continue;
    }
    let assetId: string | null = machineAsset && assets.has(machineAsset) ? machineAsset : null;
    if (!assetId && f.source_ref) {
      assetId = hostIndex.get(hostKey(f.source_ref)) || repoIndex.get(normRepo(f.source_ref)) || null;
    }
    if (!assetId) continue;
    addCrypto(`cf:${f.id}`, assetId, f);
    if (/certificate|keystore/.test(f.type) || /certificate/i.test(f.name)) certFindingsByHost.push({ assetId, f });
  }

  // ---- Git repositories -------------------------------------------------------
  for (const g of src.gitScans) {
    const key = normRepo(g.repo_url);
    const id = `repo:${shortHash(key)}`;
    addAsset({
      id, type: 'repo', name: g.repo_name || g.repo_url, criticality: 3, data_classification: 'internal',
      internet_exposed: false, source_table: 'git_scans', source_id: g.id,
      environment: inferEnvironment(g.branch),
      inference: ['Scanned source repository (software supply-chain entry)'],
    });
    repoIndex.set(key, id);
    for (const fd of g.findings || []) {
      if (fd.category === 'dependency') continue; // components come from the SBOM
      addCrypto(`git:${g.id}:${fd.id}`, id, {
        type: fd.category === 'private_key' ? (/ssh/i.test(fd.filePath) ? 'ssh_key' : 'private_key') : fd.category,
        name: fd.assetName || fd.filePath, algorithm: fd.algorithm, key_size: fd.keySize ?? null,
        description: fd.filePath, is_vulnerable: fd.isVulnerable, risk_level: fd.riskLevel,
      });
    }
  }

  // ---- PKI / KMS connectors ---------------------------------------------------
  const pkiNames: { kmsId: string; name: string }[] = [];
  for (const c of src.pkiConnectors) {
    const id = `kms:${c.id}`;
    addAsset({
      id, type: 'kms', name: c.name, criticality: 4, data_classification: 'sensitive',
      internet_exposed: false, source_table: 'pki_connectors', source_id: c.id,
      inference: [`${c.provider} key/certificate authority → crown-jewel trust service`],
    });
  }
  for (const a of src.pkiAssets) {
    const kmsId = `kms:${a.connector_id}`;
    if (!assets.has(kmsId)) continue;
    const usage = String((a.raw_metadata as any)?.KeyUsage || (a.raw_metadata as any)?.keyUsage || '');
    addCrypto(`pki:${a.id}`, kmsId, {
      type: a.asset_type, name: a.asset_name, algorithm: a.algorithm, key_size: a.key_size ?? null,
      key_usage: usage, is_vulnerable: a.is_vulnerable, risk_level: a.risk_level,
    });
    if ((a.asset_name || '').length >= 4) pkiNames.push({ kmsId, name: a.asset_name.toLowerCase() });
  }

  // ---- R2 / R4: certificate DNS names and PKI references ----------------------
  for (const { assetId, f } of certFindingsByHost) {
    const text = `${f.name} ${f.description || ''}`;
    for (const token of new Set((text.match(DNS_TOKEN) || []).map(t => hostKey(t.replace(/^\*\./, ''))))) {
      for (const epId of endpointByHost.get(token) || []) {
        addRel(assetId, epId, 'serves', 'medium', 'R2', { certificate: f.name, dns_name: token }, 'tls', null);
      }
    }
    const lower = text.toLowerCase();
    for (const p of pkiNames) {
      if (lower.includes(p.name)) addRel(assetId, p.kmsId, 'trusts', 'medium', 'R4', { certificate: f.name, pki_asset: p.name });
    }
  }

  // ---- SBOM components, vulnerabilities, R8 services --------------------------
  const compSets = new Map<string, Set<string>>();
  for (const c of src.components) {
    const ref = c.source_ref || '';
    let assetId = hostIndex.get(hostKey(ref)) || repoIndex.get(normRepo(ref)) || null;
    if (!assetId && ref) {
      const id = `sys:${shortHash(ref.toLowerCase())}`;
      assetId = addAsset({
        id, type: 'service', name: ref, criticality: 2, data_classification: 'internal',
        internet_exposed: false, source_table: 'sbom_components', source_id: ref,
        inference: [`System inferred from SBOM source "${c.source || 'unknown'}"`],
      }).id;
    }
    if (!assetId) continue;
    const compId = `cmp:${c.id}`;
    components.push({
      id: compId, asset_id: assetId, name: c.name, version: c.version, ecosystem: c.ecosystem, purl: c.purl || null,
    });
    const set = compSets.get(assetId) || new Set<string>();
    set.add(`${c.ecosystem}/${c.name}@${c.version}`.toLowerCase());
    compSets.set(assetId, set);

    for (const v of c.vulnerabilities || []) {
      const cve = (v.cveId || '').trim();
      if (!cve || cve.toUpperCase() === 'CLEAN' || /REMEDIATED/i.test(v.title || '') || !(Number(v.cvssScore) > 0)) continue;
      vulns.push({
        id: `vuln:${c.id}:${cve}`, component_id: compId, asset_id: assetId, cve,
        cvss: Number(v.cvssScore) || 0, severity: (v.severity || 'medium').toLowerCase(), title: v.title || cve,
        fixed_version: v.fixedVersion || null, remediation_cmd: v.remediationCmd || null,
        cwe: Array.isArray(v.cwe) ? v.cwe : v.cwe ? [v.cwe] : [],
      });
    }

    const host = assets.get(assetId);
    if (host?.source_table === 'fleet_machines' && SERVER_ECOSYSTEMS.has((c.ecosystem || '').toLowerCase())) {
      const sig = SERVICE_SIGNATURES.find(s => s.re.test(c.name));
      if (sig) {
        const svcId = `svc:${host.source_id}:${sig.svc}`;
        addAsset({
          id: svcId, type: sig.type, name: `${sig.label} on ${host.name}`,
          environment: host.environment, criticality: sig.type === 'database' ? 4 : 2,
          data_classification: sig.type === 'database' ? 'sensitive' : 'internal',
          internet_exposed: false, source_table: 'sbom_components', source_id: c.id,
          inference: [`R8: server package ${c.name}@${c.version} installed on ${host.name}`],
          groups: host.groups || [],
        });
        addRel(assetId, svcId, 'runs', 'high', 'R8', { package: `${c.name}@${c.version}` });
      }
    }
  }

  // ---- R5: repo → host deployment by SBOM fingerprint -------------------------
  const repoIds = [...assets.values()].filter(a => a.type === 'repo').map(a => a.id);
  const hostIds = [...assets.values()].filter(a => a.source_table === 'fleet_machines').map(a => a.id);
  for (const r of repoIds) {
    const rs = compSets.get(r);
    if (!rs || rs.size < 3) continue;
    for (const h of hostIds) {
      const hs = compSets.get(h);
      if (!hs) continue;
      let shared = 0;
      for (const x of rs) if (hs.has(x)) shared++;
      const jaccard = shared / (rs.size + hs.size - shared);
      const confidence: Confidence | null = shared >= 5 && jaccard >= 0.5 ? 'medium' : shared >= 3 && jaccard >= 0.25 ? 'low' : null;
      if (confidence) addRel(r, h, 'deployed_from', confidence, 'R5', { shared_components: shared, jaccard: Number(jaccard.toFixed(2)) });
    }
  }

  // ---- R6: network segments ---------------------------------------------------
  const segMembers = new Map<string, { label: string; hosts: string[]; reason: string }>();
  for (const m of src.machines) {
    const g = (m.group_name || '').trim();
    if (g && !/^(ungrouped|default|none)$/i.test(g)) {
      const key = `seg:group:${g.toLowerCase()}`;
      const e = segMembers.get(key) || { label: `Group: ${g}`, hosts: [], reason: `Workstation Group "${g}"` };
      e.hosts.push(`host:${m.id}`); segMembers.set(key, e);
    }
    if (m.public_ip) {
      const key = `seg:egress:${m.public_ip}`;
      const e = segMembers.get(key) || { label: `Egress ${m.public_ip}`, hosts: [], reason: `Shared egress IP ${m.public_ip}` };
      e.hosts.push(`host:${m.id}`); segMembers.set(key, e);
    }
  }
  for (const [segId, s] of segMembers) {
    if (s.hosts.length < 2) continue;
    addAsset({
      id: segId, type: 'network_segment', name: s.label, criticality: 1, data_classification: 'internal',
      internet_exposed: false, source_table: 'derived', source_id: segId,
      inference: [`R6: ${s.reason} shared by ${s.hosts.length} hosts`],
    });
    for (const h of s.hosts) addRel(h, segId, 'network_adjacent', 'low', 'R6', { segment: s.label });
  }

  // ---- R9: host role (server vs user endpoint) -------------------------------
  const runsService = new Set([...rels.values()].filter(r => r.kind === 'runs').map(r => r.from_asset));
  for (const m of src.machines) {
    const a = assets.get(`host:${m.id}`);
    if (!a) continue;
    const why = runsService.has(a.id) ? 'runs a network service (R8)'
      : /server/i.test(m.os || '') ? `server OS (${m.os})`
      : SERVER_HOSTNAME.test(m.hostname || '') && !/(darwin|mac|windows 1[01]|win1[01])/i.test(m.os || '') ? 'server naming convention'
      : null;
    if (why) {
      a.type = 'server';
      a.criticality = Math.max(a.criticality, 3);
      a.inference.push(`R9: classified as server — ${why}`);
    }
  }

  // ---- Context inference: criticality / classification by role ---------------
  const relList = [...rels.values()];
  const inDegree = new Map<string, number>();
  for (const r of relList) inDegree.set(r.to_asset, (inDegree.get(r.to_asset) || 0) + 1);
  for (const r of relList) {
    if (r.kind !== 'runs') continue;
    const svc = assets.get(r.to_asset); const host = assets.get(r.from_asset);
    if (svc?.type === 'database' && host) {
      host.criticality = Math.max(host.criticality, 3);
      host.data_classification = 'sensitive';
      host.inference.push(`Hosts ${svc.name} → sensitive data`);
    }
  }
  for (const a of assets.values()) {
    if ((inDegree.get(a.id) || 0) >= 3 && a.type !== 'network_segment' && a.criticality < 4) {
      a.criticality += 1;
      a.inference.push('Central in the discovered topology (≥3 inbound relationships)');
    }
  }

  // ---- Context overrides (admins may correct inferred context, never links) --
  for (const o of src.overrides) {
    const a = assets.get(o.asset_id);
    if (!a) continue;
    if (o.criticality) a.criticality = Math.min(4, Math.max(1, o.criticality));
    if (o.data_classification) a.data_classification = o.data_classification as DataClassification;
    if (o.environment !== undefined && o.environment !== null) a.environment = o.environment;
    a.context_origin = 'override';
  }

  return { assets: [...assets.values()], relationships: relList, crypto: [...cryptoNodes.values()], components, vulns };
};
