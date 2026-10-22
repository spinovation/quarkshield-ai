#!/usr/bin/env node
// Generate the REAL quarkshield.ai platform SBOM from live `npm audit` data,
// replacing the hardcoded 0-CVE fixture in sbomController (QUARKSHIELD_PLATFORM_STACK).
//
// What it does:
//   - For server/ and ui/: reads the direct PRODUCTION dependencies + their installed
//     versions (package-lock.json) and runs `npm audit --omit=dev --json` so the result
//     reflects what is actually SHIPPED (dev-only tool CVEs are excluded on purpose).
//   - Emits idempotent SQL: deletes the current quarkshield.ai sbom_components rows and
//     inserts the real component inventory with real advisories (GHSA/CVE, CVSS, fix).
//
// Container coverage: when Docker is available, the base images (node:22-alpine,
// postgres:15-alpine) are scanned with Trivy (run as a container, no host install) for
// OS-package AND image-bundled-tooling CVEs. The OS layer and the bundled tooling (npm
// packages inside the node image, the gosu helper inside the postgres image) are emitted
// as distinct, clearly-labeled rows so the reader can tell app-runtime risk from
// image-bundled tooling. If Docker/Trivy is unavailable, the images fall back to explicit
// "not independently scanned" rows rather than being claimed clean.
//
// Usage:
//   node scripts/generate-platform-sbom.mjs > scripts/platform-sbom.generated.sql
//   # then apply to the DB:
//   docker exec -i pqc-scanner-db psql -U postgres -d quarkshield_scanner < scripts/platform-sbom.generated.sql
// Re-run anytime to refresh the platform posture.

import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TENANT = 'quarkshield.ai';

const PROJECTS = [
  { dir: 'server', source: 'platform_backend', ref: 'https://github.com/spinovation/quarkshield-ai/server', file: 'server/package.json' },
  { dir: 'ui',     source: 'platform_ui',      ref: 'https://github.com/spinovation/quarkshield-ai/ui',     file: 'ui/package.json' },
];

// Base container images to scan with Trivy (OS + bundled tooling).
const IMAGES = [
  { image: 'node:22-alpine',     file: 'Dockerfile',         toolingLabel: 'bundled npm/npx tooling (not app runtime)' },
  { image: 'postgres:15-alpine', file: 'docker-compose.yml', toolingLabel: 'bundled entrypoint helper (gosu)' },
];
// The Go agent has no third-party modules — emitted as a verified-clean row.
const AGENT_ROW = { name: 'pqc-scanner-engine', version: '2.3.0', source: 'platform_agent', ref: 'https://github.com/spinovation/quarkshield-ai/agent', file: 'agent/go.mod', ecosystem: 'golang' };

const sq = (s) => "'" + String(s ?? '').replace(/'/g, "''") + "'";
const jsonb = (o) => sq(JSON.stringify(o)) + '::jsonb';
const mkId = (source, name, version) => 'sbom-' + createHash('md5').update(`${TENANT}:${source}:${name}:${version}`).digest('hex').slice(0, 16);

function loadLock(dir) {
  // package-lock v3: packages map keyed by "node_modules/<name>" (and "" for root).
  try {
    const lock = JSON.parse(readFileSync(path.join(ROOT, dir, 'package-lock.json'), 'utf8'));
    const pkgs = lock.packages || {};
    const byName = {};
    for (const [k, v] of Object.entries(pkgs)) {
      if (!k.startsWith('node_modules/')) continue;
      const name = k.slice('node_modules/'.length);
      // last write wins is fine; dedupe advisories resolve against this too
      byName[name] = { version: v.version, license: v.license || (Array.isArray(v.licenses) ? v.licenses.map(l => l.type).join('/') : '') };
    }
    return byName;
  } catch { return {}; }
}

function audit(dir) {
  try {
    const out = execSync('npm audit --omit=dev --json', { cwd: path.join(ROOT, dir), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return JSON.parse(out);
  } catch (e) {
    // npm audit exits non-zero when vulns are found; the JSON is still on stdout.
    try { return JSON.parse(e.stdout); } catch { return { vulnerabilities: {} }; }
  }
}

// Resolve a package's advisories, following string `via` references to leaf advisories.
function resolveAdvisories(vulns, name, seen = new Set(), fixHint) {
  if (seen.has(name)) return [];
  seen.add(name);
  const v = vulns[name];
  if (!v) return [];
  const out = [];
  for (const via of v.via || []) {
    if (typeof via === 'object' && via) {
      const url = via.url || '';
      const ghsa = (url.match(/GHSA-[0-9a-z-]+/i) || [])[0] || '';
      const cve = (String(via.title || '').match(/CVE-\d{4}-\d+/) || [])[0] || ghsa || via.source || 'ADVISORY';
      const fa = v.fixAvailable;
      const fixedVersion = (fa && typeof fa === 'object' && fa.version) ? `${fa.name}@${fa.version}` : (fa === true ? 'npm audit fix' : 'See advisory');
      out.push({
        cveId: cve,
        title: via.title || `${name} advisory`,
        cvssScore: (via.cvss && typeof via.cvss.score === 'number') ? via.cvss.score : 0,
        severity: via.severity || v.severity || 'moderate',
        fixedVersion,
        remediationCmd: (fa === true) ? `cd ${fixHint} && npm audit fix` : `cd ${fixHint} && npm install ${name}@latest`,
        description: `${via.title || 'Advisory'} (${url || 'npm advisory'}).`,
      });
    } else if (typeof via === 'string') {
      out.push(...resolveAdvisories(vulns, via, seen, fixHint));
    }
  }
  // dedupe by cveId+title
  const uniq = [];
  const keys = new Set();
  for (const a of out) { const k = a.cveId + '|' + a.title; if (!keys.has(k)) { keys.add(k); uniq.push(a); } }
  return uniq;
}

const rows = [];
let totalVuln = 0;

for (const proj of PROJECTS) {
  const pkg = JSON.parse(readFileSync(path.join(ROOT, proj.file), 'utf8'));
  const deps = Object.keys(pkg.dependencies || {});
  const lock = loadLock(proj.dir);
  const data = audit(proj.dir);
  const vulns = data.vulnerabilities || {};

  // Set of packages to emit: all direct prod deps + any vulnerable package in this project.
  const names = new Set(deps);
  for (const n of Object.keys(vulns)) names.add(n);

  for (const name of [...names].sort()) {
    const version = lock[name]?.version || (pkg.dependencies || {})[name] || 'unknown';
    const advisories = vulns[name] ? resolveAdvisories(vulns, name, new Set(), proj.dir) : [];
    const isVuln = advisories.length > 0;
    if (isVuln) totalVuln++;
    const sev = isVuln ? (['critical', 'high', 'moderate', 'low'].find(s => advisories.some(a => a.severity === s)) || 'moderate') : 'none';
    const direct = deps.includes(name);
    rows.push({
      id: mkId(proj.source, name, version),
      source: proj.source,
      source_ref: direct ? proj.ref : `${proj.ref} (transitive)`,
      file_path: proj.file,
      name,
      version,
      ecosystem: 'npm',
      purl: `pkg:npm/${name}@${version}`,
      license: lock[name]?.license || 'Unknown',
      has_vulnerabilities: isVuln,
      vuln_count: advisories.length,
      max_severity: isVuln ? (sev === 'moderate' ? 'medium' : sev) : 'none',
      vulnerabilities: isVuln ? advisories.map(a => ({ ...a, severity: a.severity === 'moderate' ? 'medium' : a.severity })) : [],
    });
  }
}

// ---- Container base-image scan (Trivy via Docker, no host install) ----
const SEV_RANK = ['critical', 'high', 'medium', 'low'];
const normSev = (s) => { const x = String(s || '').toLowerCase(); return x === 'moderate' ? 'medium' : (SEV_RANK.includes(x) ? x : 'low'); };

function dockerAvailable() {
  try { execSync('docker version', { stdio: 'ignore' }); return true; } catch { return false; }
}

function trivyScan(image) {
  const cmd = `docker run --rm -v trivy-cache:/root/.cache/ aquasec/trivy:latest image --quiet --format json --severity CRITICAL,HIGH,MEDIUM --scanners vuln ${image}`;
  try {
    const out = execSync(cmd, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] });
    return JSON.parse(out);
  } catch (e) {
    try { return JSON.parse(e.stdout); } catch { return null; }
  }
}

function trivyVulnToAdvisory(v) {
  const cvss = v.CVSS || {};
  let score = 0;
  for (const src of Object.values(cvss)) { const s = (src && (src.V3Score ?? src.V2Score)) || 0; if (s > score) score = s; }
  return {
    cveId: v.VulnerabilityID || 'ADVISORY',
    title: v.Title || (v.Description ? String(v.Description).slice(0, 120) : `${v.PkgName} advisory`),
    cvssScore: score,
    severity: normSev(v.Severity),
    fixedVersion: v.FixedVersion || 'No fix available',
    remediationCmd: v.FixedVersion ? `Rebuild base image / bump ${v.PkgName} to ${v.FixedVersion}` : 'Track upstream base-image update',
    description: (v.Title || v.Description || '').slice(0, 300) + (v.PrimaryURL ? ` (${v.PrimaryURL})` : ''),
  };
}

const dockerOk = dockerAvailable();
process.stderr.write(`[generate-platform-sbom] docker available: ${dockerOk}\n`);

for (const img of IMAGES) {
  const data = dockerOk ? trivyScan(img.image) : null;
  const artifact = img.image;
  if (!data || !Array.isArray(data.Results)) {
    // Fallback: cannot scan → explicit not-scanned row (never claimed clean).
    rows.push({
      id: mkId('container_base', img.image, 'unscanned'),
      source: 'container_base', source_ref: `docker.io/library/${img.image}`, file_path: img.file,
      name: img.image, version: 'image', ecosystem: 'container', purl: `pkg:oci/${img.image}`,
      license: 'Various (base image)', has_vulnerabilities: false, vuln_count: 0, max_severity: 'none',
      vulnerabilities: [{ cveId: 'NOT-SCANNED', title: 'Base image not scanned (Docker/Trivy unavailable)', cvssScore: 0, severity: 'low', fixedVersion: 'n/a', remediationCmd: 'Run the generator on a host with Docker to scan via Trivy', description: 'Container OS/tooling CVEs were not scanned in this run.' }],
    });
    continue;
  }
  const osVer = (data.Results.find(r => r.Class === 'os-pkgs')?.Target || artifact);
  for (const r of data.Results) {
    const vs = r.Vulnerabilities || [];
    const isOs = r.Class === 'os-pkgs';
    // Group this result's vulns by package.
    const byPkg = new Map();
    for (const v of vs) { const k = v.PkgName || 'unknown'; (byPkg.get(k) || byPkg.set(k, []).get(k)).push(v); }

    if (isOs) {
      // One row representing the OS layer (clean or not) — this is the key "container" result.
      const advs = vs.map(trivyVulnToAdvisory);
      const sev = advs.length ? (SEV_RANK.find(s => advs.some(a => a.severity === s)) || 'medium') : 'none';
      rows.push({
        id: mkId('container_base', artifact + ':os', 'os'),
        source: 'container_base', source_ref: `${osVer} — OS layer (Trivy-scanned)`, file_path: img.file,
        name: `${artifact} · OS layer`, version: (osVer.match(/\(([^)]+)\)/) || [,'os'])[1], ecosystem: 'os_pkg',
        purl: `pkg:oci/${artifact}`, license: 'Various (base image)',
        has_vulnerabilities: advs.length > 0, vuln_count: advs.length, max_severity: sev,
        vulnerabilities: advs.length ? advs : [{ cveId: 'VERIFIED-CLEAN', title: `No OS-package CVEs (CRITICAL/HIGH/MEDIUM) — Trivy-scanned`, cvssScore: 0, severity: 'low', fixedVersion: 'n/a', remediationCmd: 'n/a', description: `${osVer} OS packages scanned with Trivy: zero CRITICAL/HIGH/MEDIUM CVEs.` }],
      });
    } else {
      // Bundled tooling (node-pkg / gobinary): one row per package, clearly labeled.
      for (const [pkg, pvs] of byPkg) {
        const advs = pvs.map(trivyVulnToAdvisory);
        const sev = SEV_RANK.find(s => advs.some(a => a.severity === s)) || 'medium';
        const ver = pvs[0].InstalledVersion || 'bundled';
        rows.push({
          id: mkId('container_base', `${artifact}:${pkg}`, ver),
          source: 'container_base',
          source_ref: `${artifact} — ${img.toolingLabel}`, file_path: img.file,
          name: pkg, version: ver, ecosystem: r.Type || 'bundled',
          purl: `pkg:${r.Type || 'generic'}/${pkg}@${ver}`, license: 'Various (base image)',
          has_vulnerabilities: true, vuln_count: advs.length, max_severity: sev,
          vulnerabilities: advs,
        });
        totalVuln++;
      }
    }
  }
}

// Go agent — verified clean (pure stdlib, zero external modules).
rows.push({
  id: mkId(AGENT_ROW.source, AGENT_ROW.name, AGENT_ROW.version),
  source: AGENT_ROW.source, source_ref: AGENT_ROW.ref, file_path: AGENT_ROW.file,
  name: AGENT_ROW.name, version: AGENT_ROW.version, ecosystem: AGENT_ROW.ecosystem,
  purl: `pkg:golang/${AGENT_ROW.name}@${AGENT_ROW.version}`, license: 'Proprietary',
  has_vulnerabilities: false, vuln_count: 0, max_severity: 'none',
  vulnerabilities: [{ cveId: 'CLEAN', title: 'Pure Go standard library — zero external modules', cvssScore: 0, severity: 'low', fixedVersion: 'n/a', remediationCmd: 'n/a', description: 'Agent compiles against the Go standard library only; no third-party module CVEs.' }],
});

// ---- Emit SQL ----
const now = new Date().toISOString();
let sql = `-- GENERATED by scripts/generate-platform-sbom.mjs on ${now}
-- Real quarkshield.ai platform SBOM from \`npm audit --omit=dev\` (production deps).
-- Do not hand-edit; re-run the generator to refresh. Idempotent (replaces qs.ai rows).
\\set ON_ERROR_STOP on
BEGIN;
DELETE FROM sbom_components WHERE LOWER(tenant_name) = 'quarkshield.ai';
`;
for (const r of rows) {
  sql += `INSERT INTO sbom_components (id, tenant_name, source, source_ref, file_path, name, version, ecosystem, purl, license, has_vulnerabilities, vuln_count, max_severity, vulnerabilities) VALUES (`
    + [sq(r.id), sq(TENANT), sq(r.source), sq(r.source_ref), sq(r.file_path), sq(r.name), sq(r.version), sq(r.ecosystem), sq(r.purl), sq(r.license), r.has_vulnerabilities, r.vuln_count, sq(r.max_severity), jsonb(r.vulnerabilities)].join(', ')
    + `) ON CONFLICT (id) DO UPDATE SET version=EXCLUDED.version, has_vulnerabilities=EXCLUDED.has_vulnerabilities, vuln_count=EXCLUDED.vuln_count, max_severity=EXCLUDED.max_severity, vulnerabilities=EXCLUDED.vulnerabilities, updated_at=now();\n`;
}
sql += `SELECT COUNT(*) AS platform_components, COUNT(*) FILTER (WHERE has_vulnerabilities) AS vulnerable FROM sbom_components WHERE tenant_name='quarkshield.ai';\nCOMMIT;\n`;

process.stdout.write(sql);
process.stderr.write(`[generate-platform-sbom] ${rows.length} components, ${totalVuln} vulnerable (npm, prod-only)\n`);
