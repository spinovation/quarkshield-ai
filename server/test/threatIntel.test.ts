import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseKev, parseEpss } from '../src/lib/threatIntel/feeds';
import { vulnLikelihood } from '../src/lib/threatGraph/rules';
import { buildThreatGraph } from '../src/lib/threatGraph/engine';
import { SourceData, VulnNode } from '../src/lib/threatGraph/types';

const kevDoc = (extra: object[] = []) => JSON.stringify({
  catalogVersion: '2026.10.08',
  vulnerabilities: [
    ...Array.from({ length: 120 }, (_, i) => ({ cveID: `CVE-2020-${10000 + i}`, knownRansomwareCampaignUse: 'Unknown' })),
    ...extra,
  ],
});

test('KEV parser: validates ids, dates, ransomware flag and CWEs', () => {
  const { version, records } = parseKev(kevDoc([
    { cveID: 'CVE-2021-3156', vendorProject: 'Sudo', product: 'Sudo', vulnerabilityName: 'Sudo Heap Overflow',
      dateAdded: '2022-04-06', dueDate: '2022-04-27', knownRansomwareCampaignUse: 'Known', cwes: ['CWE-193', 'junk'] },
    { cveID: 'not-a-cve' },
  ]));
  assert.equal(version, '2026.10.08');
  const sudo = records.find(r => r.cve_id === 'CVE-2021-3156')!;
  assert.equal(sudo.ransomware_use, true);
  assert.equal(sudo.due_date, '2022-04-27');
  assert.deepEqual(sudo.cwes, ['CWE-193']);
  assert.ok(!records.some(r => r.cve_id === 'NOT-A-CVE'));
  assert.throws(() => parseKev(JSON.stringify({ vulnerabilities: [] })), /implausibly small/);
});

test('EPSS parser: reads model/score date header and rejects bad rows', () => {
  const rows = Array.from({ length: 1200 }, (_, i) => `CVE-2019-${10000 + i},0.0012${i % 10},0.4`);
  const csv = ['#model_version:v2025.03.14,score_date:2026-10-08T00:00:00+0000', 'cve,epss,percentile',
    'CVE-2021-3156,0.94,0.999', 'CVE-2021-0001,1.7,0.5', ...rows].join('\n');
  const { version, scoreDate, records } = parseEpss(csv);
  assert.equal(version, 'v2025.03.14');
  assert.equal(scoreDate, '2026-10-08');
  assert.equal(records.find(r => r.cve_id === 'CVE-2021-3156')!.epss, 0.94);
  assert.ok(!records.some(r => r.cve_id === 'CVE-2021-0001'), 'EPSS > 1 rejected');
});

const v = (o: Partial<VulnNode>): VulnNode => ({
  id: 'vuln:x:CVE-1', component_id: 'cmp:x', asset_id: 'host:a', cve: 'CVE-2024-0001', cvss: 7.5, severity: 'high',
  title: 't', fixed_version: null, remediation_cmd: null, cwe: [], kev: null, epss: null, epss_percentile: null, ...o,
});

test('likelihood: KEV > high EPSS > CVSS > very low EPSS', () => {
  assert.equal(vulnLikelihood(v({ kev: { ransomware_use: false } })), 4);
  assert.equal(vulnLikelihood(v({ epss: 0.7 })), 3);
  assert.equal(vulnLikelihood(v({ cvss: 9.8 })), 3, 'CVSS fallback');
  assert.equal(vulnLikelihood(v({ cvss: 9.8, epss: 0.002 })), 2, 'critical CVSS but exploitation very unlikely');
  assert.equal(vulnLikelihood(v({ cvss: 7.5, epss: 0.002 })), 1);
});

const src = (): SourceData => ({
  tenant: 'T',
  machines: [{ id: 'm1', hostname: 'app-prod-01', ip: '10.0.0.1' }],
  cryptoFindings: [],
  components: [
    { id: 'c1', source: 'endpoint', source_ref: 'app-prod-01', name: 'sudo', version: '1.9.5', ecosystem: 'os_pkg',
      vulnerabilities: [{ cveId: 'CVE-2021-3156', cvssScore: 7.8, severity: 'high' }] },
    { id: 'c2', source: 'endpoint', source_ref: 'app-prod-01', name: 'libfoo', version: '1.0', ecosystem: 'os_pkg',
      vulnerabilities: [{ cveId: 'CVE-2024-1111', cvssScore: 5.3, severity: 'medium' }] },
    { id: 'c3', source: 'endpoint', source_ref: 'app-prod-01', name: 'postgresql15-server', version: '15.4', ecosystem: 'os_pkg', vulnerabilities: [] },
  ],
  gitScans: [], pkiConnectors: [], pkiAssets: [], proxies: [], overrides: [],
  intel: {
    kev: {
      'CVE-2021-3156': { ransomware_use: true, due_date: '2022-04-27', cwes: ['CWE-193'] },
      'CVE-2024-1111': { ransomware_use: false, due_date: '2024-06-01' },
    },
    epss: { 'CVE-2021-3156': { epss: 0.94, percentile: 0.999 } },
  },
});

test('KEV drives threats: below-CVSS-7 KEV counts, ransomware rule fires, fixes carry CISA due date', () => {
  const g = buildThreatGraph(src());
  const exploit = g.threats.find(t => t.rule_id === 'TR-01')!;
  assert.ok(exploit.driver_ids.includes('vuln:c2:CVE-2024-1111'), 'KEV CVE with CVSS 5.3 still drives a threat');
  assert.equal(exploit.likelihood, 4, 'KEV → highest likelihood');
  assert.match(exploit.rationale, /CISA KEV/);
  const ransom = g.threats.find(t => t.rule_id === 'TR-09')!;
  assert.ok(ransom && ransom.category === 'ransomware_malware');
  assert.ok(ransom.attack.includes('T1486'));
  assert.deepEqual(g.risks.find(r => r.threat_id === ransom.id)!.controls.sort(), ['CP-10', 'CP-9', 'IR-4', 'SI-2']);
  const fix = g.remediations.find(r => r.id === 'rem:patch:cmp:c1')!;
  assert.equal(fix.kev, true);
  assert.equal(fix.kev_due_date, '2022-04-27');
  assert.equal(fix.epss_max, 0.94);
  const sudo = g.vulns.find(x => x.cve === 'CVE-2021-3156')!;
  assert.deepEqual(sudo.cwe, ['CWE-193'], 'CWE backfilled from KEV');
});

test('without intel the model falls back to CVSS (no TR-09)', () => {
  const s = src(); delete s.intel;
  const g = buildThreatGraph(s);
  assert.ok(!g.threats.some(t => t.rule_id === 'TR-09'));
  assert.ok(!g.vulns.some(x => x.cve === 'CVE-2024-1111' && g.threats.some(t => t.driver_ids.includes(x.id))), 'CVSS 5.3 alone is not a threat');
});
