import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  HOST_VALIDATIONS, sanitizeHostModuleReport, moduleDetailFor, resolveHostModule, resolveAssetModule,
  isHostResolution, moduleForConsole, hostModulesForConsole, HostModuleDetail,
  MODE_RULES,
} from '../src/lib/hostCryptoModules';
import { complianceVerdict, VERDICT_ORDER } from '../src/lib/complianceVerdict';
import { assessAsset, buildAttestationCsv } from '../src/lib/fipsAttestation';
import { CMVP_MAP_VERSION } from '../src/lib/cmvpModules';
import { cbomComponent } from '../src/lib/cyclonedx';

const prop = (c: any, name: string): string | undefined => c.properties.find((p: any) => p.name === name)?.value;
const env = (id: string, version: string, arch = 'amd64') => ({ id, version, arch, name: `${id} ${version}` });
const openssl = (version: string, fipsProvider: any, e: any): HostModuleDetail =>
  ({ key: 'openssl', name: 'OpenSSL', version, fipsProvider, environment: e });
const RHEL9 = 'Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider';

// ---- The rule that matters most ---------------------------------------------

test('from identity alone a host module is never active, historical or revoked, and carries no certIds', () => {
  const details: HostModuleDetail[] = [
    openssl('3.5.9', { present: 'yes', name: RHEL9, version: '3.0.7-cda111b5812c30d4' }, env('rhel', '9.9')),
    { key: 'windows-cng', name: 'CNG', version: '10.0.22621.4317', environment: env('windows', '10.0.22621.4317') },
    { key: 'apple-corecrypto', name: 'Apple corecrypto', version: '15.5', environment: env('macos', '15.5', 'arm64') },
    { key: 'libressl', name: 'LibreSSL', version: '3.3.6', environment: env('macos', '15.5', 'arm64') },
    { key: 'something-new', name: 'X', environment: env('linux', '1') },
  ];
  for (const d of details) {
    const r = resolveHostModule(d);
    assert.ok(['unverified', 'none'].includes(r.status), `${d.key}: ${r.status}`);
    assert.deepEqual(r.certIds, [], `${d.key} must not carry certIds`);
    assert.equal(r.basis, 'host-observed');
    assert.equal(r.mapVersion, CMVP_MAP_VERSION);
    assert.notEqual(r.fipsMode.state, 'confirmed', `${d.key}: no host fact was reported`);
    if (r.candidate) assert.match(String(r.note), /^Candidate only\./);
  }
});

// ---- OpenSSL ----------------------------------------------------------------

test('RHEL 9 FIPS provider: exact candidate when version and OS release are as tested', () => {
  // Library 3.5.9 with provider 3.0.7 is what a real RHEL 9.9 host reports: the provider, not
  // the library, is the validated module.
  const r = resolveHostModule(openssl('3.5.9', { present: 'yes', name: RHEL9, version: '3.0.7-cda111b5812c30d4' }, env('rhel', '9.9')));
  assert.equal(r.candidate?.certId, '5573');
  assert.equal(r.candidate?.match, 'exact');
  assert.equal(r.candidate?.certStatus, 'active');
  assert.equal(r.moduleName, RHEL9);
  assert.equal(r.moduleVersion, '3.0.7-cda111b5812c30d4');
});

test('the build hash decides the certificate: a superseded RHEL 9 build maps to the historical one', () => {
  const r = resolveHostModule(openssl('3.0.7', { present: 'yes', name: RHEL9, version: '3.0.7-395c1a240fbfffd8' }, env('rhel', '9.2')));
  assert.equal(r.candidate?.certId, '4857');
  assert.equal(r.candidate?.certStatus, 'historical');
});

test('an unknown build hash or a bare upstream-looking version gets no candidate', () => {
  for (const version of ['3.0.7-0000000000000000', '3.0.7', '3.0.70', '']) {
    const r = resolveHostModule(openssl('3.0.7', { present: 'yes', name: RHEL9, version }, env('rhel', '9.4')));
    assert.equal(r.candidate, undefined, `"${version}" must not match`);
    assert.equal(r.status, 'unverified');
  }
});

test('same provider version on an OS that was not tested is a weaker "version" match', () => {
  const r = resolveHostModule(openssl('3.0.7', { present: 'yes', name: RHEL9, version: '3.0.7-cda111b5812c30d4' }, env('rocky', '9.4')));
  assert.equal(r.candidate?.certId, '5573');
  assert.equal(r.candidate?.match, 'version');
  assert.match(r.candidate!.matchNote, /not on its tested list/);
  // Same for a CPU architecture the certificate was not tested on (RHEL 9 on arm64).
  const arm = resolveHostModule(openssl('3.5.9', { present: 'yes', name: RHEL9, version: '3.0.7-cda111b5812c30d4' }, env('rhel', '9.9', 'arm64')));
  assert.equal(arm.candidate?.certId, '5573');
  assert.equal(arm.candidate?.match, 'version');
});

test('the provider name must match too: a version string alone is not identity', () => {
  const r = resolveHostModule(openssl('3.0.7', { present: 'yes', name: 'Some Other Provider', version: '3.0.7-cda111b5812c30d4' }, env('rhel', '9.4')));
  assert.equal(r.candidate, undefined);
});

test('upstream provider 3.1.2 on Debian 11 and Ubuntu FIPS module on 22.04', () => {
  const up = resolveHostModule(openssl('3.1.2', { present: 'yes', name: 'OpenSSL FIPS Provider', version: '3.1.2' }, env('debian', '11')));
  assert.equal(up.candidate?.certId, '4985');
  assert.equal(up.candidate?.match, 'exact');
  const ub = resolveHostModule(openssl('3.0.2', { present: 'yes', name: 'Ubuntu 22.04 OpenSSL Cryptographic Module', version: '3.0.5-0ubuntu0.1+Fips2.1' }, env('ubuntu', '22.04')));
  assert.equal(ub.candidate?.certId, '4794');
});

test('OpenSSL 3 with no FIPS provider installed is "none"; undetermined is "unverified"', () => {
  const none = resolveHostModule(openssl('3.0.22', { present: 'no' }, env('debian', '12')));
  assert.equal(none.status, 'none');
  assert.equal(none.candidate, undefined);
  const unknown = resolveHostModule(openssl('3.0.22', { present: 'unknown' }, env('debian', '12')));
  assert.equal(unknown.status, 'unverified');
  assert.match(String(unknown.note), /could not be determined/);
  // OpenSSL 1.x has no provider concept: say nothing either way.
  const one = resolveHostModule(openssl('1.1.1k', undefined, env('rhel', '8.10')));
  assert.equal(one.status, 'unverified');
  assert.equal(one.candidate, undefined);
});

// ---- Windows ----------------------------------------------------------------

const cng = (version: string): HostModuleDetail => ({ key: 'windows-cng', name: 'CNG', version, environment: env('windows', version) });

test('Windows: tested build is exact, a patched build of the same release is "release"', () => {
  const exact = resolveHostModule(cng('10.0.22621.30001'));
  assert.equal(exact.candidate?.certId, '5410');
  assert.equal(exact.candidate?.match, 'exact');
  const patched = resolveHostModule(cng('10.0.22621.4317'));
  assert.equal(patched.candidate?.certId, '5410');
  assert.equal(patched.candidate?.match, 'release');
  assert.match(patched.candidate!.matchNote, /not the tested build/);
});

test('Windows Server 2022: the active certificate is preferred over the historical one', () => {
  assert.equal(resolveHostModule(cng('10.0.20348.2700')).candidate?.certId, '5410');
});

test('Windows builds with no certificate get no candidate, and prefixes do not bleed', () => {
  for (const v of ['10.0.19045.4651', '10.0.19044.1', '10.0.22631.4317', '10.0.26100.2', '10.0.226210.1', '']) {
    const r = resolveHostModule(cng(v));
    assert.equal(r.candidate, undefined, `${v} must not match`);
    assert.equal(r.status, 'unverified');
  }
  assert.equal(resolveHostModule(cng('10.0.22000.3260')).candidate?.certStatus, 'historical');
});

// ---- Apple ------------------------------------------------------------------

test('macOS: release and CPU family select the certificate; always a "release" match', () => {
  const mac = (version: string, arch: string): HostModuleDetail =>
    ({ key: 'apple-corecrypto', name: 'Apple corecrypto', version, environment: env('macos', version, arch) });
  assert.equal(resolveHostModule(mac('15.5', 'arm64')).candidate?.certId, '5184');
  assert.equal(resolveHostModule(mac('15.5', 'amd64')).candidate?.certId, '5217');
  assert.equal(resolveHostModule(mac('14.7.1', 'arm64')).candidate?.certId, '5216');
  assert.equal(resolveHostModule(mac('13.6', 'amd64')).candidate?.certId, '5348');
  assert.equal(resolveHostModule(mac('15.5', 'arm64')).candidate?.match, 'release');
  assert.equal(resolveHostModule(mac('12.7', 'arm64')).candidate?.certStatus, 'historical');
  // No certificate for macOS 26 on the map date; 150 must not match 15.
  assert.equal(resolveHostModule(mac('26.4.1', 'arm64')).candidate, undefined);
  assert.equal(resolveHostModule(mac('150.1', 'arm64')).candidate, undefined);
  assert.equal(resolveHostModule(mac('15.5', 'riscv64')).candidate, undefined);
});

// ---- Map integrity ----------------------------------------------------------

test('reference rows are well formed', () => {
  const ids = new Set<string>();
  for (const v of HOST_VALIDATIONS) {
    assert.match(v.certId, /^\d{4}$/);
    assert.ok(!ids.has(`${v.certId}/${v.arch || ''}`), `duplicate row ${v.certId}`);
    ids.add(`${v.certId}/${v.arch || ''}`);
    assert.ok(v.versions.length > 0 && v.testedOn.length > 0, v.certId);
    if (v.status === 'active') assert.match(String(v.sunsetDate), /^\d{4}-\d{2}-\d{2}$/, `active ${v.certId} needs a sunset date`);
    if (v.status === 'historical') assert.equal(v.sunsetDate, undefined, `historical ${v.certId}: NIST shows no sunset`);
    if (v.moduleKey === 'openssl') assert.ok(v.providerName, `openssl row ${v.certId} needs the provider name`);
  }
});

// ---- Untrusted input --------------------------------------------------------

test('the agent report is sanitised: bad shapes dropped, strings bounded, control characters removed', () => {
  assert.equal(sanitizeHostModuleReport(undefined), null);
  assert.equal(sanitizeHostModuleReport('x'), null);
  const r = sanitizeHostModuleReport({
    environment: { id: 'RHEL', version: '9.4', arch: 'amd64', name: 'a\u0000b\nc' },
    modules: [
      { ref: 'openssl:3.0.7', key: 'openssl', name: 'OpenSSL', version: '3.0.7', fipsProvider: { present: 'yes', name: 'N', version: 'V' }, evidence: 'e'.repeat(5000) },
      { ref: 'openssl:3.0.7', key: 'openssl', name: 'duplicate ref' },
      { ref: 'x', key: 'Bad Key!' },
      { ref: 'y', key: 'ok', fipsProvider: { present: 'maybe' } },
      null, 7, 'str',
      ...Array.from({ length: 100 }, (_, i) => ({ ref: `m${i}`, key: 'k' })),
    ],
    extra: '<script>',
  })!;
  assert.equal(r.environment.id, 'rhel');
  assert.equal(r.environment.name, 'a b c');
  assert.ok(r.modules.length <= 24);
  assert.equal(r.modules[0].evidence!.length, 400);
  assert.equal(r.modules.filter(m => m.ref === 'openssl:3.0.7').length, 1);
  assert.equal(r.modules.some(m => m.key === 'Bad Key!'), false);
  assert.equal(r.modules.find(m => m.ref === 'y')!.fipsProvider, undefined);
  assert.equal((r as any).extra, undefined);
});

test('a finding is tied only to a module the same report contains', () => {
  const report = sanitizeHostModuleReport({ environment: env('rhel', '9.4'), modules: [{ ref: 'openssl:3.0.7', key: 'openssl', name: 'OpenSSL', version: '3.0.7' }] });
  assert.equal(moduleDetailFor(report, 'openssl:9.9.9'), null);
  assert.equal(moduleDetailFor(report, undefined), null);
  assert.equal(moduleDetailFor(null, 'openssl:3.0.7'), null);
  const d = moduleDetailFor(report, 'openssl:3.0.7')!;
  assert.equal(d.key, 'openssl');
  assert.equal(d.environment.id, 'rhel');
  assert.equal((d as any).ref, undefined);
});

// ---- One resolver for both kinds of asset -----------------------------------

test('connector assets resolve as before; host assets resolve by identity', () => {
  const kms = resolveAssetModule('aws-kms-hsm', null);
  assert.equal(isHostResolution(kms), false);
  assert.equal(kms.status, 'active');
  assert.deepEqual(kms.certIds, ['4884']);
  assert.equal(resolveAssetModule(null, null).status, 'not-assessed');
  const host = resolveAssetModule('windows-cng', JSON.stringify(cng('10.0.22621.4317')));
  assert.equal(isHostResolution(host), true);
  // A detail record that is not one (bad JSON, wrong shape) falls back to the connector path.
  assert.equal(isHostResolution(resolveAssetModule('windows-cng', '{bad')), false);
  assert.equal(resolveAssetModule('windows-cng', '{bad').status, 'unverified');
});

test('console shape: host module shows a candidate, never a certificate list', () => {
  const detail = openssl('3.5.9', { present: 'yes', name: RHEL9, version: '3.0.7-cda111b5812c30d4' }, env('rhel', '9.9'));
  const c = moduleForConsole('openssl', 'OpenSSH reports the crypto library it runs on.', { ...detail, evidence: '/usr/bin/openssl version: OpenSSL 3.5.9' });
  assert.equal(c.basis, 'host-observed');
  assert.equal(c.status, 'unverified');
  assert.deepEqual(c.certIds, []);
  assert.equal(c.candidate?.certId, '5573');
  assert.match(String(c.evidence), /OpenSSH reports.*openssl version/);
  const k = moduleForConsole('aws-kms-hsm', 'Origin=AWS_KMS');
  assert.equal(k.basis, 'provider-reported');
  assert.equal(k.candidate, undefined);
});

test('host view lists every reported module, resolved', () => {
  const list = hostModulesForConsole({
    environment: env('rhel', '9.9'),
    modules: [{ ref: 'openssl:3.5.9', key: 'openssl', name: 'OpenSSL', version: '3.5.9', fipsProvider: { present: 'yes', name: RHEL9, version: '3.0.7-cda111b5812c30d4' } }],
  });
  assert.equal(list.length, 1);
  assert.equal(list[0].candidate?.certId, '5573');
  assert.deepEqual(hostModulesForConsole(null), []);
  assert.deepEqual(hostModulesForConsole('not json'), []);
});

// ---- CBOM -------------------------------------------------------------------

test('CBOM: a host module exports identity and a candidate, not a certificate or a verdict', () => {
  const detail = openssl('3.5.9', { present: 'yes', name: RHEL9, version: '3.0.7-cda111b5812c30d4' }, env('rhel', '9.9'));
  const c = cbomComponent({ id: 'a', name: 'sshd_config', algorithm: 'Legacy SSH Cipher/KEX', isVulnerable: true, assetKind: 'config', cryptoModule: 'openssl', cryptoModuleEvidence: 'ssh -V', cryptoModuleDetail: detail });
  assert.equal(prop(c, 'quarkshield:cmvpStatus'), 'unverified');
  assert.equal(prop(c, 'quarkshield:cmvpBasis'), 'host-observed');
  assert.equal(prop(c, 'quarkshield:cmvpModule'), RHEL9);
  assert.equal(prop(c, 'quarkshield:cmvpModuleVersion'), '3.0.7-cda111b5812c30d4');
  assert.equal(prop(c, 'quarkshield:cmvpCandidateId'), '5573');
  assert.equal(prop(c, 'quarkshield:cmvpCandidateMatch'), 'exact');
  assert.equal(prop(c, 'quarkshield:cmvpFipsMode'), 'not-determined');
  assert.equal(prop(c, 'quarkshield:complianceVerdict'), 'not_determined', 'an unclassifiable algorithm label is not determined');
  assert.equal(prop(c, 'quarkshield:cmvpCertId'), undefined, 'cmvpCertId is reserved for provider-reported certificates');
  assert.equal(prop(c, 'quarkshield:cmvpFipsLevel'), undefined);
  assert.equal(c.properties.some((p: any) => /^quarkshield:cmvp(Status|Basis)$/.test(p.name) && /validated|compliant/i.test(p.value)), false);
});

test('CBOM: connector and plain assets are unchanged by Stage 4', () => {
  const kms = cbomComponent({ id: 'k', name: 'key', algorithm: 'RSA', keySize: 4096, assetKind: 'kms_key', cryptoModule: 'aws-kms-hsm', cryptoModuleEvidence: 'Origin=AWS_KMS' });
  assert.equal(prop(kms, 'quarkshield:cmvpStatus'), 'active');
  assert.equal(prop(kms, 'quarkshield:cmvpCertId'), '4884');
  assert.equal(prop(kms, 'quarkshield:cmvpBasis'), 'provider-reported');
  assert.equal(prop(kms, 'quarkshield:cmvpCandidateId'), undefined);
  assert.equal(prop(kms, 'quarkshield:cmvpFipsMode'), undefined);
  const plain = cbomComponent({ id: 'p', name: 'CN=web', algorithm: 'RSA', keySize: 2048, assetKind: 'certificate' });
  assert.equal(prop(plain, 'quarkshield:cmvpStatus'), 'not-assessed');
  assert.equal(plain.properties.some((p: any) => /cmvp(Module|Candidate|Basis)/.test(p.name)), false);
});

// ---- Stage 5: the FIPS-mode gate --------------------------------------------

const FIPS_ON = [
  { name: 'linux.kernel.fips_enabled', value: '1', source: '/proc/sys/crypto/fips_enabled' },
  { name: 'linux.crypto_policy.current', value: 'FIPS', source: '/etc/crypto-policies/state/current' },
];
const providers = (v: string) => [{ name: 'openssl.default_providers', value: v, source: '/usr/bin/openssl list -providers' }];
const rhel = (over: Partial<HostModuleDetail> = {}, e = env('rhel', '9.4')): HostModuleDetail => ({
  ...openssl('3.0.7', { present: 'yes', name: RHEL9, version: '3.0.7-cda111b5812c30d4' }, e),
  hostModeFacts: FIPS_ON, modeFacts: providers('base,fips'), ...over,
});

test('gate: exact identity + system FIPS mode + only the fips provider active -> the certificate is reported', () => {
  const r = resolveHostModule(rhel());
  assert.equal(r.status, 'active');
  assert.deepEqual(r.certIds, ['5573']);
  assert.equal(r.standard, 'FIPS 140-3');
  assert.equal(r.sunsetDate, '2029-10-28');
  assert.equal(r.fipsMode.state, 'confirmed');
  assert.match(r.fipsMode.evidence, /fips_enabled = 1/);
  assert.match(String(r.note), /did not test the module/);
  // A superseded build in the same state reports its certificate as NIST lists it: historical.
  const old = resolveHostModule(rhel({ fipsProvider: { present: 'yes', name: RHEL9, version: '3.0.7-395c1a240fbfffd8' } }));
  assert.equal(old.status, 'historical');
  assert.deepEqual(old.certIds, ['4857']);
});

test('gate: any missing or failing fact keeps the module unverified', () => {
  const cases: [string, Partial<HostModuleDetail>, 'off' | 'not-determined'][] = [
    ['kernel flag off', { hostModeFacts: [{ name: 'linux.kernel.fips_enabled', value: '0' }, FIPS_ON[1]] }, 'off'],
    ['kernel flag not reported', { hostModeFacts: [FIPS_ON[1]] }, 'not-determined'],
    ['no host facts at all', { hostModeFacts: undefined }, 'not-determined'],
    ['crypto policy DEFAULT', { hostModeFacts: [FIPS_ON[0], { name: 'linux.crypto_policy.current', value: 'DEFAULT' }] }, 'off'],
    ['crypto policy not reported', { hostModeFacts: [FIPS_ON[0]] }, 'not-determined'],
    ['fips provider not active', { modeFacts: providers('default') }, 'off'],
    ['default provider active beside fips', { modeFacts: providers('default,fips') }, 'not-determined'],
    ['providers not reported', { modeFacts: undefined }, 'not-determined'],
    ['odd flag value', { hostModeFacts: [{ name: 'linux.kernel.fips_enabled', value: '1 ' + 'x' }, FIPS_ON[1]] }, 'off'],
  ];
  for (const [label, over, state] of cases) {
    const r = resolveHostModule(rhel(over));
    assert.equal(r.status, 'unverified', label);
    assert.deepEqual(r.certIds, [], label);
    assert.equal(r.fipsMode.state, state, label);
    assert.equal(r.candidate?.certId, '5573', `${label}: the candidate is still shown`);
  }
});

test('gate: FIPS mode on does not promote a match that is not exact', () => {
  // Same provider build on Rocky, or on an architecture the certificate was not tested on.
  for (const e of [env('rocky', '9.4'), env('rhel', '9.4', 'arm64')]) {
    const r = resolveHostModule(rhel({}, e));
    assert.equal(r.fipsMode.state, 'confirmed');
    assert.equal(r.status, 'unverified');
    assert.deepEqual(r.certIds, []);
    assert.match(String(r.note), /not exact/);
  }
});

test('gate: Ubuntu needs the kernel flag and the provider, not the RHEL crypto policy', () => {
  const ub = (hostModeFacts: any, modeFacts: any) => resolveHostModule({
    ...openssl('3.0.2', { present: 'yes', name: 'Ubuntu 22.04 OpenSSL Cryptographic Module', version: '3.0.5-0ubuntu0.1+Fips2.1' }, env('ubuntu', '22.04')),
    hostModeFacts, modeFacts,
  });
  assert.equal(ub([FIPS_ON[0]], providers('fips,base')).status, 'active');
  assert.equal(ub([{ name: 'linux.kernel.fips_enabled', value: '0' }], providers('fips')).status, 'unverified');
});

test('gate: upstream OpenSSL and Apple have no rule and are never confirmed', () => {
  const up = resolveHostModule({ ...openssl('3.1.2', { present: 'yes', name: 'OpenSSL FIPS Provider', version: '3.1.2' }, env('debian', '11')), hostModeFacts: FIPS_ON, modeFacts: providers('fips') });
  assert.equal(up.candidate?.match, 'exact');
  assert.equal(up.status, 'unverified');
  assert.equal(up.fipsMode.state, 'not-determined');
  const mac = resolveHostModule({ key: 'apple-corecrypto', name: 'Apple corecrypto', version: '15.5', environment: env('macos', '15.5', 'arm64') });
  assert.equal(mac.status, 'unverified');
});

test('gate: Windows is confirmed only on the tested build; the legacy policy matters only for #4825', () => {
  assert.equal(resolveHostModule(cng('10.0.22621.30001')).status, 'active');
  assert.deepEqual(resolveHostModule(cng('10.0.22621.30001')).certIds, ['5410']);
  // A patched build of the same release is not the validated binary.
  const patched = resolveHostModule({ ...cng('10.0.22621.4317'), hostModeFacts: [{ name: 'windows.fips_policy.enabled', value: '1' }] });
  assert.equal(patched.status, 'unverified');
  // #4825 (Windows 11 21H2) needs the FIPS policy; its listed version has no update revision,
  // so a real host is a "release" match and is not promoted even with the policy on.
  const w21 = resolveHostModule({ ...cng('10.0.22000.3260'), hostModeFacts: [{ name: 'windows.fips_policy.enabled', value: '1' }] });
  assert.equal(w21.fipsMode.state, 'confirmed');
  assert.equal(w21.status, 'unverified');
  assert.equal(resolveHostModule(cng('10.0.22000.3260')).fipsMode.state, 'not-determined');
});

test('every mode rule named by a row exists, and rules never throw on empty input', () => {
  for (const v of HOST_VALIDATIONS) if (v.modeRule) assert.equal(typeof MODE_RULES[v.modeRule], 'function', v.certId);
  for (const rule of Object.values(MODE_RULES)) assert.ok(rule({ key: 'x', name: 'x', environment: { id: 'x' } }).evidence);
});

test('mode facts are sanitised and travel with the per-asset record', () => {
  const report = sanitizeHostModuleReport({
    environment: env('rhel', '9.4'),
    modeFacts: [...FIPS_ON, { name: 'Bad Name', value: '1' }, { name: 'ok.name', value: 7 }, { name: 'long', value: 'v'.repeat(500) }, null],
    modules: [{ ref: 'openssl:3.0.7', key: 'openssl', name: 'OpenSSL', version: '3.0.7', modeFacts: providers('base,fips') }],
  })!;
  assert.deepEqual(report.modeFacts!.map(f => f.name), ['linux.kernel.fips_enabled', 'linux.crypto_policy.current', 'long']);
  assert.equal(report.modeFacts![2].value.length, 120);
  const d = moduleDetailFor(report, 'openssl:3.0.7')!;
  assert.equal(d.hostModeFacts!.length, 3);
  assert.equal(d.modeFacts![0].value, 'base,fips');
});

// ---- Stage 5: verdict -------------------------------------------------------

test('verdict table (spec 4.2)', () => {
  const rows: [string, string, string][] = [
    ['approved', 'active', 'compliant'], ['pq_approved', 'active', 'compliant'], ['acceptable', 'active', 'compliant_until'],
    ['approved', 'historical', 'validated_sunsetting'], ['acceptable', 'historical', 'validated_sunsetting'],
    ['approved', 'revoked', 'validated_revoked'],
    ['approved', 'none', 'approved_unvalidated'], ['approved', 'unverified', 'approved_unvalidated'], ['pq_approved', 'not-assessed', 'approved_unvalidated'],
    ['restricted', 'active', 'restricted_use'], ['disallowed', 'active', 'noncompliant'], ['non_fips', 'unverified', 'noncompliant'],
    ['unknown', 'active', 'not_determined'], ['not_applicable', 'active', 'not_applicable'],
  ];
  for (const [f, c, want] of rows) assert.equal(complianceVerdict(f, c), want, `${f} x ${c}`);
});

test('"compliant" is unreachable without an active module status', () => {
  const fips = ['pq_approved', 'approved', 'acceptable', 'restricted', 'disallowed', 'non_fips', 'not_applicable', 'unknown', undefined, 'garbage'];
  const cmvp = ['historical', 'revoked', 'none', 'unverified', 'not-assessed', undefined, '', 'ACTIVE', 'garbage'];
  for (const f of fips) for (const c of cmvp) {
    const v = complianceVerdict(f as any, c as any);
    assert.ok(VERDICT_ORDER.includes(v));
    assert.ok(v !== 'compliant' && v !== 'compliant_until', `${f} x ${c} -> ${v}`);
  }
});

test('assessAsset: host asset through the gate is compliant; the same asset without it is not', () => {
  const base = { id: 'a', name: 'key exchange', type: 'algorithm', algorithm: 'ML-KEM-768', purpose: 'key_establishment', crypto_module: 'openssl' };
  // Stage 6: #5573's approved-algorithm list has AES-GCM but no ML-KEM, so the same gated
  // module gives `compliant` for one and the refined verdict for the other.
  const aes = assessAsset({ ...base, algorithm: 'AES-256-GCM', purpose: 'encryption', crypto_module_detail: rhel() });
  assert.equal(aes.verdict, 'compliant');
  assert.equal(aes.cavpCovered, 'covered');
  const on = assessAsset({ ...base, crypto_module_detail: rhel() });
  assert.equal(on.verdict, 'compliant_module_algo_unverified');
  assert.equal(on.cavpCovered, 'not_covered');
  assert.deepEqual(on.certIds, ['5573']);
  assert.equal(on.fipsMode, 'confirmed');
  const off = assessAsset({ ...base, crypto_module_detail: rhel({ hostModeFacts: undefined }) });
  assert.equal(off.verdict, 'approved_unvalidated');
  assert.equal(off.candidateCertId, '5573');
  assert.equal(assessAsset({ ...base, crypto_module: null }).verdict, 'approved_unvalidated');
  assert.equal(assessAsset({ ...base, algorithm: 'MD5', crypto_module_detail: rhel() }).verdict, 'noncompliant', 'a validated module does not rescue a disallowed algorithm');
  assert.equal(assessAsset({ ...base, algorithm: 'AES-256-GCM', purpose: 'encryption', crypto_module: 'aws-kms-hsm' }).verdict, 'compliant');
});

test('evidence CSV: stamped, one row per asset, formula cells neutralised', () => {
  const out = buildAttestationCsv('Acme, Inc.', [
    { id: '1', name: '=HYPERLINK("http://x","y")', type: 'algorithm', algorithm: 'AES-256-GCM', purpose: 'encryption', crypto_module: 'openssl', crypto_module_detail: rhel(), hostname: 'web01' },
    { id: '2', name: 'CN=web', type: 'certificate', algorithm: 'RSA', key_size: 1024, hostname: '+cmd' },
  ], new Date('2026-11-16T00:00:00Z'));
  const lines = out.csv.trim().split('\r\n');
  assert.match(out.csv, /# FIPS algorithm table/);
  assert.match(out.csv, /# CMVP module map,2026-11-15/);
  assert.match(out.csv, /not a certification/);
  assert.match(out.csv, /"# Tenant","Acme, Inc\."|# Tenant,"Acme, Inc\."/);
  const header = lines.findIndex(l => l.startsWith('Asset,'));
  assert.equal(lines.length - header - 1, 2);
  assert.ok(lines[header + 1].startsWith(`"'=HYPERLINK(""http://x"",""y"")"`), lines[header + 1]);
  assert.match(lines[header + 1], /#5573/);
  assert.match(lines[header + 1], /,compliant,/);
  assert.match(lines[header + 2], /'\+cmd/);
  assert.match(lines[header + 2], /,noncompliant,/);
  assert.equal(out.counts.compliant, 1);
  assert.equal(out.counts.noncompliant, 1);
  assert.equal(out.total, 2);
});
