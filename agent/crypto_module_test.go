package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseOpenSSLVersion(t *testing.T) {
	cases := []struct{ in, key, version string }{
		{"OpenSSL 3.0.7 1 Nov 2022 (Library: OpenSSL 3.0.7 1 Nov 2022)\n", ModuleOpenSSL, "3.0.7"},
		{"OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)", ModuleOpenSSL, "3.0.13"},
		{"OpenSSL 1.1.1k  FIPS 25 Mar 2021", ModuleOpenSSL, "1.1.1k"},
		{"LibreSSL 3.3.6", ModuleLibreSSL, "3.3.6"},
		// The tool and the library it loaded differ: the library is the module.
		{"OpenSSL 3.2.0 23 Nov 2023 (Library: OpenSSL 3.0.2 15 Mar 2022)", ModuleOpenSSL, "3.0.2"},
		{"command not found", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		key, version := parseOpenSSLVersion(c.in)
		if key != c.key || version != c.version {
			t.Errorf("parseOpenSSLVersion(%q) = %q %q, want %q %q", c.in, key, version, c.key, c.version)
		}
	}
}

func TestParseModulesDir(t *testing.T) {
	if got := parseModulesDir(`MODULESDIR: "/usr/lib64/ossl-modules"`); got != "/usr/lib64/ossl-modules" {
		t.Errorf("got %q", got)
	}
	if got := parseModulesDir("OpenSSL 1.1.1k"); got != "" {
		t.Errorf("OpenSSL 1.x has no modules directory, got %q", got)
	}
}

func TestParseProviderIdentity(t *testing.T) {
	rhel := `Providers:
  default
    name: OpenSSL Default Provider
    version: 3.0.7
    status: active
  fips
    name: Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider
    version: 3.0.7-395c1a240fbfffd8
    status: active
`
	name, version, ok := parseProviderIdentity(rhel, "fips")
	if !ok || name != "Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider" || version != "3.0.7-395c1a240fbfffd8" {
		t.Errorf("fips provider = %q %q %v", name, version, ok)
	}
	// The default provider's name must never be reported as the FIPS provider's.
	if name, _, ok := parseProviderIdentity("Providers:\n  default\n    name: OpenSSL Default Provider\n    version: 3.0.13\n", "fips"); ok || name != "" {
		t.Errorf("fips provider reported where only default is listed: %q %v", name, ok)
	}
	if _, _, ok := parseProviderIdentity("unable to load provider fips", "fips"); ok {
		t.Error("an error message is not a provider listing")
	}
}

func TestParseSSHVersion(t *testing.T) {
	cases := []struct{ in, product, key, version string }{
		{"OpenSSH_8.7p1, OpenSSL 3.0.7 1 Nov 2022", "OpenSSH_8.7p1", ModuleOpenSSL, "3.0.7"},
		{"OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024", "OpenSSH_9.6p1", ModuleOpenSSL, "3.0.13"},
		{"OpenSSH_9.9p2, LibreSSL 3.3.6", "OpenSSH_9.9p2", ModuleLibreSSL, "3.3.6"},
		{"OpenSSH_for_Windows_8.6p1, LibreSSL 3.4.3", "OpenSSH_for_Windows_8.6p1", ModuleLibreSSL, "3.4.3"},
		{"OpenSSH_9.0p1, without OpenSSL", "", "", ""},
		{"", "", "", ""},
	}
	for _, c := range cases {
		product, key, version := parseSSHVersion(c.in)
		if product != c.product || key != c.key || version != c.version {
			t.Errorf("parseSSHVersion(%q) = %q %q %q", c.in, product, key, version)
		}
	}
}

func TestParseOSRelease(t *testing.T) {
	env := parseOSRelease("NAME=\"Red Hat Enterprise Linux\"\nVERSION=\"9.4 (Plow)\"\nID=\"rhel\"\nVERSION_ID=\"9.4\"\nPRETTY_NAME=\"Red Hat Enterprise Linux 9.4 (Plow)\"\n")
	if env.ID != "rhel" || env.Version != "9.4" || env.Name != "Red Hat Enterprise Linux 9.4 (Plow)" {
		t.Errorf("rhel: %+v", env)
	}
	env = parseOSRelease("ID=ubuntu\nVERSION_ID=\"22.04\"\nNAME=\"Ubuntu\"\nVERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\n")
	if env.ID != "ubuntu" || env.Version != "22.04" || env.Name != "Ubuntu 22.04.4 LTS (Jammy Jellyfish)" {
		t.Errorf("ubuntu: %+v", env)
	}
}

func TestParseWindowsProbe(t *testing.T) {
	name, display, version, file := parseWindowsProbe("Windows 10 Pro|22H2|10.0.19045.4651|10.0.19041.4597|1|\r\n")
	if name != "Windows 10 Pro" || display != "22H2" || version != "10.0.19045.4651" || file != "10.0.19041.4597" {
		t.Errorf("got %q %q %q %q", name, display, version, file)
	}
	// A missing registry value leaves a hole in the version: report no version, not a wrong one.
	if _, _, version, _ := parseWindowsProbe("Windows Server 2016|| 10.0.14393.|10.0.14393.0||"); version != "" {
		t.Errorf("incomplete build accepted: %q", version)
	}
	if name, _, _, _ := parseWindowsProbe("Get-ItemProperty : access denied"); name != "" {
		t.Errorf("error text parsed as a probe result: %q", name)
	}
}

func TestLinkFindingsToModules(t *testing.T) {
	cng := CryptoModule{Ref: "windows-cng:10.0.19045.4651", Key: ModuleWindowsCNG, Name: "CNG", Version: "10.0.19045.4651"}
	sysSSL := CryptoModule{Ref: "openssl:3.0.7", Key: ModuleOpenSSL, Name: "OpenSSL", Version: "3.0.7", binPath: "/usr/bin/openssl"}
	report := HostModuleReport{Environment: OperatingEnvironment{ID: "rhel", Version: "9.4"}, Modules: []CryptoModule{cng, sysSSL}}

	sshCalls := 0
	ssh := func() (CryptoModule, bool) {
		sshCalls++
		return CryptoModule{Ref: "openssl:3.0.7", Key: ModuleOpenSSL, Version: "3.0.7", Evidence: "/usr/bin/ssh -V: OpenSSH_8.7p1, OpenSSL 3.0.7"}, true
	}
	brew := func(p string) (CryptoModule, bool) {
		return CryptoModule{Ref: "openssl:3.4.0", Key: ModuleOpenSSL, Version: "3.4.0", binPath: p}, true
	}

	in := []AuditResult{
		{ID: "lin-sshd-cfg-12", Type: "config"},
		{ID: "lin-sshd-cfg-19", Type: "config"},
		{ID: "win-cipher-tls_rsa_with_3des", Type: "config"},
		{ID: "win-schannel-tls1.0", Type: "config"},
		{ID: "pkg-openssl", Type: "package", Path: "/usr/bin/openssl"},
		{ID: "lin-crypto-policy", Type: "config"},
		{ID: "cert-1", Type: "certificate", Path: "/etc/ssl/certs/x.pem"},
		{ID: "key-1", Type: "ssh_key", Path: "/root/.ssh/id_rsa"},
		{ID: "cli-cfg-abc-0", Type: "config", Path: "/etc/nginx/nginx.conf"},
	}
	out, rep := linkFindingsToModules(in, report, ssh, brew)

	want := map[string]string{
		"lin-sshd-cfg-12": "openssl:3.0.7", "lin-sshd-cfg-19": "openssl:3.0.7",
		"win-cipher-tls_rsa_with_3des": cng.Ref, "win-schannel-tls1.0": cng.Ref,
		"pkg-openssl": "openssl:3.0.7",
		// Data and findings with no single module: never linked.
		"lin-crypto-policy": "", "cert-1": "", "key-1": "", "cli-cfg-abc-0": "",
	}
	for _, a := range out {
		if a.CryptoModule != want[a.ID] {
			t.Errorf("%s linked to %q, want %q", a.ID, a.CryptoModule, want[a.ID])
		}
		if (a.CryptoModule == "") != (a.CryptoModuleEvidence == "") {
			t.Errorf("%s: a link must carry its evidence, and only a link", a.ID)
		}
	}
	if sshCalls != 1 {
		t.Errorf("ssh asked %d times, want once", sshCalls)
	}
	if len(rep.Modules) != 2 {
		t.Errorf("ssh's library is the system one already listed; got %d modules", len(rep.Modules))
	}
	for _, a := range in {
		if a.CryptoModule != "" {
			t.Fatal("the caller's findings were modified")
		}
	}

	// A second OpenSSL (Homebrew) behind the package finding is added to the report.
	out, rep = linkFindingsToModules([]AuditResult{{ID: "pkg-openssl", Type: "package", Path: "/opt/homebrew/bin/openssl"}}, report, ssh, brew)
	if out[0].CryptoModule != "openssl:3.4.0" || len(rep.Modules) != 3 {
		t.Errorf("second library: linked %q, %d modules", out[0].CryptoModule, len(rep.Modules))
	}

	// No module known, nothing answers: findings stay unlinked rather than guessed.
	none := func() (CryptoModule, bool) { return CryptoModule{}, false }
	out, rep = linkFindingsToModules(in, HostModuleReport{}, none, func(string) (CryptoModule, bool) { return CryptoModule{}, false })
	for _, a := range out {
		if a.CryptoModule != "" {
			t.Errorf("%s linked with no module observed", a.ID)
		}
	}
	if len(rep.Modules) != 0 {
		t.Errorf("modules invented: %d", len(rep.Modules))
	}
}

// The agent observes identity only. It must never name a certificate or claim validation.
func TestReportCarriesNoCertificateClaim(t *testing.T) {
	rep := HostModuleReport{
		Environment: OperatingEnvironment{ID: "rhel", Version: "9.4", Arch: "amd64"},
		Modules: []CryptoModule{{Ref: "openssl:3.0.7", Key: ModuleOpenSSL, Name: "OpenSSL", Version: "3.0.7", binPath: "/usr/bin/openssl",
			FipsProvider: &FipsProviderIdentity{Present: "yes", Name: "Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider", Version: "3.0.7-395c1a240fbfffd8"}}},
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ToLower(string(b))
	for _, banned := range []string{"cmvp", "cert", "validated", "compliant", "binpath"} {
		if strings.Contains(s, banned) {
			t.Errorf("module report contains %q: %s", banned, b)
		}
	}
}

// Runs the real detection on the build machine: it must finish and stay self-consistent.
func TestHostCryptoModulesOnThisMachine(t *testing.T) {
	rep := HostCryptoModules()
	if rep.Environment.ID == "" || rep.Environment.Arch == "" {
		t.Errorf("environment not identified: %+v", rep.Environment)
	}
	seen := map[string]bool{}
	for _, m := range rep.Modules {
		if m.Ref == "" || m.Key == "" || m.Evidence == "" {
			t.Errorf("module without ref, key or evidence: %+v", m)
		}
		if seen[m.Ref] {
			t.Errorf("duplicate ref %s", m.Ref)
		}
		seen[m.Ref] = true
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	t.Logf("observed on this machine:\n%s", b)
}

func TestParseWindowsFipsPolicy(t *testing.T) {
	cases := []struct{ in, enabled, mdm string }{
		{"Windows 11 Pro|22H2|10.0.22621.4317|10.0.22621.1|1|", "1", ""},
		{"Windows 11 Pro|22H2|10.0.22621.4317|10.0.22621.1|0|1", "0", "1"},
		{"Windows 11 Pro|22H2|10.0.22621.4317|10.0.22621.1||", "", ""},
		// Not a number: absent, never on or off.
		{"Windows 11 Pro|22H2|10.0.22621.4317|10.0.22621.1|True|yes", "", ""},
		{"access denied", "", ""},
	}
	for _, c := range cases {
		enabled, mdm := parseWindowsFipsPolicy(c.in)
		if enabled != c.enabled || mdm != c.mdm {
			t.Errorf("parseWindowsFipsPolicy(%q) = %q %q", c.in, enabled, mdm)
		}
	}
}

func TestParseActiveProviders(t *testing.T) {
	both := "Providers:\n  default\n    name: OpenSSL Default Provider\n    version: 3.0.7\n    status: active\n  fips\n    name: Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider\n    version: 3.0.7-cda111b5812c30d4\n    status: active\n"
	if got := strings.Join(parseActiveProviders(both), ","); got != "default,fips" {
		t.Errorf("got %q", got)
	}
	inactive := "Providers:\n  default\n    name: OpenSSL Default Provider\n    status: active\n  fips\n    name: X\n    status: inactive\n"
	if got := strings.Join(parseActiveProviders(inactive), ","); got != "default" {
		t.Errorf("an inactive provider was reported active: %q", got)
	}
	if got := parseActiveProviders("list: unable to load provider"); len(got) != 0 {
		t.Errorf("error text parsed as providers: %v", got)
	}
}
