package main

// Host cryptographic module identity (CMVP/FIPS Stage 4, prerequisite P-a).
//
// A CMVP certificate belongs to a cryptographic MODULE (a specific library build on a
// specific operating environment), never to a certificate file or a key. This file
// records which modules are on the host: name, exact version and operating environment,
// each with the command or file the fact was read from.
//
// Observation only. The agent never names a CMVP certificate and never says a module is
// validated: the certificate map lives on the server, so it can be corrected without an
// agent rebuild. Whether a module is running in FIPS-approved mode is a separate question
// (Stage 5) and is deliberately not answered here.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Stable module family keys. The server's host-module map is keyed by these.
const (
	ModuleOpenSSL        = "openssl"
	ModuleLibreSSL       = "libressl"
	ModuleWindowsCNG     = "windows-cng"
	ModuleAppleCoreCrypt = "apple-corecrypto"
)

// OperatingEnvironment is the platform a module runs on. CMVP validations list the tested
// operating environments, so the module version alone is not enough to name a certificate.
type OperatingEnvironment struct {
	ID      string `json:"id"`                // os-release ID (rhel, ubuntu, ...), "windows" or "macos"
	Name    string `json:"name,omitempty"`    // as the OS describes itself
	Version string `json:"version,omitempty"` // 9.4 | 14.5 | 10.0.19045.4651
	Arch    string `json:"arch"`
}

// FipsProviderIdentity is the identity of an OpenSSL 3 FIPS provider module found
// installed beside the library. Present is "yes", "no" or "unknown". It says the module
// file exists, NOT that applications use it.
type FipsProviderIdentity struct {
	Present string `json:"present"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
}

// ModeFact is one host fact that bears on whether a module is running in its FIPS-approved
// mode (CMVP/FIPS Stage 5, prerequisite P-b): a name, the value read, and where it was read.
// The agent reports facts only. What they add up to is decided on the server, against the
// rule each module's Security Policy sets, so a rule can be corrected without an agent rebuild.
type ModeFact struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// CryptoModule is one observed module. Ref is unique within a host report and is what a
// finding points at (AuditResult.CryptoModule).
type CryptoModule struct {
	Ref          string                `json:"ref"`
	Key          string                `json:"key"`
	Name         string                `json:"name"`
	Version      string                `json:"version,omitempty"`
	FipsProvider *FipsProviderIdentity `json:"fipsProvider,omitempty"`
	Evidence     string                `json:"evidence"`
	// Facts about this module's own configuration (for OpenSSL: which providers the default
	// library context has active).
	ModeFacts []ModeFact `json:"modeFacts,omitempty"`
	binPath   string
}

// HostModuleReport is what travels in fleet telemetry.
type HostModuleReport struct {
	Environment OperatingEnvironment `json:"environment"`
	Modules     []CryptoModule       `json:"modules"`
	// Host-wide FIPS-mode facts (kernel flag, system crypto policy, Windows FIPS policy).
	ModeFacts []ModeFact `json:"modeFacts,omitempty"`
}

const moduleProbeTimeout = 8 * time.Second

// runProbe runs a read-only identity command with a hard timeout.
func runProbe(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), moduleProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func moduleRef(key, version string) string {
	if version == "" {
		return key
	}
	return key + ":" + version
}

// ---- Parsers (pure, tested in crypto_module_test.go) ------------------------

var reOpenSSLLibrary = regexp.MustCompile(`\(Library:\s*(OpenSSL|LibreSSL)\s+([0-9][0-9A-Za-z.\-+~]*)`)
var reOpenSSLBanner = regexp.MustCompile(`(?m)^\s*(OpenSSL|LibreSSL)\s+([0-9][0-9A-Za-z.\-+~]*)`)

// parseOpenSSLVersion reads `openssl version`. When the tool and the library it loaded
// differ, OpenSSL prints both; the library is the module, so it wins.
func parseOpenSSLVersion(out string) (key, version string) {
	m := reOpenSSLLibrary.FindStringSubmatch(out)
	if m == nil {
		m = reOpenSSLBanner.FindStringSubmatch(out)
	}
	if m == nil {
		return "", ""
	}
	if m[1] == "LibreSSL" {
		return ModuleLibreSSL, m[2]
	}
	return ModuleOpenSSL, m[2]
}

var reModulesDir = regexp.MustCompile(`MODULESDIR:\s*"([^"]+)"`)

// parseModulesDir reads `openssl version -m` (OpenSSL 3 only).
func parseModulesDir(out string) string {
	if m := reModulesDir.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// parseProviderIdentity reads the name and version of one provider out of
// `openssl list -providers` output. Returns ok=false when that provider is not listed.
func parseProviderIdentity(out, provider string) (name, version string, ok bool) {
	in := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "Providers:" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent <= 2 && !strings.Contains(trimmed, ":") {
			in = trimmed == provider
			ok = ok || in
			continue
		}
		if !in {
			continue
		}
		if v, found := strings.CutPrefix(trimmed, "name:"); found {
			name = strings.TrimSpace(v)
		} else if v, found := strings.CutPrefix(trimmed, "version:"); found {
			version = strings.TrimSpace(v)
		}
	}
	return name, version, ok
}

// parseActiveProviders returns the ids of the providers `openssl list -providers` shows
// with "status: active", in the order listed.
func parseActiveProviders(out string) []string {
	active := []string{}
	current := ""
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "Providers:" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent <= 2 && !strings.Contains(trimmed, ":") {
			current = trimmed
			continue
		}
		if current != "" && trimmed == "status: active" {
			active = append(active, current)
			current = ""
		}
	}
	return active
}

var reSSHVersion = regexp.MustCompile(`(OpenSSH[_A-Za-z]*_[0-9][0-9A-Za-z.]*)[^,]*,\s*(OpenSSL|LibreSSL)\s+([0-9][0-9A-Za-z.\-+~]*)`)

// parseSSHVersion reads `ssh -V`, which prints the crypto library OpenSSH is running on:
// "OpenSSH_8.7p1, OpenSSL 3.0.7 1 Nov 2022" or "OpenSSH_9.6p1, LibreSSL 3.3.6".
func parseSSHVersion(out string) (product, key, version string) {
	m := reSSHVersion.FindStringSubmatch(out)
	if m == nil {
		return "", "", ""
	}
	if m[2] == "LibreSSL" {
		return m[1], ModuleLibreSSL, m[3]
	}
	return m[1], ModuleOpenSSL, m[3]
}

// parseWindowsProbe splits the single line the Windows identity probe prints:
// ProductName|DisplayVersion|major.minor.build.ubr|file version of bcryptprimitives.dll|
// FipsAlgorithmPolicy Enabled|FipsAlgorithmPolicy MDMEnabled.
// A version with an empty component (a registry value that was not there) is dropped.
// The two policy values are "0", "1" or "" (value absent); see parseWindowsFipsPolicy.
func parseWindowsProbe(out string) (name, display, version, fileVersion string) {
	parts := strings.Split(firstLine(out), "|")
	if len(parts) != 6 {
		return "", "", "", ""
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`).MatchString(parts[2]) {
		version = parts[2]
	}
	return parts[0], parts[1], version, parts[3]
}

// parseWindowsFipsPolicy reads the two FIPS policy registry values from the probe line.
// Anything that is not a plain number is reported as absent, never as on or off.
func parseWindowsFipsPolicy(out string) (enabled, mdmEnabled string) {
	parts := strings.Split(firstLine(out), "|")
	if len(parts) != 6 {
		return "", ""
	}
	num := func(s string) string {
		s = strings.TrimSpace(s)
		if regexp.MustCompile(`^\d+$`).MatchString(s) {
			return s
		}
		return ""
	}
	return num(parts[4]), num(parts[5])
}

// parseOSRelease reads /etc/os-release.
func parseOSRelease(content string) OperatingEnvironment {
	kv := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		k, v, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found || strings.HasPrefix(k, "#") {
			continue
		}
		kv[k] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	name := kv["PRETTY_NAME"]
	if name == "" {
		name = strings.TrimSpace(kv["NAME"] + " " + kv["VERSION"])
	}
	return OperatingEnvironment{ID: strings.ToLower(kv["ID"]), Name: name, Version: kv["VERSION_ID"], Arch: runtime.GOARCH}
}

// ---- OpenSSL / LibreSSL -----------------------------------------------------

// detectOpenSSLAt identifies the library behind one openssl binary and, for OpenSSL 3,
// whether a FIPS provider module is installed in its modules directory.
func detectOpenSSLAt(binPath string) (CryptoModule, bool) {
	out, err := runProbe(binPath, "version")
	if err != nil {
		return CryptoModule{}, false
	}
	key, version := parseOpenSSLVersion(out)
	if key == "" {
		return CryptoModule{}, false
	}
	m := CryptoModule{
		Ref:      moduleRef(key, version),
		Key:      key,
		Name:     map[string]string{ModuleOpenSSL: "OpenSSL", ModuleLibreSSL: "LibreSSL"}[key],
		Version:  version,
		Evidence: binPath + " version: " + firstLine(out),
		binPath:  binPath,
	}
	if key == ModuleOpenSSL && strings.HasPrefix(version, "3.") {
		m.FipsProvider = detectFipsProvider(binPath)
		// With no -provider flag this lists what the DEFAULT library context loads from the
		// system configuration: the providers an ordinary application gets.
		if out, err := runProbe(binPath, "list", "-providers"); err == nil {
			if active := parseActiveProviders(out); len(active) > 0 {
				m.ModeFacts = append(m.ModeFacts, ModeFact{
					Name: "openssl.default_providers", Value: strings.Join(active, ","),
					Source: binPath + " list -providers",
				})
			}
		}
	}
	return m, true
}

// detectFipsProvider looks for the FIPS provider module file, then asks OpenSSL to name
// it. Loading the provider to read its name runs its self-tests and changes nothing.
func detectFipsProvider(binPath string) *FipsProviderIdentity {
	dirOut, err := runProbe(binPath, "version", "-m")
	dir := parseModulesDir(dirOut)
	if err != nil || dir == "" {
		return &FipsProviderIdentity{Present: "unknown"}
	}
	path := findFipsModuleFile(dir)
	if path == "" {
		return &FipsProviderIdentity{Present: "no"}
	}
	id := &FipsProviderIdentity{Present: "yes", Path: path}
	if out, err := runProbe(binPath, "list", "-providers", "-provider", "fips"); err == nil {
		if name, version, ok := parseProviderIdentity(out, "fips"); ok {
			id.Name, id.Version = name, version
		}
	}
	return id
}

// findFipsModuleFile returns the FIPS provider module in an OpenSSL modules directory.
func findFipsModuleFile(dir string) string {
	for _, name := range []string{"fips.so", "fips.dylib", "fips.dll"} {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

func existingFile(paths ...string) string {
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// ---- Host report ------------------------------------------------------------

var (
	hostModulesOnce sync.Once
	hostModules     HostModuleReport
)

// HostCryptoModules returns the modules observed on this host. Detected once per process:
// the answer does not change between scans of a running agent.
func HostCryptoModules() HostModuleReport {
	hostModulesOnce.Do(func() {
		hostModules = HostModuleReport{Environment: detectOperatingEnvironment()}
		hostModules.Modules = dedupeModules(detectPlatformModules(hostModules.Environment))
		hostModules.ModeFacts = detectPlatformModeFacts()
	})
	return hostModules
}

func dedupeModules(in []CryptoModule) []CryptoModule {
	seen := map[string]bool{}
	out := []CryptoModule{}
	for _, m := range in {
		if m.Ref == "" || seen[m.Ref] {
			continue
		}
		seen[m.Ref] = true
		out = append(out, m)
	}
	return out
}

// sshCryptoLibrary asks the local OpenSSH which crypto library it runs on.
func sshCryptoLibrary() (CryptoModule, bool) {
	bin := sshBinaryPath()
	if bin == "" {
		return CryptoModule{}, false
	}
	out, _ := runProbe(bin, "-V") // prints to stderr and may exit non-zero on old builds
	product, key, version := parseSSHVersion(out)
	if key == "" {
		return CryptoModule{}, false
	}
	return CryptoModule{
		Ref:      moduleRef(key, version),
		Key:      key,
		Name:     map[string]string{ModuleOpenSSL: "OpenSSL", ModuleLibreSSL: "LibreSSL"}[key],
		Version:  version,
		Evidence: bin + " -V: " + firstLine(out) + " (" + product + ")",
	}, true
}

// ---- Tying findings to modules ----------------------------------------------

// isSSHConfigFinding matches the SSH configuration findings the platform auditors emit.
func isSSHConfigFinding(a AuditResult) bool {
	return a.Type == "config" && (strings.HasPrefix(a.ID, "lin-sshd-cfg-") || strings.HasPrefix(a.ID, "mac-cfg-"))
}

func isSchannelFinding(a AuditResult) bool {
	return a.Type == "config" && (strings.HasPrefix(a.ID, "win-schannel-") || strings.HasPrefix(a.ID, "win-cipher-"))
}

// linkFindingsToModules points a finding at the module that performs its cryptography,
// only where the host itself says so:
//   - the OpenSSL package finding is that library;
//   - SSH configuration is carried out by the library `ssh -V` reports;
//   - Schannel protocol and cipher-suite settings are carried out by Windows CNG.
//
// Everything else (certificate files, PEM and SSH keys, keystore files, remote endpoints)
// is data with no module on this host to observe, and is left unlinked.
// It returns a copy of the findings and the report extended with any module found on the way.
func linkFindingsToModules(findings []AuditResult, report HostModuleReport, ssh func() (CryptoModule, bool), opensslAt func(string) (CryptoModule, bool)) ([]AuditResult, HostModuleReport) {
	out := make([]AuditResult, len(findings))
	copy(out, findings)
	mods := append([]CryptoModule{}, report.Modules...)

	ensure := func(m CryptoModule) string {
		for _, have := range mods {
			if have.Ref == m.Ref {
				return have.Ref
			}
		}
		mods = append(mods, m)
		return m.Ref
	}
	byKey := func(key string) (string, bool) {
		for _, m := range mods {
			if m.Key == key {
				return m.Ref, true
			}
		}
		return "", false
	}

	var sshMod *CryptoModule
	sshAsked := false
	for i := range out {
		a := &out[i]
		switch {
		case a.ID == "pkg-openssl" && a.Path != "":
			ref := ""
			for _, m := range mods {
				if m.binPath == a.Path {
					ref = m.Ref
				}
			}
			if ref == "" && opensslAt != nil {
				if m, ok := opensslAt(a.Path); ok {
					ref = ensure(m)
				}
			}
			if ref != "" {
				a.CryptoModule = ref
				a.CryptoModuleEvidence = "This finding is the library itself (" + a.Path + ")."
			}
		case isSSHConfigFinding(*a):
			if !sshAsked && ssh != nil {
				sshAsked = true
				if m, ok := ssh(); ok {
					sshMod = &m
				}
			}
			if sshMod != nil {
				a.CryptoModule = ensure(*sshMod)
				a.CryptoModuleEvidence = "OpenSSH reports the crypto library it runs on. " + sshMod.Evidence
			}
		case isSchannelFinding(*a):
			if ref, ok := byKey(ModuleWindowsCNG); ok {
				a.CryptoModule = ref
				a.CryptoModuleEvidence = "Schannel is the Windows TLS stack and performs its cryptography in the Windows CNG primitives library."
			}
		}
	}
	return out, HostModuleReport{Environment: report.Environment, Modules: mods, ModeFacts: report.ModeFacts}
}

// withModuleLinks is the production wiring of linkFindingsToModules.
func withModuleLinks(findings []AuditResult) ([]AuditResult, HostModuleReport) {
	return linkFindingsToModules(findings, HostCryptoModules(), sshCryptoLibrary, detectOpenSSLAt)
}
