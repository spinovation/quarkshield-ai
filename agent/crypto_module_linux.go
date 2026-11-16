//go:build linux

package main

import (
	"os"
	"runtime"
	"strings"
)

// detectPlatformModeFacts reads the system-wide FIPS switches. A file that cannot be read
// produces no fact: absence is reported as absence, never as "off".
func detectPlatformModeFacts() []ModeFact {
	facts := []ModeFact{}
	read := func(name, path string, max int) {
		b, err := os.ReadFile(path)
		if err != nil {
			return
		}
		v := strings.TrimSpace(string(b))
		if len(v) > max {
			v = v[:max]
		}
		facts = append(facts, ModeFact{Name: name, Value: v, Source: path})
	}
	read("linux.kernel.fips_enabled", "/proc/sys/crypto/fips_enabled", 8)
	// The applied system crypto policy (RHEL family); the configured one as a fallback.
	read("linux.crypto_policy.current", "/etc/crypto-policies/state/current", 60)
	read("linux.crypto_policy.config", "/etc/crypto-policies/config", 60)
	if b, err := os.ReadFile("/proc/cmdline"); err == nil {
		for _, f := range strings.Fields(string(b)) {
			if strings.HasPrefix(f, "fips=") {
				facts = append(facts, ModeFact{Name: "linux.kernel.cmdline_fips", Value: strings.TrimPrefix(f, "fips="), Source: "/proc/cmdline"})
			}
		}
	}
	return facts
}

func detectOperatingEnvironment() OperatingEnvironment {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if b, err := os.ReadFile(p); err == nil {
			if env := parseOSRelease(string(b)); env.ID != "" {
				return env
			}
		}
	}
	return OperatingEnvironment{ID: "linux", Arch: runtime.GOARCH}
}

// The system OpenSSL only: fixed paths, never PATH (the agent may run as root).
func detectPlatformModules(_ OperatingEnvironment) []CryptoModule {
	mods := []CryptoModule{}
	if bin := existingFile("/usr/bin/openssl", "/bin/openssl"); bin != "" {
		if m, ok := detectOpenSSLAt(bin); ok {
			mods = append(mods, m)
		}
	}
	return mods
}

func sshBinaryPath() string { return existingFile("/usr/bin/ssh", "/bin/ssh") }
