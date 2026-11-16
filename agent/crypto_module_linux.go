//go:build linux

package main

import (
	"os"
	"runtime"
)

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
