//go:build darwin

package main

import (
	"runtime"
	"strings"
)

func detectOperatingEnvironment() OperatingEnvironment {
	env := OperatingEnvironment{ID: "macos", Arch: runtime.GOARCH}
	if out, err := runProbe("/usr/bin/sw_vers", "-productVersion"); err == nil {
		env.Version = strings.TrimSpace(out)
	}
	build := ""
	if out, err := runProbe("/usr/bin/sw_vers", "-buildVersion"); err == nil {
		build = strings.TrimSpace(out)
	}
	env.Name = strings.TrimSpace("macOS " + env.Version)
	if build != "" {
		env.Name += " (" + build + ")"
	}
	return env
}

func detectPlatformModules(env OperatingEnvironment) []CryptoModule {
	mods := []CryptoModule{}
	// corecrypto is part of macOS and has no version of its own to read: Apple validates
	// one corecrypto module per macOS release, so the OS version is its identity.
	if env.Version != "" {
		mods = append(mods, CryptoModule{
			Ref:      moduleRef(ModuleAppleCoreCrypt, env.Version),
			Key:      ModuleAppleCoreCrypt,
			Name:     "Apple corecrypto",
			Version:  env.Version,
			Evidence: "sw_vers: " + env.Name + ". corecrypto ships with the operating system; its version is taken from the macOS release.",
		})
	}
	if m, ok := detectOpenSSLAt("/usr/bin/openssl"); ok {
		mods = append(mods, m)
	}
	return mods
}

func sshBinaryPath() string { return existingFile("/usr/bin/ssh") }
