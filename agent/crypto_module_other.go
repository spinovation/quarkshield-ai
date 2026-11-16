//go:build !windows && !darwin && !linux

package main

import "runtime"

func detectOperatingEnvironment() OperatingEnvironment {
	return OperatingEnvironment{ID: runtime.GOOS, Arch: runtime.GOARCH}
}

func detectPlatformModules(_ OperatingEnvironment) []CryptoModule { return []CryptoModule{} }

func sshBinaryPath() string { return "" }
