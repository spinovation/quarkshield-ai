package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// GetHardwareUUID returns an immutable, permanent hardware UUID for this workstation.
func GetHardwareUUID() string {
	switch runtime.GOOS {
	case "darwin":
		// Query Apple IOPlatformUUID from IOKit registry
		cmd := exec.Command("ioreg", "-d2", "-c", "IOPlatformExpertDevice")
		out, err := cmd.Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "IOPlatformUUID") {
					parts := strings.Split(line, "=")
					if len(parts) >= 2 {
						uuid := strings.Trim(strings.TrimSpace(parts[1]), "\"")
						if len(uuid) > 10 {
							return uuid
						}
					}
				}
			}
		}

	case "windows":
		// Query Windows MachineGuid from Registry
		cmd := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid")
		hideConsole(cmd)
		out, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				if strings.Contains(line, "MachineGuid") {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						return fields[len(fields)-1]
					}
				}
			}
		}

	case "linux":
		// Query systemd / dbus machine-id
		for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if data, err := os.ReadFile(path); err == nil {
				id := strings.TrimSpace(string(data))
				if len(id) > 10 {
					return id
				}
			}
		}
	}

	// Persistent fallback if hardware UUID could not be directly queried
	return getPersistentFallbackUUID()
}

// GetFriendlyComputerName returns the user-configured workstation display name
// (e.g., "Ganapati’s MacBook Pro" on macOS rather than dynamic DHCP names).
func GetFriendlyComputerName() string {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("scutil", "--get", "ComputerName")
		out, err := cmd.Output()
		if err == nil {
			name := strings.TrimSpace(string(out))
			if name != "" {
				return name
			}
		}
	case "windows":
		compName := os.Getenv("COMPUTERNAME")
		if compName != "" {
			return compName
		}
	}

	hName, err := os.Hostname()
	if err == nil && hName != "" {
		return hName
	}
	return "workstation"
}

// getPersistentFallbackUUID generates and permanently saves a random UUID to ~/.quarkshield/device_id
func getPersistentFallbackUUID() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dir := filepath.Join(home, ".quarkshield")
	_ = os.MkdirAll(dir, 0755)
	idFile := filepath.Join(dir, "device_id")

	if data, err := os.ReadFile(idFile); err == nil {
		id := strings.TrimSpace(string(data))
		if len(id) > 10 {
			return id
		}
	}

	// Generate random 128-bit UUIDv4
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	newUUID := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])

	_ = os.WriteFile(idFile, []byte(newUUID), 0644)
	return newUUID
}
