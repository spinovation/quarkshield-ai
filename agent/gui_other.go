//go:build !windows

package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func hideConsole(cmd *exec.Cmd) {}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func detachConsole() {}

// ensureBackgroundService (DEF-39, macOS) installs + loads a per-user LaunchAgent so
// the agent keeps polling for on-demand pulls and running scheduled syncs even when
// the GUI app is closed. The plist runs THIS executable with --daemon; the daemon
// reads the enrollment token from ~/.quarkshield. No-op on Linux (install-linux.sh
// handles systemd there).
func ensureBackgroundService(serverURL string) {
	if runtime.GOOS != "darwin" {
		return
	}
	exePath, err := os.Executable()
	if err != nil || exePath == "" {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	if serverURL == "" {
		serverURL = "https://quarkshield.ai"
	}
	if err := validateServerURL(serverURL); err != nil {
		return
	}
	laDir := filepath.Join(home, "Library", "LaunchAgents")
	_ = os.MkdirAll(laDir, 0755)
	logDir := filepath.Join(home, "Library", "Logs", "QuarkShield")
	_ = os.MkdirAll(logDir, 0700)
	plistPath := filepath.Join(laDir, "ai.quarkshield.agent.plist")
	// Values are XML-escaped: exePath/serverURL must not be able to inject extra
	// <string> arguments into ProgramArguments.
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>ai.quarkshield.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>--daemon</string>
        <string>--server</string>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>ThrottleInterval</key><integer>30</integer>
    <key>ProcessType</key><string>Background</string>
    <key>StandardOutPath</key><string>%s</string>
    <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, xmlEscape(exePath), xmlEscape(serverURL), xmlEscape(filepath.Join(logDir, "agent.log")), xmlEscape(filepath.Join(logDir, "agent.err")))
	existing, _ := os.ReadFile(plistPath)
	if string(existing) != plist {
		if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
			return
		}
		_ = exec.Command("launchctl", "unload", plistPath).Run()
	}
	// (Re)load — harmless if already loaded.
	_ = exec.Command("launchctl", "load", "-w", plistPath).Run()
}

// removeBackgroundService (macOS) unloads + deletes the LaunchAgent on uninstall so
// launchd stops trying to run a removed binary. No-op elsewhere.
func removeBackgroundService() {
	if runtime.GOOS != "darwin" {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", "ai.quarkshield.agent.plist")
	_ = exec.Command("launchctl", "unload", plistPath).Run()
	_ = os.Remove(plistPath)
}

// createDesktopAndStartMenuShortcuts creates Linux XDG desktop entry
func createDesktopAndStartMenuShortcuts() {
	if runtime.GOOS != "linux" {
		return
	}
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	desktopEntry := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=QuarkShield Post-Quantum Guard
Comment=Post-Quantum Cryptographic Vulnerability Scanner
Exec="%s" --gui
Icon=security-high
Terminal=false
Categories=Security;System;
`, exePath)

	appDir := filepath.Join(home, ".local", "share", "applications")
	_ = os.MkdirAll(appDir, 0755)
	_ = os.WriteFile(filepath.Join(appDir, "quarkshield.desktop"), []byte(desktopEntry), 0644)

	desktopDir := filepath.Join(home, "Desktop")
	if fi, err := os.Stat(desktopDir); err == nil && fi.IsDir() {
		_ = os.WriteFile(filepath.Join(desktopDir, "quarkshield.desktop"), []byte(desktopEntry), 0755)
	}
}

// removeDesktopAndStartMenuShortcuts removes Linux XDG desktop entry
func removeDesktopAndStartMenuShortcuts() {
	if runtime.GOOS != "linux" {
		return
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		_ = os.Remove(filepath.Join(home, ".local", "share", "applications", "quarkshield.desktop"))
		_ = os.Remove(filepath.Join(home, "Desktop", "quarkshield.desktop"))
	}
}

// pickFolderOS opens native folder browser dialog on macOS and Linux
func pickFolderOS() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if runtime.GOOS == "darwin" {
		cmd := exec.CommandContext(ctx, "osascript", "-e", "activate", "-e", `POSIX path of (choose folder with prompt "Select folder to audit for Quantum Readiness:")`)
		out, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	} else if runtime.GOOS == "linux" {
		if _, err := exec.LookPath("zenity"); err == nil {
			cmd := exec.CommandContext(ctx, "zenity", "--file-selection", "--directory", "--title=Select folder to audit for Quantum Readiness")
			out, err := cmd.Output()
			if err == nil {
				return strings.TrimSpace(string(out))
			}
		} else if _, err := exec.LookPath("kdialog"); err == nil {
			cmd := exec.CommandContext(ctx, "kdialog", "--getexistingdirectory", "")
			out, err := cmd.Output()
			if err == nil {
				return strings.TrimSpace(string(out))
			}
		} else if _, err := exec.LookPath("yad"); err == nil {
			cmd := exec.CommandContext(ctx, "yad", "--file-selection", "--directory", "--title=Select folder to audit for Quantum Readiness")
			out, err := cmd.Output()
			if err == nil {
				return strings.TrimSpace(string(out))
			}
		} else if _, err := exec.LookPath("qarma"); err == nil {
			cmd := exec.CommandContext(ctx, "qarma", "--file-selection", "--directory", "--title=Select folder to audit for Quantum Readiness")
			out, err := cmd.Output()
			if err == nil {
				return strings.TrimSpace(string(out))
			}
		}
	}
	return ""
}
