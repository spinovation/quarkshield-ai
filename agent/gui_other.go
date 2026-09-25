//go:build !windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func hideConsole(cmd *exec.Cmd) {}
func detachConsole()            {}

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

