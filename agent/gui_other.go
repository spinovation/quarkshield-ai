//go:build !windows

package main

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func hideConsole(cmd *exec.Cmd) {}
func detachConsole()            {}
func createDesktopAndStartMenuShortcuts() {}
func removeDesktopAndStartMenuShortcuts() {}

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
		}
	}
	return ""
}

