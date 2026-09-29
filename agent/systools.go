package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// scheduleSelfDelete removes the app's own files on uninstall WITHOUT building a
// shell command around an interpolated path (which allowed command injection when
// the install path contained shell metacharacters). On macOS/Linux it uses
// os.RemoveAll directly. On Windows the running exe is locked, so it schedules a
// deferred `del` via cmd.exe — but only when the path is free of cmd
// metacharacters; an unsafe path is left in place rather than risking injection.
func scheduleSelfDelete(target string) {
	if target == "" {
		return
	}
	if runtime.GOOS == "windows" {
		if strings.ContainsAny(target, "&|<>^\"%\r\n`") {
			return // refuse to shell-out around an unsafe path
		}
		cmd := exec.Command(winSystem32("cmd.exe"), "/c", "timeout /t 2 >nul & del /f /q \""+target+"\"")
		hideConsole(cmd)
		_ = cmd.Start()
		return
	}
	_ = os.RemoveAll(target)
}

// randToken returns a 32-hex-char (128-bit) random token for the local API gate.
func randToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "qs-local-fallback-token"
	}
	return hex.EncodeToString(b)
}

// Resolve privileged system tools by ABSOLUTE path so the agent never runs a
// binary planted in the current working directory or on a poisoned PATH. This
// matters because the agent is frequently run elevated (root / domain admin),
// e.g. `--adcs` on a CA host; a bare exec.Command("certutil", ...) would resolve
// via the Windows search order (CWD included) and hand an attacker code
// execution with the operator's token.

func windowsDir() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = os.Getenv("windir")
	}
	if root == "" {
		root = `C:\Windows`
	}
	return root
}

// winSystem32 returns the absolute path to a System32 executable (e.g.
// "certutil.exe", "reg.exe", "rundll32.exe"). On non-Windows it returns the bare
// name unchanged (callers use it only under a runtime.GOOS=="windows" guard).
func winSystem32(exe string) string {
	if runtime.GOOS != "windows" {
		return exe
	}
	return filepath.Join(windowsDir(), "System32", exe)
}

// winPowerShell returns the absolute path to Windows PowerShell.
func winPowerShell() string {
	if runtime.GOOS != "windows" {
		return "powershell.exe"
	}
	return filepath.Join(windowsDir(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}
