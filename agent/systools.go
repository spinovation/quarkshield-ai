package main

import (
	"crypto/rand"
	"encoding/hex"
	"io"
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

// maxScanFileBytes bounds every file the scanner reads into memory.
const maxScanFileBytes = 2 * 1024 * 1024

// readScanFile safely reads a candidate file for inspection. Symlinks ARE
// followed (Debian's /etc/ssl/certs/*.pem and Let's Encrypt's live/*.pem are
// symlinks, and skipping them would miss the most valuable findings) but the
// size/regular-file checks are applied to the TARGET via os.Stat, and the read
// itself is capped with a LimitReader so a target that changes between stat and
// read (or /dev/zero) can never exhaust memory. Non-regular files (FIFOs, devices)
// are refused because reading them can block forever. On Windows, cloud-backed
// placeholders (OneDrive Files-On-Demand) report ModeIrregular; those are
// accepted because they are ordinary files from the application's perspective.
func readScanFile(path string) ([]byte, bool) {
	info, err := os.Stat(path) // follows symlinks
	if err != nil {
		return nil, false
	}
	mode := info.Mode()
	if !mode.IsRegular() {
		if !(runtime.GOOS == "windows" && mode&os.ModeIrregular != 0 && mode&(os.ModeDir|os.ModeNamedPipe|os.ModeSocket|os.ModeDevice|os.ModeCharDevice) == 0) {
			return nil, false
		}
	}
	if info.Size() == 0 || info.Size() > maxScanFileBytes {
		return nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxScanFileBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxScanFileBytes {
		return nil, false
	}
	return data, true
}

// tightenLocalPermissions is a one-time migration for installs created before the
// agent switched to owner-only permissions: ~/.quarkshield (0755 -> 0700) and
// historical scan records (0644 -> 0600) listed every private key path on the box
// to other local users.
func tightenLocalPermissions() {
	if runtime.GOOS == "windows" {
		return // NTFS ACLs; LOCALAPPDATA is already per-user
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	base := filepath.Join(home, ".quarkshield")
	if st, err := os.Stat(base); err != nil || !st.IsDir() {
		return
	}
	_ = os.Chmod(base, 0700)
	_ = filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			_ = os.Chmod(p, 0700)
		} else if d.Type().IsRegular() {
			_ = os.Chmod(p, 0600)
		}
		return nil
	})
}

// randToken returns a 32-hex-char (128-bit) random token for the local API gate.
func randToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// A predictable gate token would let any local process drive the agent.
		panic("crypto/rand unavailable: " + err.Error())
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
