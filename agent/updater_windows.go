//go:build windows

package main

// Windows half of the verified push-upgrade (see updater.go for the model).
// A running .exe cannot be overwritten in place, so the swap renames the running
// binary to <exe>.old, moves the verified download into its place, then launches
// the new binary and exits (mirroring the scheduleSelfDelete trick in systools.go).

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// Detached + no-window creation flags for the relaunched processes:
// DETACHED_PROCESS (0x08) | CREATE_NEW_PROCESS_GROUP (0x200) | CREATE_NO_WINDOW (0x08000000).
const detachedNoWindow = 0x08 | 0x200 | 0x08000000

// verifyBinarySignature confirms the downloaded .exe carries a valid Authenticode
// signature that chains to the QuarkShield publisher (Fedmitigate LLC via its PKI, or
// Microsoft's root for Azure Trusted Signing). Runs AFTER the SHA-256 pin has matched.
func verifyBinarySignature(path string) error {
	// Defense: the path is derived from os.Executable(), not attacker input, but reject
	// quote characters anyway so the PowerShell literal can't be broken out of.
	if strings.ContainsAny(path, "'\"`\r\n") {
		return fmt.Errorf("refusing to verify a path with quote/newline characters")
	}
	script := "$ErrorActionPreference='Stop';" +
		"$s=Get-AuthenticodeSignature -LiteralPath '" + path + "';" +
		"if($s.Status -ne 'Valid'){Write-Output ('INVALID:'+$s.Status);exit 1};" +
		"Write-Output ('OK:'+$s.SignerCertificate.Subject+'|'+$s.SignerCertificate.Issuer)"
	cmd := exec.Command(winPowerShell(), "-NoProfile", "-NonInteractive", "-Command", script)
	hideConsole(cmd)
	out, err := cmd.CombinedOutput()
	res := strings.TrimSpace(string(out))
	if err != nil {
		return fmt.Errorf("Authenticode check failed: %v: %s", err, res)
	}
	if !strings.HasPrefix(res, "OK:") {
		return fmt.Errorf("Authenticode status not Valid: %s", res)
	}
	lo := strings.ToLower(res)
	if !strings.Contains(lo, "fedmitigate") && !strings.Contains(lo, "microsoft") {
		return fmt.Errorf("signer does not chain to the QuarkShield publisher: %s", res)
	}
	return nil
}

// swapAndRestart renames the running binary aside, installs the new one, arms the
// rollback watchdog from the known-good old binary, launches the new binary, and exits.
func swapAndRestart(newPath, target, oldPath string) error {
	_ = os.Remove(oldPath)
	if err := os.Rename(target, oldPath); err != nil {
		return fmt.Errorf("could not move running binary aside: %v", err)
	}
	if err := os.Rename(newPath, target); err != nil {
		_ = os.Rename(oldPath, target) // restore
		return fmt.Errorf("could not install new binary: %v", err)
	}

	// Rollback watchdog, run from the known-good OLD binary, detached.
	wd := exec.Command(oldPath, "--upgrade-watchdog")
	wd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedNoWindow}
	_ = wd.Start()

	// Launch the NEW binary, preserving the current run mode (e.g. --daemon --server X),
	// detached from this process, then exit so the old image releases.
	run := exec.Command(target, os.Args[1:]...)
	run.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedNoWindow}
	if err := run.Start(); err != nil {
		return fmt.Errorf("could not launch new binary: %v", err)
	}
	os.Exit(0)
	return nil // unreachable
}

// restoreOldBinary rolls back by moving the running (broken) binary aside, restoring
// <exe>.old over the target, and relaunching it as the daemon.
func restoreOldBinary(oldPath, target string) error {
	if _, err := os.Stat(oldPath); err != nil {
		return fmt.Errorf("no backup binary at %s: %v", oldPath, err)
	}
	failed := target + ".failed"
	_ = os.Remove(failed)
	_ = os.Rename(target, failed) // move the broken new binary aside (best effort)
	if err := os.Rename(oldPath, target); err != nil {
		return fmt.Errorf("could not restore old binary: %v", err)
	}
	restart := exec.Command(target, "--daemon", "--server", LoadEnrollmentConfig().ServerURL)
	restart.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedNoWindow}
	_ = restart.Start()
	return nil
}
