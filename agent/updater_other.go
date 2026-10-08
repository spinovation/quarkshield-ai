//go:build !windows

package main

// macOS/Linux half of the verified push-upgrade (see updater.go for the model).
// On Unix a running executable's file CAN be renamed/replaced in place (the inode
// stays mapped), so the swap is a plain atomic rename and the restart is a re-exec.

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

// verifyBinarySignature is the OS-specific defense-in-depth check that runs AFTER the
// SHA-256 pin has already matched.
//   - macOS: `codesign --verify --deep --strict` is a hard gate (the Apple signature
//     must be intact and chain to a valid authority). `spctl -a -t exec` (Gatekeeper /
//     notarization) is run as an additional, best-effort gate: the release pipeline
//     staples the .app and .dmg, not the bare binary, so a standalone binary may not
//     pass spctl even when legitimately signed — a spctl failure is logged, not fatal,
//     because the server-pinned SHA-256 is the authoritative integrity guarantee.
//   - Linux: builds are unsigned today, so the SHA-256 pin is the gate (no-op here).
func verifyBinarySignature(path string) error {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", path).CombinedOutput()
		if err != nil {
			return fmt.Errorf("codesign --verify rejected the binary: %v: %s", err, strings.TrimSpace(string(out)))
		}
		if sout, serr := exec.Command("/usr/sbin/spctl", "-a", "-t", "exec", "-vv", path).CombinedOutput(); serr != nil {
			// Non-fatal: see doc comment. Surface it so operators can see why.
			fmt.Printf("ℹ️  Gatekeeper (spctl) did not assess the upgrade binary as notarized: %s (continuing — SHA-256 pin + codesign already verified)\n", strings.TrimSpace(string(sout)))
		}
		return nil
	default:
		// Linux: no code signature today; SHA-256 pin already enforced in updater.go.
		return nil
	}
}

// swapAndRestart performs the atomic rename swap, arms the rollback watchdog from the
// known-good old binary, and re-execs into the new binary. It does not return on success.
func swapAndRestart(newPath, target, oldPath string) error {
	// Keep the current (known-good) binary as <exe>.old for rollback.
	_ = os.Remove(oldPath)
	if err := os.Rename(target, oldPath); err != nil {
		return fmt.Errorf("could not preserve old binary: %v", err)
	}
	// Atomically move the verified download into place.
	if err := os.Rename(newPath, target); err != nil {
		// Best effort to restore before bailing out.
		_ = os.Rename(oldPath, target)
		return fmt.Errorf("could not install new binary: %v", err)
	}

	// Launch the rollback watchdog from the KNOWN-GOOD old binary, detached, so it
	// survives this process re-execing.
	wd := exec.Command(oldPath, "--upgrade-watchdog")
	wd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	_ = wd.Start()

	// Re-exec into the new binary, preserving the current run mode (--daemon, --poll,
	// or GUI). On a service-managed host (launchd/systemd KeepAlive) a plain exit would
	// also be relaunched, but re-exec restarts immediately.
	if err := syscall.Exec(target, os.Args, os.Environ()); err != nil {
		return fmt.Errorf("re-exec into new binary failed: %v", err)
	}
	return nil // unreachable on success
}

// restoreOldBinary rolls the swap back: it moves <exe>.old back over the target. On a
// service-managed host the crashing new process is relaunched by launchd/systemd and
// picks up the restored binary; as a belt-and-suspenders step we also spawn it detached.
func restoreOldBinary(oldPath, target string) error {
	if _, err := os.Stat(oldPath); err != nil {
		return fmt.Errorf("no backup binary at %s: %v", oldPath, err)
	}
	if err := os.Rename(oldPath, target); err != nil {
		return fmt.Errorf("could not restore old binary: %v", err)
	}
	restart := exec.Command(target, "--daemon", "--server", LoadEnrollmentConfig().ServerURL)
	restart.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	_ = restart.Start()
	return nil
}
