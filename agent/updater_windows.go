//go:build windows

package main

// Windows half of the verified push-upgrade (see updater.go for the model).
// A running .exe cannot be overwritten, but it CAN be renamed: the swap renames
// the running binary to <exe>.old, moves the verified download into its place,
// starts the new binary and exits.

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// Detached + no-window creation flags for relaunched processes:
// DETACHED_PROCESS (0x08) | CREATE_NEW_PROCESS_GROUP (0x200) | CREATE_NO_WINDOW (0x08000000).
const detachedNoWindow = 0x08 | 0x200 | 0x08000000

// stagedDownloadName keeps the .exe extension so Windows treats the staged file
// as an executable for both the Authenticode check and the self-test.
func stagedDownloadName() string { return "download.exe" }

// verifyCodeSignature requires a VALID Authenticode signature (Windows has
// verified the chain and the file hash) whose signer is the QuarkShield publisher
// certificate issued by Microsoft's ID Verified CA (Azure Trusted Signing). A
// signature that is merely valid, or merely issued by some Microsoft CA to
// another publisher, is rejected.
func verifyCodeSignature(path string, _ bool) error {
	// The path comes from os.Executable(), not attacker input, but reject quote
	// characters anyway so the PowerShell literal cannot be broken out of.
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
	parts := strings.SplitN(strings.TrimPrefix(res, "OK:"), "|", 2)
	if len(parts) != 2 {
		return fmt.Errorf("unexpected Authenticode output: %s", res)
	}
	subject, issuer := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if subject != releaseWindowsSubjectCN && !strings.HasPrefix(subject, releaseWindowsSubjectCN+",") {
		return fmt.Errorf("signed by %q, not the QuarkShield publisher", subject)
	}
	if !strings.HasPrefix(issuer, releaseWindowsIssuerMatch) {
		return fmt.Errorf("publisher certificate issued by %q, not a Microsoft ID Verified CA", issuer)
	}
	return nil
}

// runningUnderServiceManager: the Windows daemon is a logon-triggered Scheduled
// Task, which does not restart a process that exits.
func runningUnderServiceManager() bool { return false }

func startWatchdog(oldExe string) {
	wd := exec.Command(oldExe, "--upgrade-watchdog")
	wd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedNoWindow}
	_ = wd.Start()
}

// swapAndRestart renames the running binary aside, installs the new one, arms the
// rollback watchdog from the previous binary, starts the new binary and exits.
func swapAndRestart(plan upgradePlan, swapNew, stageDir string, marker upgradeMarker) error {
	_ = os.Remove(plan.swapOld)
	if err := os.Rename(plan.swapTarget, plan.swapOld); err != nil {
		return fmt.Errorf("could not move the running binary aside: %v", err)
	}
	if err := os.Rename(swapNew, plan.swapTarget); err != nil {
		_ = os.Rename(plan.swapOld, plan.swapTarget)
		return fmt.Errorf("could not install the new binary: %v", err)
	}
	revert := func() {
		_ = os.Remove(plan.swapTarget)
		_ = os.Rename(plan.swapOld, plan.swapTarget)
	}
	_ = os.RemoveAll(stageDir)

	if err := writeUpgradeMarker(marker); err != nil {
		revert()
		return fmt.Errorf("could not arm rollback: %v", err)
	}
	run := exec.Command(plan.exePath, os.Args[1:]...)
	run.Env = append(os.Environ(), suppressBrowserEnv+"=1")
	run.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedNoWindow}
	if err := run.Start(); err != nil {
		clearUpgradeMarker()
		revert()
		return fmt.Errorf("could not start the new binary: %v", err)
	}
	marker.Pid = run.Process.Pid
	_ = writeUpgradeMarker(marker)
	startWatchdog(plan.oldExePath)
	os.Exit(0)
	return nil // unreachable
}

// stopUpgradedProcess stops the process running the unconfirmed new build, after
// checking the pid still belongs to the agent (it may have exited and been reused).
func stopUpgradedProcess(pid int) {
	if pid <= 4 || pid == os.Getpid() {
		return
	}
	list := exec.Command(winSystem32("tasklist.exe"), "/FI", "PID eq "+strconv.Itoa(pid), "/FO", "CSV", "/NH")
	hideConsole(list)
	out, err := list.Output()
	if err != nil || !strings.Contains(strings.ToLower(string(out)), "quarkshield") {
		return
	}
	kill := exec.Command(winSystem32("taskkill.exe"), "/PID", strconv.Itoa(pid), "/F")
	hideConsole(kill)
	_ = kill.Run()
}

// relaunchDetached starts exe with the given run-mode arguments, detached.
func relaunchDetached(exe string, args []string) {
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), suppressBrowserEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedNoWindow}
	_ = cmd.Start()
}

// restartSelf starts a fresh copy of this process from its original path and
// exits (used when another process replaced the executable on disk).
func restartSelf(exePath string) {
	cmd := exec.Command(exePath, os.Args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedNoWindow}
	if cmd.Start() == nil {
		os.Exit(0)
	}
}
