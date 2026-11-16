//go:build !windows

package main

// macOS/Linux half of the verified push-upgrade (see updater.go for the model).
// On Unix a running executable (or the .app bundle holding it) can be renamed
// while it runs, so the swap is two renames and the restart is an in-place exec.

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// stagedDownloadName is the file name used for the staged download.
func stagedDownloadName() string { return "download" }

// verifyCodeSignature is the publisher check that runs after the signed manifest
// and SHA-256 pin have already passed.
//   - macOS: the code must satisfy a Developer ID requirement pinned to the
//     QuarkShield team (not merely "validly signed by someone"). An app bundle must
//     additionally pass Gatekeeper (notarized + stapled). A bare executable is not
//     notarized on its own, so the team-pinned signature is its gate.
//   - Linux: builds carry no OS code signature; the signed manifest is the gate.
func verifyCodeSignature(path string, isAppBundle bool) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	requirement := `=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists` +
		` and certificate leaf[field.1.2.840.113635.100.6.1.13] exists` +
		` and certificate leaf[subject.OU] = "` + releaseAppleTeamID + `"`
	args := []string{"--verify", "--strict", "-R", requirement}
	if isAppBundle {
		args = append(args, "--deep")
	}
	args = append(args, path)
	if out, err := exec.Command("/usr/bin/codesign", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("not signed by the QuarkShield Developer ID team: %s", strings.TrimSpace(string(out)))
	}
	if isAppBundle {
		if out, err := exec.Command("/usr/sbin/spctl", "-a", "-t", "exec", "-vv", path).CombinedOutput(); err != nil {
			return fmt.Errorf("Gatekeeper rejected the app (not notarized?): %s", strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// runningUnderServiceManager reports whether systemd / launchd will restart this
// process if it exits, so a rollback only needs to stop it.
func runningUnderServiceManager() bool {
	switch runtime.GOOS {
	case "linux":
		return os.Getenv("INVOCATION_ID") != ""
	case "darwin":
		return os.Getenv("XPC_SERVICE_NAME") == "ai.quarkshield.agent"
	}
	return false
}

// startWatchdog launches the rollback watchdog from the previous build, detached.
// Under systemd it is started as a transient unit so that a crash-looping new
// build (whose restarts kill everything in the service's control group) cannot
// take the watchdog down with it.
func startWatchdog(oldExe string) {
	if runtime.GOOS == "linux" && os.Getenv("INVOCATION_ID") != "" {
		if sdRun, err := exec.LookPath("systemd-run"); err == nil {
			unit := "quarkshield-upgrade-watchdog-" + strconv.FormatInt(time.Now().Unix(), 10)
			cmd := exec.Command(sdRun, "--quiet", "--collect", "--unit", unit,
				"--setenv=HOME="+os.Getenv("HOME"), oldExe, "--upgrade-watchdog")
			if cmd.Run() == nil {
				return
			}
		}
	}
	wd := exec.Command(oldExe, "--upgrade-watchdog")
	wd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	_ = wd.Start()
}

// swapAndRestart moves the verified build into place, arms the rollback watchdog
// from the previous build, and execs into the new build. It does not return on
// success; on failure everything is put back.
func swapAndRestart(plan upgradePlan, swapNew, stageDir string, marker upgradeMarker) error {
	_ = os.RemoveAll(plan.swapOld)
	if err := os.Rename(plan.swapTarget, plan.swapOld); err != nil {
		return fmt.Errorf("could not move the current build aside: %v", err)
	}
	revert := func() {
		_ = os.RemoveAll(plan.swapTarget)
		_ = os.Rename(plan.swapOld, plan.swapTarget)
	}
	if err := os.Rename(swapNew, plan.swapTarget); err != nil {
		_ = os.Rename(plan.swapOld, plan.swapTarget)
		return fmt.Errorf("could not install the new build: %v", err)
	}
	_ = os.RemoveAll(stageDir)

	marker.Pid = os.Getpid() // exec keeps the pid
	if err := writeUpgradeMarker(marker); err != nil {
		revert()
		return fmt.Errorf("could not arm rollback: %v", err)
	}
	startWatchdog(plan.oldExePath)

	env := append(os.Environ(), suppressBrowserEnv+"=1")
	err := syscall.Exec(plan.exePath, os.Args, env)
	// Only reached if exec failed: restore the previous build and stand down.
	clearUpgradeMarker()
	revert()
	return fmt.Errorf("could not start the new build: %v", err)
}

// stopUpgradedProcess stops the process running the unconfirmed new build, after
// checking the pid still belongs to the agent (it may have exited and been reused).
func stopUpgradedProcess(pid int) {
	if pid <= 1 || pid == os.Getpid() {
		return
	}
	out, err := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil || !strings.Contains(strings.ToLower(string(out)), "quarkshield") {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	time.Sleep(3 * time.Second)
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

// relaunchDetached starts exe with the given run-mode arguments, detached.
func relaunchDetached(exe string, args []string) {
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), suppressBrowserEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	_ = cmd.Start()
}

// restartSelf re-executes this process from its original path (used when another
// process replaced the executable on disk).
func restartSelf(exePath string) {
	_ = syscall.Exec(exePath, os.Args, os.Environ())
}
