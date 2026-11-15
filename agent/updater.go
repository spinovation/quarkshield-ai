package main

// Remote agent push-upgrade — the VERIFIED download → verify → swap → restart path.
//
// SECURITY MODEL (see agent/PUSH-UPGRADE-PLAN.md). An "upgrade" command makes the
// agent replace and re-run its own executable, so the command channel must not be
// able to deliver anything except a genuine QuarkShield release — even if the
// console, its database, or the download directory is compromised. In order:
//
//  1. Signed release manifest. The command carries the release manifest and an
//     Ed25519 signature over its exact bytes. The agent verifies it against the
//     public keys compiled in (release_keys.go). The private key lives only on the
//     release machine, never on the server. Nothing in the command is trusted
//     until this passes.
//  2. No downgrades. The manifest version must be newer than the running one
//     (`force` allows re-installing the SAME version, never an older one), so an
//     attacker cannot replay an old signed release with a known flaw.
//  3. Download only from the server this agent polls, over HTTPS, and only from
//     /downloads/. The manifest holds a path, never a host.
//  4. SHA-256 pin from the signed manifest, checked while streaming to disk.
//  5. OS code-signature check pinned to the QuarkShield publisher (Authenticode
//     on Windows, Developer ID team on macOS) — see updater_windows.go /
//     updater_other.go.
//  6. Self-test: the new executable is run with --agent-version and must report
//     exactly the manifest version before anything is swapped.
//
// Only then does the agent swap (rename, keeping the previous build as *.old) and
// restart. A watchdog started from the previous build restores it if the new one
// has not completed an authenticated server round trip within the rollback window.
//
// A host can opt out entirely: QUARKSHIELD_DISABLE_UPGRADE=1 or an
// `upgrade.disabled` file next to the enrollment config.

import (
	"archive/zip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	releaseProduct = "quarkshield-agent"
	// maxUpgradeBytes caps the download so a hostile/garbage response can't fill the disk.
	maxUpgradeBytes = 250 << 20 // 250 MiB
	// maxUpgradeUnpackedBytes caps the total size extracted from a macOS app archive.
	maxUpgradeUnpackedBytes = 500 << 20
	// upgradeRollbackWindow is how long the watchdog waits for the new build to
	// complete an authenticated server round trip before restoring the previous one.
	upgradeRollbackWindow = 10 * time.Minute
	// macOSAppArtifact is the manifest key of the notarized QuarkShield.app archive.
	macOSAppArtifact = "darwin/app"
	// suppressBrowserEnv tells a GUI restarted by an upgrade not to open a browser tab.
	suppressBrowserEnv = "QS_SUPPRESS_BROWSER"
)

var (
	strictVersionRe = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$`)
	sha256HexRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// Artifact paths are plain file names directly under /downloads/.
	artifactPathRe = regexp.MustCompile(`^/downloads/[A-Za-z0-9][A-Za-z0-9._-]{0,120}$`)
)

// releaseArtifact is one downloadable build in the signed manifest.
type releaseArtifact struct {
	Path   string `json:"path"`   // server-relative, always under /downloads/
	SHA256 string `json:"sha256"` // lowercase hex
	Size   int64  `json:"size"`
}

// releaseManifest is the signed description of a release (agent-manifest.json).
// Artifacts are keyed by "<goos>/<goarch>", plus "darwin/app" for the app archive.
type releaseManifest struct {
	Product     string                     `json:"product"`
	Version     string                     `json:"version"`
	GeneratedAt string                     `json:"generatedAt"`
	Artifacts   map[string]releaseArtifact `json:"artifacts"`
}

// UpgradeDisabledLocally reports whether the local operator has turned remote
// upgrades off on THIS host. Honored even if the server enqueues an upgrade.
func UpgradeDisabledLocally() bool {
	if v := strings.TrimSpace(os.Getenv("QUARKSHIELD_DISABLE_UPGRADE")); v == "1" || strings.EqualFold(v, "true") {
		return true
	}
	if dir := filepath.Dir(getEnrollmentConfigPath()); dir != "" {
		if _, err := os.Stat(filepath.Join(dir, "upgrade.disabled")); err == nil {
			return true
		}
	}
	return false
}

// verifyReleaseManifest checks the Ed25519 signature over the exact manifest bytes
// against the compiled-in release keys and only then parses and validates it.
func verifyReleaseManifest(manifestJSON, signatureB64 string) (*releaseManifest, error) {
	if len(releasePublicKeys) == 0 {
		return nil, fmt.Errorf("this build has no release-signing key; remote upgrade is not available")
	}
	if manifestJSON == "" || len(manifestJSON) > 64<<10 {
		return nil, fmt.Errorf("missing or oversized release manifest")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("malformed release signature")
	}
	verified := false
	for _, k := range releasePublicKeys {
		pub, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pub), []byte(manifestJSON), sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("release manifest signature does not verify against a trusted release key")
	}
	var m releaseManifest
	if err := json.Unmarshal([]byte(manifestJSON), &m); err != nil {
		return nil, fmt.Errorf("malformed release manifest: %v", err)
	}
	if m.Product != releaseProduct {
		return nil, fmt.Errorf("manifest is for product %q, not %q", m.Product, releaseProduct)
	}
	if !strictVersionRe.MatchString(m.Version) {
		return nil, fmt.Errorf("manifest version %q is not MAJOR.MINOR.PATCH", m.Version)
	}
	return &m, nil
}

// upgradePlan describes what gets swapped. For a plain executable the swap target
// is the executable itself; for a macOS app it is the whole .app bundle, so the
// bundle's signature and notarization stay intact.
type upgradePlan struct {
	artifactKey string
	swapTarget  string // path that is replaced (executable, or .app bundle)
	swapOld     string // where the previous build is kept for rollback
	exePath     string // executable to run after the swap (unchanged path)
	oldExePath  string // the previous executable once moved aside (runs the watchdog)
	relExe      string // executable path relative to swapTarget ("" for a plain binary)
}

// planUpgrade works out the artifact and swap layout for the running executable.
func planUpgrade(exePath string) upgradePlan {
	if runtime.GOOS == "darwin" {
		// <X>.app/Contents/MacOS/<exe>
		macosDir := filepath.Dir(exePath)
		contents := filepath.Dir(macosDir)
		bundle := filepath.Dir(contents)
		if filepath.Base(macosDir) == "MacOS" && filepath.Base(contents) == "Contents" && strings.HasSuffix(bundle, ".app") {
			rel, _ := filepath.Rel(bundle, exePath)
			return upgradePlan{
				artifactKey: macOSAppArtifact,
				swapTarget:  bundle,
				swapOld:     bundle + ".old",
				exePath:     exePath,
				oldExePath:  filepath.Join(bundle+".old", rel),
				relExe:      rel,
			}
		}
	}
	return upgradePlan{
		artifactKey: runtime.GOOS + "/" + runtime.GOARCH,
		swapTarget:  exePath,
		swapOld:     exePath + ".old",
		exePath:     exePath,
		oldExePath:  exePath + ".old",
	}
}

// PerformUpgrade carries out a verified in-place upgrade from an 'upgrade' command
// received from serverURL. On success the process restarts into the new build and
// this never returns; on any failure it returns an error and the running build is
// left exactly as it was.
func PerformUpgrade(serverURL string, args AgentCommandArgs) error {
	if UpgradeDisabledLocally() {
		return fmt.Errorf("remote upgrade is disabled on this host (local opt-out)")
	}

	// (1) Signed manifest.
	m, err := verifyReleaseManifest(args.Manifest, args.Signature)
	if err != nil {
		return err
	}

	// (2) No downgrades; same version only when forced.
	switch cmp := compareSemver(m.Version, AgentReleaseVersion); {
	case cmp < 0:
		return fmt.Errorf("refusing to downgrade from %s to %s", AgentReleaseVersion, m.Version)
	case cmp == 0 && !args.Force:
		return fmt.Errorf("already running %s", AgentReleaseVersion)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot resolve own path: %v", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	plan := planUpgrade(exe)

	art, ok := m.Artifacts[plan.artifactKey]
	if !ok {
		return fmt.Errorf("release %s has no build for %s", m.Version, plan.artifactKey)
	}
	if !sha256HexRe.MatchString(art.SHA256) {
		return fmt.Errorf("manifest sha256 for %s is not 64 lowercase hex characters", plan.artifactKey)
	}

	// (3) Download only from the server we poll.
	dlURL, err := resolveUpgradeURL(serverURL, art.Path)
	if err != nil {
		return err
	}

	// Stage next to the swap target (same volume → the swap is a rename).
	stageDir := filepath.Join(filepath.Dir(plan.swapTarget), ".quarkshield-upgrade-"+strconv.Itoa(os.Getpid()))
	_ = os.RemoveAll(stageDir)
	if err := os.MkdirAll(stageDir, 0700); err != nil {
		return fmt.Errorf("cannot create staging directory next to the agent (not writable by this user?): %v", err)
	}
	cleanup := func() { _ = os.RemoveAll(stageDir) }

	// (4) SHA-256 pin.
	dlPath := filepath.Join(stageDir, stagedDownloadName())
	if err := downloadVerified(dlURL, art.SHA256, dlPath); err != nil {
		cleanup()
		return err
	}

	// Materialise the thing that will be swapped in, and find its executable.
	swapNew := dlPath
	newExe := dlPath
	if plan.artifactKey == macOSAppArtifact {
		unpack := filepath.Join(stageDir, "unpacked")
		if err := extractZip(dlPath, unpack); err != nil {
			cleanup()
			return fmt.Errorf("could not unpack app archive: %v", err)
		}
		swapNew = filepath.Join(unpack, filepath.Base(plan.swapTarget))
		newExe = filepath.Join(swapNew, plan.relExe)
		if fi, err := os.Stat(newExe); err != nil || fi.IsDir() {
			cleanup()
			return fmt.Errorf("app archive does not contain %s", filepath.Join(filepath.Base(plan.swapTarget), plan.relExe))
		}
	}

	// (5) Publisher code signature.
	if err := verifyCodeSignature(swapNew, plan.artifactKey == macOSAppArtifact); err != nil {
		cleanup()
		return fmt.Errorf("code-signature verification failed: %v", err)
	}

	// (6) Self-test: the new build must run and report the manifest version.
	if err := selfTestNewBuild(newExe, m.Version); err != nil {
		cleanup()
		return err
	}

	checks := "signed manifest, sha256, self-test"
	if runtime.GOOS != "linux" {
		checks = "signed manifest, sha256, publisher code signature, self-test"
	}
	fmt.Printf("✅ Upgrade %s verified (%s). Swapping and restarting...\n", m.Version, checks)

	marker := upgradeMarker{
		SwapTarget:      plan.swapTarget,
		SwapOld:         plan.swapOld,
		ExePath:         plan.exePath,
		ExpectedVersion: m.Version,
		PreviousVersion: AgentReleaseVersion,
		Deadline:        time.Now().Add(upgradeRollbackWindow),
		Args:            append([]string{}, os.Args[1:]...),
		Managed:         runningUnderServiceManager(),
	}
	if err := swapAndRestart(plan, swapNew, stageDir, marker); err != nil {
		cleanup()
		clearUpgradeMarker()
		return fmt.Errorf("swap/restart failed: %v", err)
	}
	return nil // unreachable on success
}

// resolveUpgradeURL joins a manifest artifact path onto the origin of the server
// the agent polls. The path must be a plain file under /downloads/; the server URL
// must be https (or loopback http for development), exactly as for telemetry.
func resolveUpgradeURL(serverURL, artifactPath string) (string, error) {
	if err := validateServerURL(serverURL); err != nil {
		return "", err
	}
	if !artifactPathRe.MatchString(artifactPath) || strings.Contains(artifactPath, "..") {
		return "", fmt.Errorf("artifact path %q is not a plain file under /downloads/", artifactPath)
	}
	base, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %v", err)
	}
	return base.Scheme + "://" + base.Host + artifactPath, nil
}

// downloadVerified streams dlURL → dest and fails unless the SHA-256 matches
// expectedHex. Redirects are refused so the download cannot be bounced to another
// host. dest is created executable. A mismatch leaves no file behind.
func downloadVerified(dlURL, expectedHex, dest string) error {
	client := &http.Client{
		Timeout: 10 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("redirects are not followed for upgrade downloads")
		},
	}
	resp, err := client.Get(dlURL)
	if err != nil {
		return fmt.Errorf("download failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return fmt.Errorf("cannot create staged download: %v", err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxUpgradeBytes+1))
	closeErr := f.Close()
	fail := func(e error) error { _ = os.Remove(dest); return e }
	if err != nil {
		return fail(fmt.Errorf("download write failed: %v", err))
	}
	if closeErr != nil {
		return fail(fmt.Errorf("download close failed: %v", closeErr))
	}
	if n > maxUpgradeBytes {
		return fail(fmt.Errorf("upgrade download exceeds %d bytes; aborting", maxUpgradeBytes))
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != expectedHex {
		return fail(fmt.Errorf("sha256 mismatch: expected %s, got %s", expectedHex, got))
	}
	return nil
}

// extractZip unpacks a (hash-verified) archive into destDir. It is deliberately
// strict: no symlinks, no absolute or parent-relative names, bounded total size.
func extractZip(zipPath, destDir string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	root := filepath.Clean(destDir)
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	var total int64
	for _, f := range zr.File {
		name := filepath.FromSlash(f.Name)
		if name == "" || filepath.IsAbs(name) || strings.Contains(f.Name, "\\") {
			return fmt.Errorf("unsafe archive entry %q", f.Name)
		}
		out := filepath.Join(root, name)
		if out != root && !strings.HasPrefix(out, root+string(os.PathSeparator)) {
			return fmt.Errorf("archive entry %q escapes the destination", f.Name)
		}
		mode := f.Mode()
		if mode&os.ModeSymlink != 0 || (!mode.IsRegular() && !mode.IsDir()) {
			return fmt.Errorf("archive entry %q is not a regular file or directory", f.Name)
		}
		if mode.IsDir() {
			if err := os.MkdirAll(out, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
			return err
		}
		perm := os.FileMode(0644)
		if mode.Perm()&0111 != 0 {
			perm = 0755
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		w, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
		if err != nil {
			rc.Close()
			return err
		}
		n, err := io.Copy(w, io.LimitReader(rc, maxUpgradeUnpackedBytes-total+1))
		rc.Close()
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		total += n
		if total > maxUpgradeUnpackedBytes {
			return fmt.Errorf("archive unpacks to more than %d bytes", maxUpgradeUnpackedBytes)
		}
	}
	return nil
}

// selfTestNewBuild runs the staged executable with --agent-version and requires it
// to print exactly the manifest version. This proves the new build starts on this
// machine and that the manifest and the binary agree (no upgrade loops).
func selfTestNewBuild(newExe, wantVersion string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, newExe, "--agent-version")
	hideConsole(cmd)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("new build failed its self-test: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != wantVersion {
		return fmt.Errorf("new build reports version %q but the manifest says %q", got, wantVersion)
	}
	return nil
}

// compareSemver returns -1/0/1 comparing dotted numeric versions (a<b / a==b / a>b).
// Any pre-release suffix (after '-' or '+') is ignored; non-numeric parts sort as 0.
func compareSemver(a, b string) int {
	pa := parseSemver(a)
	pb := parseSemver(b)
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	return 0
}

func parseSemver(v string) [3]int {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	var out [3]int
	for i, part := range strings.SplitN(v, ".", 3) {
		out[i], _ = strconv.Atoi(strings.TrimSpace(part))
	}
	return out
}

// ---------------------------------------------------------------------------
// Rollback marker + watchdog
// ---------------------------------------------------------------------------

// upgradeMarker records an in-flight swap so the watchdog can roll back and the
// new build can confirm success. Kept next to the enrollment config so the old
// (watchdog) and new (confirm) processes agree on its location.
type upgradeMarker struct {
	SwapTarget      string    `json:"swapTarget"`
	SwapOld         string    `json:"swapOld"`
	ExePath         string    `json:"exePath"`
	ExpectedVersion string    `json:"expectedVersion"`
	PreviousVersion string    `json:"previousVersion"`
	Deadline        time.Time `json:"deadline"`
	Pid             int       `json:"pid"`     // process running the new build
	Args            []string  `json:"args"`    // run-mode arguments to relaunch with
	Managed         bool      `json:"managed"` // systemd/launchd will restart it for us
}

func getUpgradeMarkerPath() string {
	return filepath.Join(filepath.Dir(getEnrollmentConfigPath()), "upgrade.json")
}

func writeUpgradeMarker(m upgradeMarker) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(getUpgradeMarkerPath(), data, 0600)
}

func readUpgradeMarker() (upgradeMarker, bool) {
	var m upgradeMarker
	data, err := os.ReadFile(getUpgradeMarkerPath())
	if err != nil {
		return m, false
	}
	if json.Unmarshal(data, &m) != nil {
		return m, false
	}
	return m, true
}

func clearUpgradeMarker() { _ = os.Remove(getUpgradeMarkerPath()) }

// ConfirmUpgradeIfPending is called after a successful authenticated round trip
// with the server (the command poll). If this process is the build a pending
// upgrade was waiting for, the upgrade is confirmed: the marker is cleared, which
// stands the watchdog down, and the previous build is removed.
func ConfirmUpgradeIfPending() {
	m, ok := readUpgradeMarker()
	if !ok || m.ExpectedVersion != AgentReleaseVersion {
		return
	}
	clearUpgradeMarker()
	if m.SwapOld != "" && m.SwapOld != m.SwapTarget {
		// Best effort: on Windows the previous exe is still running the watchdog and
		// is removed by the next upgrade instead.
		_ = os.RemoveAll(m.SwapOld)
	}
	fmt.Printf("✅ Upgrade %s → %s confirmed.\n", m.PreviousVersion, AgentReleaseVersion)
}

// runUpgradeWatchdog runs in the PREVIOUS build (hidden --upgrade-watchdog flag),
// started detached by the swap. It waits for the new build to confirm; if the
// rollback window passes without confirmation it restores the previous build.
func runUpgradeWatchdog() {
	first, ok := readUpgradeMarker()
	if !ok {
		return
	}
	for time.Now().Before(first.Deadline) {
		time.Sleep(15 * time.Second)
		if _, pending := readUpgradeMarker(); !pending {
			return // confirmed in time
		}
	}
	cur, pending := readUpgradeMarker()
	if !pending {
		return
	}
	fmt.Printf("⚠️  Upgrade to %s was not confirmed within %s — restoring %s.\n", cur.ExpectedVersion, upgradeRollbackWindow, cur.PreviousVersion)

	// Restore the files first and clear the marker BEFORE stopping the new process:
	// under systemd, stopping the service's main process also stops this watchdog.
	if _, err := os.Stat(cur.SwapOld); err != nil {
		fmt.Printf("❌ Rollback impossible: previous build missing at %s\n", cur.SwapOld)
		clearUpgradeMarker()
		return
	}
	failed := cur.SwapTarget + ".failed"
	_ = os.RemoveAll(failed)
	_ = os.Rename(cur.SwapTarget, failed)
	if err := os.Rename(cur.SwapOld, cur.SwapTarget); err != nil {
		_ = os.Rename(failed, cur.SwapTarget) // put the new build back rather than leave nothing
		fmt.Printf("❌ Rollback failed: %v\n", err)
		clearUpgradeMarker()
		return
	}
	clearUpgradeMarker()
	stopUpgradedProcess(cur.Pid)
	if !cur.Managed {
		relaunchDetached(cur.ExePath, cur.Args)
	}
	_ = os.RemoveAll(failed)
}

// ---------------------------------------------------------------------------
// Sibling restart: a daemon whose executable was replaced by another process
// (the GUI applying an upgrade, or a manual re-install) restarts into it.
// ---------------------------------------------------------------------------

var (
	selfStartPath string
	selfStartInfo os.FileInfo
)

// recordSelfIdentity remembers which file this process was started from. The path
// is captured now because os.Executable() follows a later rename on Linux.
func recordSelfIdentity() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if fi, err := os.Stat(exe); err == nil {
		selfStartPath, selfStartInfo = exe, fi
	}
}

// selfBinaryReplaced reports whether the file at this process's original path is
// no longer the file it was started from. A momentarily missing file (mid-swap)
// counts as "no".
func selfBinaryReplaced() bool {
	if selfStartInfo == nil {
		return false
	}
	now, err := os.Stat(selfStartPath)
	if err != nil {
		return false
	}
	return !os.SameFile(selfStartInfo, now)
}

// restartIfBinaryReplaced restarts a long-running daemon into a build that another
// process (the GUI applying an upgrade, a rollback, or a manual re-install) put in
// its place, so every process on the host ends up on the same version.
func restartIfBinaryReplaced() {
	if selfBinaryReplaced() {
		fmt.Println("🔄 Agent executable was replaced on disk — restarting into it.")
		restartSelf(selfStartPath)
	}
}
