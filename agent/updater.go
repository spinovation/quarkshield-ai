package main

// Remote agent push-upgrade — the VERIFIED download-swap-restart path.
//
// SECURITY MODEL (see agent/PUSH-UPGRADE-PLAN.md §2.2): the fleet command channel
// is otherwise remote code execution. The agent MUST NOT run a binary it has not
// verified. In order, before the swap:
//
//   1. HTTPS-only + download only from the ENROLLED server. The URL is resolved as
//      EnrollmentConfig.ServerURL + <path of details.url>; any scheme/host embedded
//      in details.url is discarded, so a tampered command cannot point the agent at
//      an attacker host.
//   2. SHA-256 pin. The server supplies the expected hash in `details`; the agent
//      hashes the download and aborts on mismatch. This is the primary integrity
//      guarantee — a matching hash means the bytes are identical to the release.
//   3. Code-signature check (defense in depth; OS-specific — see updater_windows.go
//      / updater_other.go).
//   4. Version sanity: refuse the same or an older version unless details.force.
//
// Only after 1–4 pass does the agent perform an atomic rename swap and restart,
// keeping the previous binary as <exe>.old and arming a watchdog that rolls back
// if the new binary never confirms a successful telemetry sync in time.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// upgradeDetails is the JSON payload the server stores in fleet_commands.details
// for an 'upgrade' command.
type upgradeDetails struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	URL     string `json:"url"`   // a PATH on the enrolled server, e.g. /downloads/quarkshield-scanner-...
	Force   bool   `json:"force"` // allow re-install of the same/older version
}

const (
	// maxUpgradeBytes caps the download so a hostile/garbage response can't fill the disk.
	maxUpgradeBytes = 250 << 20 // 250 MiB
	// upgradeRollbackWindow is how long the watchdog waits for the new binary to
	// confirm a successful telemetry sync before rolling back to <exe>.old.
	upgradeRollbackWindow = 10 * time.Minute
)

// getUpgradeMarkerPath returns the path of the rollback marker, kept alongside the
// enrollment config so both the old (watchdog) and new (confirm) processes agree on it.
func getUpgradeMarkerPath() string {
	return filepath.Join(filepath.Dir(getEnrollmentConfigPath()), "upgrade.json")
}

// upgradeMarker records an in-flight swap so the watchdog can roll back and the new
// binary can confirm success.
type upgradeMarker struct {
	TargetPath      string    `json:"targetPath"`
	OldPath         string    `json:"oldPath"`
	ExpectedVersion string    `json:"expectedVersion"`
	Deadline        time.Time `json:"deadline"`
	Status          string    `json:"status"` // "pending" | "confirmed"
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

// PerformUpgrade carries out a verified in-place upgrade from an 'upgrade' command.
// On success the process re-execs/exits into the new binary and this never returns;
// on any verification failure it returns an error and the running binary is untouched.
func PerformUpgrade(detailsJSON string) error {
	detailsJSON = strings.TrimSpace(detailsJSON)
	if detailsJSON == "" {
		return fmt.Errorf("empty upgrade details")
	}
	var d upgradeDetails
	if err := json.Unmarshal([]byte(detailsJSON), &d); err != nil {
		return fmt.Errorf("malformed upgrade details: %v", err)
	}
	d.Version = strings.TrimSpace(d.Version)
	d.SHA256 = strings.ToLower(strings.TrimSpace(d.SHA256))
	if d.Version == "" || d.SHA256 == "" || strings.TrimSpace(d.URL) == "" {
		return fmt.Errorf("upgrade details missing version/sha256/url")
	}
	if len(d.SHA256) != 64 {
		return fmt.Errorf("sha256 pin must be 64 hex chars, got %d", len(d.SHA256))
	}

	// (4) Version sanity — refuse same/older unless forced.
	if !d.Force && compareSemver(d.Version, AgentVersion) <= 0 {
		return fmt.Errorf("refusing to 'upgrade' to %s from %s (not newer; set force to override)", d.Version, AgentVersion)
	}

	// (1) Resolve the download URL against the ENROLLED server only.
	cfg := LoadEnrollmentConfig()
	dlURL, err := resolveUpgradeURL(cfg.ServerURL, d.URL)
	if err != nil {
		return err
	}

	target, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot resolve own path: %v", err)
	}
	if resolved, err := filepath.EvalSymlinks(target); err == nil {
		target = resolved
	}

	// Download to a temp file NEXT TO the current binary (same volume → atomic rename).
	newPath := target + ".new"
	_ = os.Remove(newPath)
	if err := downloadVerified(dlURL, d.SHA256, newPath); err != nil {
		_ = os.Remove(newPath)
		return err
	}

	// (3) Code-signature check (OS-specific). On failure, discard the download.
	if err := verifyBinarySignature(newPath); err != nil {
		_ = os.Remove(newPath)
		return fmt.Errorf("signature verification failed: %v", err)
	}

	fmt.Printf("✅ Upgrade %s verified (sha256 + signature). Swapping and restarting...\n", d.Version)

	// Arm the rollback marker before the swap.
	oldPath := target + ".old"
	_ = writeUpgradeMarker(upgradeMarker{
		TargetPath:      target,
		OldPath:         oldPath,
		ExpectedVersion: d.Version,
		Deadline:        time.Now().Add(upgradeRollbackWindow),
		Status:          "pending",
	})

	// (2.3) Atomic swap + restart (OS-specific). Does not return on success.
	if err := swapAndRestart(newPath, target, oldPath); err != nil {
		_ = os.Remove(newPath)
		clearUpgradeMarker()
		return fmt.Errorf("swap/restart failed: %v", err)
	}
	return nil
}

// resolveUpgradeURL joins the path of the server-supplied URL onto the ENROLLED
// server origin, discarding any scheme/host the command tried to embed. It enforces
// HTTPS (mirroring the telemetry guard in client.go), allowing plain http only for
// an explicit loopback/dev server.
func resolveUpgradeURL(serverURL, rawURL string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(serverURL), "/")
	if base == "" {
		return "", fmt.Errorf("no enrolled server URL")
	}
	lo := strings.ToLower(base)
	if strings.HasPrefix(lo, "http://") &&
		!strings.Contains(lo, "127.0.0.1") && !strings.Contains(lo, "localhost") && !strings.Contains(lo, "[::1]") {
		return "", fmt.Errorf("refusing to download an upgrade over plaintext http from %s; use https", base)
	}

	// Take ONLY the path (+query) of details.url — never its scheme or host.
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("malformed upgrade url: %v", err)
	}
	p := u.Path
	if p == "" || !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("upgrade url must be a server-relative path, got %q", rawURL)
	}
	// Reject path traversal attempts outright.
	if strings.Contains(p, "..") {
		return "", fmt.Errorf("upgrade url path must not contain '..'")
	}
	full := base + p
	if u.RawQuery != "" {
		full += "?" + u.RawQuery
	}
	return full, nil
}

// downloadVerified streams url → dest and aborts unless the SHA-256 matches expectedHex.
// dest is created with executable permissions. A mismatch leaves no usable file.
func downloadVerified(dlURL, expectedHex, dest string) error {
	client := &http.Client{Timeout: 10 * time.Minute}
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
		return fmt.Errorf("cannot create temp binary: %v", err)
	}
	h := sha256.New()
	limited := io.LimitReader(resp.Body, maxUpgradeBytes+1)
	n, err := io.Copy(io.MultiWriter(f, h), limited)
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("download write failed: %v", err)
	}
	if closeErr != nil {
		return fmt.Errorf("download close failed: %v", closeErr)
	}
	if n > maxUpgradeBytes {
		return fmt.Errorf("upgrade binary exceeds %d bytes; aborting", maxUpgradeBytes)
	}

	got := hex.EncodeToString(h.Sum(nil))
	if got != expectedHex {
		return fmt.Errorf("sha256 mismatch: expected %s, got %s", expectedHex, got)
	}
	return nil
}

// compareSemver returns -1/0/1 comparing dotted numeric versions (a<b / a==b / a>b).
// Any pre-release suffix (after '-') is ignored; non-numeric parts sort as 0.
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
		if i > 2 {
			break
		}
		out[i], _ = strconv.Atoi(strings.TrimSpace(part))
	}
	return out
}

// ConfirmUpgradeIfPending is called by the NEW binary after its first successful
// telemetry sync. If a rollback marker exists and we are the expected new version,
// it confirms success: the watchdog then skips rollback and the <exe>.old is removed.
func ConfirmUpgradeIfPending() {
	m, ok := readUpgradeMarker()
	if !ok {
		return
	}
	if m.ExpectedVersion != "" && m.ExpectedVersion != AgentVersion {
		return // a different version is running than the one we were upgrading to
	}
	if m.OldPath != "" {
		_ = os.Remove(m.OldPath)
	}
	clearUpgradeMarker()
	fmt.Printf("✅ Upgrade to %s confirmed by a successful telemetry sync.\n", AgentVersion)
}

// runUpgradeWatchdog is launched (detached, from the KNOWN-GOOD old binary) by the
// swap. It waits out the rollback window; if the new binary has not confirmed a
// successful sync by then, it restores <exe>.old and restarts. Invoked via the
// hidden --upgrade-watchdog flag.
func runUpgradeWatchdog() {
	m, ok := readUpgradeMarker()
	if !ok {
		return // already confirmed + cleaned up
	}
	time.Sleep(time.Until(m.Deadline))

	cur, ok := readUpgradeMarker()
	if !ok || cur.Status == "confirmed" {
		return // new binary confirmed in time; nothing to do
	}

	// The new binary never confirmed — roll back to the last known-good binary.
	fmt.Printf("⚠️  Upgrade to %s did not confirm within %s — rolling back.\n", cur.ExpectedVersion, upgradeRollbackWindow)
	if err := restoreOldBinary(cur.OldPath, cur.TargetPath); err != nil {
		fmt.Printf("❌ Rollback failed: %v\n", err)
		return
	}
	clearUpgradeMarker()
}
