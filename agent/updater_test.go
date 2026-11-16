package main

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// withTestReleaseKey swaps the trusted release keys for a throwaway key and
// returns a signer for it.
func withTestReleaseKey(t *testing.T) func(manifest string) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	saved := releasePublicKeys
	releasePublicKeys = []string{base64.StdEncoding.EncodeToString(pub)}
	t.Cleanup(func() { releasePublicKeys = saved })
	return func(manifest string) string {
		return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(manifest)))
	}
}

func testManifest(t *testing.T, version string, artifacts map[string]releaseArtifact) string {
	t.Helper()
	b, err := json.Marshal(releaseManifest{Product: releaseProduct, Version: version, Artifacts: artifacts})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The command channel must not be able to deliver anything that the offline
// release key did not sign.
func TestVerifyReleaseManifest(t *testing.T) {
	sign := withTestReleaseKey(t)
	good := testManifest(t, "9.9.9", nil)
	sig := sign(good)

	if _, err := verifyReleaseManifest(good, sig); err != nil {
		t.Fatalf("a correctly signed manifest must verify: %v", err)
	}
	// One changed byte (here: a different version) invalidates the signature.
	if _, err := verifyReleaseManifest(strings.Replace(good, "9.9.9", "9.9.8", 1), sig); err == nil {
		t.Fatal("a tampered manifest must be rejected")
	}
	// A signature from any other key is rejected.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherSig := base64.StdEncoding.EncodeToString(ed25519.Sign(otherPriv, []byte(good)))
	if _, err := verifyReleaseManifest(good, otherSig); err == nil {
		t.Fatal("a manifest signed by an untrusted key must be rejected")
	}
	for _, bad := range []string{"", "not-base64!!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := verifyReleaseManifest(good, bad); err == nil {
			t.Fatalf("malformed signature %q must be rejected", bad)
		}
	}
	// Correctly signed, but not an agent manifest / not a strict version.
	wrongProduct := `{"product":"something-else","version":"9.9.9"}`
	if _, err := verifyReleaseManifest(wrongProduct, sign(wrongProduct)); err == nil {
		t.Fatal("a manifest for another product must be rejected")
	}
	badVersion := `{"product":"quarkshield-agent","version":"9.9.9; rm -rf /"}`
	if _, err := verifyReleaseManifest(badVersion, sign(badVersion)); err == nil {
		t.Fatal("a non MAJOR.MINOR.PATCH version must be rejected")
	}
	// A build with no trusted key refuses every upgrade.
	releasePublicKeys = nil
	if _, err := verifyReleaseManifest(good, sig); err == nil {
		t.Fatal("with no release key compiled in, upgrades must be refused")
	}
}

// The shipped trust anchor must be a well-formed Ed25519 public key.
func TestShippedReleaseKeyIsWellFormed(t *testing.T) {
	if len(releasePublicKeys) == 0 {
		t.Fatal("no release public key compiled in")
	}
	for _, k := range releasePublicKeys {
		raw, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			t.Fatalf("release key %q is not a base64 Ed25519 public key", k)
		}
	}
}

// Version rules are enforced BEFORE any download: no downgrade ever (even with
// force), same version only with force, and an unsigned command does nothing.
func TestPerformUpgrade_RefusalsHappenBeforeAnyDownload(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("LOCALAPPDATA", t.TempDir())
	sign := withTestReleaseKey(t)

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits++ }))
	defer srv.Close()

	older := testManifest(t, "0.0.1", nil)
	if err := PerformUpgrade(srv.URL, AgentCommandArgs{Manifest: older, Signature: sign(older), Force: true}); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("a forced downgrade must be refused, got: %v", err)
	}
	same := testManifest(t, AgentReleaseVersion, nil)
	if err := PerformUpgrade(srv.URL, AgentCommandArgs{Manifest: same, Signature: sign(same)}); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("same version without force must be refused, got: %v", err)
	}
	newer := testManifest(t, "99.0.0", nil)
	if err := PerformUpgrade(srv.URL, AgentCommandArgs{Manifest: newer, Signature: "AAAA"}); err == nil {
		t.Fatal("an unsigned upgrade must be refused")
	}
	// Signed and newer, but no build for this platform.
	if err := PerformUpgrade(srv.URL, AgentCommandArgs{Manifest: newer, Signature: sign(newer)}); err == nil || !strings.Contains(err.Error(), "no build for") {
		t.Fatalf("a release without this platform must be refused, got: %v", err)
	}
	// Local opt-out wins over a perfectly valid command.
	t.Setenv("QUARKSHIELD_DISABLE_UPGRADE", "1")
	if err := PerformUpgrade(srv.URL, AgentCommandArgs{Manifest: newer, Signature: sign(newer)}); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("local opt-out must refuse the upgrade, got: %v", err)
	}
	if hits != 0 {
		t.Fatalf("refused upgrades must not download anything; server saw %d request(s)", hits)
	}
}

// A signed manifest pointing at a hash that does not match the served bytes (a
// tampered download directory) must be refused and leave the agent untouched.
func TestPerformUpgrade_RejectsTamperedDownload(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("LOCALAPPDATA", t.TempDir())
	sign := withTestReleaseKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("malicious replacement binary"))
	}))
	defer srv.Close()

	exe, _ := os.Executable()
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	before, _ := os.Stat(exe)
	key := planUpgrade(exe).artifactKey
	genuine := sha256.Sum256([]byte("the genuine release"))
	m := testManifest(t, "99.0.0", map[string]releaseArtifact{
		key: {Path: "/downloads/agent-build", SHA256: hex.EncodeToString(genuine[:])},
	})
	err := PerformUpgrade(srv.URL, AgentCommandArgs{Manifest: m, Signature: sign(m)})
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected a sha256 mismatch, got: %v", err)
	}
	after, statErr := os.Stat(exe)
	if statErr != nil || !os.SameFile(before, after) {
		t.Fatal("the running executable must be untouched after a refused upgrade")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), ".quarkshield-upgrade-*")); len(leftovers) != 0 {
		t.Fatalf("staging directory left behind: %v", leftovers)
	}
	if _, pending := readUpgradeMarker(); pending {
		t.Fatal("no rollback marker may exist after a refused upgrade")
	}
}

func TestResolveUpgradeURL(t *testing.T) {
	got, err := resolveUpgradeURL("https://quarkshield.ai/", "/downloads/quarkshield-scanner-linux-amd64")
	if err != nil || got != "https://quarkshield.ai/downloads/quarkshield-scanner-linux-amd64" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := resolveUpgradeURL("http://127.0.0.1:8080", "/downloads/x"); err != nil {
		t.Fatalf("loopback http is allowed for development: %v", err)
	}
	for _, p := range []string{
		"https://evil.example.com/downloads/x.exe", // a host in the manifest path
		"//evil.example.com/downloads/x.exe",
		"/downloads/../api/admin",
		"/downloads/sub/dir/x",
		"/api/anything",
		"/downloads/x?redirect=https://evil.example.com",
		"/downloads/",
		"downloads/x",
		"",
	} {
		if got, err := resolveUpgradeURL("https://quarkshield.ai", p); err == nil {
			t.Errorf("artifact path %q must be rejected, resolved to %q", p, got)
		}
	}
	for _, s := range []string{"http://quarkshield.ai", "ftp://quarkshield.ai", "", "http://127.0.0.1.evil.example.com"} {
		if _, err := resolveUpgradeURL(s, "/downloads/x"); err == nil {
			t.Errorf("server URL %q must be rejected", s)
		}
	}
}

func TestDownloadVerified(t *testing.T) {
	payload := []byte("#!/bin/sh\necho genuine quarkshield agent\n")
	sum := sha256.Sum256(payload)
	goodHex := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/file", http.StatusFound)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	dir := t.TempDir()

	bad := filepath.Join(dir, "bad")
	if err := downloadVerified(srv.URL+"/file", strings.Repeat("0", 64), bad); err == nil {
		t.Fatal("a sha256 mismatch must be rejected")
	}
	if _, err := os.Stat(bad); err == nil {
		t.Fatal("a rejected download must not be left on disk")
	}
	if err := downloadVerified(srv.URL+"/redirect", goodHex, filepath.Join(dir, "redir")); err == nil {
		t.Fatal("redirects must not be followed")
	}
	dest := filepath.Join(dir, "good")
	if err := downloadVerified(srv.URL+"/file", goodHex, dest); err != nil {
		t.Fatalf("a matching sha256 must pass: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != string(payload) {
		t.Fatal("downloaded contents differ from source")
	}
	if fi, err := os.Stat(dest); runtime.GOOS != "windows" && (err != nil || fi.Mode().Perm()&0100 == 0) {
		t.Error("downloaded build is not executable")
	}
}

func writeZip(t *testing.T, path string, build func(zw *zip.Writer)) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	build(zw)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestExtractZip_StrictAboutEntries(t *testing.T) {
	dir := t.TempDir()

	ok := filepath.Join(dir, "ok.zip")
	writeZip(t, ok, func(zw *zip.Writer) {
		h := &zip.FileHeader{Name: "QuarkShield.app/Contents/MacOS/quarkshield-scanner", Method: zip.Deflate}
		h.SetMode(0755)
		w, _ := zw.CreateHeader(h)
		_, _ = w.Write([]byte("binary"))
		w2, _ := zw.Create("QuarkShield.app/Contents/Info.plist")
		_, _ = w2.Write([]byte("<plist/>"))
	})
	out := filepath.Join(dir, "out")
	if err := extractZip(ok, out); err != nil {
		t.Fatalf("a well-formed archive must extract: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(out, "QuarkShield.app/Contents/MacOS/quarkshield-scanner")); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm()&0100 == 0) {
		t.Fatalf("executable missing or not executable: %v", err)
	}

	traversal := filepath.Join(dir, "traversal.zip")
	writeZip(t, traversal, func(zw *zip.Writer) {
		w, _ := zw.Create("../escaped.txt")
		_, _ = w.Write([]byte("x"))
	})
	if err := extractZip(traversal, filepath.Join(dir, "t")); err == nil {
		t.Fatal("an entry escaping the destination must be rejected")
	}
	if _, err := os.Stat(filepath.Join(dir, "escaped.txt")); err == nil {
		t.Fatal("traversal entry was written outside the destination")
	}

	symlink := filepath.Join(dir, "symlink.zip")
	writeZip(t, symlink, func(zw *zip.Writer) {
		h := &zip.FileHeader{Name: "QuarkShield.app/link"}
		h.SetMode(os.ModeSymlink | 0777)
		w, _ := zw.CreateHeader(h)
		_, _ = w.Write([]byte("/etc/passwd"))
	})
	if err := extractZip(symlink, filepath.Join(dir, "s")); err == nil {
		t.Fatal("a symlink entry must be rejected")
	}
}

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.3.2", "2.3.1", 1}, {"2.3.1", "2.3.2", -1}, {"2.3.1", "2.3.1", 0},
		{"2.10.0", "2.9.9", 1}, {"v2.3.1", "2.3.1", 0}, {"3.0.0", "2.99.99", 1},
		{"", "2.3.1", -1},
	}
	for _, c := range cases {
		if got := compareSemver(c.a, c.b); got != c.want {
			t.Errorf("compareSemver(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// Only the build the upgrade was waiting for may confirm it; an older build that
// is still polling must leave the rollback armed.
func TestConfirmUpgradeIfPending(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("LOCALAPPDATA", t.TempDir())
	dir := t.TempDir()
	old := filepath.Join(dir, "agent.old")
	_ = os.WriteFile(old, []byte("previous build"), 0755)

	m := upgradeMarker{SwapTarget: filepath.Join(dir, "agent"), SwapOld: old, ExpectedVersion: "99.0.0", Deadline: time.Now().Add(time.Minute)}
	if err := writeUpgradeMarker(m); err != nil {
		t.Fatal(err)
	}
	ConfirmUpgradeIfPending()
	if _, pending := readUpgradeMarker(); !pending {
		t.Fatal("a different version must not confirm the upgrade")
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatal("the previous build must be kept until the upgrade is confirmed")
	}

	m.ExpectedVersion = AgentReleaseVersion
	_ = writeUpgradeMarker(m)
	ConfirmUpgradeIfPending()
	if _, pending := readUpgradeMarker(); pending {
		t.Fatal("the expected version must confirm the upgrade")
	}
	if _, err := os.Stat(old); err == nil {
		t.Fatal("the previous build should be removed once confirmed")
	}
}

func TestPlanUpgrade(t *testing.T) {
	p := planUpgrade(filepath.FromSlash("/usr/local/bin/quarkshield-scanner"))
	if p.artifactKey != runtime.GOOS+"/"+runtime.GOARCH || p.swapOld != p.swapTarget+".old" {
		t.Fatalf("unexpected plan for a plain executable: %+v", p)
	}
	if runtime.GOOS == "darwin" {
		p := planUpgrade("/Applications/QuarkShield.app/Contents/MacOS/quarkshield-scanner")
		if p.artifactKey != macOSAppArtifact || p.swapTarget != "/Applications/QuarkShield.app" ||
			p.oldExePath != "/Applications/QuarkShield.app.old/Contents/MacOS/quarkshield-scanner" {
			t.Fatalf("a macOS app must be swapped as a whole bundle: %+v", p)
		}
	}
}

// macOS publisher check against REAL signed code. Apple's own binaries are validly
// signed but are not ours, so they must be rejected; set QS_TEST_MACOS_ZIP to a
// released quarkshield-scanner-macos.zip to also prove a genuine release passes.
func TestVerifyCodeSignature_macOS(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	if err := verifyCodeSignature("/bin/ls", false); err == nil {
		t.Fatal("an Apple-signed binary is not a QuarkShield build and must be rejected")
	}
	if err := verifyCodeSignature("/System/Applications/Calculator.app", true); err == nil {
		t.Fatal("an Apple-signed app is not a QuarkShield build and must be rejected")
	}
	zipPath := os.Getenv("QS_TEST_MACOS_ZIP")
	if zipPath == "" {
		t.Log("QS_TEST_MACOS_ZIP not set — skipping the genuine-release half")
		return
	}
	out := filepath.Join(t.TempDir(), "unpacked")
	if err := extractZip(zipPath, out); err != nil {
		t.Fatalf("extract: %v", err)
	}
	app := filepath.Join(out, "QuarkShield.app")
	if err := verifyCodeSignature(app, true); err != nil {
		t.Fatalf("a genuine notarized release must pass: %v", err)
	}
	exe := filepath.Join(app, "Contents", "MacOS", "quarkshield-scanner")
	// Tamper with the extracted executable: the bundle must now be rejected.
	f, err := os.OpenFile(exe, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("tampered"))
	f.Close()
	if err := verifyCodeSignature(app, true); err == nil {
		t.Fatal("a modified app bundle must be rejected")
	}
}

// A service restart (or a crash + restart) while an upgrade is unconfirmed leaves
// the marker pointing at a dead pid; the new process must take the marker over so
// a rollback stops the process that is really running the new build.
func TestAdoptPendingUpgrade(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("LOCALAPPDATA", t.TempDir())

	// Pending upgrade to THIS version, recorded by another process: adopt it.
	if err := writeUpgradeMarker(upgradeMarker{ExpectedVersion: AgentReleaseVersion, PreviousVersion: "0.0.1", Pid: 1}); err != nil {
		t.Fatal(err)
	}
	AdoptPendingUpgrade()
	if m, ok := readUpgradeMarker(); !ok || m.Pid != os.Getpid() || m.PreviousVersion != "0.0.1" {
		t.Fatalf("marker not adopted: %+v (present=%v)", m, ok)
	}

	// Pending upgrade to a DIFFERENT version (this is the old build): leave it alone.
	if err := writeUpgradeMarker(upgradeMarker{ExpectedVersion: "999.0.0", Pid: 1}); err != nil {
		t.Fatal(err)
	}
	AdoptPendingUpgrade()
	if m, _ := readUpgradeMarker(); m.Pid != 1 {
		t.Fatalf("marker for another version was changed: %+v", m)
	}

	// No marker: nothing is created.
	clearUpgradeMarker()
	AdoptPendingUpgrade()
	if _, ok := readUpgradeMarker(); ok {
		t.Fatal("a marker was created out of nothing")
	}
}
