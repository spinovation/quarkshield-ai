package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestDownloadVerified_RejectsTamperedBinary is the core security property: a
// download whose bytes do not match the server-pinned SHA-256 must be rejected, and
// a download whose bytes match must pass. (See agent/PUSH-UPGRADE-PLAN.md §2.2.)
func TestDownloadVerified_RejectsTamperedBinary(t *testing.T) {
	payload := []byte("#!/bin/sh\necho genuine quarkshield agent\n")
	sum := sha256.Sum256(payload)
	goodHex := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	dir := t.TempDir()

	// (1) Wrong pin → the (tampered) binary is rejected.
	badPin := "0000000000000000000000000000000000000000000000000000000000000000"
	if err := downloadVerified(srv.URL, badPin, filepath.Join(dir, "bad")); err == nil {
		t.Fatal("expected sha256 mismatch to be rejected, got nil error")
	}

	// (2) Correct pin → accepted, file written with exec bit, contents intact.
	dest := filepath.Join(dir, "good")
	if err := downloadVerified(srv.URL, goodHex, dest); err != nil {
		t.Fatalf("expected a matching sha256 to pass, got: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("installed binary unreadable: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatal("installed binary contents differ from source")
	}
	if fi, err := os.Stat(dest); err == nil && fi.Mode().Perm()&0100 == 0 {
		t.Error("installed binary is not executable")
	}
}

// TestResolveUpgradeURL_IgnoresEmbeddedHost proves a tampered command cannot point
// the agent at an attacker host or downgrade it to plaintext http: only the PATH of
// details.url is used, joined onto the enrolled server origin.
func TestResolveUpgradeURL_IgnoresEmbeddedHost(t *testing.T) {
	const enrolled = "https://quarkshield.ai"

	// An attacker host in details.url is discarded — only the path is kept.
	got, err := resolveUpgradeURL(enrolled, "https://evil.example.com/downloads/x.exe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := enrolled + "/downloads/x.exe"; got != want {
		t.Fatalf("embedded host not ignored: got %q, want %q", got, want)
	}

	// A plain server-relative path resolves against the enrolled origin.
	if got, err := resolveUpgradeURL(enrolled, "/downloads/agent"); err != nil || got != enrolled+"/downloads/agent" {
		t.Fatalf("relative path resolve failed: got %q err %v", got, err)
	}

	// Path traversal is refused.
	if _, err := resolveUpgradeURL(enrolled, "/downloads/../../etc/passwd"); err == nil {
		t.Error("expected path traversal to be rejected")
	}

	// A plaintext-http enrolled server (non-loopback) is refused.
	if _, err := resolveUpgradeURL("http://quarkshield.ai", "/downloads/agent"); err == nil {
		t.Error("expected plaintext http to a non-loopback host to be rejected")
	}

	// Loopback dev server over http is allowed.
	if _, err := resolveUpgradeURL("http://127.0.0.1:3000", "/downloads/agent"); err != nil {
		t.Errorf("loopback http should be allowed, got: %v", err)
	}
}

// TestCompareSemver covers the version-sanity ordering used to refuse same/older upgrades.
func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.3.0", "2.2.1", 1},
		{"2.2.1", "2.3.0", -1},
		{"2.3.0", "2.3.0", 0},
		{"v2.3.1", "2.3.0", 1},
		{"2.3.0-rc1", "2.3.0", 0},
		{"2.10.0", "2.9.9", 1},
	}
	for _, c := range cases {
		if got := compareSemver(c.a, c.b); got != c.want {
			t.Errorf("compareSemver(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
