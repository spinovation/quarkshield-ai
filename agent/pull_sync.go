package main

import (
	"runtime"
	"strings"
)

// On-demand pull fidelity (DEF-55).
//
// A console "Pull Telemetry" / "Pull All" / scheduled pull enqueues a `scan_and_sync`
// command that the agent honors on its next poll. Historically BOTH execution paths
// (GUI background loop and the --daemon runSync) ran a hardcoded QUICK scan. On a host
// the operator had deep-scanned (a custom path or a full scan), that quick scan silently
// under-reported the inventory, so the admin "couldn't pull what the agent shows."
//
// The agent already persists every scan's scope and findings (scan_store.go). So an
// on-demand pull now REPRODUCES the host's real inventory instead of shrinking it:
//   1) it re-pushes the last saved scan's findings immediately, so the console updates
//      at once (instant feedback, no waiting on a rescan), then
//   2) it re-runs the SAME scope the operator last used (custom path / full / quick) and
//      pushes the fresh results.
// With no prior scan it falls back to a quick scan (the old behavior).

type pullScanPlan struct {
	quick       bool
	customPath  string
	includeSbom bool
	reScan      bool          // false → re-push cached only (sbom / probe-only history)
	cached      []AuditResult // last saved findings, pushed first for instant feedback
	scopeLabel  string        // "quick" | "full" | "custom" — how a fresh rescan is recorded
}

// planOnDemandPull derives how to reproduce this host's inventory from its last scan.
func planOnDemandPull() pullScanPlan {
	rec, err := GetLatestScanResult()
	if err != nil || rec == nil {
		return pullScanPlan{quick: true, reScan: true, scopeLabel: "quick"} // no history → quick
	}
	p := pullScanPlan{cached: rec.Findings, reScan: true}
	switch strings.ToLower(rec.ScanType) {
	case "custom":
		p.quick, p.customPath, p.scopeLabel = false, rec.TargetPath, "custom"
	case "full":
		p.quick, p.scopeLabel = false, "full"
	case "sbom":
		// An SBOM inventory is collected differently; re-push the saved view as-is rather
		// than converting it into a crypto+sbom rescan that would change its meaning.
		p.reScan, p.scopeLabel = false, "sbom"
	case "network_probe":
		// A probe is endpoint connectivity, not a filesystem inventory — just re-push.
		p.reScan, p.scopeLabel = false, "network_probe"
	default: // "quick" or unknown
		p.quick, p.scopeLabel = true, "quick"
	}
	return p
}

// runOnDemandPull services a console pull: cached-first, then a same-scope rescan.
// Returns the asset count of the freshest push it managed to send. Callers must have
// already gated on license/token and on a scan not already running.
func runOnDemandPull(server, token, host, ip string) int {
	p := planOnDemandPull()
	lic := GetLicenseInfo()

	// 1) Instant: re-push the agent's current saved view so the console matches at once.
	if len(p.cached) > 0 {
		_ = SendFleetTelemetry(server, token, host, runtime.GOOS, runtime.GOARCH, ip, p.cached, lic.LicenseKey, lic.TenantName)
	}

	// 2) Fresh: re-run the SAME scope the operator last used, then push + persist it.
	if p.reScan {
		findings, scanned, err := headlessScan(p.quick, p.customPath, p.includeSbom)
		if err == nil && len(findings) > 0 {
			_ = SendFleetTelemetry(server, token, host, runtime.GOOS, runtime.GOARCH, ip, findings, lic.LicenseKey, lic.TenantName)
			_, _ = SaveScanResult(p.scopeLabel, p.customPath, scanned, findings)
			return len(findings)
		}
	}
	return len(p.cached)
}
