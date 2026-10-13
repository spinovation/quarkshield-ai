package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// maxProbeTargetsPerCommand mirrors the server-side cap (probeTargets.ts
// MAX_TARGETS_PER_COMMAND). Defense in depth: the server validates, but the
// agent re-validates every target before dialing in case a command arrives from
// an older/compromised path.
const maxProbeTargetsPerCommand = 25

// alwaysBlockedV4 mirrors the server validator's ALWAYS_BLOCKED_V4 set. It is a
// SUBSET of a full SSRF blocklist: RFC1918 private ranges are deliberately
// allowed (probing internal infra is the point), but loopback, link-local +
// cloud metadata (169.254.169.254), multicast and reserved ranges never are.
var alwaysBlockedV4 = []string{
	"0.0.0.0/8",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"192.0.0.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
}

func isBlockedProbeIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		for _, c := range alwaysBlockedV4 {
			if _, ipnet, err := net.ParseCIDR(c); err == nil && ipnet.Contains(v4) {
				return true
			}
		}
		return false
	}
	// IPv6: block loopback, unspecified, link-local, multicast. Allow unique-local (fc/fd).
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	return false
}

// ValidateProbeTargets cleans and vets a probe target list agent-side. It returns
// the normalized host:port targets that are safe to dial; invalid or blocked
// targets are dropped (not fatal) so one bad entry doesn't void the whole batch.
func ValidateProbeTargets(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, entry := range raw {
		t := strings.TrimSpace(entry)
		if t == "" {
			continue
		}
		// Reject URLs / credentials / paths / queries outright.
		if strings.Contains(t, "://") || strings.ContainsAny(t, "@/?#") {
			continue
		}
		var host, portStr string
		if strings.HasPrefix(t, "[") {
			idx := strings.Index(t, "]")
			if idx == -1 || !strings.HasPrefix(t[idx+1:], ":") {
				continue
			}
			host = t[1:idx]
			portStr = t[idx+2:]
		} else {
			i := strings.LastIndex(t, ":")
			if i == -1 {
				continue // port required
			}
			host = t[:i]
			portStr = t[i+1:]
			if strings.Contains(host, ":") {
				continue // bare IPv6 must be bracketed
			}
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		hostLow := strings.ToLower(host)
		if hostLow == "" || hostLow == "localhost" || strings.HasSuffix(hostLow, ".localhost") {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			if isBlockedProbeIP(ip) {
				continue
			}
		}
		norm := fmt.Sprintf("%s:%d", hostLow, port)
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
		if len(out) >= maxProbeTargetsPerCommand {
			break
		}
	}
	return out
}

// ProbeDisabledLocally reports whether remote probing is turned off on THIS host
// (per-host agent opt-out, decided by the local operator). It is honored even if
// the server enqueues a probe command — a sensitive box can refuse. The flag is
// set by a sentinel file next to the enrollment config, or the
// QUARKSHIELD_DISABLE_PROBE env var.
func ProbeDisabledLocally() bool {
	if v := strings.TrimSpace(os.Getenv("QUARKSHIELD_DISABLE_PROBE")); v == "1" || strings.EqualFold(v, "true") {
		return true
	}
	if dir := filepath.Dir(getEnrollmentConfigPath()); dir != "" {
		if _, err := os.Stat(filepath.Join(dir, "probe.disabled")); err == nil {
			return true
		}
	}
	return false
}
