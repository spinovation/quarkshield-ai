import net from 'net';

/**
 * Fleet Probe target validation (server-side, defense #1).
 *
 * The probe runs ON the agent, inside the tenant's own network, so unlike the
 * server-side landing probe (which uses ssrf.ts `resolvePublicHost` to force
 * PUBLIC-only targets) a fleet probe is ALLOWED to reach private/RFC1918 infra —
 * that internal host<->host topology is the whole point of the feature.
 *
 * What is NEVER a legitimate fleet-probe target and is always rejected:
 *   - loopback (127.0.0.0/8, ::1, 0.0.0.0) — probing the agent's own box
 *   - link-local + cloud metadata (169.254.0.0/16, incl. 169.254.169.254;
 *     fe80::/10) — the credential-theft / SSRF-abuse vector
 *   - multicast / reserved / broadcast ranges
 *   - "localhost" and other obvious local names
 *   - anything carrying credentials, a path, or a query string (a target must
 *     not smuggle data out via a URL)
 *
 * This mirrors the always-block set in ssrf.ts without importing its DNS
 * resolution: the server cannot (and must not) resolve internal names like
 * `db.internal`; literal-IP targets are checked directly, and the agent
 * re-validates every target before dialing (defense in depth).
 */

export const MAX_TARGETS_PER_COMMAND = 25;

const ipv4ToInt = (ip: string): number => {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
};

const inCidr = (ip: string, cidr: string): boolean => {
  const [range, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(range) & mask);
};

// Ranges that are never a valid fleet-probe target. Note this is intentionally a
// SUBSET of ssrf.ts BLOCKED_V4: RFC1918 private ranges (10/8, 172.16/12,
// 192.168/16) and CGNAT (100.64/10) are DELIBERATELY allowed for internal infra.
const ALWAYS_BLOCKED_V4 = [
  '0.0.0.0/8',        // "this host"
  '127.0.0.0/8',      // loopback
  '169.254.0.0/16',   // link-local + cloud metadata (169.254.169.254)
  '192.0.0.0/24',     // IETF protocol assignments
  '224.0.0.0/4',      // multicast
  '240.0.0.0/4',      // reserved / future use
  '255.255.255.255/32', // limited broadcast
];

const isBlockedLiteralIp = (ip: string): boolean => {
  const type = net.isIP(ip);
  if (type === 4) return ALWAYS_BLOCKED_V4.some(c => inCidr(ip, c));
  if (type === 6) {
    const low = ip.toLowerCase();
    if (low === '::1' || low === '::') return true;          // loopback / unspecified
    if (low.startsWith('fe80')) return true;                 // link-local
    if (low.startsWith('ff')) return true;                   // multicast
    const m = low.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);     // IPv4-mapped
    if (m) return ALWAYS_BLOCKED_V4.some(c => inCidr(m[1], c));
    return false;                                            // allow fc/fd unique-local (private)
  }
  return false; // not an IP literal -> hostname, checked separately
};

export interface TargetPolicy {
  /**
   * Optional per-tenant allowlist of attested host:port targets. When provided
   * and non-empty, a target must match one of these entries exactly (case- and
   * whitespace-insensitive on the host) or it is rejected. Phase-5 hardening;
   * absent/empty means free-form (still subject to the always-block rules).
   */
  allowlist?: string[] | null;
  /** Override the per-command cap (defaults to MAX_TARGETS_PER_COMMAND). */
  maxTargets?: number;
}

export interface TargetValidationResult {
  ok: boolean;
  /** Normalized, de-duplicated host:port targets (only set when ok). */
  targets: string[];
  /** Human-readable reason when !ok. */
  error?: string;
}

const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

const normalizeAllowlist = (list?: string[] | null): Set<string> | null => {
  if (!list || list.length === 0) return null;
  return new Set(list.map(e => e.trim().toLowerCase()).filter(Boolean));
};

/**
 * Validate and normalize a list of probe targets. Returns the cleaned
 * `host:port` list on success, or a single error describing the first problem.
 * TLS-only by design — the probe is a TLS handshake, not a TCP port sweep — but
 * callers may legitimately pass non-443 TLS ports (e.g. 5432 for Postgres TLS),
 * so the port is validated for range, not against an allowlist.
 */
export const validateProbeTargets = (
  raw: unknown,
  policy: TargetPolicy = {}
): TargetValidationResult => {
  if (!Array.isArray(raw)) {
    return { ok: false, targets: [], error: 'targets must be an array of host:port strings' };
  }
  const max = policy.maxTargets ?? MAX_TARGETS_PER_COMMAND;
  const allow = normalizeAllowlist(policy.allowlist);

  const cleaned: string[] = [];
  const seen = new Set<string>();

  for (const entry of raw) {
    if (typeof entry !== 'string') {
      return { ok: false, targets: [], error: 'each target must be a string' };
    }
    let t = entry.trim();
    if (!t) continue; // skip blank lines
    // Reject anything that is a URL / carries credentials, a path, or a query.
    if (/^[a-z]+:\/\//i.test(t) || t.includes('@') || t.includes('/') || t.includes('?') || t.includes('#')) {
      return { ok: false, targets: [], error: `invalid target "${entry}": host:port only (no scheme, credentials, path, or query)` };
    }

    // Split host:port. Require an explicit port (fleet probing should be exact).
    let host = '';
    let portStr = '';
    if (t.startsWith('[')) {
      // bracketed IPv6: [::1]:443
      const idx = t.indexOf(']');
      if (idx === -1) return { ok: false, targets: [], error: `invalid target "${entry}": malformed IPv6 literal` };
      host = t.slice(1, idx);
      const rest = t.slice(idx + 1);
      if (!rest.startsWith(':')) return { ok: false, targets: [], error: `invalid target "${entry}": port required (host:port)` };
      portStr = rest.slice(1);
    } else {
      const lastColon = t.lastIndexOf(':');
      if (lastColon === -1) {
        return { ok: false, targets: [], error: `invalid target "${entry}": port required (e.g. ${t}:443)` };
      }
      host = t.slice(0, lastColon);
      portStr = t.slice(lastColon + 1);
      // A bare IPv6 literal has multiple colons and must be bracketed.
      if (host.includes(':')) {
        return { ok: false, targets: [], error: `invalid target "${entry}": bracket IPv6 literals as [addr]:port` };
      }
    }

    const port = Number(portStr);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return { ok: false, targets: [], error: `invalid target "${entry}": port must be 1-65535` };
    }

    const hostLow = host.toLowerCase();
    if (!hostLow) return { ok: false, targets: [], error: `invalid target "${entry}": empty host` };

    // Always-block obvious local names regardless of policy.
    if (hostLow === 'localhost' || hostLow.endsWith('.localhost')) {
      return { ok: false, targets: [], error: `refused target "${entry}": loopback is not a valid probe target` };
    }

    if (net.isIP(host)) {
      if (isBlockedLiteralIp(host)) {
        return { ok: false, targets: [], error: `refused target "${entry}": loopback/link-local/metadata/reserved addresses cannot be probed` };
      }
    } else if (!HOSTNAME_RE.test(host)) {
      return { ok: false, targets: [], error: `invalid target "${entry}": not a valid hostname or IP` };
    }

    const normalized = `${hostLow}:${port}`;
    if (allow && !allow.has(normalized) && !allow.has(hostLow)) {
      return { ok: false, targets: [], error: `refused target "${entry}": not in this tenant's probe allowlist` };
    }

    if (!seen.has(normalized)) {
      seen.add(normalized);
      cleaned.push(normalized);
    }
  }

  if (cleaned.length === 0) {
    return { ok: false, targets: [], error: 'no valid targets supplied' };
  }
  if (cleaned.length > max) {
    return { ok: false, targets: [], error: `too many targets: ${cleaned.length} (max ${max} per command)` };
  }
  return { ok: true, targets: cleaned };
};
