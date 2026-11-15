// Agent release manifest + version helpers for console push-upgrade.
//
// TRUST MODEL: the server is a courier, not an authority. It reads the release
// manifest and its Ed25519 signature from the downloads directory and forwards
// both, byte for byte, in an `upgrade` command. Each agent verifies the signature
// against the release key it was built with, so nothing the server (or its
// database, or its downloads directory) could alter is trusted by the endpoint.
// The private release key is never present on the server.

import fs from 'fs';
import path from 'path';

// First agent release that understands the `upgrade` command. Older agents drop
// unknown commands, so pushing to them would silently do nothing — the console
// must ask for a manual re-install instead.
export const MIN_PUSH_UPGRADE_VERSION = '2.3.2';

export interface AgentArtifact { path: string; sha256: string; size?: number; }
export interface AgentRelease {
  version: string;
  manifest: string;   // exact bytes the signature covers — never re-serialise
  signature: string;  // base64 Ed25519
  artifacts: Record<string, AgentArtifact>;
}

// Same directories index.ts serves /downloads from, so the manifest read here is
// the one sitting next to the binaries agents will actually download.
export const downloadDirCandidates = (): string[] => [
  process.env.DOWNLOADS_DIR,
  path.join(__dirname, '../../../agent/binaries'),
  path.join(__dirname, '../../agent/binaries'),
  path.join(__dirname, '../binaries'),
  path.join(__dirname, '../../downloads'),
  path.join(process.cwd(), 'agent/binaries'),
  path.join(process.cwd(), 'downloads'),
].filter(Boolean) as string[];

const STRICT_VERSION = /^\d{1,4}\.\d{1,4}\.\d{1,4}$/;

// Parse + sanity-check a manifest/signature pair. Returns null if it is not a
// usable agent release. (This is NOT the security check — agents do that.)
export const parseAgentRelease = (manifest: string, signature: string): AgentRelease | null => {
  try {
    const sig = (signature || '').trim();
    if (!manifest || manifest.length > 64 * 1024) return null;
    if (!/^[A-Za-z0-9+/]{86}==$/.test(sig)) return null; // 64-byte signature, base64
    const data = JSON.parse(manifest);
    if (!data || data.product !== 'quarkshield-agent') return null;
    if (typeof data.version !== 'string' || !STRICT_VERSION.test(data.version)) return null;
    if (!data.artifacts || typeof data.artifacts !== 'object') return null;
    return { version: data.version, manifest, signature: sig, artifacts: data.artifacts };
  } catch {
    return null;
  }
};

let cache: { key: string; release: AgentRelease | null } | null = null;

// Load the current release from the downloads directory. Cached on the two files'
// mtimes, so publishing a new release is picked up without a restart.
export const loadAgentRelease = (dirs: string[] = downloadDirCandidates()): AgentRelease | null => {
  for (const dir of dirs) {
    const mPath = path.join(dir, 'agent-manifest.json');
    const sPath = path.join(dir, 'agent-manifest.json.sig');
    try {
      const key = `${mPath}:${fs.statSync(mPath).mtimeMs}:${fs.statSync(sPath).mtimeMs}`;
      if (cache && cache.key === key) return cache.release;
      const release = parseAgentRelease(fs.readFileSync(mPath, 'utf8'), fs.readFileSync(sPath, 'utf8'));
      cache = { key, release };
      return release;
    } catch { /* not in this directory — try the next */ }
  }
  return null;
};

// Compare dotted numeric versions: -1 / 0 / 1. Pre-release suffix ignored.
export const cmpAgentVersion = (a: string, b: string): number => {
  const norm = (v: string) => (v || '').trim().replace(/^v/, '').split(/[-+]/)[0].split('.').map(n => parseInt(n, 10) || 0);
  const pa = norm(a), pb = norm(b);
  for (let i = 0; i < 3; i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
};

// Does the release contain a build this machine can install? macOS agents take
// the notarized app archive when running from QuarkShield.app, else a bare binary.
export const releaseHasBuildFor = (release: AgentRelease, os: string, arch: string): boolean => {
  const o = (os || '').toLowerCase().trim();
  const a = (arch || '').toLowerCase().trim();
  if (o === 'darwin') return !!release.artifacts['darwin/app'] || !!release.artifacts[`darwin/${a}`];
  return !!release.artifacts[`${o}/${a}`];
};

export type UpgradeState =
  | 'current'          // already on the latest release
  | 'pushable'         // out of date and able to upgrade itself
  | 'manual'           // out of date but too old to understand a push — re-install once
  | 'unsupported'      // out of date but the release has no build for this platform
  | 'unknown';         // no signed release published on this server

// Classify one machine against the published release. `force` treats a machine on
// the latest version as pushable (re-install of the same version).
export const upgradeStateFor = (
  release: AgentRelease | null,
  machine: { os: string; arch: string; agentVersion?: string | null },
  force = false,
): UpgradeState => {
  if (!release) return 'unknown';
  const current = (machine.agentVersion || '').toString();
  const behind = cmpAgentVersion(current, release.version) < 0;
  if (!behind && !(force && cmpAgentVersion(current, release.version) === 0)) return 'current';
  if (cmpAgentVersion(current, MIN_PUSH_UPGRADE_VERSION) < 0) return 'manual';
  if (!releaseHasBuildFor(release, machine.os, machine.arch)) return 'unsupported';
  return 'pushable';
};
