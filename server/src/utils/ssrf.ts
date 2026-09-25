import dns from 'dns';
import net from 'net';

/**
 * SSRF protection: reject hostnames that resolve to private, loopback,
 * link-local (incl. the 169.254.169.254 cloud metadata address), or otherwise
 * non-public IP ranges. Used before the server makes any outbound connection on
 * behalf of a caller (TLS probe, remote git clone).
 */

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

const BLOCKED_V4 = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24',
  '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
  '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
];

const isBlockedIp = (ip: string): boolean => {
  const type = net.isIP(ip);
  if (type === 4) {
    return BLOCKED_V4.some(c => inCidr(ip, c));
  }
  if (type === 6) {
    const low = ip.toLowerCase();
    if (low === '::1' || low === '::') return true;
    if (low.startsWith('fe80') || low.startsWith('fc') || low.startsWith('fd')) return true; // link-local, unique-local
    if (low.startsWith('ff')) return true; // multicast
    // IPv4-mapped (::ffff:a.b.c.d)
    const m = low.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (m) return BLOCKED_V4.some(c => inCidr(m[1], c));
    return false;
  }
  return true; // not a valid IP -> treat as blocked
};

/**
 * Resolve a hostname and throw if it (or any of its addresses) is non-public.
 * If the host is an IP literal it is checked directly.
 */
export const assertPublicHost = async (host: string): Promise<void> => {
  const clean = (host || '').trim().toLowerCase();
  if (!clean) throw new Error('No host provided');

  // Obvious local names
  if (clean === 'localhost' || clean.endsWith('.localhost') || clean.endsWith('.local') || clean.endsWith('.internal')) {
    throw new Error('Host is not permitted');
  }

  if (net.isIP(clean)) {
    if (isBlockedIp(clean)) throw new Error('Host resolves to a non-public address');
    return;
  }

  const addrs = await new Promise<dns.LookupAddress[]>((resolve, reject) => {
    dns.lookup(clean, { all: true }, (err, addresses) => {
      if (err) reject(new Error('Host could not be resolved'));
      else resolve(addresses);
    });
  });

  if (!addrs.length) throw new Error('Host could not be resolved');
  for (const a of addrs) {
    if (isBlockedIp(a.address)) throw new Error('Host resolves to a non-public address');
  }
};
