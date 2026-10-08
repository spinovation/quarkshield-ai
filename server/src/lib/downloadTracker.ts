/**
 * Agent download tracking. Logs one row per binary download with OS (from the
 * filename), client IP + country (Cloudflare headers), and a best-effort city/region
 * from a geo lookup. Logging is fire-and-forget: it never blocks or fails a download.
 *
 * Privacy: client IPs are stored for admin analytics and (unless QS_GEO_DISABLE=1) sent
 * to ip-api.com to resolve city/region. Set QS_GEO_DISABLE=1 to keep country-only.
 */
import crypto from 'crypto';
import { Request } from 'express';
import pool from '../config/db';

// req.ip already honours `trust proxy` (one hop = Cloudflare). Reading raw
// cf-connecting-ip / x-forwarded-for headers let anyone reaching the origin
// directly spoof the recorded address.
export const clientIp = (req: Request): string =>
  (req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/, '');

export const osFromFile = (file: string): string => {
  const f = file.toLowerCase();
  if (/\.(exe|msi)$/.test(f) || f.includes('windows') || /\bwin\b/.test(f)) return 'Windows';
  if (/\.(dmg|pkg)$/.test(f) || f.includes('darwin') || f.includes('macos') || f.includes('mac')) return 'macOS';
  if (/\.(deb|rpm|appimage)$/.test(f) || f.includes('linux')) return 'Linux';
  return 'Other';
};

const isPrivateIp = (ip: string): boolean =>
  !ip || ip === '::1' || ip.startsWith('127.') || ip.startsWith('10.') ||
  ip.startsWith('192.168.') || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip);

const geoEnrich = async (id: string, ip: string): Promise<void> => {
  if (process.env.QS_GEO_DISABLE === '1' || isPrivateIp(ip)) return;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 2500);
  try {
    const r = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,countryCode,regionName,city`,
      { signal: ctrl.signal }
    );
    if (!r.ok) return;
    const d: any = await r.json();
    if (d.status !== 'success') return;
    await pool.query(
      `UPDATE agent_downloads
         SET city = $1, region = $2, country = COALESCE(NULLIF(country,''), $3)
       WHERE id = $4`,
      [d.city || null, d.regionName || null, d.countryCode || null, id]
    );
  } catch {
    /* best-effort only */
  } finally {
    clearTimeout(timer);
  }
};

/**
 * BILL-7: capture + geolocate an enrolled machine's PUBLIC egress IP. Called
 * fire-and-forget from the telemetry ingest. The machine's stored `ip` is its LOCAL
 * interface address (not geolocatable); the public IP comes from Cloudflare headers on
 * the report request. We only hit ip-api when the public IP actually changed (or geo is
 * still unresolved), so daily reports don't hammer the lookup service.
 */
export const geoLocateMachine = (req: Request, machineId: string): void => {
  (async () => {
    try {
      const ip = clientIp(req);
      const country = ((req.headers['cf-ipcountry'] as string) || '').toUpperCase().slice(0, 2).replace(/[^A-Z]/g, '') || null;
      // Always record the public IP + Cloudflare country (cheap, no external call).
      const prev = await pool.query(
        `UPDATE fleet_machines
            SET public_ip = $1,
                geo_country = COALESCE($2, geo_country)
          WHERE id = $3
        RETURNING public_ip, geo_city, geo_country`,
        [ip || null, country, machineId]
      );
      const row = prev.rows[0];
      if (!row) return;
      if (process.env.QS_GEO_DISABLE === '1' || isPrivateIp(ip)) return;
      // Skip the external lookup if we already have a city for this exact IP.
      if (row.geo_city && row.public_ip === ip) return;

      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 2500);
      try {
        const r = await fetch(
          `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,countryCode,regionName,city`,
          { signal: ctrl.signal }
        );
        if (!r.ok) return;
        const d: any = await r.json();
        if (d.status !== 'success') return;
        await pool.query(
          `UPDATE fleet_machines
              SET geo_city = $1, geo_region = $2,
                  geo_country = COALESCE(NULLIF($3,''), geo_country),
                  geo_updated_at = NOW()
            WHERE id = $4`,
          [d.city || null, d.regionName || null, d.countryCode || null, machineId]
        );
      } finally {
        clearTimeout(timer);
      }
    } catch {
      /* best-effort only — never break telemetry ingest */
    }
  })();
};

export const logDownload = (req: Request, file: string): void => {
  (async () => {
    try {
      const id = 'dl-' + crypto.randomBytes(8).toString('hex');
      const ip = clientIp(req);
      const country = ((req.headers['cf-ipcountry'] as string) || '').toUpperCase().slice(0, 2).replace(/[^A-Z]/g, '') || null;
      const os = osFromFile(file);
      const ua = ((req.headers['user-agent'] as string) || '').slice(0, 400);
      await pool.query(
        `INSERT INTO agent_downloads (id, ip, country, os, file, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [id, ip || null, country, os, file.slice(0, 300), ua]
      );
      void geoEnrich(id, ip);
    } catch {
      /* never let tracking break a download */
    }
  })();
};
