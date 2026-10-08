/**
 * Exploitation-likelihood intelligence feeds:
 *   - CISA Known Exploited Vulnerabilities (KEV) catalog — public domain (U.S. Government work)
 *   - FIRST EPSS daily scores — free to use with attribution to FIRST.org
 *
 * Shared reference data (not tenant data). Each feed is fetched from its public URL, or
 * from a local file for offline / air-gapped installs (TI_KEV_FILE, TI_EPSS_FILE), parsed,
 * validated and swapped in atomically. Every run is recorded in ti_feed_runs with the
 * source and a SHA-256 of the payload so the data in use is always attributable.
 *
 * Scope boundary: these feeds only adjust LIKELIHOOD in the Threat & Risk Graph. There is
 * no IOC or threat-actor matching.
 */
import crypto from 'crypto';
import fs from 'fs';
import zlib from 'zlib';
import pool from '../../config/db';

export const KEV_URL = process.env.TI_KEV_URL || 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const EPSS_URL = process.env.TI_EPSS_URL || 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';
const MAX_BYTES = 64 * 1024 * 1024;
const TIMEOUT_MS = 60_000;
const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

type FeedName = 'kev' | 'epss';

const fetchBytes = async (url: string): Promise<Buffer> => {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(url, { signal: ctrl.signal, headers: { 'User-Agent': 'QuarkShield-ThreatIntel/1.0' } });
    if (!r.ok) throw new Error(`HTTP ${r.status} from ${url}`);
    const len = Number(r.headers.get('content-length') || 0);
    if (len > MAX_BYTES) throw new Error(`Feed too large (${len} bytes)`);
    const buf = Buffer.from(await r.arrayBuffer());
    if (buf.length > MAX_BYTES) throw new Error(`Feed too large (${buf.length} bytes)`);
    return buf;
  } finally {
    clearTimeout(timer);
  }
};

const readSource = async (feed: FeedName): Promise<{ buf: Buffer; source: string }> => {
  const file = feed === 'kev' ? process.env.TI_KEV_FILE : process.env.TI_EPSS_FILE;
  if (file) {
    const st = fs.statSync(file);
    if (st.size > MAX_BYTES) throw new Error(`Feed file too large (${st.size} bytes)`);
    return { buf: fs.readFileSync(file), source: `file:${file}` };
  }
  const url = feed === 'kev' ? KEV_URL : EPSS_URL;
  return { buf: await fetchBytes(url), source: url };
};

// ---------------------------------------------------------------------------
// Parsers (pure; unit-tested)
// ---------------------------------------------------------------------------
export interface KevRecord {
  cve_id: string; vendor: string | null; product: string | null; vulnerability_name: string | null;
  date_added: string | null; due_date: string | null; ransomware_use: boolean;
  short_description: string | null; required_action: string | null; cwes: string[];
}

const isoDate = (s: unknown): string | null => (typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : null);
const str = (s: unknown, max: number): string | null => (typeof s === 'string' && s.trim() ? s.trim().slice(0, max) : null);

export const parseKev = (json: string): { version: string | null; records: KevRecord[] } => {
  const doc = JSON.parse(json);
  if (!doc || !Array.isArray(doc.vulnerabilities)) throw new Error('KEV: missing vulnerabilities[]');
  const records: KevRecord[] = [];
  for (const v of doc.vulnerabilities) {
    const id = String(v?.cveID || '').trim().toUpperCase();
    if (!CVE_RE.test(id)) continue;
    records.push({
      cve_id: id,
      vendor: str(v.vendorProject, 255), product: str(v.product, 255), vulnerability_name: str(v.vulnerabilityName, 500),
      date_added: isoDate(v.dateAdded), due_date: isoDate(v.dueDate),
      ransomware_use: String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known',
      short_description: str(v.shortDescription, 4000), required_action: str(v.requiredAction, 2000),
      cwes: Array.isArray(v.cwes) ? v.cwes.filter((c: unknown) => typeof c === 'string' && /^CWE-\d+$/.test(c)) : [],
    });
  }
  if (records.length < 100) throw new Error(`KEV: implausibly small catalog (${records.length} entries)`);
  return { version: str(doc.catalogVersion, 100), records };
};

export interface EpssRecord { cve_id: string; epss: number; percentile: number }

/** EPSS CSV: optional "#model_version:…,score_date:…" line, then "cve,epss,percentile". */
export const parseEpss = (csv: string): { version: string | null; scoreDate: string | null; records: EpssRecord[] } => {
  const lines = csv.split(/\r?\n/);
  let version: string | null = null;
  let scoreDate: string | null = null;
  const records: EpssRecord[] = [];
  let header = false;
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('#')) {
      const mv = /model_version:([^,]+)/.exec(line); if (mv) version = mv[1].trim();
      const sd = /score_date:(\d{4}-\d{2}-\d{2})/.exec(line); if (sd) scoreDate = sd[1];
      continue;
    }
    if (!header) { header = true; if (/^cve,/i.test(line)) continue; }
    const [cve, e, p] = line.split(',');
    const id = (cve || '').trim().toUpperCase();
    const epss = Number(e); const percentile = Number(p);
    if (!CVE_RE.test(id) || !(epss >= 0 && epss <= 1) || !(percentile >= 0 && percentile <= 1)) continue;
    records.push({ cve_id: id, epss, percentile });
  }
  if (records.length < 1000) throw new Error(`EPSS: implausibly small file (${records.length} rows)`);
  return { version, scoreDate, records };
};

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------
const bulkInsert = async (db: any, table: string, cols: Record<string, string>, rows: object[]): Promise<void> => {
  const names = Object.keys(cols);
  const defs = names.map(n => `${n} ${cols[n]}`).join(', ');
  for (let i = 0; i < rows.length; i += 5000) {
    await db.query(
      `INSERT INTO ${table} (${names.join(', ')}) SELECT ${names.join(', ')} FROM jsonb_to_recordset($1::jsonb) AS x(${defs})`,
      [JSON.stringify(rows.slice(i, i + 5000))],
    );
  }
};

export interface FeedResult { feed: FeedName; status: 'success' | 'error'; records?: number; version?: string | null; error?: string }

const runFeed = async (feed: FeedName): Promise<FeedResult> => {
  const runId = `ti-${feed}-${crypto.randomUUID()}`;
  await pool.query(`INSERT INTO ti_feed_runs (id, feed, status) VALUES ($1, $2, 'running')`, [runId, feed]);
  try {
    const { buf, source } = await readSource(feed);
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    let version: string | null;
    let count: number;
    const db = await pool.connect();
    try {
      await db.query('BEGIN');
      if (feed === 'kev') {
        const parsed = parseKev(buf.toString('utf8'));
        version = parsed.version; count = parsed.records.length;
        await db.query('DELETE FROM ti_kev');
        await bulkInsert(db, 'ti_kev', {
          cve_id: 'text', vendor: 'text', product: 'text', vulnerability_name: 'text', date_added: 'date', due_date: 'date',
          ransomware_use: 'boolean', short_description: 'text', required_action: 'text', cwes: 'text[]',
        }, parsed.records);
      } else {
        const text = buf[0] === 0x1f && buf[1] === 0x8b ? zlib.gunzipSync(buf, { maxOutputLength: 256 * 1024 * 1024 }).toString('utf8') : buf.toString('utf8');
        const parsed = parseEpss(text);
        version = [parsed.version, parsed.scoreDate].filter(Boolean).join(' · ') || null; count = parsed.records.length;
        await db.query('DELETE FROM ti_epss');
        await bulkInsert(db, 'ti_epss', { cve_id: 'text', epss: 'real', percentile: 'real', score_date: 'date' },
          parsed.records.map(r => ({ ...r, score_date: parsed.scoreDate })));
      }
      await db.query('COMMIT');
    } catch (e) {
      await db.query('ROLLBACK');
      throw e;
    } finally {
      db.release();
    }
    await pool.query(
      `UPDATE ti_feed_runs SET status = 'success', source = $2, records = $3, feed_version = $4, sha256 = $5, finished_at = NOW() WHERE id = $1`,
      [runId, source, count, version, sha256],
    );
    return { feed, status: 'success', records: count, version };
  } catch (e) {
    const msg = (e as Error).message;
    await pool.query(`UPDATE ti_feed_runs SET status = 'error', error = $2, finished_at = NOW() WHERE id = $1`, [runId, msg]).catch(() => undefined);
    return { feed, status: 'error', error: msg };
  }
};

let syncing: Promise<FeedResult[]> | null = null;

/** Sync both feeds (a failed feed keeps the previous data in place). */
export const syncThreatIntel = (): Promise<FeedResult[]> => {
  if (syncing) return syncing;
  syncing = (async () => {
    try { return [await runFeed('kev'), await runFeed('epss')]; } finally { syncing = null; }
  })();
  return syncing;
};

export const feedStatus = async () => {
  const r = await pool.query(
    `SELECT DISTINCT ON (feed) feed, status, source, records, feed_version, sha256, error, started_at, finished_at
       FROM ti_feed_runs ORDER BY feed, started_at DESC`);
  const ok = await pool.query(
    `SELECT DISTINCT ON (feed) feed, finished_at, records, feed_version FROM ti_feed_runs WHERE status = 'success' ORDER BY feed, started_at DESC`);
  return {
    latest: r.rows,
    lastSuccess: Object.fromEntries(ok.rows.map((x: any) => [x.feed, x])),
    attribution: {
      kev: 'CISA Known Exploited Vulnerabilities Catalog (cisa.gov/kev)',
      epss: 'EPSS scores courtesy of FIRST.org (first.org/epss)',
    },
  };
};

/** Intelligence for a set of CVEs (what the engine needs for one tenant). */
export const loadIntelFor = async (cves: string[]) => {
  const ids = [...new Set(cves.map(c => c.toUpperCase()).filter(c => CVE_RE.test(c)))];
  if (!ids.length) return { kev: {}, epss: {} };
  const [k, e] = await Promise.all([
    pool.query(
      `SELECT cve_id, vulnerability_name, TO_CHAR(date_added, 'YYYY-MM-DD') AS date_added, TO_CHAR(due_date, 'YYYY-MM-DD') AS due_date,
              ransomware_use, required_action, cwes FROM ti_kev WHERE cve_id = ANY($1)`, [ids]),
    pool.query(`SELECT cve_id, epss, percentile FROM ti_epss WHERE cve_id = ANY($1)`, [ids]),
  ]);
  return {
    kev: Object.fromEntries(k.rows.map((r: any) => [r.cve_id, r])),
    epss: Object.fromEntries(e.rows.map((r: any) => [r.cve_id, { epss: Number(r.epss), percentile: Number(r.percentile) }])),
  };
};

// ---------------------------------------------------------------------------
// Daily scheduler (checks hourly; syncs when the last success is > 20h old)
// ---------------------------------------------------------------------------
let timer: NodeJS.Timeout | null = null;

export const startThreatIntelScheduler = (onSynced?: () => void): void => {
  if (timer || process.env.TI_FEEDS_ENABLED === 'false') return;
  const tick = async () => {
    try {
      const r = await pool.query(`SELECT MAX(finished_at) AS t FROM ti_feed_runs WHERE status = 'success' AND feed = 'kev'`);
      const last = r.rows[0]?.t ? new Date(r.rows[0].t).getTime() : 0;
      if (Date.now() - last < 20 * 3600 * 1000) return;
      const results = await syncThreatIntel();
      for (const x of results) {
        console.log(`threat-intel ${x.feed}: ${x.status}${x.records ? ` (${x.records} records)` : ''}${x.error ? ` — ${x.error}` : ''}`);
      }
      if (results.some(x => x.status === 'success')) onSynced?.();
    } catch (e) {
      console.warn('threat-intel scheduler tick failed:', (e as Error).message);
    }
  };
  setTimeout(tick, 30_000).unref?.();
  timer = setInterval(tick, 3600_000);
  timer.unref?.();
};
