/**
 * Recurring pull scheduler (DEF-41). A 60-second worker that enqueues an on-demand
 * scan_and_sync for a tenant's endpoints (optionally region-scoped) when the local
 * clock in the schedule's timezone reaches hour:minute. Agents honor the queued pull
 * on their next poll (continuously, via the DEF-39 persistent daemon).
 *
 * Idempotency: a schedule won't fire twice within ~23h (last_run_at guard), so a
 * duplicate tick inside the same minute, or a restart, can't double-queue.
 */
import pool from '../config/db';
import { enqueuePullsForScope } from '../controllers/fleetController';

let timer: NodeJS.Timeout | null = null;

const tzNow = (tz: string): { hour: number; minute: number } => {
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz || 'UTC', hour12: false, hour: '2-digit', minute: '2-digit'
    }).formatToParts(new Date());
    const h = parseInt(parts.find(p => p.type === 'hour')?.value || '0', 10) % 24;
    const m = parseInt(parts.find(p => p.type === 'minute')?.value || '0', 10);
    return { hour: h, minute: m };
  } catch {
    const d = new Date();
    return { hour: d.getUTCHours(), minute: d.getUTCMinutes() };
  }
};

const tick = async (): Promise<void> => {
  try {
    const { rows } = await pool.query(
      `SELECT id, tenant_name, region, hour, minute, timezone, last_run_at
         FROM pull_schedules WHERE enabled = true`
    );
    for (const s of rows) {
      const { hour, minute } = tzNow(s.timezone || 'UTC');
      if (hour !== s.hour || minute !== s.minute) continue;
      if (s.last_run_at && Date.now() - new Date(s.last_run_at).getTime() < 23 * 3600 * 1000) continue;
      try {
        const queued = await enqueuePullsForScope(s.tenant_name, { region: s.region });
        await pool.query('UPDATE pull_schedules SET last_run_at = NOW() WHERE id = $1', [s.id]);
        console.log(`[pullScheduler] ${s.tenant_name}/${s.region || 'ALL'} @ ${s.hour}:${String(s.minute).padStart(2, '0')} ${s.timezone} -> queued ${queued} endpoint(s)`);
      } catch (e) {
        console.error(`[pullScheduler] schedule ${s.id} failed:`, e);
      }
    }
  } catch {
    /* table may not exist on very first boot before schema runs; ignore this tick */
  }
};

export const startPullScheduler = (): void => {
  if (timer) return;
  timer = setInterval(tick, 60 * 1000);
  console.log('[pullScheduler] started (60s tick)');
};
