// Push-upgrade state for a list of fleet machines, shared by every endpoint that
// feeds a machine list to the console (the fleet list and the tenant portal), so
// the "Update agent" controls see the same answer wherever the list came from.

import pool from '../config/db';
import { loadAgentRelease, upgradeStateFor, UpgradeState } from './agentRelease';

// An upgrade counts as "in flight" for this long after it is queued. Agents poll
// every 2 minutes and roll back an unconfirmed upgrade after 10, so by then it
// has either been applied (and closed by the next telemetry) or abandoned.
export const UPGRADE_IN_FLIGHT_MIN = 30;

export interface UpgradeFields {
  latestVersion: string | null;
  upgradeState: UpgradeState;
  upgradeInFlight: boolean;
}

type MachineRow = { id: string; os: string; arch: string; agentVersion?: string | null };

// Adds latestVersion / upgradeState / upgradeInFlight to each machine row.
export const withUpgradeState = async <T extends MachineRow>(rows: T[]): Promise<(T & UpgradeFields)[]> => {
  const release = loadAgentRelease();
  let upgrading = new Set<string>();
  if (release && rows.length > 0) {
    try {
      const inFlight = await pool.query(
        `SELECT DISTINCT machine_id FROM fleet_commands
          WHERE command = 'upgrade' AND status IN ('pending', 'dispatched')
            AND created_at > NOW() - ($2 || ' minutes')::interval
            AND machine_id = ANY($1)`,
        [rows.map(r => r.id), String(UPGRADE_IN_FLIGHT_MIN)]
      );
      upgrading = new Set(inFlight.rows.map(r => r.machine_id));
    } catch (e) {
      console.warn('Could not read in-flight upgrades:', e);
    }
  }
  return rows.map(r => ({
    ...r,
    latestVersion: release?.version || null,
    upgradeState: upgradeStateFor(release, r),
    upgradeInFlight: upgrading.has(r.id),
  }));
};
