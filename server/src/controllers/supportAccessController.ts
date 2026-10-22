import { Request, Response } from 'express';
import { isSuperRole } from '../middleware/auth';
import {
  hasActiveSupportGrant, getActiveGrant, listActiveGrants, createGrant, revokeGrants,
  auditSupportEvent, DEFAULT_GRANT_HOURS, MIN_GRANT_HOURS, MAX_GRANT_HOURS,
} from '../lib/supportAccess';

/**
 * POST /api/support-access/grant   (tenant admin)
 * Body: { durationHours?, reason? }. Opens a time-boxed window during which a
 * super-admin may view this tenant's component-level SBOM for troubleshooting.
 */
export async function grantSupportAccess(req: Request, res: Response) {
  try {
    const tenant = req.user?.tenant;
    if (!tenant) return res.status(400).json({ success: false, error: 'No tenant in session.' });
    const { durationHours, reason } = req.body || {};
    const grant = await createGrant(tenant, req.user?.id || 'tenant-admin', Number(durationHours) || DEFAULT_GRANT_HOURS, reason);
    await auditSupportEvent('support_access_granted', req.user?.id || tenant,
      `tenant=${tenant} expires=${grant.expires_at} reason=${(reason || '').slice(0, 200)}`, req.ip);
    return res.json({ success: true, grant, limits: { min: MIN_GRANT_HOURS, max: MAX_GRANT_HOURS } });
  } catch (err) {
    console.error('grantSupportAccess failed:', err);
    return res.status(500).json({ success: false, error: 'Failed to grant support access.' });
  }
}

/** POST /api/support-access/revoke   (tenant admin) */
export async function revokeSupportAccess(req: Request, res: Response) {
  try {
    const tenant = req.user?.tenant;
    if (!tenant) return res.status(400).json({ success: false, error: 'No tenant in session.' });
    const n = await revokeGrants(tenant);
    if (n > 0) {
      await auditSupportEvent('support_access_revoked', req.user?.id || tenant, `tenant=${tenant}`, req.ip);
    }
    return res.json({ success: true, revoked: n });
  } catch (err) {
    console.error('revokeSupportAccess failed:', err);
    return res.status(500).json({ success: false, error: 'Failed to revoke support access.' });
  }
}

/**
 * GET /api/support-access/status
 * Tenant admin → their own tenant's active grant.
 * Super-admin  → ?tenant= to check one tenant, or the full active list.
 */
export async function getSupportAccessStatus(req: Request, res: Response) {
  try {
    const isSuper = isSuperRole(req.user?.role);
    if (isSuper) {
      const q = (req.query.tenant as string || '').trim();
      if (q) {
        const grant = await getActiveGrant(q);
        return res.json({ success: true, tenant: q, active: !!grant, grant: grant || null });
      }
      const grants = await listActiveGrants();
      return res.json({ success: true, active: grants });
    }
    const tenant = req.user?.tenant;
    if (!tenant) return res.status(400).json({ success: false, error: 'No tenant in session.' });
    const grant = await getActiveGrant(tenant);
    return res.json({ success: true, tenant, active: !!grant, grant: grant || null });
  } catch (err) {
    console.error('getSupportAccessStatus failed:', err);
    return res.status(500).json({ success: false, error: 'Failed to read support-access status.' });
  }
}

// Re-export for controllers that need the gate.
export { hasActiveSupportGrant, auditSupportEvent };
