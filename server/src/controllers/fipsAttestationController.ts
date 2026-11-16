import { Request, Response } from 'express';
import pool from '../config/db';
import { isSuperRole, superNeedsGrant, denySupportAccess, normTenant } from '../middleware/auth';
import { buildAttestationCsv, AttestationAssetRow } from '../lib/fipsAttestation';

/**
 * GET /api/compliance/fips-attestation.csv
 * FIPS / CMVP compliance evidence for ONE tenant (Stage 5, §6.4). Risk Assurance add-on;
 * the route applies requireAuth + requireTenantAccess + requireRiskAssuranceEntitlement.
 */
export const downloadFipsAttestation = async (req: Request, res: Response) => {
  try {
    // A tenant session is always its own tenant; only a platform session may name one.
    const tenant = String(isSuperRole(req.user?.role) ? (req.query.tenant || req.user?.tenant || '') : (req.user?.tenant || '')).trim();
    const key = normTenant(tenant);
    if (!key) return res.status(400).json({ error: 'A tenant is required.' });
    // Asset rows are tenant data: a platform session needs the tenant's support-access grant.
    if (superNeedsGrant(req)) return denySupportAccess(res, tenant);

    const q = await pool.query(`
      SELECT a.id, a.name, a.type, a.path, a.algorithm, a.key_size, a.hash_algorithm, a.purpose,
             a.crypto_module, a.crypto_module_evidence, a.crypto_module_detail,
             COALESCE(m.hostname, a.source_ref, '') AS hostname
        FROM assets a
        LEFT JOIN fleet_machines m ON a.machine_id = m.id
       WHERE REGEXP_REPLACE(LOWER(COALESCE(NULLIF(a.tenant_name, ''), m.tenant_name, '')), '[^a-z0-9]', '', 'g') = $1
       ORDER BY hostname, a.type, a.name`, [key]);

    const out = buildAttestationCsv(tenant, q.rows as AttestationAssetRow[]);
    const stamp = new Date().toISOString().split('T')[0];
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="QuarkShield-FIPS-CMVP-Evidence-${key}-${stamp}.csv"`);
    res.setHeader('Cache-Control', 'no-store');
    return res.send(out.csv);
  } catch (e) {
    console.error('fips attestation export error:', e);
    return res.status(500).json({ error: 'Compliance evidence export failed.' });
  }
};
