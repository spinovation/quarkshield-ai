import { Request, Response } from 'express';
import QRCode from 'qrcode';
import pool from '../config/db';
import {
  generateSecret, buildOtpauthUrl, verifyTotp,
  encryptSecret, decryptSecret,
  generateRecoveryCodes,
} from '../utils/twofactor';
import { signSession, setSessionCookie } from '../middleware/auth';

/**
 * TOTP 2FA management. All routes require an authenticated session (req.user).
 * admin_users and tenant_users are handled based on the session's accountType.
 */

const tableFor = (req: Request): 'admin_users' | 'tenant_users' =>
  req.user!.accountType === 'tenant' ? 'tenant_users' : 'admin_users';

export const twoFactorStatus = async (req: Request, res: Response) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  const table = tableFor(req);
  const r = await pool.query(`SELECT two_factor_enabled FROM ${table} WHERE id = $1`, [req.user.sub]);
  return res.json({ enabled: !!r.rows[0]?.two_factor_enabled });
};

/** Begin enrollment: generate a secret (pending) and return the QR / otpauth URL. */
export const twoFactorSetup = async (req: Request, res: Response) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  const table = tableFor(req);
  const secret = generateSecret();
  // Store the (encrypted) secret but leave 2FA disabled until a code is verified.
  await pool.query(
    `UPDATE ${table} SET two_factor_secret = $1, two_factor_enabled = false WHERE id = $2`,
    [encryptSecret(secret), req.user.sub]
  );
  const otpauth = buildOtpauthUrl(secret, req.user.email);
  const qrDataUrl = await QRCode.toDataURL(otpauth);
  return res.json({ success: true, otpauthUrl: otpauth, qrDataUrl, secret });
};

/** Confirm enrollment with a code; enables 2FA and returns one-time recovery codes. */
export const twoFactorVerify = async (req: Request, res: Response) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Code is required.' });
  const table = tableFor(req);
  const r = await pool.query(`SELECT two_factor_secret FROM ${table} WHERE id = $1`, [req.user.sub]);
  const stored = r.rows[0]?.two_factor_secret;
  const secret = stored ? decryptSecret(stored) : null;
  if (!secret) return res.status(400).json({ error: 'Start setup first.' });
  if (!verifyTotp(code, secret)) return res.status(401).json({ error: 'Invalid code. Try again.' });

  const { plain, hashes } = generateRecoveryCodes(8);
  await pool.query(
    `UPDATE ${table} SET two_factor_enabled = true, two_factor_recovery_codes = $1 WHERE id = $2`,
    [JSON.stringify(hashes), req.user.sub]
  );
  // Upgrade a pending-2FA session to a full session now that enrollment is done.
  if (req.user.pending2fa) {
    const { sub, email, role, accountType, tenant } = req.user;
    setSessionCookie(res, signSession({ sub, email, role, accountType, tenant }));
  }
  return res.json({ success: true, enabled: true, recoveryCodes: plain });
};

/** Disable 2FA (requires a valid current code). */
export const twoFactorDisable = async (req: Request, res: Response) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Current 2FA code is required to disable.' });
  const table = tableFor(req);
  const r = await pool.query(`SELECT two_factor_secret FROM ${table} WHERE id = $1`, [req.user.sub]);
  const secret = r.rows[0]?.two_factor_secret ? decryptSecret(r.rows[0].two_factor_secret) : null;
  if (!secret || !verifyTotp(code, secret)) return res.status(401).json({ error: 'Invalid code.' });
  await pool.query(
    `UPDATE ${table} SET two_factor_enabled = false, two_factor_secret = NULL, two_factor_recovery_codes = NULL WHERE id = $1`,
    [req.user.sub]
  );
  return res.json({ success: true, enabled: false });
};
