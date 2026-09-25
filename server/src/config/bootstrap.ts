import pool from './db';
import { hashPassword } from '../utils/password';

/**
 * Break-glass administrator.
 *
 * If BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD are set, upsert a
 * superadmin with a bcrypt-hashed password on startup. This guarantees a known
 * way in after auth is enforced, without anyone needing to know the legacy
 * seeded password. Set a strong password and rotate/remove after first login.
 */
export const bootstrapAdmin = async (): Promise<void> => {
  const email = (process.env.BOOTSTRAP_ADMIN_EMAIL || '').trim().toLowerCase();
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD || '';
  if (!email || !password) return;
  if (password.length < 12) {
    console.warn('BOOTSTRAP_ADMIN_PASSWORD too short (min 12); skipping bootstrap admin.');
    return;
  }
  try {
    const hash = await hashPassword(password);
    await pool.query(
      `INSERT INTO admin_users (id, email, password_hash, salt, role, email_verified, company)
       VALUES ($1, $2, $3, NULL, 'superadmin', true, 'QuarkShield Bootstrap')
       ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, salt = NULL, role = 'superadmin', row_locked = false`,
      ['usr-bootstrap-' + Buffer.from(email).toString('hex').slice(0, 12), email, hash]
    );
    console.log(`Bootstrap admin ensured for ${email}.`);
  } catch (err) {
    console.error('Bootstrap admin failed:', err);
  }
};
