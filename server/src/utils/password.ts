import bcrypt from 'bcryptjs';
import crypto from 'crypto';

/**
 * Password hashing and verification.
 *
 * New passwords are hashed with bcrypt (cost 12). Legacy accounts were stored
 * as a single round of sha256(password + salt) in `password_hash` with the
 * random salt in `salt`. verifyPassword() accepts both so existing test users
 * keep working, and reports needsUpgrade so callers can transparently re-hash
 * a legacy password to bcrypt on the next successful login.
 */

const BCRYPT_COST = 12;

export const hashPassword = async (plain: string): Promise<string> => {
  return bcrypt.hash(plain, BCRYPT_COST);
};

const legacySha256 = (plain: string, salt: string): string =>
  crypto.createHash('sha256').update(plain + salt).digest('hex');

const timingSafeEqualStr = (a: string, b: string): boolean => {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
};

export interface VerifyResult {
  ok: boolean;
  needsUpgrade: boolean;
}

/**
 * Verify a plaintext password against a stored hash.
 * @param plain     the submitted password
 * @param storedHash value of password_hash (bcrypt string, or legacy sha256 hex)
 * @param storedSalt value of salt (only used for legacy sha256)
 */
export const verifyPassword = async (
  plain: string,
  storedHash: string | null | undefined,
  storedSalt: string | null | undefined
): Promise<VerifyResult> => {
  if (!plain || !storedHash) return { ok: false, needsUpgrade: false };

  // bcrypt hashes start with $2a$/$2b$/$2y$
  if (storedHash.startsWith('$2')) {
    const ok = await bcrypt.compare(plain, storedHash);
    return { ok, needsUpgrade: false };
  }

  // Legacy sha256(password + salt)
  if (storedSalt) {
    const ok = timingSafeEqualStr(legacySha256(plain, storedSalt), storedHash);
    return { ok, needsUpgrade: ok };
  }

  return { ok: false, needsUpgrade: false };
};
