import crypto from 'crypto';
import * as otplib from 'otplib';

/**
 * TOTP two-factor authentication helpers.
 *
 * Secrets are encrypted at rest with AES-256-GCM using TWO_FACTOR_ENC_KEY
 * (any string; hashed to 32 bytes). Recovery codes are stored only as hashes.
 */

const encKey = (): Buffer => {
  const raw = process.env.TWO_FACTOR_ENC_KEY || process.env.JWT_SECRET || 'dev-insecure-2fa-key';
  return crypto.createHash('sha256').update(raw).digest();
};

export const generateSecret = (): string => (otplib as any).generateSecret();

export const buildOtpauthUrl = (secret: string, account: string, issuer = 'QuarkShield'): string =>
  (otplib as any).generateURI({ secret, label: account, issuer });

export const verifyTotp = (token: string, secret: string): boolean => {
  try {
    const clean = (token || '').replace(/\s/g, '');
    if (!clean) return false;
    const r = (otplib as any).verifySync({ token: clean, secret });
    return !!(r && r.valid);
  } catch {
    return false;
  }
};

export const encryptSecret = (secret: string): string => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encKey(), iv);
  const enc = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString('base64')}:${tag.toString('base64')}:${enc.toString('base64')}`;
};

export const decryptSecret = (stored: string): string | null => {
  try {
    if (!stored || !stored.startsWith('v1:')) return null;
    const [, ivB64, tagB64, dataB64] = stored.split(':');
    const decipher = crypto.createDecipheriv('aes-256-gcm', encKey(), Buffer.from(ivB64, 'base64'));
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    const dec = Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]);
    return dec.toString('utf8');
  } catch {
    return null;
  }
};

const hashRecoveryCode = (code: string): string =>
  crypto.createHash('sha256').update(code.replace(/[\s-]/g, '').toLowerCase()).digest('hex');

/** Generate N recovery codes; returns the plaintext (show once) and their hashes (store). */
export const generateRecoveryCodes = (n = 8): { plain: string[]; hashes: string[] } => {
  const plain: string[] = [];
  for (let i = 0; i < n; i++) {
    const raw = crypto.randomBytes(5).toString('hex'); // 10 hex chars
    plain.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return { plain, hashes: plain.map(hashRecoveryCode) };
};

/** Return the remaining hashes if the code matched one (consumed), else null. */
export const consumeRecoveryCode = (code: string, hashes: string[]): string[] | null => {
  const h = hashRecoveryCode(code);
  if (!hashes.includes(h)) return null;
  return hashes.filter(x => x !== h);
};
