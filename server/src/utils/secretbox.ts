import crypto from 'crypto';

/**
 * Symmetric encryption for secrets stored at rest (connector credentials that
 * cannot be keyless, e.g. a HashiCorp Vault token / AppRole secret_id or an
 * Azure service-principal client secret). AES-256-GCM with a key derived from
 * CONNECTOR_ENC_KEY (falls back to TWO_FACTOR_ENC_KEY / JWT_SECRET). Prefer
 * keyless auth where the provider supports it and avoid storing secrets at all.
 */

const key = (): Buffer => {
  const raw = process.env.CONNECTOR_ENC_KEY || process.env.TWO_FACTOR_ENC_KEY || process.env.JWT_SECRET || 'dev-insecure-connector-key';
  return crypto.createHash('sha256').update(raw).digest();
};

export const seal = (plain: string): string => {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key(), iv);
  const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return `v1:${iv.toString('base64')}:${c.getAuthTag().toString('base64')}:${enc.toString('base64')}`;
};

export const open = (stored: string | null | undefined): string | null => {
  try {
    if (!stored || !stored.startsWith('v1:')) return null;
    const [, iv, tag, data] = stored.split(':');
    const d = crypto.createDecipheriv('aes-256-gcm', key(), Buffer.from(iv, 'base64'));
    d.setAuthTag(Buffer.from(tag, 'base64'));
    return Buffer.concat([d.update(Buffer.from(data, 'base64')), d.final()]).toString('utf8');
  } catch {
    return null;
  }
};

export const isSealed = (v: string | null | undefined): boolean => !!v && v.startsWith('v1:');
