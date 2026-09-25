import { KMSClient, ListKeysCommand, DescribeKeyCommand, ListAliasesCommand, GetKeyRotationStatusCommand } from '@aws-sdk/client-kms';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';

/**
 * Real AWS KMS key discovery (DEF-51, Phase 1).
 *
 * Keyless by design: the customer creates a cross-account, read-only IAM role
 * and shares its ARN (+ optional external id); we AssumeRole for short-lived
 * credentials. No long-lived customer secrets are stored. For local testing
 * against LocalStack, set endpointUrl (and static creds are used when no role
 * is supplied).
 *
 * Required IAM permissions on the role:
 *   kms:ListKeys, kms:DescribeKey, kms:ListAliases, kms:GetKeyRotationStatus
 */

export interface KmsConfig {
  roleArn?: string;
  externalId?: string;
  regions?: string[];
  region?: string;
  endpointUrl?: string;      // LocalStack / VPC endpoint override
  accessKeyId?: string;      // only for local testing without a role
  secretAccessKey?: string;
}

export interface DiscoveredAsset {
  name: string;
  type: string;       // asymmetric_key | symmetric_key
  algo: string;
  size: number;
  vuln: boolean;
  risk: string;       // critical | high | secure
  threat: string;
  rot: boolean;
  expiresAt: Date | null;
}

/** Map an AWS KMS KeySpec to algorithm metadata and quantum-vulnerability. */
const mapKeySpec = (keySpec: string): { type: string; algo: string; size: number; vuln: boolean; risk: string; threat: string } => {
  const s = keySpec || 'SYMMETRIC_DEFAULT';
  if (s.startsWith('RSA_')) {
    const size = parseInt(s.replace('RSA_', ''), 10) || 2048;
    return { type: 'asymmetric_key', algo: `RSA-${size}`, size, vuln: true,
      risk: size <= 2048 ? 'critical' : 'high',
      threat: "Shor's algorithm factors the RSA modulus on a CRQC; envelope/signature keys are forgeable." };
  }
  if (s.startsWith('ECC_')) {
    const size = s.includes('P256') || s.includes('P256K1') ? 256 : s.includes('P384') ? 384 : s.includes('P521') ? 521 : 256;
    return { type: 'asymmetric_key', algo: `ECDSA-P${size === 521 ? '521' : size}`, size, vuln: true, risk: 'critical',
      threat: "Elliptic-curve discrete log solved by Shor's algorithm; signatures/key-agreement compromised." };
  }
  if (s.startsWith('HMAC_')) {
    const size = parseInt(s.replace('HMAC_', ''), 10) || 256;
    return { type: 'symmetric_key', algo: `HMAC-${size}`, size, vuln: false, risk: 'secure',
      threat: 'Symmetric MAC; quantum-resistant (Grover only halves the security level).' };
  }
  if (s.startsWith('ML_DSA') || s.startsWith('ML_KEM')) {
    return { type: 'asymmetric_key', algo: s.replace(/_/g, '-'), size: 0, vuln: false, risk: 'secure',
      threat: 'NIST FIPS 203/204 post-quantum algorithm.' };
  }
  // SYMMETRIC_DEFAULT (AES-256-GCM)
  return { type: 'symmetric_key', algo: 'AES-256-GCM', size: 256, vuln: false, risk: 'secure',
    threat: 'AES-256 is quantum-resistant (128-bit effective strength under Grover).' };
};

const buildCredentials = async (cfg: KmsConfig, region: string) => {
  const endpoint = cfg.endpointUrl || undefined;
  if (cfg.roleArn) {
    const sts = new STSClient({ region, endpoint,
      credentials: cfg.accessKeyId ? { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey || '' } : undefined });
    const out = await sts.send(new AssumeRoleCommand({
      RoleArn: cfg.roleArn,
      RoleSessionName: 'quarkshield-cbom-discovery',
      ExternalId: cfg.externalId,
      DurationSeconds: 900,
    }));
    const c = out.Credentials!;
    return { accessKeyId: c.AccessKeyId!, secretAccessKey: c.SecretAccessKey!, sessionToken: c.SessionToken };
  }
  // Local testing (LocalStack) without a role: static creds if provided, else default chain.
  if (cfg.accessKeyId) return { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey || '' };
  return undefined; // default provider chain (env/instance)
};

const kmsClient = async (cfg: KmsConfig, region: string): Promise<KMSClient> => {
  const credentials = await buildCredentials(cfg, region);
  return new KMSClient({ region, endpoint: cfg.endpointUrl || undefined, credentials });
};

const regionsOf = (cfg: KmsConfig): string[] => {
  if (cfg.regions && cfg.regions.length) return cfg.regions;
  if (cfg.region) return [cfg.region];
  return ['us-east-1'];
};

/** Lightweight reachability + auth check for the Test button. */
export const pingKms = async (cfg: KmsConfig): Promise<{ ok: boolean; region: string; keyCount?: number; message: string }> => {
  const region = regionsOf(cfg)[0];
  const client = await kmsClient(cfg, region);
  const out = await client.send(new ListKeysCommand({ Limit: 1 }));
  return { ok: true, region, keyCount: out.Keys?.length ?? 0, message: `Authenticated to AWS KMS in ${region}.` };
};

/** Full discovery across all configured regions. */
export const discoverKmsKeys = async (cfg: KmsConfig): Promise<DiscoveredAsset[]> => {
  const assets: DiscoveredAsset[] = [];
  for (const region of regionsOf(cfg)) {
    const client = await kmsClient(cfg, region);

    // Alias map: KeyId -> friendly alias
    const aliasByKey: Record<string, string> = {};
    let aliasMarker: string | undefined;
    do {
      const al = await client.send(new ListAliasesCommand({ Marker: aliasMarker }));
      for (const a of al.Aliases || []) {
        if (a.TargetKeyId && a.AliasName) aliasByKey[a.TargetKeyId] = a.AliasName;
      }
      aliasMarker = al.Truncated ? al.NextMarker : undefined;
    } while (aliasMarker);

    let marker: string | undefined;
    do {
      const list = await client.send(new ListKeysCommand({ Limit: 100, Marker: marker }));
      for (const k of list.Keys || []) {
        if (!k.KeyId) continue;
        const desc = await client.send(new DescribeKeyCommand({ KeyId: k.KeyId }));
        const md = desc.KeyMetadata;
        if (!md) continue;
        // Skip AWS-managed keys (noise); only customer keys.
        if (md.KeyManager && md.KeyManager !== 'CUSTOMER') continue;

        const m = mapKeySpec(md.KeySpec || 'SYMMETRIC_DEFAULT');
        let rot = false;
        try {
          const rs = await client.send(new GetKeyRotationStatusCommand({ KeyId: k.KeyId }));
          rot = !!rs.KeyRotationEnabled;
        } catch { /* not supported for asymmetric/HMAC keys */ }

        assets.push({
          name: aliasByKey[md.KeyId!] || md.Arn || md.KeyId!,
          type: m.type,
          algo: m.algo,
          size: m.size,
          vuln: m.vuln,
          risk: md.Enabled === false || md.KeyState !== 'Enabled' ? 'low' : m.risk,
          threat: `[${region}] ${m.threat}`,
          rot,
          expiresAt: md.ValidTo || md.DeletionDate || null,
        });
      }
      marker = list.Truncated ? list.NextMarker : undefined;
    } while (marker);
  }
  return assets;
};
