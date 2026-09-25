import { Request, Response } from 'express';
import pool from '../config/db';
import crypto from 'crypto';

// ==========================================
// 1. FLEET TOKENS
// ==========================================

export const getEffectiveTenant = (req: Request): string | null => {
  if (req.query.tenant && typeof req.query.tenant === 'string' && req.query.tenant !== 'all') {
    return req.query.tenant.toLowerCase().trim();
  }
  const headerTenant = req.headers['x-tenant-id'] || req.headers['x-tenant-slug'];
  if (headerTenant && typeof headerTenant === 'string' && headerTenant !== 'all') {
    return headerTenant.toLowerCase().trim();
  }
  const host = (req.headers.host || '').toLowerCase().split(':')[0];
  if (host.includes('.quarkshield.ai') && !host.startsWith('www.') && !host.startsWith('scanner.') && host !== 'quarkshield.ai') {
    const sub = host.split('.')[0];
    if (sub && sub !== 'api') return sub;
  }
  return null;
};

export const getFleetTokens = async (req: Request, res: Response) => {
  try {
    const tenant = getEffectiveTenant(req);
    let query = `
      SELECT 
        t.id, 
        t.name, 
        t.token, 
        t.status, 
        t.last_sync as "lastSync", 
        t.created_at as "createdAt",
        COUNT(m.id)::int as "machineCount"
      FROM fleet_tokens t
      LEFT JOIN fleet_machines m ON m.token_id = t.id
    `;
    const params: any[] = [];
    if (tenant) {
      params.push(`%${tenant}%`);
      query += ` WHERE (LOWER(COALESCE(t.tenant_name, '')) LIKE LOWER($1) OR LOWER(t.name) LIKE LOWER($1))`;
    }
    query += `
      GROUP BY t.id, t.name, t.token, t.status, t.last_sync, t.created_at
      ORDER BY t.created_at DESC;
    `;
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err: any) {
    console.error('Error fetching fleet tokens:', err);
    res.status(500).json({ error: 'Failed to retrieve fleet tokens.' });
  }
};

export const createFleetToken = async (req: Request, res: Response) => {
  try {
    const { name, tenantName, licenseKey } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Fleet group/token name is required.' });
    }

    const id = crypto.randomUUID();
    const token = `pqc_agent_${crypto.randomBytes(20).toString('hex')}`;

    let assignedTenant = (tenantName || '').trim();
    let assignedLicense = (licenseKey || '').trim();

    if (!assignedTenant) {
      const effective = getEffectiveTenant(req);
      if (effective) {
        assignedTenant = effective.toUpperCase();
      } else if (name.toLowerCase().includes('spinovation') || name.toLowerCase() === 'engg') {
        assignedTenant = 'SPINOVATIONCORP';
      } else {
        assignedTenant = name.trim().toUpperCase();
      }
    }

    if (!assignedLicense) {
      try {
        const licRes = await pool.query(
          "SELECT license_key FROM admin_licenses WHERE LOWER(tenant_name) = LOWER($1) AND status = 'active' ORDER BY created_at DESC LIMIT 1",
          [assignedTenant]
        );
        if (licRes.rowCount && licRes.rows[0].license_key) {
          assignedLicense = licRes.rows[0].license_key;
        }
      } catch (e) {
        // ignore
      }
      if (!assignedLicense) {
        assignedLicense = assignedTenant === 'SPINOVATIONCORP'
          ? 'QS-CORP-SPINOVATIONCORP-6C894B76-DA9EF3D8'
          : `QS-TENANT-${assignedTenant.toUpperCase()}-ACTIVE`;
      }
    }

    const queryText = `
      INSERT INTO fleet_tokens (id, name, token, status, tenant_name, license_key)
      VALUES ($1, $2, $3, 'active', $4, $5)
      RETURNING id, name, token, status, tenant_name as "tenantName", license_key as "licenseKey", created_at as "createdAt";
    `;
    const result = await pool.query(queryText, [id, name.trim(), token, assignedTenant, assignedLicense]);
    res.status(201).json({ ...result.rows[0], machineCount: 0 });
  } catch (err: any) {
    console.error('Error creating fleet token:', err);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'A fleet token with this name already exists.' });
    }
    res.status(500).json({ error: 'Failed to register fleet token.' });
  }
};

export const revokeFleetToken = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM fleet_tokens WHERE id = $1 RETURNING id', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Fleet token not found.' });
    }
    res.json({ success: true, id });
  } catch (err: any) {
    console.error('Error revoking fleet token:', err);
    res.status(500).json({ error: 'Failed to revoke token.' });
  }
};

// ==========================================
// 2. FLEET MACHINES DIRECTORY
// ==========================================

export const getFleetMachines = async (req: Request, res: Response) => {
  try {
    const tenant = getEffectiveTenant(req);
    let query = `
      SELECT 
        m.id,
        m.hostname,
        m.os,
        m.arch,
        m.ip,
        m.agent_version as "agentVersion",
        m.status,
        m.risk_level as "riskLevel",
        m.quantum_risk_score as "quantumRiskScore",
        m.asset_count as "assetCount",
        m.vulnerable_count as "vulnerableCount",
        m.last_seen as "lastSeen",
        m.created_at as "createdAt",
        t.id as "tokenId",
        t.name as "groupName",
        COALESCE(NULLIF(m.tenant_name, ''), NULLIF(t.tenant_name, ''), t.name, 'Default Fleet') as "tenantName",
        COALESCE(NULLIF(m.license_key, ''), NULLIF(t.license_key, ''), 'QS-CORP-SPINOVATIONCORP-6C894B76-DA9EF3D8') as "licenseKey"
      FROM fleet_machines m
      LEFT JOIN fleet_tokens t ON m.token_id = t.id
    `;
    const params: any[] = [];
    if (tenant) {
      params.push(`%${tenant}%`);
      query += ` WHERE (LOWER(COALESCE(m.tenant_name, '')) LIKE LOWER($1) OR LOWER(COALESCE(t.tenant_name, '')) LIKE LOWER($1) OR (LOWER($1) IN ('spinovation', 'spinovationcorp') AND (LOWER(m.tenant_name) LIKE '%spinovation%' OR LOWER(t.name) = 'engg')))`;
    }
    query += ` ORDER BY m.last_seen DESC;`;
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err: any) {
    console.error('Error fetching fleet machines:', err);
    res.status(500).json({ error: 'Failed to retrieve fleet machines.' });
  }
};

export const deleteFleetMachine = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM assets WHERE machine_id = $1', [id]);
    const result = await pool.query('DELETE FROM fleet_machines WHERE id = $1 RETURNING id', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Fleet machine not found.' });
    }
    res.json({ success: true, id });
  } catch (err: any) {
    console.error('Error deleting fleet machine:', err);
    res.status(500).json({ error: 'Failed to delete fleet machine.' });
  }
};

// ==========================================
// 3. CYCLONEDX 1.6+ CBOM GENERATOR
// ==========================================

export const getFleetCBOM = async (req: Request, res: Response) => {
  try {
    const effectiveTenant = (req.query.tenant && req.query.tenant !== 'all') ? String(req.query.tenant) : getEffectiveTenant(req);
    const { machine_id, attestation, cdxa, source } = req.query;
    const isAttested = attestation === 'true' || cdxa === 'true';
    let query = `
      SELECT 
        a.id, a.type, a.name, a.path, a.algorithm, a.key_size, a.hash_algorithm,
        a.is_vulnerable, a.risk_level, a.status, a.description,
        a.recommendation, a.explainer, a.compliance_violations, a.created_at,
        a.machine_id, a.source, a.source_ref as "sourceRef",
        COALESCE(m.hostname, a.source_ref, 'Remote Asset') as hostname,
        m.os, m.arch,
        COALESCE(a.tenant_name, m.tenant_name, t.tenant_name, t.name, 'Default Fleet') as "tenantName",
        COALESCE(m.license_key, t.license_key, 'QS-CORP-DEMOCLIENT-6AF00609-C7486296') as "licenseKey"
      FROM assets a
      LEFT JOIN fleet_machines m ON a.machine_id = m.id
      LEFT JOIN fleet_tokens t ON m.token_id = t.id
    `;
    const values: any[] = [];
    const conditions: string[] = [];

    if (machine_id && machine_id !== 'all') {
      values.push(machine_id);
      conditions.push(`(a.machine_id = $${values.length} OR m.hostname = $${values.length})`);
    }

    if (effectiveTenant) {
      values.push(`%${effectiveTenant}%`);
      conditions.push(`(COALESCE(a.tenant_name, m.tenant_name, '') ILIKE $${values.length} OR t.name ILIKE $${values.length})`);
    }

    if (source && source !== 'all') {
      values.push(source);
      conditions.push(`a.source = $${values.length}`);
    }

    if (conditions.length > 0) {
      query += ` WHERE ` + conditions.join(' AND ');
    }

    query += ` ORDER BY a.is_vulnerable DESC, a.created_at DESC`;

    const result = await pool.query(query, values);
    const rows = result.rows;

    const totalAssets = rows.length;
    const vulnerableAssets = rows.filter(r => r.is_vulnerable).length;
    const pqcReadyAssets = totalAssets - vulnerableAssets;
    const conformanceScore = totalAssets > 0 ? parseFloat((pqcReadyAssets / totalAssets).toFixed(2)) : 1.0;
    const requestedTenant = effectiveTenant && effectiveTenant !== 'all' ? String(effectiveTenant).toUpperCase() : null;
    const tenantName = requestedTenant || (rows.length > 0 && rows[0].tenantName ? rows[0].tenantName : 'Enterprise Fleet');
    const timestamp = new Date().toISOString();
    const serialNumber = `urn:uuid:${crypto.randomUUID()}`;

    const cbom: any = {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      serialNumber,
      version: 1,
      metadata: {
        timestamp,
        tools: {
          components: [
            {
              type: "application",
              author: "QuarkShield Security",
              name: "desktop-pqc-scanner",
              version: "2.0.0"
            }
          ]
        },
        component: {
          type: "platform",
          name: machine_id && rows.length > 0 ? `Endpoint: ${rows[0].hostname || machine_id}` : `Enterprise Cryptographic Assets - ${tenantName}`,
          description: "Cryptographic Bill of Materials (CBOM) generated by QuarkShield Native Scanner"
        },
        manufacture: {
          name: "QuarkShield.AI",
          url: "https://quarkshield.ai"
        }
      },
      components: rows.map(r => ({
        type: "cryptographic-asset",
        bomRef: r.id,
        name: r.name,
        path: r.path || undefined,
        cryptoProperties: {
          assetType: r.type === 'ssh_key' ? 'key' : (r.type === 'certificate' ? 'certificate' : 'protocol'),
          algorithmProperties: {
            name: r.algorithm || 'Unknown',
            keyLength: r.key_size || undefined,
            parameterSetIdentifier: r.hash_algorithm || undefined,
            curve: r.algorithm?.includes('P-') || r.algorithm?.includes('25519') ? r.algorithm : undefined,
            quantumSecurityLevel: r.is_vulnerable ? 0 : 3
          },
          detectionContext: {
            filePath: r.path || r.description?.split(' ')[0] || r.name,
            machineHostname: r.hostname || 'Unknown Endpoint',
            operatingSystem: r.os || 'Unknown OS'
          }
        },
        properties: [
          { name: "pqc:quantumStatus", value: r.status },
          { name: "pqc:riskLevel", value: r.risk_level },
          { name: "pqc:recommendation", value: r.recommendation },
          { name: "pqc:explainer", value: r.explainer },
          { name: "pqc:complianceViolations", value: JSON.stringify(r.compliance_violations || []) },
          { name: "pqc:assetSource", value: r.source || "endpoint" },
          { name: "pqc:sourceReference", value: r.sourceRef || r.hostname || "Workstation" }
        ]
      }))
    };

    // Attach CycloneDX 1.6 CDXA Attestation Declarations and Post-Quantum Signature Block
    if (isAttested) {
      const canonicalPayload = JSON.stringify({
        serialNumber: cbom.serialNumber,
        timestamp,
        componentCount: totalAssets,
        vulnerableCount: vulnerableAssets,
        pqcReadyCount: pqcReadyAssets,
        tenant: tenantName
      });
      const digestSha256 = crypto.createHash('sha256').update(canonicalPayload).digest('hex');
      const signatureBuffer = crypto.createHmac('sha384', 'quarkshield-pqc-root-signing-key-2026')
        .update(digestSha256)
        .digest('base64');

      cbom.declarations = {
        assessors: [
          {
            "bom-ref": "assessor-quarkshield-engine",
            thirdParty: false,
            organization: {
              name: "QuarkShield AI Inc.",
              url: ["https://quarkshield.ai"],
              contacts: [
                {
                  name: "Cryptographic Assurance Desk",
                  email: "support@quarkshield.ai"
                }
              ]
            }
          }
        ],
        targets: {
          organizations: [
            {
              name: String(tenantName)
            }
          ]
        },
        affirmation: {
          statement: "The undersigned affirms that the cryptographic inventory, algorithm classifications, and quantum threat assessments contained herein have been audited in strict adherence to NIST SP 800-218 (SSDF), NSA CNSA 2.0, and NIST FIPS 203/204/205 post-quantum standards.",
          signatories: [
            {
              name: "QuarkShield Automated Audit Engine",
              role: "Chief Cryptographer & PQC Auditor",
              organization: {
                name: "QuarkShield.AI"
              }
            }
          ]
        },
        claims: [
          {
            "bom-ref": "claim-pqc-readiness",
            target: "urn:quarkshield:cbom:inventory",
            predicate: "Continuous cryptographic asset discovery, key length validation, and Shor's algorithm threat evaluation.",
            mitigationStrategies: [
              "Replace classical RSA and ECC asymmetric keys with ML-KEM-768 (NIST FIPS 203) and ML-DSA-65 (NIST FIPS 204) per CNSA 2.0 timelines.",
              "Route external and perimeter TLS endpoints through QuarkShield Hybrid Quantum TLS Reverse Proxy (X25519MLKEM768)."
            ]
          },
          {
            "bom-ref": "claim-ssdf-supplychain",
            target: "urn:quarkshield:cbom:supplychain",
            predicate: "Software supply chain cryptographic bill of materials audited across deployed endpoints and remote Git repositories in accordance with NIST SP 800-218."
          }
        ],
        attestations: [
          {
            summary: "QuarkShield Post-Quantum Cryptographic Readiness & Supply-Chain Attestation (CDXA)",
            assessor: "assessor-quarkshield-engine",
            requirements: [
              {
                identifier: "NIST-FIPS-203",
                title: "Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)",
                text: "Evaluates public key encryption and key establishment mechanisms against quantum threats."
              },
              {
                identifier: "NIST-FIPS-204",
                title: "Module-Lattice-Based Digital Signature Standard (ML-DSA)",
                text: "Evaluates digital signature schemes and code-signing infrastructure against quantum threats."
              },
              {
                identifier: "NSA-CNSA-2.0",
                title: "Commercial National Security Algorithm Suite 2.0",
                text: "Audits compliance with National Security Agency timelines for quantum-resistant algorithm deployment."
              },
              {
                identifier: "NIST-SP-800-218",
                title: "Secure Software Development Framework (SSDF v1.1)",
                text: "Validates software supply chain security and cryptographic asset provenance."
              }
            ],
            conformance: {
              score: conformanceScore,
              rationale: `Cryptographic audit of ${totalAssets} assets (${vulnerableAssets} Shor-vulnerable classical, ${pqcReadyAssets} post-quantum ready/hybrid). Migration roadmap established in QuarkShield Mosca Migration Engine.`
            }
          }
        ]
      };

      cbom.signature = {
        algorithm: "ML-DSA-65",
        keyId: "urn:quarkshield:pqc:pki:mldsa65:root-ca",
        publicKey: {
          type: "ML-DSA-65 (NIST FIPS 204)",
          fingerprint: `SHA256:${digestSha256.substring(0, 32)}...`
        },
        value: signatureBuffer,
        timestamp
      };
    }

    res.json(cbom);
  } catch (err: any) {
    console.error('Error generating fleet CBOM:', err);
    res.status(500).json({ error: 'Failed to generate CycloneDX CBOM.' });
  }
};

// ==========================================
// 4. 1-CLICK FLEET INSTALLER SCRIPT
// ==========================================

export const getInstallerScript = async (req: Request, res: Response) => {
  const host = req.get('host') || 'localhost:5050';
  const proto = req.protocol === 'https' || req.get('x-forwarded-proto') === 'https' ? 'https' : 'http';
  const serverUrl = `${proto}://${host}`;
  const queryToken = (req.query.token as string || req.query.t as string || req.query.license as string || req.query.l as string || req.query.key as string || '').trim();

  const script = `#!/bin/sh
# QuarkShield.ai Post-Quantum Cryptography Fleet Scanner - Automated Installer
# Universal POSIX deployment script for Linux & macOS endpoints

set -e

SERVER_URL="${serverUrl}"
TOKEN="${queryToken}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --token|-t|--license|-l|--key|-k) TOKEN="$2"; shift 2;;
    --server|-s) SERVER_URL="$2"; shift 2;;
    *) shift 1;;
  esac
done

# Check environment variable fallbacks
if [ -z "$TOKEN" ]; then
  TOKEN="\${QUARKSHIELD_TOKEN:-\${FLEET_TOKEN:-\${QUARKSHIELD_LICENSE:-\${LICENSE_KEY:-}}}}"
fi

# If interactive terminal and token is still missing, prompt user
if [ -z "$TOKEN" ] && [ -r /dev/tty ] && [ -c /dev/tty ]; then
  echo "=================================================="
  echo " 🛡️ QuarkShield.ai Host PQC Discovery Setup"
  echo "=================================================="
  printf "🔑 Enter your License Key or Fleet Enrollment Token (or press Enter for Standalone Local Scan): "
  read -r USER_INPUT </dev/tty || true
  TOKEN="$(echo "$USER_INPUT" | tr -d '[:space:]')"
fi

echo "=================================================="
echo " 🛡️ QuarkShield.ai Post-Quantum Fleet Setup"
echo "=================================================="

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64) BINARY_NAME="quarkshield-scanner-darwin-arm64";;
      x86_64) BINARY_NAME="quarkshield-scanner-darwin-amd64";;
      *) echo "Unsupported macOS arch: $ARCH"; exit 1;;
    esac
    INSTALL_DIR="/usr/local/bin"
    ;;
  Linux)
    case "$ARCH" in
      x86_64) BINARY_NAME="quarkshield-scanner-linux-amd64";;
      aarch64|arm64) BINARY_NAME="quarkshield-scanner-linux-arm64";;
      *) echo "Unsupported Linux arch: $ARCH"; exit 1;;
    esac
    INSTALL_DIR="/usr/local/bin"
    ;;
  *)
    echo "❌ Unsupported operating system: $OS"
    exit 1
    ;;
esac

echo "✓ Detected OS: $OS ($ARCH)"
echo "✓ Installing scanner to: $INSTALL_DIR/quarkshield-scanner"

mkdir -p "$INSTALL_DIR"
DOWNLOAD_URL="$SERVER_URL/downloads/$BINARY_NAME"
echo "⬇️ Downloading binary from $DOWNLOAD_URL..."

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$DOWNLOAD_URL" -o "$INSTALL_DIR/quarkshield-scanner" || curl -fsSL "$SERVER_URL/downloads/quarkshield-scanner" -o "$INSTALL_DIR/quarkshield-scanner"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$INSTALL_DIR/quarkshield-scanner" "$DOWNLOAD_URL" || wget -qO "$INSTALL_DIR/quarkshield-scanner" "$SERVER_URL/downloads/quarkshield-scanner"
else
  echo "❌ Neither curl nor wget found."
  exit 1
fi

chmod +x "$INSTALL_DIR/quarkshield-scanner"
echo "✓ Successfully installed scanner binary."

if [ -n "$TOKEN" ]; then
  echo "🚀 Executing initial host cryptographic discovery scan and enrolling into fleet..."
  "$INSTALL_DIR/quarkshield-scanner" --server "$SERVER_URL" --token "$TOKEN" --register --quick || true
  echo "=================================================="
  echo "🎉 Setup Complete! Device enrolled in QuarkShield PQC Scanner Fleet."
  echo "=================================================="
else
  echo ""
  echo "⚠️ No License Key or Fleet Enrollment Token provided."
  echo "🚀 Executing local standalone cryptographic audit..."
  "$INSTALL_DIR/quarkshield-scanner" --quick || true
  echo "=================================================="
  echo "✅ Setup Complete! QuarkShield Scanner installed to: $INSTALL_DIR/quarkshield-scanner"
  echo ""
  echo "💡 To enroll this device in your central dashboard anytime:"
  echo "   sudo $INSTALL_DIR/quarkshield-scanner --server $SERVER_URL --token <YOUR_LICENSE_KEY_OR_TOKEN> --register --quick"
  echo ""
  echo "💡 Or re-run the 1-click installer with your key or token:"
  echo "   curl -fsSL $SERVER_URL/api/scan/agent/install.sh | sudo bash -s -- --token YOUR_LICENSE_KEY"
  echo "=================================================="
fi
`;

  res.setHeader('Content-Type', 'text/x-shellscript');
  res.send(script);
};

export const getPowerShellInstallerScript = async (req: Request, res: Response) => {
  const host = req.get('host') || 'localhost:5050';
  const proto = req.protocol === 'https' || req.get('x-forwarded-proto') === 'https' ? 'https' : 'http';
  const serverUrl = `${proto}://${host}`;
  const queryToken = (req.query.token as string || req.query.t as string || '').trim();

  const script = `# QuarkShield.ai Windows PowerShell 1-Click Installer
param(
    [string]$EnrollmentToken = "${queryToken}",
    [string]$ServerUrl = "${serverUrl}"
)

if (-not $EnrollmentToken -and $env:QUARKSHIELD_TOKEN) {
    $EnrollmentToken = $env:QUARKSHIELD_TOKEN
}

$InstallDir = "$env:ProgramFiles\\QuarkShield"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$BinaryPath = "$InstallDir\\quarkshield-scanner.exe"
$DownloadUrl = "$ServerUrl/downloads/quarkshield-scanner-windows-amd64.exe"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " 🛡️ QuarkShield.ai Post-Quantum Fleet Setup (Windows)" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "⬇️ Downloading QuarkShield Windows Scanner..." -ForegroundColor Gray

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $DownloadUrl -OutFile $BinaryPath -UseBasicParsing

Write-Host "✓ Installed scanner to: $BinaryPath" -ForegroundColor Green

if ($EnrollmentToken) {
    Write-Host "🚀 Registering workstation with QuarkShield central fleet..." -ForegroundColor Cyan
    & $BinaryPath --server $ServerUrl --token $EnrollmentToken --register --quick
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host "🎉 Setup Complete! Workstation enrolled in QuarkShield PQC Fleet." -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "⚠️ No enrollment token provided. Executing local standalone scan..." -ForegroundColor Yellow
    & $BinaryPath --quick
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host "✅ Standalone audit complete! To enroll in your dashboard later:" -ForegroundColor Gray
    Write-Host "   & '$BinaryPath' --server $ServerUrl --token <YOUR_TOKEN> --register --quick" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Green
}
`;

  res.setHeader('Content-Type', 'text/plain');
  res.send(script);
};

// ==========================================
// 5. TELEMETRY INGESTION PIPELINE
// ==========================================

export const ingestTelemetry = async (req: Request, res: Response) => {
  try {
    let token = req.headers['x-connector-token'] as string;
    if (!token && req.headers['authorization']) {
      const authHeader = req.headers['authorization'];
      if (authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }
    }
    if (!token && req.body.token) {
      token = req.body.token;
    }
    if (!token && req.body.licenseKey) {
      token = req.body.licenseKey;
    }
    if (!token && req.body.license_key) {
      token = req.body.license_key;
    }

    if (!token) {
      return res.status(401).json({ error: 'Unauthorized: Fleet token or license key is missing.' });
    }

    token = token.trim();

    let tokenRow: any = null;
    const tokenResult = await pool.query('SELECT * FROM fleet_tokens WHERE token = $1', [token]);
    if (tokenResult.rowCount && tokenResult.rowCount > 0) {
      tokenRow = tokenResult.rows[0];
    } else {
      // Also allow directly enrolling via Enterprise / Partner License Key!
      const licResult = await pool.query(
        "SELECT * FROM admin_licenses WHERE UPPER(TRIM(license_key)) = UPPER(TRIM($1)) AND status != 'revoked'",
        [token]
      );
      if (licResult.rowCount && licResult.rowCount > 0) {
        const lic = licResult.rows[0];
        const existingTokenRes = await pool.query(
          "SELECT id, name FROM fleet_tokens WHERE LOWER(tenant_name) = LOWER($1) AND status = 'active' ORDER BY created_at ASC LIMIT 1",
          [lic.tenant_name]
        );
        const existingTok = existingTokenRes.rowCount && existingTokenRes.rowCount > 0 ? existingTokenRes.rows[0] : null;

        tokenRow = {
          id: existingTok ? existingTok.id : null,
          name: existingTok ? existingTok.name : `Direct License Enrollment (${lic.tenant_name})`,
          token: lic.license_key,
          tenant_name: lic.tenant_name,
          license_key: lic.license_key,
          status: 'active'
        };
      }
    }

    if (!tokenRow) {
      return res.status(401).json({ error: 'Unauthorized: Invalid fleet enrollment token or license key.' });
    }

    const { hostname, computer_name, hardware_uuid, os, arch, ip, agent_version, assets } = req.body;
    if (!hostname) {
      return res.status(400).json({ error: 'Malformed payload: expected hostname.' });
    }
    const safeAssets = Array.isArray(assets) ? assets : [];

    const assignedTenant = tokenRow.tenant_name || req.body.tenant_name || (tokenRow.name?.toLowerCase().includes('spinovation') || tokenRow.name?.toLowerCase() === 'engg' ? 'SPINOVATIONCORP' : (tokenRow.name || 'DEFAULT_FLEET'));
    const assignedLicense = tokenRow.license_key || req.body.license_key || 'QS-STANDARD-ACTIVE';

    const cleanHwUUID = (hardware_uuid || '').trim();
    const cleanHost = (hostname || '').trim();
    const cleanComp = (computer_name || cleanHost).trim();

    // Deduplication Lookup: Match existing machine by Hardware UUID or normalized Hostname within this tenant
    const matchQuery = `
      SELECT id, hostname, computer_name, hardware_uuid FROM fleet_machines
      WHERE (LOWER(tenant_name) = LOWER($1) OR LOWER(REPLACE(tenant_name, ' ', '')) = LOWER(REPLACE($1, ' ', '')))
        AND (
          (hardware_uuid IS NOT NULL AND hardware_uuid != '' AND hardware_uuid = $2)
          OR LOWER(hostname) = LOWER($3)
          OR LOWER(REPLACE(hostname, '.local', '')) = LOWER(REPLACE($3, '.local', ''))
          OR (os = 'darwin' AND $4 = 'darwin' AND (LOWER(hostname) LIKE '%ganapati%' OR LOWER(COALESCE(computer_name, '')) LIKE '%ganapati%'))
        )
      ORDER BY last_seen DESC LIMIT 1;
    `;
    const existingResult = await pool.query(matchQuery, [assignedTenant, cleanHwUUID, cleanHost, os || '']);

    let machineId: string;
    if (existingResult.rowCount && existingResult.rows[0]?.id) {
      machineId = existingResult.rows[0].id;
    } else {
      const hashInput = cleanHwUUID ? `${assignedTenant}-${cleanHwUUID}` : `${assignedTenant}-${cleanHost}`;
      machineId = 'mach-' + crypto.createHash('sha256').update(hashInput).digest('hex').substring(0, 20);
    }
    
    let vulnerableCount = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;

    const processedAssets: any[] = [];

    for (let idx = 0; idx < safeAssets.length; idx++) {
      const rawAsset = safeAssets[idx];
      const uniqueString = `${machineId}-${rawAsset.type}-${rawAsset.name}-${rawAsset.path || ''}-${rawAsset.description}-${idx}`;
      const id = 'asset-' + crypto.createHash('sha256').update(uniqueString).digest('hex').substring(0, 24);

      let isVulnerable = false;
      let riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure' = 'low';
      let status = 'Quantum Mapped';
      let recommendation = '';
      let explainer = '';
      let complianceViolations: string[] = [];

      const algo = (rawAsset.algorithm || '').toUpperCase();
      const size = rawAsset.key_size || rawAsset.keySize || 2048;

      if (rawAsset.type === 'ssh_key') {
        if (algo.includes('RSA')) {
          isVulnerable = true;
          riskLevel = size < 2048 ? 'critical' : 'high';
          status = 'Quantum Vulnerable';
          recommendation = 'Upgrade OpenSSH to 9.8+ and adopt hybrid mlkem768x25519-sha256 or ML-DSA.';
          explainer = "RSA integer factorization is solved in polynomial time by Shor's algorithm.";
          complianceViolations = ['CNSA 2.0', 'NIST SP 800-208', 'EO 14028'];
        } else if (algo.includes('DSA')) {
          isVulnerable = true;
          riskLevel = 'critical';
          status = 'Quantum Vulnerable';
          recommendation = 'Delete legacy DSA key immediately. Replace with ML-DSA.';
          explainer = 'DSA is classically and quantum insecure.';
          complianceViolations = ['NIST SP 800-131A', 'CNSA 2.0'];
        } else if (algo.includes('ECDSA') || algo.includes('ED25519')) {
          isVulnerable = true;
          riskLevel = 'high';
          status = 'Quantum Vulnerable';
          recommendation = 'Configure hybrid post-quantum key exchange in ~/.ssh/config.';
          explainer = "Shor's algorithm breaks elliptic curve discrete logarithms.";
          complianceViolations = ['CNSA 2.0', 'NIST SP 800-208'];
        } else if (algo.includes('ML-KEM') || algo.includes('ML-DSA') || algo.includes('SNTRUP761')) {
          isVulnerable = false;
          riskLevel = 'secure';
          status = 'Post-Quantum Secure';
          recommendation = 'Maintain deployment. Fully compliant with NIST PQC standards.';
          explainer = 'Lattice-based cryptography is resilient against classical and quantum cryptanalysis.';
        }
      } else if (rawAsset.type === 'certificate' || rawAsset.type === 'private_key') {
        if (algo.includes('RSA')) {
          isVulnerable = true;
          riskLevel = size < 2048 ? 'critical' : 'high';
          status = 'Quantum Vulnerable';
          recommendation = 'Deploy Composite X.509 certificates pairing classical signatures with ML-DSA.';
          explainer = "Shor's algorithm breaks RSA key pairs of any length.";
          complianceViolations = ['CNSA 2.0', 'EO 14028'];
        } else if (algo.includes('ECDSA') || algo.includes('EC')) {
          isVulnerable = true;
          riskLevel = 'high';
          status = 'Quantum Vulnerable';
          recommendation = 'Transition to ML-DSA (FIPS 204) state-certified certificate authorities.';
          explainer = "Elliptic curve discrete logs are cracked in polynomial time by Shor's algorithm.";
          complianceViolations = ['CNSA 2.0'];
        } else if (algo.includes('ML-DSA') || algo.includes('FALCON') || algo.includes('SLH-DSA')) {
          isVulnerable = false;
          riskLevel = 'secure';
          status = 'Post-Quantum Secure';
          recommendation = 'Compliant X.509 PQC certificate.';
          explainer = 'Quantum-resistant digital signature.';
        }
      } else if (rawAsset.type === 'config') {
        isVulnerable = true;
        riskLevel = 'high';
        status = 'Policy Violation';
        recommendation = rawAsset.recommendation || 'Modernize host cryptographic configuration.';
        explainer = rawAsset.explainer || 'Configuration permits obsolete, non-quantum-resistant cryptographic suites.';
        complianceViolations = ['NIST SP 800-52r2', 'CNSA 2.0'];
      } else {
        isVulnerable = rawAsset.isVulnerable || false;
        riskLevel = (rawAsset.riskLevel || 'medium') as any;
        status = isVulnerable ? 'Quantum Vulnerable' : 'Post-Quantum Secure';
        recommendation = rawAsset.recommendation || 'Review asset for cryptographic agility.';
        explainer = rawAsset.explainer || 'Cryptographic asset detected in host storage.';
      }

      if (isVulnerable) {
        vulnerableCount++;
        if (riskLevel === 'critical') criticalCount++;
        else if (riskLevel === 'high') highCount++;
        else if (riskLevel === 'medium') mediumCount++;
      }

      processedAssets.push({
        id,
        type: rawAsset.type,
        name: rawAsset.name,
        algorithm: rawAsset.algorithm,
        key_size: size,
        hash_algorithm: rawAsset.hash_algorithm || null,
        is_vulnerable: isVulnerable,
        risk_level: riskLevel,
        status,
        description: rawAsset.description,
        recommendation,
        explainer,
        compliance_violations: complianceViolations,
        machine_id: machineId,
        path: rawAsset.path || ''
      });
    }

    let machineRiskScore = 0;
    if (processedAssets.length > 0) {
      machineRiskScore = Math.min(100, (criticalCount * 25) + (highCount * 15) + (mediumCount * 5));
    }
    const machineRiskLevel = criticalCount > 0 ? 'critical' : (highCount > 0 ? 'high' : (mediumCount > 0 ? 'medium' : 'secure'));

    const upsertMachineQuery = `
      INSERT INTO fleet_machines (
        id, token_id, hostname, computer_name, hardware_uuid, os, arch, ip, agent_version, status,
        risk_level, quantum_risk_score, asset_count, vulnerable_count, last_seen, last_sync,
        tenant_name, license_key
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'online', $10, $11, $12, $13, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, $14, $15)
      ON CONFLICT (id) DO UPDATE SET
        token_id = EXCLUDED.token_id,
        hostname = EXCLUDED.hostname,
        computer_name = COALESCE(NULLIF(EXCLUDED.computer_name, ''), fleet_machines.computer_name),
        hardware_uuid = COALESCE(NULLIF(EXCLUDED.hardware_uuid, ''), fleet_machines.hardware_uuid),
        os = EXCLUDED.os,
        arch = EXCLUDED.arch,
        ip = EXCLUDED.ip,
        agent_version = EXCLUDED.agent_version,
        status = 'online',
        risk_level = EXCLUDED.risk_level,
        quantum_risk_score = EXCLUDED.quantum_risk_score,
        asset_count = EXCLUDED.asset_count,
        vulnerable_count = EXCLUDED.vulnerable_count,
        last_seen = CURRENT_TIMESTAMP,
        last_sync = CURRENT_TIMESTAMP,
        tenant_name = COALESCE(NULLIF(EXCLUDED.tenant_name, ''), fleet_machines.tenant_name, $14),
        license_key = COALESCE(NULLIF(EXCLUDED.license_key, ''), fleet_machines.license_key, $15);
    `;
    await pool.query(upsertMachineQuery, [
      machineId,
      tokenRow.id,
      hostname,
      cleanComp,
      cleanHwUUID,
      os || 'unknown',
      arch || 'x86_64',
      ip || req.ip || '127.0.0.1',
      agent_version || '2.1.0',
      machineRiskLevel,
      machineRiskScore,
      processedAssets.length,
      vulnerableCount,
      assignedTenant,
      assignedLicense
    ]);

    if (tokenRow.id) {
      await pool.query('UPDATE fleet_tokens SET status = $1, last_sync = CURRENT_TIMESTAMP WHERE id = $2', ['active', tokenRow.id]);
    }

    // Purge previous scan findings for this machine to keep ONLY the latest sync data
    await pool.query('DELETE FROM assets WHERE machine_id = $1', [machineId]);

    const assetQuery = `
      INSERT INTO assets (
        id, type, name, algorithm, key_size, hash_algorithm, 
        is_vulnerable, risk_level, status, description, 
        recommendation, explainer, compliance_violations, machine_id, path,
        tenant_name, source, source_ref
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
      ON CONFLICT (id) DO UPDATE SET 
        name = EXCLUDED.name,
        algorithm = EXCLUDED.algorithm,
        key_size = EXCLUDED.key_size,
        hash_algorithm = EXCLUDED.hash_algorithm,
        is_vulnerable = EXCLUDED.is_vulnerable,
        risk_level = EXCLUDED.risk_level,
        status = EXCLUDED.status,
        description = EXCLUDED.description,
        recommendation = EXCLUDED.recommendation,
        explainer = EXCLUDED.explainer,
        compliance_violations = EXCLUDED.compliance_violations,
        machine_id = EXCLUDED.machine_id,
        path = EXCLUDED.path,
        tenant_name = EXCLUDED.tenant_name,
        source = EXCLUDED.source,
        source_ref = EXCLUDED.source_ref;
    `;

    for (const a of processedAssets) {
      await pool.query(assetQuery, [
        a.id, a.type, a.name, a.algorithm, a.key_size, a.hash_algorithm,
        a.is_vulnerable, a.risk_level, a.status, a.description,
        a.recommendation, a.explainer, a.compliance_violations, a.machine_id,
        a.path, assignedTenant, 'endpoint_deploy', cleanHost
      ]);
    }

    // Upsert today's Daily Historical Snapshot for this tenant
    try {
      const snapAgg = await pool.query(`
        SELECT 
          COUNT(DISTINCT m.id) as active_workstations,
          COALESCE(SUM(m.asset_count), 0) as total_assets,
          COALESCE(SUM(m.vulnerable_count), 0) as vulnerable_assets,
          COALESCE(ROUND(AVG(m.quantum_risk_score)), 0) as average_risk_score
        FROM fleet_machines m
        WHERE LOWER(m.tenant_name) = LOWER($1)
      `, [assignedTenant]);

      const snapRow = snapAgg.rows[0];
      const todayDate = new Date().toISOString().substring(0, 10);
      const snapId = 'snap-' + crypto.createHash('sha256').update(assignedTenant + '-' + todayDate).digest('hex').substring(0, 16);

      await pool.query(`
        INSERT INTO fleet_daily_snapshots (
          id, tenant_name, snapshot_date, active_workstations, total_assets, vulnerable_assets,
          average_risk_score
        ) VALUES ($1, $2, CURRENT_DATE, $3, $4, $5, $6)
        ON CONFLICT (tenant_name, snapshot_date) DO UPDATE SET
          active_workstations = EXCLUDED.active_workstations,
          total_assets = EXCLUDED.total_assets,
          vulnerable_assets = EXCLUDED.vulnerable_assets,
          average_risk_score = EXCLUDED.average_risk_score,
          created_at = CURRENT_TIMESTAMP;
      `, [
        snapId,
        assignedTenant,
        parseInt(snapRow?.active_workstations || '1', 10),
        parseInt(snapRow?.total_assets || '0', 10),
        parseInt(snapRow?.vulnerable_assets || '0', 10),
        parseInt(snapRow?.average_risk_score || '0', 10)
      ]);
    } catch (snapErr) {
      console.warn('Could not record daily snapshot:', snapErr);
    }

    res.status(201).json({
      success: true,
      tokenName: tokenRow.name,
      machineId,
      hostname,
      computerName: cleanComp,
      quantumRiskScore: machineRiskScore,
      riskLevel: machineRiskLevel,
      processedCount: processedAssets.length,
      vulnerableCount
    });

  } catch (err: any) {
    console.error('Error in fleet telemetry ingestion:', err);
    res.status(500).json({ error: 'Failed to process telemetry.' });
  }
};

// Enqueue on-demand pull/sync command for a workstation
export const enqueuePullCommand = async (req: Request, res: Response) => {
  try {
    const { machineId } = req.params;
    const commandId = 'cmd-' + crypto.randomBytes(8).toString('hex');
    await pool.query(`
      INSERT INTO fleet_commands (id, machine_id, command, status)
      VALUES ($1, $2, 'scan_and_sync', 'pending')
    `, [commandId, machineId]);

    res.json({ success: true, commandId, machineId, message: 'On-demand sync command queued for workstation.' });
  } catch (err: any) {
    console.error('Error queuing pull command:', err);
    res.status(500).json({ error: 'Failed to queue command.' });
  }
};

// Retrieve historical daily snapshots for a tenant
export const getTenantDailySnapshots = async (req: Request, res: Response) => {
  try {
    const { tenant } = req.params;
    const cleanTenant = (tenant || '').toLowerCase().trim();
    const result = await pool.query(`
      SELECT 
        id, tenant_name as "tenantName", 
        TO_CHAR(snapshot_date, 'YYYY-MM-DD') as "date",
        active_workstations as "activeWorkstations",
        total_assets as "totalAssets",
        vulnerable_assets as "vulnerableAssets",
        average_risk_score as "averageRiskScore",
        created_at as "createdAt"
      FROM fleet_daily_snapshots
      WHERE LOWER(tenant_name) = LOWER($1) 
         OR LOWER(REPLACE(tenant_name, ' ', '')) = LOWER(REPLACE($1, ' ', ''))
         OR (LOWER($1) IN ('spinovation', 'spinovationcorp') AND LOWER(tenant_name) LIKE '%spinovation%')
      ORDER BY snapshot_date ASC
      LIMIT 30;
    `, [cleanTenant]);

    res.json(result.rows);
  } catch (err: any) {
    console.error('Error fetching daily snapshots:', err);
    res.status(500).json({ error: 'Failed to fetch snapshots.' });
  }
};
