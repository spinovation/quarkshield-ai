import { Request, Response } from 'express';
import pool from '../config/db';
import crypto from 'crypto';

// Reusable crypto rules for CI file analysis
const CI_CRYPTO_RULES = [
  {
    name: 'Hardcoded RSA Private Key',
    regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/i,
    algorithm: 'RSA',
    keySize: 2048,
    riskLevel: 'critical',
    threat: "Shor's algorithm factorization on CRQC. Enables Harvest Now, Decrypt Later (HNDL).",
    recommendation: 'Replace with NIST FIPS 204 (ML-DSA-65) or load securely from AWS KMS / Azure Key Vault.'
  },
  {
    name: 'Hardcoded EC Private Key',
    regex: /-----BEGIN EC PRIVATE KEY-----/i,
    algorithm: 'ECDSA',
    curve: 'secp256r1',
    riskLevel: 'critical',
    threat: "Shor's algorithm discrete logarithm solution. Forgery of digital signatures.",
    recommendation: 'Migrate to NIST FIPS 204 (ML-DSA) or FIPS 205 (SLH-DSA).'
  },
  {
    name: 'Legacy RSA Algorithm Reference',
    regex: /(?:crypto\.createSign|RSA_PKCS1_PADDING|RSASSA-PKCS1-v1_5|RSA-OAEP|RSA-PSS|RSA_2048|RSA_4096)/i,
    algorithm: 'RSA',
    keySize: 2048,
    riskLevel: 'critical',
    threat: 'Quantum-vulnerable asymmetric signature/encryption primitive.',
    recommendation: 'Upgrade to NIST FIPS 203 (ML-KEM-768) key exchange and ML-DSA signatures.'
  },
  {
    name: 'Elliptic Curve Cryptography (ECDSA/ECDH)',
    regex: /(?:secp256k1|prime256v1|P-256|P-384|curve25519|ed25519|ECDH|ECDSA)/i,
    algorithm: 'ECC',
    riskLevel: 'high',
    threat: 'Broken by Shor’s quantum algorithm with ~2330 logical qubits.',
    recommendation: 'Implement hybrid dual-key scheme (e.g., X25519MLKEM768 / FIPS 203).'
  },
  {
    name: 'Deprecated Broken Symmetric Cipher (3DES / DES / RC4)',
    regex: /(?:DES-EDE3-CBC|3DES|DES_EDE_CBC|RC4|ARCFOUR|Blowfish)/i,
    algorithm: '3DES/RC4',
    riskLevel: 'critical',
    threat: 'Classically broken and quantum trivial (Sweet32, Grover).',
    recommendation: 'Migrate to AES-256-GCM or ChaCha20-Poly1305.'
  },
  {
    name: 'Deprecated Broken Hash Function (MD5 / SHA-1)',
    regex: /(?:crypto\.createHash\(['"](?:md5|sha1)['"]\)|HASH_MD5|HASH_SHA1)/i,
    algorithm: 'MD5/SHA-1',
    riskLevel: 'high',
    threat: 'Collision vulnerability; obsolete under NIST SP 800-131A & CNSA 2.0.',
    recommendation: 'Upgrade to SHA-256, SHA-384, or SHA-3.'
  }
];

export const evaluateCIGate = async (req: Request, res: Response) => {
  try {
    const {
      tenantName = 'SPINOVATIONCORP',
      provider = 'github',
      repoName = 'unknown-repo',
      repoUrl = '',
      branch = 'main',
      prNumber = 'PR',
      commitHash = 'HEAD',
      commitAuthor = 'CI Runner',
      commitMessage = '',
      filesChanged = [],
      rawFindings = [],
      findings = [],
      policyName = 'CNSA 2.0 Strict Gate',
      maxAllowedRisk = 40
    } = req.body;

    // Resolve the tenant from the CI token (Bearer / X-Connector-Token), not the
    // request body. A valid fleet token scopes to its tenant; the community token
    // or none maps to 'COMMUNITY'. The client cannot pick another tenant's policy.
    let ciToken = (req.headers['x-connector-token'] as string) || '';
    const authHeader = req.headers['authorization'];
    if (!ciToken && authHeader && authHeader.startsWith('Bearer ')) ciToken = authHeader.slice(7).trim();
    let resolvedTenant = 'COMMUNITY';
    if (ciToken && ciToken !== 'QS-COMMUNITY-TOKEN') {
      try {
        const ft = await pool.query('SELECT tenant_name FROM fleet_tokens WHERE token = $1', [ciToken]);
        if (ft.rows[0]?.tenant_name) resolvedTenant = ft.rows[0].tenant_name;
        else {
          const lic = await pool.query("SELECT tenant_name FROM admin_licenses WHERE UPPER(TRIM(license_key)) = UPPER(TRIM($1)) AND status != 'revoked'", [ciToken]);
          if (lic.rows[0]?.tenant_name) resolvedTenant = lic.rows[0].tenant_name;
        }
      } catch { /* fall back to COMMUNITY */ }
    }
    const effectiveTenant = resolvedTenant;

    const initialFindings = Array.isArray(findings) && findings.length > 0 ? findings : (Array.isArray(rawFindings) ? rawFindings : []);
    const detectedFindings: any[] = [...initialFindings];

    // Fail closed (DEF-50): if the runner sent nothing to evaluate, do NOT report
    // a clean PASS — that let a broken/empty runner silently green-light merges.
    const hasScanInput = (Array.isArray(filesChanged) && filesChanged.length > 0) || initialFindings.length > 0;
    if (!hasScanInput) {
      const gateId = 'gate-' + crypto.randomUUID().substring(0, 10);
      const md = `## 🛡️ QuarkShield CI/CD Security Gate: **ERROR**\n\n> [!CAUTION]\n> The gate received no changed files or findings to evaluate. Failing closed to avoid a false pass — ensure the runner sends changed files (\`filesChanged\`) or scan findings.`;
      await pool.query(
        `INSERT INTO ci_security_gates (id, tenant_name, provider, repo_name, repo_url, branch, pr_number, commit_hash, commit_author, commit_message, status, violations_count, critical_count, high_count, quantum_risk_score, policy_name, markdown_report)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'ERROR',0,0,0,0,$11,$12)`,
        [gateId, String(effectiveTenant).toUpperCase(), provider, repoName, repoUrl, branch, prNumber, commitHash, commitAuthor, commitMessage, policyName, md]
      ).catch(() => {});
      return res.status(200).json({
        success: true, gateId, status: 'ERROR', exitCode: 1, blocked: true,
        quantumRiskScore: 0, violationsCount: 0,
        message: 'No scan input received; failing closed.', markdownReport: md,
      });
    }

    // Threshold comes from the tenant's policy, not a client-supplied value
    // (a client could otherwise raise its own bar to pass).
    let threshold = 40;
    try {
      const pol = await pool.query(
        "SELECT max_quantum_risk_score FROM ci_gate_policies WHERE LOWER(tenant_name) = LOWER($1) OR tenant_name = 'global' OR is_default = TRUE ORDER BY (LOWER(tenant_name) = LOWER($1)) DESC, is_default DESC LIMIT 1",
        [effectiveTenant]
      );
      if (pol.rows[0] && pol.rows[0].max_quantum_risk_score != null) threshold = Number(pol.rows[0].max_quantum_risk_score);
      else if (Number.isFinite(Number(maxAllowedRisk))) threshold = Number(maxAllowedRisk);
    } catch { /* keep default */ }

    // If filesChanged provided, scan them
    if (Array.isArray(filesChanged) && filesChanged.length > 0) {
      for (const file of filesChanged) {
        if (!file.path || !file.content) continue;
        const lines = String(file.content).split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          for (const rule of CI_CRYPTO_RULES) {
            if (rule.regex.test(line)) {
              detectedFindings.push({
                id: 'viol-' + crypto.randomUUID().substring(0, 8),
                ruleName: rule.name,
                filePath: file.path,
                lineNumber: i + 1,
                lineContent: line.trim().substring(0, 120),
                algorithm: rule.algorithm,
                riskLevel: rule.riskLevel,
                threat: rule.threat,
                recommendation: rule.recommendation
              });
            }
          }
        }
      }
    }

    // Tally counts
    const criticalCount = detectedFindings.filter(f => (f.riskLevel || '').toLowerCase() === 'critical').length;
    const highCount = detectedFindings.filter(f => (f.riskLevel || '').toLowerCase() === 'high').length;
    const mediumCount = detectedFindings.filter(f => (f.riskLevel || '').toLowerCase() === 'medium').length;
    const actualViolations = detectedFindings.filter(f => f.isVulnerable !== false && (f.riskLevel || '').toLowerCase() !== 'secure');
    const violationsCount = actualViolations.length;

    // Calculate quantum risk score
    let quantumRiskScore = Math.min(100, (criticalCount * 35) + (highCount * 18) + (mediumCount * 8));
    if (violationsCount === 0) quantumRiskScore = 0;

    // Gate decision
    const isBlocked = criticalCount > 0 || highCount > 2 || quantumRiskScore > threshold;
    const gateStatus = isBlocked ? 'BLOCKED' : (violationsCount > 0 ? 'WARNING' : 'PASSED');
    const exitCode = isBlocked ? 1 : 0;

    // Format rich Markdown Report for PR comment or CI step summary
    let markdownReport = `## 🛡️ QuarkShield Post-Quantum CI/CD Security Gate: **${gateStatus}**\n\n`;
    markdownReport += `| Metric | Result |\n| :--- | :--- |\n`;
    markdownReport += `| **Repository** | \`${repoName}\` (\`${branch}\`) |\n`;
    markdownReport += `| **Pull Request / Commit** | ${prNumber} (\`${commitHash.substring(0, 7)}\`) |\n`;
    markdownReport += `| **Commit Author** | ${commitAuthor} |\n`;
    markdownReport += `| **Policy Profile** | \`${policyName}\` |\n`;
    markdownReport += `| **Quantum Risk Score** | **${quantumRiskScore} / 100** |\n`;
    markdownReport += `| **Gate Decision** | **${gateStatus === 'BLOCKED' ? '❌ MERGE BLOCKED (Exit 1)' : '✅ MERGE ALLOWED (Exit 0)'}** |\n\n`;

    if (violationsCount > 0) {
      markdownReport += `### ⚠️ Cryptographic Policy Violations (${violationsCount}):\n\n`;
      markdownReport += `| Risk | Algorithm | Location | Quantum Threat & Recommendation |\n| :--- | :--- | :--- | :--- |\n`;
      for (const v of actualViolations.slice(0, 15)) {
        const ruleTitle = v.ruleName || v.algorithm || 'Cryptographic Policy Violation';
        const recText = v.recommendation || v.threat || 'Upgrade to NIST FIPS 203/204 post-quantum primitives.';
        markdownReport += `| **${String(v.riskLevel || 'critical').toUpperCase()}** | \`${v.algorithm || 'Classical'}\` | \`${v.filePath || 'code'}${v.lineNumber ? ':' + v.lineNumber : ''}\` | **${ruleTitle}**: ${recText} |\n`;
      }
      markdownReport += `\n> [!CAUTION]\n> **Action Required**: Pull request introduces cryptographic algorithms vulnerable to Shor's algorithm on a Cryptanalytically Relevant Quantum Computer (CRQC). Upgrade keys to **NIST FIPS 203 (ML-KEM)** or **FIPS 204 (ML-DSA)** before merging.\n`;
    } else {
      markdownReport += `> [!NOTE]\n> **PQC Compliance Verified**: No classical vulnerable cryptographic primitives discovered. All examined code complies with NIST Post-Quantum Standards and NSA CNSA 2.0 requirements.\n`;
    }

    const gateId = 'gate-' + crypto.randomUUID().substring(0, 10);

    // Save to PostgreSQL
    await pool.query(`
      INSERT INTO ci_security_gates (
        id, tenant_name, provider, repo_name, repo_url, branch, pr_number, 
        commit_hash, commit_author, commit_message, status, violations_count, 
        critical_count, high_count, medium_count, quantum_risk_score, policy_name, 
        findings, markdown_report
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
    `, [
      gateId, effectiveTenant.toUpperCase(), provider, repoName, repoUrl, branch, prNumber,
      commitHash, commitAuthor, commitMessage, gateStatus, violationsCount,
      criticalCount, highCount, mediumCount, quantumRiskScore, policyName,
      JSON.stringify(detectedFindings), markdownReport
    ]);

    res.json({
      gateId,
      status: gateStatus,
      exitCode,
      isBlocked,
      violationsCount,
      criticalCount,
      highCount,
      quantumRiskScore,
      markdownReport,
      message: isBlocked 
        ? `QuarkShield Security Gate BLOCKED PR #${prNumber}. Detected ${criticalCount} critical quantum vulnerabilities.`
        : `QuarkShield Security Gate PASSED PR #${prNumber}. Compliant with PQC standards.`
    });
  } catch (err: any) {
    console.error('Error in evaluateCIGate:', err);
    res.status(500).json({ error: 'Failed to evaluate CI gate: ' + err.message });
  }
};

export const getCIGateHistory = async (req: Request, res: Response) => {
  try {
    const { tenant, limit = 50 } = req.query;
    let query = 'SELECT * FROM ci_security_gates';
    const params: any[] = [];

    if (tenant && typeof tenant === 'string' && tenant.trim()) {
      query += ' WHERE LOWER(tenant_name) = LOWER($1)';
      params.push(tenant.trim());
    }

    query += ' ORDER BY created_at DESC LIMIT $' + (params.length + 1);
    params.push(Number(limit) || 50);

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err: any) {
    console.error('Error fetching CI gate history:', err);
    res.status(500).json({ error: 'Failed to retrieve CI gate history.' });
  }
};

export const getCIGatePolicies = async (req: Request, res: Response) => {
  try {
    const { tenant = 'SPINOVATIONCORP' } = req.query;
    const result = await pool.query(
      "SELECT * FROM ci_gate_policies WHERE LOWER(tenant_name) = LOWER($1) OR tenant_name = 'global' OR is_default = TRUE ORDER BY is_default DESC, created_at DESC",
      [String(tenant)]
    );
    res.json(result.rows);
  } catch (err: any) {
    console.error('Error fetching CI gate policies:', err);
    res.status(500).json({ error: 'Failed to retrieve CI gate policies.' });
  }
};

export const getCITemplate = async (req: Request, res: Response) => {
  try {
    const { provider = 'github' } = req.params;
    const serverUrl = 'https://quarkshield.ai';

    if (provider === 'github') {
      const yaml = `name: QuarkShield PQC Security Gate
on:
  pull_request:
    branches: [ main, master, release/* ]
  push:
    branches: [ main ]

jobs:
  pqc-cbom-gate:
    name: Post-Quantum Cryptographic Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run QuarkShield PQC Gate
        env:
          QUARKSHIELD_TOKEN: \${{ secrets.QUARKSHIELD_API_TOKEN }}
          QUARKSHIELD_URL: "${serverUrl}"
        run: |
          echo "🔍 Scanning pull request for post-quantum cryptographic violations..."
          curl -sSL "\${QUARKSHIELD_URL}/api/git/ci-gate/runner.sh" | bash -s -- \\
            --provider github \\
            --repo "\${{ github.repository }}" \\
            --pr "\${{ github.event.pull_request.number || 'push' }}" \\
            --commit "\${{ github.sha }}" \\
            --author "\${{ github.actor }}"
`;
      return res.type('text/yaml').send(yaml);
    }

    if (provider === 'gitlab') {
      const gitlabYaml = `stages:
  - security-gate

quarkshield-pqc-gate:
  stage: security-gate
  image: alpine:latest
  before_script:
    - apk add --no-cache curl bash git python3
  script:
    - echo "🛡️ Evaluating Merge Request against QuarkShield PQC Security Policies..."
    - curl -sSL "${serverUrl}/api/git/ci-gate/runner.sh" | bash -s -- --provider gitlab --repo "$CI_PROJECT_PATH" --pr "$CI_MERGE_REQUEST_IID" --commit "$CI_COMMIT_SHA" --author "$GITLAB_USER_EMAIL"
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
`;
      return res.type('text/yaml').send(gitlabYaml);
    }

    if (provider === 'bitbucket') {
      const bitbucketYaml = `pipelines:
  pull-requests:
    '**':
      - step:
          name: QuarkShield PQC Security Gate
          image: alpine:latest
          script:
            - apk add --no-cache curl bash git python3
            - curl -sSL "${serverUrl}/api/git/ci-gate/runner.sh" | bash -s -- --provider bitbucket --repo "$BITBUCKET_REPO_FULL_NAME" --pr "$BITBUCKET_PR_ID" --commit "$BITBUCKET_COMMIT"
`;
      return res.type('text/yaml').send(bitbucketYaml);
    }

    // Default universal runner bash script. It collects the files changed in the
    // commit/PR (falling back to the tracked source tree), sends their contents to
    // the gate, and FAILS CLOSED on any error (missing tools, network failure,
    // BLOCKED/ERROR verdict). Requires bash, git, curl and python3 (all present in
    // the CI images the templates provision).
    const runnerScript = `#!/usr/bin/env bash
set -euo pipefail

QUARKSHIELD_URL="\${QUARKSHIELD_URL:-${serverUrl}}"
QUARKSHIELD_TOKEN="\${QUARKSHIELD_TOKEN:-QS-COMMUNITY-TOKEN}"
BASE_REF="\${BASE_REF:-origin/main}"

PROVIDER="cli"; REPO="local-repo"; PR="HEAD"
COMMIT="\$(git rev-parse HEAD 2>/dev/null || echo unknown)"
AUTHOR="\$(git log -1 --pretty=format:'%ae' 2>/dev/null || echo ci-user)"
while [[ \$# -gt 0 ]]; do
  case \$1 in
    --provider) PROVIDER="\$2"; shift 2 ;;
    --repo) REPO="\$2"; shift 2 ;;
    --pr) PR="\$2"; shift 2 ;;
    --commit) COMMIT="\$2"; shift 2 ;;
    --author) AUTHOR="\$2"; shift 2 ;;
    --base) BASE_REF="\$2"; shift 2 ;;
    *) shift ;;
  esac
done

echo "================================================================="
echo "🛡️  QUARKSHIELD CI/CD PQC SECURITY GATE"
echo "   Repo: \$REPO | Ref: \$PR | Commit: \$COMMIT"
echo "================================================================="

fail_closed() { echo "❌ GATE ERROR (failing closed): \$1"; exit 1; }
command -v git >/dev/null 2>&1 || fail_closed "git not found"
command -v curl >/dev/null 2>&1 || fail_closed "curl not found"
command -v python3 >/dev/null 2>&1 || fail_closed "python3 not found"

# Determine changed files: PR diff against the base if available, else last commit.
if git rev-parse --verify "\$BASE_REF" >/dev/null 2>&1; then
  CHANGED="\$(git diff --name-only "\$BASE_REF"...HEAD 2>/dev/null || true)"
else
  CHANGED="\$(git diff --name-only HEAD~1..HEAD 2>/dev/null || true)"
fi
[ -z "\$CHANGED" ] && CHANGED="\$(git ls-files 2>/dev/null | head -300)"

# Build the JSON payload (with file contents) safely via python3. The changed
# file list is passed via an env var (stdin is taken by the heredoc program).
PAYLOAD="\$(CHANGED_FILES="\$CHANGED" python3 - "\$PROVIDER" "\$REPO" "\$PR" "\$COMMIT" "\$AUTHOR" <<'PY'
import json, sys, os
provider, repo, pr, commit, author = sys.argv[1:6]
exts = ('.js','.ts','.jsx','.tsx','.py','.go','.java','.rb','.php','.cs','.c','.cpp','.h','.rs','.kt','.scala','.swift','.sh','.tf','.yaml','.yml','.json','.pem','.key','.crt','.conf','.cnf','.env','.config')
files = []
for path in os.environ.get('CHANGED_FILES', '').split('\\n'):
    path = path.strip()
    if not path or not os.path.isfile(path):
        continue
    if not path.lower().endswith(exts):
        continue
    try:
        if os.path.getsize(path) > 200_000:
            continue
        with open(path, 'r', errors='ignore') as f:
            files.append({'path': path, 'content': f.read()})
    except Exception:
        continue
    if len(files) >= 300:
        break
print(json.dumps({'provider': provider, 'repoName': repo, 'prNumber': pr,
                  'commitHash': commit, 'commitAuthor': author, 'filesChanged': files}))
PY
)"
[ -z "\$PAYLOAD" ] && fail_closed "failed to build scan payload"

# Call the gate; capture body + HTTP status. Any transport failure fails closed.
HTTP_BODY="\$(mktemp)"
HTTP_CODE="\$(curl -s -o "\$HTTP_BODY" -w '%{http_code}' -X POST "\${QUARKSHIELD_URL}/api/git/ci-gate/evaluate" \\
  -H 'Content-Type: application/json' -H "Authorization: Bearer \${QUARKSHIELD_TOKEN}" \\
  --data-binary @<(printf '%s' "\$PAYLOAD") 2>/dev/null || echo 000)"
RESPONSE="\$(cat "\$HTTP_BODY")"; rm -f "\$HTTP_BODY"
[ "\$HTTP_CODE" -ge 200 ] 2>/dev/null && [ "\$HTTP_CODE" -lt 300 ] 2>/dev/null || fail_closed "gate request failed (HTTP \$HTTP_CODE)"

STATUS="\$(printf '%s' "\$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","ERROR"))' 2>/dev/null || echo ERROR)"
SCORE="\$(printf '%s' "\$RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("quantumRiskScore",0))' 2>/dev/null || echo 0)"
echo "Gate status: \$STATUS (quantum risk score: \$SCORE)"

case "\$STATUS" in
  PASSED)  echo "✅ GATE PASSED: no vulnerable classical cryptography introduced."; exit 0 ;;
  WARNING) echo "⚠️  GATE WARNING: vulnerabilities found but under the blocking threshold."; exit 0 ;;
  BLOCKED) echo "❌ GATE BLOCKED: quantum-vulnerable cryptography detected. Upgrade to FIPS 203/204."; exit 1 ;;
  *)       fail_closed "unexpected gate status '\$STATUS'" ;;
esac
`;
    res.type('text/x-shellscript').send(runnerScript);
  } catch (err: any) {
    console.error('Error generating CI template:', err);
    res.status(500).json({ error: 'Failed to generate template.' });
  }
};
