import { Request, Response } from 'express';
import pool from '../config/db';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { execFile } from 'child_process';

export interface GitFinding {
  id: string;
  category: 'private_key' | 'certificate' | 'source_code' | 'dependency' | 'config' | 'web3';
  filePath: string;
  lineNumber?: number;
  lineContent?: string;
  assetName: string;
  algorithm: string;
  keySize?: number;
  curve?: string;
  quantumThreat: string;
  isVulnerable: boolean;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure';
  status: string;
  recommendation: string;
  remediationSnippet?: string;
  complianceStandards: string[];
}

export interface GitScanSummary {
  id: string;
  provider: 'github' | 'bitbucket' | 'gitlab' | 'generic';
  repoUrl: string;
  repoName: string;
  branch: string;
  commitHash?: string;
  commitAuthor?: string;
  commitMessage?: string;
  scannedAt: string;
  scanDurationMs: number;
  totalFilesScanned: number;
  totalAssets: number;
  vulnerableCount: number;
  pqcCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  quantumRiskScore: number;
  cnsaStatus: 'Non-Compliant' | 'Partially Compliant' | 'PQC Ready';
  findings: GitFinding[];
}

// In-memory cache for recent scans fallback if DB table is initializing
const recentScansCache: GitScanSummary[] = [];

// ==============================================================================
// 1. RECURSIVE REPOSITORY CRYPTO SCANNER ENGINE
// ==============================================================================

const IGNORED_DIRS = new Set([
  '.git', 'node_modules', 'vendor', '.svn', '.hg', 'dist', 'build', 
  '.next', '.nuxt', '__pycache__', '.venv', 'venv', 'env', '.idea', '.vscode',
  'coverage', 'target', 'bin', 'obj'
]);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz',
  '.exe', '.bin', '.dll', '.so', '.dylib', '.iso', '.dmg', '.pkg', '.mp3',
  '.mp4', '.mov', '.avi', '.woff', '.woff2', '.ttf', '.eot', '.class', '.pyc'
]);

// Rule definitions for source code static analysis
interface CryptoPatternRule {
  name: string;
  category: 'private_key' | 'certificate' | 'source_code' | 'dependency' | 'config' | 'web3';
  regex: RegExp;
  algorithm: string;
  keySize?: number;
  curve?: string;
  isVulnerable: boolean;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure';
  status: string;
  quantumThreat: string;
  recommendation: string;
  remediationSnippet: string;
  compliance: string[];
}

const CRYPTO_RULES: CryptoPatternRule[] = [
  // --- HARDCODED KEYS & CERTIFICATES ---
  {
    name: 'Hardcoded RSA Private Key',
    category: 'private_key',
    regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/i,
    algorithm: 'RSA',
    keySize: 2048,
    isVulnerable: true,
    riskLevel: 'critical',
    status: 'Quantum Vulnerable (Shor\'s Algorithm)',
    quantumThreat: 'Vulnerable to polynomial-time integer factorization via Shor\'s algorithm on a Cryptanalytically Relevant Quantum Computer (CRQC). Exposed private key enables total decryption of historic traffic (HNDL).',
    recommendation: 'Remove private keys from source code immediately. Migrate authentication/encryption to NIST FIPS 203 (ML-KEM-768) or FIPS 204 (ML-DSA-65). Store keys in a Hardware Security Module (HSM) or cloud KMS.',
    remediationSnippet: '// Remediate: Replace RSA with Post-Quantum ML-DSA-65 (FIPS 204)\nimport { mldsa65 } from "@noble/post-quantum/ml-dsa";\nconst keyPair = mldsa65.keygen();',
    compliance: ['NIST FIPS 204', 'CNSA 2.0 Violations', 'White House OMB M-23-02']
  },
  {
    name: 'Hardcoded EC Private Key',
    category: 'private_key',
    regex: /-----BEGIN EC PRIVATE KEY-----/i,
    algorithm: 'ECDSA',
    curve: 'P-256',
    isVulnerable: true,
    riskLevel: 'critical',
    status: 'Quantum Vulnerable (Shor\'s Algorithm)',
    quantumThreat: 'Shor\'s algorithm solves elliptic curve discrete logarithms in polynomial time. Elliptic curve keys provide zero post-quantum security.',
    recommendation: 'Remove EC private key from version control. Replace with hybrid post-quantum signatures (e.g. Ed25519 + ML-DSA) or pure ML-DSA-65 / Falcon.',
    remediationSnippet: '// Migrate EC key exchange to Hybrid Post-Quantum KEM\n// X25519 + ML-KEM-768 (draft-ietf-tls-hybrid-design)',
    compliance: ['NIST FIPS 203', 'CNSA 2.0 Non-Compliant']
  },
  {
    name: 'OpenSSH Private Key',
    category: 'private_key',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/i,
    algorithm: 'SSH Key (OpenSSH)',
    isVulnerable: true,
    riskLevel: 'critical',
    status: 'Quantum Vulnerable',
    quantumThreat: 'Exposed SSH private key allows unauthorized server access and lateral movement. Classical SSH host keys can be decrypted via Shor\'s algorithm.',
    recommendation: 'Revoke key immediately. Upgrade SSH server and client to OpenSSH 9.0+ and enforce post-quantum hybrid key exchange `sntrup761x25519-sha512@openssh.com` or `mlkem768x25519-sha256`.',
    remediationSnippet: '# OpenSSH config (sshd_config):\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256',
    compliance: ['NIST FIPS 203', 'OpenSSH Post-Quantum Standard']
  },
  {
    name: 'X.509 Certificate in Code',
    category: 'certificate',
    regex: /-----BEGIN CERTIFICATE-----/i,
    algorithm: 'X.509 (Classical RSA/ECC)',
    isVulnerable: true,
    riskLevel: 'high',
    status: 'Quantum Vulnerable',
    quantumThreat: 'Classical PKI certificates relying on RSA-2048/3072 or ECDSA P-256 are subject to forgery by quantum computers capable of running Shor\'s algorithm.',
    recommendation: 'Transition PKI infrastructure to hybrid or dual certificates incorporating ML-DSA (Dilithium) or SLH-DSA (SPHINCS+).',
    remediationSnippet: '# Renew certificate with post-quantum root CA / hybrid intermediate',
    compliance: ['NIST FIPS 204', 'NIST SP 800-227']
  },

  // --- SOURCE CODE CRYPTOGRAPHIC INVOCATIONS ---
  {
    name: 'RSA Key Generation / Cipher in Code',
    category: 'source_code',
    regex: /(?:generateKeyPair(?:Sync)?\s*\(\s*['"]rsa['"]|KeyPairGenerator\.getInstance\s*\(\s*["']RSA["']|RSA\.generate|createSign\s*\(\s*['"]RSA-SHA256['"]|Cipher\.getInstance\s*\(\s*["']RSA|rsa\.GenerateKey)/i,
    algorithm: 'RSA',
    keySize: 2048,
    isVulnerable: true,
    riskLevel: 'high',
    status: 'Quantum Vulnerable',
    quantumThreat: 'Integer factorization can be cracked by Shor\'s algorithm running on a quantum system with sufficient logical qubits (~4000 logical qubits).',
    recommendation: 'Refactor code to replace RSA encryption with NIST ML-KEM (Kyber) and RSA signing with NIST ML-DSA (Dilithium).',
    remediationSnippet: '// Modern Post-Quantum Replacement (NIST FIPS 203 ML-KEM):\nimport { mlkem768 } from "@noble/post-quantum/ml-kem";\nconst [alicePub, alicePriv] = mlkem768.keygen();\nconst { cipherText, sharedSecret } = mlkem768.encapsulate(alicePub);',
    compliance: ['NIST FIPS 203', 'CNSA 2.0 High Priority']
  },
  {
    name: 'ECDSA / ECDH Elliptic Curve Invocations',
    category: 'source_code',
    regex: /(?:createECDH\s*\(\s*['"](?:secp256k1|prime256v1)['"]|crypto\.subtle\.generateKey\s*\(\s*\{[^\}]*name:\s*['"]ECDSA['"]|KeyPairGenerator\.getInstance\s*\(\s*["']EC["']|ecdsa\.GenerateKey)/i,
    algorithm: 'ECDSA / ECDH',
    curve: 'P-256 / secp256k1',
    isVulnerable: true,
    riskLevel: 'high',
    status: 'Quantum Vulnerable',
    quantumThreat: 'Discrete Logarithm Problem (DLP) over elliptic curves can be broken by Shor\'s algorithm using fewer quantum resources than factoring RSA (~2330 logical qubits for P-256).',
    recommendation: 'Migrate to ML-DSA-65 (FIPS 204) for digital signatures or ML-KEM-768 (FIPS 203) for key agreement.',
    remediationSnippet: '// ML-DSA Digital Signature Verification:\nimport { mldsa65 } from "@noble/post-quantum/ml-dsa";\nconst sig = mldsa65.sign(alicePriv, message);\nconst valid = mldsa65.verify(alicePub, message, sig);',
    compliance: ['NIST FIPS 204', 'CNSA 2.0']
  },
  {
    name: 'Ed25519 / Curve25519 Usage',
    category: 'source_code',
    regex: /(?:crypto\.subtle\.generateKey\s*\(\s*\{[^\}]*name:\s*['"]Ed25519['"]|ed25519\.GenerateKey|nacl\.sign\.keyPair|ed25519\.sign)/i,
    algorithm: 'Ed25519 / Edwards-Curve',
    curve: 'Curve25519',
    isVulnerable: true,
    riskLevel: 'high',
    status: 'Quantum Vulnerable',
    quantumThreat: 'While mathematically robust against classical supercomputers, Curve25519 relies on discrete logarithms and will be broken by quantum Shor\'s algorithm.',
    recommendation: 'Implement hybrid signatures combining Ed25519 with ML-DSA-65, or migrate completely to SLH-DSA (SPHINCS+) for stateless hash-based signatures.',
    remediationSnippet: '// Combine Ed25519 with ML-DSA-65 in dual-signature verification',
    compliance: ['NIST FIPS 205', 'CNSA 2.0']
  },
  {
    name: 'Diffie-Hellman Key Agreement',
    category: 'source_code',
    regex: /(?:createDiffieHellman|DHParameterSpec|dh_generate_key|crypto\.createDiffieHellmanGroup)/i,
    algorithm: 'Diffie-Hellman (DH)',
    isVulnerable: true,
    riskLevel: 'high',
    status: 'Quantum Vulnerable (DLP)',
    quantumThreat: 'Finite field Diffie-Hellman key exchanges are vulnerable to retroactive decryption (HNDL) and active quantum MITM attacks via Shor\'s algorithm.',
    recommendation: 'Deprecate Diffie-Hellman. Transition directly to ML-KEM-768 (Module-Lattice Key Encapsulation Mechanism).',
    remediationSnippet: '// Use ML-KEM-768 for quantum-safe key exchange\nimport { mlkem768 } from "@noble/post-quantum/ml-kem";',
    compliance: ['NIST FIPS 203', 'White House OMB M-23-02']
  },
  {
    name: 'Broken Hash Function (MD5 / SHA-1)',
    category: 'source_code',
    regex: /(?:createHash\s*\(\s*['"](?:md5|sha1)['"]|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1)["']|crypto\.createHash\(['"](?:md5|sha1)['"]\))/i,
    algorithm: 'MD5 / SHA-1',
    isVulnerable: true,
    riskLevel: 'medium',
    status: 'Broken Classical Hash',
    quantumThreat: 'Classical collision attacks already exist. Grover\'s algorithm further reduces effective preimage resistance from 128-bit/160-bit down to 64-bit/80-bit.',
    recommendation: 'Immediately upgrade to SHA-256 or SHA-3 (SHAKE-256) for collision resistance and 128-bit quantum security strength.',
    remediationSnippet: 'const hash = crypto.createHash("sha384").update(data).digest("hex");',
    compliance: ['NIST SP 800-131A', 'FIPS 180-4']
  },
  {
    name: 'Legacy Symmetric Cipher (DES / 3DES / RC4 / Blowfish)',
    category: 'source_code',
    regex: /(?:createCipheriv\s*\(\s*['"](?:des|des3|des-ede3-cbc|rc4|blowfish)['"]|Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|RC4|Blowfish)["'])/i,
    algorithm: 'Legacy Block Cipher (DES/RC4)',
    isVulnerable: true,
    riskLevel: 'critical',
    status: 'Deprecated & Cryptographically Broken',
    quantumThreat: 'Completely broken classically and quantum-vulnerable. Grover\'s algorithm reduces effective key length of 3DES to under 56 bits.',
    recommendation: 'Replace with AES-256-GCM or ChaCha20-Poly1305 to ensure minimum 128-bit quantum security strength under Grover\'s algorithm.',
    remediationSnippet: 'const cipher = crypto.createCipheriv("aes-256-gcm", key256, iv);',
    compliance: ['NIST SP 800-175B', 'CNSA 2.0 Mandate']
  },

  // --- WEB3 & BLOCKCHAIN SIGNATURE PATTERNS ---
  {
    name: 'Web3 secp256k1 Signature / ecrecover',
    category: 'web3',
    regex: /(?:ecrecover\s*\(|eth_sign|recoverAddress|ethers\.Wallet\.createRandom|@solana\/web3\.js.*Keypair\.generate)/i,
    algorithm: 'secp256k1 / Ed25519 (Blockchain)',
    curve: 'secp256k1',
    isVulnerable: true,
    riskLevel: 'high',
    status: 'Quantum Vulnerable (Blockchain Identity)',
    quantumThreat: 'Once a public key is exposed on-chain (upon transaction submission), Shor\'s algorithm can deduce the private key before block confirmation or during historic account compromise.',
    recommendation: 'Implement Account Abstraction (ERC-4337) smart contract wallets supporting quantum-safe signature verification modules (ML-DSA / Falcon).',
    remediationSnippet: '// QuarkShield Web3 PQC: Deploy ERC-4337 Quantum-Safe Paymaster & Module\n// Supporting Lamport one-time signatures or ML-DSA-65 validation',
    compliance: ['ERC-4337 PQC Extension', 'Ethereum PQC Roadmap']
  },

  // --- POST-QUANTUM CRYPTOGRAPHY (COMPLIANT) ---
  {
    name: 'ML-KEM / Kyber Lattice Key Encapsulation',
    category: 'source_code',
    regex: /(?:mlkem(?:512|768|1024)|kyber(?:512|768|1024)|X25519MLKEM768|bouncycastle.*pqc|circl\/pqc\/kyber)/i,
    algorithm: 'ML-KEM (Kyber)',
    isVulnerable: false,
    riskLevel: 'secure',
    status: 'Post-Quantum Compliant (NIST FIPS 203)',
    quantumThreat: 'Based on Module Learning With Errors (M-LWE) lattice hardness problem. Secure against known quantum and classical algorithmic cryptanalysis.',
    recommendation: 'Excellent. Verified NIST FIPS 203 compliant implementation. Continue monitoring parameter set guidance.',
    remediationSnippet: '// Verified Post-Quantum Ready Asset',
    compliance: ['NIST FIPS 203', 'CNSA 2.0 Approved', 'NIST Security Category 3/5']
  },
  {
    name: 'ML-DSA / Dilithium Digital Signatures',
    category: 'source_code',
    regex: /(?:mldsa(?:44|65|87)|dilithium(?:2|3|5)|circl\/pqc\/dilithium)/i,
    algorithm: 'ML-DSA (Dilithium)',
    isVulnerable: false,
    riskLevel: 'secure',
    status: 'Post-Quantum Compliant (NIST FIPS 204)',
    quantumThreat: 'Based on Module Learning with Errors and Short Integer Solution (M-SIS). Resists cryptanalytic attacks on quantum hardware.',
    recommendation: 'Excellent. Verified NIST FIPS 204 compliant implementation.',
    remediationSnippet: '// Verified Post-Quantum Ready Asset',
    compliance: ['NIST FIPS 204', 'CNSA 2.0 Approved']
  },
  {
    name: 'SLH-DSA / SPHINCS+ Stateless Hash-Based Signatures',
    category: 'source_code',
    regex: /(?:slhdsa|sphincs\+|sphincsplus|slh_dsa)/i,
    algorithm: 'SLH-DSA (SPHINCS+)',
    isVulnerable: false,
    riskLevel: 'secure',
    status: 'Post-Quantum Compliant (NIST FIPS 205)',
    quantumThreat: 'Stateless hash-based signature scheme. Security relies solely on the cryptographic properties of hash functions rather than lattice assumptions.',
    recommendation: 'Excellent. Conservative post-quantum signature backup standard.',
    remediationSnippet: '// Verified Post-Quantum Ready Asset',
    compliance: ['NIST FIPS 205']
  }
];

// Scan a single file for cryptographic violations
function auditFileContent(filePath: string, content: string, relPath: string): GitFinding[] {
  const findings: GitFinding[] = [];
  const lines = content.split('\n');

  // Check file extension specific rules
  const ext = path.extname(filePath).toLowerCase();
  const baseName = path.basename(filePath).toLowerCase();

  // 1. Check for hardcoded key files directly by filename
  if (['id_rsa', 'id_dsa', 'id_ecdsa'].includes(baseName) || (['.pem', '.key', '.pkcs8', '.p12', '.pfx', '.jks'].includes(ext) && !content.includes('BEGIN CERTIFICATE'))) {
    findings.push({
      id: crypto.randomUUID().substring(0, 8),
      category: 'private_key',
      filePath: relPath,
      lineNumber: 1,
      lineContent: `File: ${baseName} (Cryptographic Key File)`,
      assetName: `Cryptographic Key Storage (${baseName})`,
      algorithm: ext === '.jks' ? 'Java Keystore' : (baseName.includes('ecdsa') ? 'ECDSA' : 'RSA/Private Key'),
      keySize: 2048,
      isVulnerable: true,
      riskLevel: 'critical',
      status: 'Quantum Vulnerable Key Stored in Repository',
      quantumThreat: 'Private keys committed to Git repositories remain in git commit history and can be decrypted or exploited by adversaries preparing for quantum decryption.',
      recommendation: 'Purge this key from git history using git-filter-repo or BFG Repo-Cleaner. Move secret management to Vault or AWS/GCP Secrets Manager.',
      remediationSnippet: '# Remove key from git history:\ngit filter-repo --path ' + relPath + ' --invert-paths',
      complianceStandards: ['NIST SP 800-57', 'CMMC AC.1.001', 'SOC 2 CC6.1']
    });
  }

  // 2. Dependency Manifest Audits
  if (baseName === 'package.json') {
    try {
      const pkg = JSON.parse(content);
      const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      
      const vulnerableDeps: Record<string, { algo: string; threat: string }> = {
        'jsonwebtoken': { algo: 'JWT (RS256/ES256 default)', threat: 'Tokens signed with RS256/ES256 can be forged once a CRQC breaks public key verification.' },
        'bcrypt': { algo: 'Blowfish-based KDF', threat: 'Blowfish cipher has 64-bit block size susceptible to quantum collision search.' },
        'web3': { algo: 'secp256k1 Ethereum Library', threat: 'secp256k1 transactions exposed to Shor\'s algorithm on-chain.' },
        'ethers': { algo: 'secp256k1 Ethereum Suite', threat: 'Exposed signatures vulnerable to quantum key extraction.' },
        '@solana/web3.js': { algo: 'Ed25519 Solana Suite', threat: 'Ed25519 transactions vulnerable to quantum discrete log solving.' }
      };

      for (const [dep, info] of Object.entries(vulnerableDeps)) {
        if (allDeps[dep]) {
          findings.push({
            id: crypto.randomUUID().substring(0, 8),
            category: 'dependency',
            filePath: relPath,
            assetName: `Package Dependency: ${dep} (${allDeps[dep]})`,
            algorithm: info.algo,
            isVulnerable: true,
            riskLevel: 'medium',
            status: 'Vulnerable Cryptographic Dependency',
            quantumThreat: info.threat,
            recommendation: `Evaluate post-quantum alternatives or wrap calls with hybrid quantum-safe signatures.`,
            remediationSnippet: `"dependencies": {\n  "${dep}": "${allDeps[dep]}",\n  "@noble/post-quantum": "^0.2.0"\n}`,
            complianceStandards: ['NIST FIPS 203/204', 'White House OMB M-23-02']
          });
        }
      }

      // Check if PQC libraries are present!
      const pqcDeps = ['@noble/post-quantum', 'circl', 'oqs', 'pqc-starter-lib', 'dilithium', 'kyber'];
      for (const dep of pqcDeps) {
        if (allDeps[dep]) {
          findings.push({
            id: crypto.randomUUID().substring(0, 8),
            category: 'dependency',
            filePath: relPath,
            assetName: `PQC Package Dependency: ${dep}`,
            algorithm: 'Post-Quantum Lattice Library',
            isVulnerable: false,
            riskLevel: 'secure',
            status: 'Post-Quantum Dependency Detected',
            quantumThreat: 'Post-quantum secure algorithms implemented.',
            recommendation: 'Keep library updated to the latest NIST FIPS 203/204/205 final specifications.',
            remediationSnippet: `// Verified PQC Dependency: ${dep}`,
            complianceStandards: ['NIST FIPS 203', 'NIST FIPS 204']
          });
        }
      }
    } catch {
      // Ignored if invalid json
    }
  }

  // 3. Python requirements.txt audit
  if (baseName === 'requirements.txt' || baseName === 'pipfile') {
    if (content.includes('cryptography') || content.includes('pycryptodome') || content.includes('rsa') || content.includes('ecdsa')) {
      findings.push({
        id: crypto.randomUUID().substring(0, 8),
        category: 'dependency',
        filePath: relPath,
        assetName: 'Python Cryptography Dependency (cryptography / pycryptodome)',
        algorithm: 'Classical Python Crypto',
        isVulnerable: true,
        riskLevel: 'medium',
        status: 'Classical Crypto Library in Requirements',
        quantumThreat: 'Standard cryptography library uses OpenSSL default classical primitives (RSA/ECDSA).',
        recommendation: 'Integrate `liboqs-python` or hybrid post-quantum cipher suites.',
        remediationSnippet: '# Add post-quantum python bindings:\nliboqs-python>=0.9.0',
        complianceStandards: ['CNSA 2.0', 'OMB M-23-02']
      });
    }
  }

  // 4. Infrastructure & TLS config checks
  if (['nginx.conf', 'httpd.conf', 'haproxy.cfg'].includes(baseName) || ext === '.tf' || ext === '.conf') {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/ssl_protocols\s+.*(?:TLSv1|TLSv1\.1)/i.test(line)) {
        findings.push({
          id: crypto.randomUUID().substring(0, 8),
          category: 'config',
          filePath: relPath,
          lineNumber: i + 1,
          lineContent: line.trim(),
          assetName: 'Deprecated TLS Protocol (TLSv1.0 / TLSv1.1)',
          algorithm: 'Legacy TLS Protocol',
          isVulnerable: true,
          riskLevel: 'critical',
          status: 'Cryptographically Broken & Quantum Vulnerable',
          quantumThreat: 'TLS 1.0 and 1.1 allow trivial downgrade attacks, lack forward secrecy, and rely on broken SHA-1 handshakes.',
          recommendation: 'Enforce TLS 1.3 only (or TLS 1.2 with strict forward secrecy ECDHE).',
          remediationSnippet: 'ssl_protocols TLSv1.2 TLSv1.3;',
          complianceStandards: ['PCI DSS 4.0', 'NIST SP 800-52r2', 'CNSA 2.0']
        });
      }
    }
  }

  // 5. Line-by-line pattern matching with CRYPTO_RULES
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line || line.trim().length === 0 || line.length > 500) continue;

    for (const rule of CRYPTO_RULES) {
      if (rule.regex.test(line)) {
        findings.push({
          id: crypto.randomUUID().substring(0, 8),
          category: rule.category,
          filePath: relPath,
          lineNumber: i + 1,
          lineContent: line.trim().substring(0, 160),
          assetName: `${rule.name} in ${path.basename(filePath)}`,
          algorithm: rule.algorithm,
          keySize: rule.keySize,
          curve: rule.curve,
          isVulnerable: rule.isVulnerable,
          riskLevel: rule.riskLevel,
          status: rule.status,
          quantumThreat: rule.quantumThreat,
          recommendation: rule.recommendation,
          remediationSnippet: rule.remediationSnippet,
          complianceStandards: rule.compliance
        });
      }
    }
  }

  return findings;
}

// Recursive directory crawler
function crawlAndAuditDirectory(dir: string, baseDir: string, maxFiles: number = 3000): { findings: GitFinding[]; fileCount: number } {
  let fileCount = 0;
  const allFindings: GitFinding[] = [];

  function traverse(currentPath: string) {
    if (fileCount >= maxFiles) return;

    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(currentPath, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (fileCount >= maxFiles) break;

      const fullPath = path.join(currentPath, entry.name);
      const relPath = path.relative(baseDir, fullPath).replace(/\\/g, '/');

      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
          traverse(fullPath);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (BINARY_EXTENSIONS.has(ext)) continue;

        try {
          const stats = fs.statSync(fullPath);
          if (stats.size > 2 * 1024 * 1024) continue; // Skip files > 2MB

          fileCount++;
          const content = fs.readFileSync(fullPath, 'utf8');
          const fileFindings = auditFileContent(fullPath, content, relPath);
          allFindings.push(...fileFindings);
        } catch {
          // File read error skip
        }
      }
    }
  }

  traverse(dir);
  return { findings: allFindings, fileCount };
}

// Helper to sanitize remote git url for secure cloning
function buildAuthenticatedUrl(repoUrl: string, token?: string, username?: string): { safeUrl: string; sanitizedDisplayUrl: string } {
  const cleanUrl = repoUrl.trim().replace(/\/+$/, '');
  
  // Clean display URL (never displays credentials)
  const sanitizedDisplayUrl = cleanUrl.replace(/:\/\/[^@]+@/, '://');

  if (!token || !token.trim()) {
    return { safeUrl: cleanUrl, sanitizedDisplayUrl };
  }

  const cleanToken = token.trim();
  const cleanUser = username?.trim() || '';

  try {
    const urlObj = new URL(sanitizedDisplayUrl);
    if (urlObj.hostname.includes('github.com')) {
      // GitHub PAT format
      urlObj.username = 'x-access-token';
      urlObj.password = cleanToken;
    } else if (urlObj.hostname.includes('bitbucket.org')) {
      // Bitbucket App Password / Token format
      if (cleanUser) {
        urlObj.username = cleanUser;
        urlObj.password = cleanToken;
      } else {
        urlObj.username = 'x-token-auth';
        urlObj.password = cleanToken;
      }
    } else if (urlObj.hostname.includes('gitlab.com')) {
      urlObj.username = 'oauth2';
      urlObj.password = cleanToken;
    } else {
      urlObj.username = cleanUser || 'oauth2';
      urlObj.password = cleanToken;
    }
    return { safeUrl: urlObj.toString(), sanitizedDisplayUrl };
  } catch {
    // Fallback URL manipulation
    return { safeUrl: cleanUrl, sanitizedDisplayUrl };
  }
}

// ==============================================================================
// 2. REMOTE GIT SCANNER ENDPOINT (POST /api/scan/remote-git)
// ==============================================================================

export const scanRemoteGitRepo = async (req: Request, res: Response) => {
  const startTime = Date.now();
  const { 
    repoUrl, 
    provider = 'github', 
    token, 
    username, 
    branch = 'main'
  } = req.body;

  if (!repoUrl || typeof repoUrl !== 'string') {
    return res.status(400).json({ error: 'Valid Git repository URL is required (e.g. https://github.com/org/repo).' });
  }

  // Basic security check on repoUrl to prevent command injection
  if (!/^https?:\/\/[a-zA-Z0-9_\-\.\:\@\/]+$/.test(repoUrl.trim())) {
    return res.status(400).json({ error: 'Invalid repository URL format. Please provide a standard HTTPS git URL.' });
  }

  const { safeUrl, sanitizedDisplayUrl } = buildAuthenticatedUrl(repoUrl, token, username);
  
  // Extract clean repository name
  const urlParts = sanitizedDisplayUrl.split('/').filter(Boolean);
  const repoName = urlParts.length >= 2 ? `${urlParts[urlParts.length - 2]}/${urlParts[urlParts.length - 1].replace(/\.git$/i, '')}` : urlParts[urlParts.length - 1] || 'git-repo';

  // Create isolated ephemeral directory
  const scanId = 'git-' + crypto.randomUUID().substring(0, 10);
  const tmpDir = path.join(os.tmpdir(), `qs-git-scan-${scanId}`);

  try {
    fs.mkdirSync(tmpDir, { recursive: true });

    // Step 1: Execute shallow git clone
    await new Promise<void>((resolve, reject) => {
      const gitArgs = ['clone', '--depth', '1'];
      if (branch && branch.trim()) {
        gitArgs.push('--branch', branch.trim());
      }
      gitArgs.push(safeUrl, tmpDir);

      execFile('git', gitArgs, {
        timeout: 60000, // 60s timeout
        env: {
          ...process.env,
          GIT_TERMINAL_PROMPT: '0', // Do not prompt for password
          GIT_ASKPASS: 'echo'
        }
      }, (error, stdout, stderr) => {
        if (error) {
          // Sanitize any token from error message
          const sanitizedErr = (stderr || error.message || 'Git clone failed')
            .replace(/https?:\/\/[^@]+@/gi, 'https://***@');
          
          // If branch was specified and failed, retry default branch clone
          if (branch && branch !== 'master' && (sanitizedErr.includes('Remote branch') || sanitizedErr.includes('not found'))) {
            // Attempt fallback to default branch
            execFile('git', ['clone', '--depth', '1', safeUrl, tmpDir], {
              timeout: 60000,
              env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: 'echo' }
            }, (fallbackErr, fbStdout, fbStderr) => {
              if (fallbackErr) {
                const fbSanitized = (fbStderr || fallbackErr.message).replace(/https?:\/\/[^@]+@/gi, 'https://***@');
                return reject(new Error(fbSanitized));
              }
              resolve();
            });
            return;
          }

          return reject(new Error(sanitizedErr));
        }
        resolve();
      });
    });

    // Step 2: Extract latest commit metadata
    let commitHash = '';
    let commitAuthor = '';
    let commitMessage = '';

    try {
      commitHash = fs.readFileSync(path.join(tmpDir, '.git', 'FETCH_HEAD'), 'utf8').substring(0, 40);
    } catch {
      try {
        commitHash = fs.readFileSync(path.join(tmpDir, '.git', 'HEAD'), 'utf8').trim();
      } catch {
        commitHash = 'HEAD';
      }
    }

    // Step 3: Run cryptographic discovery engine across the tree
    const { findings, fileCount } = crawlAndAuditDirectory(tmpDir, tmpDir);

    // Step 4: Calculate Quantum Risk Metrics
    const criticalCount = findings.filter(f => f.riskLevel === 'critical').length;
    const highCount = findings.filter(f => f.riskLevel === 'high').length;
    const mediumCount = findings.filter(f => f.riskLevel === 'medium').length;
    const lowCount = findings.filter(f => f.riskLevel === 'low').length;
    const pqcCount = findings.filter(f => f.riskLevel === 'secure').length;
    const vulnerableCount = findings.filter(f => f.isVulnerable).length;

    // Score from 0 (PQC Secure) to 100 (Max Vulnerable)
    let rawScore = (criticalCount * 25) + (highCount * 12) + (mediumCount * 5) + (lowCount * 2);
    // Mitigate score if PQC algorithms are already adopted
    if (pqcCount > 0) {
      rawScore = Math.max(10, rawScore - (pqcCount * 15));
    }
    const quantumRiskScore = vulnerableCount === 0 ? 5 : Math.min(100, Math.max(15, rawScore));

    let cnsaStatus: 'Non-Compliant' | 'Partially Compliant' | 'PQC Ready' = 'Non-Compliant';
    if (vulnerableCount === 0 && pqcCount > 0) {
      cnsaStatus = 'PQC Ready';
    } else if (pqcCount > 0) {
      cnsaStatus = 'Partially Compliant';
    }

    const durationMs = Date.now() - startTime;

    const summary: GitScanSummary = {
      id: scanId,
      provider: provider as any,
      repoUrl: sanitizedDisplayUrl,
      repoName,
      branch,
      commitHash: commitHash.substring(0, 8),
      commitAuthor: commitAuthor || 'Git Operator',
      commitMessage: commitMessage || 'Repository Snapshot Scan',
      scannedAt: new Date().toISOString(),
      scanDurationMs: durationMs,
      totalFilesScanned: fileCount,
      totalAssets: findings.length,
      vulnerableCount,
      pqcCount,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      quantumRiskScore,
      cnsaStatus,
      findings
    };

    // Cache in memory
    recentScansCache.unshift(summary);
    if (recentScansCache.length > 50) recentScansCache.pop();

    // Persist in DB if available
    try {
      await pool.query(`
        INSERT INTO git_scans (
          id, provider, repo_url, repo_name, branch, commit_hash,
          quantum_risk_score, total_assets, vulnerable_count, pqc_count,
          critical_count, high_count, medium_count, summary_text, findings, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW())
        ON CONFLICT (id) DO NOTHING
      `, [
        summary.id,
        summary.provider,
        summary.repoUrl,
        summary.repoName,
        summary.branch,
        summary.commitHash,
        summary.quantumRiskScore,
        summary.totalAssets,
        summary.vulnerableCount,
        summary.pqcCount,
        summary.criticalCount,
        summary.highCount,
        summary.mediumCount,
        `Audited ${fileCount} files in ${durationMs}ms. Found ${vulnerableCount} quantum-vulnerable items and ${pqcCount} PQC items.`,
        JSON.stringify(findings)
      ]);
    } catch (dbErr) {
      console.warn('Could not persist git_scan into PostgreSQL (table might be initializing):', dbErr);
    }

    return res.status(200).json({
      success: true,
      summary
    });

  } catch (err: any) {
    console.error('Git scan error:', err);
    return res.status(500).json({ 
      error: 'Failed to scan remote repository: ' + (err.message || 'Unknown error occurred during clone or audit.') 
    });
  } finally {
    // Guaranteed cleanup of temporary clone directory
    try {
      if (fs.existsSync(tmpDir)) {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    } catch (cleanupErr) {
      console.warn('Failed to cleanup tmp dir:', cleanupErr);
    }
  }
};

// ==============================================================================
// 3. RETRIEVE RECENT REPO SCANS (GET /api/scan/remote-git/history)
// ==============================================================================

export const getGitScanHistory = async (req: Request, res: Response) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, provider, repo_url as "repoUrl", repo_name as "repoName", branch,
        commit_hash as "commitHash", quantum_risk_score as "quantumRiskScore",
        total_assets as "totalAssets", vulnerable_count as "vulnerableCount",
        pqc_count as "pqcCount", critical_count as "criticalCount",
        high_count as "highCount", medium_count as "mediumCount",
        summary_text as "summaryText", created_at as "scannedAt"
      FROM git_scans
      ORDER BY created_at DESC
      LIMIT 20
    `);

    if (result.rows && result.rows.length > 0) {
      return res.json(result.rows);
    }
  } catch (dbErr) {
    console.warn('DB read for git_scans failed, returning cached scans:', dbErr);
  }

  // Fallback to memory cache
  const list = recentScansCache.map(s => ({
    id: s.id,
    provider: s.provider,
    repoUrl: s.repoUrl,
    repoName: s.repoName,
    branch: s.branch,
    commitHash: s.commitHash,
    quantumRiskScore: s.quantumRiskScore,
    totalAssets: s.totalAssets,
    vulnerableCount: s.vulnerableCount,
    pqcCount: s.pqcCount,
    criticalCount: s.criticalCount,
    highCount: s.highCount,
    mediumCount: s.mediumCount,
    summaryText: `Audited ${s.totalFilesScanned} files. Found ${s.vulnerableCount} vulnerable assets.`,
    scannedAt: s.scannedAt
  }));

  return res.json(list);
};

// ==============================================================================
// 4. EXPORT CYCLONEDX 1.6 CBOM (POST /api/scan/remote-git/export-cbom)
// ==============================================================================

export const exportGitCBOM = async (req: Request, res: Response) => {
  try {
    const { summary } = req.body;
    if (!summary || !summary.findings) {
      return res.status(400).json({ error: 'Scan summary payload with findings is required.' });
    }

    const cbom = {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      serialNumber: `urn:uuid:${crypto.randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: {
          components: [
            {
              type: "application",
              author: "QuarkShield Security",
              name: "quarkshield-git-auditor",
              version: "2.0.0"
            }
          ]
        },
        component: {
          type: "application",
          name: summary.repoName || "Git Repository",
          description: `Cryptographic Bill of Materials (CBOM) generated from remote repository: ${summary.repoUrl}`
        }
      },
      components: (summary.findings as GitFinding[]).map((f: GitFinding) => ({
        type: "cryptographic-asset",
        bomRef: f.id,
        name: f.assetName,
        cryptoProperties: {
          assetType: f.category === 'private_key' ? 'key' : (f.category === 'certificate' ? 'certificate' : 'algorithm'),
          algorithmProperties: {
            name: f.algorithm,
            keyLength: f.keySize || undefined,
            curve: f.curve || undefined,
            quantumSecurityLevel: f.isVulnerable ? 0 : 3
          },
          detectionContext: {
            filePath: f.filePath,
            lineNumber: f.lineNumber,
            repository: summary.repoUrl
          }
        },
        properties: [
          { name: "pqc:status", value: f.status },
          { name: "pqc:riskLevel", value: f.riskLevel },
          { name: "pqc:quantumThreat", value: f.quantumThreat },
          { name: "pqc:recommendation", value: f.recommendation },
          { name: "pqc:complianceViolations", value: JSON.stringify(f.complianceStandards || []) }
        ]
      }))
    };

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${(summary.repoName || 'repo').replace(/[\/\\]/g, '_')}_CBOM_CycloneDX.json"`);
    return res.json(cbom);

  } catch (err: any) {
    console.error('Error generating Git CBOM:', err);
    return res.status(500).json({ error: 'Failed to generate CycloneDX CBOM.' });
  }
};
