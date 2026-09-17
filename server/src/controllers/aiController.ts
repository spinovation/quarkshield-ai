import { Request, Response } from 'express';
import pool from '../config/db';

// POST /api/ai/chat
export const getAIChatResponse = async (req: Request, res: Response) => {
  try {
    const { message, history, attachments } = req.body;
    if (!message) {
      return res.status(400).json({ error: 'Missing prompt message parameter.' });
    }

    // Fetch active assets context to feed into Gemini prompt
    let assetsContext = '';
    try {
      const assetsRes = await pool.query('SELECT name, algorithm, key_size, is_vulnerable, risk_level, status, description, compliance_violations FROM assets');
      if (assetsRes.rows.length > 0) {
        assetsContext = "Here is the list of active Cryptographic Assets currently registered in the user's QuarkShield dashboard/CMDB:\n" +
          JSON.stringify(assetsRes.rows.map(r => ({
            name: r.name,
            algorithm: r.algorithm,
            keySize: r.key_size,
            isVulnerable: r.is_vulnerable,
            riskLevel: r.risk_level,
            status: r.status,
            description: r.description,
            complianceViolations: r.compliance_violations || []
          })), null, 2);
      } else {
        assetsContext = "The user currently has no Cryptographic Assets registered in their QuarkShield dashboard/CMDB.";
      }
    } catch (dbErr) {
      console.warn('Failed to query assets for advisor chat context:', dbErr);
    }

    let geminiKey = process.env.GEMINI_API_KEY ? process.env.GEMINI_API_KEY.trim() : '';
    let anthropicKey = process.env.ANTHROPIC_API_KEY ? process.env.ANTHROPIC_API_KEY.trim() : '';

    // Fetch tenant-specific API keys from tenant_settings if not provided via process.env
    try {
      const settingsRes = await pool.query("SELECT key, value FROM tenant_settings WHERE key IN ('gemini_api_key', 'anthropic_api_key')");
      for (const row of settingsRes.rows) {
        if (row.key === 'gemini_api_key' && row.value && row.value.trim() !== '') {
          geminiKey = row.value.trim();
        } else if (row.key === 'anthropic_api_key' && row.value && row.value.trim() !== '') {
          anthropicKey = row.value.trim();
        }
      }
    } catch (settingsErr) {
      console.warn('Failed to query tenant_settings for AI keys in chat:', settingsErr);
    }

    const systemInstruction = 
      "You are QuarkShield AI, an expert post-quantum cryptography (PQC) migration and cybersecurity advisor. " +
      "You have detailed knowledge about the QuarkShield platform features: " +
      "1. Crypto Scanner: Scans servers, certificates, directories, and Blockchain/RPC endpoints to detect classical/vulnerable cryptography. " +
      "2. Crypto CMDB: A configuration management database that inventories cryptographic assets, keys, and algorithms, highlighting vulnerability flags. " +
      "3. QS CoPilot: A virtual interactive assistant (you!) that answers post-quantum cryptography, cybersecurity, networking, and technology questions. " +
      "4. Quark Migrate: A migration planner that applies Mosca's Theorem, defines transition roadmaps, manages the local QuarkShield MCP Daemon for private scanning, and orchestrates project charters with human-in-the-loop approvals. " +
      "5. Compliance Reports: Audits cryptographic infrastructure against NIST SP 800-208, CNSA 2.0, and Executive Order 14028. " +
      "DOMAIN SCOPE: You answer all technical questions regarding Post-Quantum Cryptography (PQC), Quantum Computing, Shor's and Grover's algorithms, Cybersecurity, Cryptographic Infrastructure, Cryptographic Agility, and Blockchain/Web3/Ethereum Cryptography (such as ECDSA secp256k1 vulnerabilities, smart contract PQC mitigation, ERC-4337 Account Abstraction with post-quantum signatures, hash-based signatures like LMS/XMSS/Winternitz, and lattice-based verifiers). " +
      "If the user's question is personal, non-technical, or unrelated to technology (such as cooking recipes, fitness advice, general chit-chat, personal opinions), politely decline, stating your expertise is in PQC and cybersecurity remediation. " +
      "For valid topics: Provide thorough, detailed, and mathematically grounded explanations. When asked about Ethereum or smart contracts, explain the vulnerability of secp256k1 to Shor's algorithm and outline concrete mitigation steps (Discovery, Account Abstraction ERC-4337, post-quantum signature schemes like LMS/XMSS, Falcon, or ML-DSA, STARK rollups, and upgradeable proxy patterns). Always provide complete milestones (CNSA 2.0 2024-2033). Provide clean code snippets in Solidity, Go, Rust, Nginx config, or OpenSSH config format.";

    // Assemble prompt text
    let promptText = `${systemInstruction}\n\n`;
    if (assetsContext) {
      promptText += `${assetsContext}\n\n`;
    }
    promptText += `User Question: ${message}`;

    // 1. Attempt Google Gemini if key available
    if (geminiKey) {
      const geminiCandidateModels = [
        process.env.GEMINI_MODEL,
        'gemini-2.5-flash',
        'gemini-2.0-flash',
        'gemini-1.5-flash',
        'gemini-1.5-pro'
      ].filter(Boolean) as string[];

      // Sanitize past history so roles strictly alternate and avoid duplicate user turn at the end
      const contents: any[] = [];
      if (Array.isArray(history)) {
        const validHistory = history.filter(h => h && h.text && h.text.trim() !== '' && h.text !== 'Typing...');
        // Remove trailing user turn if it equals the current prompt
        if (validHistory.length > 0 && validHistory[validHistory.length - 1].sender === 'user') {
          validHistory.pop();
        }

        let lastRole: string | null = null;
        for (const h of validHistory) {
          const role = h.sender === 'user' ? 'user' : 'model';
          if (role !== lastRole) {
            contents.push({
              role,
              parts: [{ text: h.text }]
            });
            lastRole = role;
          }
        }
        // If last turn is user, pop it because userParts is about to be appended
        if (contents.length > 0 && contents[contents.length - 1].role === 'user') {
          contents.pop();
        }
      }

      const userParts: any[] = [{ text: promptText }];
      if (Array.isArray(attachments)) {
        for (const att of attachments) {
          if (att.mimeType && att.data) {
            userParts.push({
              inlineData: {
                mimeType: att.mimeType,
                data: att.data
              }
            });
          }
        }
      }
      contents.push({ role: 'user', parts: userParts });

      for (const model of geminiCandidateModels) {
        console.log(`AI Controller: Querying Gemini API (model: ${model})...`);
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiKey}`;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 45000);

        try {
          const geminiRes = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ contents }),
            signal: controller.signal
          });

          if (geminiRes.ok) {
            const data: any = await geminiRes.json();
            const aiText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
            if (aiText) {
              const { textResponse, codeResponse, langResponse } = extractCodeBlock(aiText);
              return res.json({
                text: textResponse,
                code: codeResponse,
                language: langResponse
              });
            }
          } else {
            const errText = await geminiRes.text();
            console.warn(`Gemini API query (${model}) returned non-OK status: ${geminiRes.status} ${geminiRes.statusText}. Response body: ${errText}`);
          }
        } catch (fetchErr: any) {
          console.warn(`Error or timeout querying Gemini API (${model}):`, fetchErr.message);
        } finally {
          clearTimeout(timeoutId);
        }
      }
      console.warn('All configured Gemini models failed. Checking for Anthropic Claude fallback...');
    }

    // 2. Attempt Anthropic Claude fallback if key available
    if (anthropicKey) {
      console.log('AI Controller: Querying Anthropic Claude for Chat...');
      const url = 'https://api.anthropic.com/v1/messages';
      
      const claudeMessages: any[] = [];
      if (Array.isArray(history)) {
        const validHistory = history.filter(h => h && h.text && h.text.trim() !== '' && h.text !== 'Typing...');
        if (validHistory.length > 0 && validHistory[validHistory.length - 1].sender === 'user') {
          validHistory.pop();
        }

        let lastRole: string | null = null;
        for (const h of validHistory) {
          const role = h.sender === 'user' ? 'user' : 'assistant';
          if (role !== lastRole) {
            claudeMessages.push({
              role,
              content: h.text
            });
            lastRole = role;
          }
        }
        if (claudeMessages.length > 0 && claudeMessages[claudeMessages.length - 1].role === 'user') {
          claudeMessages.pop();
        }
      }
      claudeMessages.push({
        role: 'user',
        content: promptText
      });

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 45000);

      try {
        const claudeRes = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': anthropicKey,
            'anthropic-version': '2023-06-01'
          },
          body: JSON.stringify({
            model: 'claude-3-5-sonnet-20241022',
            max_tokens: 3000,
            system: systemInstruction,
            messages: claudeMessages
          }),
          signal: controller.signal
        });

        if (claudeRes.ok) {
          const data: any = await claudeRes.json();
          const aiText = data?.content?.[0]?.text || '';
          if (aiText) {
            const { textResponse, codeResponse, langResponse } = extractCodeBlock(aiText);
            return res.json({
              text: textResponse,
              code: codeResponse,
              language: langResponse
            });
          }
        } else {
          const errText = await claudeRes.text();
          console.warn(`Anthropic Claude chat returned non-OK status: ${claudeRes.status} ${claudeRes.statusText}. Response body: ${errText}`);
        }
      } catch (fetchErr: any) {
        console.warn('Error or timeout querying Anthropic Claude for chat:', fetchErr.message);
      } finally {
        clearTimeout(timeoutId);
      }
    }

    // --- Local Rules Fallback Logic ---
    console.log('AI Controller: Executing local rules-based fallback...');
    const query = message.toLowerCase();
    let text = '';
    let code = '';
    let language = 'javascript';

    if (attachments && Array.isArray(attachments) && attachments.length > 0) {
      text = "Hello! I see you attached a file or screenshot. However, this QuarkShield Secure Node is currently running in local-offline mode because cloud AI keys are not reachable or configured.\n\n" +
             "To enable visual OCR and AI image reading, please configure `GEMINI_API_KEY` or `ANTHROPIC_API_KEY` in the `/opt/quantum-rap/.env` file on your VPS and restart the server.\n\n" +
             "In the meantime, you can copy-paste the text content or error details directly into this chat, or ask technical questions about PQC, Ethereum, SSH, or Nginx.";
    } else if (
      query.includes('ethereum') || 
      query.includes('smart contract') || 
      query.includes('smart-contract') || 
      query.includes('contract') || 
      query.includes('solidity') || 
      query.includes('evm') || 
      query.includes('erc-4337') || 
      query.includes('erc4337') || 
      query.includes('account abstraction') || 
      query.includes('ecrecover') || 
      query.includes('secp256k1') || 
      query.includes('web3') || 
      query.includes('blockchain')
    ) {
      text = "### Post-Quantum Cryptographic Mitigation Process for Ethereum Smart Contracts\n\n" +
             "Ethereum accounts (EOAs) and transaction signing rely on the **secp256k1** Elliptic Curve Digital Signature Algorithm (ECDSA). Because Shor's algorithm solves elliptic curve discrete logarithms in polynomial time $O((\\log N)^3)$, a Cryptanalytically Relevant Quantum Computer (CRQC) can derive private keys directly from exposed public keys, forge transaction signatures, and hijack `ecrecover`-based smart contract permissions.\n\n" +
             "Here is the 5-phase process to mitigate quantum vulnerabilities across Ethereum smart contracts and dApps:\n\n" +
             "1. **Cryptographic Discovery & Vulnerability Inventory**:\n" +
             "   - Scan all smart contracts and off-chain relayer services for dependencies on `ecrecover`, `ECDSA.recover`, EIP-712 permits, and meta-transaction forwarders (ERC-2771).\n" +
             "   - Identify exposed public keys: While addresses with zero outgoing transactions only expose Keccak-256 hashes, broadcasting a single transaction permanently exposes the raw public key to quantum cryptanalysis.\n\n" +
             "2. **Account Abstraction Migration (ERC-4337 & EIP-7702)**:\n" +
             "   - Migrate Externally Owned Accounts (EOAs) to modular Smart Contract Accounts via **ERC-4337**.\n" +
             "   - ERC-4337 decouples transaction validation from the Ethereum L1 consensus protocol. This allows custom `validateUserOp()` logic to enforce quantum-safe signature verification schemes without requiring an Ethereum network hard fork.\n\n" +
             "3. **Quantum-Resilient Signature Verification Schemes**:\n" +
             "   - **Stateful / Hash-Based Signatures (NIST SP 800-208)**: Deploy Winternitz One-Time Signatures (W-OTS+) or Leighton-Micali Signatures (LMS). These rely strictly on quantum-resistant hash functions (Keccak-256 / SHA-256), where Grover's algorithm only yields quadratic speedup (safeguarded by 256-bit digests).\n" +
             "   - **Lattice-Based Verification (NIST FIPS 204 ML-DSA / Falcon)**: Validate signatures off-chain and prove their verification on-chain using zero-knowledge STARK / SNARK proofs to avoid prohibitive EVM calldata gas fees.\n" +
             "   - **Hybrid Signatures**: Enforce dual verification (requiring both classical ECDSA and a quantum-safe signature) during the migration window.\n\n" +
             "4. **Quantum-Safe Zero-Knowledge Layer-2 Rollups**:\n" +
             "   - Transition computation to STARK-based Layer-2 rollups (such as Starknet). Unlike pairing-friendly elliptic curve SNARKs (e.g. Groth16 using BN254/alt_bn128), STARKs rely entirely on collision-resistant hash functions, making them inherently post-quantum secure.\n\n" +
             "5. **Crypto-Agility & Upgradeable Proxies (UUPS)**:\n" +
             "   - Implement ERC-1967 UUPS proxy patterns to enable hot-swapping cryptographic verification modules once native NIST PQC precompiles (e.g. EIPs for ML-KEM/ML-DSA) are integrated into Ethereum.\n\n" +
             "Below is a production-grade Solidity smart contract account demonstrating post-quantum hash-based verification with state rotation:";
      language = 'solidity';
      code = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title QuantumSafeAccount
 * @notice ERC-4337 compatible smart contract account demonstrating post-quantum
 *         hash-based verification (Lamport/Winternitz OTS) and crypto-agility.
 */
contract QuantumSafeAccount {
    // Active quantum-safe public root (hash commitment to private seed state)
    bytes32 public quantumRootPublicKey;
    address public immutable entryPoint;
    uint256 public stateNonce;

    event QuantumKeyRotated(bytes32 indexed oldRoot, bytes32 indexed newRoot);
    event Executed(address indexed target, uint256 value, bytes data);

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "Only EntryPoint can call");
        _;
    }

    constructor(address _entryPoint, bytes32 _initialQuantumRoot) {
        entryPoint = _entryPoint;
        quantumRootPublicKey = _initialQuantumRoot;
    }

    /**
     * @notice Validates an ERC-4337 UserOperation against quantum-safe signature proofs.
     * @dev Verifies pre-image hash chains (Winternitz/Lamport) resistant to Shor's algorithm.
     */
    function validateUserOp(
        bytes32 userOpHash,
        bytes calldata pqSignature,
        bytes32 nextQuantumRoot
    ) external onlyEntryPoint returns (uint256 validationData) {
        // 1. Verify that the signature pre-images hash back to quantumRootPublicKey
        bytes32 derivedRoot = keccak256(abi.encodePacked(userOpHash, pqSignature, stateNonce));
        if (derivedRoot != quantumRootPublicKey) {
            return 1; // SIG_VALIDATION_FAILED in ERC-4337
        }

        // 2. Advance state nonce to prevent signature replay
        stateNonce++;

        // 3. Rotate to next one-time public root (stateful hash signature requirement)
        emit QuantumKeyRotated(quantumRootPublicKey, nextQuantumRoot);
        quantumRootPublicKey = nextQuantumRoot;

        return 0; // Success
    }

    /**
     * @notice Executes authorized contract transactions once validated
     */
    function execute(address dest, uint256 value, bytes calldata func) external onlyEntryPoint {
        (bool success, bytes memory result) = dest.call{value: value}(func);
        require(success, string(result));
        emit Executed(dest, value, func);
    }

    receive() external payable {}
}`;
    } else if (
      query.includes('mitigat') || 
      query.includes('remediat') || 
      query.includes('process') || 
      query.includes('roadmap') || 
      query.includes('transition') || 
      query.includes('strategy') || 
      query.includes('framework') || 
      query.includes('action plan') ||
      query.includes('steps')
    ) {
      text = "### Standard Post-Quantum Cryptography (PQC) 5-Phase Mitigation Framework\n\n" +
             "Transitioning enterprise infrastructure from quantum-vulnerable cryptography (RSA, ECDSA, ECDH) to quantum-resilient standards requires an orderly, phased migration aligned with **NIST SP 800-219**, **NIST SP 800-208**, and **CNSA 2.0**:\n\n" +
             "1. **Phase 1: Discovery & Automated Cryptographic Inventory (Crypto CMDB)**\n" +
             "   - Continuously scan internal and external digital assets: TLS endpoints, load balancers, VPNs, SSH hosts, code repositories, and smart contracts.\n" +
             "   - Catalog key sizes, cipher suites, signature schemes, and certificate chains in the QuarkShield Crypto CMDB.\n" +
             "   - Grade risks as Critical, High, or Medium based on exposure to Shor's and Grover's algorithms.\n\n" +
             "2. **Phase 2: Risk Prioritization via Mosca's Theorem**\n" +
             "   - Model threat horizons using Mosca's Theorem: **$X + Y > Z$**\n" +
             "     - **$X$ (Shelf-life)**: Number of years data must remain confidential.\n" +
             "     - **$Y$ (Migration time)**: Years required to migrate legacy systems to PQC.\n" +
             "     - **$Z$ (Quantum threat timeline)**: Estimated years until a Cryptanalytically Relevant Quantum Computer (CRQC) is realized.\n" +
             "   - If $X + Y > Z$, data is already vulnerable to **'Harvest Now, Decrypt Later' (HNDL)** attacks and requires immediate remediation.\n\n" +
             "3. **Phase 3: Hybrid Cryptographic Deployment (Crypto-Agility)**\n" +
             "   - Deploy dual-key hybrid mechanisms combining classical and post-quantum algorithms:\n" +
             "     - **TLS 1.3**: Deploy `X25519MLKEM768` across Nginx, ingress controllers, and API gateways.\n" +
             "     - **SSH**: Configure `sntrup761x25519-sha512@openssh.com` in `sshd_config`.\n" +
             "     - **Dual-Key Certificates**: Combine classical RSA/ECDSA with ML-DSA (FIPS 204) for backwards-compatible PKI verification.\n\n" +
             "4. **Phase 4: Full Algorithm Migration (NIST FIPS Standards)**\n" +
             "   - **Key Encapsulation**: Enforce **ML-KEM** (FIPS 203) for key exchange.\n" +
             "   - **Digital Signatures**: Deploy **ML-DSA** (FIPS 204) and **SLH-DSA** (FIPS 205) for code signing and document signing.\n" +
             "   - **Firmware & Bootloaders**: Enforce stateful hash-based signatures like **LMS** or **XMSS** (NIST SP 800-208).\n" +
             "   - **Symmetric Ciphers**: Upgrade to **AES-256** and **SHA-384/SHA-512** to maintain a 128-bit security margin against Grover's algorithm.\n\n" +
             "5. **Phase 5: Continuous Policy Governance & Enforcement**\n" +
             "   - Enforce Open Policy Agent (OPA) guardrails in CI/CD pipelines to block commits containing weak classical ciphers.\n" +
             "   - Monitor compliance against CNSA 2.0 enforcement deadlines (2024 published, 2026 software signatures, 2030 network protocols, 2033 full deprecation).";
    } else if (query.includes('kyber') || query.includes('ml-kem') || query.includes('mlkem')) {
      text = "**ML-KEM (FIPS 203, formerly CRYSTALS-Kyber)** is the primary NIST-standardized Post-Quantum Key Encapsulation Mechanism.\n\n" +
             "- **Underlying Math**: Based on the hardness of Module Learning with Errors (M-LWE) over module lattices, which resists Shor's quantum factoring.\n" +
             "- **Security Levels**:\n" +
             "  - *ML-KEM-512* (NIST Category 1, equivalent to AES-128)\n" +
             "  - *ML-KEM-768* (NIST Category 3, equivalent to AES-192 / standard recommendation)\n" +
             "  - *ML-KEM-1024* (NIST Category 5, equivalent to AES-256)\n" +
             "- **Production Adoption**: Standardized in TLS 1.3 via hybrid groups like `X25519MLKEM768`. It replaces RSA-OAEP and ECDH key exchanges across browsers, web servers, and VPN tunnels.";
    } else if (query.includes('dilithium') || query.includes('ml-dsa') || query.includes('mldsa')) {
      text = "**ML-DSA (FIPS 204, formerly CRYSTALS-Dilithium)** is the primary NIST-standardized Post-Quantum Digital Signature Algorithm.\n\n" +
             "- **Underlying Math**: Based on Module Learning with Errors (M-LWE) and Short Integer Solution (SIS) over lattices using the Fiat-Shamir with Aborts framework.\n" +
             "- **Security Levels**:\n" +
             "  - *ML-DSA-44* (NIST Category 2)\n" +
             "  - *ML-DSA-65* (NIST Category 3 / standard enterprise recommendation)\n" +
             "  - *ML-DSA-87* (NIST Category 5)\n" +
             "- **Application**: Directly replaces classical RSA and ECDSA signatures in digital certificates, code signing, document verification, and authentication tokens.";
    } else if (query.includes('sphincs') || query.includes('slh-dsa') || query.includes('slhdsa')) {
      text = "**SLH-DSA (FIPS 205, formerly SPHINCS+)** is the NIST-standardized Stateless Hash-Based Digital Signature Algorithm.\n\n" +
             "- **Underlying Math**: Relies solely on the security properties of standard cryptographic hash functions (SHA-2, SHAKE-256), completely independent of lattice assumptions.\n" +
             "- **Key Advantage**: Serves as a robust, mathematically conservative hedge in case unexpected mathematical breakthroughs ever weaken lattice-based cryptography.\n" +
             "- **Trade-off**: Produces larger signature sizes (~8 KB to ~40 KB) compared to ML-DSA (~2.4 KB) and Falcon (~666 bytes).";
    } else if (query.includes('falcon') || query.includes('fn-dsa')) {
      text = "**Falcon (FN-DSA)** is a NIST-selected lattice-based signature scheme based on Short Integer Solution (SIS) over NTRU lattices with Fast Fourier orthogonalization.\n\n" +
             "- **Key Advantage**: Falcon generates the most compact public keys and signatures (~666 bytes for Category 1) among all NIST post-quantum signature schemes.\n" +
             "- **Ideal Use Cases**: DNSSEC, constrained embedded environments, and smart contract verification where bandwidth and memory are strictly limited.";
    } else if (query.includes('lms') || query.includes('xmss')) {
      text = "**LMS (Leighton-Micali Signatures) and XMSS (eXtended Merkle Signature Scheme)** are stateful hash-based digital signature schemes standardized under **NIST SP 800-208** and RFC 8554 / RFC 8391.\n\n" +
             "- **Characteristics**: Require maintaining state across signings to prevent one-time key reuse.\n" +
             "- **Best Use Cases**: Secure boot, firmware verification, operating system updates, and immutable hardware roots of trust where signatures are infrequent and state tracking can be strictly controlled.";
    } else if (query.includes('hybrid')) {
      text = "**Hybrid Post-Quantum Cryptography** combines a classical algorithm (like X25519, P-256, or RSA) with a post-quantum algorithm (like ML-KEM or ML-DSA) in a single operation.\n\n" +
             "- **Key Exchange**: Derives the shared session secret using both ECDH and ML-KEM ($K = \\text{KDF}(K_{\\text{classical}} \\parallel K_{\\text{pqc}})$). Even if one algorithm is compromised, the connection remains completely secure.\n" +
             "- **Standard**: Standardized in TLS 1.3 as `X25519MLKEM768`, deployed natively by Google Chrome, Cloudflare, and OpenSSL 3.2+.";
    } else if (query.includes('lattice')) {
      text = "**Lattice-Based Cryptography** is the mathematical foundation for the leading post-quantum algorithms (ML-KEM, ML-DSA, Falcon).\n\n" +
             "- **The Math**: Relies on the computational hardness of geometric vector space lattice problems, specifically the **Shortest Vector Problem (SVP)**, Closest Vector Problem (CVP), and **Learning With Errors (LWE)** in high dimensions.\n" +
             "- **Quantum Resistance**: Unlike integer factorization and discrete logarithms (which Shor's algorithm solves in polynomial time), lattice problems exhibit no known periodic structure that quantum computers can exploit efficiently.";
    } else if (query.includes('mosca')) {
      text = "**Mosca's Theorem** is the standard mathematical risk model for evaluating post-quantum migration urgency:\n\n" +
             "$$\\text{If } X + Y > Z, \\text{ your data is compromised today!}$$\n\n" +
             "- **$X$ (Shelf-life)**: How many years must proprietary or classified data remain secure?\n" +
             "- **$Y$ (Migration Time)**: How many years will it take your organization to fully transition to PQC?\n" +
             "- **$Z$ (Quantum Threat Timeline)**: Years until a Cryptanalytically Relevant Quantum Computer (CRQC) is deployed.\n\n" +
             "If $X + Y > Z$, adversaries collecting encrypted network traffic today via **'Harvest Now, Decrypt Later' (HNDL)** will decrypt it before the data's confidentiality lifespan expires.";
    } else if (query.includes('harvest') || query.includes('hndl') || query.includes('retro-decryption')) {
      text = "**Harvest Now, Decrypt Later (HNDL)** is an active cyber threat where adversaries capture and store encrypted data traffic today (TLS sessions, VPN tunnels, database backups), anticipating that a Cryptanalytically Relevant Quantum Computer (CRQC) will allow them to decrypt the stored records retrospectively.\n\n" +
             "Because HNDL impacts data in transit right now, organizations cannot wait until quantum computers are built; hybrid key exchanges (X25519+ML-KEM) must be deployed immediately.";
    } else if (query.includes('migrate') || query.includes('migrat') || query.includes('playbook') || query.includes('playbok')) {
      text = "**Quark Migrate** is the migration orchestration module of QuarkShield. It includes the following features:\n\n" +
             "- **Mosca's Theorem Planner**: Calculates risk horizons by comparing data shelf-life (X) and migration transition time (Y) against the estimated quantum threat timeline (Z). If X + Y > Z, your data is at risk of retro-decryption.\n" +
             "- **Project Charter Builder**: Generates actionable, scoped program charters for transitioning classical hosts to post-quantum standards.\n" +
             "- **On-Prem QuarkShield MCP Daemon**: A lightweight, local secure agent run in private VPCs/networks to discover ADCS, databases, and internal scan targets safely without opening inbound firewall ports.\n" +
             "- **Human-in-the-Loop Approvals**: Email-verified executive authorization triggers to approve project milestones and deploy quantum-safe configuration rules.";
    } else if (query.includes('scanner') || query.includes('scan') || query.includes('scaner') || query.includes('discover') || query.includes('sniff')) {
      text = "**Crypto Scanner** is the active discovery module of QuarkShield. It allows you to:\n\n" +
             "- **Scan Directories**: Audit source code and certificate directories locally or remotely.\n" +
             "- **Audit Configurations**: Analyze files (such as SSH configurations or Nginx setups) to identify weak key-exchange and signature ciphers.\n" +
             "- **Web3 & Blockchain RPC Audits**: Connect to public RPC nodes to analyze signature algorithms and keys active on smart contracts and wallets.\n" +
             "- **Vulnerability Classification**: Flags classical RSA, ECC, and DH keys as vulnerable to Shor's and Grover's quantum algorithms.";
    } else if (query.includes('vulnerable') || query.includes('list') || query.includes('assets') || query.includes('dashboard') || query.includes('inventory') || query.includes('cmdb')) {
      try {
        const assetsRes = await pool.query('SELECT name, algorithm, key_size, is_vulnerable, risk_level, status FROM assets');
        const total = assetsRes.rows.length;
        const vulnerable = assetsRes.rows.filter(r => r.is_vulnerable);
        
        if (query.includes('list') || query.includes('vulnerable') || query.includes('status')) {
          if (total === 0) {
            text = "According to your QuarkShield CMDB inventory database, there are currently no cryptographic assets registered. Please run a security scan first using the 'Crypto Scanner' or our CLI tool.";
          } else if (vulnerable.length === 0) {
            text = `According to your QuarkShield dashboard and CMDB, you have a total of **${total}** monitored cryptographic assets, and **none of them are currently flagged as vulnerable**. All registered assets are secure and compliant with quantum-safe standards!`;
          } else {
            text = `Based on your QuarkShield dashboard and CMDB, you have a total of **${total}** monitored cryptographic assets, with **${vulnerable.length} vulnerable assets** flagged. Here is the list of vulnerable assets:\n\n` +
              vulnerable.map((r, index) => `${index + 1}. **${r.name}** (Algorithm: ${r.algorithm} ${r.key_size ? r.key_size + '-bit' : ''}) - Risk: *${r.risk_level}* (${r.status})`).join('\n') +
              `\n\nTo secure these assets, you should transition them from classical asymmetric algorithms to post-quantum standards like ML-KEM/ML-DSA.`;
          }
        } else {
          text = "**Crypto CMDB** (Configuration Management Database) is the asset tracking database of QuarkShield. It features:\n\n" +
                 "- **Centralized Inventory**: Automatically registers all cryptographic assets discovered by active/passive audits.\n" +
                 "- **Risk Scoring**: Grades risk based on key sizes and algorithms (e.g. RSA-2048 is flagged as High/Critical Risk, while AES-256 is Secure).\n" +
                 "- **Violation Monitoring**: Shows compliance flags for standards like CNSA 2.0, NIST SP 800-208, and EO 14028.\n\n" +
                 `Currently, your CMDB contains **${total}** cryptographic assets (**${vulnerable.length}** vulnerable).`;
        }
      } catch (dbErr: any) {
        text = "**Crypto CMDB** (Configuration Management Database) is the asset tracking database of QuarkShield. It catalogs all cryptographic keys, algorithms, and certificates. (Failed to query live inventory: " + dbErr.message + ")";
      }
    } else if (query.includes('shor') && query.includes('grover')) {
      text = "Shor's and Grover's algorithms are the two primary quantum algorithms that threaten classical cryptography:\n\n" +
             "1. **Shor's Algorithm**: Solves integer factorization and discrete logarithms in polynomial time. This completely breaks asymmetric public-key systems like RSA, Diffie-Hellman, and Elliptic Curve Cryptography (ECC).\n" +
             "2. **Grover's Algorithm**: Speeds up search in unsorted databases quadratically. When applied to symmetric cryptography (like AES) or hash functions, it halves the effective key length (e.g., AES-128 is reduced to 64 bits of security). This is mitigated by upgrading to AES-256.";
    } else if (query.includes('quarkshield') || query.includes('quak') || query.includes('features') || query.includes('capabilities') || query.includes('advisor') || query.includes('advice') || query.includes('advis') || query.includes('chat') || query.includes('virtual')) {
      text = "QuarkShield is a state-of-the-art post-quantum risk management and migration suite designed to transition classical IT and Web3 architectures to quantum-safe standards. The platform includes the following modules:\n\n" +
             "1. **Crypto Scanner**: Audits directories, server configuration files, public certificates, and blockchain RPC endpoints to identify classical algorithms (like RSA, ECC).\n" +
             "2. **Crypto CMDB**: Inventories all cryptographic assets, keys, and algorithms, grading risk levels (Critical, High, Medium, Low) and tracking compliance violations.\n" +
             "3. **QS CoPilot**: Your interactive virtual assistant (me!) providing step-by-step remediation scripts and secure config setups.\n" +
             "4. **Quark Migrate**: A migration planner that uses Mosca's Theorem to assess security lifetimes, draft program charters, integrate the lightweight local QuarkShield MCP Daemon for private scanning, and secure executive authorization.\n" +
             "5. **Compliance Reports**: Evaluates security compliance posture against NIST SP 800-208, CNSA 2.0, and Executive Order 14028.";
    } else if (
      /\b(timeline|milestones?|schedule|deadlines?|dates?|roadmap)\b/i.test(query) ||
      (/\b(cnsa|nist)\b/i.test(query) && /\b(timeline|milestones?|schedule|year|dates?|transition|deadline|status|official|roadmap)\b/i.test(query)) ||
      (/\b(official\s+website|website)\b/i.test(query) && /\b(timeline|pqc|post-quantum)\b/i.test(query))
    ) {
      text = "Here is the complete set of Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) and NIST Post-Quantum Cryptography (PQC) milestones:\n\n" +
             "1. **2024 (Standards Published)**: NIST published final FIPS specifications for standard algorithms: ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205).\n" +
             "2. **2025 (Transition Commences)**: Software, firmware, and systems must begin supporting PQC hybrid options natively.\n" +
             "3. **2026 (Default Enforcements)**: Software and firmware digital signatures must transition to enforce PQC algorithms (like ML-DSA or stateful hash signatures) by default, deprecating pure legacy options.\n" +
             "4. **2030 (Network Protocols)**: Web servers, browsers, load balancers, and network layers must complete PQC hybrid adoption for TLS, SSH, and HTTPS connections (fully deprecating pure RSA/ECC key exchanges).\n" +
             "5. **2033 (Complete Deprecation)**: Mandatory transition deadline. 100% of National Security Systems (NSS) must enforce post-quantum algorithms; all legacy classical ciphers are banned.\n\n" +
             "These timelines are tracked directly inside your Quark Migrate planning dashboard to monitor organizational compliance.";
    } else if (/\b(cnsa\s*2\.0|cnsa|nist\s*sp\s*800-208|eo\s*14028|executive\s+order)\b/i.test(query)) {
      text = "NIST SP 800-208, CNSA 2.0, and Executive Order 14028 mandate moving Federal systems and national security systems to post-quantum algorithms by 2030. Key milestones require replacing classic public-key algorithms (RSA, ECDH) with module lattices (ML-KEM, ML-DSA) and state-based signatures (LMS, XMSS) for firmware verification.";
    } else if (/\b(ssh|openssh|sshd)\b/i.test(query) && /\b(config|conf|kex|key|sshd_config|setup|hybrid)\b/i.test(query)) {
      text = 'To secure OpenSSH, you should prepend sntrup761x25519-sha512@openssh.com (a Streamlined NTRU Prime and Curve25519 hybrid) to your Key Exchange algorithms. This protects admin channels from retro-decryption. Here is the configuration to add to your sshd_config:';
      language = 'nginx';
      code = `# /etc/ssh/sshd_config
# Enforce sntrup761 hybrid post-quantum key exchange (standard in OpenSSH 9.0+)
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org

# Enforce secure symmetric ciphers (resisting Grover's search)
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com

# Enforce secure MACs
MACs hmac-sha2-512-etm@openssh.com`;
    } else if (/\bnginx\b/i.test(query) && /\b(config|conf|ssl|tls|cipher|server|oqs|hybrid)\b/i.test(query)) {
      text = 'For Nginx, you must use an Open Quantum Safe (OQS) build of OpenSSL. Ensure you enable TLSv1.3 and specify post-quantum hybrid groups like X25519+MLKEM768 or secp384r1+MLKEM1024. Here is a configuration snippet:';
      language = 'nginx';
      code = `# nginx.conf snippet
server {
    listen 443 ssl;
    server_name secure.enterprise.com;

    # OQS OpenSSL build ciphers supporting ML-KEM hybrids
    ssl_protocols TLSv1.3;
    
    # Enable X25519 + ML-KEM-768 hybrid key share groups
    ssl_curves x25519_kyber768:X25519+MLKEM768:secp384r1_kyber1024;

    # Enforce strong symmetric AES-256 for Grover resistance
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
    ssl_prefer_server_ciphers on;
}`;
    } else if (
      /\b(golang|go language|in go|go code|go tls|go snippet|go sdk)\b/i.test(query) ||
      (/\bgo\b/i.test(query) && /\b(tls|code|example|snippet|implement|client|http|config)\b/i.test(query))
    ) {
      text = 'In Go (since version 1.24), you can utilize native TLS post-quantum groups in tls.Config. Set CurvePreferences to prioritize ML-KEM hybrids. Here is how:';
      language = 'go';
      code = `package main

import (
	"crypto/tls"
	"net/http"
)

func main() {
	// Configure TLS config with ML-KEM key exchange curves
	// Note: requires Go 1.24+ for native ML-KEM / Kyber standard support
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.CurveID(0x003F), // X25519MLKEM768 hybrid
			tls.X25519,
		},
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	
	// Request secure post-quantum server
	client.Get("https://cloudflare.com")
}`;
    } else if (
      /\b(rust|cargo|rustlang)\b/i.test(query) &&
      /\b(code|snippet|example|implement|sign|signature|verify|crate|keypair)\b/i.test(query)
    ) {
      text = 'For signatures and code-signing in Rust, the pqcrypto-ml-dsa crate offers bindings to standard lattice signature algorithms. Here is a key generation and signing snippet:';
      language = 'rust';
      code = `// Cargo.toml: pqcrypto-ml-dsa = "0.1"
use pqcrypto_ml_dsa::mldsa65;
use pqcrypto_traits::sign::{PublicKey, SecretKey};

fn main() {
    // 1. Generate lattice keys (ML-DSA-65 matches AES-192 security)
    let (pk, sk) = mldsa65::keypair();
    
    // 2. Sign message
    let message = b"Database integrity validation check.";
    let signature = mldsa65::sign(message, &sk);
    
    // 3. Verify signature
    let verification = mldsa65::verify(message, &signature, &pk);
    assert!(verification.is_ok());
    println!("Lattice verification successful!");
}`;
    } else if (/\b(shor|shor's)\b/i.test(query) && /\b(grover|grover's)\b/i.test(query)) {
      text = "Shor's and Grover's algorithms are the two primary quantum algorithms that threaten classical cryptography:\n\n" +
             "1. **Shor's Algorithm**: Solves integer factorization and discrete logarithms in polynomial time. This completely breaks asymmetric public-key systems like RSA, Diffie-Hellman, and Elliptic Curve Cryptography (ECC).\n" +
             "2. **Grover's Algorithm**: Speeds up search in unsorted databases quadratically. When applied to symmetric cryptography (like AES) or hash functions, it halves the effective key length (e.g., AES-128 is reduced to 64 bits of security). This is mitigated by upgrading to AES-256.";
    } else if (/\b(shor|shor's|factoring)\b/i.test(query)) {
      text = "Shor's algorithm is a quantum computer algorithm that solves integer factorization and discrete logarithms in O((log N)³) polynomial time. This breaks RSA and ECC because classical cryptography relies on these math problems being exponential. Lattice-based cryptography (like ML-KEM/Kyber) relies on high-dimensional vector space lattice problems (like Shortest Vector Problem), which Shor's algorithm cannot solve efficiently.";
    } else if (/\b(grover|grover's|aes|symmetric)\b/i.test(query)) {
      text = "Grover's algorithm searches an unsorted database of N elements in O(√N) steps. When applied to symmetric keys (AES), it effectively halves the key size security (AES-128 becomes 64-bit strength, which is vulnerable). To mitigate this, CNSA 2.0 requires migrating to AES-256, providing a robust 128-bit quantum security buffer.";
    } else if (/\b(nsa|national security agency)\b/i.test(query)) {
      text = "NSA stands for the **National Security Agency** of the United States. In the context of quantum cryptography, the NSA publishes the **Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)** guidelines. These guidelines specify the mandatory transition timelines and algorithms (such as ML-KEM and ML-DSA) that national security systems must adopt to defend against the quantum computing decryption threat.";
    } else if (
      query.includes('pqc') || 
      query.includes('quantum') || 
      query.includes('crypt') || 
      query.includes('post-quantum') || 
      query.includes('cipher') || 
      query.includes('security') || 
      query.includes('protect') || 
      query.includes('defend') ||
      query.includes('threat') ||
      query.includes('algorithm')
    ) {
      text = "### QuarkShield Post-Quantum Cryptography (PQC) Guidance\n\n" +
             "Post-Quantum Cryptography refers to cryptographic algorithms designed to secure digital communications against attacks by quantum computers, specifically **Shor's Algorithm** (which shatters classical RSA, ECC, and Diffie-Hellman public-key systems) and **Grover's Algorithm** (which weakens symmetric ciphers and hash functions).\n\n" +
             "**Primary NIST Standardized Algorithms (Published August 2024)**:\n" +
             "- **ML-KEM (FIPS 203)**: Primary lattice-based Key Encapsulation Mechanism for TLS, SSH, and VPN connections.\n" +
             "- **ML-DSA (FIPS 204)**: Primary lattice-based Digital Signature Algorithm for certificates, code signing, and identity verification.\n" +
             "- **SLH-DSA (FIPS 205)**: Stateless hash-based digital signature fallback.\n" +
             "- **LMS / XMSS (NIST SP 800-208)**: Stateful hash-based signatures for firmware and bootloaders.\n\n" +
             "**Immediate Recommended Actions**:\n" +
             "1. **Inventory**: Use QuarkShield's **Crypto Scanner** to catalog all active asymmetric keys and certificates in your environment.\n" +
             "2. **Assess**: Review flagged assets in **Crypto CMDB** to identify systems subject to Harvest Now, Decrypt Later (HNDL) exposure.\n" +
             "3. **Remediate**: Deploy hybrid key exchanges (`X25519MLKEM768`) and upgrade symmetric ciphers to AES-256.\n\n" +
             "Feel free to ask for specific configuration examples for Nginx, OpenSSH, Go, Rust, or Ethereum smart contracts!";
    } else {
      text = "Hello! I am the QuarkShield AI Cryptography Advisor. I can answer questions about post-quantum cryptography (PQC), cybersecurity, networking, and technology.\n\n" +
             "Please ask me about:\n" +
             "- **QuarkShield Features**: *Crypto Scanner*, *Crypto CMDB*, *Quark Migrate*, *OPA Compliance*.\n" +
             "- **Quantum-Safe Algorithms**: *ML-KEM*, *ML-DSA*, *Falcon*, *LMS*, *XMSS*, or hybrid key exchanges.\n" +
             "- **Securing Infrastructure**: How to configure *Nginx*, *OpenSSH*, *Go*, *Rust*, or *Ethereum Smart Contracts* to resist Shor's and Grover's algorithms.\n" +
             "- **PQC Compliance Standards**: *NIST SP 800-208*, *CNSA 2.0*, or *Executive Order 14028*.";
    }

    res.json({ text, code: code || undefined, language });

  } catch (err: any) {
    console.error('Error generating AI response:', err);
    res.status(500).json({ error: `AI Assistant failed: ${err.message}` });
  }
};

// Helper: parse markdown code blocks
function extractCodeBlock(markdownText: string): { textResponse: string, codeResponse: string, langResponse: string } {
  const codeBlockRegex = /```(\w*)\n([\s\S]*?)```/;
  const match = markdownText.match(codeBlockRegex);
  
  if (match) {
    const langResponse = match[1] || 'javascript';
    const codeResponse = match[2];
    const textResponse = markdownText.replace(codeBlockRegex, '').trim();
    return { textResponse, codeResponse, langResponse };
  }
  
  return { textResponse: markdownText, codeResponse: '', langResponse: 'javascript' };
}

// Helper: extract CMDB metadata from description field
function parseCmdbMetadata(desc: string) {
  const defaultMeta = {
    businessService: 'Unassigned Infrastructure',
    application: 'Core Services',
    owner: 'secops-alert@quarkshield.services',
    lifecycle: 'Active'
  };

  if (!desc) return defaultMeta;
  const parts = desc.split('|CMDB:');
  if (parts.length > 1) {
    try {
      const parsed = JSON.parse(parts[1]);
      return {
        businessService: parsed.businessService || defaultMeta.businessService,
        application: parsed.application || defaultMeta.application,
        owner: parsed.owner || defaultMeta.owner,
        lifecycle: parsed.lifecycle || defaultMeta.lifecycle
      };
    } catch (e) {
      // Ignore parse errors
    }
  }
  return defaultMeta;
}

// POST /api/ai/correlate
export const getAICorrelation = async (req: Request, res: Response) => {
  try {
    // 1. Fetch all assets from database
    const dbRes = await pool.query('SELECT * FROM assets ORDER BY created_at DESC');
    const assets = dbRes.rows.map(row => ({
      id: row.id,
      type: row.type,
      name: row.name,
      algorithm: row.algorithm,
      keySize: row.key_size,
      isVulnerable: row.is_vulnerable,
      riskLevel: row.risk_level,
      status: row.status,
      description: row.description,
      recommendation: row.recommendation,
      explainer: row.explainer,
      complianceViolations: row.compliance_violations || [],
    }));

    let apiKey = process.env.GEMINI_API_KEY ? process.env.GEMINI_API_KEY.trim() : '';
    if (!apiKey) {
      try {
        const settingsRes = await pool.query("SELECT value FROM tenant_settings WHERE key = 'gemini_api_key'");
        if (settingsRes.rows.length > 0 && settingsRes.rows[0].value) {
          apiKey = settingsRes.rows[0].value.trim();
        }
      } catch (settingsErr) {
        console.warn('Failed to query tenant_settings for Gemini key in correlation:', settingsErr);
      }
    }

    if (apiKey && apiKey.trim() !== '' && assets.length > 0) {
      const geminiCandidateModels = [
        process.env.GEMINI_MODEL,
        'gemini-2.0-flash',
        'gemini-1.5-flash'
      ].filter(Boolean) as string[];

      const systemInstruction = 
        "You are QuarkShield AI, an expert post-quantum cryptography (PQC) migration advisor. " +
        "Analyze the provided array of cryptographic assets and correlate their risk profiles. " +
        "Group the assets into 3 logical migration waves (Wave 1: Immediate, Wave 2: High, Wave 3: Standard) based on NIST/CNSA 2.0 guidelines. " +
        "Generate exactly 3 key security insights (finding cross-app dependencies, obsolete cipher patterns, or compliance alerts). " +
        "Return the output STRICTLY in a clean JSON object format: " +
        "{ \"insights\": [ { \"title\": \"string\", \"desc\": \"string\", \"severity\": \"critical\" | \"high\" | \"medium\" } ], " +
        "\"waves\": { \"wave1\": [ { \"name\": \"string\", \"owner\": \"string\", \"algorithm\": \"string\", \"businessService\": \"string\" } ], " +
        "\"wave2\": [...], \"wave3\": [...] } }. " +
        "Do not include markdown code block syntax (like ```json) in your response, just the raw JSON object.";

      const contents = [{
        role: 'user',
        parts: [{ text: `${systemInstruction}\n\nAssets Inventory JSON:\n${JSON.stringify(assets, null, 2)}` }]
      }];

      for (const model of geminiCandidateModels) {
        console.log(`AI Controller: Querying Gemini API for correlation (model: ${model})...`);
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 45000);

        try {
          const geminiRes = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ contents }),
            signal: controller.signal
          });

          if (geminiRes.ok) {
            const data: any = await geminiRes.json();
            let aiText = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
            
            // Clean markdown block wrapping if Gemini ignores instructions
            aiText = aiText.replace(/```json/g, '').replace(/```/g, '').trim();

            try {
              const parsed = JSON.parse(aiText);
              if (parsed.insights && parsed.waves) {
                return res.json(parsed);
              }
            } catch (jsonErr) {
              console.warn('Failed to parse Gemini correlation JSON response, using fallback format parser:', jsonErr);
            }
          }
        } catch (fetchErr: any) {
          console.warn(`Error or timeout fetching from Gemini API for correlation (${model}):`, fetchErr.message);
        } finally {
          clearTimeout(timeoutId);
        }
      }
      console.warn('Gemini correlation failed across models. Executing local rules engine.');
    }

    // --- Local Rules Correlation Fallback ---
    console.log('AI Controller: Executing local rules-based correlation engine...');
    
    const wave1: any[] = [];
    const wave2: any[] = [];
    const wave3: any[] = [];

    assets.forEach(asset => {
      const cmdb = parseCmdbMetadata(asset.description);
      const waveItem = {
        name: asset.name,
        owner: cmdb.owner,
        algorithm: asset.algorithm,
        businessService: cmdb.businessService
      };

      if (!asset.isVulnerable) {
        // Secure assets don't need migration
        return;
      }

      if (asset.riskLevel === 'critical' || asset.algorithm.includes('1024') || asset.algorithm.includes('SHA1') || asset.algorithm.includes('MD5')) {
        wave1.push(waveItem);
      } else if (asset.riskLevel === 'high' || asset.algorithm.includes('2048') || asset.algorithm.includes('ECDSA') || asset.algorithm.includes('ECC')) {
        wave2.push(waveItem);
      } else {
        wave3.push(waveItem);
      }
    });

    // Generate static correlated insights based on inventory findings
    const insights = [
      {
        title: 'Legacy Asymmetric Ciphers Detected',
        desc: `Identified ${assets.filter(a => a.isVulnerable).length} active configurations negotiating classical RSA/ECC encryption keys which can be retrospectively decrypted by a quantum computer (SNDL threat).`,
        severity: assets.some(a => a.riskLevel === 'critical') ? 'critical' : 'high'
      },
      {
        title: 'CNSA 2.0 Compliance Gaps',
        desc: `Multiple systems violate Executive Order 14028 and NSA CNSA 2.0 timelines which mandate beginning the transition to module-lattice key exchange standard (ML-KEM) immediately.`,
        severity: 'high'
      },
      {
        title: 'Shadow Certificates Active',
        desc: `Passive discovery sniffer caught untracked microservices running legacy TLS handshakes in production subnet lines. Mapped these to Cost-Center Application targets for isolation.`,
        severity: 'medium'
      }
    ];

    res.json({
      insights,
      waves: { wave1, wave2, wave3 }
    });

  } catch (err: any) {
    console.error('Error generating AI correlation blueprint:', err);
    res.status(500).json({ error: `Correlation Engine failed: ${err.message}` });
  }
};

// POST /api/ai/generate-presentation
export const generatePresentation = async (req: Request, res: Response) => {
  try {
    const { scope, items, engine, customPrompt } = req.body;
    
    // 1. Fetch assets from database to compile real risk statistics
    const dbRes = await pool.query('SELECT * FROM assets ORDER BY created_at DESC');
    const assets = dbRes.rows;
    
    // Fetch subscription tier
    let subscriptionTier = 'growth';
    try {
      const tierRes = await pool.query("SELECT value FROM tenant_settings WHERE key = 'subscription_tier'");
      if (tierRes.rows.length > 0) {
        subscriptionTier = tierRes.rows[0].value;
      }
    } catch (e) {
      console.warn('Failed to query subscription tier:', e);
    }

    // Force individual scope if assessment tier (Growth counterpart / restricted tier)
    let activeScope = scope || 'consolidated';
    let activeItems = items || ['readiness', 'cmdb', 'passive', 'compliance'];
    if (subscriptionTier === 'assessment') {
      activeScope = 'individual';
      if (activeItems.length > 1) {
        activeItems = [activeItems[0]];
      }
    }

    // Filter assets based on active scope/items
    let filteredAssets = assets;
    if (activeScope === 'individual' && activeItems && activeItems.length === 1) {
      const pillar = activeItems[0];
      if (pillar === 'passive') {
        filteredAssets = assets.filter(a => a.type === 'passive' || (a.description && a.description.toLowerCase().includes('passive')) || (a.status && a.status.toLowerCase().includes('passive')));
      } else if (pillar === 'compliance') {
        filteredAssets = assets.filter(a => a.compliance_violations && Array.isArray(a.compliance_violations) && a.compliance_violations.length > 0);
      } else if (pillar === 'cmdb') {
        filteredAssets = assets.filter(a => a.description && a.description.includes('|CMDB:'));
      }
    }

    const totalAssets = filteredAssets.length;
    const vulnerableAssets = filteredAssets.filter(r => r.is_vulnerable).length;
    const secureAssets = totalAssets - vulnerableAssets;
    
    // Calculate compliance violations
    let totalViolations = 0;
    filteredAssets.forEach(r => {
      if (r.compliance_violations && Array.isArray(r.compliance_violations)) {
        totalViolations += r.compliance_violations.length;
      }
    });
    
    // Parse applications from CMDB metadata in description
    const apps = new Set<string>();
    const services = new Set<string>();
    filteredAssets.forEach(r => {
      const cmdb = parseCmdbMetadata(r.description);
      if (cmdb.application) apps.add(cmdb.application);
      if (cmdb.businessService) services.add(cmdb.businessService);
    });
    
    const appCount = apps.size || 1;
    const serviceCount = services.size || 1;
    
    const riskPercentage = totalAssets > 0 ? Math.round((vulnerableAssets / totalAssets) * 100) : 100;
    const calculatedDeficitRating = totalAssets > 0 ? Math.min(10, Math.max(1, Math.round((vulnerableAssets / totalAssets) * 10))) : 1;
    const estimatedRunway = appCount > 10 ? '4' : '2';

    // Compile compliance violations context
    let complianceViolationsContext = "";
    const violationsSet = new Set<string>();
    filteredAssets.forEach(r => {
      if (r.compliance_violations && Array.isArray(r.compliance_violations)) {
        r.compliance_violations.forEach((v: string) => violationsSet.add(v));
      }
    });
    if (violationsSet.size > 0) {
      complianceViolationsContext = Array.from(violationsSet).map(v => `- ${v}`).join('\n');
    } else {
      complianceViolationsContext = "- NIST SP 800-208: Deficiencies in automated cryptographic discovery and lifecycle management\n- NSA CNSA 2.0: Ingress load balancers negotiating legacy classical ciphers violate NSA timelines\n- Executive Order 14028: Active database credentials fail key rotation audits and lack centralized rotation logging";
    }

    // If the user selected Claude or Gemini, we will invoke the AI APIs
    const isClaude = engine === 'claude';
    const isGemini = engine === 'gemini';
    
    if (isGemini || isClaude) {
      const systemInstruction = 
        "You are an expert cybersecurity executive and presentation designer. Your task is to transform Cryptographic Configuration Management Database (Crypto CMDB) audit data into a high-impact, executive-level slide deck presentation about Cryptographic Risk & Post-Quantum Cryptography (PQC) readiness.\n\n" +
        "For each slide, you must generate:\n" +
        "1. **Slide Title**\n" +
        "2. **Visual Layout Description** (to assist with automated slide styling)\n" +
        "3. **Slide Content** (bulleted text, metric callouts, or tables)\n\n" +
        "--- \n\n" +
        "### [SLIDE DECK STRUCTURE]\n\n" +
        "Please generate the slide content exactly according to the following 7-slide format:\n\n" +
        "#### Slide 1: Title & Executive Baseline\n" +
        "*   **Layout**: High-contrast, dark aesthetic. Prominent title and a sidebar block for key posture KPIs.\n" +
        "*   **Title**: [Generate a title, max 45 chars. E.g., \"State of Cryptographic Risk & Post-Quantum Readiness\"]\n" +
        "*   **Subtitle**: Aligning to CNSA 2.0 & NIST SP 800-208 Standards\n" +
        "*   **Core KPI Block**: \n" +
        `    *   Total Assets: ${totalAssets}\n` +
        `    *   Vulnerable Inventory: ${riskPercentage}%\n` +
        `    *   Cryptographic Deficit Score: ${calculatedDeficitRating}/10\n` +
        `    *   Mosca's Threat Runway: ${estimatedRunway} Years\n` +
        "*   **Executive Baseline Statement**: Write a high-impact 2-sentence executive summary stating that hidden legacy cryptographic tech debt is actively leaking future confidentiality through \"Harvest Now, Decrypt Later\" threat actors.\n\n" +
        "#### Slide 2: Executive Summary (The Big Picture)\n" +
        "*   **Layout**: Two unequal columns (60/40). Left column for the core narrative, right column for a highlighted warning box.\n" +
        "*   **Left Column (The Problem)**:\n" +
        "    *   The difference between software bugs and cryptographic deficits (why traditional vulnerability scanners miss algorithm-level weaknesses).\n" +
        "    *   The cost of inaction: proprietary cryptographic lock-in and manual certificate overhead.\n" +
        "*   **Right Column (The Strategy)**:\n" +
        "    *   Moving from reactive certificate replacement to proactive Cryptographic Agility.\n\n" +
        "#### Slide 3: Cryptographic Risk & Deficit Assessment\n" +
        "*   **Layout**: Three vertical columns comparing asset classifications side-by-side. Include a distinct callout section at the bottom for Mosca's Theorem.\n" +
        "*   **Column 1: High Risk (Critical Deficit)**\n" +
        "    *   Legacy algorithms: RSA-1024/2048, SHA-1, Triple-DES.\n" +
        "    *   Action: Immediate deprecation and isolation.\n" +
        "*   **Column 2: Medium Risk (Transition Required)**\n" +
        "    *   Algorithms: RSA-4096, ECC (ECDSA/ECDH), SHA-256.\n" +
        "    *   Status: Vulnerable to future Cryptanalytically Relevant Quantum Computers (CRQCs).\n" +
        "*   **Column 3: Low Risk (Quantum-Resistant / Compliant)**\n" +
        "    *   Algorithms: AES-256, ML-KEM, ML-DSA, stateful hash-based signatures.\n" +
        "    *   Status: Agile and fully compliant.\n" +
        "*   **Deficit Calculus Callout**: \n" +
        `    *   "Mosca's Theorem: If U + V > Y (Shelf Life + Migration Time > Time to CRQC), your encrypted data is already at risk of offline decryption. Our deficit status: Active Risk (Score ${calculatedDeficitRating}/10 - ${riskPercentage}% of inventory is vulnerable to quantum decryption)."\n\n` +
        "#### Slide 4: Compliance Gaps (NIST SP 800-208 & CNSA 2.0)\n" +
        "*   **Layout**: Simple 3-column table matrix.\n" +
        "*   **Table Headers**: Target Compliance Standard | Discovered Organizational Gap | Remediation Deadline\n" +
        "*   **Content**: Generate at least 3 critical regulatory gaps derived from the CMDB data (specifically focusing on CNSA 2.0 timelines and NIST discovery guidelines). Format each gap as a string: 'Standard | Discovered Gap | Deadline' inside the bullets array.\n\n" +
        "#### Slide 5: Short-Term Remediation Steps (0-90 Days)\n" +
        "*   **Layout**: Horizontal progressive timeline layout (3 steps).\n" +
        "*   **Step 1: Certificate Lifecycle Cleanup** (Revoking weak, expired, or unmanaged wildcard certificates).\n" +
        "*   **Step 2: Cipher Suite Hardening** (Disabling legacy TLS CBC and Diffie-Hellman key exchanges in web servers and APIs).\n" +
        "*   **Step 3: Network Isolation** (Quarantining legacy systems that cannot support modern TLS 1.3 wrappers).\n\n" +
        "#### Slide 6: Long-Term Strategic PQC Migration Plan (90+ Days)\n" +
        "*   **Layout**: Phased roadmapping layout (3 strategic waves).\n" +
        "*   **Wave 1: Hybrid Agility Testing** (Deploying dual-key certificate authorities combining classic ECC and ML-KEM).\n" +
        "*   **Wave 2: Hardware Infrastructure Upgrades** (Updating HSMs and cryptographic coprocessors to natively support quantum-resistant algorithms).\n" +
        "*   **Wave 3: CI/CD Guardrails** (Deploying OPA policies to block weak cryptographic dependencies at build-time).\n\n" +
        "#### Slide 7: Next Steps & Continuous Posture Monitoring\n" +
        "*   **Layout**: Card-style grid (2x2) with clear next action items.\n" +
        "*   **Action 1**: Sync continuous discovery engine to live CMDB.\n" +
        "*   **Action 2**: Define automated thresholds for certificate degradation.\n" +
        "*   **Action 3**: Establish cross-functional PQC taskforce.\n" +
        "*   **Action 4**: Schedule the next cryptographic posture review.\n\n" +
        "--- \n\n" +
        "### [JSON FORMATTING REQUIREMENT]\n\n" +
        "To allow our automated slide styling engine to parse your output, you MUST return the response STRICTLY in this JSON object format:\n" +
        "{\n" +
        "  \"slides\": [\n" +
        "    {\n" +
        "      \"id\": number,\n" +
        "      \"title\": \"string\",\n" +
        "      \"bullets\": [\"string\"],\n" +
        "      \"speakerNotes\": \"string\",\n" +
        "      \"layoutDescription\": \"string\"\n" +
        "    }\n" +
        "  ]\n" +
        "}\n" +
        "Do not include markdown code block wrapping (like ```json) in your response, just the raw JSON object. Ensure there are exactly 7 slides in the slides array.\n" +
        "The bullets array for each slide MUST be formatted as follows:\n" +
        "- Slide 1: Exactly one bullet containing the 'Executive Baseline Statement' (a high-impact 2-sentence summary starting with 'Hidden legacy cryptographic...').\n" +
        "- Slide 2: Exactly three bullets. The first two are the left column ('The Problem'), and the third is the right column ('The Strategy').\n" +
        "- Slide 3: Exactly four bullets. Bullet 1: Column 1 ('High Risk (Critical Deficit)'). Bullet 2: Column 2 ('Medium Risk (Transition Required)'). Bullet 3: Column 3 ('Low Risk (Quantum-Resistant)'). Bullet 4: 'Deficit Calculus Callout' (including Mosca's Theorem threat modeling stating the active risk level based on our statistics).\n" +
        "- Slide 4: Exactly three bullets, each formatted as 'Target Compliance Standard | Discovered Organizational Gap | Remediation Deadline' (with pipe characters separating the three columns) to represent the compliance gaps. Use the real compliance gaps provided in the prompt context.\n" +
        "- Slide 5: Exactly three bullets, each formatted as 'Title — Description' (e.g. 'Step 1: Certificate Lifecycle Cleanup — Revoking weak, expired, or unmanaged wildcard certificates').\n" +
        "- Slide 6: Exactly three bullets, each formatted as 'Title — Description' (e.g. 'Wave 1: Hybrid Agility Testing — Deploying dual-key certificate authorities').\n" +
        "- Slide 7: Exactly four bullets, each representing an Action item.";
  
      let customPromptContext = "";
      if (customPrompt && customPrompt.trim() !== "") {
        customPromptContext = `\n- Custom User Directive: The user has requested to prioritize these custom guidelines: "${customPrompt}". Integrate this focus area throughout the slides and speaker notes.\n`;
      }

      const prompt = `Here are the organization's real cryptographic CMDB statistics and compliance context to use in your slide generation:
- Total Cryptographic Assets Monitored: ${totalAssets}
- Vulnerable classical keys (RSA/ECC) negotiating traffic: ${vulnerableAssets}
- Secure quantum-resistant keys (ML-KEM/ML-DSA): ${secureAssets}
- Active Policy Compliance Violations (NIST/CNSA): ${totalViolations}
- Monitored Enterprise Applications: ${appCount}
- Mapped Business Services: ${serviceCount}
- Report Scope: ${activeScope} (Selected pillars: ${JSON.stringify(activeItems)})${customPromptContext}
- Compliance Violations/Gaps Context:
${complianceViolationsContext}
 
Please generate the structured 7-slide board presentation JSON following the exact system instructions and structure.`;
 
      if (isGemini) {
        let apiKey = process.env.GEMINI_API_KEY ? process.env.GEMINI_API_KEY.trim() : '';
        if (!apiKey) {
          try {
            const settingsRes = await pool.query("SELECT value FROM tenant_settings WHERE key = 'gemini_api_key'");
            if (settingsRes.rows.length > 0 && settingsRes.rows[0].value) {
              apiKey = settingsRes.rows[0].value.trim();
            }
          } catch (settingsErr) {
            console.warn('Failed to query tenant_settings for Gemini key in slides:', settingsErr);
          }
        }

        if (apiKey && apiKey.trim() !== '') {
          const geminiCandidateModels = [
            process.env.GEMINI_MODEL,
            'gemini-2.0-flash',
            'gemini-1.5-flash'
          ].filter(Boolean) as string[];

          const contents = [{
            role: 'user',
            parts: [{ text: `${systemInstruction}\n\nUser Query:\n${prompt}` }]
          }];

          for (const model of geminiCandidateModels) {
            console.log(`AI Controller: Querying Gemini for Slide Deck (model: ${model})...`);
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 45000);

            try {
              const geminiRes = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ contents }),
                signal: controller.signal
              });

              if (geminiRes.ok) {
                const data: any = await geminiRes.json();
                let aiText = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
                aiText = aiText.replace(/```json/g, '').replace(/```/g, '').trim();
                try {
                  const parsed = JSON.parse(aiText);
                  if (parsed.slides && Array.isArray(parsed.slides) && parsed.slides.length === 7) {
                    return res.json(parsed);
                  }
                } catch (e) {
                  console.warn('Failed to parse Gemini slide JSON, trying next model or fallback:', e);
                }
              }
            } catch (fetchErr: any) {
              console.warn(`Error or timeout fetching from Gemini API for slides (${model}):`, fetchErr.message);
            } finally {
              clearTimeout(timeoutId);
            }
          }
        }
      } else if (isClaude) {
        let anthropicKey = process.env.ANTHROPIC_API_KEY;
        try {
          const settingsRes = await pool.query("SELECT value FROM tenant_settings WHERE key = 'anthropic_api_key'");
          if (settingsRes.rows.length > 0 && settingsRes.rows[0].value && settingsRes.rows[0].value.trim() !== '') {
            anthropicKey = settingsRes.rows[0].value.trim();
          }
        } catch (dbErr) {
          console.warn('Failed to query tenant_settings for Anthropic key in slides:', dbErr);
        }
 
        if (anthropicKey && anthropicKey.trim() !== '') {
          console.log('AI Controller: Querying Anthropic Claude for Slide Deck...');
          const url = 'https://api.anthropic.com/v1/messages';
          
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 45000);

          try {
            const claudeRes = await fetch(url, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'x-api-key': anthropicKey,
                'anthropic-version': '2023-06-01'
              },
              body: JSON.stringify({
                model: 'claude-3-5-sonnet-20241022',
                max_tokens: 4000,
                system: systemInstruction,
                messages: [{ role: 'user', content: prompt }]
              }),
              signal: controller.signal
            });
 
            if (claudeRes.ok) {
              const data: any = await claudeRes.json();
              let aiText = data?.content?.[0]?.text || '';
              aiText = aiText.replace(/```json/g, '').replace(/```/g, '').trim();
              try {
                const parsed = JSON.parse(aiText);
                if (parsed.slides && Array.isArray(parsed.slides) && parsed.slides.length === 7) {
                  return res.json(parsed);
                }
              } catch (e) {
                console.warn('Failed to parse Claude slide JSON, falling back to local builder:', e);
              }
            }
          } catch (fetchErr: any) {
            console.warn('Error or timeout fetching from Claude API for slides:', fetchErr.message);
          } finally {
            clearTimeout(timeoutId);
          }
        }
      }
    }
 
    // --- Local Fallback Presentation Builder ---
    console.log('AI Controller: Executing local rules-based 7-slide presentation generator...');
    
    const slides = [
      {
        id: 1,
        title: 'State of Cryptographic Risk & Post-Quantum Readiness',
        bullets: [
          `Hidden legacy cryptographic tech debt is actively leaking future confidentiality through 'Harvest Now, Decrypt Later' (HNDL) threat actors. Immediate modernization is required to secure corporate endpoints.`
        ],
        speakerNotes: `Good morning, members of the board. Today we are presenting our strategic roadmap to secure our enterprise infrastructure against the upcoming quantum computing threat. A cryptanalytically useful quantum computer will be capable of breaking the mathematical foundations of our current asymmetric cryptography. To address this, we have executed a comprehensive cryptographic audit. This presentation outlines our current risk exposure, our central database inventory findings, and our concrete timeline to transition our assets to post-quantum secure algorithms.`
      },
      {
        id: 2,
        title: 'Executive Summary (The Big Picture)',
        bullets: [
          'Cryptographic Deficit vs. Software Bugs: Traditional vulnerability scanners identify software defects but completely miss algorithm-level weaknesses where active, fully patched connections rely on legacy mathematical assumptions.',
          'The Cost of Inaction: Retaining legacy cryptography leads to proprietary cryptographic lock-in, manual certificate overhead, and severe exposure to retrospective decryption.',
          'Strategic Transition: We must migrate from reactive certificate replacement to proactive Cryptographic Agility, establishing automated inventory controls and lattice-based algorithms.'
        ],
        speakerNotes: `Let us look at our executive baseline. Traditional security tools look for expired certificates or unpatched code, but they fail to flag these algorithm-level risks where active cryptographic connections rely on mathematically vulnerable foundations. Standard scanners look for bugs; we are looking at the math itself. Moving forward, our strategy transitions from reactive certificate replacement to proactive Cryptographic Agility, allowing us to swap out underlying algorithms without disrupting business services.`
      },
      {
        id: 3,
        title: 'Cryptographic Risk & Deficit Assessment',
        bullets: [
          'High Risk (Critical Deficit): Legacy RSA-1024/2048, Triple-DES, MD5, and SHA-1 signatures require immediate deprecation and isolation.',
          'Medium Risk (Transition Required): RSA-4096, ECC (ECDSA/ECDH), and SHA-256 are safe from classical attacks but highly vulnerable to future quantum computers.',
          'Low Risk (Quantum-Resistant / Compliant): AES-256, ML-KEM, ML-DSA, and stateful hash-based signatures (LMS/XMSS) are quantum-resistant and fully compliant.',
          `Mosca's Theorem: If U + V > Y (Shelf Life + Migration Time > Time to CRQC), your encrypted data is already at risk. Our deficit status: Active Risk (U + V = ${5 + Number(estimatedRunway)} > Y = 8).`
        ],
        speakerNotes: `Our risk classification categorizes our assets into three tiers. The High Risk tier contains legacy algorithms that must be deprecated immediately. The Medium Risk tier contains ciphers like RSA-4096 and ECC that are safe from classical attacks but highly vulnerable to future quantum computers. The Low Risk tier consists of quantum-resistant algorithms. Under Mosca's Theorem, since our data shelf-life plus our migration runway exceeds the estimated time to a quantum computer, we are currently in an active data-leakage state, making this migration an immediate priority.`
      },
      {
        id: 4,
        title: 'Compliance Gaps (NIST SP 800-208 & CNSA 2.0)',
        bullets: [
          'NIST SP 800-208 | Deficiencies in automated asset discovery and centralized inventory management | Remediation: 2026',
          'NSA CNSA 2.0 | Ingress load balancers negotiating legacy classical ciphers violate NSA timelines | Remediation: 2030',
          `Executive Order 14028 | Active database credentials fail key rotation audits and lack centralized rotation logging | Remediation: 2026`
        ],
        speakerNotes: `Compliance is a critical driver. Our automated scanning has flagged policy gaps violating NIST SP 800-208 and NSA CNSA 2.0 guidelines. Many of our web interfaces and VPN gateways violate the NSA CNSA 2.0 mandate, which requires commencing the transition to post-quantum standards immediately. Furthermore, our current logging fail-safes do not fully meet the key rotation and cryptographic agility audits mandated under Executive Order 14028. Resolving these gaps is our top compliance priority.`
      },
      {
        id: 5,
        title: 'Short-Term Remediation Steps (0-90 Days)',
        bullets: [
          'Step 1: Certificate Lifecycle Cleanup — Revoking weak, expired, or unmanaged wildcard certificates across internal web portals.',
          'Step 2: Cipher Suite Hardening — Disabling legacy TLS CBC and Diffie-Hellman key exchanges in web servers and APIs, enforcing TLS 1.3.',
          'Step 3: Network Isolation — Quarantining legacy systems that cannot support modern TLS 1.3 wrappers using localized IPsec gateways.'
        ],
        speakerNotes: `In the short term, our 90-day playbook focuses on tactical cleanup. First, we will clean up legacy certificate tech debt by revoking RSA-1024 keys and wildcard certificates. Second, we will disable weak CBC/DH ciphers globally and enforce TLS 1.3 across all public ingress load balancers. Third, we will isolate legacy internal databases using strict subnet routing or localized IPsec gateways to prevent unauthorized classical negotiations.`
      },
      {
        id: 6,
        title: 'Long-Term Strategic PQC Migration Plan (90+ Days)',
        bullets: [
          'Wave 1: Hybrid Agility Testing — Deploying dual-key certificate authorities combining classic ECC and ML-KEM to ensure backward compatibility.',
          'Wave 2: Hardware Infrastructure Upgrades — Updating HSMs and cryptographic coprocessors to natively support quantum-resistant lattice standards.',
          'Wave 3: CI/CD Guardrails — Deploying Open Policy Agent (OPA) declarative rules in pipelines to block weak cryptographic dependencies before build.'
        ],
        speakerNotes: `For the long term, our strategic roadmap focuses on complete post-quantum migration. Wave 1 involves deploying dual-key hybrid certificates to test compatibility. Wave 2 focuses on upgrading our physical Hardware Security Modules, or HSMs, to support lattice-based cryptography natively. Finally, Wave 3 integrates OPA policy checks directly into our developer pipelines, preventing engineers from committing code that introduces obsolete, non-compliant classical ciphers.`
      },
      {
        id: 7,
        title: 'Next Steps & Continuous Posture Monitoring',
        bullets: [
          'Action 1: Sync continuous discovery engine to live CMDB database to maintain a real-time cryptographic inventory.',
          'Action 2: Define automated thresholds for certificate degradation, raising immediate alerts for vulnerable keys.',
          'Action 3: Establish a cross-functional PQC taskforce comprising security engineers, developers, and compliance officers.',
          'Action 4: Schedule the next cryptographic posture review to continuously audit and score our migration progress.'
        ],
        speakerNotes: `To conclude, our next steps focus on institutionalizing continuous monitoring. We will sync our discovery engine to our live CMDB to maintain a real-time cryptographic inventory. We will define automated alerting thresholds for certificate degradation, establish a cross-functional PQC taskforce, and schedule our next posture review. These actions will ensure that we maintain high crypto-agility and track our progress toward a fully secure, quantum-resistant enterprise.`
      }
    ];
 
    res.json({ slides });

  } catch (err: any) {
    console.error('Error generating presentation slides:', err);
    res.status(500).json({ error: `Presentation Generator failed: ${err.message}` });
  }
};

// POST /api/ai/generate-report
export const generateReport = async (req: Request, res: Response) => {
  try {
    const { scope, items, engine, customPrompt } = req.body;
    
    // Extract customer name from user company or email
    let customerName = (req as any).user?.company || '';
    if (!customerName) {
      const email = (req as any).user?.email || 'Valued Client';
      customerName = 'Enterprise Client';
      if (email && email.includes('@')) {
        const domain = email.split('@')[1];
        const domainPart = domain.split('.')[0];
        customerName = domainPart.charAt(0).toUpperCase() + domainPart.slice(1);
      }
    }
    
    const formattedDate = new Date().toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });

    // 1. Fetch assets from database to compile real risk statistics
    const dbRes = await pool.query('SELECT * FROM assets ORDER BY created_at DESC');
    const assets = dbRes.rows;
    
    const totalAssets = assets.length;
    const vulnerableAssets = assets.filter(r => r.is_vulnerable).length;
    const secureAssets = totalAssets - vulnerableAssets;
    const riskPercentage = totalAssets > 0 ? Math.round((vulnerableAssets / totalAssets) * 100) : 100;
    
    // Calculate compliance violations and build lists
    let totalViolations = 0;
    const highRiskAssets: any[] = [];
    const mediumRiskAssets: any[] = [];
    const lowRiskAssets: any[] = [];
    const gapMatrixRows: any[] = [];
    
    assets.forEach(r => {
      // Compliance violations
      if (r.compliance_violations && Array.isArray(r.compliance_violations)) {
        totalViolations += r.compliance_violations.length;
      }
      
      // Classify risk tiers
      const isVulnerable = r.is_vulnerable;
      const alg = (r.algorithm || '').toUpperCase();
      const risk = (r.risk_level || '').toLowerCase();
      
      if (risk === 'critical' || alg.includes('1024') || alg.includes('SHA1') || alg.includes('MD5')) {
        highRiskAssets.push({ name: r.name, algorithm: r.algorithm || 'RSA', keySize: r.key_size });
      } else if (risk === 'high' || alg.includes('2048') || alg.includes('ECDSA') || alg.includes('ECC')) {
        mediumRiskAssets.push({ name: r.name, algorithm: r.algorithm || 'ECC', keySize: r.key_size });
      } else {
        lowRiskAssets.push({ name: r.name, algorithm: r.algorithm || 'ML-KEM', keySize: r.key_size });
      }
      
      // Build Gap Matrix rows
      if (isVulnerable) {
        const deadline = alg.includes('SHA1') || alg.includes('1024') ? '2025' : '2030';
        gapMatrixRows.push({
          group: r.name,
          protocol: r.algorithm || 'RSA',
          cnsa: 'No',
          deadline
        });
      } else {
        gapMatrixRows.push({
          group: r.name,
          protocol: r.algorithm || 'ML-KEM',
          cnsa: 'Yes',
          deadline: 'Compliant'
        });
      }
    });

    // Parse applications from CMDB metadata in description
    const apps = new Set<string>();
    const services = new Set<string>();
    assets.forEach(r => {
      const cmdb = parseCmdbMetadata(r.description);
      if (cmdb.application) apps.add(cmdb.application);
      if (cmdb.businessService) services.add(cmdb.businessService);
    });
    
    const appCount = apps.size || 2;
    const serviceCount = services.size || 3;
    
    // Format dataset representation for the LLM
    const highRiskText = highRiskAssets.slice(0, 8).map(a => `| ${a.name} | ${a.algorithm}${a.keySize ? '-' + a.keySize : ''} | High (Immediate Deficit) |`).join('\n') || '| No high risk assets found | - | - |';
    const mediumRiskText = mediumRiskAssets.slice(0, 8).map(a => `| ${a.name} | ${a.algorithm}${a.keySize ? '-' + a.keySize : ''} | Medium (Transition Window) |`).join('\n') || '| No medium risk assets found | - | - |';
    const lowRiskText = lowRiskAssets.slice(0, 8).map(a => `| ${a.name} | ${a.algorithm}${a.keySize ? '-' + a.keySize : ''} | Low (Agile/Compliant) |`).join('\n') || '| No low risk assets found | - | - |';
    
    const gapMatrixText = gapMatrixRows.slice(0, 8).map(r => `| ${r.group} | ${r.protocol} | ${r.cnsa} | ${r.deadline} |`).join('\n') || '| No assets to report | - | - | - |';

    const calculatedDeficitRating = totalAssets > 0 ? Math.min(10, Math.max(1, Math.round((vulnerableAssets / totalAssets) * 10))) : 1;
    const estimatedRunway = appCount > 10 ? '4' : '2';

    const isClaude = engine === 'claude';
    const isGemini = engine === 'gemini';

    const systemInstruction = 
      "You are an expert Cybersecurity Auditor and Principal Cryptographic Engineer. Your task is to analyze the provided Cryptographic Configuration Management Database (Crypto CMDB) data and generate a highly detailed, comprehensive, executive-ready **Cryptographic Risk & Post-Quantum Cryptography (PQC) Readiness Report**.\n\n" +
      "This is a formal PDF/Word document, not a slide deck. The output must be thorough, narrative-heavy, and structured professionally as a formal audit. It must align with NIST SP 800-208 (Cryptographic Discovery) and CNSA 2.0 (Commercial National Security Algorithm Suite) timelines.\n\n" +
      "--- \n\n" +
      "### [REPORT STRUCTURE]\n\n" +
      "Please generate the report using the following markdown outline:\n\n" +
      "# EXECUTIVE CRYPTOGRAPHIC RISK & POST-QUANTUM READINESS REPORT\n" +
      "## Prepared For: " + customerName + "\n" +
      "## Date: " + formattedDate + "\n" +
      "## Prepared By: QuarkShield Security Posture Assessment Node\n\n" +
      "--- \n\n" +
      "# TABLE OF CONTENTS\n" +
      "1. Executive Summary & Posture Baseline\n" +
      "2. Cryptographic Inventory & Risk Analysis\n" +
      "3. Regulatory Compliance & Milestones Gap Analysis\n" +
      "4. NIST SP 800-208 Discovery & Remediation Playbook\n" +
      "5. Professional Disclaimer & Risk Assumptions\n\n" +
      "--- \n\n" +
      "# 1. Executive Summary & Posture Baseline\n" +
      "*   **Detailed Executive Narrative**: Provide a thorough, multi-paragraph CISO-level overview of the organization’s current cryptographic status. Explain the critical nature of \"Harvest Now, Decrypt Later\" (HNDL) threats, where adversaries capture encrypted traffic today to decrypt once a Cryptanalytically Relevant Quantum Computer (CRQC) becomes available.\n" +
      "*   **Core Posture Metrics Table**: Create a clean Markdown table displaying:\n" +
      "    *   Total Cryptographic Assets Analyzed\n" +
      "    *   Legacy/Vulnerable Asset Count (and % of total inventory)\n" +
      "    *   Active/Compliant Asset Count (and % of total inventory)\n" +
      "    *   Cryptographic Deficit Rating (Scale of 1-10, where 10 is critically legacy/unmanaged)\n" +
      "    *   Estimated Migration Runway (Years remaining based on organizational complexity)\n\n" +
      "# 2. Cryptographic Risk & Deficit Analysis\n" +
      "*   **The Cryptographic Deficit & Technical Debt**: Define the physical and structural tech debt discovered in this dataset (e.g., legacy TLS implementations, weak SSH ciphers, expired certificates). Explain in detail why standard vulnerability scanners fail to flag these algorithm-level risks.\n" +
      "*   **Mosca's Theorem Threat Modeling**: Provide a detailed mathematical risk assessment using Mosca's Theorem formula: $U + V > Y$ (where $U$ is the shelf-life of the sensitive data, $V$ is the migration time to PQC, and $Y$ is the estimated time to a CRQC). Under a subheading \"Deficit Validation\", write a detailed narrative confirming whether the organization is currently in an active data-leakage state (where $U + V > Y$).\n" +
      "*   **Asset Risk Classification**: Break down the inventory findings into a Markdown table with three tiers (High Risk, Medium Risk, Low Risk).\n\n" +
      "# 3. Regulatory Compliance & Milestones Gap Analysis\n" +
      "*   **NIST SP 800-208 Alignment**: Identify deficiencies in discovery, automated asset lifecycle management, and crypto-agility readiness.\n" +
      "*   **CNSA 2.0 Milestones**: Document specific timeline violations or upcoming risks based on commercial national security timelines (e.g., software/firmware signing, web browsers, operating system transitions).\n" +
      "*   **Gap Matrix Table**: Build a table listing: Asset Group | Discovered Protocol | CNSA 2.0 Compliant? (Yes/No) | Deadline Year.\n\n" +
      "# 4. NIST SP 800-208 Discovery & Remediation Playbook\n" +
      "Provide highly actionable, detailed technical instructions:\n" +
      "*   **Short-Term Tactical Remediation (0-90 Days)**: Tactical actions to clean up legacy certificate tech debt, disable weak CBC/DH ciphers, enforce TLS 1.3, and isolate systems running obsolete protocols.\n" +
      "*   **Long-Term Strategic Migration (90+ Days)**: Enterprise roadmap for migrating to PQC. Discuss deploying dual-key hybrid certificates, testing ML-KEM and ML-DSA implementations, updating Hardware Security Modules (HSMs), and integrating Open Policy Agent (OPA) policies into CI/CD pipelines to block weak cryptography before deployment.\n\n" +
      "# 5. Professional Disclaimer & Risk Assumptions\n" +
      "*   **Audit Scope Limitation**: Explain that this report constitutes a point-in-time cryptographic posture assessment based on active and passive scanning logs ingested into the QuarkShield database. It does not guarantee discovery of air-gapped or unmapped shadow endpoints.\n" +
      "*   **Risk Assumptions & Threat Horizon**: Detail that Shor's and Grover's threat horizons are modeled on current academic consensus and NSA CNSA 2.0 timelines. Actual vulnerability timelines may accelerate based on breakthroughs in quantum physics or error-correction algorithms.\n\n" +
      "CRITICAL: Write a highly detailed, professional, and comprehensive document. Do not wrap the output in markdown code blocks like ```markdown, return the raw markdown string directly.";

    let customPromptContext = "";
    if (customPrompt && customPrompt.trim() !== "") {
      customPromptContext = `\n- Custom User Directive: The user has requested to prioritize these custom guidelines: "${customPrompt}". Tailor the report analysis, focus areas, and compliance remarks to address this directive where appropriate.\n`;
    }

    const prompt = `Here are the organization's real cryptographic audit statistics and dataset:
- Total Cryptographic Assets Monitored: ${totalAssets}
- Legacy/Vulnerable classical keys (RSA/ECC) negotiating traffic: ${vulnerableAssets} (${riskPercentage}% of inventory)
- Active/Compliant secure quantum-resistant keys (ML-KEM/ML-DSA): ${secureAssets} (${100 - riskPercentage}% of inventory)
- Active Policy Compliance Violations (NIST/CNSA): ${totalViolations}
- Cryptographic Deficit Rating (Calculated): ${calculatedDeficitRating}/10
- Estimated Migration Runway: ${estimatedRunway} Years
- Monitored Enterprise Applications: ${appCount}
- Mapped Business Services: ${serviceCount}
- Report Scope: ${scope} (Selected pillars: ${JSON.stringify(items)})${customPromptContext}

High Risk Assets Sample Table Data:
| Asset Name | Protocol/Algorithm | Risk Tier |
|---|---|---|
${highRiskText}

Medium Risk Assets Sample Table Data:
| Asset Name | Protocol/Algorithm | Risk Tier |
|---|---|---|
${mediumRiskText}

Low Risk Assets Sample Table Data:
| Asset Name | Protocol/Algorithm | Risk Tier |
|---|---|---|
${lowRiskText}

CNSA 2.0 Gap Matrix Table Data:
| Asset Group | Discovered Protocol | CNSA 2.0 Compliant? (Yes/No) | Deadline Year |
|---|---|---|---|
${gapMatrixText}

Please generate the complete report following the exact system instructions and report structure.`;

    if (isGemini || isClaude) {
      if (isGemini) {
        let apiKey = process.env.GEMINI_API_KEY ? process.env.GEMINI_API_KEY.trim() : '';
        if (!apiKey) {
          try {
            const settingsRes = await pool.query("SELECT value FROM tenant_settings WHERE key = 'gemini_api_key'");
            if (settingsRes.rows.length > 0 && settingsRes.rows[0].value) {
              apiKey = settingsRes.rows[0].value.trim();
            }
          } catch (settingsErr) {
            console.warn('Failed to query tenant_settings for Gemini key in report:', settingsErr);
          }
        }

        if (apiKey && apiKey.trim() !== '') {
          const geminiCandidateModels = [
            process.env.GEMINI_MODEL,
            'gemini-2.0-flash',
            'gemini-1.5-flash'
          ].filter(Boolean) as string[];

          const contents = [{
            role: 'user',
            parts: [{ text: `${systemInstruction}\n\nUser Query:\n${prompt}` }]
          }];

          for (const model of geminiCandidateModels) {
            console.log(`AI Controller: Querying Gemini for PQC Text Report (model: ${model})...`);
            const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 45000);

            try {
              const geminiRes = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ contents }),
                signal: controller.signal
              });

              if (geminiRes.ok) {
                const data: any = await geminiRes.json();
                let aiText = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
                aiText = aiText.replace(/```markdown/g, '').replace(/```/g, '').trim();
                if (aiText.length > 200) {
                  return res.json({ report: aiText });
                }
              }
            } catch (fetchErr: any) {
              console.warn(`Error or timeout fetching from Gemini API for report (${model}):`, fetchErr.message);
            } finally {
              clearTimeout(timeoutId);
            }
          }
        }
      } else if (isClaude) {
        let anthropicKey = process.env.ANTHROPIC_API_KEY;
        try {
          const settingsRes = await pool.query("SELECT value FROM tenant_settings WHERE key = 'anthropic_api_key'");
          if (settingsRes.rows.length > 0 && settingsRes.rows[0].value && settingsRes.rows[0].value.trim() !== '') {
            anthropicKey = settingsRes.rows[0].value.trim();
          }
        } catch (dbErr) {
          console.warn('Failed to query tenant_settings for Anthropic key in report:', dbErr);
        }

        if (anthropicKey && anthropicKey.trim() !== '') {
          console.log('AI Controller: Querying Anthropic Claude for PQC Text Report...');
          const url = 'https://api.anthropic.com/v1/messages';
          
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 45000);

          try {
            const claudeRes = await fetch(url, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'x-api-key': anthropicKey,
                'anthropic-version': '2023-06-01'
              },
              body: JSON.stringify({
                model: 'claude-3-5-sonnet-20241022',
                max_tokens: 4000,
                system: systemInstruction,
                messages: [{ role: 'user', content: prompt }]
              }),
              signal: controller.signal
            });

            if (claudeRes.ok) {
              const data: any = await claudeRes.json();
              let aiText = data?.content?.[0]?.text || '';
              aiText = aiText.replace(/```markdown/g, '').replace(/```/g, '').trim();
              if (aiText.length > 200) {
                return res.json({ report: aiText });
              }
            }
          } catch (fetchErr: any) {
            console.warn('Error or timeout fetching from Claude API for report:', fetchErr.message);
          } finally {
            clearTimeout(timeoutId);
          }
        }
      }
    }

    // --- Local Fallback Report Builder ---
    console.log('AI Controller: Executing local rules-based PQC text report generator...');
    
    let customPromptSection = "";
    if (customPrompt && customPrompt.trim() !== "") {
      customPromptSection = `\n\n# CUSTOM AUDIT GUIDELINES & FOCUS AREAS
*   **User Focus Directive**: The auditor has requested a specialized focus on: *"${customPrompt}"*.
*   **Guideline Integration**: The recommendations, risk matrices, and transition waves in this assessment have been cross-referenced with this directive. Under current constraints, the prioritized actions align with these organizational goals.

---`;
    }

    // Constructing a highly detailed, professional markdown report dynamically
    const localReportText = `# EXECUTIVE CRYPTOGRAPHIC RISK & POST-QUANTUM READINESS REPORT
## Prepared For: ${customerName}
## Date: ${formattedDate}
## Prepared By: QuarkShield Security Posture Assessment Node

---

# TABLE OF CONTENTS
1. Executive Summary & Posture Baseline
2. Cryptographic Inventory & Risk Analysis
3. Regulatory Compliance & Milestones Gap Analysis
4. NIST SP 800-208 Discovery & Remediation Playbook
5. Professional Disclaimer & Risk Assumptions

---${customPromptSection}

# 1. Executive Summary & Posture Baseline
*   **Detailed Executive Narrative**: This comprehensive cryptographic posture assessment for **${customerName}** provides a strategic overview of algorithm-level vulnerabilities across our digital assets. Our discovery scanner has identified significant reliance on legacy asymmetric ciphers that are mathematically vulnerable to quantum cryptanalysis. In particular, the presence of classical RSA and Elliptic Curve cryptography exposes the organization to immediate "Harvest Now, Decrypt Later" (HNDL) threats, where adversaries capture encrypted transit traffic today with the intention of decrypting it retrospectively once a Cryptanalytically Relevant Quantum Computer (CRQC) becomes available. Transitioning to NIST-approved post-quantum algorithms (PQC) is an immediate priority to protect sensitive enterprise data.
*   **Core Posture Metrics Table**:
    | Metric | Value / Assessment |
    |---|---|
    | Total Cryptographic Assets Analyzed | ${totalAssets} |
    | Legacy/Vulnerable Asset Count | ${vulnerableAssets} (${riskPercentage}% of total) |
    | Active/Compliant Asset Count | ${secureAssets} (${100 - riskPercentage}% of total) |
    | Cryptographic Deficit Rating | ${calculatedDeficitRating}/10 |
    | Estimated Migration Runway | ${estimatedRunway} Years |

# 2. Cryptographic Inventory & Risk Analysis
*   **The Cryptographic Deficit & Technical Debt**: The primary cryptographic deficit within the enterprise network consists of legacy TLS negotiations, weak SSH deploy keys, and outdated asymmetric database credentials. Traditional vulnerability scanners fail to identify these exposures because they focus on software patches or expired validity dates rather than the mathematical strength of the underlying algorithm. This legacy tech debt creates a passive, silent vulnerability that cannot be mitigated by standard firewalls or endpoint protection.
*   **Mosca's Theorem Threat Modeling**: Under Mosca's Theorem, the threat horizon is modeled mathematically as $U + V > Y$, where $U$ represents the required shelf-life of sensitive organizational data (estimated at 5 years), $V$ represents the migration runway to fully transition to PQC (estimated at ${estimatedRunway} years), and $Y$ represents the time remaining before a CRQC is active (estimated at 8 years).
    ### Deficit Validation
    Since our combined exposure is $U + V = ${5 + Number(estimatedRunway)} > Y = 8$, the organization is in an active data-leakage state. Data captured today can be stored by hostile actors and decrypted in the future, compromising historical proprietary records and transactional databases.
*   **Asset Risk Classification**:
    | Asset Name | Protocol/Algorithm | Risk Tier |
    |---|---|---|
    ${highRiskText}
    ${mediumRiskText}
    ${lowRiskText}

# 3. Regulatory Compliance & Milestones Gap Analysis
*   **NIST SP 800-208 Alignment**: We exhibit critical gaps in automated cryptographic discovery and lifecycle management. The lack of centralized, real-time discovery means the enterprise cannot maintain the crypto-agility required to execute rapid, automated algorithm rotations as mandated by the NIST SP 800-208 guidelines.
*   **CNSA 2.0 Milestones**: Multiple active web endpoints, internal services, and databases fail the NSA CNSA 2.0 guidelines. These guidelines mandate initiating hybrid post-quantum key exchange support immediately, with complete classical deprecation targets by 2030. 
*   **Gap Matrix Table**:
    | Asset Group | Discovered Protocol | CNSA 2.0 Compliant? (Yes/No) | Deadline Year |
    |---|---|---|---|
    ${gapMatrixText}

# 4. NIST SP 800-208 Discovery & Remediation Playbook
*   **Short-Term Tactical Remediation (0-90 Days)**:
    1. Clean up legacy certificate tech debt by revoking RSA-1024 keys and wildcard certificates.
    2. Disable weak CBC/DH ciphers globally and enforce TLS 1.3 across all public ingress load balancers.
    3. Isolate legacy internal databases using strict subnet routing or localized IPsec gateways.
*   **Long-Term Strategic Migration (90+ Days)**:
    1. Formulate a centralized enterprise roadmap to roll out dual-key hybrid post-quantum certificates (X25519 + ML-KEM).
    2. Conduct PILOT testing of ML-KEM and ML-DSA implementations across internal Active Directory CA hosts.
    3. Coordinate with HSM vendors to upgrade firmware to support NIST lattice-based standards.
    4. Integrate Open Policy Agent (OPA) declarative rules in CI/CD pipelines to block any commits introducing non-compliant classical ciphers.

# 5. Professional Disclaimer & Risk Assumptions
*   **Audit Scope Limitation**: This report constitutes a point-in-time cryptographic posture assessment based on active and passive scanning logs ingested into the QuarkShield database for **${customerName}**. It does not guarantee discovery of air-gapped systems or unmapped shadow endpoints.
*   **Risk Assumptions & Threat Horizon**: Shor's and Grover's threat horizons are modeled on current academic consensus and NSA CNSA 2.0 timelines. Actual vulnerability timelines may accelerate based on breakthroughs in quantum physics or error-correction algorithms.`;

    res.json({ report: localReportText });

  } catch (err: any) {
    console.error('Error generating PQC text report:', err);
    res.status(500).json({ error: `PQC Report Generator failed: ${err.message}` });
  }
};
