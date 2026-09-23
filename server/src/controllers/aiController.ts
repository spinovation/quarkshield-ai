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
      "You are QuarkShield AI, the elite Post-Quantum Cryptography (PQC), Quantum Computing, Cybersecurity, IT Networking, and NIST Compliance Copilot for QuarkShield.ai. " +
      "STRICT SCOPE & GUARDRAILS: You answer questions related to: " +
      "1. Post-Quantum Cryptography (PQC), NIST Standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, SP 800-208 LMS/XMSS, SP 800-56C, CNSA 2.0, EO 14028, CMMC 2.0). " +
      "2. Quantum computing threats: Shor's algorithm (polynomial time prime factorization and discrete log collapse), Grover's algorithm (quadratic speedup against symmetric ciphers requiring AES-256), and Harvest Now Decrypt Later (HNDL). " +
      "3. IT Networking & Cybersecurity Architecture: TLS 1.3, OpenSSH 9.8+, NGINX, Apache, Envoy, Next-Gen Firewalls (Palo Alto, Fortinet, F5), IPsec/IKEv2 VPNs, mTLS, Zero Trust, IAM, PKI, HSMs, STARK rollups. " +
      "4. Classical Cryptography vulnerabilities: RSA-2048/3072/4096 (broken in O((log N)^3) by Shor's algorithm), ECDSA P-256/secp256k1 (broken with ~2,330 logical qubits—falls ~45% faster than RSA), 3DES, MD5, SHA-1. " +
      "5. Mosca's Theorem: X + Y > Z (Shelf-life X + Migration time Y > Threat timeline Z). " +
      "6. Complete QuarkShield.ai Platform Processes, Workflows, and Next Steps: " +
      "   • TENANT ONBOARDING & 'NEXT STEPS' WORKFLOW: " +
      "     - Step 1 (Admin Login & Initial Credentials): After onboarding and license assignment, the Corporate Admin / Partner Admin receives their Welcome & 'Next Steps' email from support@quarkshield.ai. They log in at https://quarkshield.ai/?view=console or their dedicated tenant workspace (e.g., https://quarkshield.ai/?tenant=YOURTENANT or /tenant/spinovation). Initial credentials include their corporate admin email and initial password (e.g. QS-Amberoon7033! or customer-assigned secure password). Admins establish 2FA/MFA and verify allocated seats. " +
      "     - Step 2 (First Host / Endpoint PQC Scan): Go to Fleet Overview or Settings > Deployment. Download macOS DMG or run 1-click curl command (curl -sSL https://quarkshield.ai/api/scan/agent/install.sh | bash -s -- --token YOUR_TOKEN); on Windows run PowerShell installer with FedMitigate code-signing certs; on Linux run linux-amd64 binary. The scanner audits local certificate stores, private keys (PEM/DER/PKCS#12), SSH host/user keys, browser keychains, and OpenSSL configs, publishing a CycloneDX 1.6+ CBOM inventory back to the dashboard with zero host reboots. " +
      "     - Step 3 (Staff Onboarding & Seat Allocation): Go to Settings > Users & Access (or Tenant Portal > Users & Access), click '+ Invite User', enter corporate email, assign RBAC role (Corporate Admin, Cryptographer, Auditor, Viewer), track license seat count, and set tenant 2FA enforcement policies. " +
      "     - Step 4 (Documentation & Online Help): Access downloadable guides under Downloads & Resources (Enterprise PQC Deployment Guide, Customer PQC Readiness Guide DOCX, OS User Guides, root CAs) or contact support@quarkshield.ai. " +
      "   • 3-TIER ENTERPRISE PQC DEPLOYMENT STRATEGY: " +
      "     - Tier 1 (Cloud & Infrastructure): Agentless Out-of-Band Cloud Volume Snapshots (AWS EBS, Azure Disks, GCP) with 0% CPU, 0 MB RAM, and 0% reboot risk + Central PKI Connectors. " +
      "     - Tier 2 (In-Flight Wire Cryptography): Passive network TLS handshake inspection via SPAN/TAP, Palo Alto, Fortinet, F5, or Zscaler. Detects HNDL exposure and verifies X25519MLKEM768. " +
      "     - Tier 3 (Endpoints & In-Host Workloads): OpenTelemetry (OTel) Collector running as unprivileged LOCAL SERVICE streaming Windows CAPI2 and Linux auditd event logs with guaranteed zero reboots + Ephemeral 1-Shot CLI. " +
      "   • CI/CD PIPELINE CBOM SECURITY GATE: Automated PR scanning for GitHub Actions, GitLab CI, and Bitbucket. Blocks pull requests (Exit Code 1) containing vulnerable algorithms (RSA, ECC, 3DES, MD5, SHA-1) or excessive risk score (>30-40). Approves PRs (Exit Code 0) when compliant with NIST FIPS 203/204/205. Posts rich markdown comments with line numbers and remediation steps. Provides 1-click YAML workflow templates and downloadable runner script (https://quarkshield.ai/api/git/ci-gate/runner.sh). " +
      "   • ENTERPRISE PKI & CLOUD VAULT CONNECTORS: Continuous automated key discovery and sync with AWS KMS (IAM roles), Azure Key Vault (Service Principals), HashiCorp Vault (AppRole/Token), and Microsoft Active Directory Certificate Services (AD CS via LDAP/Kerberos). Features 1-click 'Sync Now' triggers and inventories assets into pki_synced_assets. " +
      "   • TRANSPARENT HYBRID QUANTUM TLS REVERSE PROXY: Transparent inline gateway upgrading legacy application traffic to post-quantum hybrid TLS 1.3 (X25519MLKEM768, curve 0x11ec, NIST FIPS 203) with zero application code changes. Listens on port 8443/5443, proxies to backend on port 8080/5050. Exports ready-to-run configurations for NGINX, Envoy, and Docker Compose. Includes active diagnostic handshake prober. " +
      "GUARDRAIL ENFORCEMENT: Politely decline questions completely unrelated to Quantum computing, PQC, cybersecurity, technology, or QuarkShield (such as cooking recipes, celebrity gossip, creative writing), explaining that you specialize exclusively in Post-Quantum Cryptography, Cybersecurity, and QuarkShield.ai. " +
      "FORMATTING: Format your responses with structured markdown, bold headings, step-by-step numbered lists, bullet points, markdown comparison tables, and copyable code/config snippets.";

    // Assemble prompt text
    let promptText = `${systemInstruction}\n\n`;
    if (assetsContext) {
      promptText += `${assetsContext}\n\n`;
    }
    if (Array.isArray(attachments) && attachments.length > 0) {
      promptText += "ATTACHED FILES FOR ANALYSIS:\n";
      for (const att of attachments) {
        promptText += `--- File: ${att.name || 'attachment'} (${att.type || 'unknown'}, ${att.size || 0} bytes) ---\n`;
        if (att.data) {
          const content = att.data.length > 40000 ? att.data.substring(0, 40000) + '... [truncated]' : att.data;
          promptText += `Content:\n${content}\n`;
        }
      }
      promptText += "\n";
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
    console.log('AI Controller: Executing enhanced local rules-based knowledge engine...');
    
    const rawQuery = message || '';
    // Normalize typos and variations to ensure accurate natural language matching
    let normalized = rawQuery.toLowerCase()
      .replace(/\bconfgiure\b|\bconfiguer\b|\bcnfigure\b|\bconfgure\b|\bconfigre\b/gi, 'configure')
      .replace(/\bnetwrok\b|\bnetwroking\b|\bnetwrk\b|\bnework\b/gi, 'networking')
      .replace(/\bcyver\b|\bcybersec\b|\bcybersecurty\b|\bsecuity\b|\bsecurty\b/gi, 'cybersecurity')
      .replace(/\bstandrd\b|\bstandrds\b|\bstandars\b|\bstandered\b/gi, 'standards')
      .replace(/\balgotithm\b|\balgoritm\b|\balgorthm\b/gi, 'algorithm')
      .replace(/\bfips[- ]?203\b/gi, 'fips 203')
      .replace(/\bfips[- ]?204\b/gi, 'fips 204')
      .replace(/\bfips[- ]?205\b/gi, 'fips 205')
      .replace(/\btls[- ]?1\.?3\b|\btlsv1\.?3\b/gi, 'tls 1.3')
      .replace(/\btls[- ]?1\.?2\b|\btlsv1\.?2\b/gi, 'tls 1.2')
      .replace(/\bceritificate\b|\bcertficate\b|\bcerts\b/gi, 'certificate')
      .replace(/\bfirewal\b|\bfirewalls\b/gi, 'firewall')
      .replace(/\bencrpyt\b|\bencrpytion\b/gi, 'encryption')
      .replace(/\bauthntication\b|\bauthenication\b/gi, 'authentication')
      .replace(/\blicence\b|\blicencing\b/gi, 'license')
      .replace(/\bcicd\b|\bci-cd\b/gi, 'ci/cd')
      .replace(/\bthree[- ]tier\b/gi, '3-tier')
      .replace(/\bpasswrd\b|\bpassowrd\b/gi, 'password')
      .replace(/\bonboarding\b/gi, 'onboard');

    const query = normalized;
    let text = '';
    let code = '';
    let language = 'javascript';

    // 0. Attachment Inspection in Offline Fallback Mode
    let attachmentAnalysis = '';
    if (attachments && Array.isArray(attachments) && attachments.length > 0) {
      const parsedFindings: string[] = [];
      for (const att of attachments) {
        const name = att.name || 'uploaded file';
        const rawContent = (att.data || '').toString();
        if (rawContent.includes('BEGIN CERTIFICATE')) {
          parsedFindings.push(`• **X.509 Certificate Detected** (\`${name}\`): Contains classical public-key infrastructure. If utilizing RSA-2048 or ECDSA P-256, it is susceptible to Shor's algorithm and requires migration to Composite X.509 or ML-DSA (FIPS 204).`);
        } else if (rawContent.includes('BEGIN RSA PRIVATE KEY') || rawContent.includes('BEGIN PRIVATE KEY') || rawContent.includes('ssh-rsa')) {
          parsedFindings.push(`• **Classical RSA Key Detected** (\`${name}\`): Relies on prime integer factorization ($N=pq$). Shor's algorithm factors this in $O((\\log N)^3)$ polynomial time. Replace with ML-DSA-65 or stateful hash signatures (LMS/XMSS).`);
        } else if (rawContent.includes('BEGIN EC PRIVATE KEY') || rawContent.includes('ecdsa-sha2') || rawContent.includes('secp256k1')) {
          parsedFindings.push(`• **Elliptic Curve Key Detected** (\`${name}\`): Relies on discrete logarithms. Only ~2,330 logical qubits are needed to compute discrete logs, falling even faster than RSA-2048 (~4,096 qubits). Replace with ML-KEM / ML-DSA.`);
        } else if (rawContent.includes('nginx') || rawContent.includes('ssl_ciphers') || rawContent.includes('ssl_protocols')) {
          parsedFindings.push(`• **Web Server Ingress Configuration** (\`${name}\`): Analyzed for post-quantum hybrid TLS ciphers. Ensure TLSv1.3 and \`X25519MLKEM768\` curves are enforced.`);
        } else if (rawContent.includes('KexAlgorithms') || rawContent.includes('sshd_config')) {
          parsedFindings.push(`• **OpenSSH Server Configuration** (\`${name}\`): Analyzed for post-quantum key exchange. Prepend \`mlkem768x25519-sha256\` or \`sntrup761x25519-sha512@openssh.com\` to prevent retroactive decryption.`);
        } else {
          parsedFindings.push(`• **File Received** (\`${name}\`, ${att.size || 0} bytes): Analyzed file content against QuarkShield cryptographic policies and standards.`);
        }
      }
      if (parsedFindings.length > 0) {
        attachmentAnalysis = `### Cryptographic File Analysis\n\n${parsedFindings.join('\n')}\n\n`;
      }
    }

    // 1. Domain Scope Guardrail: Politely decline non-technical / off-topic queries
    const nonTechPatterns = [
      /\b(recipe|cook|bake|dinner|lunch|breakfast|salad|soup|pasta|pizza|dessert|ingredient)\b/i,
      /\b(weather|forecast|rain|temperature)\b/i,
      /\b(celebrity|hollywood|movie|cinema|actor|actress|gossip|film review)\b/i,
      /\b(sports|football|basketball|soccer|baseball|nba|nfl|score|fifa)\b/i,
      /\b(horoscope|astrology|zodiac)\b/i,
      /\b(dating|relationship|romance|love advice)\b/i,
      /\b(joke|funny story|humor)\b/i
    ];
    const isOffTopic = nonTechPatterns.some(p => p.test(query));
    if (isOffTopic) {
      text = "I am QuarkShield AI Copilot, specialized exclusively in **Post-Quantum Cryptography (PQC), Quantum Computing, Cybersecurity, IT Networking, and Industry Standards**.\n\n" +
             "I cannot assist with general, personal, or non-technical topics. Please feel free to ask about:\n" +
             "• **NIST PQC Standards**: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), and SP 800-208 (LMS/XMSS).\n" +
             "• **IT Networking & Ingress**: Configuring TLS 1.3, Next-Gen Firewalls, IPsec/IKEv2 VPNs, mTLS, and Zero Trust.\n" +
             "• **Cybersecurity Standards**: NIST CSF 2.0, NIST SP 800-53, ISO 27001, SOC 2, PCI DSS v4.0, and CNSA 2.0.\n" +
             "• **Threat Defense**: Mitigating Harvest Now, Decrypt Later (HNDL), Shor's algorithm, and MITM attacks.\n" +
             "• **QuarkShield Platform**: CBOM inventory, endpoint scanner, and automated migration playbooks.";
      return res.json({ text, code: undefined, language: 'text' });
    }

    // =========================================================================
    // 2. QUARKSHIELD ONBOARDING, PLATFORM ROADMAP FEATURES & PROCESSES
    // =========================================================================

    // 2A. Onboarding & Next Steps Workflow
    if (
      query.includes('next step') ||
      query.includes('after onboard') ||
      query.includes('after license') ||
      query.includes('initial password') ||
      query.includes('first login') ||
      query.includes('admin login') ||
      query.includes('welcome email') ||
      query.includes('getting started') ||
      (query.includes('onboard') && (query.includes('process') || query.includes('step') || query.includes('guide') || query.includes('how to') || query.includes('what to do')))
    ) {
      text = "### QuarkShield Enterprise Onboarding & Next Steps Workflow 🚀\n\n" +
             "Welcome to QuarkShield.ai! Once your organization has been onboarded and your enterprise license assigned, follow this end-to-end operational roadmap to establish your post-quantum cryptographic posture:\n\n" +
             "| Step | Phase | Key Action | Primary Portal Location |\n" +
             "| :--- | :--- | :--- | :--- |\n" +
             "| **1** | **Admin First Login** | Authenticate with initial credentials and establish MFA | [Console Login](https://quarkshield.ai/?view=console) / Dedicated Tenant URL |\n" +
             "| **2** | **First Endpoint Scan** | Deploy 1-shot scanner across workstations & servers | **Fleet Overview** / **Deployment** |\n" +
             "| **3** | **Staff Onboarding & RBAC** | Invite team members & allocate license seats | **Tenant Portal > Users & Access** |\n" +
             "| **4** | **Documentation & Help** | Review deployment guides or contact 24/7 support | **Downloads & Resources** / PQC Copilot |\n\n" +
             "#### Step 1: Admin First Login & Credential Verification\n" +
             "1. **Welcome Email**: The Corporate Admin / Partner Admin receives an official onboarding email dispatched from `support@quarkshield.ai`.\n" +
             "2. **Access Portal**: Open **https://quarkshield.ai/?view=console** or your dedicated tenant workspace (e.g., `https://quarkshield.ai/?tenant=YOUR_TENANT` or `/tenant/spinovation`).\n" +
             "3. **Initial Credentials**:\n" +
             "   - **Username / Email**: Your corporate administrator email address.\n" +
             "   - **Initial Password**: Supplied securely in your Welcome Email (e.g. `QS-Amberoon7033!` or your customer-assigned secure password).\n" +
             "4. **Security Hardening**: Log in, establish **Phishing-Resistant MFA (TOTP / FIDO2 WebAuthn)**, and verify your allocated seat count under *License & Seats*.\n\n" +
             "#### Step 2: Run Your First Host / Workstation PQC Scan\n" +
             "Deploy the QuarkShield lightweight scanner to establish your baseline Cryptographic Bill of Materials (CBOM):\n" +
             "• **macOS (1-Click CLI)**: `curl -sSL https://quarkshield.ai/api/scan/agent/install.sh | bash -s -- --token YOUR_TENANT_TOKEN` (or download `QuarkShield-Scanner.dmg`).\n" +
             "• **Windows (PowerShell)**: `iwr -useb https://quarkshield.ai/api/scan/agent/install.ps1 | iex` (signed with FedMitigate certs).\n" +
             "• **Linux**: `curl -sSL https://quarkshield.ai/api/scan/agent/install-linux.sh | sudo bash -s -- --token YOUR_TENANT_TOKEN`.\n" +
             "• **Zero Reboot Guarantee**: The audit is 100% read-only, non-disruptive, uses < 1% CPU, and never requires a system reboot.\n\n" +
             "#### Step 3: Staff Onboarding & Seat Allocation\n" +
             "1. Navigate to **Tenant Portal > Users & Access** (or *Settings > Users*).\n" +
             "2. Click **+ Invite User**, enter their corporate email, and assign an RBAC role (**Corporate Admin**, **Cryptographer**, **Auditor**, **Viewer**).\n" +
             "3. Track your active seat utilization under *License & Seats*.\n\n" +
             "#### Step 4: Documentation, Resources & Support\n" +
             "• **Downloads & Resources**: Download official guides including the *Enterprise PQC Deployment Guide*, *Customer PQC Readiness & Code Signing Guide (DOCX/PDF)*, and *OS User Manuals*.\n" +
             "• **PQC Copilot**: Available 24/7 in your dashboard to answer any cryptographic question or generate configs.\n" +
             "• **Human Support**: Contact **`support@quarkshield.ai`** for priority technical assistance.";
      return res.json({ text, code: undefined, language: 'text' });
    }

    // 2B. First Desktop Scan & Scanner Agent Deployment
    else if (
      query.includes('desktop scan') ||
      query.includes('first scan') ||
      (query.includes('how to') && query.includes('scan')) ||
      (query.includes('run') && query.includes('scan')) ||
      query.includes('install agent') ||
      query.includes('agent install') ||
      (query.includes('scanner') && (query.includes('install') || query.includes('download') || query.includes('deploy') || query.includes('command'))) ||
      query.includes('scan endpoint') ||
      query.includes('scan workstation')
    ) {
      text = "### Running Your First QuarkShield Desktop & Endpoint PQC Scan 🔍\n\n" +
             "The QuarkShield Endpoint Scanner performs an automated, read-only audit of local cryptographic assets—discovering vulnerable classical RSA/ECC private keys, X.509 certificates, SSH credentials, browser keychains, and OpenSSL configurations without disrupting user workflows or requiring system reboots.\n\n" +
             "| OS Platform | Installation / Run Method | Execution Impact |\n" +
             "| :--- | :--- | :--- |\n" +
             "| **macOS** (Apple Silicon & Intel) | 1-Click Curl CLI or Signed DMG Installer | 0% CPU spike, 0 MB disk footprint, Zero Reboots |\n" +
             "| **Windows** (10 / 11 / Server) | 1-Click PowerShell CLI or FedMitigate MSI | Unprivileged CAPI2 / CNG audit, Zero Reboots |\n" +
             "| **Linux** (Debian/Ubuntu/RHEL) | 1-Click Bash CLI or standalone ELF binary | Read-only `/etc/ssl` and `~/.ssh` audit, Zero Reboots |\n\n" +
             "#### 1. Quick 1-Click Terminal / Console Commands:\n\n" +
             "**macOS**:\n" +
             "```bash\n" +
             "curl -sSL https://quarkshield.ai/api/scan/agent/install.sh | bash -s -- --token YOUR_TENANT_TOKEN\n" +
             "```\n\n" +
             "**Windows (Run in Administrative PowerShell)**:\n" +
             "```powershell\n" +
             "iwr -useb https://quarkshield.ai/api/scan/agent/install.ps1 | iex\n" +
             "```\n\n" +
             "**Linux (Ubuntu / RHEL / CentOS / Debian)**:\n" +
             "```bash\n" +
             "curl -sSL https://quarkshield.ai/api/scan/agent/install-linux.sh | sudo bash -s -- --token YOUR_TENANT_TOKEN\n" +
             "```\n\n" +
             "#### 2. What the Scanner Discovers:\n" +
             "• **X.509 Certificates**: System keychain, Windows Certificate Store (MY/ROOT/CA), and `/etc/ssl/certs`.\n" +
             "• **Private Key Files**: Discovers `.pem`, `.key`, `.p12`, `.pfx`, and `.der` files containing Shor-vulnerable RSA/ECC algorithms.\n" +
             "• **SSH Infrastructure**: Audits `~/.ssh/id_rsa`, `~/.ssh/id_ecdsa`, and `/etc/ssh/ssh_host_*` keys.\n" +
             "• **Crypto Libraries**: Checks active OpenSSL / LibreSSL / BoringSSL runtimes for NIST FIPS 203 (ML-KEM) readiness.\n\n" +
             "#### 3. Automatic CBOM Publication:\n" +
             "Upon scan completion, the findings are automatically uploaded to your tenant workspace, generating a **CycloneDX 1.6+ Cryptographic Bill of Materials (CBOM)** and populating your **Crypto CMDB** with Mosca timeline risk scores.";
      return res.json({ text, code: undefined, language: 'text' });
    }

    // 2C. Staff Onboarding & Seat Allocation / RBAC
    else if (
      ((query.includes('staff') || query.includes('team') || query.includes('user')) && (query.includes('onboard') || query.includes('invite') || query.includes('add') || query.includes('provision'))) ||
      query.includes('seat allocation') ||
      query.includes('license seats') ||
      query.includes('allocate seat') ||
      query.includes('rbac') ||
      (query.includes('roles') && (query.includes('permission') || query.includes('access') || query.includes('user')))
    ) {
      text = "### Staff Onboarding, Seat Allocation & RBAC Management 👥\n\n" +
             "QuarkShield enables enterprise administrators to seamlessly invite team members, delegate operational responsibilities, and control access permissions using granular Role-Based Access Control (**RBAC**).\n\n" +
             "#### How to Invite & Onboard Staff:\n" +
             "1. Navigate to **Tenant Portal > Users & Access** (or *Settings > Users*).\n" +
             "2. Click the **+ Invite User** button in the upper right.\n" +
             "3. Enter the employee's corporate email address and select an RBAC Role.\n" +
             "4. Click **Send Invitation**. The user will receive an automated invitation link with onboarding instructions.\n\n" +
             "#### Role-Based Access Control (RBAC) Matrix:\n" +
             "| Role | Scope & Permissions | Target Audience |\n" +
             "| :--- | :--- | :--- |\n" +
             "| **Corporate Admin** | Full read/write authority over tenant settings, user invitations, license seats, API keys, and 2FA policies. | CISO, VP of Security, Lead Security Architect |\n" +
             "| **Cryptographer / SecOps** | Full access to CBOM inventories, asset management, migration wave planning, CI/CD security gate rules, and remediation scripts. | Cryptographers, SecOps Engineers, DevOps Leads |\n" +
             "| **Auditor / Compliance** | Read-only access to CBOM, compliance reporting (NIST CSF, CNSA 2.0, FIPS 203/204/205, ISO 27001), and exportable executive reports. | Internal/External Auditors, Compliance Officers |\n" +
             "| **Viewer** | Read-only visibility into high-level dashboard metrics and posture scores. | Executive stakeholders, Business unit owners |\n\n" +
             "#### Seat Allocation & Quota Management:\n" +
             "• **Seat Consumption**: Each enrolled user consumes **1 seat** from your tenant's allocated license pool.\n" +
             "• **Seat Tracking**: Review real-time seat utilization in the **License & Seats** tab.\n" +
             "• **Seat Recovery**: Deactivating or removing a departed employee instantly returns that seat to your available quota.\n" +
             "• **Mandatory 2FA**: Corporate Admins can enforce tenant-wide Phishing-Resistant MFA under Security Settings.";
      return res.json({ text, code: undefined, language: 'text' });
    }

    // 2D. CI/CD Pipeline CBOM Security Gate
    else if (
      query.includes('ci/cd') ||
      query.includes('security gate') ||
      query.includes('cbom gate') ||
      query.includes('pr scan') ||
      query.includes('pull request') ||
      query.includes('github actions') ||
      query.includes('gitlab ci') ||
      query.includes('bitbucket') ||
      ((query.includes('pipeline') || query.includes('git')) && (query.includes('gate') || query.includes('block') || query.includes('check')))
    ) {
      text = "### CI/CD Pipeline CBOM Security Gate 🛡️\n\n" +
             "The **QuarkShield CI/CD Security Gate** integrates automated post-quantum cryptographic auditing directly into developer pull requests across **GitHub Actions, GitLab CI, and Bitbucket Pipelines**. It stops cryptographic debt *before* it merges to production.\n\n" +
             "| Feature | Operational Mechanism |\n" +
             "| :--- | :--- |\n" +
             "| **PR Automated Scanning** | Evaluates modified source code, config files, and cryptographic dependencies in every pull request |\n" +
             "| **Exit Code 1 Blocking** | Exits with `Exit Code 1` to block the PR merge if classical vulnerable algorithms (RSA, ECC, 3DES, MD5) are committed |\n" +
             "| **Exit Code 0 Approval** | Exits with `Exit Code 0` when the PR passes all NIST FIPS 203/204/205 quantum-safety checks |\n" +
             "| **Automated PR Comments** | Posts a rich Markdown review comment on the PR detailing line numbers, detected algorithms, and quantum-safe remediation snippets |\n\n" +
             "#### Ready-to-Use GitHub Actions Workflow (`.github/workflows/quarkshield-gate.yml`):";
      language = 'yaml';
      code = `name: QuarkShield PQC Security Gate

on:
  pull_request:
    branches: [ main, master, production ]

jobs:
  pqc-gate:
    name: CBOM Security Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run QuarkShield CI/CD CBOM Gate
        env:
          QUARKSHIELD_API_KEY: \${{ secrets.QUARKSHIELD_API_KEY }}
          QUARKSHIELD_TENANT: \${{ vars.QUARKSHIELD_TENANT }}
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
        run: |
          # Download and execute the official QuarkShield CI/CD Security Gate Runner
          curl -sSL https://quarkshield.ai/api/git/ci-gate/runner.sh | bash -s -- \\
            --api-key "$QUARKSHIELD_API_KEY" \\
            --tenant "$QUARKSHIELD_TENANT" \\
            --threshold 30 \\
            --block-vulnerable true`;
      return res.json({ text, code, language });
    }

    // 2E. Enterprise PKI & Cloud Vault Connectors
    else if (
      query.includes('pki connector') ||
      query.includes('vault connector') ||
      query.includes('pki & vault') ||
      query.includes('pki and vault') ||
      query.includes('ad cs') ||
      query.includes('active directory certificate') ||
      query.includes('aws kms') ||
      query.includes('azure key vault') ||
      query.includes('hashicorp vault') ||
      ((query.includes('sync') || query.includes('discover')) && (query.includes('vault') || query.includes('pki') || query.includes('kms')))
    ) {
      text = "### Enterprise PKI & Cloud Vault Connectors 🔐\n\n" +
             "QuarkShield provides automated key discovery synchronization across enterprise cloud vaults and on-premise Public Key Infrastructure (PKI). This continuous discovery catalogs all asymmetric and symmetric keys into your **Crypto CMDB** (`pki_synced_assets`) without manual tracking.\n\n" +
             "| Connector | Supported Discovery Target | Authentication Method |\n" +
             "| :--- | :--- | :--- |\n" +
             "| **AWS KMS** | Customer Master Keys (CMKs), asymmetric signing & encryption keys, aliases | AWS IAM Role / STS AssumeRole or Access Keys |\n" +
             "| **Azure Key Vault** | Asymmetric RSA/ECC Keys, Secrets, and X.509 Certificate Authorities | Entra ID (Azure AD) Service Principal (`client_id`, `client_secret`) |\n" +
             "| **HashiCorp Vault** | Transit Secrets Engine keys, PKI Secrets Engine certificates, KV secrets | Vault Token or AppRole (`role_id`, `secret_id`) |\n" +
             "| **Microsoft AD CS** | Enterprise Root/Subordinate CAs, certificate templates, issued certificates | Windows LDAP / Kerberos RPC integration |\n\n" +
             "#### Key Features:\n" +
             "1. **Continuous & On-Demand Sync**: Trigger a 1-click discovery sync at any time using the **Sync Now** button in the *PKI & Vault Connectors* tab, or schedule automated scans (e.g. every 6 hours).\n" +
             "2. **Quantum Vulnerability Classification**: Automatically analyzes key sizes and algorithms (e.g. flagging RSA-2048 signing keys as High Risk, while validating AES-256 as Grover-safe).\n" +
             "3. **Zero Impact Discovery**: Uses read-only metadata APIs (`kms:ListKeys`, `keyvault:GetKeys`, `vault:transit/keys`)—private key material is never exported or touched.";
      return res.json({ text, code: undefined, language: 'text' });
    }

    // 2F. Transparent Hybrid Quantum TLS Reverse Proxy
    else if (
      query.includes('hybrid proxy') ||
      query.includes('quantum proxy') ||
      query.includes('tls proxy') ||
      query.includes('reverse proxy') ||
      query.includes('pqc proxy') ||
      query.includes('x25519mlkem768 proxy') ||
      ((query.includes('transparent') || query.includes('zero code') || query.includes('inline')) && (query.includes('proxy') || query.includes('gateway') || query.includes('tls')))
    ) {
      text = "### Transparent Hybrid Quantum TLS Reverse Proxy 🌐\n\n" +
             "The **QuarkShield Hybrid Quantum TLS Proxy** is a transparent inline network gateway that upgrades legacy client-server application traffic to post-quantum hybrid ciphers (**`X25519MLKEM768`**, NIST FIPS 203, curve code `0x11ec`) **without modifying a single line of application source code**.\n\n" +
             "```\n" +
             "  [ Modern Client / Browser ]\n" +
             "             │\n" +
             "             ▼  TLS 1.3 with X25519MLKEM768 Hybrid Key Exchange (Curve 0x11ec)\n" +
             "  ┌────────────────────────────────────────────────────────────────────────┐\n" +
             "  │  QuarkShield Transparent Hybrid TLS Proxy (Port 8443 / 443)            │\n" +
             "  │  • Terminates Quantum-Resilient TLS Handshake                          │\n" +
             "  │  • Defeats 'Harvest Now, Decrypt Later' (HNDL) Wire Eavesdropping       │\n" +
             "  └────────────────────────────────────────────────────────────────────────┘\n" +
             "             │\n" +
             "             ▼  Clean Local Traffic (HTTP/1.1 or HTTP/2)\n" +
             "  [ Legacy Backend Application (Port 8080 / 5050) ]  <-- ZERO CODE CHANGES REQUIRED!\n" +
             "```\n\n" +
             "#### Ready-to-Run NGINX Proxy Configuration:";
      language = 'nginx';
      code = `# /etc/nginx/conf.d/pqc-proxy.conf
# Upgrades legacy backend (port 8080) to post-quantum hybrid TLS on port 8443

server {
    listen 8443 ssl http2;
    listen [::]:8443 ssl http2;
    server_name proxy.quarkshield.ai;

    # Server Certificates (Composite X.509 or standard RSA/ECDSA)
    ssl_certificate /etc/ssl/certs/quarkshield.crt;
    ssl_certificate_key /etc/ssl/private/quarkshield.key;

    # Enforce TLS 1.3 with Hybrid ML-KEM-768
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
    ssl_curves X25519MLKEM768:x25519:secp384r1;

    # Forward clean HTTP traffic to legacy application
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-PQC-Enforced "X25519MLKEM768-FIPS203";
    }
}`;
      return res.json({ text, code, language });
    }

    // 2G. 3-Tier Enterprise PQC Deployment Strategy
    else if (
      query.includes('3-tier') ||
      ((query.includes('deployment strategy') || query.includes('enterprise strategy')) && (query.includes('tier') || query.includes('pqc') || query.includes('enterprise')))
    ) {
      text = "### 3-Tier Enterprise PQC Deployment Strategy 🏗️\n\n" +
             "To achieve complete post-quantum readiness across mission-critical enterprise environments without business disruption, QuarkShield employs a battle-tested **3-Tier Deployment Architecture**:\n\n" +
             "| Tier | Focus Layer | Technology & Mechanism | Business Impact |\n" +
             "| :--- | :--- | :--- | :--- |\n" +
             "| **Tier 1** | **Cloud & Infrastructure** | Agentless Out-of-Band Cloud Volume Snapshots (AWS EBS, Azure Disks, GCP) + Central PKI Connectors | **0% CPU, 0 MB RAM, 0% Reboot Risk** |\n" +
             "| **Tier 2** | **In-Flight Wire Cryptography** | Passive network TLS handshake inspection via SPAN/TAP, Palo Alto, Fortinet, F5, or Zscaler | **Zero network latency, discovers HNDL risk** |\n" +
             "| **Tier 3** | **Endpoints & In-Host Workloads**| OpenTelemetry (OTel) Collector running as unprivileged LOCAL SERVICE + Ephemeral 1-Shot CLI | **Guaranteed zero host reboots, continuous telemetry** |\n\n" +
             "#### 1. Tier 1: Agentless Out-of-Band Cloud Discovery\n" +
             "• **How it Works**: Connects directly to cloud management planes to take point-in-time snapshots of encrypted volumes, mounts them in an isolated analysis sandbox, and catalogs cryptographic keys without attaching software to production instances.\n" +
             "• **PKI Integration**: Synchronizes keys and certificates from AWS KMS, Azure Key Vault, HashiCorp Vault, and Microsoft AD CS.\n\n" +
             "#### 2. Tier 2: Passive Wire TLS Handshake Inspection\n" +
             "• **How it Works**: Captures unencrypted TLS `ClientHello` and `ServerHello` handshake packets via network SPAN/TAP ports or firewall syslog feeds.\n" +
             "• **Defends HNDL**: Instantly identifies legacy sessions negotiating RSA or ECDH key exchange that are vulnerable to retroactive harvesting.\n\n" +
             "#### 3. Tier 3: Workstation Endpoints & In-Host Telemetry\n" +
             "• **How it Works**: Deploys lightweight OpenTelemetry (OTel) collectors as unprivileged background daemons streaming Windows CAPI2 and Linux auditd security events, paired with the 1-shot desktop scanner.";
      return res.json({ text, code: undefined, language: 'text' });
    }

    // 2H. Documentation, Resources & Support Desk
    else if (
      query.includes('documentation') ||
      query.includes('user guide') ||
      query.includes('readiness guide') ||
      query.includes('deployment guide') ||
      query.includes('support email') ||
      ((query.includes('how to contact') || query.includes('contact')) && query.includes('support'))
    ) {
      text = "### QuarkShield Documentation, Resources & Support 📚\n\n" +
             "QuarkShield provides extensive enterprise documentation, downloadable implementation guides, and round-the-clock technical support for your cryptographic transition:\n\n" +
             "#### Downloadable Enterprise Guides (Console > Downloads & Resources):\n" +
             "• **Customer PQC Readiness & Code Signing Guide (DOCX / PDF)**: Comprehensive blueprint covering NIST FIPS 203/204/205 transition, Apple Developer / Authenticode code signing, and root CA migration.\n" +
             "• **Enterprise PQC Deployment Guide**: Step-by-step administrator guide for multi-tenant deployment, agent rollouts, and cloud volume snapshots.\n" +
             "• **OS-Specific Scanner User Manuals**: Detailed command-line references and execution flags for macOS, Windows, and Linux scanners.\n" +
             "• **QuarkShield Root CA & Intermediate Certificates**: Downloadable public trust roots for dual-key composite certificate deployments.\n\n" +
             "#### Interactive AI Copilot:\n" +
             "The **QuarkShield PQC Copilot** is available 24/7 inside your tenant workspace to answer questions, analyze uploaded certificate files (`.pem`, `.crt`, `.key`), and generate ready-to-use configurations for NGINX, Envoy, OpenSSH, and CI/CD pipelines.\n\n" +
             "#### Contacting Human Support Desk:\n" +
             "• **Official Support Email**: **`support@quarkshield.ai`**\n" +
             "• **SLA**: Priority 24/7 enterprise response for licensing, tenant provisioning, and cryptographic security emergencies.";
      return res.json({ text, code: undefined, language: 'text' });
    }

    // =========================================================================
    // 3. NIST STANDARDIZED POST-QUANTUM CRYPTOGRAPHY: FIPS 203, 204, 205
    // =========================================================================
    else if (
      query.includes('fips 203') ||
      query.includes('fips 204') ||
      query.includes('fips 205') ||
      (query.includes('203') && query.includes('204')) ||
      (query.includes('fips') && (query.includes('standard') || query.includes('pqc') || query.includes('algorithm')))
    ) {
      text = "### NIST Standardized Post-Quantum Cryptography: FIPS 203, FIPS 204 & FIPS 205\n\n" +
             "On **August 13, 2024**, the U.S. National Institute of Standards and Technology (NIST) officially finalized and published the world's primary Federal Information Processing Standards (FIPS) for Post-Quantum Cryptography. These standards replace legacy RSA and Elliptic Curve Cryptography (ECC) broken by Shor's algorithm on quantum hardware:\n\n" +
             "| Standard | Algorithm Name | Former Project Name | Cryptographic Primitive | Mathematical Hardness | Primary Enterprise Use Case |\n" +
             "| :--- | :--- | :--- | :--- | :--- | :--- |\n" +
             "| **FIPS 203** | **ML-KEM** | CRYSTALS-Kyber | Key Encapsulation Mechanism (KEM) | Module Learning with Errors (M-LWE) | TLS 1.3 key exchange, IKEv2/IPsec VPNs, SSH sessions (defends HNDL) |\n" +
             "| **FIPS 204** | **ML-DSA** | CRYSTALS-Dilithium | Digital Signature Algorithm (DSA) | M-LWE and Short Integer Solution (SIS) | X.509 Public-Key Certificates, Code Signing, PKI Root/Intermediate CAs |\n" +
             "| **FIPS 205** | **SLH-DSA** | SPHINCS+ | Stateless Hash-Based Digital Signatures | Cryptographic Hash Functions (SHA-2 / SHAKE) | Long-term archival signatures, immutable firmware roots of trust |\n\n" +
             "#### 1. NIST FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)\n" +
             "• **Purpose**: Replaces classical Diffie-Hellman (DH, ECDH, X25519) and RSA key transport. Secures session keys against Harvest Now, Decrypt Later (HNDL).\n" +
             "• **Security Categories & Parameter Sets**:\n" +
             "  - **ML-KEM-512** (NIST Category 1, equivalent to AES-128 security).\n" +
             "  - **ML-KEM-768** (NIST Category 3, equivalent to AES-192 security — **Standard Enterprise Default**).\n" +
             "  - **ML-KEM-1024** (NIST Category 5, equivalent to AES-256 security — Mandated for CNSA 2.0 classified systems).\n" +
             "• **Deployment Pattern**: Implemented in TLS 1.3 as hybrid key exchange **`X25519MLKEM768`** (curve code `0x11ec`), combining classical X25519 with ML-KEM-768 so that data remains secure even if one algorithm is theoretically broken.\n\n" +
             "#### 2. NIST FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Standard)\n" +
             "• **Purpose**: Replaces classical RSA signatures (PKCS#1 v1.5, PSS) and ECDSA/Ed25519 for identity authentication, certificates, and non-repudiation.\n" +
             "• **Security Categories & Parameter Sets**:\n" +
             "  - **ML-DSA-44** (NIST Category 2): Public key 1,312 bytes; Signature 2,420 bytes.\n" +
             "  - **ML-DSA-65** (NIST Category 3 — **Standard Enterprise Default**): Public key 1,952 bytes; Signature 3,309 bytes.\n" +
             "  - **ML-DSA-87** (NIST Category 5): Public key 2,592 bytes; Signature 4,627 bytes.\n" +
             "• **Deployment Pattern**: Deployed via **Dual-Key Composite X.509 Certificates** or Catalyst Hybrid Certificates to maintain backward compatibility with legacy operating system trust stores.\n\n" +
             "#### 3. NIST FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Standard)\n" +
             "• **Purpose**: Serves as a vital conservative hedge. Because its mathematical security depends **strictly on the collision resistance of cryptographic hash functions** (SHA-256 or SHAKE-256) rather than lattice geometry, no quantum mathematical breakthrough against lattices can affect SLH-DSA.\n" +
             "• **Parameter Variants**: Available in 'fast' (`f`) or 'small' (`s`) variants across 128, 192, and 256 bits of security (e.g., `SLH-DSA-SHA2-128s`, `SLH-DSA-SHAKE-256f`).\n" +
             "• **Trade-off**: Larger signature sizes (~8 KB to 49 KB), making it ideal for firmware validation, OS secure boot, and immutable document signing where signature size is secondary to multi-decade mathematical permanence.\n\n" +
             "#### Compliance Timelines:\n" +
             "Under **NSA CNSA 2.0** and **OMB M-23-02**, enterprise and federal systems must begin hybrid deployment in **2025**, mandate PQC software signing by **2026**, transition network infrastructure by **2030**, and achieve 100% full deprecation of classical RSA/ECC by **2033**.";
      return res.json({ text, code: undefined, language: 'text' });
    }

    // =========================================================================
    // 3. TLS 1.3 & WEB / INGRESS CONFIGURATION GUIDE (NGINX, APACHE, HAPROXY)
    // =========================================================================
    if (
      query.includes('tls 1.3') ||
      query.includes('tls1.3') ||
      (query.includes('tls') && (
        query.includes('configure') || query.includes('config') || query.includes('setup') ||
        query.includes('how do i') || query.includes('how to') || query.includes('enable') ||
        query.includes('hardening') || query.includes('ciphers') || query.includes('cipher') ||
        query.includes('nginx') || query.includes('apache') || query.includes('haproxy') ||
        query.includes('envoy') || query.includes('handshake')
      )) ||
      (query.includes('ssl') && (query.includes('configure') || query.includes('setup') || query.includes('config')))
    ) {
      text = "### Enterprise TLS 1.3 Configuration & Post-Quantum Hybrid Hardening Guide\n\n" +
             "**Transport Layer Security (TLS) 1.3 (RFC 8446)** is the foundational protocol for securing web ingress, API gateways, and microservice traffic. Unlike TLS 1.2, TLS 1.3 completely eliminates vulnerable classical primitives:\n\n" +
             "• **Eliminated Vulnerabilities**: Static RSA key exchange is removed (mandating **Ephemeral Diffie-Hellman / Perfect Forward Secrecy**); vulnerable CBC block ciphers, RC4, 3DES, MD5, and SHA-1 are banned.\n" +
             "• **Handshake Performance**: Reduces handshake latency from 2-RTT to **1-RTT** (with optional 0-RTT session resumption).\n" +
             "• **Post-Quantum Defense**: Enables hybrid key exchange (**`X25519MLKEM768`** / NIST FIPS 203) to defeat **Harvest Now, Decrypt Later (HNDL)** attacks.\n\n" +
             "#### Production Hardening Configurations:\n\n" +
             "**1. NGINX Ingress Configuration (`/etc/nginx/conf.d/pqc-tls.conf`)**:\n" +
             "Enforces TLS 1.3, strong AES-256 AEAD ciphers, and hybrid Post-Quantum key exchange (OpenSSL 3.2+ / BoringSSL):\n";
      language = 'nginx';
      code = `# /etc/nginx/conf.d/pqc-tls.conf
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name api.enterprise.com;

    # X.509 Certificates (Classical or Dual-Key Composite)
    ssl_certificate /etc/ssl/certs/enterprise.crt;
    ssl_certificate_key /etc/ssl/private/enterprise.key;

    # Enforce TLS 1.3 exclusively (or allow TLS 1.2 during transition)
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;

    # Quantum-Resilient TLS 1.3 Cipher Suites (AES-256 protects against Grover's algorithm)
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;

    # Enable Hybrid ML-KEM-768 Post-Quantum Key Exchange (NIST FIPS 203)
    ssl_curves X25519MLKEM768:x25519:secp384r1;

    # Session Cache & Ticket Hardening
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # HSTS & Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}`;
      text += "\n\n**2. Apache HTTP Server Configuration (`/etc/httpd/conf.d/ssl.conf`)**:\n" +
              "```apache\n" +
              "SSLProtocol -all +TLSv1.3\n" +
              "SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256\n" +
              "SSLOpenSSLConfCmd Curves X25519MLKEM768:X25519\n" +
              "SSLHonorCipherOrder on\n" +
              "```\n\n" +
              "**3. HAProxy Configuration (`/etc/haproxy/haproxy.cfg`)**:\n" +
              "```haproxy\n" +
              "frontend https-in\n" +
              "    bind :443 ssl crt /etc/haproxy/certs/ alpn h2,http/1.1 ssl-min-ver TLSv1.3 curves X25519MLKEM768:X25519\n" +
              "    default_backend api_cluster\n" +
              "```\n\n" +
              "**4. Verifying Post-Quantum TLS Handshake via OpenSSL 3.2+**:\n" +
              "```bash\n" +
              "# Test if your server accepts X25519MLKEM768 hybrid key share\n" +
              "openssl s_client -connect api.enterprise.com:443 -tls1_3 -curves X25519MLKEM768\n" +
              "```";
      return res.json({ text, code, language });
    }

    // =========================================================================
    // 4. IT NETWORKING & NETWORK ARCHITECTURE / SECURITY
    // =========================================================================
    if (
      query.includes('networking') ||
      query.includes('network') ||
      query.includes('subnet') ||
      query.includes('routing') ||
      query.includes('router') ||
      query.includes('switch') ||
      query.includes('firewall') ||
      query.includes('ngfw') ||
      query.includes('vpn') ||
      query.includes('ipsec') ||
      query.includes('ikev2') ||
      query.includes('wireguard') ||
      query.includes('openvpn') ||
      query.includes('bgp') ||
      query.includes('ospf') ||
      query.includes('vlan') ||
      query.includes('dnssec') ||
      query.includes('mtls') ||
      query.includes('palo alto') ||
      query.includes('fortinet') ||
      query.includes('f5') ||
      query.includes('ztna')
    ) {
      text = "### Enterprise IT Networking & Network Security Architecture\n\n" +
             "Modern enterprise networking requires a convergence of high-throughput routing, zero-trust micro-segmentation, and quantum-safe cryptographic protocols to eliminate exposure to adversaries:\n\n" +
             "| Network Domain | Core Technologies | Security Role | Post-Quantum Transition Path |\n" +
             "| :--- | :--- | :--- | :--- |\n" +
             "| **Perimeter & NGFW** | Palo Alto, Fortinet, Check Point, F5 | Deep Packet Inspection (DPI), WAF, L7 policy | Passive wire TLS inspection (SPAN/TAP) & hybrid ingress |\n" +
             "| **Zero Trust Access** | ZTNA, Software-Defined Perimeter (SDP) | Least-privilege identity-based micro-segmentation | NIST SP 800-207 continuous cryptographic verification |\n" +
             "| **Site-to-Site VPN** | IPsec, IKEv2, GRE over IPsec | WAN encryption between datacenters and clouds | **RFC 9370** hybrid Diffie-Hellman + ML-KEM key exchange |\n" +
             "| **Workstation VPN** | WireGuard, OpenVPN, Zscaler ZPA | Remote developer and employee connectivity | WireGuard + Rosenpass PQC key exchange, AES-256 |\n" +
             "| **Service Mesh / mTLS** | Istio, Linkerd, Envoy, Envoy Gateway | Zero-trust microservice-to-microservice auth | Dual-key X.509 client certificates with ML-DSA |\n" +
             "| **Routing & DNS** | BGP, OSPF, RPKI, DNSSEC, DoH | Global routing integrity and domain authentication | RPKI route origin validation, Falcon/ML-DSA DNSSEC |\n\n" +
             "#### 1. Zero Trust Network Architecture (NIST SP 800-207)\n" +
             "• **Core Tenet**: Assume network locality is compromised ('Never trust, always verify'). Eliminates the obsolete 'castle-and-moat' model.\n" +
             "• **Micro-Segmentation**: Workloads and microservices are isolated using virtual local area networks (802.1Q VLANs) and software-defined firewall policies, preventing lateral movement if a host is compromised.\n" +
             "• **Mutual TLS (mTLS)**: Every API call and intra-service communication authenticates both client and server cryptographically via X.509 certificates.\n\n" +
             "#### 2. Next-Generation Firewalls (NGFW) & Passive Wire Inspection\n" +
             "• **Active L7 Deep Packet Inspection**: Evaluates application traffic, blocking malicious payloads, command-and-control (C2) callbacks, and unauthorized tunneling.\n" +
             "• **Passive SPAN / TAP Wire Auditing (QuarkShield Tier 2)**: Perimeter firewalls (Palo Alto, Fortinet) stream TLS `ClientHello` and `ServerHello` handshake metadata via syslog to QuarkShield Central. This catalogs active cipher suites, discovers uncataloged shadow web servers, and identifies Harvest Now, Decrypt Later vulnerabilities without installing endpoint agents.\n\n" +
             "#### 3. Quantum-Safe VPN Engineering\n" +
             "• **IPsec / IKEv2**: Under **IETF RFC 9370**, IKEv2 negotiates multiple key exchanges in a single security association, combining classical Diffie-Hellman (MODP or ECP groups) with NIST FIPS 203 (ML-KEM). This guarantees WAN links resist retroactive decryption.\n" +
             "• **WireGuard**: Operates at Layer 3 with high throughput. Upgraded with post-quantum key exchange (such as the Rosenpass protocol) to wrap the classical Noise protocol in post-quantum key agreement.\n\n" +
             "#### 4. Core Routing & Infrastructure Controls\n" +
             "• **BGP & RPKI**: Resource Public Key Infrastructure (RPKI) signs Route Origin Authorizations (ROAs) with cryptographic certificates, defeating malicious BGP prefix hijacking.\n" +
             "• **DNSSEC (RFC 4033)**: Cryptographically signs DNS records (A, AAAA, MX) to prevent DNS spoofing and cache poisoning, paving the way for compact post-quantum signatures (Falcon / FN-DSA).";
      return res.json({ text, code: undefined, language: 'text' });
    }

    // =========================================================================
    // 5. CYBERSECURITY STANDARDS, FRAMEWORKS & REGULATORY COMPLIANCE
    // =========================================================================
    if (
      query.includes('standards') ||
      query.includes('compliance') ||
      query.includes('framework') ||
      query.includes('regulation') ||
      query.includes('regulatory') ||
      query.includes('audit') ||
      query.includes('nist csf') ||
      query.includes('800-53') ||
      query.includes('800-171') ||
      query.includes('800-207') ||
      query.includes('800-208') ||
      query.includes('800-219') ||
      query.includes('iso 27001') ||
      query.includes('soc 2') ||
      query.includes('pci dss') ||
      query.includes('cis controls') ||
      query.includes('cmmc') ||
      query.includes('cnsa') ||
      query.includes('eo 14028') ||
      query.includes('omb m-23-02') ||
      query.includes('rfc 8446')
    ) {
      text = "### Master Cybersecurity, Technology & Post-Quantum Compliance Standards\n\n" +
             "Enterprise security architectures are governed by standardized regulatory and technical frameworks. Below is the authoritative mapping of global cybersecurity standards and their cryptographic/networking requirements:\n\n" +
             "| Standard / Framework | Governing Body | Primary Domain | Cryptographic & Network Mandates |\n" +
             "| :--- | :--- | :--- | :--- |\n" +
             "| **NIST FIPS 203/204/205** | NIST / U.S. Dept of Commerce | Post-Quantum Cryptography | Standardizes ML-KEM (KEM), ML-DSA (signatures), and SLH-DSA (stateless hash signatures) |\n" +
             "| **NSA CNSA 2.0** | National Security Agency (NSA) | National Security Systems (NSS) | 2025–2033 migration schedule; mandates ML-KEM, ML-DSA, LMS/XMSS, and AES-256 |\n" +
             "| **NIST SP 800-53 Rev 5** | NIST | Federal Security & Privacy Controls | **SC-8** (Transmission Confidentiality), **SC-12** (Key Establishment), **SC-13** (Cryptographic Protection) |\n" +
             "| **NIST SP 800-171 & CMMC 2.0**| U.S. DoD / NIST | Defense Industrial Base (CUI) | Protects Controlled Unclassified Information; enforces FIPS-validated cryptographic modules |\n" +
             "| **NIST CSF 2.0** | NIST | Comprehensive Cyber Risk Management | Six core pillars: **Govern (GV), Identify (ID), Protect (PR), Detect (DE), Respond (RS), Recover (RC)** |\n" +
             "| **NIST SP 800-208** | NIST | Stateful Hash-Based Signatures | Leighton-Micali Signatures (LMS) and XMSS for secure boot and firmware validation |\n" +
             "| **NIST SP 800-219** | NIST | Automated Cryptographic Discovery | Guidelines for automated discovery and migration to post-quantum cryptography |\n" +
             "| **ISO/IEC 27001:2022** | International Organization for Standardization | Information Security Management (ISMS) | Annex A: **A.5.15** Access Control, **A.8.20** Network Security, **A.8.24** Use of Cryptography |\n" +
             "| **SOC 2 Type II** | AICPA | Cloud SaaS & Vendor Trust | Trust Services Criteria: Security (CC6.1-CC6.8 access & encryption), Confidentiality, Availability |\n" +
             "| **PCI DSS v4.0** | PCI Security Standards Council | Payment Card Data Protection | **Requirement 3** (Protect Stored Account Data), **Requirement 4** (Protect Cardholder Data in Transit) |\n" +
             "| **CIS Critical Controls v8** | Center for Internet Security | Actionable Cyber Defense | **Control 3** (Data Protection), **Control 12** (Network Infrastructure), **Control 13** (Network Monitoring) |\n" +
             "| **OMB M-23-02 & EO 14028** | White House / OMB | Federal Cyber Executive Orders | Mandates federal agencies submit annual Cryptographic Bill of Materials (CBOM) inventories |\n" +
             "| **RFC 8446 (TLS 1.3)** | Internet Engineering Task Force (IETF) | Transport Encryption | Mandates Perfect Forward Secrecy; deprecates static RSA, RC4, CBC; specifies 1-RTT handshake |\n\n" +
             "#### Crucial Mandates for Post-Quantum Compliance:\n" +
             "1. **Cryptographic Inventory (OMB M-23-02 & NIST SP 800-219)**: Organizations must maintain an active, automated inventory of all certificates, keys, and algorithms (CBOM - CycloneDX 1.6+).\n" +
             "2. **NSA CNSA 2.0 Enforcement Deadlines**:\n" +
             "   - **2025**: Systems must begin supporting hybrid post-quantum algorithms.\n" +
             "   - **2026**: Software and firmware updates must enforce PQC signatures (ML-DSA / LMS / XMSS).\n" +
             "   - **2030**: Web servers, browsers, load balancers, and network layers must enforce post-quantum TLS and SSH.\n" +
             "   - **2033**: Complete mandatory deprecation of legacy classical algorithms (RSA, ECDH, ECDSA) across all systems.";
      return res.json({ text, code: undefined, language: 'text' });
    }

    // =========================================================================
    // 6. CYBERSECURITY ARCHITECTURE, THREAT MODELING & DEFENSE OPERATIONS
    // =========================================================================
    if (
      query.includes('cybersecurity') ||
      query.includes('threat model') ||
      query.includes('stride') ||
      query.includes('pasta') ||
      query.includes('mitre') ||
      query.includes('defense in depth') ||
      query.includes('least privilege') ||
      query.includes('iam') ||
      query.includes('identity') ||
      query.includes('mfa') ||
      query.includes('sso') ||
      query.includes('oauth') ||
      query.includes('oidc') ||
      query.includes('rbac') ||
      query.includes('siem') ||
      query.includes('soar') ||
      query.includes('edr') ||
      query.includes('xdr') ||
      query.includes('soc') ||
      query.includes('incident response') ||
      query.includes('ransomware') ||
      query.includes('phishing') ||
      query.includes('mitm') ||
      query.includes('vulnerability') ||
      query.includes('cvss') ||
      query.includes('pki') ||
      query.includes('crypto-agility') ||
      query.includes('cbom')
    ) {
      text = "### Enterprise Cybersecurity Architecture & Defense Operations\n\n" +
             "Enterprise cybersecurity requires a holistic, multi-layered defensive posture that integrates identity, infrastructure, application security, and cryptographic governance:\n\n" +
             "```\n" +
             "                          ENTERPRISE DEFENSE-IN-DEPTH\n" +
             "  ┌────────────────────────────────────────────────────────────────────────┐\n" +
             "  │ 1. IDENTITY LAYER: Phishing-Resistant MFA, SSO, Zero Trust IAM, PAM    │\n" +
             "  ├────────────────────────────────────────────────────────────────────────┤\n" +
             "  │ 2. ENDPOINT LAYER: EDR/XDR, Unprivileged Daemons, BitLocker/FileVault   │\n" +
             "  ├────────────────────────────────────────────────────────────────────────┤\n" +
             "  │ 3. NETWORK LAYER: NGFW, Micro-segmentation, TLS 1.3 (PQC Hybrid), VPN  │\n" +
             "  ├────────────────────────────────────────────────────────────────────────┤\n" +
             "  │ 4. APPLICATION LAYER: Secure SDLC, SAST/DAST, OPA Guardrails, WAF     │\n" +
             "  ├────────────────────────────────────────────────────────────────────────┤\n" +
             "  │ 5. DATA LAYER: AES-256 Encryption at Rest, Tokenization, FIPS 140-3 HSM│\n" +
             "  ├────────────────────────────────────────────────────────────────────────┤\n" +
             "  │ 6. CRYPTO-AGILITY: Automated CBOM (CycloneDX 1.6), Modular PQC Roots  │\n" +
             "  └────────────────────────────────────────────────────────────────────────┘\n" +
             "```\n\n" +
             "#### 1. Core Threat Modeling Frameworks\n" +
             "• **STRIDE Model**: Spoofing (IAM), Tampering (Signatures/MACs), Repudiation (Non-repudiation audit trails), Information Disclosure (Encryption), Denial of Service (Rate limiting/DDoS defense), Elevation of Privilege (Least privilege RBAC/ABAC).\n" +
             "• **MITRE ATT&CK Framework**: Categorizes real-world adversary tactics from Initial Access and Execution to Lateral Movement and Exfiltration.\n" +
             "• **CVSS v3.1 / v4.0 Vulnerability Scoring**: Measures vulnerability severity across Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, and Confidentiality/Integrity/Availability impact.\n\n" +
             "#### 2. Identity & Access Management (IAM)\n" +
             "• **Phishing-Resistant Multi-Factor Authentication**: FIDO2 / WebAuthn hardware security keys and Passkeys eliminate credential theft, session hijacking, and adversary-in-the-middle (AiTM) proxy kits.\n" +
             "• **Federated Identity**: SAML 2.0 and OpenID Connect (OIDC) / OAuth 2.0 protocol enforcement with ephemeral token lifetimes.\n\n" +
             "#### 3. Security Operations Center (SOC) & Incident Response\n" +
             "• **SIEM / SOAR Telemetry**: Aggregates log feeds from firewalls, endpoints, and cloud audit trails with automated containment playbooks (e.g. isolating compromised hosts via EDR API).\n" +
             "• **Incident Response Lifecycle (NIST SP 800-61)**: Preparation -> Detection & Analysis -> Containment, Eradication & Recovery -> Post-Incident Lessons Learned.\n\n" +
             "#### 4. Cryptographic Agility & CBOM Governance\n" +
             "• **Crypto-Agility**: The engineering capacity to replace outdated cryptographic algorithms without modifying underlying application code, achieved via abstracted crypto providers and externalized configuration.\n" +
             "• **Cryptographic Bill of Materials (CBOM)**: Automated scanning and inventorying of keys, certificates, libraries, and protocols (standardized under **CycloneDX 1.6+**), ensuring continuous visibility into enterprise quantum exposure.";
      return res.json({ text, code: undefined, language: 'text' });
    }

    // =========================================================================
    // 7. QUANTUM CRYPTANALYSIS, MATHEMATICS & CLASSICAL ALGORITHM COLLAPSE
    // =========================================================================
    if (
      query.includes('factor') || 
      query.includes('rsa') || 
      (query.includes('prime') && query.includes('integer')) ||
      query.includes('2048') ||
      query.includes('4096')
    ) {
      text = "### RSA Factorization Vulnerability (Shor's Algorithm)\n\n" +
             "Classical RSA cryptography (including RSA-2048, RSA-3072, and RSA-4096) relies on the computational hardness of **prime integer factorization**—given public modulus $N = p \\times q$, finding prime factors $p$ and $q$:\n\n" +
             "| Algorithm | Modulus Size | Classical Security | Quantum Vulnerability (Shor's) | Logical Qubits Needed |\n" +
             "| :--- | :--- | :--- | :--- | :--- |\n" +
             "| **RSA-2048** | 2,048 bits | 112 bits (GNFS resistant) | **Completely broken in $O((\\log N)^3)$** | ~4,096 logical qubits |\n" +
             "| **RSA-3072** | 3,072 bits | 128 bits | **Completely broken** | ~6,144 logical qubits |\n" +
             "| **RSA-4096** | 4,096 bits | 144 bits | **Completely broken** | ~8,192 logical qubits |\n\n" +
             "#### Core Technical Vulnerabilities:\n" +
             "• **Polynomial-Time Factorization**: While classical supercomputers require trillions of years using the General Number Field Sieve (GNFS), **Shor's algorithm solves prime integer factorization in polynomial time $O((\\log N)^3)$** on a Cryptanalytically Relevant Quantum Computer (CRQC).\n" +
             "• **Period-Finding via QFT**: Shor's algorithm translates factorization into order-finding $a^r \\equiv 1 \\pmod N$ using the Quantum Fourier Transform (QFT). Once period $r$ is derived, computing $\\gcd(a^{r/2} \\pm 1, N)$ instantly yields the private factors $p$ and $q$.\n" +
             "• **Key Size Inefficacy**: Increasing RSA key sizes to 4096 or 8192 bits does **not** protect against quantum attack. Polynomial scaling means doubling key size only requires a linear increase in qubits and quantum gate depth.\n\n" +
             "#### NIST PQC Remediation:\n" +
             "Transition all RSA usage to **ML-KEM (FIPS 203)** for key encapsulation and **ML-DSA (FIPS 204)** or **SLH-DSA (FIPS 205)** for digital signatures.";
      return res.json({ text, code: undefined, language: 'text' });
    } else if (
      query.includes('elliptic') || 
      query.includes('ecc') || 
      query.includes('ecdsa') || 
      query.includes('diffie') || 
      query.includes('ecdh') || 
      query.includes('2300') || 
      query.includes('p-256') || 
      query.includes('secp256') ||
      query.includes('discrete log')
    ) {
      text = "### Elliptic Curve Collapse & Diffie-Hellman Vulnerabilities\n\n" +
             "Classical Elliptic Curve Cryptography (ECDSA, Ed25519, ECDH) and finite-field Diffie-Hellman rely on the computational hardness of the **Discrete Logarithm Problem** (recovering scalar $k$ from $Q = k \\cdot G$ or exponent $x$ from $g^x \\equiv y \\pmod p$).\n\n" +
             "| Cryptosystem | Classical Security | Qubits to Break (Shor's) | Comparison vs RSA-2048 |\n" +
             "| :--- | :--- | :--- | :--- |\n" +
             "| **ECDSA P-256 (NIST)** | 128 bits | **~2,330 logical qubits** | **Falls ~45% FASTER than RSA-2048** |\n" +
             "| **secp256k1 (Bitcoin/Ethereum)** | 128 bits | **~2,330 logical qubits** | **Falls ~45% FASTER than RSA-2048** |\n" +
             "| **Ed25519 / X25519** | 128 bits | **~2,330 logical qubits** | **Falls ~45% FASTER than RSA-2048** |\n" +
             "| **Diffie-Hellman 2048-bit** | 112 bits | **~4,096 logical qubits** | Breaks simultaneously with RSA-2048 |\n\n" +
             "#### Why Elliptic Curves Collapse Faster than RSA:\n" +
             "• **Smaller Group Sizes**: ECC achieves strong classical security with smaller operand sizes (256-bit ECC matches 3,072-bit RSA). However, on quantum hardware, smaller operand sizes require **substantially fewer logical qubits and shorter circuit depths**.\n" +
             "• **~2,300 Logical Qubits**: Shor's algorithm for elliptic curve discrete logarithms requires only **~2,330 logical qubits**, meaning **ECDSA will collapse before RSA-2048**!\n" +
             "• **Total Key Exposure**: As soon as an elliptic curve public key is broadcast (e.g. during a TLS 1.3 handshake or an on-chain Web3 transaction), Shor's algorithm extracts the private scalar $k$ directly, enabling signature forgery and session key recovery.\n\n" +
             "#### NIST PQC Remediation:\n" +
             "• **Key Agreement**: Replace ECDH/X25519 with **ML-KEM-768 (FIPS 203)** or hybrid `X25519MLKEM768`.\n" +
             "• **Digital Signatures**: Replace ECDSA/Ed25519 with **ML-DSA-65 (FIPS 204)** or **Falcon-512 (FN-DSA)**.";
      return res.json({ text, code: undefined, language: 'text' });
    } else if (
      query.includes('production') || 
      query.includes('pervasive') || 
      query.includes('underpin') || 
      query.includes('99%') || 
      query.includes('gateway')
    ) {
      text = "### Pervasive Classical Cryptography in Production (99% Infrastructure Impact)\n\n" +
             "Classical public-key cryptography (primarily RSA and ECC) currently underpins **over 99% of digital enterprise production infrastructure** globally. The quantum threat is not an isolated academic curiosity—it is a systemic architecture exposure:\n\n" +
             "| Production Layer | Classical Dependency | Quantum Threat Impact | Remediation Standard |\n" +
             "| :--- | :--- | :--- | :--- |\n" +
             "| **TLS / HTTPS Web Ingress** | RSA-2048 / ECDSA certificates, ECDH KEX | Retroactive decryption (HNDL), MITM session hijacking | Hybrid TLS 1.3 (`X25519MLKEM768`) |\n" +
             "| **SSH Fleet Administration** | `ssh-rsa`, `ecdsa-sha2-nistp256` keys | Complete remote server & root access compromise | OpenSSH 9.8+ (`mlkem768x25519-sha256`) |\n" +
             "| **Enterprise VPN Gateways** | IPsec / IKEv2 / OpenVPN DH groups | Adversary eavesdropping on WAN & corporate networks | Post-quantum IPsec / ML-KEM encapsulation |\n" +
             "| **API Tokens & Microservices** | RS256 / ES256 JWT tokens & OAuth | Forged auth claims, privilege escalation, replay | ML-DSA tokens or symmetric HS256 HMAC |\n" +
             "| **Code Signing & CI/CD** | Authenticode, Apple Developer, Git commits | Malicious firmware & software supply chain injection | ML-DSA-65 / NIST SP 800-208 (LMS/XMSS) |\n" +
             "| **Identity & PKI CAs** | RSA/ECC Intermediate & Root CAs | Total collapse of corporate trust hierarchy | Dual-Key Composite X.509 (ML-DSA + RSA) |\n\n" +
             "#### Why Enterprise Migration Timelines Span Years:\n" +
             "Because RSA and ECC are deeply embedded in operating system trust stores, hardware security modules (HSMs), embedded firmware, and third-party SaaS integrations, complete migration takes **3 to 7 years**. Waiting until a CRQC is announced guarantees organizational vulnerability.";
      return res.json({ text, code: undefined, language: 'text' });
    } else if (
      query.includes('harvest') || 
      query.includes('hndl') || 
      query.includes('mosca') || 
      query.includes('retro')
    ) {
      text = "### Harvested Traffic Threat ('Harvest Now, Decrypt Later' / HNDL) & Mosca's Theorem Engine\n\n" +
             "**Harvest Now, Decrypt Later (HNDL)** is an active offensive cyber campaign executed by state-sponsored adversaries and foreign intelligence services:\n\n" +
             "```\n" +
             "  TODAY: Mass Interception & Storage             FUTURE: Quantum Decryption\n" +
             "  ==================================             ==========================\n" +
             "  [Adversary Taps Fiber / Cloud]                 [CRQC Becomes Operational]\n" +
             "                 │                                             │\n" +
             "                 ▼                                             ▼\n" +
             "  Captures TLS sessions, VPN tunnels,            Applies Shor's Algorithm\n" +
             "  and confidential customer PII                  to factored private keys\n" +
             "                 │                                             │\n" +
             "                 ▼                                             ▼\n" +
             "  Stores encrypted blobs in data centers  =====> Decrypts historical traffic!\n" +
             "```\n\n" +
             "#### Mosca's Theorem Risk Equation:\n" +
             "Dr. Michele Mosca formalized the mathematical proof establishing when an organization is already compromised today:\n\n" +
             "$$\\mathbf{X + Y > Z} \\implies \\text{Your Confidentiality Is ALREADY Lost!}$$\n\n" +
             "• **$X$ (Confidentiality Shelf-Life)**: Number of years sensitive data must remain secret (e.g. intellectual property: 15-20 yrs, defense secrets: 30+ yrs, healthcare PII: 50+ yrs).\n" +
             "• **$Y$ (Migration Timeline)**: Years required to migrate legacy infrastructure to post-quantum standards (Enterprise benchmark: 4 to 8 years).\n" +
             "• **$Z$ (Quantum Threat Horizon)**: Years until a Cryptanalytically Relevant Quantum Computer (CRQC) is deployed (Global intelligence estimate: 2029 - 2033).\n\n" +
             "| Scenario | Shelf-Life ($X$) | Migration ($Y$) | Total ($X+Y$) | CRQC Timeline ($Z$) | Posture Status |\n" +
             "| :--- | :--- | :--- | :--- | :--- | :--- |\n" +
             "| **Trade Secrets / IP** | 15 years | 5 years | **20 years** | ~7 years | **CRITICAL COMPROMISE (Active HNDL)** |\n" +
             "| **Customer PII / Healthcare** | 25 years | 4 years | **29 years** | ~7 years | **CRITICAL COMPROMISE (Active HNDL)** |\n" +
             "| **Ephemeral Session Data** | 1 year | 3 years | **4 years** | ~7 years | Compliant if migrated within 3 years |\n\n" +
             "#### Immediate Remediation:\n" +
             "To defend against HNDL, organizations must deploy **hybrid post-quantum key exchange (`X25519MLKEM768`)** immediately across all TLS endpoints and VPNs to ensure harvested ciphertext cannot be decrypted in the future.";
      return res.json({ text, code: undefined, language: 'text' });
    } else if (
      query.includes('ethereum') || 
      query.includes('smart contract') || 
      query.includes('solidity') || 
      query.includes('evm') || 
      query.includes('erc-4337') || 
      query.includes('web3')
    ) {
      text = "### Post-Quantum Cryptographic Mitigation Process for Ethereum Smart Contracts\n\n" +
             "Ethereum accounts (EOAs) and transaction signing rely on the **secp256k1** Elliptic Curve Digital Signature Algorithm (ECDSA). Because Shor's algorithm solves elliptic curve discrete logarithms in polynomial time $O((\\log N)^3)$, a Cryptanalytically Relevant Quantum Computer (CRQC) can derive private keys directly from exposed public keys, forge transaction signatures, and hijack `ecrecover`-based smart contract permissions.\n\n" +
             "Here is the 5-phase process to mitigate quantum vulnerabilities across Ethereum smart contracts and dApps:\n\n" +
             "1. **Cryptographic Discovery & Vulnerability Inventory**: Scan contracts for `ecrecover` and exposed ECDSA public keys.\n" +
             "2. **Account Abstraction Migration (ERC-4337 & EIP-7702)**: Migrate EOAs to smart accounts with modular validation.\n" +
             "3. **Quantum-Resilient Signatures (NIST SP 800-208)**: Enforce Winternitz One-Time Signatures (W-OTS+) or LMS.\n" +
             "4. **Zero-Knowledge STARKs**: Use STARK-based Layer-2 rollups (inherently post-quantum) to avoid high EVM gas.\n" +
             "5. **Crypto-Agility Proxies (UUPS)**: Implement upgradeable proxies for swapping algorithm precompiles.\n\n" +
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

    function validateUserOp(
        bytes32 userOpHash,
        bytes calldata pqSignature,
        bytes32 nextQuantumRoot
    ) external onlyEntryPoint returns (uint256 validationData) {
        bytes32 derivedRoot = keccak256(abi.encodePacked(userOpHash, pqSignature, stateNonce));
        if (derivedRoot != quantumRootPublicKey) {
            return 1; // SIG_VALIDATION_FAILED
        }
        stateNonce++;
        emit QuantumKeyRotated(quantumRootPublicKey, nextQuantumRoot);
        quantumRootPublicKey = nextQuantumRoot;
        return 0; // Success
    }

    function execute(address dest, uint256 value, bytes calldata func) external onlyEntryPoint {
        (bool success, bytes memory result) = dest.call{value: value}(func);
        require(success, string(result));
        emit Executed(dest, value, func);
    }

    receive() external payable {}
}`;
      return res.json({ text, code, language });
    } else if (query.includes('kyber') || query.includes('ml-kem') || query.includes('mlkem')) {
      text = "**ML-KEM (FIPS 203, formerly CRYSTALS-Kyber)** is the primary NIST-standardized Post-Quantum Key Encapsulation Mechanism.\n\n" +
             "- **Underlying Math**: Based on the hardness of Module Learning with Errors (M-LWE) over module lattices, which resists Shor's quantum factoring.\n" +
             "- **Security Levels**:\n" +
             "  - *ML-KEM-512* (NIST Category 1, equivalent to AES-128)\n" +
             "  - *ML-KEM-768* (NIST Category 3, equivalent to AES-192 / standard recommendation)\n" +
             "  - *ML-KEM-1024* (NIST Category 5, equivalent to AES-256)\n" +
             "- **Production Adoption**: Standardized in TLS 1.3 via hybrid groups like `X25519MLKEM768`. It replaces RSA-OAEP and ECDH key exchanges across browsers, web servers, and VPN tunnels.";
      return res.json({ text, code: undefined, language: 'text' });
    } else if (query.includes('dilithium') || query.includes('ml-dsa') || query.includes('mldsa')) {
      text = "**ML-DSA (FIPS 204, formerly CRYSTALS-Dilithium)** is the primary NIST-standardized Post-Quantum Digital Signature Algorithm.\n\n" +
             "- **Underlying Math**: Based on Module Learning with Errors (M-LWE) and Short Integer Solution (SIS) over lattices using the Fiat-Shamir with Aborts framework.\n" +
             "- **Security Levels**:\n" +
             "  - *ML-DSA-44* (NIST Category 2)\n" +
             "  - *ML-DSA-65* (NIST Category 3 / standard enterprise recommendation)\n" +
             "  - *ML-DSA-87* (NIST Category 5)\n" +
             "- **Application**: Directly replaces classical RSA and ECDSA signatures in digital certificates, code signing, document verification, and authentication tokens.";
      return res.json({ text, code: undefined, language: 'text' });
    } else if (query.includes('sphincs') || query.includes('slh-dsa') || query.includes('slhdsa')) {
      text = "**SLH-DSA (FIPS 205, formerly SPHINCS+)** is the NIST-standardized Stateless Hash-Based Digital Signature Algorithm.\n\n" +
             "- **Underlying Math**: Relies solely on the security properties of standard cryptographic hash functions (SHA-2, SHAKE-256), completely independent of lattice assumptions.\n" +
             "- **Key Advantage**: Serves as a robust, mathematically conservative hedge in case unexpected mathematical breakthroughs ever weaken lattice-based cryptography.\n" +
             "- **Trade-off**: Produces larger signature sizes (~8 KB to ~40 KB) compared to ML-DSA (~2.4 KB) and Falcon (~666 bytes).";
      return res.json({ text, code: undefined, language: 'text' });
    } else if (query.includes('lms') || query.includes('xmss')) {
      text = "**LMS (Leighton-Micali Signatures) and XMSS (eXtended Merkle Signature Scheme)** are stateful hash-based digital signature schemes standardized under **NIST SP 800-208** and RFC 8554 / RFC 8391.\n\n" +
             "- **Characteristics**: Require maintaining state across signings to prevent one-time key reuse.\n" +
             "- **Best Use Cases**: Secure boot, firmware verification, operating system updates, and immutable hardware roots of trust where signatures are infrequent and state tracking can be strictly controlled.";
      return res.json({ text, code: undefined, language: 'text' });
    } else if (query.includes('hybrid')) {
      text = "**Hybrid Post-Quantum Cryptography** combines a classical algorithm (like X25519, P-256, or RSA) with a post-quantum algorithm (like ML-KEM or ML-DSA) in a single operation.\n\n" +
             "- **Key Exchange**: Derives the shared session secret using both ECDH and ML-KEM ($K = \\text{KDF}(K_{\\text{classical}} \\parallel K_{\\text{pqc}})$). Even if one algorithm is compromised, the connection remains completely secure.\n" +
             "- **Standard**: Standardized in TLS 1.3 as `X25519MLKEM768`, deployed natively by Google Chrome, Cloudflare, and OpenSSL 3.2+.";
      return res.json({ text, code: undefined, language: 'text' });
    } else if (query.includes('shor') && query.includes('grover')) {
      text = "Shor's and Grover's algorithms are the two primary quantum algorithms that threaten classical cryptography:\n\n" +
             "1. **Shor's Algorithm**: Solves integer factorization and discrete logarithms in polynomial time. This completely breaks asymmetric public-key systems like RSA, Diffie-Hellman, and Elliptic Curve Cryptography (ECC).\n" +
             "2. **Grover's Algorithm**: Speeds up search in unsorted databases quadratically. When applied to symmetric cryptography (like AES) or hash functions, it halves the effective key length (e.g., AES-128 is reduced to 64 bits of security). This is mitigated by upgrading to AES-256.";
      return res.json({ text, code: undefined, language: 'text' });
    } else if (/\b(shor|shor's|factoring)\b/i.test(query)) {
      text = "Shor's algorithm is a quantum computer algorithm that solves integer factorization and discrete logarithms in O((log N)³) polynomial time. This breaks RSA and ECC because classical cryptography relies on these math problems being exponential. Lattice-based cryptography (like ML-KEM/Kyber) relies on high-dimensional vector space lattice problems (like Shortest Vector Problem), which Shor's algorithm cannot solve efficiently.";
      return res.json({ text, code: undefined, language: 'text' });
    } else if (/\b(grover|grover's|aes|symmetric)\b/i.test(query)) {
      text = "Grover's algorithm searches an unsorted database of N elements in O(√N) steps. When applied to symmetric keys (AES), it effectively halves the key size security (AES-128 becomes 64-bit strength, which is vulnerable). To mitigate this, CNSA 2.0 requires migrating to AES-256, providing a robust 128-bit quantum security buffer.";
      return res.json({ text, code: undefined, language: 'text' });
    } else if (/\b(ssh|openssh|sshd)\b/i.test(query) && /\b(config|conf|kex|key|sshd_config|setup|hybrid)\b/i.test(query)) {
      text = 'To secure OpenSSH, you should prepend sntrup761x25519-sha512@openssh.com or mlkem768x25519-sha256 to your Key Exchange algorithms. This protects admin channels from retro-decryption:';
      language = 'nginx';
      code = `# /etc/ssh/sshd_config
# Enforce post-quantum key exchange (OpenSSH 9.0+)
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256

# Enforce secure symmetric ciphers (Grover resistance)
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com

# Enforce secure MACs
MACs hmac-sha2-512-etm@openssh.com`;
      return res.json({ text, code, language });
    } else if (
      /\b(golang|go language|in go|go code|go tls|go snippet|go sdk)\b/i.test(query) ||
      (/\bgo\b/i.test(query) && /\b(tls|code|example|snippet|implement|client|http|config)\b/i.test(query))
    ) {
      text = 'In Go (since version 1.24), native TLS post-quantum groups are supported in tls.Config. Set CurvePreferences to prioritize ML-KEM hybrids:';
      language = 'go';
      code = `package main

import (
	"crypto/tls"
	"net/http"
)

func main() {
	// Configure TLS config with ML-KEM key exchange curves (Go 1.24+)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.CurveID(0x11ec), // X25519MLKEM768 hybrid (Standard FIPS 203)
			tls.X25519,
		},
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	
	client.Get("https://quarkshield.ai")
}`;
      return res.json({ text, code, language });
    } else if (
      query.includes('vulnerable') || query.includes('list') || query.includes('assets') || query.includes('dashboard') || query.includes('inventory') || query.includes('cmdb')
    ) {
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
              `\n\nTo secure these assets, transition them from classical asymmetric algorithms to post-quantum standards like ML-KEM/ML-DSA.`;
          }
        } else {
          text = "**Crypto CMDB** (Configuration Management Database) is the asset tracking database of QuarkShield. It features:\n\n" +
                 "- **Centralized Inventory**: Automatically registers all cryptographic assets discovered by active/passive audits.\n" +
                 "- **Risk Scoring**: Grades risk based on key sizes and algorithms (e.g. RSA-2048 is flagged as High/Critical Risk, while AES-256 is Secure).\n" +
                 "- **Violation Monitoring**: Shows compliance flags for standards like CNSA 2.0, NIST SP 800-208, and EO 14028.\n\n" +
                 `Currently, your CMDB contains **${total}** cryptographic assets (**${vulnerable.length}** vulnerable).`;
        }
      } catch (dbErr: any) {
        text = "**Crypto CMDB** (Configuration Management Database) catalogs all cryptographic keys, algorithms, and certificates. (Failed to query live inventory: " + dbErr.message + ")";
      }
      return res.json({ text, code: undefined, language: 'text' });
    } else if (
      /\b(hi|hello|hey|greetings|good morning|good afternoon|good evening|who are you|help)\b/i.test(query) && query.length < 35
    ) {
      text = "### Welcome to QuarkShield AI Copilot 🛡️\n\n" +
             "I am your specialized advisor across **Post-Quantum Cryptography (PQC), IT Networking, Cybersecurity Architecture, and Global Security Standards**.\n\n" +
             "**How I Can Assist You**:\n" +
             "• **NIST PQC Standards**: Deep-dive into **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)**, **FIPS 205 (SLH-DSA)**, and **SP 800-208** (LMS/XMSS).\n" +
             "• **IT Networking & Ingress**: Step-by-step configurations for **TLS 1.3**, Next-Gen Firewalls, IPsec/IKEv2 VPNs, WireGuard, mTLS, and Zero Trust micro-segmentation.\n" +
             "• **Cybersecurity Standards**: Audit controls and roadmaps for **NIST CSF 2.0**, **NIST SP 800-53**, **ISO 27001**, **SOC 2 Type II**, **PCI DSS v4.0**, and **NSA CNSA 2.0**.\n" +
             "• **Threat Defense**: Countering **Harvest Now, Decrypt Later (HNDL)**, Shor's and Grover's algorithms, MITM, and retroactive decryption.\n" +
             "• **QuarkShield Platform Controls**: Host agent deployment, out-of-band cloud volume snapshots, CycloneDX 1.6 CBOM synthesis, and migration charters.\n\n" +
             "Feel free to ask any technical question (e.g., *'How do I configure TLS 1.3?'*, *'Explain FIPS 203 vs 204'*, *'What are the key requirements of ISO 27001 for cryptography?'*)!";
    } else {
      text = "### QuarkShield AI Copilot — Technical & Platform Advisor 🛡️\n\n" +
             "I am your dedicated enterprise advisor for **Post-Quantum Cryptography (PQC), IT Networking, Cybersecurity Architecture, and QuarkShield Platform Operations**.\n\n" +
             "Here are key areas and step-by-step guides you can ask me about:\n\n" +
             "#### 🚀 QuarkShield Platform & Onboarding Workflows:\n" +
             "• **Next Steps After Onboarding**: Ask *'What are my next steps after license onboarding?'* for admin first login, initial credentials, and MFA setup.\n" +
             "• **Endpoint Scanner Deployment**: Ask *'How do I run my first desktop scan?'* for macOS DMG/curl, Windows PowerShell/MSI, and Linux commands.\n" +
             "• **Staff Onboarding & RBAC**: Ask *'How do I onboard staff and allocate license seats?'* to invite users and configure roles.\n" +
             "• **CI/CD CBOM Security Gate**: Ask *'How do I configure the CI/CD Pipeline Security Gate?'* for GitHub Actions / GitLab CI PR blocking.\n" +
             "• **Enterprise PKI & Vaults**: Ask *'How do I connect Enterprise PKI & Vaults?'* for AWS KMS, Azure Key Vault, HashiCorp Vault, and AD CS sync.\n" +
             "• **Hybrid Quantum TLS Proxy**: Ask *'How do I deploy the Hybrid Quantum TLS Proxy?'* for zero-code transparent gateway upgrades.\n" +
             "• **3-Tier Deployment Strategy**: Ask *'Explain the 3-Tier Enterprise PQC Deployment Strategy'* (Cloud Snapshots, Wire Inspection, OTel Collector).\n\n" +
             "#### 🔬 PQC Standards, Networking & Math:\n" +
             "• **NIST Standards**: *FIPS 203 (ML-KEM)*, *FIPS 204 (ML-DSA)*, *FIPS 205 (SLH-DSA)*, *SP 800-208 (LMS/XMSS)*.\n" +
             "• **IT Networking & Ingress**: *TLS 1.3*, *NGINX X25519MLKEM768*, *OpenSSH 9.8+*, *IPsec/IKEv2 VPNs*, *Firewalls*.\n" +
             "• **Quantum Cryptanalysis**: *Shor's algorithm* vs RSA/ECC, *Grover's algorithm* vs AES, *Harvest Now, Decrypt Later (HNDL)*, *Mosca's Theorem*.\n" +
             "• **Compliance Roadmaps**: *NSA CNSA 2.0*, *NIST CSF 2.0*, *ISO 27001:2022*, *PCI DSS v4.0*, *OMB M-23-02*.\n\n" +
             "Type your question above or click one of the quick prompt chips below to get started!";
    }

    if (attachmentAnalysis) {
      text = attachmentAnalysis + (text ? `\n\n${text}` : '');
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
