# QuarkShield Enterprise Platform: Complete Feature Architecture & User Operations Guide

![QuarkShield Platform](https://quarkshield.ai/quarkshield-logo.png)

> **Document Version:** 3.5.0  
> **Date:** September 2026  
> **Platform Version:** QuarkShield Enterprise 2.0  
> **Compliance & Standards:** NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NSA CNSA 2.0, Executive Order 14028, OMB M-23-02, CycloneDX 1.6+ (CBOM & CDXA)  
> **Production Target:** [https://quarkshield.ai](https://quarkshield.ai)  

---

## Table of Contents
1. [Platform Overview & 3-Tier Enterprise Strategy](#1-platform-overview--3-tier-enterprise-strategy)
2. [Feature 1: Unified Integrations Hub (Centralized Ingestion Architecture)](#2-feature-1-unified-integrations-hub)
3. [Feature 2: Tier 1 Cloud KMS Connectors (AWS KMS & Azure Key Vault)](#3-feature-2-tier-1-cloud-kms-connectors)
4. [Feature 3: Tier 1 Enterprise PKI & Secret Vaults (AD CS & HashiCorp Vault)](#4-feature-3-tier-1-enterprise-pki--secret-vaults)
5. [Feature 4: Tier 2 Transparent Hybrid Quantum TLS Reverse Proxy Gateway](#5-feature-4-tier-2-transparent-hybrid-quantum-tls-reverse-proxy-gateway)
6. [Feature 5: Tier 2 In-Flight Wire TLS Passive Probing & Mirroring](#6-feature-5-tier-2-in-flight-wire-tls-passive-probing--mirroring)
7. [Feature 6: Tier 3 Endpoint Workstation Fleet Scanner (macOS, Windows, Linux)](#7-feature-6-tier-3-endpoint-workstation-fleet-scanner)
8. [Feature 7: Tier 3 CI/CD Pipeline CBOM Security Gate (Shift-Left PR Blocker)](#8-feature-7-tier-3-cicd-pipeline-cbom-security-gate)
9. [Feature 8: Tier 3 Remote Git Repository Cryptographic Auditor](#9-feature-8-tier-3-remote-git-repository-cryptographic-auditor)
10. [Feature 9: Universal Cryptographic Bill of Materials (CBOM) & Multi-Source Inventory](#10-feature-9-universal-cbom--multi-source-inventory)
11. [Feature 10: CycloneDX 1.6 & CDXA (CycloneDX Attestation) Post-Quantum Signing Block](#11-feature-10-cyclonedx-16--cdxa-post-quantum-signing-block)
12. [Feature 11: Mosca's Migration Planner (Y2Q Readiness Assessment)](#12-feature-11-moscas-migration-planner)
13. [Feature 12: PQC Copilot (Enterprise Cryptographic Advisory AI)](#13-feature-12-pqc-copilot)

---

## 1. Platform Overview & 3-Tier Enterprise Strategy

QuarkShield provides enterprise organizations and federal agencies with unified cryptographic discovery, risk quantification, and post-quantum migration enforcement. To eliminate the friction of traditional "agent fatigue", QuarkShield operates across a **3-Tier Enterprise Model**:

- **Tier 1 (Cloud & PKI):** Agentless, out-of-band cryptographic discovery across cloud key vaults (AWS KMS, Azure KV) and centralized enterprise certificate authorities (Microsoft AD CS, HashiCorp Vault).
- **Tier 2 (In-Flight Wire TLS):** Network-level post-quantum inspection and inline hybrid quantum TLS reverse proxies that terminate NIST FIPS 203 ciphers with zero code changes.
- **Tier 3 (Workstations & Repositories):** Lightweight non-intrusive workstation agents (macOS, Windows, Linux), CI/CD pull request security gates, and remote Git repository scanners.

All discoveries flow automatically into a centralized **Cryptographic Bill of Materials (CBOM)** backed by tamper-evident **CycloneDX Attestation (CDXA)** digitally signed with **ML-DSA-65 (NIST FIPS 204)**.

---

## 2. Feature 1: Unified Integrations Hub

### Purpose
The **Unified Integrations Hub** serves as the single-pane command center for managing all ingestion connectors across the enterprise. Modeled after modern enterprise cloud security architectures, it consolidates setup blueprints, IAM permissions, credentials, and live telemetry feeds into one cohesive directory. This eliminates navigation fragmentation and removes duplicated setup screens from administrative menus.

### Steps to Connect
1. Log into the QuarkShield Portal (`https://quarkshield.ai` or your custom tenant subdomain e.g., `https://[tenant].quarkshield.ai`).
2. In the left navigation sidebar, click **Integrations Hub**.
3. Use the filter tabs at the top (`All Integrations`, `Tier 1: Cloud & PKI`, `Tier 2: In-Flight Wire TLS`, `Tier 3: Workstations & Repos`) to locate the desired connector.
4. Click on any connector card (e.g., **AWS KMS**, **Microsoft AD CS**, **Hybrid TLS Proxy**, **macOS Workstations**) to open the interactive 3-step slide-out configuration drawer.

### Requirements to Execute / Complete the Process
- **Access Level:** Corporate Administrator or Cryptographer role.
- **Authentication Credentials:** 
  - For Cloud/PKI: Cloud IAM Role ARN, Azure Client Secrets, Vault Tokens, or LDAP service accounts.
  - For Endpoints: Organization Fleet Enrollment Token.
- **Execution Step:** Complete Step 2 (*Credentials & Ingestion*) in the slide-out drawer, click **Verify & Test Connection**, then click **Save & Sync Connector**.

### Results Produced
- Activates live connector monitoring with visual status indicators (`Connected`, `Ready to Connect`, or `Active Gateways`).
- Automatically triggers cryptographic discovery jobs.
- Discovered keys, certificates, algorithms, and ciphers are tagged with their specific source (`cloud_kms`, `enterprise_pki`, `pqc_proxy`, `endpoint`, or `git_repo`) and ingested into the central database.

### How to View the Results
- **Within the Drawer:** Step 3 (*Live Discovered Cryptographic Inventory*) displays a live preview table of synced keys, key types, and risk levels.
- **Directory Overview:** Each integration card updates with live key counters (e.g., `Discovered Keys: 412`, `Quantum Vulnerable: 398`).
- **CBOM Inventory Tab:** Click the **Open in CBOM Inventory** shortcut button inside Step 3 to view the findings pre-filtered by that connector.

---

## 3. Feature 2: Tier 1 Cloud KMS Connectors (AWS KMS & Azure Key Vault)

### Purpose
Discovers and catalogs cryptographic keys, asymmetric certificates, and envelope encryption configurations residing inside cloud provider hardware security modules (HSMs) and managed key vaults without installing agents on cloud virtual machines.

### Steps to Connect
#### For AWS KMS (`aws_kms`):
1. Navigate to **Integrations Hub ➔ Tier 1 ➔ AWS KMS**.
2. Copy the provided IAM Policy JSON from the drawer:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "kms:ListKeys",
           "kms:ListAliases",
           "kms:DescribeKey",
           "kms:GetKeyRotationStatus",
           "kms:ListResourceTags"
         ],
         "Resource": "*"
       }
     ]
   }
   ```
3. Attach this policy to a dedicated IAM Role in your AWS account and configure Cross-Account Trust with QuarkShield's AWS Account ID and External ID.
4. Enter your **Role ARN** (`arn:aws:iam::123456789012:role/QuarkShieldKmsAuditRole`) and **Target AWS Regions** (e.g., `us-east-1, us-west-2`).

#### For Azure Key Vault (`azure_keyvault`):
1. Navigate to **Integrations Hub ➔ Tier 1 ➔ Azure Key Vault**.
2. Register an App Registration in Microsoft Entra ID (formerly Azure AD).
3. Grant `Key Vault Reader` and `Key Vault Secrets User` permissions on target Key Vaults.
4. Provide the **Azure Tenant ID**, **Client ID**, and **Client Secret / Certificate**.

### Requirements to Execute / Complete the Process
- Valid read-only cloud IAM permissions (no cryptographic decrypt or sign permissions required).
- Click **Test Connection** to verify network ingress and STS assume-role negotiation.
- Click **Trigger Discovery Sync**.

### Results Produced
- Enumeration of all Customer Master Keys (CMKs) and AWS/Azure managed keys.
- Algorithm identification (e.g., `RSA-2048`, `RSA-4096`, `ECC_NIST_P256`, `ECC_NIST_P384`, `SYMMETRIC_DEFAULT`).
- Key rotation state audit and key lifecycle metadata.
- Shor's algorithm vulnerability classification (High/Critical risk for classical RSA and ECC keys).

### How to View the Results
- **Settings / Enterprise PKI & Vaults Tab:** View the summary cards: *Total Discovered Keys*, *Quantum Vulnerable Keys*, *PQC-Ready Keys*.
- **CBOM Inventory:** Select `Source: Cloud KMS` from the source filter dropdown to view all cloud keys alongside their Key ID, Cloud Region, Algorithm, and Quantum Risk Score.
- **Exported CBOM / CDXA:** Present under CycloneDX component type `cryptographic-asset` with `cryptoProperties.assetType = "key"`.

---

## 4. Feature 3: Tier 1 Enterprise PKI & Secret Vaults (AD CS & HashiCorp Vault)

### Purpose
Provides centralized visibility into internal enterprise Public Key Infrastructure (PKI), Certificate Authorities (CAs), and secrets engines that issue certificates to internal servers, VPN gateways, mobile devices, and microservices.

### Steps to Connect
#### For Microsoft Active Directory Certificate Services (`ad_cs`):
1. Navigate to **Integrations Hub ➔ Tier 1 ➔ Microsoft AD CS**.
2. Deploy the provided PowerShell Discovery Script or configure LDAP / Kerberos read-only credentials:
   ```powershell
   # Enumerate AD CS Enterprise CAs & Templates
   certutil -CATemplates -v
   Get-ChildItem -Path Cert:\LocalMachine\Root
   ```
3. Enter the **CA Hostname / URL** (e.g., `ldap://ca01.corp.internal`), **Base DN** (`DC=corp,DC=internal`), and **Service Account Credentials**.

#### For HashiCorp Vault (`hashicorp_vault`):
1. Navigate to **Integrations Hub ➔ Tier 1 ➔ HashiCorp Vault**.
2. Enable AppRole authentication or generate a read-only Vault Token with access to `/v1/pki*` and `/v1/transit*`.
3. Enter the **Vault Cluster URL** (e.g., `https://vault.corp.internal:8200`), **Mount Paths** (e.g., `pki/`, `transit/`), and **AppRole Role ID / Secret ID**.

### Requirements to Execute / Complete the Process
- Read-only access to LDAP directory partitions or Vault HTTP API endpoints.
- Network line-of-sight from QuarkShield Connector or on-premises proxy agent to the CA server.
- Click **Run Discovery Sync**.

### Results Produced
- Catalogs all Root CAs, Subordinate CAs, and Active Certificate Templates.
- Identifies signature hashing algorithms (e.g., `SHA-1`, `SHA-256`, `SHA-384`) and public key algorithms (e.g., `RSA-2048`, `ECDSA-P256`).
- Identifies weak templates (e.g., templates permitting client-specified SANs or outdated key sizes).
- Detects expiration dates and automated renewal statuses.

### How to View the Results
- **Enterprise PKI & Vaults Dashboard:** Inspect the connector card status, last sync timestamp, and total discovered certificates.
- **CBOM Inventory:** Filter by `Source: Enterprise PKI` to review all enterprise CA certificates, issuing authorities, validity windows, and Shor risk ratings.

---

## 5. Feature 4: Tier 2 Transparent Hybrid Quantum TLS Reverse Proxy Gateway

### Purpose
Enables enterprise applications, legacy web servers, and API backends to communicate over quantum-safe TLS **without modifying a single line of application source code**. The gateway terminates post-quantum hybrid key exchange ciphers (`X25519MLKEM768`, curve `0x11ec`, NIST FIPS 203) at the network edge and forwards traffic to internal HTTP/1.1 or legacy TLS applications. This provides immediate, zero-downtime protection against **"Harvest Now, Decrypt Later" (HNDL)** espionage.

### Steps to Connect
1. In the left navigation sidebar, click **Hybrid Quantum TLS Proxy** (or navigate via **Integrations Hub ➔ Tier 2**).
2. Click **+ New Proxy Instance**.
3. Configure the Gateway Parameters:
   - **Instance Name:** e.g., `Production API Ingress Proxy`
   - **Listen Port:** e.g., `5443` or `8443`
   - **Upstream Target URL:** Destination backend (e.g., `http://127.0.0.1:5050` or `http://internal-app.local:8080`)
   - **PQC Hybrid Group:** `X25519MLKEM768` (Default / NIST FIPS 203)
   - **Fallback Classical Cipher:** `ECDHE-RSA-AES256-GCM-SHA384` (ensures legacy non-PQC clients continue to connect seamlessly)
4. Upload or select the Edge SSL/TLS Server Certificate and Private Key.
5. Click **Create & Launch Proxy**.

### Requirements to Execute / Complete the Process
- Available ingress network port (e.g., 5443, 8443, 443).
- Valid upstream HTTP/HTTPS endpoint reachable by the proxy host.
- Optional: Download production deployment templates (NGINX with OpenSSL 3.2+ PQC patches, Envoy, or Docker Compose) via the **Export Config Template** button to run the proxy on your own ingress clusters.

### Results Produced
- Starts an active proxy listener terminating post-quantum TLS handshakes.
- Ingests the proxy endpoint as an active cryptographic asset into the central inventory (`source = 'pqc_proxy'`).
- Live handshake counter tracks incoming connections, negotiated protocols, and client PQC readiness percentages.

### How to View the Results
- **Hybrid Proxy Manager Screen:** Shows live status badge (`Running`), Active Listen Port, Negotiated Cipher Suite, and Live Handshake Count.
- **Run Live Diagnostic Test:** Click the **Test Handshake** button on any running proxy. QuarkShield sends an active TLS 1.3 ClientHello with `supported_groups: 0x11ec (X25519MLKEM768)`. The modal returns:
  - Negotiated Protocol: `TLSv1.3 (RFC 8446)`
  - Key Exchange: `X25519MLKEM768 (Curve ID: 0x11ec / NIST FIPS 203)`
  - Cipher Suite: `TLS_AES_256_GCM_SHA384`
  - Handshake Latency: (e.g., `28ms`)
  - Quantum Resilience: `Protected against Harvest Now, Decrypt Later (HNDL) attacks.`
- **CBOM Inventory:** Filter by `Source: Hybrid Proxy` to view the running proxy cryptographic configurations.

---

## 6. Feature 5: Tier 2 In-Flight Wire TLS Passive Probing & Mirroring

### Purpose
Discovers and audits cryptographic protocols across physical, virtual, and cloud networks **out-of-band** without intercepting, decrypting, or adding latency to live production traffic. Identifies deprecated TLS versions (1.0, 1.1), non-forward-secret ciphers, and unencrypted in-flight protocols across corporate data centers and cloud VPCs.

### Steps to Connect
1. Navigate to **Integrations Hub ➔ Tier 2 ➔ Passive Wire Mirror**.
2. Configure network traffic mirroring on your core infrastructure:
   - **Cloud VPCs:** AWS VPC Traffic Mirroring / Azure Virtual Network TAP directed to a QuarkShield collector target.
   - **On-Premises:** SPAN / TAP port on Cisco, Arista, or Palo Alto Firewalls.
3. Configure the QuarkShield Wire Sniffer:
   ```bash
   # Run passive wire prober on mirror interface eth1
   sudo ./pqc-scanner --mode=wire --interface=eth1 --tenant="SPINOVATION"
   ```

### Requirements to Execute / Complete the Process
- Promiscuous network interface or mirrored flow log sink (Zeek, Suricata, or NetFlow v9/IPFIX logs).
- Network permissions to capture TCP SYN/ClientHello packets (only handshake headers are inspected; payload data is ignored).

### Results Produced
- Real-time catalog of all in-flight TLS handshakes.
- Cryptographic visibility into Server Name Indications (SNI), client-offered cipher suites, selected cipher suites, and negotiated TLS protocol versions.
- Identification of legacy ciphers (e.g., `RC4`, `3DES`, static `RSA` key exchange without Perfect Forward Secrecy).

### How to View the Results
- **Overview & Metrics:** Total in-flight sessions categorized by TLS 1.3, TLS 1.2, and legacy TLS versions.
- **CBOM Inventory:** Assets tagged with `source = 'wire_tls'` showing host endpoints, listening ports, and detected ciphers.

---

## 7. Feature 6: Tier 3 Endpoint Workstation Fleet Scanner (macOS, Windows, Linux)

### Purpose
Discovers cryptographic keys, asymmetric certificates, SSH keys, OpenSSL/GPG configurations, Java KeyStores (JKS), and application crypto libraries installed across enterprise employee workstations, developer laptops, and physical/virtual servers. **Guarantees zero reboots, non-intrusive operations, and 0% idle CPU overhead.**

### Steps to Connect
1. Navigate to **Integrations Hub ➔ Tier 3 ➔ Endpoint Workstations** (or console **Settings ➔ Deployment**).
2. Copy the pre-authenticated, 1-click deployment command for your operating system:

#### macOS (Apple Silicon & Intel):
```bash
curl -fsSL "https://quarkshield.ai/api/fleet/download/macos?token=YOUR_FLEET_TOKEN" -o install.sh && sudo bash install.sh
```

#### Windows (PowerShell):
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://quarkshield.ai/api/fleet/download/windows?token=YOUR_FLEET_TOKEN'))
```

#### Linux (Debian, Ubuntu, RHEL, Rocky):
```bash
curl -fsSL "https://quarkshield.ai/api/fleet/download/linux?token=YOUR_FLEET_TOKEN" -o install.sh && sudo bash install.sh
```

3. Deploy via your enterprise device management tooling:
   - **macOS:** Jamf Pro, Microsoft Intune, Kandji, or Munki.
   - **Windows:** Microsoft Intune, SCCM, Group Policy (GPO), or BigFix.
   - **Linux:** Ansible, Puppet, Chef, or SaltStack.

### Requirements to Execute / Complete the Process
- Valid Fleet Token (automatically injected into script).
- Standard operating system user execution (scans user profile and public trust stores) or root/Administrator (scans system-wide key chains and services).
- No kernel extensions, no background reboots, and non-blocking I/O.

### Results Produced
- Complete audit of all stored cryptographic artifacts:
  - Private Keys (`.pem`, `.key`, `.pkcs8`, `.p12`)
  - X.509 Certificates (macOS Keychain, Windows Root Cert Store, Linux `/etc/ssl/certs`)
  - SSH User Keys (`id_rsa`, `id_ed25519`, `known_hosts`)
  - GPG / PGP Keyrings
  - Java KeyStores (`.jks`, `.keystore`)
  - Python / Node / Go cryptographic dependency libraries
- Continuous telemetry reporting (Hostname, IP, OS version, Agent version, Last Seen timestamp, Vulnerable Asset count).

### How to View the Results
- **Fleet Management Screen:** Displays all enrolled endpoints in an interactive table with Online/Offline status, hostname, OS icon, total assets found, and last check-in.
- **CBOM Inventory:** Filter by `Source: Fleet Endpoints`. Click any asset row to view the machine hostname, exact file system path, key length, algorithm, and quantum vulnerability status.

---

## 8. Feature 7: Tier 3 CI/CD Pipeline CBOM Security Gate (Shift-Left PR Blocker)

### Purpose
Prevents quantum-vulnerable cryptography from entering production codebases by embedding automated policy gates into developers' continuous integration workflows. Automatically audits code changes in pull requests and **fails the CI/CD build (Exit Code 1)** if developers introduce deprecated classical algorithms (RSA, ECC, 3DES, MD5, SHA-1).

### Steps to Connect
1. Navigate to **Integrations Hub ➔ Tier 3 ➔ CI/CD Pipeline Gate** (or **External Repositories ➔ CI/CD Gate**).
2. Choose your CI/CD provider (**GitHub Actions**, **GitLab CI**, or **Bitbucket Pipelines**).
3. Copy the pre-configured workflow file into your repository:

#### For GitHub Actions (`.github/workflows/quarkshield-pqc-gate.yml`):
```yaml
name: QuarkShield Post-Quantum Security Gate

on:
  pull_request:
    branches: [ "main", "master", "develop" ]

jobs:
  pqc-audit:
    name: Evaluate Cryptographic Bill of Materials (CBOM)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Execute QuarkShield CI/CD Policy Gate
        env:
          QUARKSHIELD_API_URL: "https://quarkshield.ai"
          QUARKSHIELD_API_TOKEN: ${{ secrets.QUARKSHIELD_API_TOKEN }}
          QUARKSHIELD_POLICY: "Strict Zero-Tolerance PQC"
        run: |
          curl -sSL "https://quarkshield.ai/api/git/ci-gate/runner.sh" | bash -s -- \
            --token="$QUARKSHIELD_API_TOKEN" \
            --policy="$QUARKSHIELD_POLICY" \
            --repo="${{ github.repository }}" \
            --pr="${{ github.event.number }}" \
            --sha="${{ github.sha }}"
```

4. Add `QUARKSHIELD_API_TOKEN` to your repository or organization secrets.

### Requirements to Execute / Complete the Process
- Repository webhook or CI/CD runner execution permissions.
- Outbound HTTPS network access from runner to `https://quarkshield.ai`.
- Developer creates or updates a Pull Request.

### Results Produced
- **Automated Policy Decision:**
  - **`PASSED` (Exit Code 0):** PR contains zero non-compliant algorithms. CI build passes and merge is unblocked.
  - **`BLOCKED` (Exit Code 1):** PR introduces quantum-vulnerable primitives (e.g., `crypto.createCipher('des')` or RSA-1024 keys). CI build fails and blocks the PR from merging.
- **GitHub Flavored Markdown PR Comment:** Automatically posted directly onto the pull request thread:
  ```markdown
  ### 🛡️ QuarkShield Post-Quantum Security Gate: BLOCKED (Exit Code 1)
  **Repository:** `spinovation/payment-gateway` | **PR:** `#42` | **Risk Score:** `84 / 100`

  #### Violations Detected:
  - ❌ **CRITICAL:** `RSA-1024` private key declared in `src/auth/jwt.js:45` (Quantum Breakable via Shor's Algorithm)
  - ❌ **HIGH:** `MD5` hashing used for checksum in `src/utils/hasher.py:12`
  - 💡 **Remediation Recommendation:** Replace with `ML-DSA-65` (FIPS 204) or `SHA-256 / SHA-384`.
  ```

### How to View the Results
- **Inside GitHub / GitLab / Bitbucket:** View directly on the Pull Request conversation tab and CI Checks status list.
- **QuarkShield Console (CI/CD Gate History Tab):** Review the audit table containing timestamps, repository names, PR numbers, authors, violation summaries, risk scores, and gate verdicts.

---

## 9. Feature 8: Tier 3 Remote Git Repository Cryptographic Auditor

### Purpose
Performs static application cryptographic analysis (SACA) across remote Git repositories (public or private) without requiring developers to check out code or install local scanners. Detects hardcoded private keys, certificates, cryptographic library calls, weak hashing algorithms, and insecure cipher suites.

### Steps to Connect
1. Navigate to **Integrations Hub ➔ Tier 3 ➔ Remote Git Repositories** (or click **External Repositories** in the left sidebar).
2. Enter the **Git Repository URL** (e.g., `https://github.com/spinovation/api-service.git`).
3. Specify the **Target Branch** (default: `main` or `master`).
4. (Optional for private repositories): Enter a **Personal Access Token (PAT)** or SSH Deploy Key.
5. Click **Scan Repository**.

### Requirements to Execute / Complete the Process
- Valid Git URL.
- Read access to target repository.
- Outbound network access from QuarkShield scanning workers to GitHub / GitLab / Bitbucket.

### Results Produced
- Scans file trees, manifests (`package.json`, `pom.xml`, `requirements.txt`, `go.mod`), and source code files.
- Extracts cryptographic primitives, key lengths, and cipher parameters.
- Idempotently catalogs findings into the central `assets` database tagged with `source = 'git_repo'` and `source_ref = [repo_url]`.
- Calculates repository-specific Quantum Risk Score (0–100).

### How to View the Results
- **Scan Summary Cards:** Displays Total Scanned Files, Cryptographic Primitives Discovered, Quantum-Vulnerable Assets, and Average Risk Score.
- **Code Snippet Inspector:** View exact matching lines, file paths, and syntax-highlighted code blocks with flagged cryptographic vulnerabilities.
- **CBOM Inventory:** Filter by `Source: Git Repositories` to view code findings alongside workstation and cloud assets.

---

## 10. Feature 9: Universal Cryptographic Bill of Materials (CBOM) & Multi-Source Inventory

### Purpose
Provides a consolidated, single-pane inventory of **every cryptographic asset across the entire enterprise** regardless of where it was discovered (cloud HSMs, enterprise PKI, hybrid proxies, workstations, or source code repositories). Formatted in accordance with the **CycloneDX 1.6 Cryptographic BOM specification**.

### Steps to Connect
- Automatically populated by all connected Tier 1, Tier 2, and Tier 3 sources. No separate manual connection required.

### Requirements to Execute / Complete the Process
- Open the **CBOM Inventory** tab in the tenant portal or administrative console.
- Use the **Source Filter Dropdown** to segment data:
  - `All Sources` (Complete enterprise view)
  - `Fleet Endpoints` (macOS, Windows, Linux workstations)
  - `Git Repositories` (Source code findings)
  - `Cloud KMS` (AWS KMS & Azure Key Vault)
  - `Enterprise PKI` (Microsoft AD CS & HashiCorp Vault)
  - `Hybrid Proxy` (Active edge TLS gateways)
- Use the **Search Bar** to search across algorithm names, hostnames, file paths, or key sizes.

### Results Produced
- **Universal Inventory Table:**
  - **Asset Name / Algorithm:** e.g., `RSA-2048`, `ML-KEM-768`, `ECDSA-P384`, `AES-256-GCM`.
  - **Source Badge:** Color-coded badges indicating origin (`Endpoint`, `Git Repo`, `Cloud KMS`, `Enterprise PKI`, `Hybrid Proxy`).
  - **Host / Source Reference:** Machine hostname, repository URL, or cloud ARN.
  - **Location / Path:** File path, registry hive, or KMS alias.
  - **Shor Algorithm Threat:** Explicit indicator (`VULNERABLE` in red or `PQC SECURE` in emerald).
  - **Quantum Risk Score:** Numerical risk score (0 to 100).
- **High-Performance Pagination:** Renders 50 assets per page with instant page flipping to ensure 0ms UI lag even with tens of thousands of discovered assets.

### How to View the Results
- Navigated via **CBOM Inventory** tab in the main portal navigation.
- CSV and JSON export buttons available on top right of the table.

---

## 11. Feature 10: CycloneDX 1.6 & CDXA (CycloneDX Attestation) Post-Quantum Signing Block

### Purpose
Generates standards-compliant **CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)** files enriched with **CycloneDX Attestation (CDXA)** declarations. Certifies compliance against **NIST SP 800-218 (Secure Software Development Framework - SSDF)**, **NSA CNSA 2.0**, and **NIST FIPS 203/204/205**. The attestation document is digitally signed using **ML-DSA-65 (NIST FIPS 204)**, creating a tamper-evident compliance artifact for federal agencies, defense contractors, and external auditors.

### Steps to Connect
1. Navigate to **CBOM Inventory ➔ Raw JSON & Export** sub-tab.
2. In the toolbar, click either:
   - **Export Standard CBOM:** Generates lean CycloneDX 1.6 JSON containing all discovered components.
   - **Export Attested CBOM (CDXA):** Generates attested CycloneDX 1.6 JSON with formal assessor claims, target bindings, and post-quantum digital signature.

### Requirements to Execute / Complete the Process
- Authenticated user session.
- Attestation engine dynamically resolves the active tenant name and binds the claims to that specific organization.

### Results Produced
- Standardized CycloneDX 1.6 JSON document containing:
  - `bomFormat`: `"CycloneDX"`
  - `specVersion`: `"1.6"`
  - `metadata.component.name`: `"QuarkShield PQC CBOM - [TENANT_NAME]"`
  - `declarations.assessors`: Certified by `QuarkShield AI Inc.`
  - `declarations.targets`: Formally bound to target organization `{ name: "[TENANT_NAME]" }`
  - `declarations.affirmation`: Conformance statement with NIST SP 800-218 and CNSA 2.0.
  - `declarations.claims`: Detailed claims evaluating Shor's algorithm susceptibility and post-quantum migration posture.
  - `signature`: Tamper-evident JSF envelope signed with **ML-DSA-65** over SHA-256 payload digest.

### How to View the Results
- **Interactive JSON Viewer:** On-screen viewer displays a lightweight preview of the schema with syntax formatting.
- **CDXA Toggle Button:** Toggle `CDXA Attestation & Signing: ON/OFF` to dynamically inspect the live declarations and signature block.
- **Download File:** Downloads `[tenant]-cbom.cyclonedx-1.6.json` or `[tenant]-cbom.cdxa-attested-1.6.json`.

---

## 12. Feature 11: Mosca's Migration Planner (Y2Q Readiness Assessment)

### Purpose
Implements quantitative risk modeling based on **Mosca's Theorem ($X + Y > Z$)** to help executive leadership and compliance officers calculate when an organization will experience quantum compromise:
- **Shelf-Life ($X$):** How many years customer/organizational data must remain confidential (e.g., medical records, financial data, state secrets: 10–30 years).
- **Migration Time ($Y$):** How many years required to re-architect, recertify, and migrate infrastructure to post-quantum algorithms (typically 3–7 years).
- **Quantum Threat Horizon ($Z$):** How many years until a Cryptanalytically Relevant Quantum Computer (CRQC) emerges (NIST/NSA estimates: 2029–2033).
- **Risk Condition:** If **$X + Y > Z$**, the organization is ALREADY compromised today due to "Harvest Now, Decrypt Later" (HNDL) attacks.

### Steps to Connect
1. In the tenant portal, click **Settings** in the left sidebar.
2. Select the **Mosca's Migration Planner** sub-tab.

### Requirements to Execute / Complete the Process
- Adjust the interactive input sliders:
  - **Data Confidentiality Shelf-Life ($X$):** Select between 1 and 30 years.
  - **Infrastructure Migration Timeline ($Y$):** Select between 1 and 10 years.
  - **Estimated Arrival of Quantum Computer ($Z$):** Set target year (default: 2030).
- The engine dynamically pulls live discovered fleet metrics (Total Fleet Endpoints, Total Cryptographic Assets, and Shor-Vulnerable Assets) to compute migration workload sizing.

### Results Produced
- **Mathematical Verdict:**
  - 🚨 **CRITICAL RISK (Compromised Today):** Displayed when $X + Y > Z$. Visual warning indicates data harvested today will be decrypted before confidentiality obligations expire.
  - ⚠️ **BALANCED MIGRATION:** Displayed when migration will complete just in time.
  - ✅ **SECURE POSTURE:** Displayed when migration completes safely before quantum arrival.
- **Timeline Gantt Chart:** Visual horizontal bar chart contrasting Data Shelf-Life, Migration Phase, and Quantum Threat Arrival.
- **Critical Path Gap Analysis:** Quantifies exact deficit in months and years.

### How to View the Results
- Rendered interactively inside **Settings ➔ Mosca's Migration Planner**.
- Summarized on executive PDF/DOCX reports exported for board and audit committee presentations.

---

## 13. Feature 12: PQC Copilot (Enterprise Cryptographic Advisory AI)

### Purpose
Provides administrators, cryptographers, and auditors with a conversational AI assistant trained specifically on post-quantum cryptography, NIST standards (FIPS 203, 204, 205), NSA CNSA 2.0 migration timelines, QuarkShield platform operations, and step-by-step remediation playbooks.

### Steps to Connect
1. Click **PQC Copilot** in the left navigation sidebar (or click the floating Copilot launcher icon).
2. Type any natural language question into the message input box, or click one of the 1-click **Quick Prompt Chips** located above the prompt box:
   - *"What are my next steps after license onboarding?"*
   - *"How do I run my first desktop scan?"*
   - *"Explain the 3-Tier Enterprise Strategy"*
   - *"How do I configure the CI/CD Pipeline Gate?"*
   - *"How do I deploy the Hybrid Quantum TLS Proxy?"*
   - *"How do I connect Enterprise PKI & Vaults?"*

### Requirements to Execute / Complete the Process
- Connected to QuarkShield backend. Operates in dual-mode:
  - **Online Mode:** Powered by state-of-the-art LLMs (Gemini / Anthropic Claude) enriched with live platform context and tenant statistics.
  - **Offline Local Rules Engine:** Immediate deterministic fallback answers if external AI APIs are unreachable, ensuring 100% operational uptime in air-gapped environments.

### Results Produced
- Step-by-step technical and operational guidance.
- Copyable terminal commands (curl, bash, PowerShell, Docker, YAML).
- Concrete code remediation examples (e.g., how to replace `crypto.createSign('RSA-SHA256')` with post-quantum equivalents).
- Audit and compliance verification guidelines.

### How to View the Results
- Direct conversational responses displayed in the **PQC Copilot** message thread with rich Markdown, code blocks, and copy buttons.

---

## Summary Matrix of QuarkShield Features

| Feature | Primary Tier | Target Environment | Authentication / Protocol | Primary Output / Result |
| :--- | :--- | :--- | :--- | :--- |
| **Unified Integrations Hub** | All Tiers | Central Management | RBAC (Corporate Admin / Crypto) | Single-pane connector directory & sync manager |
| **Cloud KMS Connectors** | Tier 1 | AWS KMS, Azure Key Vault | IAM Role ARN / App Registration | Discovered cloud keys, key rotation, Shor risk |
| **Enterprise PKI Connectors** | Tier 1 | Microsoft AD CS, HashiCorp Vault | LDAP, Kerberos, Vault AppRole | CA templates, root certs, internal PKI inventory |
| **Hybrid Quantum TLS Proxy** | Tier 2 | Application Ingress / Edge | OpenSSL 3.2+ / X25519MLKEM768 | Zero-code PQC TLS termination, HNDL defense |
| **In-Flight Wire TLS Mirror** | Tier 2 | Core Switches, VPC TAPs | SPAN, TAP, eBPF, Flow Logs | Unencrypted / weak TLS network session audit |
| **Endpoint Fleet Scanner** | Tier 3 | macOS, Windows, Linux Fleets | Fleet Enrollment Token (1-Click) | Host certificates, private keys, SSH, JKS |
| **CI/CD CBOM Security Gate** | Tier 3 | GitHub, GitLab, Bitbucket | API Token (`QUARKSHIELD_API_TOKEN`) | PR blocking (Exit Code 1), Markdown comments |
| **Remote Git Repo Auditor** | Tier 3 | GitHub, GitLab Repositories | Repo URL + Optional Git PAT | Static source code & dependency crypto audit |
| **Universal CBOM Inventory** | Cross-Tier | Unified PostgreSQL Database | Central Ingestion Engine | CycloneDX 1.6 inventory with multi-source filter |
| **CycloneDX Attestation (CDXA)**| Cross-Tier | Security Audits & Compliance | ML-DSA-65 (NIST FIPS 204) Signature | Attested, tamper-evident post-quantum CBOM |
| **Mosca's Migration Planner** | Governance | Executive & Compliance Review | Interactive Mathematical Engine | $X + Y > Z$ timeline risk posture & deadline gap |
| **PQC Copilot** | Advisory | Operational & Remediation AI | Dual LLM + Offline Deterministic Rules | Real-time CLI snippets, guidance, playbooks |

---

*© 2026 QuarkShield AI Inc. All rights reserved. For support, contact `support@quarkshield.ai` or visit `https://quarkshield.ai`.*
