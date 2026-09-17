# 🛡️ QuarkShield Agentless & API-First PQC Discovery Architecture
## The "Wiz Model" for Post-Quantum Cryptographic Visibility & CBOM Synthesis

**Document Version**: 2.0  
**Date**: September 2026  
**Audience**: Enterprise CISOs, Cloud Security Architects, Cryptographic Engineers, DevOps & SRE Teams  
**Compliance Frameworks**: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NSA CNSA 2.0, Executive Order 14028, CycloneDX 1.6+ CBOM  

---

## Executive Summary

The single greatest bottleneck in enterprise cybersecurity adoption is **"Agent Fatigue."** 

Traditional security vendors require organizations to deploy and maintain persistent background root daemons across tens of thousands of developer laptops, production Linux nodes, and cloud instances. This creates:
1. **DevOps & Developer Friction**: Strong pushback against CPU/RAM overhead, thermal throttling, and local process interference.
2. **Systemic Operational Risk**: Highlighted by the catastrophic July 2024 global CrowdStrike outage, where a single corrupted sensor update caused kernel panics and billions in enterprise downtime.
3. **Severe Procurement Latency**: Enterprise Architecture Review Boards (ARB) and change control committees routinely take **3 to 6 months** to approve agent deployments on production workloads.

Following the market disruption pioneered by **Wiz** (which reached a $12B+ valuation by championing 100% agentless cloud security), **QuarkShield introduces the Agentless & API-First PQC Discovery Architecture**. 

Instead of demanding resident agents on endpoints, QuarkShield connects to existing enterprise APIs—**Cloud KMS & Certificate Managers (AWS/Azure/GCP)**, **Enterprise MDMs (Microsoft Intune & Jamf Pro)**, **Centralized Vaults**, and **Out-of-Band Cloud Volume Snapshots**—to synthesize a comprehensive **Cryptographic Bill of Materials (CBOM)** and quantum vulnerability posture in **under 2 minutes with zero host footprint**.

---

## The Core Dilemma: Agent Friction vs. Agentless Speed

```
   TRADITIONAL AGENT MODEL                     QUARKSHIELD AGENTLESS / API MODEL
 ┌──────────────────────────┐               ┌──────────────────────────────────────┐
 │ • Root/Admin installation│               │ • Zero software installed on targets │
 │ • 3–6 months change ctrl │               │ • 2-minute read-only API onboarding  │
 │ • Kernel/daemon crashes  │    VERSUS     │ • 0% CPU & 0 MB RAM overhead         │
 │ • Heavy version drift    │               │ • Taps into existing MDMs (Intune)   │
 │ • Dev & SRE pushback     │               │ • Instant CISO & compliance sign-off │
 └──────────────────────────┘               └──────────────────────────────────────┘
```

---

## The 5 Core Agentless PQC API Connectors

```
                         ┌──────────────────────────────────────────┐
                         │   QuarkShield Management Console & API   │
                         │             (quarkshield.ai)             │
                         └────────────────────┬─────────────────────┘
                                              │
         ┌──────────────────┬─────────────────┼─────────────────┬──────────────────┐
         ▼                  ▼                 ▼                 ▼                  ▼
  ┌──────────────┐   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   ┌──────────────┐
  │ 1. Cloud KMS │   │2. Enterprise │  │ 3. Secret &  │  │ 4. Out-of-   │   │  5. Active   │
  │    & ACM     │   │     MDM      │  │  Code Repos  │  │ Band Storage │   │  TLS Prober  │
  └──────┬───────┘   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   └──────┬───────┘
         │                  │                 │                 │                  │
   • AWS KMS / ACM    • MS Intune       • HashiCorp Vault • AWS EBS Snapshot • Zero-touch TLS
   • Azure KeyVault   • Jamf Pro        • CyberArk        • Azure Disk Snap    1.3 handshake
   • GCP Cloud KMS    • Kandji          • GitHub / GitLab • Ephemeral mount  • Leaf & CA cert
     & Cert Manager   (Audits 10,000+     (Scans deploy     (0% host impact    chain analysis
                       laptops via API)    keys & repos)     0 agents needed) • PQC key exchange
```

### 1. Cloud Infrastructure & KMS APIs (AWS, Azure, Google Cloud)
* **Onboarding**: Read-only cross-account IAM Role (AWS), Service Principal (Azure), or Service Account (GCP).
* **Cryptographic Assets Discovered**:
  * **AWS**: KMS Customer Master Keys (CMKs), ACM Public & Private X.509 Certificates, CloudFront / ALB / NLB SSL negotiation profiles (flagging missing hybrid post-quantum key exchange groups).
  * **Azure**: Azure Key Vault keys, secrets, and certificates; Application Gateway / Front Door TLS termination settings.
  * **Google Cloud**: Cloud KMS KeyRings, Certificate Manager SSL certificates, HTTPS Cloud Load Balancing policies.
* **Quantum Risk Analysis**: Instantly categorizes RSA-2048/4096 and ECC (P-256, P-384, secp256k1) as Shor-vulnerable, providing transition pathways to NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).

### 2. Enterprise MDM APIs (Microsoft Intune & Jamf Pro for Workstations)
* **The Strategic Breakthrough**: Enterprises *already* run mandatory MDM agents on corporate devices. Rather than creating a competing daemon, QuarkShield taps directly into the MDM's centralized control plane via API.
* **Microsoft Intune (Graph API)**:
  * Connects to `https://graph.microsoft.com/v1.0/deviceManagement`.
  * Reads enrolled workstation profiles, installed root and intermediate certificate stores, BitLocker encryption algorithm settings, and system security configurations.
* **Jamf Pro REST API (macOS Fleets)**:
  * Queries macOS configuration profiles, installed identity certificates in system keychains, FileVault encryption keys, and developer workstation inventories.
* **Result**: Complete audit of 10,000+ developer and employee laptops in minutes with **zero software pushed to end-user machines**.

### 3. Centralized Secrets Vault & Git Repository APIs
* **Vault Connectors (HashiCorp Vault, CyberArk)**:
  * Reads PKI secrets engines, transit keys, and stored SSH certificates via read-only tokens.
* **Source Code & Git Connectors (GitHub, GitLab, Bitbucket)**:
  * Scans organization repositories and CI/CD pipelines for hardcoded PEM, DER, CRT, and KEY blobs.
  * Audits SSH deploy keys across all projects, identifying deprecated 1024/2048-bit RSA keys.

### 4. Out-of-Band Cloud Volume Snapshotting (The "Wiz Secret Sauce")
* For cloud virtual machines (EC2, Azure VMs, GCE instances) where deep filesystem inspection is required (discovering `/etc/ssh/sshd_config`, `/etc/ssl/certs`, and developer `~/.ssh` keys):
  1. QuarkShield requests a read-only point-in-time snapshot of the root EBS / disk volume via Cloud API.
  2. The snapshot is attached out-of-band to a dedicated, ephemeral QuarkShield scanning container inside an isolated analysis VPC.
  3. The scanning engine inspects the disk image, parses certificate headers, examines dynamic libraries (`libcrypto.so`), and indexes the filesystem.
  4. Findings are pushed to the customer's CBOM database; the snapshot is detached and permanently deleted.
* **Impact**: **0% CPU, 0 MB RAM, and 0 agents on the customer's production host.**

### 5. Remote Network & Port PQC Prober (Zero-Touch Active Scanner)
* **Scope**: External and internal IP CIDRs, subnets, and fully qualified domain names (FQDNs).
* **Operations**:
  * Conducts active TLS 1.3 handshakes to detect hybrid post-quantum key exchange support (`X25519MLKEM768` / `mlkem768x25519`).
  * Validates full X.509 certificate chains down to the root CA, flagging classical signatures (SHA256withRSA, ECDSA).
  * Audits SSH endpoints on port 22 for post-quantum key exchange groups (`sntrup761x25519-sha512`).
  * *See complete specification*: [Active Network & Outbound TCP/TLS Socket PQC Probing Architecture](ACTIVE_NETWORK_TLS_PQC_PROBING.md) for live socket workflows, empirical tests against `microsoft.com`, and HNDL/Shor's/Grover's threat breakdowns.

---

## Repositioning the Native Binary: The Ephemeral 1-Shot CLI

In this modern architecture, the Go scanner binary (`quarkshield-scanner`) is not discarded—it is repositioned into its most potent enterprise form: an **Ephemeral 1-Shot CLI & CI/CD Security Gate**:

```bash
# 1. Developer self-audit (runs in 2 seconds, prints output, terminates):
./quarkshield-scanner --quick

# 2. Local CBOM export:
./quarkshield-scanner --output cbom.json

# 3. CI/CD Pipeline Step (GitHub Actions / GitLab CI):
- name: QuarkShield Post-Quantum Security Gate
  run: |
    curl -fsSL https://quarkshield.ai/downloads/quarkshield-scanner-linux-amd64 -o /usr/local/bin/quarkshield-scanner
    chmod +x /usr/local/bin/quarkshield-scanner
    quarkshield-scanner --ci --fail-on-vulnerable
```

* **No Background Daemon**: Runs once in user-space and immediately terminates.
* **Air-Gapped Ready**: Operates completely offline in high-security classified environments.

---

## Architectural Comparison Matrix

| Evaluation Dimension | **Wiz-Style Agentless (API)** | **Persistent Daemon Agent** | **Ephemeral 1-Shot CLI** |
| :--- | :--- | :--- | :--- |
| **Deployment Time** | **< 2 minutes** (OAuth/IAM role) | 3–6 months (rollout & approvals) | 10 seconds (`curl \| sh`) |
| **Host Resource Impact** | **0% CPU / 0 MB RAM** | Constant memory & CPU overhead | 2 seconds runtime, then exits |
| **Production Crash Risk** | **0%** (Read-only API calls) | High (Kernel/system panics) | 0% (User-space execution) |
| **Workstation Fleet Audit** | **Instant** via Intune / Jamf APIs | Complex MDM installer push | Developer-driven or CI gate |
| **Cloud KMS & ACM Audit** | **Native** (AWS, Azure, GCP) | Cannot audit cloud control planes| Requires local API keys |
| **CI/CD Integration** | N/A (Infrastructure layer) | Impractical for ephemeral runners| **Native fit** (Trivy-style) |
| **Enterprise Buyer Buy-In** | **Highest** (CISO & ARB preferred) | Strong resistance & friction | High for Engineering teams |

---

## Roadmap for Standalone VPS (`quarkshield.ai`)

When deploying to the dedicated Contabo VPS, QuarkShield will provide a unified **Hybrid Management Console**:

1. **Tab 1: Cloud & MDM API Connectors**:
   - 1-click wizard to connect AWS, Azure, Microsoft Intune, and Jamf Pro.
   - Automatically synchronizes cloud KMS keys and corporate workstation certificates into the centralized asset graph.
2. **Tab 2: Remote Active Network Prober**:
   - Enter IP ranges, subnets, or domain names to launch zero-touch external PQC scans.
3. **Tab 3: Ephemeral CLI & 1-Click Enrollment**:
   - For developer laptops and CI/CD pipelines wanting instantaneous local audits.
4. **Tab 4: Unified CycloneDX 1.6+ CBOM Explorer**:
   - Aggregates assets from both Agentless APIs and CLI runners into a single cryptographic bill of materials with real-time NIST PQC remediation roadmaps.
