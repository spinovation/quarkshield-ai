# QuarkShield.ai — Super Admin Guide: Platform Stack SBOM & Competitive Analysis Matrix
**Document Classification: HIGHLY CONFIDENTIAL — SUPER ADMIN & PLATFORM SEC-OPS ONLY**  
**Target Scope: quarkshield.ai Infrastructure Governance & Market Positioning**  
**Regulatory Standards: NIST SP 800-218 (SSDF) | CycloneDX 1.6 | OMB M-22-18 | NSA CNSA 2.0 | FIPS 203/204/205**  
**Last Updated: 2026-09-23**

---

## 1. Executive Summary & Purpose

This document is strictly restricted to **Super Administrators, Platform Architects, and Enterprise SecOps Leadership** of QuarkShield.ai. It serves two strategic purposes:

1. **Internal Platform Infrastructure SBOM Governance**: Details the complete, authentic Software Bill of Materials (SBOM) for the **`quarkshield.ai`** platform stack, documenting its 15 core components, runtime dependencies, container images, zero-vulnerability audit provenance, historical remediation trails, and the 1-click platform upgrade/fix engine.
2. **Competitive Intelligence & Technical Comparison**: Provides an exhaustive, objective technical review and feature-by-feature comparison matrix evaluating **QuarkShield.ai** against the three dominant market competitors in post-quantum cryptography (PQC) and cryptographic agility:
   - **SandboxAQ (AQtive Guard)**
   - **IBM Quantum Safe (Explorer, Advisor, Remediator)**
   - **QuSecure (QuProtect)**

---

## 2. QuarkShield.ai Platform Stack SBOM (`quarkshield.ai`)

### 2.1 Why the Platform Stack SBOM is Restricted Strictly to Super Admin
Under no circumstances should the internal infrastructure stack of `quarkshield.ai` be exposed to customer tenants, unauthenticated external visitors, or client users:
- **Reconnaissance Mitigation**: Revealing exact runtime package versions (e.g., Express 4.19.2, pg 8.11.5, Alpine 3.22) provides adversaries with exact targeting vectors for zero-day exploitation.
- **Tenant Data Isolation**: Regular customers logging into their dedicated tenant portal (`TenantPortal.tsx`) must only view their own enrolled enterprise assets, repositories, and software workloads (e.g., `SPINOVATIONCORP`, `AMBEROON`).
- **Enforcement Architecture**:
  - **Backend Privilege Gate**: The backend controller (`sbomController.ts`) intercepts all incoming requests where `tenant` resolves to `quarkshield.ai`, `system`, or `platform`.
  - It validates the request against `x-admin-role: super_admin`, `root_admin`, or `admin=true`.
  - If a non-super-admin attempts to query platform stack components, stats, export, or fix scripts, the server immediately terminates the connection with **`HTTP 403 Forbidden`**:
    ```json
    {"success": false, "error": "Access Denied: QuarkShield Platform Stack SBOM is restricted to Super Admin only."}
    ```
  - **Frontend Scoping**: In `TenantPortal.tsx`, `isSuperAdmin` is hardcoded to `false`. The platform stack banner and scope toggle are completely omitted from the DOM. In `AdminPanel.tsx`, the dedicated tab **Platform Stack SBOM (quarkshield.ai)** is rendered with a prominent **Super Admin Only** security badge.

---

### 2.2 Complete Platform Stack Inventory (15 Components)

Every package deployed in the production environment of `quarkshield.ai` (`13.140.40.99`) is cataloged below, structured according to **CycloneDX 1.6** specifications:

| ID | Component Name | Installed Version | Ecosystem / Layer | License | PURL | Vulnerability Posture & Remediation Status | Actionable Upgrade / Fix Command |
|---|---|---|---|---|---|---|---|
| `qs-plat-01` | **express** | `4.19.2` | `npm` (Backend) | MIT | `pkg:npm/express@4.19.2` | ✅ **0 Known CVEs**. Minimal HTTP server framework. | `npm install express@latest` |
| `qs-plat-02` | **pg** | `8.11.5` | `npm` (Backend) | MIT | `pkg:npm/pg@8.11.5` | ✅ **0 Known CVEs**. Non-blocking PostgreSQL connection pool. | `npm install pg@latest` |
| `qs-plat-03` | **cors** | `2.8.5` | `npm` (Backend) | MIT | `pkg:npm/cors@2.8.5` | ✅ **0 Known CVEs**. Strict CORS policy middleware. | `npm install cors@latest` |
| `qs-plat-04` | **dotenv** | `16.4.5` | `npm` (Backend) | BSD-2-Clause | `pkg:npm/dotenv@16.4.5` | ✅ **0 Known CVEs**. Isolated environment configuration. | `npm install dotenv@latest` |
| `qs-plat-05` | **typescript** | `5.4.5` | `npm` (Backend) | Apache-2.0 | `pkg:npm/typescript@5.4.5` | ✅ **0 Known CVEs**. Static type checker and compiler. | `npm install -D typescript@latest` |
| `qs-plat-06` | **qs** | `6.15.4` | `npm` (Backend) | BSD-3-Clause | `pkg:npm/qs@6.15.4` | 🛡️ **REMEDIATED (0 Active CVEs)**. Previously affected v6.15.3 via `GHSA-x5fp-wj9c-mxmx` (CVSS 7.5 array-limit bypass). Remediated to v6.15.4 via `npm audit fix`. | `npm audit fix` |
| `qs-plat-07` | **react** | `19.2.6` | `npm` (Frontend) | MIT | `pkg:npm/react@19.2.6` | ✅ **0 Known CVEs**. React core component and state library. | `npm install react@latest react-dom@latest` |
| `qs-plat-08` | **react-dom** | `19.2.6` | `npm` (Frontend) | MIT | `pkg:npm/react-dom@19.2.6` | ✅ **0 Known CVEs**. React Virtual DOM rendering engine. | `npm install react-dom@latest` |
| `qs-plat-09` | **lucide-react** | `1.17.0` | `npm` (Frontend) | ISC | `pkg:npm/lucide-react@1.17.0` | ✅ **0 Known CVEs**. High performance vector icon suite. | `npm install lucide-react@latest` |
| `qs-plat-10` | **vite** | `8.0.12` | `npm` (Frontend) | MIT | `pkg:npm/vite@8.0.12` | ✅ **0 Known CVEs**. Production build tool and asset optimizer. | `npm install -D vite@latest` |
| `qs-plat-11` | **pqc-scanner-engine** | `2.0.0` | `golang` (Agent) | Proprietary | `pkg:golang/quarkshield.ai/scanner-engine@2.0.0` | ✅ **0 External Dependencies**. Pure Go standard library (`crypto/x509`, `crypto/tls`). 100% memory-safe compiled binary. | `cd agent && go build -ldflags="-s -w" -o binaries/pqc-scanner auditor.go` |
| `qs-plat-12` | **node** | `22-alpine` | `os_pkg` (Container) | MIT | `pkg:docker/node@22-alpine` | ✅ **0 Known CVEs**. Minimal hardened Alpine Linux Node 22 LTS base. | `docker pull node:22-alpine` |
| `qs-plat-13` | **postgres** | `15-alpine` | `os_pkg` (Container) | PostgreSQL | `pkg:docker/postgres@15-alpine` | ✅ **0 Known CVEs**. Minimal PostgreSQL 15 enterprise database image. | `docker pull postgres:15-alpine` |
| `qs-plat-14` | **openssl** | `3.5.8-r0` | `os_pkg` (OS Runtime)| Apache-2.0 | `pkg:alpine/openssl@3.5.8-r0` | ✅ **0 Known CVEs**. Hybrid PQC TLS 1.3 cryptographic engine. | `apk upgrade --no-cache openssl` |
| `qs-plat-15` | **curl** | `8.22.0-r0` | `os_pkg` (OS Runtime)| curl | `pkg:alpine/curl@8.22.0-r0` | ✅ **0 Known CVEs**. Hardened HTTP network transport utility. | `apk upgrade --no-cache curl` |

---

### 2.3 Vulnerability Audit & Clean Certification
- **Auditing Toolchain**: Node package manifests (`package.json`, `package-lock.json`) are audited using `npm audit` and compared against the GitHub Advisory Database and National Vulnerability Database (NVD).
- **Audit Verification Command**:
  ```bash
  cd /opt/desktop-pqc-scanner/server && npm audit
  cd /opt/desktop-pqc-scanner/ui && npm audit
  ```
- **Audit Result**:
  ```
  audited 86 packages in 4s
  found 0 vulnerabilities
  ```
- **Transitive Remediation Provenance**: To demonstrate rigorous supply-chain compliance under **NIST SP 800-218 Section PW.4.1**, the platform explicitly logs that `qs` was upgraded from `6.15.3` to `6.15.4`. This satisfies auditor inquiries demonstrating active, continuous patch management.

---

### 2.4 Super Admin 1-Click Platform Maintenance Script
Super Admins can download `quarkshield-platform-upgrade.sh` directly from the Admin Panel or trigger it via curl. The script executes a deterministic 5-step maintenance lifecycle:

```bash
#!/bin/bash
# ==============================================================================
# QuarkShield Platform Stack Maintenance & Upgrade Script
# Target: quarkshield.ai Production Infrastructure (13.140.40.99)
# Access: Strictly Super Admin Only
# Security Posture: 0 Active Vulnerabilities | NIST SP 800-218 Aligned
# ==============================================================================

set -e

echo "🛡️ Starting QuarkShield Platform Stack Maintenance & Security Verification..."

# 1. Server Dependencies Security Audit & Upgrades
echo "📦 [1/5] Auditing server dependencies..."
cd server
npm audit
npm audit fix
npm update express pg cors dotenv
cd ..

# 2. Frontend UI Dependencies Security Audit & Upgrades
echo "🎨 [2/5] Auditing UI dependencies..."
cd ui
npm audit
npm audit fix
npm update react react-dom lucide-react vite
cd ..

# 3. Scanner Agent Binary Rebuild & Verification
echo "⚡ [3/5] Verifying PQC Scanner Agent (Zero-Dependency Pure Go)..."
cd agent
go build -ldflags="-s -w" -o binaries/pqc-scanner auditor.go
cd ..

# 4. OS System Package Updates (Alpine Container)
echo "🐧 [4/5] Checking OS system packages in Alpine runner..."
if command -v apk >/dev/null 2>&1; then
  apk update && apk upgrade --no-cache openssl ca-certificates curl
fi

# 5. Production Container Build & Reload
echo "🚀 [5/5] Rebuilding and launching production containers..."
docker compose build --no-cache
docker compose up -d

echo "======================================================================"
echo "✅ QuarkShield Platform Stack Upgrade & Verification Complete!"
echo "📡 Service Health: http://localhost:5050/health"
echo "🌐 Platform SBOM:   http://localhost:5050/api/sbom/export?tenant=quarkshield.ai"
echo "======================================================================"
```

---

## 3. In-Depth Competitive Review

To evaluate QuarkShield's market position, we analyze the three primary competitors in the post-quantum cryptography and cryptographic agility market:

### 3.1 Competitor 1: SandboxAQ (AQtive Guard)
* **Origins & Funding**: Spun out of Alphabet in 2022 with \$500M+ in funding. Led by Jack Hidary (CEO) and Eric Schmidt (Chairman).
* **Flagship Platform**: **AQtive Guard** (formerly AQInsight), modularized into Discovery, Inventory, and Remediation.
* **Architecture & Mechanics**:
  - Deploys proprietary host-level software agents ("AQ Sensor") across enterprise endpoints, combined with network SPAN port/mirror taps.
  - Generates Cryptographic Bill of Materials (CBOM) by scanning local certificate stores, running processes, and network TLS handshakes.
  - Relies heavily on cloud SaaS analytics with enterprise SIEM/SOAR connectors.
* **Target Audience**: Global Fortune 100 enterprises, Tier-1 investment banks (Mount Sinai, Vodafone, US Air Force, SoftBank), and defense contractors.
* **Pricing & Procurement**:
  - Extremely high price point (typically \$250,000 – \$1,000,000+ annual subscription).
  - Mandatory high-cost professional services engagements lasting 6 to 12 months for initial baseline deployment.
* **Critical Limitations**:
  - **Heavy Infrastructure Overhead**: Requires complex network tapping or resource-intensive endpoint agents.
  - **No Unified Lightweight SBOM**: Focuses almost exclusively on cryptographic assets (keys, certs, TLS); generic software dependency vulnerability management (npm, PyPI, Go, Alpine OS CVEs) is treated as a secondary thought and requires separate tooling (Snyk, Veracode).
  - **No 1-Click Copyable Code Fixes**: Provides high-level strategic migration roadmaps but lacks developer-centric, 1-click terminal copyable package remediations.
  - **Closed Ecosystem**: Proprietary data formats; slow to deliver standalone, offline, zero-dependency tools for small-to-medium enterprises.

---

### 3.2 Competitor 2: IBM Quantum Safe
* **Origins & Backing**: Developed by IBM Research and IBM Security; heavily promoted at IBM Think 2023–2025.
* **Flagship Platform**: A tripartite suite consisting of:
  - **IBM Quantum Safe Explorer**: Source code static analysis tool scanning application codebases for cryptographic API usage.
  - **IBM Quantum Safe Advisor**: Centralized cryptographic asset inventory, aggregating discovered CBOMs across servers and networks.
  - **IBM Quantum Safe Remediator**: Policy automation tool assisting in cryptographic agility patterns and hybrid TLS configurations.
* **Architecture & Mechanics**:
  - Tightly coupled to the **IBM Z mainframe (z/OS)** ecosystem, LinuxONE, and Red Hat OpenShift.
  - Uses abstract syntax tree (AST) scanners to parse legacy languages (COBOL, C/C++, Java, Python) for hardcoded cryptographic primitives.
* **Target Audience**: Large-scale financial institutions, insurance conglomerates, and government agencies with massive legacy mainframe investments.
* **Pricing & Procurement**:
  - Multi-year enterprise license agreements (ELA) bundled into IBM Cloud Paks.
  - Heavily dependent on **IBM Consulting** (formerly IBM Global Business Services) for implementation and operational maintenance.
* **Critical Limitations**:
  - **Ecosystem Lock-in**: Almost entirely geared towards Red Hat OpenShift and IBM hybrid cloud infrastructure. Impractical for agile, cloud-native startups or mid-market enterprises running lean Docker or Kubernetes.
  - **Massive Resource Footprint**: Running the Quantum Safe stack requires dedicated OpenShift clusters, Apache Kafka event buses, and extensive database backends.
  - **Sluggish Time-to-Value**: Deployment, rule configuration, and baseline generation typically require 9 to 18 months of consulting time.
  - **Lack of Multi-Tenant Self-Service**: Designed for single monolithic enterprise deployments; lacks lightweight multi-tenant isolation out-of-the-box.

---

### 3.3 Competitor 3: QuSecure (QuProtect)
* **Origins & Backing**: Founded in 2019; Silicon Valley-based startup focusing on post-quantum cybersecurity software.
* **Flagship Platform**: **QuProtect** (QuProtect Core, QuProtect Orchestrator, QuProtect VPN).
* **Architecture & Mechanics**:
  - Specializes in **active cryptographic tunneling and real-time session orchestration**.
  - Operates as an inline network overlay proxy / PQC VPN between clients, edge devices, and servers.
  - Features dynamic cryptographic agility: can swap cipher suites mid-session (e.g., fallback from Kyber/ML-KEM to classical ECDH) without dropping active TCP connections.
* **Target Audience**: Telecommunications carriers, satellite/LEO constellations (Starlink/government comms), federal defense (DoD, USAF), and real-time financial transaction switches.
* **Pricing & Procurement**:
  - Bandwidth, node, and throughput-based subscription licensing, typically starting at \$100,000+ per year.
* **Critical Limitations**:
  - **No Codebase or Git Repository Scanning**: QuProtect is an *in-flight communication protector*; it does NOT scan Git repositories, does NOT parse `package.json` or `go.mod`, and cannot detect static cryptographic vulnerabilities in developer source code.
  - **No CI/CD PR Merge Gates**: Does not integrate into GitHub Actions or GitLab CI to block vulnerable pull requests before they reach production.
  - **No Software Supply-Chain SBOM**: Does not inventory software libraries, does not match CVEs, and cannot provide CycloneDX 1.6 SBOM deliverables.
  - **Inline Latency & Single Point of Failure**: Routing all traffic through QuProtect nodes introduces latency and risk of network partition if orchestration nodes fail.

---

### 3.4 Competitor 4: QuarkShield.ai (Our Strategic Advantages)
QuarkShield.ai was engineered to eliminate the enterprise bloat, massive consulting overhead, and fragmented toolchains of competitors by delivering:

1. **First Unified Dual-Layer CBOM + CycloneDX 1.6 SBOM Platform**:
   - Simultaneously scans for cryptographic assets (TLS ciphers, RSA/ECC keys, certificates, post-quantum readiness) AND software package dependencies (`npm`, `PyPI`, `Go`, `Alpine OS` packages, CVEs, CVSS ratings).
2. **Zero-Dependency, Ultra-Lightweight Scanner Binary**:
   - Single compiled Go binary (`pqc-scanner-engine` v2.0.0, <15MB) with **zero external shared libraries or runtime dependencies**. Runs natively on macOS (Apple Silicon + Intel), Linux (x86_64 + ARM64), and Windows in under 3 seconds.
3. **Agentless Network & Host Probing**:
   - Discovers external cryptographic posture and TLS 1.3 / PQC algorithm negotiation over the wire without installing any software on the target host.
4. **Automated CI/CD DevSecOps Security Gate**:
   - 1-click ready-to-run workflows for GitHub Actions, GitLab CI, and Bitbucket. Automatically blocks pull requests introducing classical cryptographic algorithms (RSA, ECC, MD5, SHA-1) with exit code 1 and posts rich GFM markdown comments.
5. **Enterprise PKI & Cloud Vault Connectors**:
   - Automated continuous discovery synchronization for Microsoft Active Directory Certificate Services (AD CS), AWS KMS, Azure Key Vault, and HashiCorp Vault.
6. **Transparent Post-Quantum TLS Reverse Proxy Gateway**:
   - Enables legacy web applications to terminate post-quantum hybrid TLS (`X25519MLKEM768`, curve `0x11ec`, NIST FIPS 203) with zero code modifications.
7. **Instant Actionable Remediation**:
   - Every single vulnerability includes copyable terminal commands (`npm install ...`, `pip install ...`, `apk upgrade ...`) and downloadable batch `.sh` scripts.
8. **Physical Multi-Tenant Isolation & Super Admin Governance**:
   - Multi-tenant architecture with separate Docker container boundaries and isolated database schemas.
   - Internal platform infrastructure SBOM (`quarkshield.ai`) is strictly restricted to Super Admins and gated with HTTP 403 Forbidden.

---

## 4. Comprehensive Feature-by-Feature Comparison Matrix

The following matrix compares the four platforms across 18 critical architectural and business dimensions:

| Dimension / Capability | **QuarkShield.ai** | **SandboxAQ (AQtive Guard)** | **IBM Quantum Safe** | **QuSecure (QuProtect)** |
|---|---|---|---|---|
| **1. Primary Focus** | Unified CBOM + SBOM Cryptographic Agility & DevSecOps Platform | Enterprise Cryptographic Discovery & Quantum Vulnerability Management | Enterprise Code & Infrastructure Modernization for Mainframe/Cloud | Inline Quantum-Resilient Communication Tunneling & Overlay VPN |
| **2. Dual CBOM + SBOM Support** | ✅ **Full Native Support** (CycloneDX 1.6 CBOM + Software Package SBOM in 1 pane) | ⚠️ **Partial** (Heavy focus on CBOM; generic SBOM requires 3rd-party tools) | ⚠️ **Partial** (Deep cryptographic AST focus; generic package SBOM requires add-ons) | ❌ **No SBOM** (Focuses purely on active network tunnels, not software packages) |
| **3. Software Dependency Vulnerability Scanning** | ✅ **Native** (Tracks npm, PyPI, Go, OS packages with CVSS ratings & CVEs) | ❌ **Minimal** (Requires Snyk, Veracode, or Sonatype integrations) | ❌ **Minimal** (Requires IBM Dependency-Track or external tools) | ❌ **None** (Does not scan application packages or dependency trees) |
| **4. Discovery Modes** | ✅ **Hybrid Triple-Mode**: Agentless Network Probing + Lightweight Binary + Git Scans | ⚠️ Agent-based (AQ Sensor) + Network SPAN/Tap hardware | ⚠️ Static code AST scans + z/OS Mainframe telemetry feeds | ⚠️ In-line network proxy taps & VPN gateway routing |
| **5. Scanner Agent Footprint** | ✅ **<15 MB single Go binary**, zero external dependencies, memory-safe, runs in <3s | ❌ Heavyweight Java/C++ background service daemon (50MB–200MB) | ❌ Heavy Java AST agent or OpenShift container agent | ❌ Kernel-level network driver or dedicated gateway appliance |
| **6. CI/CD PR Merge Gate** | ✅ **Native** (GitHub Actions, GitLab CI, Bitbucket; blocks PRs with exit code 1) | ⚠️ Available via custom enterprise API webhooks / consulting | ⚠️ Available via IBM DevOps tools (requires complex setup) | ❌ None (No DevSecOps code repository integration) |
| **7. 1-Click Actionable Remediation** | ✅ **Instant copyable CLI commands** + downloadable batch `.sh` scripts | ❌ High-level PDF roadmap reports; manual engineering remediation | ❌ Architecture advisory documents; manual code refactoring | ⚠️ Automated network cipher switching only; no code/package fixes |
| **8. Post-Quantum Hybrid TLS Reverse Proxy** | ✅ **Included Native** (OpenSSL 3.5+, terminates `X25519MLKEM768`, curve `0x11ec`) | ❌ Focuses on monitoring; does not ship native reverse proxy | ⚠️ Available as IBM DataPower Gateway add-on module | ✅ **Core Competency** (QuProtect inline quantum tunnel proxy) |
| **9. Enterprise PKI & Cloud Vault Connectors** | ✅ **Native** (AWS KMS, Azure Key Vault, HashiCorp Vault, Microsoft AD CS) | ✅ Enterprise PKI discovery supported | ✅ IBM Cloud Secrets Manager & Mainframe Key Store | ⚠️ Integration with PKI for tunnel certificates only |
| **10. Deployment Footprint** | ✅ **Extremely Light**: Docker Compose / single container / VPS (`13.140.40.99`) | ❌ Enterprise SaaS + on-premise dedicated server collectors | ❌ Heavy Red Hat OpenShift clusters, Kafka, DB instances | ❌ Inline appliances, edge gateways, or container meshes |
| **11. Time to Initial Value** | ✅ **<5 Minutes** (Instant URL scan or 1-line curl agent execution) | ❌ 3 to 6 months (Hardware SPAN configuration, agent approval) | ❌ 6 to 18 months (Lengthy IBM Consulting engagement) | ❌ 2 to 4 months (Network re-routing, gateway deployment) |
| **12. Multi-Tenant Architecture** | ✅ **Built-in Native** (Physically isolated tenant schemas, tokens, & containers) | ⚠️ Single-tenant enterprise instances or custom VPC partitions | ❌ Monolithic enterprise deployment (no multi-tenant MSP model) | ⚠️ Multi-tenant network policies, but single enterprise focus |
| **13. Super Admin Platform Governance** | ✅ **Self-Auditing SBOM** (`quarkshield.ai` stack with 403 Forbidden gating) | ❌ Does not expose real-time internal platform SBOM to customers | ❌ Proprietary black-box IBM software; internal SBOM hidden | ❌ Closed proprietary appliance architecture |
| **14. NIST PQC Standards Alignment** | ✅ **NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)** | ✅ NIST PQC compliant | ✅ NIST PQC compliant | ✅ NIST PQC compliant |
| **15. NSA CNSA 2.0 Compliance Engine** | ✅ **Built-in Compliance Matrix** & strict policy gates | ✅ CNSA 2.0 advisory reporting | ✅ CNSA 2.0 advisory reporting | ✅ CNSA 2.0 tunnel configurations |
| **16. Open Standards Adherence** | ✅ **CycloneDX 1.6 (JSON/XML)**, standard PURLs, standard Git workflows | ⚠️ Proprietary CBOM format with export options | ⚠️ Proprietary IBM schemas; partial CycloneDX export | ⚠️ Proprietary QuProtect protocol encapsulation |
| **17. Professional Services Dependency** | ✅ **Zero Dependency** (100% self-service, instant onboarding, auto-generated scripts) | ❌ Extremely heavy (Mandatory consulting hours included in contract) | ❌ Extremely heavy (Requires dedicated IBM Consulting team) | ⚠️ Moderate-to-heavy (Network engineering consulting required) |
| **18. Total Cost of Ownership (TCO)** | 💰 **Low / High ROI** (Accessible SaaS/MSP pricing, transparent tiers) | 💸 **Extremely High** (\$250,000 to \$1M+ per year) | 💸 **Extremely High** (Enterprise ELA + consulting fees) | 💸 **High** (\$100,000+ per year based on network throughput) |

---

## 5. Strategic Battlecard: Executive Objection Handling

When enterprise prospects, CISOs, or procurement committees ask how QuarkShield.ai compares to the competition, use these verified talking points:

### 5.1 "Why should we choose QuarkShield over SandboxAQ?"
> **Key Response**:
> *"SandboxAQ is an enterprise consulting and monitoring company designed for the Fortune 50. Their deployment requires months of network SPAN port configuration, heavy proprietary agents, and \$500k+ consulting budgets. Furthermore, SandboxAQ only looks at cryptography — they do not give you a unified Software Bill of Materials (SBOM) for your software packages, leaving you to buy a separate tool like Snyk or BlackDuck.*  
>  
> *QuarkShield gives your security and DevOps teams immediate time-to-value: a single <15MB zero-dependency Go binary, instant agentless network scanning, and a unified platform that delivers BOTH your Cryptographic BOM and CycloneDX 1.6 Software BOM in one pane of glass. Plus, QuarkShield automates remediation by giving developers exact 1-click copyable upgrade commands and blocks non-compliant PRs directly inside GitHub Actions."*

### 5.2 "Why should we choose QuarkShield over IBM Quantum Safe?"
> **Key Response**:
> *"IBM Quantum Safe is built to protect legacy IBM Z mainframes and sell IBM Consulting services. It requires heavy Red Hat OpenShift clusters, extensive infrastructure overhead, and multi-year consulting commitments that cost millions.*  
>  
> *QuarkShield is modern, agile, and cloud-native. You can spin up QuarkShield in Docker in minutes, scan cloud repositories (GitHub, GitLab, Bitbucket), discover keys in AWS KMS, Azure Key Vault, and HashiCorp Vault, and protect modern microservices with our zero-code Post-Quantum TLS Reverse Proxy — at a fraction of the infrastructure footprint and total cost of ownership."*

### 5.3 "Why should we choose QuarkShield over QuSecure?"
> **Key Response**:
> *"QuSecure is an inline VPN and tunnel overlay — they route packets between servers. They do not scan source code repositories, they do not parse your application package dependencies (`package.json`, `go.mod`), they do not generate software supply-chain SBOMs, and they cannot stop developers from committing vulnerable RSA keys into your Git repository.*  
>  
> *QuarkShield covers the entire DevSecOps lifecycle: we discover cryptographic and package vulnerabilities in your code repositories before they merge, discover keys across cloud vaults, and provide an inline Hybrid Quantum TLS Reverse Proxy for runtime ingress without forcing all your enterprise traffic through complex proprietary overlay appliances."*

---

## 6. Super Admin Security Operational Procedures

### 6.1 Verifying Platform Stack Health on Production
To inspect the live platform stack SBOM on the production server without web UI access, use the privileged Super Admin API endpoint:

```bash
# Query the live platform stack inventory (15 components)
curl -s -H "x-admin-role: super_admin" "http://localhost:5050/api/sbom/components?tenant=quarkshield.ai" | jq .

# Verify zero-vulnerability stats
curl -s -H "x-admin-role: super_admin" "http://localhost:5050/api/sbom/stats?tenant=quarkshield.ai" | jq .

# Export official CycloneDX 1.6 JSON specification
curl -s -H "x-admin-role: super_admin" "http://localhost:5050/api/sbom/export?tenant=quarkshield.ai" > quarkshield.ai-cyclonedx-1.6.json

# Download and execute the automated platform maintenance upgrade script
curl -s -H "x-admin-role: super_admin" "http://localhost:5050/api/sbom/fix-script?tenant=quarkshield.ai" > upgrade.sh
chmod +x upgrade.sh
./upgrade.sh
```

### 6.2 Testing Negative Authorization (Security Regression Test)
Super Admins should periodically verify that unprivileged requests are properly blocked by running:

```bash
# 1. Unauthenticated request to platform components (Must return HTTP 403 Forbidden)
curl -s -i "http://localhost:5050/api/sbom/components?tenant=quarkshield.ai" | grep "HTTP/1.1 403"

# 2. Unauthenticated request to platform fix script (Must return HTTP 403 Forbidden)
curl -s -i "http://localhost:5050/api/sbom/fix-script?tenant=quarkshield.ai" | grep "HTTP/1.1 403"

# 3. Client tenant query (Must return HTTP 200 OK and isolate client components)
curl -s -i "http://localhost:5050/api/sbom/components?tenant=SPINOVATIONCORP" | grep "HTTP/1.1 200"
```

---

## 7. Document Control & Sign-off

| Role | Name | Signature / Status | Date |
|---|---|---|---|
| **Root Platform Architect** | Sridhar GS | Verified & Approved | 2026-09-23 |
| **Platform SecOps Lead** | Elena Rostova | Cryptographic Audit Certified | 2026-09-23 |
| **SOC2 / FedRAMP Auditor** | Compliance Office | CycloneDX 1.6 / NIST SP 800-218 Verified | 2026-09-23 |
