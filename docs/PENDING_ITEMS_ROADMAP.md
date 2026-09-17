# 📋 QuarkShield PQC — Pending Items & Strategic Feature Backlog

**Status:** Official Backlog Registry  
**Current Focus:** Finalizing the 100% foolproof Desktop / Host Agent (Windows, licensing, TLS prober) before triggering Phase 2 items.

---

## 📌 The Pending Items List

### 1. Remote Git Repository & DevOps Connectors (GitHub, GitLab, Bitbucket, Azure DevOps)
* **Origin**: User request to audit source code repositories and CI/CD pipelines via user ID, API keys, or Personal Access Tokens (PAT).
* **Scope**:
  * **Option A (Central Cloud Platform - Wiz Model Pillar 3)**:
    * Organization-level OAuth and App Connectors in `quarkshield.ai` / `quarkshield.ai` under **"Integrations"**.
    * Automatic scanning of 100+ repositories simultaneously for hardcoded PEM, DER, private keys, SSH deploy keys, and cryptographic dependency manifests (`pom.xml`, `package.json`, `go.mod`).
    * Pre-commit and pull-request cryptographic security gates.
  * **Option B (Desktop Agent Feature)**:
    * A **"Clone & Audit Git URL"** dropdown / tab in the desktop GUI where a user inputs a repository URL + token.
    * The desktop agent performs an ephemeral shallow clone (`git clone --depth 1`), scans the repository, generates findings, and immediately wipes the temporary clone.
* **Current Status**: **PENDING (Phase 2)** — Queued until desktop host agent reaches production maturity.

---

### 2. Spring Boot PQC Remediation Library & Developer Playbooks (`PqcStarterLib`)
* **Origin**: User request to research [PqcStarterLib](https://github.com/catallicpankaj/pqc-starter-lib) for abstracting quantum-safe algorithms into standard, autoconfigured Spring Boot beans.
* **Scope**:
  * **Bridging Discovery to Remediation**:
    * QuarkShield answers *"Where are the vulnerable cryptographic assets in our code?"* (Discovery / CBOM).
    * `PqcStarterLib` provides the remediation answer: *"How do developers fix them in Java / Spring Boot?"*.
  * **Key Capabilities to Integrate**:
    1. **NIST FIPS 203/204/205 Real Algorithms**: Bouncy Castle-backed autoconfigured beans for ML-KEM (Kyber-768), ML-DSA (Dilithium-3), and SLH-DSA (SPHINCS+).
    2. **Hybrid Handshake Orchestration**: $\text{HKDF}(\text{ECDHE-P384} \parallel \text{Kyber-768})$ for zero-risk backward compatibility.
    3. **Quantum-Safe JWT**: Replacing vulnerable RS256/ES256 tokens with Dilithium-3 signed JWTs (`DilithiumJwtFilter`).
    4. **Canary RSA-to-PQC Migration Bridge**: Microservice traffic routing (`RSA_ONLY` $\rightarrow$ `BRIDGE` with canary percentage $\rightarrow$ `PQC_ONLY`).
    5. **QuarkShield Java SDK & Automated Playbooks**: Generating 1-click remediation code snippets directly inside the QuarkShield CBOM findings table when a Java/Spring service is flagged.
* **Current Status**: **PENDING (Phase 2)** — Architecture researched; implementation deferred until desktop discovery engine is locked down.

---

### 3. Cross-Platform Parity: macOS & Linux Native Scanners
* **Origin**: User request: *"Although we have windows scanner, we also need one for Mac and Linux, once we have the Windows version fully trustable"*.
* **Scope**:
  * **macOS Scanner**:
    * Audit native Apple Keychain Services (`/Library/Keychains/System.keychain`, `~/Library/Keychains/login.keychain-db`).
    * SecTrustStore inspection for deprecated root CAs.
    * Jamf Pro REST API connector for fleet-wide deployment.
  * **Linux Scanner**:
    * OpenSSL Trust Store (`/etc/ssl/certs`, `/etc/pki/tls/certs`) and NSS databases (`~/.pki/nssdb`).
    * Linux systemd service crypto configurations and SSH host key compliance.
* **Current Status**: **PENDING (Phase 2)** — Pre-compiled binaries exist (`quarkshield-scanner-darwin-arm64`, `darwin-amd64`, `linux-amd64`); deep OS store auditing will be expanded following Windows validation.

---

### 4. Cloud Fleet Multi-Tenant Port & Database Isolation (Matching `quarkshield.ai`)
* **Origin**: User architectural requirement: *"every tenant will have their own database and port (same as Quarkshield.services)"*.
* **Scope**:
  * Dedicated PostgreSQL database per client tenant (`pqc_tenant_<tenant_id>`).
  * Dynamic dedicated internal port routing (`5100+N`, `5433+N`, `4100+N`).
  * Admin panel license synchronization ensuring corporate and partner keys route desktop telemetry to the correct isolated tenant enclave.
* **Current Status**: **ACTIVE / IN-PROGRESS** — Architecture designed, schema implemented, license controller generated.

---

## 🎯 Current Phase 1 Deliverables in Progress
1. ✅ **Windows Full-Drive & Quick Scanner**: 1,811 assets audited across Shor's, Grover's, and HNDL categories.
2. ✅ **One-Click CBOM Filter Tabs & Clickable Metric Cards**: Deployed live on production.
3. ✅ **7-Day Default Offline Trial & HMAC License Engine**: Implemented and verified in `license.go`.
4. ✅ **Active Outbound TCP/TLS Socket Prober (e.g. `microsoft.com`)**: Specification documented in `ACTIVE_NETWORK_TLS_PQC_PROBING.md`.
