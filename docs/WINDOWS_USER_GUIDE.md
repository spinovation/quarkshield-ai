# QuarkShield Post-Quantum Guard: Windows User Guide & Operations Manual

![QuarkShield Platform](https://quarkshield.ai/quarkshield-logo.png)

> **Document Version:** 2.1.0  
> **Target Audience:** IT Administrators, Security Engineers, DevOps, Compliance Officers, and Windows End Users  
> **Platform:** Windows 10, Windows 11, Windows Server 2016 / 2019 / 2022 (x86_64 / amd64)  
> **Publisher:** FedMitigate LLC — Washington, D.C.  
> **Central Console:** [https://quarkshield.ai](https://quarkshield.ai)  

---

## Table of Contents
1. [Introduction & Threat Context](#1-introduction--threat-context)
2. [Download Locations & Package Formats](#2-download-locations--package-formats)
3. [Installation & Windows Security Trust Setup](#3-installation--windows-security-trust-setup)
4. [What Assets QuarkShield Audits on Windows & The Zero-Exfiltration Guarantee](#4-what-assets-quarkshield-audits-on-windows--the-zero-exfiltration-guarantee)
5. [Scan Operations Explained](#5-scan-operations-explained)
   - [Quick Scan Workstation](#quick-scan-workstation)
   - [Custom Path Scan & Quick Targets](#custom-path-scan--quick-targets)
   - [Remote TLS Handshake Auditor (Probe TLS)](#remote-tls-handshake-auditor-probe-tls)
6. [Reading & Interpreting Audit Results](#6-reading--interpreting-audit-results)
7. [Exporting CBOM (CycloneDX 1.6) & Audit JSON](#7-exporting-cbom-cyclonedx-16--audit-json)
8. [Connecting & Synchronizing with QuarkShield Cloud Fleet](#8-connecting--synchronizing-with-quarkshield-cloud-fleet)
9. [Automated Enterprise & MDM Deployment (Intune / SCCM / Group Policy)](#9-automated-enterprise--mdm-deployment-intune--sccm--group-policy)
10. [Preparing for Microsoft OS-Level PQC Trust Roots (Windows 11, Server 2025 & Azure)](#10-preparing-for-microsoft-os-level-pqc-trust-roots-windows-11-server-2025--azure)
11. [Uninstallation & Troubleshooting](#11-uninstallation--troubleshooting)

---

## 1. Introduction & Threat Context

**QuarkShield Post-Quantum Guard for Windows** is an enterprise-grade cryptographic discovery and posture assessment agent. It automatically inventories cryptographic keys, certificates, signature mechanisms, and cipher suites across your Windows workstation or server, evaluating them against quantum cryptanalysis threats.

### The Threat: Harvest Now, Decrypt Later (HNDL)
Adversaries and nation-state threat actors are actively intercepting and storing encrypted data today. When cryptanalytically relevant quantum computers (CRQCs) arrive, **Shor's Algorithm** will instantaneously break all classical asymmetric cryptography:
- **RSA** (1024, 2048, 3072, 4096-bit)
- **Elliptic Curve Cryptography** (ECDSA, ECDH, Ed25519, Curve25519)
- **Diffie-Hellman & DSA**

QuarkShield audits your local cryptographic landscape and validates readiness against the newly finalized **NIST Post-Quantum Cryptography (PQC) Standards**:
- **FIPS 203:** Module-Lattice-Based Key-Encapsulation Mechanism (**ML-KEM** / Kyber)
- **FIPS 204:** Module-Lattice-Based Digital Signature Algorithm (**ML-DSA** / Dilithium)
- **FIPS 205:** Stateless Hash-Based Digital Signature Algorithm (**SLH-DSA** / SPHINCS+)
- **NSA CNSA 2.0:** Commercial National Security Algorithm Suite mandates

---

## 2. Download Locations & Package Formats

All official Windows packages are signed by **FedMitigate LLC** via **Microsoft Azure Trusted Signing** and hosted directly on the QuarkShield production infrastructure:

| Package | Filename | Download URL | Description |
| :--- | :--- | :--- | :--- |
| **Standalone 64-bit EXE** | `quarkshield-scanner-windows-amd64.exe` | [Download EXE](https://quarkshield.ai/downloads/quarkshield-scanner-windows-amd64.exe) | Single executable with embedded Web GUI and CLI engines. |
| **Complete ZIP Distribution** | `quarkshield-scanner-windows.zip` | [Download ZIP](https://quarkshield.ai/downloads/quarkshield-scanner-windows.zip) | Includes executable, desktop icon (`app_icon.ico`), uninstaller (`uninstall.bat`), and trust scripts. |
| **Legacy Compatibility Alias** | `pqc-scanner-windows-amd64.exe` | [Download Legacy EXE](https://quarkshield.ai/downloads/pqc-scanner-windows-amd64.exe) | Legacy naming alias for existing CI/CD automation pipelines. |

### Verifying File Authenticity
You can verify the Authenticode signature of the downloaded `.exe` in PowerShell:
```powershell
Get-AuthenticodeSignature .\quarkshield-scanner-windows-amd64.exe | Format-List
```
**Expected Signer Information:**
- **Status:** `Valid`
- **Signer Certificate:** `CN=Fedmitigate LLC, O=Fedmitigate LLC, L=Sheridan, ST=Wyoming, C=US`
- **Issuer:** `CN=Microsoft ID Verified CS EOC CA 03, O=Microsoft Corporation, C=US`
- **Timestamp Authority:** `Microsoft Public RSA Timestamping CA 2020`

---

## 3. Installation & Windows Security Trust Setup

QuarkShield does not require complex installations or intrusive kernel drivers. It runs as a self-contained, unprivileged background service paired with an intuitive local web interface.

### Option 1: 1-Click Launch (Recommended)
1. Download `quarkshield-scanner-windows.zip` and extract it to a folder of your choice (e.g., `C:\Program Files\QuarkShield` or your User folder).
2. Double-click **`quarkshield-scanner-windows-amd64.exe`**.
3. QuarkShield will:
   - Start the local audit daemon on loopback port `48291` (`http://127.0.0.1:48291`).
   - Automatically open the interactive **Post-Quantum Guard for Windows** dashboard in your default browser (Chrome, Edge, Firefox).
   - Create convenient Desktop and Start Menu shortcuts.

### Option 2: PowerShell One-Liner (Automated Download & Run)
Open PowerShell as Administrator or regular user and execute:
```powershell
Invoke-WebRequest -Uri "https://quarkshield.ai/downloads/quarkshield-scanner-windows-amd64.exe" -OutFile "$env:TEMP\quarkshield-scanner.exe"
& "$env:TEMP\quarkshield-scanner.exe"
```

### Option 3: Enterprise Trust Configuration (`Trust-FedMitigate.ps1` / `.bat`)
If your organization enforces strict Windows Defender SmartScreen or AppLocker policies for newly downloaded executables:
1. Right-click **`Trust-FedMitigate.ps1`** (included in the ZIP package) and select **Run with PowerShell** (or run as Administrator).
2. The script installs the FedMitigate Root and Code Signing certificates into your workstation's **Trusted Publishers** store:
```powershell
.\Trust-FedMitigate.ps1
```
3. Once completed, Windows Defender and SmartScreen will automatically authorize QuarkShield binaries without prompting.

---

## 4. What Assets QuarkShield Audits on Windows & The Zero-Exfiltration Guarantee

QuarkShield deeply inspects both file-system assets and Windows native cryptographic stores:

### 1. Windows Certificate Store (CAPI / CNG)
- **Current User Stores:** `Cert:\CurrentUser\My` (Personal), `Root` (Trusted Roots), `CA` (Intermediate Authorities), `Trust` (Enterprise Trust).
- **Local Machine Stores:** `Cert:\LocalMachine\My`, `Root`, `CA`, `Remote Desktop`, `WebHosting`.
- Audits certificate algorithms, public key lengths (e.g., RSA-1024, RSA-2048, RSA-4096, ECC P-256), signature algorithms (SHA1withRSA, SHA256withRSA, ECDSA), and expiration timestamps.

### 2. Developer & Administrator Credentials
- **OpenSSH for Windows:** `C:\Users\<User>\.ssh\` (`id_rsa`, `id_ecdsa`, `id_ed25519`, `config`, `authorized_keys`, `known_hosts`).
- **System OpenSSH Service:** `C:\ProgramData\ssh\` (`ssh_host_rsa_key`, `ssh_host_ecdsa_key`, `sshd_config`).
- **Git Credential Helpers:** `.gitconfig`, embedded private keys, and repository signing identities.
- **GnuPG / GPG Keys:** `C:\Users\<User>\AppData\Roaming\gnupg\` (`pubring.kbx`, `trustdb.gpg`).

### 3. Application & Server Keystores
- **Java Keystores:** `cacerts`, `.jks`, `.keystore` files used by Tomcat, Spring Boot, Jenkins, Elasticsearch, and Oracle Java.
- **IIS & Web Server Certificates:** `.pfx`, `.p12`, `.pem`, `.crt`, `.cer` files in web roots and staging directories.
- **VPN & Tunnel Configurations:** WireGuard, OpenVPN (`.ovpn`), and IPsec configurations.

### 4. Binary & Library Signatures
- Evaluates cryptographic signatures on installed DLLs and executables in `C:\Program Files` and `C:\Windows\System32` to detect deprecated SHA-1 or broken RSA-1024 code-signing certificates.

### 5. Understanding "Keys" in QuarkShield & The Zero-Exfiltration Guarantee

In QuarkShield's dashboards and CBOM inventory, **"Keys"** refers exclusively to **Cryptographic Assets and Public Algorithm Primitives**—specifically:
- **Public Certificates:** X.509 certificates and root CA chains in Windows CAPI/CNG.
- **Asymmetric Key Parameters:** RSA public moduli (2048/4096-bit), Elliptic Curve public points and curve names (secp256r1/P-256, secp384r1/P-384, Ed25519).
- **Host Identities & Cipher Suites:** SSH public host keys and TLS cipher configurations.

> **CRITICAL SECURITY PROMISE: Zero-Exfiltration Guarantee**  
> QuarkShield operates strictly on a **local-in-RAM inspection model**:
> - **Private Keys Are NEVER Exfiltrated:** Private key files (`BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`, PKCS#8), passphrases, seed material, or decrypted plaintexts are **NEVER captured, stored, uploaded, or transmitted** to any remote server.
> - **Volatile Memory Execution:** File and certificate parsing takes place strictly inside temporary local volatile RAM. As soon as public cryptographic metadata (algorithm name, bit length, validity dates, issuer DN) is extracted, working memory is cleared.
> - **Privacy-Preserving Telemetry:** Telemetry synchronized with the QuarkShield Cloud Fleet contains solely non-sensitive public metadata structured according to the CycloneDX 1.6 CBOM standard.

---

### 6. Quantum Vulnerability of Discovered Keys: Shor's Algorithm

Virtually all keys discovered on Windows today rely on classical asymmetric mathematics:
- **RSA Factorization:** RSA-2048 and RSA-4096 rely on prime integer factorization. Shor's algorithm running on a Cryptanalytically Relevant Quantum Computer (CRQC) solves prime factorization in polynomial time ($O((\log N)^3)$).
- **Elliptic Curve Collapse (~2,300 Logical Qubits):** Windows CNG and SSH credentials frequently rely on ECDSA (P-256) and Ed25519. Because elliptic curve groups are much smaller than RSA moduli, **ECC collapses even faster on quantum hardware—requiring only ~2,300 logical qubits** compared to ~4,096 for RSA-2048.

---

## 5. Scan Operations Explained

When you access the QuarkShield GUI (`http://127.0.0.1:48291`), you have three primary audit capabilities:

### ⚡ Quick Scan Workstation
- **Purpose:** Fast, non-intrusive evaluation of your machine's primary attack surface.
- **Execution Time:** Typically completes in **3 to 10 seconds**.
- **Scope:**
  - Audits all Windows Personal and Trusted Root certificate stores (`Cert:\CurrentUser` and `Cert:\LocalMachine`).
  - Scans user SSH keys (`%USERPROFILE%\.ssh`).
  - Scans system SSH configuration (`%ALLUSERSPROFILE%\ssh`).
  - Evaluates developer credentials and environment keystores.
- **How to Run:** Click the large cyan **⚡ Quick Scan Workstation** button on the dashboard.

### 📁 Custom Path Scan & Quick Targets
- **Purpose:** Deep recursive audit of specific folders, project source code, shared network drives, or backup repositories.
- **Quick Target Presets:**
  - 💻 **`Drive C:\`** — Audits the primary drive.
  - 📁 **`C:\Users`** — Audits all user profiles, desktop files, downloads, and app data.
  - 🛡️ **`C:\Windows`** — Audits system certificates, driver catalogs, and security configurations.
  - 📦 **`C:\Program Files`** — Audits installed third-party software, Java runtimes, and local web servers.
- **Native Windows Folder Dialog:** Click **📂 Browse Folder...** to open the native Windows Explorer folder picker. If the dialog opens behind the browser, click the folder icon on your taskbar or press <kbd>Alt</kbd> + <kbd>Tab</kbd>.
- **How to Run:**
  1. Click **📁 Custom Path Scan**.
  2. Click any Quick Target preset chip or type a custom path (e.g., `D:\SourceCode\MyProject`).
  3. Click **⚡ Audit Path**.

### 🌐 Remote TLS Handshake Auditor (Probe TLS)
- **Purpose:** Active assessment of any public or internal domain, API endpoint, or web server for Post-Quantum TLS 1.3 readiness.
- **Outbound Connection Disclosure:**
  - QuarkShield initiates a **direct outbound TCP socket connection on port 443** from your machine to the target server.
  - **Zero Payload Guarantee:** No HTTP headers, data payloads, cookies, or credentials are sent or inspected. Only the public cryptographic TLS handshake is audited.
- **Evaluated Parameters:**
  - **Negotiated Key Exchange:** Identifies whether the endpoint supports hybrid post-quantum key exchange (such as `X25519Kyber768Draft00` or standardized `ML-KEM-768`) vs classical `ECDHE_RSA` or `ECDHE_ECDSA`.
  - **TLS Protocol Version:** TLS 1.3 (quantum-ready architecture) vs TLS 1.2 / 1.1 / 1.0.
  - **Cipher Suite:** Evaluates AEAD ciphers (`AES_256_GCM`, `CHACHA20_POLY1305`).
  - **Leaf & Intermediate Certificates:** Audits public key algorithms, signature algorithms, and certificate validity.
- **How to Run:**
  1. Click **🌐 Probe TLS / Endpoint**.
  2. Enter any URL or domain (e.g., `cloudflare.com`, `google.com`, or `internal-api.corp.local`).
  3. Check the authorization checkbox and click **Scan Endpoint**.
  4. A detailed cryptographic handshake card will appear showing quantum vulnerability status and cipher negotiation details.

---

## 6. Reading & Interpreting Audit Results

After an audit completes, QuarkShield displays an interactive posture breakdown:

### Executive Status Heading
- **Protected / Quantum Ready (Green):** All discovered cryptographic assets use post-quantum algorithms (e.g., ML-KEM, ML-DSA) or quantum-resilient symmetric encryption (AES-256).
- **Vulnerabilities Detected (Red/Orange):** Classical asymmetric algorithms identified that are vulnerable to Shor's Algorithm.

### Vulnerability Severity Breakdown
| Risk Level | Color | Criteria & Cryptographic Algorithms |
| :--- | :--- | :--- |
| **CRITICAL** | 🔴 Red | Sub-2048-bit RSA (e.g., RSA-1024), legacy DSA, MD5/SHA-1 signatures, expired certificates. Classically insecure today. |
| **HIGH** | 🟠 Orange | RSA-2048, RSA-3072, RSA-4096, ECDSA P-256, ECDSA P-384, Ed25519. Vulnerable to Harvest Now, Decrypt Later (HNDL) and Shor's Algorithm. |
| **MEDIUM** | 🟡 Yellow | Deprecated TLS protocol versions (TLS 1.0, TLS 1.1), SHA-256 certificates expiring within 30 days. |
| **LOW / INFO** | 🔵 Blue | Informational configuration items, self-signed test certificates in non-production stores. |
| **PQC READY** | 🟢 Green | NIST FIPS 203 (ML-KEM/Kyber), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), stateful hash-based signatures (LMS/XMSS). |

### Actionable Remediation Guidance
Each finding provides an **Actionable Remediation** step:
- **RSA-2048/4096 Keys:** Replace with NIST FIPS 203 (ML-KEM-768 / Kyber) for key encapsulation or NIST FIPS 204 (ML-DSA-65) for digital signatures.
- **OpenSSH Keys:** Upgrade to OpenSSH 9.0+ and generate hybrid post-quantum keys using `ssh-keygen -t sntrup761x25519-sha512@openssh.com`.
- **Web Certificates:** Transition to hybrid PQC certificates or dual-certificate authentication chains conforming to NSA CNSA 2.0 timelines.

---

## 7. Exporting CBOM (CycloneDX 1.6) & Audit JSON

To comply with federal mandates (EO 14028, OMB M-23-02) and enterprise governance, QuarkShield exports standardized **Cryptographic Bill of Materials (CBOM)**:

### In the Web GUI
1. In the upper right corner of the dashboard or in the Audit Results header, click **💾 Export JSON** or **Export CBOM (CycloneDX)**.
2. A JSON file containing the full structured cryptographic inventory will be saved to your `Downloads` folder.

### Via Command Line
You can export results directly from PowerShell or Command Prompt:
```powershell
# Output human-readable CLI summary
.\quarkshield-scanner-windows-amd64.exe --quick

# Export raw JSON inventory
.\quarkshield-scanner-windows-amd64.exe --quick --json > cbom-audit.json

# Scan a specific folder and output JSON
.\quarkshield-scanner-windows-amd64.exe --path "C:\inetpub\wwwroot" --json > web-cbom.json
```

---

## 8. Connecting & Synchronizing with QuarkShield Cloud Fleet

To aggregate cryptographic posture data across hundreds or thousands of enterprise workstations into a single executive dashboard:

### Method 1: Using the Interactive GUI
1. In the top navigation bar of QuarkShield, click **🌐 Connect to Fleet**.
2. A synchronization modal will open:
   - **Central Management URL:** `https://quarkshield.ai` (default)
   - **Enterprise Fleet Token:** Paste the enrollment token provided by your QuarkShield administrator or generated in the Admin Console.
3. Click **Transmit & Sync**.
4. Telemetry, machine hostname, IP address, and all cryptographic findings will be securely ingested into QuarkShield Central.

### Method 2: Via PowerShell / Command Line
```powershell
.\quarkshield-scanner-windows-amd64.exe `
  --server "https://quarkshield.ai" `
  --token "YOUR_FLEET_ENROLLMENT_TOKEN" `
  --register `
  --quick
```

---

## 9. Automated Enterprise & MDM Deployment (Intune / SCCM / Group Policy)

System administrators can deploy QuarkShield across an entire corporate fleet silently without requiring end-user interaction.

### Microsoft Intune / SCCM Deployment Package
1. **Packaging:** Create a standard `.intunewin` package containing `quarkshield-scanner-windows-amd64.exe`.
2. **Install Command (Silent):**
```cmd
quarkshield-scanner-windows-amd64.exe --server "https://quarkshield.ai" --token "YOUR_ENROLLMENT_TOKEN" --register --quick --silent
```
3. **Detection Rule:** Check for the existence of `C:\ProgramData\QuarkShield\agent.id` or registry key `HKLM:\SOFTWARE\FedMitigate\QuarkShield`.

### Windows Scheduled Task (Daily Continuous Audit)
To run a daily automated background posture audit:
```powershell
$Action = New-ScheduledTaskAction -Execute "C:\Program Files\QuarkShield\quarkshield-scanner-windows-amd64.exe" -Argument "--server https://quarkshield.ai --token YOUR_TOKEN --quick"
$Trigger = New-ScheduledTaskTrigger -Daily -At 3:00AM
Register-ScheduledTask -TaskName "QuarkShield-PQCAudit" -Action $Action -Trigger $Trigger -User "SYSTEM"
```

### Enterprise Non-Root / Zero-Reboot Alternative: OpenTelemetry (OTel) Collector & CAPI2
For enterprise environments seeking non-intrusive cryptographic visibility without dedicated host agent overhead:
- **Zero-Reboot Telemetry**: Use your existing **OpenTelemetry (OTel) Collector** to stream cryptographic events directly from the `Microsoft-Windows-CAPI2/Operational` event log to QuarkShield.
- **Unprivileged Execution**: Runs securely as `NT AUTHORITY\LOCAL SERVICE` with zero kernel drivers and 0% risk of system reboot.
- **Detailed Blueprint**: See the [QuarkShield Enterprise Post-Quantum Cryptographic Deployment Guide](ENTERPRISE_AGENT_DEPLOYMENT_GUIDE.md) for ready-to-use `otel-collector-pqc.yaml` configurations and AD CS PowerShell connectors.

---

## 10. Preparing for Microsoft OS-Level PQC Trust Roots (Windows 11, Server 2025 & Azure)

Microsoft is transitioning Windows and Azure security infrastructures toward post-quantum cryptography under NIST FIPS 203/204/205 and NSA CNSA 2.0:
- **Windows CNG & Schannel:** Windows 11 and Windows Server 2025 are adding native Cryptography Next Generation (CNG) algorithm providers for `ML-KEM` key exchange and `ML-DSA` signature validation.
- **Azure Trusted Signing:** Cloud-based code-signing pipelines are incorporating hybrid signatures combining Authenticode RSA/ECC with post-quantum lattice signatures.
- **Root Store Deprecation:** Microsoft's Root Certificate Program will begin enforcing PQC trust anchors, progressively flagging classical RSA-2048/SHA-256 certificates with deprecation warnings in Windows Event Logs and SmartScreen.

### Recommended Customer Action Plan:
1. **Continuous CBOM Discovery:** Deploy QuarkShield across your Windows domain via Microsoft Intune, SCCM, or Group Policy to discover every certificate in `Cert:\LocalMachine` and `Cert:\CurrentUser`.
2. **Audit Active Directory Certificate Services (AD CS):** Plan the transition of your internal enterprise CA templates from classical RSA to hybrid or ML-DSA templates.
3. **Enable Hybrid Schannel / IIS TLS:** Configure Windows Server IIS instances and Azure Application Gateways to negotiate hybrid `X25519MLKEM768` TLS 1.3 handshakes.
4. **Transition Authenticode Signing Pipelines:** Adopt Azure Trusted Signing or hybrid signing tools to sign internal and commercial executables (`.exe`, `.dll`, `.msi`) with dual classical + PQC signatures.
5. **Set Up Automated Drift Governance:** Utilize QuarkShield's Cloud Fleet plane to alert security teams when endpoints or developer environments introduce legacy, non-compliant keys.

---

## 11. Uninstallation & Troubleshooting

### How to Uninstall
- **Via GUI (1-Click):** Click the red **🗑️ Uninstall** button in the top navigation bar. QuarkShield will prompt for confirmation, terminate its background service, delete Windows shortcuts, and clean up local files.
- **Via Script:** Double-click **`uninstall.bat`** (included in the ZIP package) or run:
```cmd
uninstall.bat
```
- **Manual Removal:** Delete the folder containing `quarkshield-scanner-windows-amd64.exe` and remove Desktop/Start Menu shortcuts.

### Troubleshooting Common Issues
| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **Port 48291 in use** | Another instance or process is using port 48291. | QuarkShield automatically attempts ports 48292-48295. Look at the console output for the assigned URL. |
| **SmartScreen warning** | Binary was downloaded via browser without local trust installed. | Click "More info" &rarr; "Run anyway", or run `Trust-FedMitigate.ps1` as Administrator. |
| **Cannot connect to Fleet** | Outbound HTTPS (port 443) blocked by corporate proxy. | Ensure outbound traffic to `https://quarkshield.ai` is allowed through your corporate firewall or proxy. |

---

### Technical Support & Enterprise Contact
- **Documentation & Portal:** [https://quarkshield.ai](https://quarkshield.ai)
- **Enterprise Support:** `support@quarkshield.ai`
- **Publisher:** FedMitigate LLC | Washington, D.C.
