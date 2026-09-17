# QuarkShield Post-Quantum Guard: macOS User Guide & Operations Manual

![QuarkShield Platform](https://quarkshield.ai/quarkshield-logo.png)

> **Document Version:** 2.1.0  
> **Target Audience:** Mac Users, Security Engineers, Enterprise Mac Admins (Jamf/Kandji/Munki), DevOps, and Compliance Teams  
> **Platform:** macOS Sonoma (14.x), macOS Sequoia (15.x), macOS Ventura (13.x), macOS Monterey (12.x)  
> **Architecture:** Universal Mach-O (Apple Silicon M1/M2/M3/M4 & Intel x86_64)  
> **Code Signing:** Developer ID Application: Ganapati Sridhar (4ADVSK467Z)  
> **Central Console:** [https://quarkshield.ai](https://quarkshield.ai)  

---

## Table of Contents
1. [Introduction & Threat Context](#1-introduction--threat-context)
2. [Download Locations & Package Formats](#2-download-locations--package-formats)
3. [Installation & macOS Security Trust Setup](#3-installation--macos-security-trust-setup)
4. [What Assets QuarkShield Audits on macOS](#4-what-assets-quarkshield-audits-on-macos)
5. [Scan Operations Explained](#5-scan-operations-explained)
   - [Quick Scan Workstation](#quick-scan-workstation)
   - [Custom Path Scan & macOS Quick Targets](#custom-path-scan--macos-quick-targets)
   - [Remote TLS Handshake Auditor (Probe TLS)](#remote-tls-handshake-auditor-probe-tls)
6. [Reading & Interpreting Audit Results](#6-reading--interpreting-audit-results)
7. [Exporting CBOM (CycloneDX 1.6) & Audit JSON](#7-exporting-cbom-cyclonedx-16--audit-json)
8. [Connecting & Synchronizing with QuarkShield Cloud Fleet](#8-connecting--synchronizing-with-quarkshield-cloud-fleet)
9. [Enterprise Mac Fleet Deployment (Jamf / Kandji / Munki)](#9-enterprise-mac-fleet-deployment-jamf--kandji--munki)
10. [Uninstallation & Troubleshooting](#10-uninstallation--troubleshooting)

---

## 1. Introduction & Threat Context

**QuarkShield Post-Quantum Guard for Mac** is a dedicated cryptographic discovery, vulnerability auditing, and CBOM generation agent engineered specifically for the macOS ecosystem. It audits local macOS keychains, developer certificates, SSH configurations, and application bundles to identify algorithms vulnerable to quantum decryption.

### The Threat: Harvest Now, Decrypt Later (HNDL)
Threat actors are actively harvesting encrypted intellectual property, Git repositories, and proprietary communications today. Once a Cryptanalytically Relevant Quantum Computer (CRQC) is realized, **Shor's Algorithm** will break:
- **RSA** (1024, 2048, 3072, 4096-bit)
- **Elliptic Curve Cryptography** (ECDSA P-256 / P-384, Ed25519)
- **Diffie-Hellman / DSA**

QuarkShield evaluates your Mac against the newly finalized **NIST Post-Quantum Cryptography Standards**:
- **FIPS 203:** Module-Lattice-Based Key-Encapsulation Mechanism (**ML-KEM** / Kyber)
- **FIPS 204:** Module-Lattice-Based Digital Signature Algorithm (**ML-DSA** / Dilithium)
- **FIPS 205:** Stateless Hash-Based Digital Signature Algorithm (**SLH-DSA** / SPHINCS+)
- **NSA CNSA 2.0:** Commercial National Security Algorithm Suite mandates

---

## 2. Download Locations & Package Formats

Official macOS packages are hosted on `quarkshield.ai` and signed with an official Apple Developer ID certificate:

| Package | Filename | Download Link | Description |
| :--- | :--- | :--- | :--- |
| **Apple Disk Image (DMG)** | `QuarkShield-macOS.dmg` | [Download DMG](https://quarkshield.ai/downloads/QuarkShield-macOS.dmg) | Standard macOS installer volume with drag-and-drop `/Applications` install and 1-click trust scripts. |
| **Portable App Bundle (ZIP)** | `quarkshield-scanner-macos.zip` | [Download ZIP](https://quarkshield.ai/downloads/quarkshield-scanner-macos.zip) | Portable `.zip` archive containing `QuarkShield.app`, `Trust-QuarkShield.command`, and documentation. |
| **Universal CLI Binary** | `quarkshield-scanner-darwin-universal` | [Download Universal CLI](https://quarkshield.ai/downloads/quarkshield-scanner-darwin-universal) | Single Mach-O binary containing slices for both Apple Silicon (`arm64`) and Intel (`x86_64`). |
| **Apple Silicon CLI** | `quarkshield-scanner-darwin-arm64` | [Download arm64 CLI](https://quarkshield.ai/downloads/quarkshield-scanner-darwin-arm64) | Optimized headless binary for M1, M2, M3, and M4 Macs. |
| **Intel x86_64 CLI** | `quarkshield-scanner-darwin-amd64` | [Download amd64 CLI](https://quarkshield.ai/downloads/quarkshield-scanner-darwin-amd64) | Headless binary for Intel-based Macs. |
| **macOS Trust Assistant** | `Trust-QuarkShield.command` | [Download Trust Script](https://quarkshield.ai/downloads/Trust-QuarkShield.command) | Standalone script to authorize QuarkShield with Gatekeeper and clear quarantine flags. |

### Verifying Digital Signatures
To verify the digital signature of `QuarkShield.app` or `QuarkShield-macOS.dmg`:
```bash
codesign -dvvv /Applications/QuarkShield.app
```
**Expected Output:**
- **Authority:** `Developer ID Application: Ganapati Sridhar (4ADVSK467Z)`
- **Authority:** `Developer ID Certification Authority`
- **Authority:** `Apple Root CA`
- **TeamIdentifier:** `4ADVSK467Z`
- **Flags:** `0x10000(runtime)` (Apple Hardened Runtime enabled)

---

## 3. Installation & macOS Security Trust Setup

### Method 1: Apple Disk Image (DMG) Installation (Recommended)
1. Download **`QuarkShield-macOS.dmg`**.
2. Double-click the downloaded `.dmg` to mount the **QuarkShield Guard** volume.
3. Drag **`QuarkShield.app`** onto the **`/Applications`** shortcut.
4. Double-click **`Trust-QuarkShield.command`** inside the DMG window:
   - This automatically authorizes `QuarkShield.app` with macOS Gatekeeper.
   - Clears the browser download quarantine attribute (`com.apple.quarantine`).
   - Launches the interactive web dashboard in your default browser (`http://127.0.0.1:48291`).

### Method 2: Terminal One-Liner (Automated Download & Run)
Open Terminal (`/Applications/Utilities/Terminal.app`) and execute:
```bash
curl -fsSL https://quarkshield.ai/downloads/quarkshield-scanner-darwin-universal -o quarkshield-scanner
chmod +x quarkshield-scanner
xattr -cr quarkshield-scanner
./quarkshield-scanner --server https://quarkshield.ai
```

### Method 3: First-Time Launch via Finder (Gatekeeper Clearance)
If you prefer not to run the trust script:
1. Open `/Applications` in Finder.
2. **Right-click** (or Control-click) `QuarkShield.app` and select **Open**.
3. In the security confirmation dialog, click **Open**.
4. Future launches can be done with a standard double-click.

---

## 4. What Assets QuarkShield Audits on macOS

QuarkShield leverages native macOS APIs (`/usr/bin/security`) and file system evaluators to discover cryptographic assets:

### 1. macOS System & User Keychains
- **User Keychains:** `~/Library/Keychains/login.keychain-db`, `login.keychain`.
- **System Keychains:** `/Library/Keychains/System.keychain`.
- **System Trust Roots:** `/System/Library/Keychains/SystemRootCertificates.keychain`.
- Evaluates code-signing identities, client authentication certificates, VPN credentials, and trusted CA certificates.

### 2. Developer & Administrator Credentials
- **OpenSSH Keys:** `~/.ssh/id_rsa`, `~/.ssh/id_ecdsa`, `~/.ssh/id_ed25519`, `~/.ssh/config`, `~/.ssh/authorized_keys`, `~/.ssh/known_hosts`.
- **System SSH Host Keys:** `/etc/ssh/ssh_host_*_key`.
- **GnuPG / GPG Keys:** `~/.gnupg/` (`pubring.kbx`, `trustdb.gpg`, private key stubs).
- **Homebrew OpenSSL / LibreSSL:** `/opt/homebrew/etc/openssl/certs/` (Apple Silicon) and `/usr/local/etc/openssl/certs/` (Intel).

### 3. Application Bundles & Developer Certs
- Xcode developer profiles, iOS/macOS distribution certificates, and provisioned entitlements.
- Java keystores used by developer tools: `/Library/Java/JavaVirtualMachines/*/Contents/Home/lib/security/cacerts`.

---

## 5. Scan Operations Explained

The local dashboard at `http://127.0.0.1:48291` provides three dedicated scan modes:

### ⚡ Quick Scan Workstation
- **Purpose:** Rapid assessment of the Mac's core identity and credential repositories.
- **Execution Time:** **2 to 5 seconds**.
- **Scope:**
  - Audits user keychains (`login.keychain-db`).
  - Audits system keychains and trust roots.
  - Audits user SSH directory (`~/.ssh`) and system SSH host keys (`/etc/ssh`).
  - Inspects active environment developer certificates.
- **How to Run:** Click **⚡ Quick Scan Workstation**.

### 📁 Custom Path Scan & macOS Quick Targets
- **Purpose:** Deep recursive audit of specific directories, code repositories, or external drives.
- **macOS Quick Target Presets:**
  - 🍎 **`Applications`** (`/Applications`) — Scans all installed third-party apps and bundles.
  - 👤 **`User Home`** (`~/Users/<username>`) — Scans your entire user profile.
  - 📥 **`Downloads`** (`~/Downloads`) — Audits downloaded keys, packages, and certs.
  - 🔑 **`SSH Keys`** (`~/.ssh`) — Directly targets SSH credentials and host configs.
  - 🛡️ **`Keychains`** (`/Library/Keychains`) — Audits machine-wide system keychains.
- **Native macOS Folder Picker:** Click **📂 Browse Folder...** to open the native AppleScript folder picker (`POSIX path of choose folder`).
- **How to Run:**
  1. Click **📁 Custom Path Scan**.
  2. Click any preset chip (e.g. `Downloads` or `SSH Keys`) or type a custom path.
  3. Click **⚡ Audit Path**.

### 🌐 Remote TLS Handshake Auditor (Probe TLS)
- **Purpose:** Actively probes any external URL, domain, or API endpoint for Post-Quantum TLS 1.3 compliance.
- **Outbound Connection Disclosure:**
  - Initiates a direct outbound TLS socket connection on port 443.
  - **Zero Payload Guarantee:** No HTTP headers, payloads, cookies, or user credentials are sent or inspected. Only public cryptographic handshake negotiations are audited.
- **Evaluated Parameters:**
  - **Key Exchange Suite:** Detects whether the server supports hybrid post-quantum key exchange (such as `X25519Kyber768Draft00` or `ML-KEM-768`) vs classical `ECDHE` or `RSA`.
  - **TLS Protocol Version:** Validates TLS 1.3 negotiation.
  - **Certificate Chain:** Inspects leaf and intermediate certificates for quantum vulnerability and validity.
- **How to Run:**
  1. Click **🌐 Probe TLS / Endpoint**.
  2. Enter target domain (e.g., `cloudflare.com` or `apple.com`).
  3. Check the authorization checkbox and click **Scan Endpoint**.

---

## 6. Reading & Interpreting Audit Results

### Executive Summary Cards
- **Total Cryptographic Artifacts:** Sum of all discovered certificates, asymmetric keys, and keystores.
- **Post-Quantum Ready (Green):** Assets using NIST-standardized PQC algorithms or quantum-safe symmetric encryption.
- **At Quantum Risk (Red/Orange):** Classical asymmetric algorithms vulnerable to Shor's algorithm.

### Vulnerability Classification
| Severity | Color | Criteria |
| :--- | :--- | :--- |
| **CRITICAL** | 🔴 Red | Sub-2048-bit RSA (e.g., RSA-1024), legacy DSA, MD5/SHA-1 signatures, expired certificates. |
| **HIGH** | 🟠 Orange | RSA-2048/3072/4096, ECDSA P-256/P-384, Ed25519. Vulnerable to Harvest Now, Decrypt Later (HNDL). |
| **MEDIUM** | 🟡 Yellow | Certificates expiring within 30 days, deprecated TLS protocol settings. |
| **LOW / INFO** | 🔵 Blue | Informational metadata, self-signed local development certs. |
| **PQC READY** | 🟢 Green | NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA). |

### Actionable Remediation Guidance
- **For SSH Keys:** Upgrade to OpenSSH 9.0+ and generate post-quantum hybrid keys:
```bash
ssh-keygen -t sntrup761x25519-sha512@openssh.com -C "mac-quantum-safe"
```
- **For Code Signing:** Plan migration to NIST FIPS 204 (ML-DSA) algorithms as Apple Developer tools adopt post-quantum standards.
- **For TLS Endpoints:** Enable post-quantum hybrid key exchange (`X25519Kyber768Draft00` or `ML-KEM-768`) in Nginx, Envoy, Cloudflare, or AWS CloudFront.

---

## 7. Exporting CBOM (CycloneDX 1.6) & Audit JSON

To comply with federal cybersecurity directives (EO 14028, OMB M-23-02) and enterprise governance:

### In the Web GUI
1. In the upper right corner of the results section, click **💾 Export JSON** or **Export CBOM (CycloneDX)**.
2. A `.json` file formatted according to the **CycloneDX 1.6 CBOM specification** will be saved to your `~/Downloads` folder.

### Via Command Line
```bash
# Output formatted CLI report
/Applications/QuarkShield.app/Contents/MacOS/quarkshield-scanner --quick

# Export raw JSON CBOM inventory
/Applications/QuarkShield.app/Contents/MacOS/quarkshield-scanner --quick --json > mac-cbom.json

# Audit a specific folder and export JSON
/Applications/QuarkShield.app/Contents/MacOS/quarkshield-scanner --path "/Applications" --json > apps-cbom.json
```

---

## 8. Connecting & Synchronizing with QuarkShield Cloud Fleet

To aggregate telemetry across all organizational Macs into your central QuarkShield dashboard:

### Method 1: In the Web GUI
1. Click **🌐 Connect to Fleet** in the top navigation bar.
2. Enter:
   - **Central Management URL:** `https://quarkshield.ai`
   - **Enterprise Fleet Token:** Your tenant token.
3. Click **Transmit & Sync**.
4. Your Mac's cryptographic inventory will immediately appear under **Fleet Assets** on the cloud console.

### Method 2: Via Terminal
```bash
/Applications/QuarkShield.app/Contents/MacOS/quarkshield-scanner \
  --server "https://quarkshield.ai" \
  --token "YOUR_FLEET_TOKEN" \
  --register \
  --quick
```

---

## 9. Enterprise Mac Fleet Deployment (Jamf / Kandji / Munki)

QuarkShield can be deployed silently across thousands of managed Macs using your Mobile Device Management (MDM) solution.

### Jamf Pro / Kandji Script Deployment
Create a Jamf policy with the following execution script:
```bash
#!/usr/bin/env bash
# Download QuarkShield universal binary
curl -fsSL "https://quarkshield.ai/downloads/quarkshield-scanner-darwin-universal" -o "/usr/local/bin/quarkshield-scanner"
chmod +x "/usr/local/bin/quarkshield-scanner"
xattr -cr "/usr/local/bin/quarkshield-scanner"

# Execute silent scan and register with central fleet
/usr/local/bin/quarkshield-scanner \
  --server "https://quarkshield.ai" \
  --token "YOUR_ENTERPRISE_TOKEN" \
  --register \
  --quick \
  --silent
```

### LaunchDaemon for Continuous Posture Monitoring
To run a periodic background audit every 24 hours, place a `.plist` in `/Library/LaunchDaemons/com.fedmitigate.quarkshield.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.fedmitigate.quarkshield</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/quarkshield-scanner</string>
        <string>--server</string>
        <string>https://quarkshield.ai</string>
        <string>--token</string>
        <string>YOUR_ENTERPRISE_TOKEN</string>
        <string>--quick</string>
        <string>--silent</string>
    </array>
    <key>StartInterval</key>
    <integer>86400</integer>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

---

## 10. Uninstallation & Troubleshooting

### How to Uninstall
- **Via GUI (1-Click):** Click **🗑️ Uninstall** in the top navigation bar. QuarkShield will prompt for confirmation, terminate the background service, and remove local application files.
- **Manual Removal:** Drag `/Applications/QuarkShield.app` to the Trash and empty it.

### Troubleshooting Common Issues
| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **"App is damaged and can't be opened"** | Gatekeeper quarantine flag set by browser download. | Run `xattr -cr /Applications/QuarkShield.app` or double-click `Trust-QuarkShield.command`. |
| **Port 48291 in use** | Another instance is already running. | QuarkShield automatically increments to port 48292. Check the terminal output for the active URL. |
| **Terminal process exited with serial number error** | Running older binary with macOS `-psn_...` flag. | Update to version 2.1.0 which automatically filters process serial numbers. |

---

### Technical Support & Enterprise Contact
- **Portal & Cloud Console:** [https://quarkshield.ai](https://quarkshield.ai)
- **Enterprise Support:** `support@quarkshield.ai`
- **Publisher:** FedMitigate LLC | Washington, D.C.
