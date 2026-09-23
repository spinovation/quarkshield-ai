# QuarkShield Post-Quantum Guard: Linux User Guide & Operations Manual

![QuarkShield Platform](https://quarkshield.ai/quarkshield-logo.png)

> **Document Version:** 2.1.0  
> **Target Audience:** Linux System Administrators, Security Engineers, SREs, DevOps, Cloud Architects, and Enterprise Infrastructure Teams  
> **Platform:** Ubuntu, Debian, Red Hat Enterprise Linux (RHEL), CentOS, Rocky Linux, AlmaLinux, Alpine Linux, Amazon Linux 2 / 2023, SUSE  
> **Architecture:** Linux x86_64 (amd64) and Linux ARM64 (aarch64 / AWS Graviton)  
> **Central Console:** [https://quarkshield.ai](https://quarkshield.ai)  

---

## Table of Contents
1. [Introduction & Threat Context](#1-introduction--threat-context)
2. [Download Locations & Binary Options](#2-download-locations--binary-options)
3. [Installation & Execution Modes](#3-installation--execution-modes)
   - [Interactive Web GUI Mode](#interactive-web-gui-mode)
   - [Headless CLI Audit Mode](#headless-cli-audit-mode)
   - [Automated 1-Line Installer Script](#automated-1-line-installer-script)
4. [What Assets QuarkShield Audits on Linux & The Zero-Exfiltration Guarantee](#4-what-assets-quarkshield-audits-on-linux--the-zero-exfiltration-guarantee)
5. [Scan Operations Explained](#5-scan-operations-explained)
   - [Quick Scan Host](#quick-scan-host)
   - [Custom Path Scan & Linux Quick Targets](#custom-path-scan--linux-quick-targets)
   - [Remote TLS Handshake Auditor (Probe TLS)](#remote-tls-handshake-auditor-probe-tls)
6. [Reading & Interpreting Audit Results](#6-reading--interpreting-audit-results)
7. [Exporting CBOM (CycloneDX 1.6) & Audit JSON](#7-exporting-cbom-cyclonedx-16--audit-json)
8. [Connecting & Synchronizing with QuarkShield Cloud Fleet](#8-connecting--synchronizing-with-quarkshield-cloud-fleet)
9. [Automated Infrastructure Deployment (systemd, Ansible, Docker, Kubernetes)](#9-automated-infrastructure-deployment-systemd-ansible-docker-kubernetes)
10. [Preparing Linux Server Fleets for OS & Library PQC Trust Roots](#10-preparing-linux-server-fleets-for-os--library-pqc-trust-roots)
11. [Uninstallation & Troubleshooting](#11-uninstallation--troubleshooting)

---

## 1. Introduction & Threat Context

**QuarkShield Post-Quantum Guard for Linux** is a lightweight, zero-dependency, statically compiled binary engineered to discover, audit, and remediate quantum-vulnerable cryptography across Linux workstations, cloud instances (AWS EC2, Google Cloud, Azure), on-premise servers, and containerized workloads.

### The Threat: Harvest Now, Decrypt Later (HNDL)
Encrypted network traffic, server SSL keys, WireGuard VPN tunnels, and OpenSSH host keys intercepted by adversaries today can be decrypted retroactively once a Cryptanalytically Relevant Quantum Computer (CRQC) is deployed.

QuarkShield audits your Linux infrastructure against the newly finalized **NIST Post-Quantum Cryptography (PQC) Standards**:
- **FIPS 203:** Module-Lattice-Based Key-Encapsulation Mechanism (**ML-KEM** / Kyber)
- **FIPS 204:** Module-Lattice-Based Digital Signature Algorithm (**ML-DSA** / Dilithium)
- **FIPS 205:** Stateless Hash-Based Digital Signature Algorithm (**SLH-DSA** / SPHINCS+)
- **NSA CNSA 2.0:** Commercial National Security Algorithm Suite mandates

---

## 2. Download Locations & Binary Options

All Linux binaries are statically linked with no external dependencies (runs out-of-the-box on glibc and musl systems including Alpine):

| Binary | Architecture | Download URL | Description |
| :--- | :--- | :--- | :--- |
| **Linux x86_64 Binary** | `amd64` | [Download x86_64](https://quarkshield.ai/downloads/quarkshield-scanner-linux-amd64) | For Intel / AMD servers, workstations, and VMs. |
| **Linux ARM64 Binary** | `aarch64` | [Download ARM64](https://quarkshield.ai/downloads/quarkshield-scanner-linux-arm64) | For AWS Graviton, Raspberry Pi 4/5, Ampere Altra, Apple Silicon VMs. |
| **1-Click Linux Installer** | Bash Script | [Download install.sh](https://quarkshield.ai/api/scan/agent/install.sh) | Automated script to download, configure permissions, and run. |

---

## 3. Installation & Execution Modes

### Mode A: 1-Click Terminal Automated Installer
Run the automated installer script directly via `curl` or `wget`:
```bash
curl -fsSL https://quarkshield.ai/api/scan/agent/install.sh | bash
```
The installer detects your CPU architecture (`x86_64` vs `aarch64`), downloads the correct binary, sets executable permissions, and launches the scanner.

### Mode B: Manual Download & Interactive Web GUI
If you are running a Linux desktop (Ubuntu Desktop, Fedora, Arch, Mint):
```bash
# 1. Download binary
curl -fsSL https://quarkshield.ai/downloads/quarkshield-scanner-linux-amd64 -o quarkshield-scanner

# 2. Make executable
chmod +x quarkshield-scanner

# 3. Launch interactive GUI
./quarkshield-scanner
```
QuarkShield will start its background engine on loopback port `48291` and attempt to launch your default desktop browser (Firefox, Chrome). You can also open `http://127.0.0.1:48291` manually.

### Mode C: Headless Server CLI Mode (No Browser)
On cloud servers, headless VPS instances, or CI/CD pipelines:
```bash
# Run quick discovery scan in terminal
./quarkshield-scanner --quick

# Scan a specific directory and print human-readable summary
./quarkshield-scanner --path /etc/ssl

# Output raw CycloneDX 1.6 CBOM in JSON format
./quarkshield-scanner --quick --json > cbom-linux.json
```

---

## 4. What Assets QuarkShield Audits on Linux & The Zero-Exfiltration Guarantee

QuarkShield scans both system configuration directories and runtime application stores:

### 1. System Certificate Stores
- **Debian / Ubuntu:** `/etc/ssl/certs/`, `/usr/share/ca-certificates/`
- **RHEL / CentOS / Rocky / AlmaLinux:** `/etc/pki/tls/certs/`, `/etc/pki/ca-trust/`
- **OpenSSL Global Directory:** `/etc/ssl/openssl.cnf`

### 2. OpenSSH Infrastructure
- **Server Host Keys:** `/etc/ssh/ssh_host_*_key` (`rsa`, `ecdsa`, `ed25519`)
- **Server Configuration:** `/etc/ssh/sshd_config` (identifies allowed `KexAlgorithms` and `HostKeyAlgorithms`)
- **User SSH Keys:** `~/.ssh/id_*`, `~/.ssh/authorized_keys`, `~/.ssh/config`, `~/.ssh/known_hosts`

### 3. Web Servers & Ingress Proxies
- **Nginx:** `/etc/nginx/ssl/`, `/etc/nginx/conf.d/`
- **Apache HTTP Server:** `/etc/apache2/`, `/etc/httpd/`
- **Caddy & Traefik:** `/etc/caddy/`, `/etc/traefik/acme/`
- **Web Roots:** `/var/www/`, `/srv/`

### 4. Containers & Cloud Secret Volumes
- Mounted Kubernetes secrets: `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`
- Docker daemon certificates: `/etc/docker/certs.d/`
- WireGuard VPN keys: `/etc/wireguard/`
- Java Keystores: `/etc/ssl/certs/java/cacerts`

### 5. Understanding "Keys" in QuarkShield & The Zero-Exfiltration Guarantee

In QuarkShield's Linux dashboards, CLI logs, and CBOM inventory, **"Keys"** refers exclusively to **Cryptographic Assets and Public Algorithm Primitives**—specifically:
- **Public Certificates:** X.509 server and CA certificates in `/etc/ssl/certs` and `/etc/pki`.
- **Asymmetric Key Parameters:** RSA public moduli (2048/4096-bit), Elliptic Curve public coordinates and curve identifiers (secp256r1/P-256, secp384r1/P-384, Ed25519).
- **Host Identities & Cipher Suites:** SSH public host keys and TLS cipher configurations.

> **CRITICAL SECURITY PROMISE: Zero-Exfiltration Guarantee**  
> QuarkShield operates strictly on a **local-in-RAM inspection model**:
> - **Private Keys Are NEVER Exfiltrated:** Private key files (`BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`, PKCS#8), passphrases, seed material, or decrypted plaintexts are **NEVER captured, stored, uploaded, or transmitted** to any remote server.
> - **Volatile Memory Execution:** File and certificate parsing takes place strictly inside temporary local volatile RAM. As soon as public cryptographic metadata (algorithm name, bit length, validity dates, issuer DN) is extracted, working memory is cleared.
> - **Privacy-Preserving Telemetry:** Telemetry synchronized with the QuarkShield Cloud Fleet contains solely non-sensitive public metadata structured according to the CycloneDX 1.6 CBOM standard.

---

### 6. Quantum Vulnerability of Discovered Keys: Shor's Algorithm

Virtually all server keys and TLS certificates discovered across Linux distributions today rely on classical asymmetric mathematics:
- **RSA Factorization:** RSA-2048 and RSA-4096 rely on prime integer factorization. Shor's algorithm running on a Cryptanalytically Relevant Quantum Computer (CRQC) solves prime factorization in polynomial time ($O((\log N)^3)$).
- **Elliptic Curve Collapse (~2,300 Logical Qubits):** Linux SSH host keys, WireGuard VPNs, and modern TLS certificates heavily favor ECDSA (P-256) and Ed25519. Because elliptic curve groups are much smaller than RSA moduli, **ECC collapses even faster on quantum hardware—requiring only ~2,300 logical qubits** compared to ~4,096 for RSA-2048.

---

## 5. Scan Operations Explained

Whether in the Web GUI (`http://127.0.0.1:48291`) or CLI:

### ⚡ Quick Scan Host
- **Purpose:** Rapid audit of operating system credentials, SSH host keys, and system certificate stores.
- **Execution Time:** **1 to 4 seconds**.
- **Scope:**
  - Audits `/etc/ssl/certs` and `/etc/pki`.
  - Audits `/etc/ssh` and `~/.ssh`.
  - Evaluates OpenSSL cipher suite configuration.
- **CLI Command:** `./quarkshield-scanner --quick`

### 📁 Custom Path Scan & Linux Quick Targets
- **Purpose:** Deep recursive audit of production directories, container volumes, or web application directories.
- **Linux Quick Target Presets (in GUI):**
  - 🛡️ **`System SSL`** (`/etc/ssl`) — Audits system-wide certificate bundles and OpenSSL configs.
  - 🔑 **`SSH Config`** (`/etc/ssh`) — Audits server host keys and daemon policies.
  - 👤 **`User Home`** (`~/`) — Audits the current user directory.
  - 🔑 **`User SSH`** (`~/.ssh`) — Audits user SSH private and public keys.
  - 🌐 **`Web Root`** (`/var/www`) — Audits production web applications and embedded certificates.
- **CLI Command:**
```bash
./quarkshield-scanner --path "/var/www"
```

### 🌐 Remote TLS Handshake Auditor (Probe TLS)
- **Purpose:** Active probe of any remote domain, internal microservice, or API gateway for Post-Quantum TLS 1.3 readiness.
- **Outbound Connection Disclosure:**
  - Direct outbound TCP connection on port 443.
  - **Zero Payload Guarantee:** No HTTP headers or data payloads are transmitted. Only public cryptographic handshake negotiations are audited.
- **Evaluated Parameters:**
  - Support for hybrid post-quantum key exchange (`X25519Kyber768Draft00` or `ML-KEM-768`).
  - Negotiation of TLS 1.3 vs legacy TLS 1.2.
  - Cipher suite strength (`AES-256-GCM`, `CHACHA20-POLY1305`).
- **CLI Command:**
```bash
./quarkshield-scanner --probe "cloudflare.com"
```

---

## 6. Reading & Interpreting Audit Results

### Severity & Vulnerability Ratings
| Risk Level | Color | Criteria & Cryptographic Details |
| :--- | :--- | :--- |
| **CRITICAL** | 🔴 Red | Sub-2048 RSA (RSA-1024), legacy DSA, SHA-1/MD5 certificates, expired certificates. |
| **HIGH** | 🟠 Orange | RSA-2048/3072/4096, ECDSA P-256/P-384, Ed25519. Vulnerable to Harvest Now, Decrypt Later (HNDL) quantum attacks. |
| **MEDIUM** | 🟡 Yellow | Weak Diffie-Hellman parameters, certificates expiring within 30 days. |
| **LOW / INFO** | 🔵 Blue | Informational configuration notices, self-signed test certs. |
| **PQC READY** | 🟢 Green | NIST FIPS 203 (ML-KEM/Kyber), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA). |

### Actionable Remediation Guidance
- **For OpenSSH Host & Client Keys:**  
  Update `/etc/ssh/sshd_config` to enable post-quantum hybrid key exchange:
  ```sshconfig
  KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256
  ```
- **For Web Servers (Nginx / Caddy):**  
  Enable TLS 1.3 hybrid post-quantum key exchange groups.
- **For Certificates:**  
  Begin migration to hybrid certificates combining RSA/ECDSA with ML-DSA per NSA CNSA 2.0 timelines.

---

## 7. Exporting CBOM (CycloneDX 1.6) & Audit JSON

QuarkShield generates standard **Cryptographic Bill of Materials (CBOM)** compliant with **CycloneDX 1.6** and federal OMB M-23-02 / EO 14028 directives:

### CLI Export Commands
```bash
# Generate full CycloneDX 1.6 JSON CBOM
./quarkshield-scanner --quick --json > cbom-system.json

# Audit custom application directory and save CBOM
./quarkshield-scanner --path "/var/www/my-app" --json > app-cbom.json
```

---

## 8. Connecting & Synchronizing with QuarkShield Cloud Fleet

To stream real-time cryptographic posture data from Linux servers into your centralized QuarkShield dashboard:

### Via Command Line (Ideal for Servers & CI/CD)
```bash
./quarkshield-scanner \
  --server "https://quarkshield.ai" \
  --token "YOUR_FLEET_TOKEN" \
  --register \
  --quick
```

### In the Web GUI
1. Open `http://127.0.0.1:48291`.
2. Click **🌐 Connect to Fleet** in the top navigation bar.
3. Enter your **Enterprise Fleet Token** and click **Transmit & Sync**.

---

## 9. Automated Infrastructure Deployment (systemd, Ansible, Docker, Kubernetes)

### 1. Systemd Service (Daily Continuous Audit)
Create `/etc/systemd/system/quarkshield-audit.service`:
```ini
[Unit]
Description=QuarkShield Post-Quantum Posture Auditor
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/quarkshield-scanner --server https://quarkshield.ai --token YOUR_FLEET_TOKEN --quick --silent
User=root

[Install]
WantedBy=multi-user.target
```
Create `/etc/systemd/system/quarkshield-audit.timer`:
```ini
[Unit]
Description=Run QuarkShield Audit Daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```
Enable and start the timer:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now quarkshield-audit.timer
```

### 2. Ansible Playbook Task
```yaml
- name: Deploy and execute QuarkShield Post-Quantum Audit
  hosts: all
  tasks:
    - name: Download QuarkShield binary
      get_url:
        url: https://quarkshield.ai/downloads/quarkshield-scanner-linux-amd64
        dest: /usr/local/bin/quarkshield-scanner
        mode: '0755'

    - name: Run audit and register with central fleet
      command: /usr/local/bin/quarkshield-scanner --server https://quarkshield.ai --token "{{ fleet_token }}" --register --quick --silent
```

### 3. Docker Container Scan
You can mount host directories or container images to audit their cryptographic assets:
```bash
docker run --rm \
  -v /etc/ssl:/scan/ssl:ro \
  -v /var/www:/scan/www:ro \
  curlimages/curl:latest sh -c \
  "curl -fsSL https://quarkshield.ai/downloads/quarkshield-scanner-linux-amd64 -o /tmp/qs && chmod +x /tmp/qs && /tmp/qs --path /scan"
```

### 4. Enterprise Non-Root / Zero-Reboot Alternative: OpenTelemetry (OTel) & Cloud Snapshots
For mission-critical production servers subject to strict change freezes or where operational teams resist resident agent installations:
- **OpenTelemetry Telemetry (Tier 3)**: Utilize your existing **OpenTelemetry (OTel) Collector** to forward OpenSSL, GnuTLS, and `auditd` cryptographic logs to QuarkShield with 0% risk of system reboot and unprivileged non-root execution.
- **Agentless Cloud Volume Snapshots (Tier 1)**: For AWS EC2, Azure VMs, and GCP instances, leverage out-of-band disk snapshot auditing. The disk volume is audited in an ephemeral analysis container—guaranteeing **0% CPU, 0 MB RAM overhead on the production host**.
- **Detailed Blueprint**: See the [QuarkShield Enterprise Post-Quantum Cryptographic Deployment Guide](ENTERPRISE_AGENT_DEPLOYMENT_GUIDE.md).

---

## 10. Preparing Linux Server Fleets for OS & Library PQC Trust Roots

Major Linux enterprise distributions (Ubuntu 24.04+, RHEL 9.4+, Debian 13) and upstream cryptographic libraries are actively adopting NIST FIPS 203/204/205 post-quantum trust roots:
- **OpenSSL 3.5+ & OQS Provider:** Upstream OpenSSL is integrating native post-quantum key exchange (`ML-KEM-768`) and signatures (`ML-DSA-65`).
- **OpenSSH 9.8+ Post-Quantum Hybrid KEX:** OpenSSH defaults to `sntrup761x25519-sha512@openssh.com` and `mlkem768x25519-sha256` for key exchange to eliminate HNDL threats.
- **Enterprise Linux Trust Stores:** `/etc/pki/ca-trust` and `/etc/ssl/certs` will introduce hybrid and PQC root authorities, mandating modernization for web ingress and internal microservice mTLS.

### Recommended Customer Action Plan:
1. **Continuous CBOM Discovery:** Deploy QuarkShield via Ansible or systemd timers across all server instances to maintain a real-time CycloneDX 1.6 CBOM.
2. **Audit Web Ingress & Reverse Proxies:** Configure NGINX, HAProxy, and Envoy proxies with hybrid `X25519MLKEM768` TLS 1.3 ciphers to immediately defend against Harvest Now, Decrypt Later adversaries.
3. **Upgrade OpenSSH Host Configurations:** Audit `/etc/ssh/sshd_config` across your server fleet with QuarkShield to ensure post-quantum hybrid KEX algorithms are prioritized.
4. **Internal Microservices & mTLS:** Transition internal service mesh certificates (Consul, Istio, Linkerd) and Vault PKI engines toward hybrid certificate signing.
5. **Enforce Automated Drift Monitoring:** Use QuarkShield's Cloud Fleet plane to alert SecOps and SRE teams whenever newly spun up VMs or containers introduce obsolete RSA-1024/2048 or legacy SHA-1 certificates.

---

## 11. Uninstallation & Troubleshooting

### How to Uninstall
- **Via GUI:** Click **🗑️ Uninstall** in the top bar.
- **Manual Removal:**
```bash
sudo rm -f /usr/local/bin/quarkshield-scanner
sudo rm -f /etc/systemd/system/quarkshield-audit.*
```

### Troubleshooting Common Issues
| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **Permission denied on system stores** | Scanned directories (`/etc/ssh`, `/etc/ssl/certs`) require elevated permissions. | Run with `sudo ./quarkshield-scanner --quick`. QuarkShield reads public metadata in volatile memory only and never exfiltrates private key content. |
| **Port 48291 in use** | Another service or instance is using port 48291. | QuarkShield will automatically try ports 48292-48295. |
| **Corporate proxy blocking sync** | Outbound traffic to port 443 intercepted. | Export `https_proxy="http://proxy:8080"` in your environment before running. |

---

### Technical Support & Enterprise Contact
- **Central Management Console:** [https://quarkshield.ai](https://quarkshield.ai)
- **Enterprise Support:** `support@quarkshield.ai`
- **Publisher:** FedMitigate LLC | Washington, D.C.
