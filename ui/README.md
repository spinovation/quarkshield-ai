# 🛡️ QuarkShield Desktop & Host PQC Vulnerability Scanner (Option A)

A completely self-contained, enterprise-grade Desktop & Host Cryptographic Discovery & Post-Quantum Cryptography (PQC) Vulnerability Scanner.

This sub-project is designed to run as an **isolated, standalone instance** (e.g., hosted on `quarkshield.ai` or a dedicated VPS), completely independent of tenant applications.

---

## 🌟 Key Architecture Pillars

1. **Zero Network Noise (Native Go Binary)**:
   - Compiles down to a single zero-dependency native executable for macOS (`darwin-arm64`, `darwin-amd64`), Linux (`linux-amd64`, `linux-arm64`), and Windows (`windows-amd64.exe`).
   - Runs locally on the host in under 2 seconds. No python runtimes, no java, no external npm packages.
2. **Deep Host & Desktop Introspection**:
   - Parses OpenSSH key formats, SSH configs, known hosts, and authorized keys.
   - Inspects PEM, DER, CRT, CER, KEY, and PKCS#12 bundles across developer workdirs, `/etc/ssl`, and keychains.
   - Audits system-wide crypto policies (`/etc/crypto-policies`, OpenSSL configuration directives).
   - Flags Shor's algorithm-vulnerable algorithms (RSA, DSA, ECDSA, Ed25519) with NIST FIPS 203/204/205 remediation roadmaps (ML-KEM, ML-DSA, SLH-DSA).
3. **Enterprise MDM Push-Ready**:
   - Ready for immediate automated roll-out via Jamf Pro, Microsoft Intune, Ansible playbooks, or Puppet across 10,000+ developer laptops and cloud servers.
4. **CycloneDX 1.6+ CBOM Generation**:
   - Automatically synthesizes compliant **Cryptographic Bill of Materials (CBOM)** according to the CycloneDX 1.6 specification with deep algorithm properties, quantum security levels, and compliance tags.
5. **Independent Management Console & Token Authority**:
   - Centralized React 19 UI with real-time Fleet Overview, Cryptographic Asset Inventory, Token Management, and 1-Click Installation Script generator.

---

## 📁 Sub-Project Structure

```text
desktop-pqc-scanner/
├── agent/                         # High-performance Go native host scanner
│   ├── main.go                    # CLI runner, argument parser, orchestrator
│   ├── auditor.go                 # Local filesystem crypto scanner & parser
│   ├── client.go                  # Secure TLS telemetry ingestion client
│   ├── go.mod
│   └── binaries/                  # Pre-compiled cross-platform binaries
│       ├── quarkshield-scanner-darwin-arm64      (Apple Silicon M1/M2/M3/M4)
│       ├── quarkshield-scanner-darwin-amd64      (Intel Mac)
│       ├── quarkshield-scanner-linux-amd64       (Ubuntu / Debian / RHEL / Alpine)
│       └── quarkshield-scanner-windows-amd64.exe (Windows 10/11 / Windows Server)
├── server/                        # Express / TypeScript Telemetry & CBOM Backend
│   ├── package.json
│   ├── tsconfig.json
│   └── src/
│       ├── index.ts               # Server entrypoint (serves API, downloads, and UI)
│       ├── config/db.ts           # PostgreSQL connection pool & auto-migrations
│       ├── controllers/           # Fleet tokens, machines, CBOM generator, installer
│       ├── models/schema.sql      # Database schema (fleet_tokens, fleet_machines, assets)
│       └── routes/routes.ts       # REST routing table
├── ui/                            # Dedicated React 19 + Vite Management Console
│   ├── package.json
│   ├── vite.config.ts
│   └── src/
│       ├── App.tsx                # 3-Tab Console: Fleet Overview, CBOM, Agent Tokens
│       ├── index.css              # Cyber-dark glassmorphism styling
│       └── main.tsx
├── Dockerfile                     # Multi-stage production container
├── docker-compose.yml             # Standalone Postgres + Console orchestration
├── docs/                          # Enterprise Post-Quantum Architecture Specifications
│   ├── AGENTLESS_PQC_ARCHITECTURE.md       # The "Wiz Model" for Agentless PQC Discovery
│   └── ACTIVE_NETWORK_TLS_PQC_PROBING.md   # Zero-Touch Outbound Socket & TLS Probing Guide
├── deploy.sh                      # 1-click VPS installation & update script
├── .env.example                   # Environment configuration template
└── README.md
```

### 📚 Architectural Specifications & Whitepapers
- **[Agentless & API-First PQC Discovery ("The Wiz Model")](docs/AGENTLESS_PQC_ARCHITECTURE.md)**: Details the 5 pillars eliminating agent fatigue via Cloud KMS, IAM/MDM, Git repositories, and out-of-band volume snapshotting.
- **[Active Network & Outbound TCP/TLS Socket Probing Architecture](docs/ACTIVE_NETWORK_TLS_PQC_PROBING.md)**: Deep-dive into active TLS 1.3 socket probing (e.g. testing `microsoft.com`), 5-stage handshake inspection, and empirical HNDL / Shor's / Grover's threat evaluation.

---

## 🚀 Deployment on a Dedicated VPS (e.g. `quarkshield.ai`)

When your new VPS is ready, deploy the scanner console in one step:

### 1. Copy or clone the sub-project to the target VPS:
```bash
# Example using rsync from your local machine:
rsync -avz --exclude 'node_modules' desktop-pqc-scanner/ root@<YOUR_VPS_IP>:/opt/desktop-pqc-scanner/
```

### 2. Run the 1-Click Deployment Script:
```bash
ssh root@<YOUR_VPS_IP>
cd /opt/desktop-pqc-scanner
./deploy.sh
```

The script automatically:
- Builds the optimized multi-stage Docker container
- Initializes the isolated PostgreSQL database
- Applies database schemas (`fleet_tokens`, `fleet_machines`, `assets`)
- Exposes the Management Console and binary downloads on port `5050`
- Configures health verification

---

## 💻 Fleet Agent Deployment Options

Once the console is running on your VPS (e.g. `https://scanner.quarkshield.ai` or `http://<VPS_IP>:5050`):

### Option 1: 1-Click curl / POSIX Shell (Mac & Linux)
```bash
curl -fsSL https://scanner.quarkshield.ai/api/scan/agent/install.sh | sudo sh -s -- --token YOUR_FLEET_TOKEN
```

### Option 2: Microsoft Intune (Windows PowerShell)
```powershell
Invoke-WebRequest -Uri "https://scanner.quarkshield.ai/downloads/quarkshield-scanner-windows-amd64.exe" -OutFile "$env:TEMP\quarkshield-scanner.exe"
& "$env:TEMP\quarkshield-scanner.exe" --server "https://scanner.quarkshield.ai" --token "YOUR_FLEET_TOKEN" --register
```

### Option 3: Jamf Pro (macOS Script Payload)
```bash
#!/bin/bash
curl -fsSL https://scanner.quarkshield.ai/downloads/quarkshield-scanner-darwin-arm64 -o /usr/local/bin/quarkshield-scanner
chmod +x /usr/local/bin/quarkshield-scanner
/usr/local/bin/quarkshield-scanner --server https://scanner.quarkshield.ai --token YOUR_FLEET_TOKEN --register
```

### Option 4: Ansible Playbook (Linux Fleet)
```yaml
- name: Deploy QuarkShield PQC Scanner Agent
  hosts: all
  become: true
  tasks:
    - name: Download scanner binary
      get_url:
        url: https://scanner.quarkshield.ai/downloads/quarkshield-scanner-linux-amd64
        dest: /usr/local/bin/quarkshield-scanner
        mode: '0755'
    - name: Execute host cryptographic audit
      command: /usr/local/bin/quarkshield-scanner --server https://scanner.quarkshield.ai --token YOUR_FLEET_TOKEN --register --quick
```

---

## 🔍 Agent CLI Usage (Standalone / Offline)

You can run the scanner binary locally without connecting to any server:

```bash
# Run local host audit and print discovered cryptographic assets to stdout
./quarkshield-scanner-darwin-arm64

# Export Cryptographic Bill of Materials (CBOM) to a JSON file locally:
./quarkshield-scanner-darwin-arm64 --output cbom.json

# Quick scan (audits standard user SSH, TLS certs, and configs):
./quarkshield-scanner-darwin-arm64 --quick

# Full deep scan across custom paths:
./quarkshield-scanner-darwin-arm64 --path /etc/ssl --path /var/www --path ~/.ssh
```

---

## 🛡️ Telemetry & CBOM API Endpoints

- `GET /health` — Service health check
- `GET /downloads/:binary` — Download native agent binaries
- `GET /api/fleet/tokens` — List enrollment tokens
- `POST /api/fleet/tokens` — Generate enrollment token for a new department or fleet
- `DELETE /api/fleet/tokens/:id` — Revoke token
- `GET /api/fleet/machines` — Live inventory of enrolled endpoints and risk scores
- `DELETE /api/fleet/machines/:id` — Decommission endpoint
- `GET /api/fleet/cbom` — CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)
- `GET /api/scan/agent/install.sh` — Universal auto-install script
- `POST /api/scan/agent/ingest` — Endpoint agent telemetry ingestion
