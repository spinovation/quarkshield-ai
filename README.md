# 🛡️ QuarkShield.ai — Enterprise Post-Quantum Cryptography (PQC) Platform

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-blue.svg)](LICENSE)
[![Status: Production](https://img.shields.io/badge/Status-Production-success.svg)](https://quarkshield.ai)
[![CBOM: CycloneDX 1.6](https://img.shields.io/badge/CBOM-CycloneDX%201.6%20Compliant-purple.svg)](https://cyclonedx.org)
[![Security: NIST FIPS 203/204/205](https://img.shields.io/badge/Standards-NIST%20FIPS%20203%2F204%2F205-cyan.svg)](https://csrc.nist.gov/pqc)

**QuarkShield.ai** is an end-to-end, enterprise-grade Cryptographic Observability, Discovery, and Post-Quantum Cryptographic (PQC) Transition Management Platform. It continuously audits infrastructure, servers, and endpoints to synthesize **CycloneDX 1.6 Cryptographic Bills of Materials (CBOM)**, identifies Harvest Now, Decrypt Later (HNDL) exposure, and orchestrates migration to quantum-resistant standards (ML-KEM, ML-DSA, SLH-DSA).

---

## 🌟 Architecture & Core Capabilities

```text
                               ┌─────────────────────────────────────────┐
                               │       QuarkShield Cloud Platform        │
                               │           (https://quarkshield.ai)      │
                               └────────────────────┬────────────────────┘
                                                    │
                ┌───────────────────────────────────┼───────────────────────────────────┐
                │                                   │                                   │
                ▼                                   ▼                                   ▼
   ┌──────────────────────────┐       ┌──────────────────────────┐       ┌──────────────────────────┐
   │    Tenant Admin Pods     │       │    Git Repo Auditor      │       │     PQC AI Copilot       │
   │ (*.quarkshield.ai / 5002)│       │  (GitHub/GitLab/Bitbucket)│       │  (Remediation Engine)    │
   └────────────┬─────────────┘       └─────────────┬────────────┘       └─────────────┬────────────┘
                │                                   │                                   │
                └───────────────────────────────────┼───────────────────────────────────┘
                                                    │ Telemetry Ingestion / Remote Pull
                                                    ▼
                                      ┌──────────────────────────┐
                                      │   QuarkShield Agent      │
                                      │  (macOS / Win / Linux)   │
                                      └──────────────────────────┘
```

### 1. High-Performance Host & Desktop Agent (`/agent`)
* **Zero-Noise Native Binary**: Compiled in Go with zero external runtime dependencies. Runs in <2 seconds.
* **Microsoft-Style Hardware UUID Entitlement**: Binds workstation identity permanently to hardware (`IOPlatformUUID` on macOS, `MachineGuid` on Windows, `/etc/machine-id` on Linux). Re-syncs update existing records in-place, consuming exactly 1 license seat per physical device.
* **Permanent Enrollment**: Securely caches tenant token in `~/.quarkshield/enrollment.json` for hands-off ongoing sync.
* **Automated Background Scheduling & On-Demand Pull**: Periodic local discovery ticker plus remote priority telemetry pull dispatched via the console.
* **Broad Cryptographic Introspection**: Scans OpenSSH keys, PEM/DER/CRT/CER/KEY/PFX certificates, developer workdirs, system keychains, and OpenSSL configurations.

### 2. Multi-Tenant Telemetry & Ingestion Backend (`/server`)
* **Strict Tenant Scoping & Subdomain Routing**: Supports independent tenant gateways (e.g. `spinovation.quarkshield.ai` or dedicated port routing).
* **Automated Deduplication**: Ingestion matches on `(tenant_name, hardware_uuid)`, purging previous assets for that machine and updating the state idempotently.
* **Daily Historical Compliance Snapshots**: Archives daily asset and vulnerability counts (`fleet_daily_snapshots`) without inflating active workstation seats.
* **On-Demand Remote Pull API**: Enqueues telemetry pull commands (`POST /api/fleet/machines/:id/pull`).

### 3. Modern Enterprise Management Console (`/ui`)
* **CycloneDX 1.6 CBOM Explorer**: Interactive cryptographic component table with dual-mode JSON viewer and 1-click CBOM export.
* **Fleet Seat Management**: Real-time license quota tracking, hardware UUID display, and remote telemetry pull controls.
* **PQC Remediation Copilot**: Integrated AI advisory providing code snippets and configs for FIPS-203 (ML-KEM-768), FIPS-204 (ML-DSA), OpenSSH 9.8+, and NGINX post-quantum TLS.
* **Automated Sync Scheduler Modal**: Configure tenant-wide sync cadence (Daily 02:00 AM, Hourly, Weekly).

---

## 📁 Repository Structure

```text
.
├── agent/                         # High-performance Go native host scanner & agent
│   ├── main.go                    # CLI runner, argument parser, orchestrator
│   ├── device_id.go               # Hardware UUID & friendly computer name detection
│   ├── client.go                  # Secure TLS telemetry ingestion & enrollment storage
│   ├── gui.go                     # Embedded local Web UI & status server (port 48291)
│   ├── auditor.go                 # Local filesystem crypto scanner & parser
│   ├── prober.go                  # Active network TLS 1.3 socket prober
│   └── build_macos.sh             # Universal Mach-O & .app packager
├── server/                        # Express / TypeScript Telemetry & CBOM Backend
│   ├── src/
│   │   ├── index.ts               # Server entrypoint (API, downloads, and UI routing)
│   │   ├── config/db.ts           # PostgreSQL connection pool & migrations
│   │   ├── controllers/           # Fleet, Admin, AI Copilot, Git scan controllers
│   │   ├── models/schema.sql      # Database schema (tenants, machines, assets, snapshots)
│   │   └── routes/routes.ts       # REST routing table
│   └── tsconfig.json
├── ui/                            # React 19 + Vite Enterprise Management Console
│   ├── src/
│   │   ├── App.tsx                # Main application & routing controller
│   │   ├── components/
│   │   │   ├── LandingPage.tsx    # Modern public portal & threat showcase
│   │   │   ├── TenantPortal.tsx   # Isolated tenant portal, CBOM explorer, fleet table
│   │   │   ├── AdminPanel.tsx     # Super Admin management console
│   │   │   └── GitRepoAuditor.tsx # Remote Git repository cryptographic auditor
│   │   └── index.css              # Cyber-dark glassmorphism theme
│   └── vite.config.ts
├── docs/                          # Architecture guides & user manuals
├── docker-compose.yml             # Standalone production PostgreSQL + Console orchestration
├── Dockerfile                     # Multi-stage optimized production container build
├── deploy.sh                      # Production VPS deployment & verification script
└── README.md
```

---

## 🚀 Deployment & Operations

The platform is deployed live on the production cluster (`13.140.40.99` / `https://quarkshield.ai`):

```bash
# 1. Sync repository to production VPS
rsync -avz --exclude 'node_modules' --exclude '.git' ./ root@13.140.40.99:/opt/desktop-pqc-scanner/

# 2. Run deployment script on VPS
ssh root@13.140.40.99 "cd /opt/desktop-pqc-scanner && ./deploy.sh"
```

---

## 💻 Fleet Agent Rollout

### macOS (Universal Binary / .app)
```bash
# 1-click terminal install
curl -fsSL https://quarkshield.ai/downloads/quarkshield-scanner-macos.zip -o quarkshield.zip
unzip quarkshield.zip && cd QuarkShield.app/Contents/MacOS
./quarkshield-scanner --server https://quarkshield.ai --token <YOUR_TENANT_TOKEN> --enroll
```

### Windows (PowerShell / Intune)
```powershell
Invoke-WebRequest -Uri "https://quarkshield.ai/downloads/quarkshield-scanner-windows-amd64.exe" -OutFile "$env:TEMP\quarkshield-scanner.exe"
& "$env:TEMP\quarkshield-scanner.exe" --server "https://quarkshield.ai" --token "<YOUR_TENANT_TOKEN>" --enroll
```

### Linux (Systemd / Ansible)
```bash
curl -fsSL https://quarkshield.ai/downloads/quarkshield-scanner-linux-amd64 -o /usr/local/bin/quarkshield-scanner
chmod +x /usr/local/bin/quarkshield-scanner
/usr/local/bin/quarkshield-scanner --server https://quarkshield.ai --token <YOUR_TENANT_TOKEN> --enroll
```

---

## 🛡️ Telemetry & Fleet API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Production service health check |
| `POST` | `/api/scan/agent/ingest` | Workstation telemetry ingestion (auto-deduplicated) |
| `GET` | `/api/fleet/tokens` | Tenant enrollment token listing |
| `POST` | `/api/fleet/tokens` | Issue new department / environment enrollment token |
| `DELETE` | `/api/fleet/tokens/:id` | Instant token revocation |
| `GET` | `/api/fleet/cbom` | Export CycloneDX 1.6 Cryptographic Bill of Materials (JSON) |
| `POST` | `/api/fleet/machines/:id/pull` | Enqueue on-demand priority telemetry pull for a workstation |
| `GET` | `/api/tenant/:tenant/portal-data` | Isolated tenant portal metrics, machines, and license info |
| `GET` | `/api/tenant/:tenant/daily-snapshots`| Historical compliance and asset snapshots for audit trends |

---

## 📄 License & Compliance

© 2026 QuarkShield.ai / FedMitigate LLC All rights reserved.
Compliant with NIST FIPS 203 (ML-KEM), NIST FIPS 204 (ML-DSA), NIST FIPS 205 (SLH-DSA), and CycloneDX 1.6 CBOM specifications.
