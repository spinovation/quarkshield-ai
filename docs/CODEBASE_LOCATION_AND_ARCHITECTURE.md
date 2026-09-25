# 📍 QuarkShield.ai — Codebase Location & Architecture Reference

> **Important Operational Guideline**: This document details the local filesystem locations, remote Git endpoints, and deployment targets for QuarkShield.ai. Do not push or sync this local reference to upstream git repositories unless explicitly instructed.

---

## 1. Local Filesystem Location on macOS

The active **QuarkShield.ai** development codebase is located at:

```bash
/Users/sridhargs/Documents/Antigravity/Quantum RAP/desktop-pqc-scanner
```

### Git Repository Configuration
- **Working Directory**: `/Users/sridhargs/Documents/Antigravity/Quantum RAP/desktop-pqc-scanner`
- **Git Remote (`origin`)**: `https://github.com/spinovation/quarkshield-ai.git`
- **Active Branch**: `main`

> ⚠️ **CRITICAL RULE**: Under NO circumstances should any git push, commit, or sync command touch `Quantum-RAP.git`. All active development, git commits, and pushes belong exclusively inside `desktop-pqc-scanner/` targeting `https://github.com/spinovation/quarkshield-ai.git`.

---

## 2. Production Deployment Target

- **Domain**: `https://quarkshield.ai`
- **Production Server IP**: `13.140.40.99`
- **SSH Target**: `root@13.140.40.99`
- **Server Deployment Path**: `/opt/desktop-pqc-scanner/`
- **Live Ports**:
  - `5050`: Central Super Admin Management Console & API (`quarkshield.ai`)
  - `5000`: Production Web Gateway / Landing Page
  - `5432`: PostgreSQL Database (`quarkshield_scanner`)

> ⚠️ **CRITICAL RULE**: `quarkshield.services` is a separate standalone service. Under NO circumstances should any deployment or script touch `quarkshield.services`. All references and deployments must point exclusively to **`quarkshield.ai` (`13.140.40.99`)**.

### Deployment Procedure
To deploy new code, fixes, or builds to production:
```bash
# 1. Sync files to the production VPS (excluding local build artifacts & git history)
rsync -avz --exclude 'node_modules' --exclude '.git' desktop-pqc-scanner/ root@13.140.40.99:/opt/desktop-pqc-scanner/

# 2. Rebuild and launch containers on production
ssh root@13.140.40.99 "cd /opt/desktop-pqc-scanner && ./deploy.sh"
```

---

## 3. Directory & Subsystem Map

```text
/Users/sridhargs/Documents/Antigravity/Quantum RAP/desktop-pqc-scanner/
├── ui/                              # Frontend Web Application (React 19 + Vite + TypeScript)
│   ├── src/
│   │   ├── App.tsx                  # Main Router, Super Admin Console, Global Fleet view
│   │   ├── components/
│   │   │   ├── LandingPage.tsx      # Public QuarkShield landing page & PQC demo
│   │   │   ├── TenantPortal.tsx     # Isolated Tenant/Partner portal view (subdomain-locked)
│   │   │   ├── AdminPanel.tsx       # Super Admin settings, licenses, tenant registry
│   │   │   ├── SbomInventory.tsx    # CycloneDX 1.6 SBOM Platform Stack inventory
│   │   │   ├── GitRepoAuditor.tsx   # Remote Git cryptographic scanner
│   │   │   └── EnterprisePkiVaults.tsx # PKI & Cloud KMS vault synchronizer
│   │   └── index.css                # Dark cyber-glassmorphism theme
│   └── package.json
│
├── server/                          # Backend API & Orchestration (Express + TypeScript + PostgreSQL)
│   ├── src/
│   │   ├── index.ts                 # Express entrypoint & HTTP server
│   │   ├── config/db.ts             # PostgreSQL pool & automated migrations
│   │   ├── routes/routes.ts         # REST API routes (Fleet, Admin, Auth, SBOM, Ingestion)
│   │   ├── controllers/
│   │   │   ├── fleetController.ts   # Machine registration, heartbeat, token auth, CBOM queries
│   │   │   ├── adminController.ts   # Client onboarding, licenses, users, RBAC
│   │   │   └── sbomController.ts    # CycloneDX 1.6 ingestion & vulnerability scanning
│   │   └── models/schema.sql        # Database schema definitions
│   └── package.json
│
├── agent/                           # Cross-Platform Host Agent (Go native binary)
│   ├── main.go                      # Scanner CLI runner and orchestrator
│   ├── device_id.go                 # Hardware UUID detection (macOS, Linux, Windows)
│   ├── auditor.go                   # Filesystem cryptographic discovery & parsing
│   ├── prober.go                    # Active network TLS socket PQC prober
│   ├── client.go                    # Telemetry ingestion client & local enrollment store
│   └── binaries/                    # Pre-compiled cross-platform agent binaries
│
├── docs/                            # Documentation & Architecture specifications
├── Dockerfile                       # Multi-stage production container build
├── docker-compose.yml               # Production container stack definition
├── deploy.sh                        # Automated deployment script for production VPS
└── README.md                        # Project overview & documentation
```
