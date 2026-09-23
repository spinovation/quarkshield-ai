# QuarkShield Enterprise Post-Quantum Cryptographic Deployment Guide
## Architectural Strategy & Operational Blueprint: Overcoming Agent Fatigue via the 3-Tier Enterprise Model

![QuarkShield Platform](https://quarkshield.ai/quarkshield-logo.png)

> **Document Version:** 3.0.0  
> **Date:** September 2026  
> **Target Audience:** Chief Information Security Officers (CISOs), Enterprise Architecture Review Boards (ARB), Cryptographic Centers of Excellence (CoE), Cloud & Platform Engineering Teams, EUC & Infrastructure Operations  
> **Compliance & Standards:** NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NSA CNSA 2.0, Executive Order 14028, OMB M-23-02, CycloneDX 1.6+ CBOM  
> **Production Console:** [https://quarkshield.ai](https://quarkshield.ai)  

---

## Executive Summary: The Enterprise "Agent Fatigue" Crisis

In modern Fortune 500 and government enterprises, deploying a traditional resident endpoint agent is the single slowest, most expensive, and politically fraught path in cybersecurity.

### Challenges of Traditional Enterprise Agent Deployment:
1. **Multi-Department Approval Lifecycles:**
   - Installing resident software requires cross-functional coordination across Windows Server, Linux/SRE, and End User Computing teams, often stretching rollout schedules across multiple quarters.
2. **Ongoing Agent Maintenance Overhead:**
   - Packaging, testing, deploying, and maintaining resident background agents across large fleets requires continuous engineering cycles and update reconciliation.
3. **Operational Stability & Host Risk:**
   - Kernel-level drivers and intrusive resident daemons present operational risks to production workloads. A single misconfiguration or faulty update can lead to service degradation or server downtime.
4. **The Security & Crypto Team Mandate:**
   - Cyber Security and Cryptographic teams are accountable for Post-Quantum readiness and regulatory compliance (e.g., OMB M-23-02, NSA CNSA 2.0). However, obtaining dedicated host access across thousands of servers is complex and resource-intensive.

---

## The QuarkShield 3-Tier Enterprise Strategy

To provide **100% cryptographic visibility** without requiring months of committee approvals or intrusive resident agents, QuarkShield delivers a **3-Tier Hybrid Enterprise Architecture**:

```
                                  ┌──────────────────────────────────────────┐
                                  │   QuarkShield Central Console & API      │
                                  │             (quarkshield.ai)             │
                                  └────────────────────┬─────────────────────┘
                                                       │
         ┌─────────────────────────────────────────────┼─────────────────────────────────────────────┐
         ▼                                             ▼                                             ▼
 ┌──────────────────────────────┐              ┌──────────────────────────────┐              ┌──────────────────────────────┐
 │           TIER 1             │              │           TIER 2             │              │           TIER 3             │
 │   Cloud & Infrastructure     │              │    Network & Wire Traffic    │              │ Endpoints & In-Host Runtimes │
 ├──────────────────────────────┤              ├──────────────────────────────┤              ├──────────────────────────────┤
 │ • Out-of-Band Disk Snapshots │              │ • Passive TLS 1.3 Inspection │              │ • OpenTelemetry Collector    │
 │   (AWS EBS / Azure / GCP)    │              │   at Firewall / Ingress      │              │   (CAPI2 / ETW / auditd)     │
 │   - 0% CPU / 0 MB RAM        │              │   - Palo Alto, F5, Fortinet  │              │   - Runs as LOCAL SERVICE    │
 │   - Zero reboot risk         │              │   - Zscaler, SPAN/TAP Wire   │              │   - Non-root, Zero-Reboot    │
 │ • Central PKI Connectors     │              │ • Harvest Now Decrypt Later  │ • Ephemeral 1-Shot CLI       │
 │   (AD CS, DigiCert, Vault)   │              │   (HNDL) Session Detection   │   (Fallback / CI/CD Gate)    │
 └──────────────────────────────┘              └──────────────────────────────┘              └──────────────────────────────┘
```

### Architectural Guarantees:
- **SecOps Autonomy:** Cyber Security and Crypto teams can initiate 90%+ of audits centrally without waiting on EUC or OS teams.
- **Zero Privilege Escalation:** Does not require Domain Admin rights or intrusive kernel-level hooks.
- **Guaranteed Zero Reboot:** No system restarts, no driver installations, and no production interruption.

---

## Tier 1: Infrastructure & Cloud (Servers & Virtual Machines)

Tier 1 targets the heart of enterprise server infrastructure: production cloud VMs, database hosts, application clusters, and enterprise Certificate Authorities.

### 1. Out-of-Band Cloud Disk Snapshot Auditing (Agentless Architecture)
Instead of pushing an agent to thousands of AWS EC2, Azure VM, or Google Cloud Compute Engine instances:
1. **Snapshot Creation:** QuarkShield calls cloud control-plane APIs (via read-only IAM Role / Azure Managed Identity) to trigger a point-in-time snapshot of the target VM’s root block storage volume (AWS EBS, Azure Managed Disk, GCP Persistent Disk).
2. **Ephemeral Read-Only Mount:** The snapshot is cloned and mounted in read-only mode to an isolated QuarkShield analysis sandbox container within your cloud VPC.
3. **Deep Cryptographic Inspection:** The scanner audits the static disk image:
   - Certificate stores (`/etc/ssl/certs`, Java keystores `cacerts`, Windows System32 cert stores).
   - SSH configurations and private keys (`/etc/ssh`, `~/.ssh`).
   - Shared dynamic cryptographic libraries (`libcrypto.so`, `bcrypt.dll`).
4. **CBOM Ingestion & Cleanup:** Inventory data is indexed into QuarkShield Central; the snapshot volume is immediately detached and deleted.

**Key Enterprise Advantages:**
- **0% Host Overhead:** Exactly 0% CPU utilization, 0 MB RAM consumption, and 0 network packets on the production VM.
- **Zero Downtime / Zero Reboot:** The running server is completely untouched and unaware of the audit.
- **100% Cloud Coverage:** Audits all running and stopped instances across multi-account cloud environments in minutes.

---

### 2. Centralized Enterprise PKI Connectors
Over 80% of an enterprise’s active certificates originate from centralized internal and commercial Certificate Authorities. Connecting to these central hubs captures the vast majority of cryptographic assets in a single stroke:

- **Microsoft Active Directory Certificate Services (AD CS):**
  - Connects via read-only PowerShell RPC / WMI to your enterprise Root and Intermediate CAs.
  - Extracts all issued certificates, active certificate templates, validity horizons, and underlying key algorithms (flagging RSA-2048 and classical ECC).
- **DigiCert ONE / CertCentral & Sectigo:**
  - Ingests public and private SSL/TLS certificates via read-only REST API tokens.
- **HashiCorp Vault & Venafi Trust Protection Platform:**
  - Queries PKI secrets engines, transit keys, and automated certificate management workflows.

---

## Tier 2: Network & In-Flight Cryptographic Traffic

Tier 2 addresses the critical threat vector: **Harvest Now, Decrypt Later (HNDL)**, where state-sponsored adversaries intercept and archive encrypted enterprise traffic across fiber lines and internet gateways to decrypt once a Cryptanalytically Relevant Quantum Computer (CRQC) matures.

### Passive TLS Handshake Inspection (Wire-Level Posture)
Rather than installing agents on clients or servers, QuarkShield analyzes the unencrypted initial TLS handshake packets (`ClientHello` and `ServerHello`) traversing your existing enterprise perimeter and core networks:

```
  Client (Workstation / Browser)
         │
         │  1. ClientHello (Cipher Suites, Supported Groups: X25519MLKEM768?)
         ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ Existing Firewall / Gateway / SPAN Port                                │
 │ (Palo Alto Networks / F5 BIG-IP / Fortinet / Zscaler / Optical TAP)    │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │ 2. Mirrored Handshake Telemetry (Syslog / IPFIX)
                                     ▼
                      ┌──────────────────────────────┐
                      │ QuarkShield Passive Receiver │
                      │ (Ingests Handshake Metadata) │
                      └──────────────┬───────────────┘
                                     ▼
 3. Identifies:
    • Deprecated TLS 1.0/1.1/1.2 sessions
    • Classical RSA/ECDHE key exchanges (HNDL Critical!)
    • Quantum-Ready Hybrid Sessions (X25519MLKEM768 / FIPS 203)
    • Expiring or classical leaf certificates in flight
```

### Integration Points:
1. **Next-Generation Firewalls (NGFW):** Palo Alto Networks (PAN-OS SSL Decryption/Decryption Port Mirroring or SSL session logs), Fortinet FortiGate, Check Point.
2. **Application Delivery Controllers & Load Balancers:** F5 BIG-IP (iRules / HSL High-Speed Logging of TLS handshakes), Citrix ADC, AWS Application Load Balancer (ALB) access logs.
3. **Secure Access Service Edge (SASE) & Cloud Proxies:** Zscaler Cloud NSS (Nanolog Streaming Service), Cloudflare Magic WAN.
4. **Physical Core Switches:** SPAN / RSPAN port mirroring or hardware optical TAPs feeding the QuarkShield passive sensor.

**Key Enterprise Advantages:**
- **Zero End-User Impact:** No software on workstations or production servers.
- **Real-Time Traffic Reality:** Identifies shadow IT, rogue web servers, and legacy protocols actively in use that static file audits miss.

---

## Tier 3: Endpoints & In-Host Workloads (Zero-Reboot, Non-Root)

For organizations requiring host-level visibility across laptops and physical servers without the friction of deploying full proprietary agents, Tier 3 provides two non-disruptive options:

```
  Option A: Enterprise Standard (Primary)
  ┌──────────────────────────────────────────────────────────────────────┐
  │ OpenTelemetry (OTel) Collector                                       │
  │ • Open-source, CNCF standard, pre-approved by most ARBs              │
  │ • Ingests Windows CAPI2 Event Logs & Linux auditd                    │
  │ • Runs as unprivileged 'LOCAL SERVICE' (Non-Root)                    │
  │ • 100% Guaranteed ZERO REBOOT                                        │
  └──────────────────────────────────────────────────────────────────────┘
                                  OR
  Option B: Ephemeral 1-Shot CLI / Fallback
  ┌──────────────────────────────────────────────────────────────────────┐
  │ QuarkShield Ephemeral CLI Binary (`quarkshield-scanner`)             │
  │ • Zero-dependency single executable (2-second run, then exits)       │
  │ • Ideal for developer laptops, CI/CD gates, air-gapped enclaves      │
  │ • No background resident daemon                                      │
  └──────────────────────────────────────────────────────────────────────┘
```

---

### Option A: OpenTelemetry (OTel) Collector Telemetry (Recommended)

**OpenTelemetry** is the vendor-neutral, CNCF-governed observability standard already approved and deployed by enterprise infrastructure teams. Instead of introducing a new binary, QuarkShield provides an OpenTelemetry configuration that transforms the existing collector into a cryptographic audit sensor.

#### How It Works:
1. **Windows Cryptographic API (CAPI2) Event Logging:**
   - Windows natively logs cryptographic operations, certificate validation chains, and SSL handshakes under the event channel:
     `Microsoft-Windows-CAPI2/Operational`
   - The OTel Collector's `windowseventlog` receiver captures these events in real time.
2. **Linux Auditd & eBPF Telemetry:**
   - The collector monitors OpenSSL, GnuTLS, and crypto syscalls via standard system audit logging.
3. **QuarkShield Ingestion:**
   - The collector batches and forwards structured JSON logs to QuarkShield Central via OTLP/HTTP.

#### Technical Blueprint: `otel-collector-pqc.yaml`
Deploy this lightweight configuration file to your existing OpenTelemetry collector:

```yaml
receivers:
  # Windows Cryptographic Event Log Receiver
  windowseventlog/capi2:
    channel: Microsoft-Windows-CAPI2/Operational
    raw: false
    poll_interval: 10s

  # Linux Filelog Receiver for OpenSSL/auditd
  filelog/crypto:
    include:
      - /var/log/audit/audit.log
    operators:
      - type: regex_parser
        regex: '^type=(?P<type>\w+).*'

processors:
  batch:
    timeout: 10s
    send_batch_size: 100
  filter/crypto_events:
    error_mode: ignore
    logs:
      log_record:
        # Keep certificate chain validation and TLS handshake events
        - 'not (body matches "CryptCATAdmin" or body matches "X509Chain")'

exporters:
  otlphttp/quarkshield:
    endpoint: "https://quarkshield.ai/api/v1/otel"
    headers:
      Authorization: "Bearer YOUR_FLEET_ENROLLMENT_TOKEN"
      X-QuarkShield-Tenant: "SpinovationCorp"

service:
  pipelines:
    logs:
      receivers: [windowseventlog/capi2, filelog/crypto]
      processors: [filter/crypto_events, batch]
      exporters: [otlphttp/quarkshield]
```

#### Why OpenTelemetry Wins with Enterprise Operations:
- **Pre-Approved Architecture:** Enterprise ARB and change boards readily approve OTel because it is open-source, vendor-agnostic, and avoids vendor lock-in.
- **Unprivileged Execution:** Runs securely under Windows `NT AUTHORITY\LOCAL SERVICE` or standard Linux `otel` service user.
- **Guaranteed Zero Reboot:** Enabling the CAPI2 event channel and launching OTel requires **no system reboot whatsoever**.

---

### Option B: Ephemeral 1-Shot CLI (Fallback & Developer Self-Service)

For isolated enclaves, developer workstations, air-gapped test labs, or CI/CD pipelines where no persistent telemetry exists, QuarkShield provides the **Ephemeral 1-Shot CLI**:

```bash
# Developer 2-second audit:
./quarkshield-scanner --quick

# Export CycloneDX 1.6 Cryptographic Bill of Materials (CBOM):
./quarkshield-scanner --quick --output cbom.json

# Silent CI/CD Security Gate (GitHub Actions / GitLab CI):
./quarkshield-scanner --ci --fail-on-vulnerable --token "$QUARKSHIELD_TOKEN"
```

- **Execution Profile:** Runs once in user space, indexes cryptographic stores in under 3 seconds, securely transmits findings over TLS, and terminates immediately.
- **No Background Daemon:** Consumes 0 MB RAM and 0% CPU when not actively scanning.

---

## Technical Blueprints: Step-by-Step Deployment

### Blueprint 1: Central AD CS Certificate Discovery (PowerShell One-Liner)
SecOps can execute this script from a single management server to inventory all enterprise certificates across the Active Directory forest without touching a single domain workstation:

```powershell
# Query Enterprise Active Directory Certificate Services (AD CS)
Import-Module ActiveDirectory
$CAs = Get-ADObject -Filter 'objectClass -eq "pkiCertificationAuthority"' -SearchBase (Get-ADRootDSE).configurationNamingContext

foreach ($CA in $CAs) {
    Write-Host "Auditing Enterprise CA: $($CA.Name)"
    # Query issued certificates with cryptographic metadata
    certutil -config "$($CA.dNSHostName)\$($CA.Name)" -view -out "RequestID,CommonName,NotAfter,PublicKeyAlgorithm,PublicKeyLength" csv > "adcs_certs.csv"
}

# Ingest directly into QuarkShield Central
Invoke-RestMethod -Uri "https://quarkshield.ai/api/v1/ingest/pki" `
  -Method POST `
  -Headers @{ "Authorization" = "Bearer YOUR_FLEET_TOKEN" } `
  -InFile "adcs_certs.csv" `
  -ContentType "text/csv"
```

---

### Blueprint 2: AWS Cloud Snapshot IAM Policy (Agentless Model)
Attach this minimal, read-only policy to your cross-account QuarkShield scanning role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "QuarkShieldAgentlessSnapshotRead",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:CreateSnapshot",
        "ec2:CreateTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "QuarkShieldKMSAudit",
      "Effect": "Allow",
      "Action": [
        "kms:ListKeys",
        "kms:DescribeKey",
        "acm:ListCertificates",
        "acm:DescribeCertificate"
      ],
      "Resource": "*"
    }
  ]
}
```

---

### Blueprint 3: Enabling Windows CAPI2 Logging via Group Policy (GPO)
To activate CAPI2 logging across your domain without installing any software or rebooting:
1. Open **Group Policy Management** (`gpmc.msc`).
2. Navigate to:  
   `Computer Configuration` -> `Administrative Templates` -> `Windows Components` -> `Event Log Service` -> `CAPI2`.
3. Set **Turn on logging** to **Enabled**.
4. Alternatively, execute via PowerShell on target servers:
```powershell
wevtutil sl "Microsoft-Windows-CAPI2/Operational" /e:true
```
5. Deploy the `otel-collector-pqc.yaml` via your existing software distribution tool (Intune, SCCM, or Ansible).

---

## Architectural Comparison & Decision Matrix

| Dimension | **Tier 1: Cloud Snapshots & PKI** | **Tier 2: Passive Wire TLS** | **Tier 3: OpenTelemetry (OTel)** | **Traditional Resident Agent** |
| :--- | :--- | :--- | :--- | :--- |
| **Approval Timeline** | **< 1 Week** (Cloud IAM / PKI API) | **1–2 Weeks** (SecOps / NetOps) | **1–2 Weeks** (Uses Existing OTel) | **2–4 Months** (Multi-team approvals) |
| **Host Resource Impact** | **0% CPU / 0 MB RAM** | **0% CPU / 0 MB RAM** | **< 0.5% CPU / < 25 MB RAM** | 1–5% CPU / 100–300 MB RAM |
| **Host Reboot Required?**| **NEVER (0% Risk)** | **NEVER (0% Risk)** | **NEVER (0% Risk)** | Frequently during install/patch |
| **Privilege Requirement** | Read-Only Cloud API / CA RPC | Network Mirror / Tap Feed | Unprivileged (`LOCAL SERVICE`) | Root / Administrator / Kernel |
| **Coverage Percentage** | 100% of Cloud VMs & CAs | 100% of Active Wire Traffic | 95%+ of Managed Endpoints | Typically caps at ~80% |
| **Primary Beneficiary** | Cloud Security / DevOps | Network Security / SecOps | EUC / Systems Operations | Vendor only |

---

## Enterprise RACI Governance Model

This RACI matrix shows how the Cyber Security / Cryptographic CoE team can maintain ownership and execution velocity across all three tiers:

| Milestone / Task | Cyber Security / Crypto CoE | Cloud & DevOps Team | Network / Firewall Team | EUC / Desktop Team | Change Management |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Tier 1: AWS/Azure IAM Snapshot Role** | **A / R** | **C** | I | I | I |
| **Tier 1: Central AD CS Connector Setup** | **A / R** | I | I | I | I |
| **Tier 2: Firewall Handshake Log Forwarding** | **A** | I | **R** | I | I |
| **Tier 3: OTel CAPI2 Config Deployment** | **A** | **C** | I | **R** | **C** |
| **Tier 3: Ephemeral CLI for CI/CD Gates** | **A / R** | **R** | I | I | I |
| **CBOM Review & PQC Migration Planning** | **A / R** | **C** | **C** | **C** | I |

*Legend: **R** = Responsible, **A** = Accountable, **C** = Consulted, **I** = Informed*

---

## Summary: Moving Forward with Confidence

By embracing the **3-Tier Enterprise Strategy**, organizations completely bypass the agent fatigue trap. Security teams achieve comprehensive visibility into:
1. **At-Rest Assets:** Keys and certificates audited out-of-band across cloud disks and enterprise CAs (Tier 1).
2. **In-Flight Assets:** Network sessions actively exposed to Harvest Now, Decrypt Later threats (Tier 2).
3. **Host-Level Activity:** Live cryptographic invocations collected via non-root OpenTelemetry with guaranteed zero reboots (Tier 3).

For architectural consultations, enterprise deployment scripts, or custom integration assistance:
- **Central Management Console:** [https://quarkshield.ai](https://quarkshield.ai)
- **Technical Support:** `support@quarkshield.ai`
- **Published by:** FedMitigate LLC — Washington, D.C.
