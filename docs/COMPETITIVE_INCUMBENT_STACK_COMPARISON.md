# QuarkShield vs the Incumbent Security Stack

**Answering "don't we already have this with Qualys / ArcSight / Venafi?"**

Status: Competitive positioning · Owner: QuarkShield · Last updated: 2026-10-22
Companion to [SUPERADMIN_SBOM_AND_COMPETITIVE_ANALYSIS.md](SUPERADMIN_SBOM_AND_COMPETITIVE_ANALYSIS.md) (which compares the **PQC-native** field: SandboxAQ, IBM Quantum Safe, QuSecure). This doc compares against the tools a customer **already owns**.

---

## 1. The framing

Prospects rarely own a PQC tool, but they almost always own a **vulnerability manager**, a **SIEM**, and often a **certificate / machine-identity** platform. The objection is "isn't this already covered?" It isn't — but *why* it isn't differs by category, so the honest answer is **"we complement two of these and go broader than the third."**

| Category | Representative tools | What they actually do | Relationship to QuarkShield |
|---|---|---|---|
| **SIEM** | ArcSight (OpenText), Splunk ES | Log/event collection + correlation, SOC detection & response | **Complementary** — no crypto discovery; ingest QuarkShield's CBOM/evidence |
| **Vulnerability Mgmt** | Qualys (VMDR/CertView), Tenable (Nessus) | CVE scanning, asset inventory, some TLS/cert & weak-cipher checks | **Complementary** — CVE breadth QuarkShield doesn't replace; no CBOM/PQC migration |
| **Machine Identity / PKI** | Venafi (CyberArk), Keyfactor | Certificate & key **lifecycle** (discovery → issuance → renewal), now adding PQC cert-agility & (Keyfactor) crypto-posture | **Real overlap, different anchor** — PKI/cert-centric & enterprise-heavy; QuarkShield is broader crypto-agility + enforcement |

> **Honest guardrail (so reps don't get burned):** Venafi/CyberArk and Keyfactor have shipped genuine PQC capability — PQC/hybrid certificate issuance, crypto-agility, and (Keyfactor, via its InfoSec Global + CipherInsights acquisitions) cryptographic **posture** management with endpoint and network visibility. Do **not** claim they "have no PQC." The accurate claim is about **scope and anchor**: they are certificate/PKI platforms extending into crypto-agility; QuarkShield is a crypto-agility *platform* (CBOM + SBOM + code + config + network + CI/CD + an active PQC enforcement data plane) that is lightweight and fast to deploy. Likewise QuarkShield does **not** replace a SIEM, does **not** match Qualys/Tenable CVE breadth, and does **not** do full CA issuance/renewal automation at Venafi/Keyfactor scale.

---

## 2. Feature-by-feature matrix

Legend: ✅ native/strong · ⚠️ partial/add-on/adjacent · ❌ not a function of the product

| Dimension | **QuarkShield** | Qualys | Tenable | ArcSight / Splunk | Venafi (CyberArk) | Keyfactor |
|---|---|---|---|---|---|---|
| **Primary purpose** | PQC crypto-agility: CBOM+SBOM, discovery, migration & enforcement | Vulnerability management | Vulnerability management | SIEM / log analytics | Machine-identity & cert lifecycle | PKI & cert lifecycle |
| **Cryptographic BOM (CycloneDX CBOM)** | ✅ Native 1.6 | ❌ | ❌ | ❌ | ⚠️ cert/key-centric inventory, not unified CBOM | ⚠️ crypto-posture inventory (post-acquisition), PKI-anchored |
| **Crypto discovery scope** (certs / keys / algorithms / TLS config / code deps / network / git) | ✅ All of these | ⚠️ Certs + TLS/weak-cipher (CertView) | ⚠️ Certs + weak-crypto plugins | ❌ | ⚠️ Certs/keys + network | ⚠️ Certs/keys + endpoint & network (CipherInsights) |
| **Quantum-vulnerability assessment** (Shor/Grover, HNDL) + grading | ✅ Per-asset + Quantum Risk Rating | ❌ | ❌ | ❌ | ⚠️ PQC-readiness framing | ⚠️ PQC-readiness framing |
| **PQC migration roadmap & prioritization** | ✅ A–F grade + what-breaks impact | ❌ | ❌ | ❌ | ⚠️ cert-migration focus | ⚠️ cert-migration focus |
| **Software SBOM + dependency CVE scanning** | ✅ npm/PyPI/Go/OS packages | ✅ (CVE; separate from crypto) | ✅ (CVE) | ❌ | ❌ | ❌ |
| **CI/CD crypto policy gate** (block PRs) | ✅ GitHub/GitLab/Bitbucket | ⚠️ via API | ⚠️ via API | ❌ | ❌ | ⚠️ signing/policy integrations |
| **Certificate *lifecycle* automation** (issuance/renewal at scale) | ⚠️ Discovery + PKI/KMS connectors + hybrid proxy (not full CA automation) | ⚠️ Inventory/expiry (CertView) | ⚠️ Expiry alerts | ❌ | ✅✅ Core strength | ✅✅ Core strength (EJBCA) |
| **Active PQC enforcement** (hybrid TLS proxy / gateway tunnels) | ✅ Hybrid TLS proxy + QSG gateway (ML-KEM/IPsec) | ❌ | ❌ | ❌ | ⚠️ cert automation, not a PQC data plane | ⚠️ cert automation, not a PQC data plane |
| **Hybrid / PQC certificate issuance** | ⚠️ via connected PKI | ❌ | ❌ | ❌ | ✅ | ✅ (hybrid RSA/ML-DSA, HSM) |
| **General CVE / vuln management** | ⚠️ dependency CVEs only | ✅✅ | ✅✅ | ❌ | ❌ | ❌ |
| **SIEM / log correlation** | ❌ (exports evidence to SIEM) | ❌ | ❌ | ✅✅ | ❌ | ❌ |
| **Deployment footprint** | ✅ <15 MB agent / agentless / container | ⚠️ SaaS + cloud agents | ⚠️ Scanners/agents | ⚠️ Heavy SIEM infra | ⚠️ Enterprise control plane | ⚠️ Enterprise control plane |
| **Time to initial value** | ✅ <5 min (URL scan / 1-line agent) | ⚠️ Days–weeks | ⚠️ Days–weeks | ❌ Weeks–months | ⚠️ Weeks–months | ⚠️ Weeks–months |
| **Relationship to QuarkShield** | — | Complement | Complement | Complement | Overlap (narrower anchor) | Overlap (narrower anchor) |

---

## 3. Battlecard — objection handling

**"We already run Qualys / Tenable."**
Those find CVEs and flag some weak TLS/certs — they don't produce a **cryptographic bill of materials**, don't assess **quantum** exposure (Shor/Grover/HNDL), and don't give you a **PQC migration roadmap** or an **enforcement** path. QuarkShield sits alongside them and fills the crypto-agility gap; it even exports findings your VM/SIEM can consume.

**"We already run ArcSight / Splunk."**
That's your SIEM — detection and response on logs. It has **zero** cryptographic discovery. QuarkShield is the *source* of crypto posture and enforcement evidence that flows *into* the SIEM. Not a replacement in either direction.

**"We already use Venafi / CyberArk or Keyfactor."**
The strongest overlap — and worth respecting: they're excellent at **certificate and key lifecycle**, and they're real on PQC/hybrid cert issuance and crypto-agility. But they're **PKI/certificate-anchored and enterprise-heavy**. QuarkShield goes **broader than certificates** — algorithms in **code dependencies, host configs, network handshakes, and SBOM** — adds a **CI/CD merge gate** and an **active PQC enforcement data plane** (hybrid TLS + the QSG gateway), and deploys in minutes. The honest positioning is **"use them for cert lifecycle; use QuarkShield for whole-estate crypto agility, PQC readiness, and enforcement — and feed each other."** For a greenfield buyer who doesn't already own one, QuarkShield covers the crypto-discovery + PQC-migration job at a fraction of the deployment weight.

---

## 4. One-line summary

- **SIEM & VM (ArcSight/Splunk, Qualys/Tenable):** complementary — they don't do CBOM/PQC; QuarkShield feeds and augments them.
- **Machine-identity/PKI (Venafi/CyberArk, Keyfactor):** genuine overlap on crypto-agility, but anchored on certificate lifecycle; QuarkShield is broader (code/config/network/SBOM + CI/CD + enforcement) and lighter-weight.
- **QuarkShield's defensible lane:** the only platform combining **CBOM + SBOM + full-estate crypto discovery + PQC grading/roadmap + CI/CD gate + an active PQC enforcement gateway** in one lightweight, fast-to-deploy product.

---

## 5. Sources & claims discipline

Capabilities evolve quickly — re-verify before external use. Grounding for the incumbent PQC claims (2025–2026):
- Keyfactor PQC / crypto-posture (InfoSec Global + CipherInsights acquisitions): https://www.keyfactor.com/press-releases/keyfactor-accelerates-enterprise-post-quantum-readiness-and-crypto-agility-amid-shrinking-certificate-lifespans/ and https://thequantuminsider.com/2025/04/23/keyfactor-expands-post-quantum-security-capabilities-across-its-cryptographic-solutions-portfolio/
- Venafi / CyberArk PQC & machine identity: https://www.cyberark.com/resources/white-papers/from-risk-to-readiness-identity-security-in-the-post-quantum-era and https://www.cyberark.com/press/venafi-unveils-new-product-capabilities-to-help-organizations-prepare-for-a-multi-cloud-and-post-quantum-future/
- ABI Research crypto-agility / CA-agility market (lists CyberArk, Keyfactor, Entrust, DigiCert): https://www.abiresearch.com/market-research/product/7787229-crypto-agility-and-certificate-authority-a

Not independently verified here: Qualys CertView's current PQC/cert-assessment feature set, and Tenable's exact crypto-plugin coverage — marked ⚠️ conservatively. Keep all competitor claims category-level and defensible; avoid absolute "they can't do X" statements where the vendor markets X.
