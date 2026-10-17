# QSG → Q‑VIKRAM Parity Roadmap

**A path to a software equivalent of C‑DOT Q‑VIKRAM.**

Status: Planning baseline · Owner: QuarkShield · Last updated: 2026‑10‑17
Audience: Product, cryptography engineering, platform engineering, leadership.

---

## 1. Purpose & intent

The original goal of the QuarkShield Quantum Security Gateway (QSG) is to **replicate C‑DOT's Q‑VIKRAM as software, not as an FPGA appliance.** This document states where QSG stands against Q‑VIKRAM today (code‑verified, not design‑intent), separates the gaps into *buildable*, *inherent software‑vs‑hardware*, and *external/formal*, and lays out a phased plan to a sellable "software‑Vikram" — with explicit discipline on what may and may not be *claimed* at each stage.

> Source of truth: the Q‑VIKRAM product page (C‑DOT, Post‑Quantum Cryptography product line) and the QSG implementation as reported against its code and tests (2026‑10‑17). "BUILT" below means an end‑to‑end test exists.

---

## 2. Baseline — what Q‑VIKRAM is

C‑DOT **Q‑VIKRAM**: an **FPGA‑based 1 Gbps post‑quantum network encryptor** (2U appliance).

- **Crypto:** hardware‑accelerated **ML‑KEM‑1024** (FIPS 203, NIST Level 5) key encapsulation + **AES‑256‑GCM** bulk; hybrid session‑key derivation (SP 800‑56C Rev. 2); hardware **TRNG** (SP 800‑90B).
- **Network scope:** **L3 IPsec** (up to 1,024 SAs; point‑to‑point/multipoint/mesh) **and L2 MACsec**.
- **Key sources:** native **PSK** + external **QKD** key feed.
- **Assurance:** side‑channel‑resistant IP cores; strict **Red/Black** hardware isolation; tamper detection; multi‑factor operator auth via **CIK** token + PIN + password; two‑key emergency erase.
- **Positioning:** a pure, hardware‑rooted encryptor for government/defense, L2 DC interconnect, enterprise IPsec VPN, and QKD integration.

It does **not** do posture‑aware access decisions — it is an encryptor.

---

## 3. Positioning — software vs appliance (the deliberate line)

Choosing software over an FPGA appliance is the *point* of QSG, and it has permanent consequences that should be stated to customers as design choices, not defects:

| Dimension | Appliance (Vikram) | Software (QSG) |
|---|---|---|
| Deploy | ship/rack hardware | Linux host, VM, or cloud instance; minutes to deploy; scales horizontally |
| Crypto agility | field‑replace IP cores | signed policy profiles, make‑before‑break |
| Throughput ceiling | fixed wire‑speed FPGA (1 Gbps) | host/CPU‑bound, but elastic |
| Hardware roots of trust | TRNG, SCA cores, Red/Black, tamper/CIK | **approximated** via TPM, enclaves, HSM, process isolation — never identical |
| Intelligence | none (pure encryptor) | **posture‑aware enforcement** (allow/protect/restrict/block) |

**QSG's differentiator over Vikram:** cryptographic **posture‑aware enforcement** plus crypto agility — Vikram encrypts; QSG decides *whether and how* to protect based on the destination asset's crypto exposure, then protects.

---

## 4. Verified closeness matrix (2026‑10‑17)

Legend: ✅ BUILT (tested) · ⚠️ PARTIAL · ❌ NONE · ➕ QSG beyond Vikram

| Capability | Q‑VIKRAM | QSG today (code‑verified) | Status |
|---|---|---|---|
| PQ key establishment | ML‑KEM‑1024 (L5) pure | hybrid X25519MLKEM768 default **+ built‑in pure ML‑KEM‑1024 (L5) TLS profile**; IKE ECP‑384+ML‑KEM‑1024 | ✅ parity option exists |
| Bulk encryption | AES‑256‑GCM | AES‑256‑GCM‑16 (ESP), ML‑KEM PFS per rekey | ✅ |
| L3 IPsec tunnels | IKE/ESP, 1024 SAs, mesh | strongSwan 6.1/XFRM; make‑before‑break, NAT‑T, no‑cleartext nftables guard, per‑SA evidence | ✅ (mesh = pairwise; **1024 SAs untested**) |
| **L2 MACsec** | ✅ | — | ❌ **gap** |
| PQ TLS front door | — | rustls/aws‑lc‑rs TLS 1.3; ML‑DSA‑65 certs; EST/ACME; optional FIPS build | ➕ BUILT |
| PSK ingestion | native PSK | **RFC 8784 PPK** mixed on top of ML‑KEM, rotatable | ✅ (PPK) |
| **QKD ingestion** | ✅ | — (path: feed QKD keys as PPK) | ❌ **gap** |
| IKE authentication | — | ECDSA today; **ML‑DSA‑in‑IKE blocked on upstream strongSwan** | ⚠️ not yet PQ |
| TRNG (SP 800‑90B) | HW | OS CSPRNG + lib DRBG; no SP 800‑90B assessment | ⚠️ software‑inherent |
| Side‑channel resistance | HW cores | relies on AWS‑LC/OpenSSL/strongSwan; unassessed | ⚠️ software‑inherent |
| Red/Black isolation | HW zones | `qsg-keyd` (mlock, no core dumps), process/AppArmor/systemd sandbox, TPM measured‑boot; separate NICs/namespaces | ⚠️ strong software equivalent |
| Tamper / CIK / zeroise | HW | OIDC SSO+MFA + quorum (no CIK); no tamper/erase | ❌ software‑inherent |
| Crypto agility | field‑replace cores | signed profiles + allowlist + make‑before‑break | ➕ BUILT |
| Sovereign algorithms | supported | — (needs a provider/module) | ❌ |
| Posture‑aware enforcement | — | allow/protect/restrict/block by crypto posture | ➕➕ QSG superset |
| Throughput | 1 Gbps wire‑speed | **never measured**; Linux/Docker x86_64 only | ⚠️ unverified |
| Deployment | shipping appliance | Linux (Debian trixie); **not deployed anywhere; cloud/AWS untested** | ❌ pre‑release |

**Read:** the *cryptographic engine* is at or near parity (incl. an ML‑KEM‑1024 Level‑5 option) and tested; QSG exceeds Vikram on intelligence. The true gaps are **MACsec, QKD, PQ‑IKE‑auth, throughput/cloud proof, formal validation,** and the hardware‑rooted assurances that software approximates but cannot equal.

---

## 5. Gap taxonomy

**A. Buildable in software (ours / QSG to close)**
1. **L2 / MACsec** — biggest functional gap (metro/DCI use cases).
2. **QKD key ingestion** — smallest lift: ETSI GS QKD 014 client feeding keys in as PPKs (plumbing exists).
3. **Throughput + cloud/AWS deployment proof** — currently unmeasured, Docker‑only.
4. **SA scale toward 1024**, outbound/transparent proxy mode (Mode A), point‑to‑multipoint at scale.
5. **Sovereign‑algorithm support** — via a crypto provider/module + allowlist extension.

**B. Inherent software‑vs‑hardware (approximate, don't chase to equality; state honestly)**
- TRNG / SP 800‑90B entropy, side‑channel‑resistant cores, physical Red/Black, tamper + CIK + two‑key erase.
- Software stand‑ins: OS/kernel DRBG, TPM measured‑boot + enclaves, HSM‑held keys (pending **PKCS#11 3.2** for ML‑DSA), `qsg-keyd` process isolation, separate NICs/namespaces for plaintext/ciphertext.

**C. External / formal (people + time, gate "government‑grade" claims)**
- **FIPS 140‑3** (CMVP) validation of the module(s); **ML‑DSA in IKE** (upstream strongSwan stable); independent **crypto assessment + pentest**; AWS‑LC FIPS licence legal review; export classification; sovereign/national‑cipher certification.

---

## 6. Phased roadmap

Each phase lists deliverables, dependencies, and — critically — the **claims allowed** at that stage.

### Phase 0 — Prove it runs (now)
- **Deliverables:** stand up one `qsg-control` + gateway on an **AWS EC2 (VPC/segment boundary — the recommended cloud model)**; complete a live posture pull from the QuarkShield control plane for a real tenant (Spinovation); demonstrate a Mode B PQ IPsec tunnel between two gateways with packet‑capture proof of no cleartext.
- **Dependencies:** none external. Token minted by the owner; set directly on the host.
- **Claims allowed:** "post‑quantum hybrid (ML‑KEM) IPsec tunnel, demonstrated in software." **Not** "quantum‑safe," **not** "FIPS‑validated."

### Phase 1 — Encryptor feature parity (software)
- **Deliverables:**
  1. **QKD ingestion** (ETSI GS QKD 014 → PPK) — closes the QKD gap cheaply.
  2. **Throughput/load testing** (10K/100K/1M flows) with published numbers vs Vikram's 1 Gbps reference.
  3. **Cloud/VM/bare‑metal deployment** hardening beyond Docker; packaged installers + SBOM.
  4. **SA‑scale testing** toward 1,024 SAs; multipoint topologies.
- **Dependencies:** QKD device/emulator for test.
- **Claims allowed:** "software PQ encryptor with QKD key integration; measured throughput X Gbps on \<hardware\>."

### Phase 2 — L2 MACsec
- **Deliverables:** L2 MACsec data path (software or kernel `macsec`/`wpa_supplicant`‑based), integrated with the posture/policy and PROTECT model; metro/DCI reference config.
- **Dependencies:** none external; significant engineering.
- **Claims allowed:** "L2 and L3 post‑quantum protection in software."

### Phase 3 — PQ authentication + key custody
- **Deliverables:** **ML‑DSA in IKE** (when upstream strongSwan ships it); **ML‑DSA keys in HSM/TPM** (when **PKCS#11 3.2** support lands); harden `qsg-keyd` custody story.
- **Dependencies:** **upstream** (strongSwan, PKCS#11 3.2) — track, don't block Phases 1–2 on these.
- **Claims allowed:** "fully post‑quantum authenticated IKE; keys held in hardware."

### Phase 4 — Formal assurance
- **Deliverables:** **FIPS 140‑3 (CMVP)** validation of the crypto module(s); independent **crypto assessment + pentest**; SP 800‑90B entropy assessment (document the software/platform entropy story and its limits); AWS‑LC FIPS licence legal review; export classification.
- **Dependencies:** **external** (labs, CMVP, counsel) — long lead; start early.
- **Claims allowed (only after certificates issue):** "FIPS 140‑3 validated"; "assessed by \<lab\>." Never before.

### Phase 5 — Government/sovereign edition
- **Deliverables:** sovereign/national‑cipher provider; hardened operator auth (hardware‑token MFA as the CIK analogue); documented Red/Black NIC/namespace separation; tamper/zeroise software analogues clearly scoped.
- **Claims allowed:** parity statements *scoped to software*, with the hardware‑only assurances explicitly excluded.

---

## 7. QuarkShield platform (control‑plane) work implied

QSG is the **data plane**; QuarkShield is the **control plane**. The current `GET /api/fleet/cbom` posture token is a working *interim* read surface, but the gateway design centers on a **signed, scoped, versioned posture + policy bundle** (not a full CBOM dump). Platform work to be design‑conformant (also the answer to large‑customer egress cost):

1. **Signed/scoped/versioned posture bundle** (expiry/max‑staleness, anti‑rollback, signature key id, tenant/gateway scope) — replaces the unsigned CBOM read; *scoped bundles, not full 7k‑asset dumps.*
2. **Per‑asset + delta posture API** (`/v1/posture/{asset}`, verify) so large tenants aren't force‑fed the whole fleet.
3. **Policy plane** (`/v1/policy/validate`, `/v1/policy/publish`; signed, dual‑approved) + declarative policy schema and signed PROTECT profiles.
4. **Richer posture fields** policy needs: confidence (incl. UNKNOWN), evidence_source/timestamp, crypto_role, business_criticality, pqc_state tri‑state.
5. **Evidence‑ingest endpoints** for gateway events (the *optional* CBOM‑export direction, gateway→CBOM).
6. **Credential separation** (read‑posture vs export identities) + **mTLS** on the gateway channel.

> **Do NOT** add per‑endpoint `ipAddress`/`fqdn`/`certFingerprint` enrichment into the bulk CBOM. The gateway resolves IP→asset **locally** and matches by asset_id/tag; IP from the control plane, if offered, is an optional *correlation hint* via a scoped/delta feed — which also protects egress cost.

---

## 8. Claims discipline (applies to every stage)

- Never say **"quantum‑safe," "quantum‑proof,"** or **"FIPS 140‑3 validated"** until the corresponding certificate exists. Say "post‑quantum hybrid (ML‑KEM)" and name the protocol negotiated.
- State **which path segments** a PROTECT action covers; never imply end‑to‑end protection the gateway didn't negotiate.
- Treat **UNKNOWN** crypto posture as explicitly not‑safe, with a deterministic policy outcome.
- When comparing to Vikram, scope parity claims to **software**, and list the hardware‑only assurances as *out of scope by design*.

---

## 9. Recommended sequence (one line)

**Phase 0 (prove it on AWS now) → QKD + throughput/cloud proof → MACsec → PQ‑IKE‑auth/HSM (as upstream lands) → FIPS & assessment (start early, lands last).** The crypto engine is already real; the roadmap is about *scope, proof, and credentials* — not inventing the cryptography.
