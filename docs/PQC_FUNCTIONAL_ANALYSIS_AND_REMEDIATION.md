# 🧠 QuarkShield Cryptographic Functional Analysis & Precision Remediation Engine
**Technical Specification: Decoupling PQC Readiness into Function, Threat Urgency, and NIST Standards**

---

## Executive Summary

A critical shortcoming of legacy vulnerability scanners is treating all classical cryptography (such as RSA-2048 or ECDSA P-256) as a single monolithic threat. In reality, **Post-Quantum Cryptography (PQC) readiness consists of two fundamentally distinct cryptographic problems with drastically different threat timelines**:

1. **Confidentiality & Key Establishment** $\rightarrow$ **Threat: Harvest Now, Decrypt Later (HNDL)** $\rightarrow$ **Standard: NIST FIPS 203 (ML-KEM)**
   * *Urgency*: **IMMEDIATE (Priority 1 — Critical Red Alert)**.
   * *Reasoning*: Adversaries and nation-states are intercepting and archiving encrypted network traffic and confidential payloads **today**. When a Cryptographically Relevant Quantum Computer (CRQC) becomes operational, all recorded traffic encrypted with classical key exchanges will be retroactively decrypted.
2. **Authenticity, Integrity & Digital Signatures** $\rightarrow$ **Threat: Quantum Signature Forgery (Shor's Algorithm)** $\rightarrow$ **Standard: NIST FIPS 204 (ML-DSA) & FIPS 205 (SLH-DSA)**
   * *Urgency*: **PLANNED MIGRATION (Priority 2 — High Yellow/Orange Alert)**.
   * *Reasoning*: An attacker recording a digital signature today *cannot* retroactively alter historical documents, past signed code, or past TLS sessions. The threat only activates *after* a CRQC exists, at which point the attacker can forge new signatures, mint fraudulent certificates, and execute real-time Man-in-the-Middle (MitM) impersonations.

---

## 1. The PQC Functional Cryptographic Matrix

The QuarkShield Cloud Fleet and Host Agent classify every discovered cryptographic asset (such as `RTC.der`, PEM keys, TLS endpoints, and SSH configurations) against this matrix:

| Cryptographic Function | Current Classical Tech | Target PQC Replacement | HNDL Concern & Threat Urgency | Primary NIST Standard |
| :--- | :--- | :--- | :--- | :--- |
| **Key Establishment / Encryption** | RSA Key Exchange, RSA-OAEP, Diffie-Hellman | **ML-KEM (Kyber-768 / 1024)** | 🚨 **MAJOR IMMEDIATE HNDL CONCERN**<br/>(Traffic captured today can be decrypted tomorrow) | **NIST FIPS 203** |
| **TLS Key Exchange (In-Transit)** | ECDHE (X25519, P-256), RSA KEX | **Hybrid ECDHE + ML-KEM**<br/>(`X25519MLKEM768`) | 🚨 **CRITICAL FOR HNDL**<br/>(Immediate migration mandatory for all sensitive egress) | **NIST FIPS 203** |
| **Authentication / Digital Signature** | RSA-2048/4096, ECDSA, Ed25519 | **ML-DSA (Dilithium-3/5)**<br/>or **SLH-DSA (SPHINCS+)** | ⚠️ **Vulnerable in future to Shor's**<br/>(No retroactive HNDL decryption; future forgery risk) | **NIST FIPS 204 / 205** |
| **X.509 Certificates & CAs** | RSA / ECDSA Leaf & CA Certificates | **ML-DSA / Hybrid Composite Certs** | ⚠️ **Migration required prior to CRQC**<br/>(Prevents CA spoofing and rogue cert generation) | **NIST FIPS 204** |
| **Symmetric Bulk / Session Encryption** | AES-128 / AES-256, ChaCha20 | **AES-256-GCM / ChaCha20** | ℹ️ **Usually not immediate issue**<br/>(AES-256 retains 128-bit quantum margin under Grover's) | **NSA CNSA 2.0** |

---

## 2. Case Study: Deep Analysis of `RTC.der`

When the QuarkShield desktop scanner audits `RTC.der` (or any X.509 certificate file), a surface-level scan merely reports:
> *"Vulnerable RSA-2048 certificate. Upgrade to post-quantum certificate."*

This is insufficient for enterprise engineering teams. **QuarkShield Cloud Fleet performs deep X.509 Key Usage & Function Triaging**:

### Step 1: X.509 Key Usage & Extended Key Usage (EKU) Dissection
By inspecting the certificate's RFC 5280 metadata:
* **Key Usage Flags**:
  * `KeyEncipherment` / `DataEncipherment` / `KeyAgreement`:
    * If present: The certificate is utilized for **Key Establishment & Confidentiality**.
    * **QuarkShield Verdict**: 🚨 **CRITICAL HNDL RISK**. If used in real-time communications (WebRTC, VoIP, SIP, or video conferencing), adversaries recording the encrypted RTP/SRTP session key exchange can decrypt the recorded communications in the future.
    * **Remediation**: Transition session key exchange to **NIST FIPS 203 (ML-KEM-768)** or hybrid KEM.
  * `DigitalSignature` / `NonRepudiation` / `CertificateSign`:
    * If present: The certificate is utilized purely for **Identity Verification, Authentication, or Code/Firmware Signing**.
    * **QuarkShield Verdict**: ⚠️ **FUTURE SHOR'S FORGERY RISK**. The recorded communications cannot be decrypted through this certificate. The risk is that an attacker with a future quantum computer could impersonate the WebRTC server or sign malicious software.
    * **Remediation**: Transition signing keys to **NIST FIPS 204 (ML-DSA)**.

---

## 3. Cloud Fleet Precision Remediation Engine

When QuarkShield Cloud Fleet auto-generates remediation code snippets or playbooks, it avoids generic advice and produces **function-specific, copy-pasteable engineering implementations**:

### Scenario A: Remediation for Key Establishment Assets (Target: FIPS 203 ML-KEM)
* **Trigger**: Asset has `KeyEncipherment`, `KeyAgreement`, or is a TLS/KEX server configuration.
* **Auto-Generated Code Snippet (Spring Boot / Java with `pqc-starter-lib`)**:
  ```java
  // QuarkShield Auto-Generated Remediation: NIST FIPS 203 ML-KEM Hybrid Exchange
  @Autowired
  private HybridHandshakeOrchestrator pqcHandshake;

  // Protects data-in-transit against Harvest Now, Decrypt Later (HNDL)
  HandshakeSession session = pqcHandshake.establishHybridSession("target-service");
  byte[] sharedSecret = session.getDerivedKey(); // HKDF(ECDHE-P384 || Kyber-768)
  ```
* **Auto-Generated Code Snippet (Go TLS 1.3 / Nginx)**:
  ```go
  // Enforce X25519MLKEM768 (NIST FIPS 203) on outbound client connection:
  config := &tls.Config{
      CurvePreferences: []tls.CurveID{
          tls.CurveID(0x11ec), // X25519MLKEM768
          tls.X25519,
      },
      MinVersion: tls.VersionTLS13,
  }
  ```

### Scenario B: Remediation for Authentication & Signature Assets (Target: FIPS 204 ML-DSA)
* **Trigger**: Asset has `DigitalSignature`, `CodeSigning`, or is an identity token/certificate.
* **Auto-Generated Code Snippet (Spring Boot / Java with `pqc-starter-lib`)**:
  ```java
  // QuarkShield Auto-Generated Remediation: NIST FIPS 204 ML-DSA Digital Signature
  @Autowired
  private DilithiumSigningEngine dilithiumSigner;

  // Sign payloads to protect against future quantum signature forgery:
  byte[] signature = dilithiumSigner.signString(privateKey, documentPayload);
  boolean valid = dilithiumSigner.verifyString(publicKey, documentPayload, signature);
  ```
* **Auto-Generated OpenSSL Command for Composite / Hybrid Certificate**:
  ```bash
  # Generate composite certificate combining RSA/ECDSA with ML-DSA (Dilithium):
  openssl req -new -newkey mldsa65 -nodes -keyout rtc_pqc.key -out rtc_pqc.csr
  ```

---

## 4. Architectural Summary: The Two-Tiered Analysis Flow

```
[ Local Desktop / Cloud Snapshot / MDM ]
                  │
                  ▼ Discovers Cryptographic File (e.g. RTC.der)
       [ Local Host Scanner ]
                  │ (Parses ASN.1 DER, Public Key, KeyUsage, EKU)
                  ▼
         [ Telemetry Payload ]
                  │
                  ▼
       [ Cloud Fleet Engine ]
                  │
                  ├─────────────────────────────────────────┐
                  ▼                                         ▼
   [ FUNCTION: KEY ESTABLISHMENT ]           [ FUNCTION: DIGITAL SIGNATURE ]
   • HNDL Risk: 🚨 CRITICAL IMMEDIATE        • HNDL Risk: ⚠️ FUTURE FORGERY
   • Target: NIST FIPS 203 ML-KEM            • Target: NIST FIPS 204 ML-DSA
   • Code: Hybrid KEM Handshake Snippet      • Code: Dilithium Signing Snippet
                  │                                         │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  [ Consolidated Multi-Tenant CBOM Graph ]
                  • Prioritized Remediation Backlog
                  • One-Click Spring Boot & Nginx Playbooks
```
