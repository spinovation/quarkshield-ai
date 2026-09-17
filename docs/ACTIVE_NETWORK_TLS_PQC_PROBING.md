# Active Network & Outbound TCP/TLS Socket PQC Probing Architecture
**Technical Specification & Operational Guide: Zero-Touch Active TLS Auditing**

---

## Executive Summary

While static discovery methods inspect cryptographic artifacts at rest (such as PEM files, private keys, and OS certificate stores on a workstation or server), **Active Network & Outbound TCP/TLS Socket Probing** evaluates cryptography **in motion**.

By initiating a direct outbound TCP connection and executing a customized **TLS 1.3 ClientHello**, the scanner inspects live cryptographic negotiations in real time. This enables enterprises to answer three critical post-quantum security questions:
1. **Harvest Now, Decrypt Later (HNDL)**: Is the session key exchange protected by a Post-Quantum Key Encapsulation Mechanism (e.g., NIST FIPS 203 ML-KEM / Kyber768), or is it vulnerable to eavesdropping and retroactive quantum decryption?
2. **Shor’s Algorithm Risk**: Are the server and intermediate Certificate Authorities (CAs) using classical asymmetric signature algorithms (RSA-2048/4096, ECDSA P-256/P-384) that can be factored or forged by a Cryptographically Relevant Quantum Computer (CRQC)?
3. **Grover’s Algorithm Risk**: Is bulk symmetric encryption configured with 128-bit ciphers (which Grover’s algorithm reduces to an insecure 64 bits of quantum security) instead of CNSA 2.0-compliant 256-bit ciphers?

---

## 1. Architectural Placement: Where Is Outbound Socket Scanning Done?

In the QuarkShield **"Wiz Model" Agentless Architecture**, Active Outbound TCP/TLS Socket Probing is designated as **Pillar 5: Remote Network & Port PQC Prober**. 

To provide comprehensive visibility across both external perimeters and internal infrastructure, outbound socket probing is deployed across **two complementary operational environments**:

```
                    ┌────────────────────────────────────────────────────────┐
                    │    QUARKSHIELD ARCHITECTURE: OUTBOUND TLS PROBING      │
                    └────────────────────────────────────────────────────────┘

         [ ENVIRONMENT A: CLOUD SAAS PLATFORM ]     [ ENVIRONMENT B: DESKTOP & CLI AGENT ]
         (quarkshield.ai / Cloud Fleet)       (Local Workstation / CI/CD Runner)
                          │                                            │
                          ▼                                            ▼
               External Perimeter Prober                    Internal Intranet Prober
          • Audits: microsoft.com:443                  • Audits: Private RFC 1918 IPs (10.x, 192.168.x)
          • Audits: public SaaS, APIs, CDNs            • Audits: Intranet apps & dev/staging clusters
          • 100% Agentless (Zero Install)              • Audits: TLS inspection proxies & middleboxes
                          │                                            │
                          └───────────────────┬────────────────────────┘
                                              │
                                              ▼
                                  Direct Outbound TCP Socket
                               (SYN -> SYN-ACK -> Established)
                                              │
                                              ▼
                                 Active TLS 1.3 Handshake
                          (ClientHello with FIPS 203 ML-KEM)
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
            Key Exchange Group           X.509 Cert Chain          Symmetric Cipher
           (Active HNDL Threat)       (Shor's Algorithm Risk)    (Grover's 64-bit Risk)
```

### Environment A: The Cloud Management Console (SaaS Zero-Touch Perimeter Scanner)
* **Execution Location**: The QuarkShield Cloud Fleet backend (`quarkshield.ai` / `quarkshield.ai`).
* **Target Scope**: Public-facing Fully Qualified Domain Names (FQDNs), public IP ranges, external APIs, and SaaS endpoints (e.g., `microsoft.com:443`, `api.github.com:443`, `portal.enterprise.com:443`).
* **Operational Flow**:
  1. An administrator or security auditor enters a target domain or IP CIDR block into the Cloud Management Console.
  2. The cloud scanner backend initiates an outbound TCP connection to port 443 (or custom TLS ports).
  3. Findings are parsed, evaluated against NIST FIPS 203/204/205 and CNSA 2.0 guidelines, and ingested into the enterprise Cryptographic Bill of Materials (CBOM).
* **Enterprise Benefit**: **100% Zero-Touch & Agentless**. Requires no software deployment, no credential onboarding, and zero changes to target servers.

### Environment B: The Desktop Agent & Ephemeral CLI (Local & Intranet Prober)
* **Execution Location**: Installed QuarkShield Desktop Agent or ephemeral CLI binary (`quarkshield-scanner`).
* **Target Scope**: Internal corporate network endpoints and workstation outbound egress paths.
* **Why Local Execution Is Mandatory**:
  1. **Private Intranet & RFC 1918 Networks**: Cloud servers cannot access private corporate subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Kubernetes internal cluster ingresses, or staging database ports behind enterprise firewalls and VPNs.
  2. **Corporate TLS Interception & Middlebox Detection**:
     - In large enterprises, employee outbound traffic to external sites like `microsoft.com` frequently passes through **SSL Decryption Middleboxes** (e.g., Zscaler Internet Access, Palo Alto Networks NGFW, BlueCoat ProxySG, Netskope).
     - These middleboxes terminate TLS, decrypt corporate traffic for DLP inspection, and re-encrypt it using the company's internal classical RSA/ECDSA root certificate.
     - Probing from the desktop identifies whether corporate middleboxes are **actively stripping modern Post-Quantum (ML-KEM) handshakes** and downgrading outbound traffic to classical algorithms.

---

## 2. Deep-Dive: The 5 Stages of an Active Outbound TCP/TLS Socket Probe

When probing a remote endpoint such as `microsoft.com:443`, the scanner performs the following sequential socket operations:

```
CLIENT (QuarkShield)                                           SERVER (microsoft.com)
      │                                                                  │
      │ 1. TCP SYN (Port 443)                                           │
      ├─────────────────────────────────────────────────────────────────>│
      │    TCP SYN-ACK                                                   │
      │<─────────────────────────────────────────────────────────────────┤
      │    TCP ACK [Socket Established]                                  │
      ├─────────────────────────────────────────────────────────────────>│
      │                                                                  │
      │ 2. TLS 1.3 ClientHello                                          │
      │    • Supported Groups: X25519MLKEM768 (0x11ec), X25519, P-256    │
      │    • Key Share: Public Ephemeral ML-KEM + X25519 Keys            │
      │    • Ciphers: AES-256-GCM, CHACHA20-POLY1305, AES-128-GCM       │
      │    • SNI: microsoft.com                                          │
      ├─────────────────────────────────────────────────────────────────>│
      │                                                                  │
      │ 3. TLS 1.3 ServerHello                                          │
      │    • Selected Group: X25519MLKEM768 (or classical fallback)      │
      │    • Selected Cipher: TLS_AES_256_GCM_SHA384                     │
      │<─────────────────────────────────────────────────────────────────┤
      │                                                                  │
      │ 4. EncryptedExtensions, Certificate Chain, CertificateVerify    │
      │    • Leaf: CN=microsoft.com (RSA 2048 / ECDSA P-256)             │
      │    • Intermediates: Microsoft TLS RSA CA                         │
      │    • Root: DigiCert Global Root G2                               │
      │<─────────────────────────────────────────────────────────────────┤
      │                                                                  │
      │ 5. Finished & Immediate Socket Close                             │
      ├─────────────────────────────────────────────────────────────────>│
```

### Stage 1: DNS Resolution & Raw TCP 3-Way Handshake
* The prober performs a DNS lookup for the target FQDN.
* Establishes a raw TCP socket with an enforceable timeout (default: 5000 ms) using `net.DialTimeout("tcp", target, timeout)`.
* Confirms network reachability, latency, and firewall path accessibility.

### Stage 2: TLS 1.3 ClientHello with Hybrid Post-Quantum Key Exchange Groups
* The prober constructs a TLS `ClientHello` offering hybrid post-quantum key exchange groups in the `supported_groups` (Extension 10) and `key_share` (Extension 51):
  * `X25519MLKEM768` (Code `0x11ec` / Standardized NIST FIPS 203 ML-KEM)
  * `SecP256r1MLKEM768` (Code `0x11ed`)
  * `X25519Kyber768Draft00` (Code `0x6399` / Google Chrome & Cloudflare draft)
  * Classical fallbacks: `X25519` (`0x001d`), `secp256r1` (`0x0017`), `secp384r1` (`0x0018`)
* Sets Server Name Indication (SNI) to ensure virtual host routing.
* Offers modern symmetric ciphers: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, and `TLS_AES_128_GCM_SHA256`.

### Stage 3: ServerHello Inspection — Active HNDL Threat Assessment
* The scanner parses the `ServerHello` returned by the server:
  * **Quantum-Safe KEM**: If the server negotiates `X25519MLKEM768`, the ephemeral shared secret is protected by lattice-based cryptography (Module-LWE). An adversary intercepting the session cannot decrypt the traffic, even with a future quantum computer.
  * **Active HNDL Vulnerability**: If the server ignores the PQC share and negotiates classical `X25519` or `secp256r1`, the session key exchange relies solely on classical discrete logarithms. The session is flagged as **Active Harvest Now, Decrypt Later (HNDL)** vulnerable.

### Stage 4: Peer Certificate Chain Inspection — Shor’s Algorithm Assessment
* The scanner extracts the complete X.509 peer certificate hierarchy (`conn.ConnectionState().PeerCertificates`):
  * **Leaf Certificate**: Audits public key type, key length (e.g., RSA 2048-bit, RSA 4096-bit, ECDSA P-256), and signature algorithm (e.g., `SHA256withRSA`).
  * **Intermediate CAs & Root CA**: Evaluates issuing chain up to the trust anchor.
  * **Threat Classification**: Any RSA or ECDSA certificate is flagged as vulnerable to **Shor’s Algorithm**. A CRQC running Shor’s algorithm can factor RSA integers and compute discrete logarithms in polynomial time, enabling signature forgery and adversary Man-in-the-Middle (MitM) impersonation.
  * **Remediation**: Transition to NIST FIPS 204 (ML-DSA / Dilithium) or stateful hash-based signatures.

### Stage 5: Symmetric Cipher Suite Audit — Grover’s Algorithm Assessment
* The scanner verifies the negotiated bulk encryption cipher:
  * **256-Bit Ciphers** (`TLS_AES_256_GCM_SHA384`): **Quantum Safe**. Grover’s algorithm provides a quadratic speedup for brute-force symmetric search, halving the effective security. A 256-bit key retains 128 bits of quantum security, fulfilling NSA CNSA 2.0 standards.
  * **128-Bit Ciphers** (`TLS_AES_128_GCM_SHA256`): **Grover’s Risk**. Grover’s algorithm reduces 128-bit keys to an effective 64 bits of security, making it vulnerable to quantum search.

---

## 3. Empirical Case Study: Live Cryptographic Audit of `microsoft.com:443`

Direct socket probing was executed against `microsoft.com:443` via an outbound TLS 1.3 handshake. Below are the exact captured technical results:

```
[TARGET AUDITED] microsoft.com:443
-----------------------------------------------------------------------------------------
Protocol Version:           TLS 1.3 (0x0304)
Negotiated Cipher Suite:    TLS_AES_256_GCM_SHA384 (0x1302)
Negotiated KEM Curve:       X25519MLKEM768 (0x11ec) -> [QUANTUM-SAFE KEY EXCHANGE]

PEER CERTIFICATE CHAIN AUDITED (4 CERTIFICATES):
 [0] Leaf Certificate:
     Subject:               CN=microsoft.com
     Issuer:                CN=Microsoft TLS G2 RSA CA OCSP 04
     Signature Algorithm:   SHA384-RSA
     Public Key:            RSA 2048-bit -> [VULNERABLE: Shor's Algorithm Risk]
     Validity:              Expires 2026-12-20

 [1] Intermediate CA 1:
     Subject:               CN=Microsoft TLS G2 RSA CA OCSP 04
     Issuer:                CN=Microsoft TLS RSA Root G2
     Signature Algorithm:   SHA384-RSA
     Public Key:            RSA 4096-bit -> [VULNERABLE: Shor's Algorithm Risk]

 [2] Intermediate CA 2:
     Subject:               CN=Microsoft TLS RSA Root G2
     Issuer:                CN=DigiCert Global Root G2
     Signature Algorithm:   SHA384-RSA
     Public Key:            RSA 4096-bit -> [VULNERABLE: Shor's Algorithm Risk]

 [3] Root Trust Anchor:
     Subject:               CN=DigiCert Global Root G2
     Issuer:                CN=DigiCert Global Root G2
     Signature Algorithm:   SHA256-RSA
     Public Key:            RSA 2048-bit -> [VULNERABLE: Shor's Algorithm Risk]
-----------------------------------------------------------------------------------------
OVERALL FINDING:
• Data-in-Transit (KEM):    SECURE (Immune to HNDL via X25519MLKEM768)
• Identity/Auth (PKI):      VULNERABLE (Leaf and all CAs rely on classical RSA)
• Symmetric Bulk Cipher:    SECURE (AES-256-GCM satisfies CNSA 2.0 128-bit quantum margin)
```

### Analysis of the Microsoft Result:
1. **PQC Hybrid Key Exchange is Active**: Microsoft has rolled out support for **hybrid ML-KEM-768 (`X25519MLKEM768`)** across its edge infrastructure. Outbound traffic to `microsoft.com` is protected against Harvest Now, Decrypt Later.
2. **PKI Remains 100% Classical**: Every certificate in the chain—from the leaf `microsoft.com` to DigiCert's Root CA—relies on classical RSA keys. These signatures are vulnerable to forgery once a CRQC exists.
3. **The Migration Gap**: This real-world finding demonstrates why enterprises must audit both **Key Exchange** and **Authentication** independently: modern organizations are adopting hybrid KEMs first, while PKI migration to ML-DSA signatures remains an outstanding industry challenge.

---

## 4. Comparison: Active Socket Probing vs. Static Host Scanning

| Feature Dimension | **Static Host & Disk Scan** | **OS Cert Store & Schannel** | **Active Outbound TCP/TLS Probe** |
| :--- | :--- | :--- | :--- |
| **Object of Audit** | Files on disk (`.pem`, `.key`, `.crt`) | Windows Registry / macOS Keychain | Live TCP socket connection |
| **Target Scope** | Local files & configs | Local OS configuration | Remote FQDNs, IPs, ports (`:443`) |
| **Execution Environment** | Local Desktop or Server | Local OS | Cloud SaaS **or** Desktop Agent |
| **HNDL Detection** | Inferred from configuration files | Inferred from protocol registry keys | **Actively verified via TLS Handshake** |
| **Middlebox Detection** | Cannot detect | Cannot detect | **Detects SSL proxy re-signing** |
| **Shor's Detection** | Direct key analysis | Direct cert analysis | **Full live X.509 cert chain analysis** |
| **Grover's Detection** | Audits configured cipher lists | Audits registry cipher suites | **Audits actively negotiated cipher** |
| **Agent Requirement** | Requires binary on host | Requires binary on host | **Zero-install (Cloud) or 1-shot (CLI)** |

---

## 5. Implementation Architecture in QuarkShield

### 1. In the Desktop Agent GUI
A dedicated action button **"🌐 Probe Network / TLS Endpoint"** is provided alongside "Quick Scan" and "Custom Path Scan".
* The user inputs a target (e.g. `microsoft.com:443`, `api.internal.corp:8443`).
* The agent executes an outbound socket probe in < 2 seconds.
* Displays the negotiated KEM curve, cipher suite, certificate chain, and CBOM findings in the dashboard.

### 2. In the Ephemeral CLI
```bash
# Probe a public endpoint:
quarkshield-scanner --probe microsoft.com:443

# Probe an internal intranet service behind corporate firewall:
quarkshield-scanner --probe internal-api.corp.local:8443

# Export probe findings as CycloneDX 1.6 CBOM JSON:
quarkshield-scanner --probe microsoft.com:443 --output cbom.json
```

### 3. In the Cloud Management Console (`quarkshield.ai`)
* An agentless web interface where security teams can launch one-off probes or automated continuous monitoring of external domains, ingesting results into their central multi-tenant cryptographic dashboard.

---

## 6. Summary Checklist for Security Teams

When evaluating an outbound TCP/TLS socket for quantum readiness:
- [x] **TLS 1.3 Enforced**: Confirm TLS 1.2 and obsolete protocols (TLS 1.0/1.1) are disabled.
- [x] **Post-Quantum KEM Negotiated**: Verify `X25519MLKEM768` (or `secp256r1MLKEM768`) is accepted by the server.
- [x] **256-bit Symmetric Encryption**: Mandate `AES-256-GCM` or `ChaCha20-Poly1305` to mitigate Grover's attack.
- [x] **Cert Chain Audited**: Catalog all RSA and ECDSA certificates for future migration to NIST FIPS 204 (ML-DSA).
- [x] **Corporate Middleboxes Verified**: Confirm outbound enterprise proxies do not strip hybrid PQC extensions.
