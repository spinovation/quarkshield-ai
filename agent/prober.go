package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// ProbeEndpoint performs an active outbound TCP/TLS socket handshake against a target host:port
// and audits for active HNDL, Shor's algorithm, and Grover's algorithm vulnerabilities.
func ProbeEndpoint(rawTarget string) ([]AuditResult, error) {
	target := strings.TrimSpace(rawTarget)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.Split(target, "/")[0] // strip paths

	host := target
	port := "443"
	if strings.Contains(target, ":") {
		h, p, err := net.SplitHostPort(target)
		if err == nil {
			host = h
			port = p
		}
	} else {
		target = net.JoinHostPort(host, port)
	}

	dialer := &net.Dialer{Timeout: 6 * time.Second}
	tlsConfig := &tls.Config{
		ServerName: host,
		CurvePreferences: []tls.CurveID{
			tls.CurveID(0x11ec), // X25519MLKEM768 (Standard NIST FIPS 203)
			tls.CurveID(0x11ed), // SecP256r1MLKEM768
			tls.X25519,
			tls.CurveP256,
		},
		InsecureSkipVerify: false,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", target, tlsConfig)
	if err != nil {
		// If verification failed due to internal CA or self-signed cert, retry with InsecureSkipVerify
		// to still inspect the cryptographic parameters and certificate chain
		tlsConfig.InsecureSkipVerify = true
		conn, err = tls.DialWithDialer(dialer, "tcp", target, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to establish outbound TCP/TLS socket to %s: %w", target, err)
		}
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	var findings []AuditResult

	// 1. Key Exchange Group / Curve (Active HNDL Threat Assessment)
	isQuantumSafeKEM := (cs.CurveID == 0x11ec || cs.CurveID == 0x11ed)
	curveName := fmt.Sprintf("Curve 0x%04x", cs.CurveID)
	switch cs.CurveID {
	case 0x11ec:
		curveName = "X25519MLKEM768 (NIST FIPS 203 Hybrid)"
	case 0x11ed:
		curveName = "SecP256r1MLKEM768 (NIST FIPS 203 Hybrid)"
	case tls.X25519:
		curveName = "X25519 (Classical ECDH)"
	case tls.CurveP256:
		curveName = "secp256r1 / P-256 (Classical ECDH)"
	case tls.CurveP384:
		curveName = "secp384r1 / P-384 (Classical ECDH)"
	case tls.CurveP521:
		curveName = "secp521r1 / P-521 (Classical ECDH)"
	}

	if isQuantumSafeKEM {
		findings = append(findings, AuditResult{
			ID:                   generateID(),
			Type:                 "network_probe",
			Name:                 fmt.Sprintf("%s - TLS Key Exchange", host),
			Path:                 target,
			Algorithm:            curveName,
			KeySize:              768,
			QuantumThreat:        "Post-Quantum Protected (NIST FIPS 203 ML-KEM)",
			IsVulnerable:         false,
			RiskLevel:            "low",
			Status:               "Post-Quantum Secure",
			Description:          fmt.Sprintf("Outbound TLS 1.3 socket to %s negotiated quantum-safe %s hybrid KEM.", host, curveName),
			Recommendation:       "Endpoint is actively hardened against Harvest Now, Decrypt Later (HNDL). Continue monitoring.",
			RemediationSteps:     []string{"No immediate action required for key encapsulation."},
			CodeSnippet:          fmt.Sprintf("# Negotiated Key Share: %s\n# Standard: NIST FIPS 203 ML-KEM-768", curveName),
			Explainer:            "Hybrid lattice-based key encapsulation protects ephemeral secrets against CRQC decryption.",
			ComplianceViolations: []string{},
		})
	} else {
		findings = append(findings, AuditResult{
			ID:                   generateID(),
			Type:                 "network_probe",
			Name:                 fmt.Sprintf("%s - TLS Key Exchange", host),
			Path:                 target,
			Algorithm:            curveName,
			KeySize:              256,
			QuantumThreat:        "Harvest Now, Decrypt Later (HNDL) & Shor's Algorithm",
			IsVulnerable:         true,
			RiskLevel:            "critical",
			Status:               "Quantum Vulnerable",
			Description:          fmt.Sprintf("🚨 Outbound TLS socket to %s fell back to classical %s. Traffic is vulnerable to recording and retroactive decryption.", host, curveName),
			Recommendation:       "Configure TLS reverse proxy / edge termination to negotiate X25519MLKEM768 hybrid KEM to eliminate active HNDL exposure.",
			RemediationSteps: []string{
				"Update server TLS configuration (Nginx, Envoy, Cloudflare) to enable Post-Quantum supported_groups.",
				"Mandate TLS 1.3 with X25519MLKEM768 (curve ID 0x11ec) hybrid key share.",
				"In Java / Spring Boot services, autowire PqcStarterLib HybridHandshakeOrchestrator to secure inter-service communication.",
			},
			CodeSnippet: `// Spring Boot (PqcStarterLib) Remediation: NIST FIPS 203 ML-KEM Session Key Exchange
@Autowired
private HybridHandshakeOrchestrator pqcHandshake;

HandshakeSession session = pqcHandshake.establishHybridSession("` + host + `");
byte[] sharedSecret = session.getDerivedKey(); // HKDF(ECDHE-P384 || Kyber-768)`,
			Explainer:            "Classical ECDH key exchange is completely solvable by Shor's Algorithm running on a future quantum computer.",
			ComplianceViolations: []string{"NIST FIPS 203", "NSA CNSA 2.0", "EO 14028"},
		})
	}

	// 2. Peer Certificates (Leaf, Intermediates, Root - Shor's Algorithm Assessment)
	for i, cert := range cs.PeerCertificates {
		certAlgo := "RSA"
		keySize := 2048
		switch cert.PublicKeyAlgorithm {
		case x509.RSA:
			certAlgo = "RSA"
			if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok && rsaKey != nil && rsaKey.N != nil {
				keySize = rsaKey.N.BitLen()
			}
		case x509.ECDSA:
			certAlgo = "ECDSA"
			keySize = 256
			if ecdsaKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok && ecdsaKey != nil && ecdsaKey.Params() != nil {
				keySize = ecdsaKey.Params().BitSize
			}
		default:
			certAlgo = cert.PublicKeyAlgorithm.String()
		}

		label := fmt.Sprintf("%s (Leaf Cert)", cert.Subject.CommonName)
		if i > 0 {
			label = fmt.Sprintf("%s (Intermediate CA %d)", cert.Subject.CommonName, i)
		}
		if cert.Subject.CommonName == cert.Issuer.CommonName {
			label = fmt.Sprintf("%s (Root Trust Anchor)", cert.Subject.CommonName)
		}

		desc := fmt.Sprintf("X.509 Certificate in peer chain. Subject: %s. Signature: %s. Expiry: %s.",
			cert.Subject.CommonName, cert.SignatureAlgorithm.String(), cert.NotAfter.Format("2006-01-02"))

		findings = append(findings, AuditResult{
			ID:            generateID(),
			Type:          "network_probe",
			Name:          label,
			Path:          target,
			Algorithm:     fmt.Sprintf("%s-%d", certAlgo, keySize),
			KeySize:       keySize,
			QuantumThreat: "Shor's Algorithm (Asymmetric Factorization/DLP)",
			IsVulnerable:  true,
			RiskLevel:     "high",
			Status:        "Quantum Vulnerable",
			Description:   desc,
			Recommendation: fmt.Sprintf("⚠️ SHOR'S FORGERY RISK: Upgrade certificate chain to support NIST FIPS 204 (ML-DSA) composite signatures prior to CRQC realization."),
			RemediationSteps: []string{
				"Plan migration of public key infrastructure to dual-signature composite certificates (ML-DSA + classical).",
				"Audit issuing Certificate Authority roadmap for post-quantum intermediate root availability.",
				"Prepare client trust stores to accept NIST FIPS 204 (ML-DSA / Dilithium) certificates.",
			},
			CodeSnippet: `# Verify certificate chain and signature algorithms:
openssl s_client -connect ` + target + ` -servername ` + host + ` -showcerts`,
			Explainer:            "RSA and ECDSA signatures can be forged by Shor's algorithm, allowing adversaries to impersonate servers.",
			ComplianceViolations: []string{"NIST FIPS 204", "CNSA 2.0"},
		})
	}

	// 3. Negotiated Symmetric Cipher Suite (Grover's Algorithm Assessment)
	cipherName := tls.CipherSuiteName(cs.CipherSuite)
	is128Bit := strings.Contains(cipherName, "128")
	if is128Bit {
		findings = append(findings, AuditResult{
			ID:            generateID(),
			Type:          "network_probe",
			Name:          fmt.Sprintf("%s - Symmetric Cipher (%s)", host, cipherName),
			Path:          target,
			Algorithm:     cipherName,
			KeySize:       128,
			QuantumThreat: "Grover's Algorithm (Symmetric Halving to 64-bit)",
			IsVulnerable:  true,
			RiskLevel:     "medium",
			Status:        "Quantum Vulnerable",
			Description:   fmt.Sprintf("Negotiated 128-bit symmetric cipher (%s). Grover's algorithm halves effective quantum security to 64 bits.", cipherName),
			Recommendation: "Upgrade server and client cipher suites to mandate 256-bit encryption (TLS_AES_256_GCM_SHA384 / ChaCha20-Poly1305) satisfying CNSA 2.0.",
			RemediationSteps: []string{
				"Enforce TLS_AES_256_GCM_SHA384 in server cipher suite preferences.",
				"Deprecate 128-bit ciphers across TLS 1.3 and TLS 1.2 configurations.",
			},
			CodeSnippet:          `# Mandate 256-bit AES in Nginx:\nssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256';`,
			Explainer:            "Grover's quadratic speedup reduces 128-bit keys to 64 bits of security, making brute-force feasible on large quantum hardware.",
			ComplianceViolations: []string{"NSA CNSA 2.0"},
		})
	}

	return findings, nil
}
