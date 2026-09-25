//go:build linux

package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AuditPlatformSystemStores audits Linux trust stores and system security policies
func AuditPlatformSystemStores() ([]AuditResult, []AuditResult) {
	certs := AuditLinuxCertStore()
	configs := AuditLinuxTLSConfig()
	return certs, configs
}

// AuditLinuxCertStore discovers certificates in Linux system trust stores
func AuditLinuxCertStore() []AuditResult {
	var results []AuditResult
	seenFingerprints := make(map[string]bool)

	// Known system CA bundle files and directories across Debian, RHEL, Arch, Alpine, SUSE
	bundlePaths := []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/ssl/cert.pem",
	}

	certDirs := []string{
		"/etc/ssl/certs",
		"/etc/pki/tls/certs",
		"/etc/pki/ca-trust/source/anchors",
		"/usr/local/share/ca-certificates",
		"/etc/letsencrypt/live",
		"/etc/nginx/ssl",
		"/etc/nginx/certs",
		"/etc/apache2/ssl",
		"/etc/httpd/conf.d",
		"/etc/kubernetes/pki",
		"/var/lib/kubelet/pki",
		"/etc/docker/certs.d",
	}

	// 1. Process CA Bundle files
	for _, bundlePath := range bundlePaths {
		if len(results) >= 120 {
			break
		}

		data, err := os.ReadFile(bundlePath)
		if err != nil || len(data) == 0 {
			continue
		}

		rest := data
		for len(rest) > 0 {
			if len(results) >= 120 {
				break
			}

			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}

			if block.Type != "CERTIFICATE" {
				continue
			}

			audit := processCertBytes(block.Bytes, bundlePath, seenFingerprints)
			if audit != nil {
				results = append(results, *audit)
			}
		}
	}

	// 2. Process individual certificate files in cert directories
	for _, dir := range certDirs {
		if len(results) >= 120 {
			break
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if len(results) >= 120 {
				break
			}

			if entry.IsDir() {
				continue
			}

			name := strings.ToLower(entry.Name())
			if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".cer") {
				filePath := filepath.Join(dir, entry.Name())
				data, err := os.ReadFile(filePath)
				if err != nil || len(data) == 0 {
					continue
				}

				block, _ := pem.Decode(data)
				if block == nil || block.Type != "CERTIFICATE" {
					continue
				}

				audit := processCertBytes(block.Bytes, filePath, seenFingerprints)
				if audit != nil {
					results = append(results, *audit)
				}
			}
		}
	}

	return results
}

func processCertBytes(certBytes []byte, storePath string, seen map[string]bool) *AuditResult {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil
	}

	fpBytes := sha256.Sum256(certBytes)
	fp := hex.EncodeToString(fpBytes[:])
	if seen[fp] {
		return nil
	}
	seen[fp] = true

	algo := "RSA"
	keySize := 2048
	riskLevel := "high"
	explainer := "RSA prime factorization is vulnerable to Shor's Algorithm."

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		algo = "RSA"
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			keySize = rsaKey.N.BitLen()
		}
		if keySize < 2048 {
			riskLevel = "critical"
		}
		explainer = "RSA prime factorization is solved in polynomial time by Shor's Algorithm."
	case x509.ECDSA:
		algo = "ECDSA"
		if ecdsaKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			keySize = ecdsaKey.Params().BitSize
		}
		explainer = "Elliptic curve discrete logarithm is solved in polynomial time by Shor's Algorithm."
	default:
		algo = cert.PublicKeyAlgorithm.String()
	}

	// KeyUsage Triaging: FIPS 203 ML-KEM (HNDL) vs FIPS 204 ML-DSA (Signatures)
	isKeyEstablishment := cert.KeyUsage&(x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment|x509.KeyUsageKeyAgreement) != 0
	isSignature := cert.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0

	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			isKeyEstablishment = true
		}
		if eku == x509.ExtKeyUsageClientAuth || eku == x509.ExtKeyUsageCodeSigning || eku == x509.ExtKeyUsageTimeStamping {
			isSignature = true
		}
	}

	funcTag := "General Linux TLS Certificate"
	quantumThreat := "Shor's Algorithm (Asymmetric Factorization/DLP)"
	complianceViolations := []string{"CNSA 2.0", "NIST SP 800-208", "EO 14028"}

	if isKeyEstablishment && !isSignature {
		funcTag = "Key Establishment / Encryption"
		quantumThreat = "Harvest Now, Decrypt Later (HNDL) & Shor's Algorithm"
		explainer = "Linux certificate utilized for Key Establishment. 🚨 Active HNDL concern: Encrypted sessions recorded today can be retroactively decrypted by a future quantum computer."
		complianceViolations = []string{"CNSA 2.0", "NIST FIPS 203 (ML-KEM)", "EO 14028"}
	} else if isSignature && !isKeyEstablishment {
		funcTag = "Authentication / Digital Signature"
		quantumThreat = "Shor's Algorithm (Signature Forgery & Spoofing)"
		explainer = "Linux certificate utilized for Authentication / Code Signing / Signatures. ⚠️ Future Shor's Risk: No immediate HNDL session recording; signatures can be forged once a CRQC exists."
		complianceViolations = []string{"CNSA 2.0", "NIST FIPS 204 (ML-DSA)", "EO 14028"}
	} else if isKeyEstablishment && isSignature {
		funcTag = "Dual: Key Establishment (HNDL) & Authentication (Shor's)"
		quantumThreat = "Active HNDL (Key Exchange) & Shor's (Signatures)"
		explainer = "Dual-purpose certificate in Linux trust store. Subject to both active Harvest Now Decrypt Later (HNDL) session capture and future Shor's signature spoofing."
		complianceViolations = []string{"CNSA 2.0", "NIST FIPS 203 (ML-KEM)", "NIST FIPS 204 (ML-DSA)"}
	}

	subjectName := cert.Subject.CommonName
	if subjectName == "" && len(cert.Subject.Organization) > 0 {
		subjectName = cert.Subject.Organization[0]
	}
	if subjectName == "" {
		subjectName = "Unknown Subject"
	}

	issuerName := cert.Issuer.CommonName
	if issuerName == "" && len(cert.Issuer.Organization) > 0 {
		issuerName = cert.Issuer.Organization[0]
	}

	expiry := cert.NotAfter.Format("2006-01-02")
	desc := fmt.Sprintf("Linux trust store asset (%s). Subject: %s. Issuer: %s. Expiry: %s. Functional Role: %s.",
		storePath, subjectName, issuerName, expiry, funcTag)

	dispSubject := subjectName
	if len(dispSubject) > 40 {
		dispSubject = dispSubject[:40] + "..."
	}

	shortID := fp
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}

	plan := GenerateRemediationWithUsage("certificate", algo, keySize, subjectName, desc, storePath, isKeyEstablishment, isSignature)

	return &AuditResult{
		ID:                   fmt.Sprintf("lin-cert-%s", shortID),
		Type:                 "certificate",
		Name:                 fmt.Sprintf("Linux Trust Store: %s", dispSubject),
		Path:                 storePath,
		Algorithm:            fmt.Sprintf("%s-%d", algo, keySize),
		KeySize:              keySize,
		QuantumThreat:        quantumThreat,
		IsVulnerable:         true,
		RiskLevel:            riskLevel,
		Status:               "Quantum Vulnerable",
		Description:          desc,
		Recommendation:       plan.Recommendation,
		RemediationSteps:     plan.Steps,
		CodeSnippet:          plan.CodeSnippet,
		Explainer:            explainer,
		ComplianceViolations: complianceViolations,
	}
}

// AuditLinuxTLSConfig audits system SSH and Linux crypto policies (/etc/crypto-policies/config)
func AuditLinuxTLSConfig() []AuditResult {
	var results []AuditResult

	// 1. Audit /etc/crypto-policies/config (RHEL/CentOS/Fedora)
	cryptoPolicyPath := "/etc/crypto-policies/config"
	if policyData, err := os.ReadFile(cryptoPolicyPath); err == nil {
		policy := strings.TrimSpace(string(policyData))
		if policy == "LEGACY" || policy == "DEFAULT" {
			riskLevel := "medium"
			if policy == "LEGACY" {
				riskLevel = "critical"
			}
			results = append(results, AuditResult{
				ID:                   "lin-crypto-policy",
				Type:                 "config",
				Name:                 "Linux System Crypto Policy: " + policy,
				Path:                 cryptoPolicyPath,
				Algorithm:            fmt.Sprintf("System Crypto Policy (%s)", policy),
				QuantumThreat:        "Harvest Now, Decrypt Later (HNDL) & Weak Cryptography",
				IsVulnerable:         true,
				RiskLevel:            riskLevel,
				Status:               "Quantum Vulnerable",
				Description:          fmt.Sprintf("System cryptographic policy in %s is currently set to '%s', permitting classical and non-PQC cipher suites.", cryptoPolicyPath, policy),
				Recommendation:       "Update Linux system crypto policy to 'FUTURE' or 'FIPS' to disallow legacy cryptography.",
				RemediationSteps: []string{
					"Run elevated terminal command: sudo update-crypto-policies --set FUTURE",
					"Verify active policy: update-crypto-policies --show",
					"Restart system services to apply modernized cryptographic profiles.",
				},
				CodeSnippet:          "sudo update-crypto-policies --set FUTURE\nsudo update-crypto-policies --show",
				Explainer:            "Linux crypto-policies manage TLS, IPsec, Kerberos, and SSH algorithms across the entire operating system.",
				ComplianceViolations: []string{"CNSA 2.0", "NIST SP 800-52r2", "FIPS 140-3"},
			})
		}
	}

	// 2. Audit /etc/ssh/sshd_config
	sshdPath := "/etc/ssh/sshd_config"
	if sshdData, err := os.ReadFile(sshdPath); err == nil {
		lines := strings.Split(string(sshdData), "\n")
		for lineNum, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}

			if strings.HasPrefix(trimmed, "KexAlgorithms") || strings.HasPrefix(trimmed, "Ciphers") {
				lower := strings.ToLower(trimmed)
				if strings.Contains(lower, "diffie-hellman-group1") || strings.Contains(lower, "3des") || strings.Contains(lower, "arcfour") {
					results = append(results, AuditResult{
						ID:                   fmt.Sprintf("lin-sshd-cfg-%d", lineNum+1),
						Type:                 "config",
						Name:                 "Linux SSH Daemon Config: Legacy Ciphers",
						Path:                 sshdPath,
						Algorithm:            "Legacy SSH Cipher/KEX",
						QuantumThreat:        "Harvest Now, Decrypt Later (HNDL) & Shor's Algorithm",
						IsVulnerable:         true,
						RiskLevel:            "critical",
						Status:               "Quantum Vulnerable",
						Description:          fmt.Sprintf("Linux SSH daemon config (%s:%d) enables obsolete cipher/KEX suite: '%s'", sshdPath, lineNum+1, trimmed),
						Recommendation:       "Enforce modern Post-Quantum Hybrid KEX (e.g., sntrup761x25519-sha512@openssh.com or mlkem768x25519-sha512) and AES-256-GCM.",
						RemediationSteps: []string{
							fmt.Sprintf("Edit %s: remove legacy algorithms from '%s'", sshdPath, strings.Fields(trimmed)[0]),
							"Add post-quantum hybrid KEX: KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256",
							"Restart SSH daemon: sudo systemctl restart sshd",
						},
						CodeSnippet:          "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
						Explainer:            "Classical Diffie-Hellman and legacy ciphers enable immediate Harvest-Now-Decrypt-Later decryption when quantum computing emerges.",
						ComplianceViolations: []string{"CNSA 2.0", "NIST SP 800-52r2", "PCI-DSS 4.0"},
					})
				}
			}
		}
	}

	// 3. Audit OpenSSL system configuration (/etc/ssl/openssl.cnf, /etc/pki/tls/openssl.cnf)
	opensslCnfPaths := []string{"/etc/ssl/openssl.cnf", "/etc/pki/tls/openssl.cnf"}
	for _, cnfPath := range opensslCnfPaths {
		if cnfData, err := os.ReadFile(cnfPath); err == nil {
			lines := strings.Split(string(cnfData), "\n")
			for lineNum, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") || trimmed == "" {
					continue
				}
				lower := strings.ToLower(trimmed)
				if strings.Contains(lower, "seclevel=1") || strings.Contains(lower, "seclevel=0") {
					results = append(results, AuditResult{
						ID:                   fmt.Sprintf("lin-openssl-seclevel-%d", lineNum+1),
						Type:                 "config",
						Name:                 "Linux OpenSSL Config: Weak SECLEVEL",
						Path:                 cnfPath,
						Algorithm:            "OpenSSL Security Level",
						QuantumThreat:        "Harvest Now, Decrypt Later (HNDL) & Weak Cryptography",
						IsVulnerable:         true,
						RiskLevel:            "high",
						Status:               "Quantum Vulnerable",
						Description:          fmt.Sprintf("System OpenSSL configuration (%s:%d) configures weak security level: '%s'", cnfPath, lineNum+1, trimmed),
						Recommendation:       "Set CipherString to 'DEFAULT@SECLEVEL=2' or higher (preferably SECLEVEL=3) and enforce TLS 1.3.",
						RemediationSteps: []string{
							fmt.Sprintf("Edit %s: update CipherString to use SECLEVEL=2 or SECLEVEL=3", cnfPath),
							"Enforce TLS 1.3 minimum protocol: MinProtocol = TLSv1.3",
						},
						CodeSnippet:          "CipherString = DEFAULT@SECLEVEL=2\nMinProtocol = TLSv1.3",
						Explainer:            "OpenSSL SECLEVEL 0 and 1 allow 80-bit and 112-bit security levels (1024-bit RSA and weak SHA-1/3DES).",
						ComplianceViolations: []string{"CNSA 2.0", "NIST SP 800-52r2"},
					})
				}
				if strings.Contains(lower, "minprotocol = tlsv1.0") || strings.Contains(lower, "minprotocol = tlsv1.1") {
					results = append(results, AuditResult{
						ID:                   fmt.Sprintf("lin-openssl-minproto-%d", lineNum+1),
						Type:                 "config",
						Name:                 "Linux OpenSSL Config: Deprecated TLS Protocol",
						Path:                 cnfPath,
						Algorithm:            "Legacy TLS Protocol (TLS 1.0/1.1)",
						QuantumThreat:        "Harvest Now, Decrypt Later (HNDL)",
						IsVulnerable:         true,
						RiskLevel:            "critical",
						Status:               "Quantum Vulnerable",
						Description:          fmt.Sprintf("System OpenSSL configuration (%s:%d) permits deprecated TLS version: '%s'", cnfPath, lineNum+1, trimmed),
						Recommendation:       "Update MinProtocol to TLSv1.3 in system OpenSSL configuration.",
						RemediationSteps: []string{
							fmt.Sprintf("Edit %s: set MinProtocol = TLSv1.3", cnfPath),
						},
						CodeSnippet:          "MinProtocol = TLSv1.3",
						Explainer:            "Protocols below TLS 1.2 lack post-quantum forward secrecy and are vulnerable to retrospective decryption.",
						ComplianceViolations: []string{"CNSA 2.0", "NIST SP 800-52r2", "PCI-DSS 4.0"},
					})
				}
			}
			break
		}
	}

	// 4. Audit /etc/ssh/ssh_config (Outbound Client SSH Connections)
	sshClientPath := "/etc/ssh/ssh_config"
	if sshClientData, err := os.ReadFile(sshClientPath); err == nil {
		lines := strings.Split(string(sshClientData), "\n")
		for lineNum, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}
			if strings.HasPrefix(trimmed, "KexAlgorithms") || strings.HasPrefix(trimmed, "Ciphers") {
				lower := strings.ToLower(trimmed)
				if strings.Contains(lower, "diffie-hellman-group1") || strings.Contains(lower, "3des") || strings.Contains(lower, "arcfour") {
					results = append(results, AuditResult{
						ID:                   fmt.Sprintf("lin-ssh-client-cfg-%d", lineNum+1),
						Type:                 "config",
						Name:                 "Linux SSH Client Config: Legacy Outbound Ciphers",
						Path:                 sshClientPath,
						Algorithm:            "Legacy SSH Cipher/KEX",
						QuantumThreat:        "Harvest Now, Decrypt Later (HNDL)",
						IsVulnerable:         true,
						RiskLevel:            "high",
						Status:               "Quantum Vulnerable",
						Description:          fmt.Sprintf("Linux SSH client config (%s:%d) permits outbound connection via deprecated cipher/KEX: '%s'", sshClientPath, lineNum+1, trimmed),
						Recommendation:       "Update client SSH configuration to prefer hybrid post-quantum key exchange (sntrup761x25519-sha512@openssh.com or mlkem768x25519-sha512).",
						RemediationSteps: []string{
							fmt.Sprintf("Edit %s: remove legacy algorithms from '%s'", sshClientPath, strings.Fields(trimmed)[0]),
							"Add post-quantum hybrid KEX: KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256",
						},
						CodeSnippet:          "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org",
						Explainer:            "Outbound SSH connections using classical Diffie-Hellman can be intercepted and recorded for retrospective decryption.",
						ComplianceViolations: []string{"CNSA 2.0", "NIST SP 800-52r2"},
					})
				}
			}
		}
	}

	// 5. Audit Kernel Crypto Modules (/proc/crypto) for active legacy algorithms
	if procCryptoData, err := os.ReadFile("/proc/crypto"); err == nil {
		text := string(procCryptoData)
		legacyDrivers := []string{"des3_ede", "des", "arc4", "blowfish", "cast5"}
		seenDrivers := make(map[string]bool)
		for _, driver := range legacyDrivers {
			if strings.Contains(text, "driver       : "+driver) || strings.Contains(text, "name         : "+driver) {
				if !seenDrivers[driver] {
					seenDrivers[driver] = true
					results = append(results, AuditResult{
						ID:                   fmt.Sprintf("lin-kernel-crypto-%s", driver),
						Type:                 "config",
						Name:                 fmt.Sprintf("Linux Kernel Registered Crypto Driver: %s", driver),
						Path:                 "/proc/crypto",
						Algorithm:            fmt.Sprintf("Legacy Kernel Cipher (%s)", driver),
						QuantumThreat:        "Grover's Algorithm (Key Halving)",
						IsVulnerable:         true,
						RiskLevel:            "medium",
						Status:               "Quantum Vulnerable",
						Description:          fmt.Sprintf("Linux kernel has registered deprecated cryptographic driver '%s', vulnerable to symmetric key search and halving.", driver),
						Recommendation:       fmt.Sprintf("Blacklist kernel module for %s if not required by legacy hardware.", driver),
						RemediationSteps: []string{
							fmt.Sprintf("Create blacklist file: echo 'blacklist %s' | sudo tee /etc/modprobe.d/blacklist-legacy-crypto.conf", driver),
						},
						CodeSnippet:          fmt.Sprintf("echo 'blacklist %s' | sudo tee -a /etc/modprobe.d/blacklist-legacy-crypto.conf", driver),
						Explainer:            fmt.Sprintf("Kernel cipher %s provides short block or key sizes that are easily broken by classical attacks or Grover's algorithm.", driver),
						ComplianceViolations: []string{"CNSA 2.0", "FIPS 140-3"},
					})
				}
			}
		}
	}

	return results
}
