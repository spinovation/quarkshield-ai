//go:build darwin

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
	"os/exec"
	"path/filepath"
	"strings"
)

// AuditPlatformSystemStores audits macOS Keychains and system TLS/SSH configurations
func AuditPlatformSystemStores() ([]AuditResult, []AuditResult) {
	certs := AuditMacOSKeychains()
	configs := AuditMacOSTLSConfig()
	return certs, configs
}

// AuditMacOSKeychains discovers certificates stored in user and system macOS keychains
func AuditMacOSKeychains() []AuditResult {
	var results []AuditResult
	seenFingerprints := make(map[string]bool)

	// Keychains to query
	keychains := []string{
		"", // Default search list (User login.keychain-db + System.keychain)
		"/Library/Keychains/System.keychain",
		"/System/Library/Keychains/SystemRootCertificates.keychain",
	}

	userHome, _ := os.UserHomeDir()
	if userHome != "" {
		userLogin := filepath.Join(userHome, "Library", "Keychains", "login.keychain-db")
		if _, err := os.Stat(userLogin); err == nil {
			keychains = append(keychains, userLogin)
		}
	}

	for _, kc := range keychains {
		var cmd *exec.Cmd
		kcPath := kc
		if kc == "" {
			cmd = exec.Command("/usr/bin/security", "find-certificate", "-a", "-p")
			kcPath = "macOS Keychain Search List"
		} else {
			if _, err := os.Stat(kc); err != nil {
				continue
			}
			cmd = exec.Command("/usr/bin/security", "find-certificate", "-a", "-p", kc)
		}

		out, err := cmd.Output()
		if err != nil || len(out) == 0 {
			continue
		}

		rest := out
		for len(rest) > 0 {
			// Limit total imported keychain certs to 60 per run to ensure sub-minute scans
			if len(results) >= 60 {
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

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}

			fpBytes := sha256.Sum256(block.Bytes)
			fp := hex.EncodeToString(fpBytes[:])
			if seenFingerprints[fp] {
				continue
			}
			seenFingerprints[fp] = true

			// Determine Key Algorithm and Key Size
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

			funcTag := "General macOS TLS Certificate"
			quantumThreat := "Shor's Algorithm (Asymmetric Factorization/DLP)"
			complianceViolations := []string{"CNSA 2.0", "NIST SP 800-208", "EO 14028"}

			if isKeyEstablishment && !isSignature {
				funcTag = "Key Establishment / Encryption"
				quantumThreat = "Harvest Now, Decrypt Later (HNDL) & Shor's Algorithm"
				explainer = "macOS certificate utilized for Key Establishment. 🚨 Active HNDL concern: Encrypted sessions recorded today can be retroactively decrypted by a future quantum computer."
				complianceViolations = []string{"CNSA 2.0", "NIST FIPS 203 (ML-KEM)", "EO 14028"}
			} else if isSignature && !isKeyEstablishment {
				funcTag = "Authentication / Digital Signature"
				quantumThreat = "Shor's Algorithm (Signature Forgery & Spoofing)"
				explainer = "macOS certificate utilized for Authentication / Code Signing / Signatures. ⚠️ Future Shor's Risk: No immediate HNDL session recording; signatures can be forged once a CRQC exists."
				complianceViolations = []string{"CNSA 2.0", "NIST FIPS 204 (ML-DSA)", "EO 14028"}
			} else if isKeyEstablishment && isSignature {
				funcTag = "Dual: Key Establishment (HNDL) & Authentication (Shor's)"
				quantumThreat = "Active HNDL (Key Exchange) & Shor's (Signatures)"
				explainer = "Dual-purpose certificate in macOS Keychain. Subject to both active Harvest Now Decrypt Later (HNDL) session capture and future Shor's signature spoofing."
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
			desc := fmt.Sprintf("macOS Keychain asset (%s). Subject: %s. Issuer: %s. Expiry: %s. Functional Role: %s.",
				kcPath, subjectName, issuerName, expiry, funcTag)

			dispSubject := subjectName
			if len(dispSubject) > 40 {
				dispSubject = dispSubject[:40] + "..."
			}

			shortID := fp
			if len(shortID) > 8 {
				shortID = shortID[:8]
			}

			plan := GenerateRemediationWithUsage("certificate", algo, keySize, subjectName, desc, kcPath, isKeyEstablishment, isSignature)

			results = append(results, AuditResult{
				ID:                   fmt.Sprintf("mac-cert-%s", shortID),
				Type:                 "certificate",
				Name:                 fmt.Sprintf("macOS Keychain: %s", dispSubject),
				Path:                 kcPath,
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
			})
		}
	}

	return results
}

// AuditMacOSTLSConfig audits system SSH and TLS configurations on macOS
func AuditMacOSTLSConfig() []AuditResult {
	var results []AuditResult

	sshConfigs := []string{
		"/etc/ssh/sshd_config",
		"/etc/ssh/ssh_config",
	}

	userHome, _ := os.UserHomeDir()
	if userHome != "" {
		sshConfigs = append(sshConfigs, filepath.Join(userHome, ".ssh", "config"))
	}

	for _, cfgPath := range sshConfigs {
		content, err := os.ReadFile(cfgPath)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for lineNum, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}

			// Check for weak ciphers or key exchange algorithms
			if strings.HasPrefix(trimmed, "KexAlgorithms") || strings.HasPrefix(trimmed, "Ciphers") {
				lower := strings.ToLower(trimmed)
				if strings.Contains(lower, "diffie-hellman-group1") || strings.Contains(lower, "3des") || strings.Contains(lower, "arcfour") {
					results = append(results, AuditResult{
						ID:                   fmt.Sprintf("mac-cfg-%s-%d", filepath.Base(cfgPath), lineNum+1),
						Type:                 "config",
						Name:                 fmt.Sprintf("macOS SSH Config: %s", filepath.Base(cfgPath)),
						Path:                 cfgPath,
						Algorithm:            "Legacy SSH Cipher/KEX",
						QuantumThreat:        "Harvest Now, Decrypt Later (HNDL) & Shor's Algorithm",
						IsVulnerable:         true,
						RiskLevel:            "critical",
						Status:               "Quantum Vulnerable",
						Description:          fmt.Sprintf("macOS SSH configuration (%s:%d) enables obsolete cipher/KEX suite: '%s'", cfgPath, lineNum+1, trimmed),
						Recommendation:       "Enforce modern Post-Quantum Hybrid KEX (e.g., sntrup761x25519-sha512@openssh.com or mlkem768x25519-sha512) and AES-256-GCM.",
						RemediationSteps: []string{
							fmt.Sprintf("Edit %s: remove legacy algorithms from '%s'", cfgPath, strings.Fields(trimmed)[0]),
							"Add post-quantum hybrid KEX: KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256",
							"Reload SSH configuration",
						},
						CodeSnippet:          "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
						Explainer:            "Classical Diffie-Hellman and 3DES/Blowfish enable immediate Harvest-Now-Decrypt-Later decryption when quantum computing emerges.",
						ComplianceViolations: []string{"CNSA 2.0", "NIST SP 800-52r2", "PCI-DSS 4.0"},
					})
				}
			}
		}
	}

	return results
}
