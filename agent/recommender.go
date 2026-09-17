package main

import (
	"fmt"
	"runtime"
	"strings"
)

// RemediationPlan provides contextual, actionable steps for resolving quantum vulnerabilities
type RemediationPlan struct {
	Recommendation string
	Steps          []string
	CodeSnippet    string
}

// GenerateRemediationWithUsage generates tailored, actionable recommendations based on asset context and X.509 KeyUsage
func GenerateRemediationWithUsage(assetType string, algorithm string, keySize int, name string, description string, path string, isKeyEstablishment bool, isSignature bool) RemediationPlan {
	lowerName := strings.ToLower(name)
	lowerDesc := strings.ToLower(description)
	lowerPath := strings.ToLower(path)

	// 1. Intune / MDM / Active Directory Device Certificates
	if strings.Contains(lowerDesc, "intune") || strings.Contains(lowerName, "intune") || strings.Contains(lowerPath, "intune") || strings.Contains(lowerDesc, "device ca") {
		return RemediationPlan{
			Recommendation: "Configure Microsoft Intune SCEP profile to issue short-lived certs (<1 yr) and enable Windows CNG ML-DSA provider when deploying Intune PQC policy.",
			Steps: []string{
				"Open Microsoft Intune admin center -> Devices -> Configuration profiles.",
				"Locate SCEP / PKCS certificate profiles and update certificate validity period to 180-365 days to shrink the quantum capture window.",
				"Prepare enrollment template for Windows 11 / Server 2025 CNG (Cryptography Next Generation) hybrid ML-DSA provider.",
			},
			CodeSnippet: `# Verify Windows Intune MDM certificate status in PowerShell:
Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Issuer -match "Intune" } | Select-Object Subject, NotAfter, Thumbprint`,
		}
	}

	// 2. Deprecated / Weak Key Sizes (RSA-1024, RSA-512, MD5) - only applies to RSA
	isRSA := strings.Contains(strings.ToUpper(algorithm), "RSA")
	if isRSA && keySize > 0 && keySize <= 1024 {
		dumpCmd := `openssl x509 -in "` + path + `" -text -noout`
		if runtime.GOOS == "windows" {
			dumpCmd = `certutil -dump "` + path + `"`
		} else if strings.Contains(path, "keychain") {
			dumpCmd = `/usr/bin/security find-certificate -a -p "` + path + `" | openssl x509 -text -noout`
		}
		return RemediationPlan{
			Recommendation: fmt.Sprintf("URGENT: Deprecated %d-bit RSA key size is broken classically and vulnerable to instant quantum decryption. Revoke & re-key immediately.", keySize),
			Steps: []string{
				"Immediately contact the issuing authority or application provider to revoke this certificate.",
				"Re-issue credential with minimum RSA-4096 or ECDSA P-384 as a bridge, requesting NIST FIPS 204 (ML-DSA) compliance.",
				"Verify associated client application or broker KYC portal is updated to reject sub-2048-bit keys.",
			},
			CodeSnippet: `# Check certificate details and key parameters:
` + dumpCmd,
		}
	}

	// 3. Database Root CAs (e.g. db_root_ca_*.cer)
	if strings.Contains(lowerName, "db_root") || strings.Contains(lowerName, "root_ca") || strings.Contains(lowerName, "database") {
		return RemediationPlan{
			Recommendation: "Establish dual-root trust store for database cluster. Configure clients with 'sslmode=verify-full' and plan migration to hybrid composite ML-DSA/RSA root prior to 2030.",
			Steps: []string{
				"Append post-quantum root certificate to the database server CA bundle (ca.crt / truststore.jks).",
				"Update database client connection strings to require TLS 1.3 verification (sslmode=verify-full).",
				"Transition database drivers (JDBC, ODBC, pgx) to use Post-Quantum hybrid providers (liboqs / Bouncy Castle).",
			},
			CodeSnippet: `# Verify database root certificate expiration and signature algorithm:
openssl x509 -in "` + path + `" -text -noout | grep -E "(Issuer|Algorithm|Not After)"`,
		}
	}

	// 4. Plaintext Private Keys on Disk (Chain.pem, id_rsa, *.key)
	if assetType == "private_key" || strings.Contains(lowerName, "key") || strings.HasSuffix(lowerName, ".pem") {
		storageDesc := "macOS Keychain / Secure Enclave, cloud KMS (AWS KMS / GCP KMS), or HashiCorp Vault"
		if runtime.GOOS == "windows" {
			storageDesc = "Windows DPAPI, Azure Key Vault, or TPM"
		} else if runtime.GOOS == "linux" {
			storageDesc = "Linux Kernel Keyring / TPM2, cloud KMS, or HashiCorp Vault"
		}
		return RemediationPlan{
			Recommendation: fmt.Sprintf("Migrate plaintext private key off disk into %s. Generate ML-DSA-65 / Kyber-768 replacement keypair.", storageDesc),
			Steps: []string{
				"Remove unencrypted private key files from disk to prevent local credential harvesting.",
				fmt.Sprintf("Store private keys in hardware-backed storage (%s).", storageDesc),
				"Generate quantum-safe replacement keypair using OpenSSL 3.3+ with oqsprovider or QuarkShield PQC generator.",
			},
			CodeSnippet: `# Generate post-quantum ML-DSA-65 signature keypair (via OpenSSL oqsprovider):
openssl genpkey -algorithm mldsa65 -out mldsa65_private.pem
openssl pkey -in mldsa65_private.pem -pubout -out mldsa65_public.pem`,
		}
	}

	// 5. Windows Schannel / TLS Protocol Violations
	if assetType == "config" && (strings.Contains(lowerName, "schannel") || strings.Contains(lowerName, "tls") || strings.Contains(lowerName, "ssl")) {
		proto := "TLS 1.0"
		if strings.Contains(lowerName, "1.1") {
			proto = "TLS 1.1"
		} else if strings.Contains(lowerName, "3.0") {
			proto = "SSL 3.0"
		}
		return RemediationPlan{
			Recommendation: fmt.Sprintf("Disable obsolete %s in Windows registry ('DisabledByDefault=1', 'Enabled=0'). Enforce TLS 1.3 with Hybrid ML-KEM.", proto),
			Steps: []string{
				fmt.Sprintf("Open Administrator PowerShell and disable %s client/server protocol keys in SCHANNEL.", proto),
				"Enforce modern cipher suites (TLS_AES_256_GCM_SHA384) in Group Policy (Computer Configuration -> Administrative Templates -> Network -> SSL Configuration Settings).",
				"Reboot workstation to activate updated Schannel cryptographic security provider.",
			},
			CodeSnippet: `# Disable ` + proto + ` via Administrator PowerShell:
$path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\` + proto + `\Client"
New-Item $path -Force | Out-Null
Set-ItemProperty $path -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty $path -Name "DisabledByDefault" -Value 1 -Type DWord`,
		}
	}

	// 6. Grover's Algorithm / Symmetric Ciphers (AES-128, 3DES, Blowfish)
	if strings.Contains(lowerName, "aes128") || strings.Contains(lowerName, "aes-128") || strings.Contains(lowerDesc, "grover") || strings.Contains(lowerName, "3des") || strings.Contains(lowerName, "blowfish") {
		return RemediationPlan{
			Recommendation: "Upgrade AES-128 to AES-256-GCM. Under Grover's Algorithm, AES-128 effective security is halved to 64 bits, violating NSA CNSA 2.0.",
			Steps: []string{
				"Update server, TLS, and SSH cipher suite configs to mandate 256-bit symmetric encryption (e.g. TLS_AES_256_GCM_SHA384, aes256-gcm@openssh.com).",
				"Ensure symmetric database and disk volume keys use AES-256 to retain 128-bit quantum security against Grover search.",
				"Upgrade hashing pipelines from SHA-1 / SHA-256 to SHA-384 or SHA-512 to preserve collision resistance under quantum attacks.",
			},
			CodeSnippet: `# Verify and enforce 256-bit AES ciphers:
# In OpenSSH sshd_config: Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
# In Nginx: ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';`,
		}
	}

	// 7. SSH Keys (id_rsa, id_ecdsa)
	if strings.Contains(lowerName, "ssh") || strings.Contains(lowerName, "id_rsa") || strings.Contains(lowerName, "id_ecdsa") {
		return RemediationPlan{
			Recommendation: "Upgrade OpenSSH to v9.0+ and generate hybrid post-quantum key: 'ssh-keygen -t sntrup761x25519-sha512@openssh.com' or 'ssh-keygen -t ml-dsa-65'.",
			Steps: []string{
				"Verify OpenSSH version is 9.0 or higher: ssh -V",
				"Generate hybrid post-quantum SSH key: ssh-keygen -t sntrup761x25519-sha512@openssh.com -f ~/.ssh/id_pqc",
				"Copy public key to remote servers: ssh-copy-id -i ~/.ssh/id_pqc.pub user@server",
				"Deprecate and delete classical RSA/ECDSA keys from ~/.ssh/authorized_keys to eliminate HNDL session risk.",
			},
			CodeSnippet: `# Generate Hybrid Quantum-Resistant OpenSSH Keypair:
ssh-keygen -t sntrup761x25519-sha512@openssh.com -f "$HOME\.ssh\id_pqc" -C "quantum-safe-workstation"`,
		}
	}

	// 8. Functional Certificate Triaging (FIPS 203 ML-KEM vs FIPS 204 ML-DSA)
	algoText := algorithm
	if keySize > 0 {
		algoText = fmt.Sprintf("%s-%d", algorithm, keySize)
	}

	if isKeyEstablishment && !isSignature {
		return RemediationPlan{
			Recommendation: fmt.Sprintf("🚨 CRITICAL HNDL EXPOSURE: %s is used for Key Establishment / Encryption. Upgrade to NIST FIPS 203 (ML-KEM-768) hybrid key exchange immediately to block retroactive quantum decryption.", algoText),
			Steps: []string{
				"Configure TLS termination endpoints and client applications to negotiate X25519MLKEM768 (FIPS 203) hybrid key encapsulation.",
				"In Java / Spring Boot microservices, autowire PqcStarterLib HybridHandshakeOrchestrator to enforce hybrid session secrets.",
				"Mandate minimum 256-bit symmetric session ciphers (TLS_AES_256_GCM_SHA384) to eliminate Grover's 64-bit vulnerability.",
			},
			CodeSnippet: `// Spring Boot (PqcStarterLib) Remediation: NIST FIPS 203 ML-KEM Session Key Exchange
@Autowired
private HybridHandshakeOrchestrator pqcHandshake;

// Protects session traffic against Harvest Now, Decrypt Later (HNDL):
HandshakeSession session = pqcHandshake.establishHybridSession("service-endpoint");
byte[] sharedSecret = session.getDerivedKey(); // HKDF(ECDHE-P384 || Kyber-768)`,
		}
	}

	if isSignature && !isKeyEstablishment {
		return RemediationPlan{
			Recommendation: fmt.Sprintf("⚠️ SHOR'S FORGERY RISK: %s is used for Authentication / Digital Signatures. Upgrade to NIST FIPS 204 (ML-DSA-65) to protect against future quantum signature forgery and CA spoofing.", algoText),
			Steps: []string{
				"Plan PKI transition to NIST FIPS 204 (ML-DSA) or FIPS 205 (SLH-DSA) digital signatures prior to CRQC realization.",
				"In Spring Boot microservices, replace RS256/ES256 JWT filters with DilithiumJwtFilter for quantum-safe identity verification.",
				"Issue dual-signature / composite X.509 certificates to maintain backward compatibility with legacy classical clients.",
			},
			CodeSnippet: `// Spring Boot (PqcStarterLib) Remediation: NIST FIPS 204 ML-DSA Digital Signature
@Autowired
private DilithiumSigningEngine dilithiumSigner;

// Generates quantum-safe signature immune to Shor's factorization:
byte[] signature = dilithiumSigner.signString(privateKey, payload);
boolean valid = dilithiumSigner.verifyString(publicKey, payload, signature);`,
		}
	}

	return RemediationPlan{
		Recommendation: fmt.Sprintf("Upgrade %s certificate to dual-certificate architecture supporting NIST FIPS 204 (ML-DSA) and hybrid key encapsulation (FIPS 203 ML-KEM) to block Harvest Now Decrypt Later (HNDL).", algoText),
		Steps: []string{
			"Audit certificate consumers (web servers, load balancers, client applications) for PQC readiness.",
			"Deploy hybrid composite certificate (X.509 with ML-DSA + RSA extension) to maintain backward compatibility.",
			"Configure TLS termination endpoints to negotiate X25519MLKEM768 hybrid key exchange to defend data in transit against HNDL.",
		},
		CodeSnippet: `# OpenSSL 3.3+ command to inspect certificate parameters and key usage:
openssl x509 -in "` + path + `" -noout -text | grep -E "(Signature Algorithm|Subject|Key Usage|Extended Key Usage)"`,
	}
}

// GenerateRemediation is the standard wrapper for backwards compatibility
func GenerateRemediation(assetType string, algorithm string, keySize int, name string, description string, path string) RemediationPlan {
	return GenerateRemediationWithUsage(assetType, algorithm, keySize, name, description, path, false, false)
}

