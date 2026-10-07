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
		// Build a verification command that ACTUALLY works for the given location.
		// A Windows cert-store provider path cannot be read by `certutil -dump`
		// (it expects a file), so use Get-ChildItem there instead.
		dumpCmd := `openssl x509 -in "` + path + `" -text -noout`
		if runtime.GOOS == "windows" {
			if strings.Contains(path, "certificate::") || strings.Contains(lowerPath, "currentuser") || strings.Contains(lowerPath, "localmachine") {
				dumpCmd = "Get-ChildItem Cert: -Recurse | Where-Object { try { $_.GetRSAPublicKey().KeySize -lt 2048 } catch { $false } } | Format-List Subject, Thumbprint, NotAfter, SignatureAlgorithm, @{N='KeySizeBits';E={ try { $_.GetRSAPublicKey().KeySize } catch { 0 } }}"
			} else {
				dumpCmd = `certutil -dump "` + path + `"` // a real file path — valid
			}
		} else if strings.Contains(path, "keychain") {
			dumpCmd = `/usr/bin/security find-certificate -a -p "` + path + `" | openssl x509 -text -noout`
		}
		return RemediationPlan{
			Recommendation: fmt.Sprintf("%d-bit RSA is below the NIST-mandated 2048-bit minimum (disallowed for new use since 2013) and is within reach of well-resourced classical attackers; it is also fully broken by Shor's algorithm once a cryptographically-relevant quantum computer (CRQC) exists. Re-key to RSA-3072+/ECDSA P-384 now and plan migration to ML-DSA (FIPS 204).", keySize),
			Steps: []string{
				"Confirm whether this is a certificate your organization issued/controls (typically in the Personal \\My store) versus a trust-anchor you do not own (root/intermediate CA store).",
				"For a cert you control: re-issue with RSA-3072+ or ECDSA P-384 and plan ML-DSA (FIPS 204) compliance.",
				"For a trust-anchor you do not own: track the CA operator's post-quantum roadmap; remove it only if your organization no longer needs to trust that CA.",
			},
			CodeSnippet: `# Inspect the certificate's real key size, algorithm and validity:
` + dumpCmd,
		}
	}

	// 3. Database Root CAs (e.g. db_root_ca_*.cer) → canonical 4-phase cert remediation
	//    with database-specific hardening (sslmode=verify-full) and verification (psql).
	if strings.Contains(lowerName, "db_root") || strings.Contains(lowerName, "root_ca") || strings.Contains(lowerName, "database") {
		return buildCertRemediation(algorithm, keySize, name, path, lowerName, lowerPath, isKeyEstablishment, isSignature, true)
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

	// 6. Symmetric ciphers (AES-128 → Grover; RC4/DES/3DES/Blowfish/CAST5/RC2 →
	//    classically broken). These migrate to AES-256-GCM, NOT to a PQC KEM/
	//    signature — route them here so they don't fall through to the PQC fallback.
	if strings.Contains(lowerName, "aes128") || strings.Contains(lowerName, "aes-128") || strings.Contains(lowerDesc, "grover") ||
		strings.Contains(lowerName, "3des") || strings.Contains(lowerName, "blowfish") || strings.Contains(lowerName, "rc4") ||
		strings.Contains(lowerName, "arcfour") || strings.Contains(lowerName, "cast5") || strings.Contains(lowerName, "rc2") ||
		strings.Contains(lowerName, "_des_") || strings.Contains(lowerName, "des-") || strings.Contains(lowerName, "des_") ||
		strings.Contains(lowerDesc, "classically broken") {
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

	// 8. All remaining X.509 certificate findings → canonical 4-phase PQC remediation,
	//    tailored to the cert's function (FIPS 204 ML-DSA signatures vs FIPS 203 ML-KEM
	//    key establishment — never conflated). Covers signature, key-establishment,
	//    dual-purpose and undetermined-usage certs.
	return buildCertRemediation(algorithm, keySize, name, path, lowerName, lowerPath, isKeyEstablishment, isSignature, false)
}

// buildCertRemediation produces the canonical four-phase, FIPS-203/204-separated PQC
// remediation shared by every X.509 certificate finding (database root CAs, signature
// certs, key-establishment certs, generic/undetermined certs).
//
// Design rules (so the output survives review by a crypto architect / an AI check):
//   - TLS hardening (TLS 1.3, chain + hostname validation, sslmode=verify-full) is a
//     PREREQUISITE, explicitly NOT presented as PQC.
//   - FIPS 203 (ML-KEM) = key establishment; FIPS 204 (ML-DSA) = signatures. Never mixed.
//   - PQC steps are CONDITIONAL on the full stack (engine → TLS lib → each client driver)
//     supporting it — no blanket "install liboqs/Bouncy Castle".
//   - Verification is done on a LIVE connection, not just the static certificate file.
func buildCertRemediation(algorithm string, keySize int, name, path, lowerName, lowerPath string, isKeyEstablishment, isSignature, isDatabase bool) RemediationPlan {
	algoText := algorithm
	if keySize > 0 {
		algoText = fmt.Sprintf("%s-%d", algorithm, keySize)
	}

	// Tailor the function description, risk framing and migration target to the cert's
	// actual key usage. Complementary-function reminders are included without conflation.
	var funcDesc, riskDesc, migrateStep string
	switch {
	case isSignature && !isKeyEstablishment:
		funcDesc = "digital-signature / authentication (a certificate/CA-impersonation and integrity risk, NOT an immediate data-interception / HNDL risk)"
		riskDesc = "Once a CRQC exists, Shor's algorithm could forge signatures or impersonate this certificate's identity."
		migrateStep = "Phase 3 — PQC migration (only where the full stack supports it): migrate the certificate/CA signature to ML-DSA (FIPS 204) or an approved composite-hybrid signature. If this certificate also secures a TLS endpoint, separately move that endpoint's key establishment to ML-KEM (FIPS 203) / a hybrid group. Deploy the matching certificates and trust chain, then validate interoperability with every client."
	case isKeyEstablishment && !isSignature:
		funcDesc = "key-establishment / encryption (an active Harvest-Now-Decrypt-Later confidentiality risk)"
		riskDesc = "Traffic recorded today can be retroactively decrypted once a CRQC exists."
		migrateStep = "Phase 3 — PQC migration (only where the full stack supports it): migrate the TLS key establishment to ML-KEM (FIPS 203) or a hybrid group (e.g. X25519MLKEM768), and migrate the certificate's own signature to ML-DSA (FIPS 204). Deploy the matching certificates and trust chain, then validate interoperability with every client."
	case isKeyEstablishment && isSignature:
		funcDesc = "both key-establishment AND digital-signature (subject to both HNDL confidentiality capture and future signature forgery)"
		riskDesc = "Recorded traffic is retroactively decryptable, and signatures/identity are forgeable, once a CRQC exists."
		migrateStep = "Phase 3 — PQC migration (only where the full stack supports it): migrate signatures to ML-DSA (FIPS 204) AND key establishment to ML-KEM (FIPS 203) / a hybrid group (e.g. X25519MLKEM768). Deploy the matching certificates and trust chain, then validate interoperability with every client."
	default:
		funcDesc = "an undetermined function — treat as both signature and key-establishment until the certificate's key usage is confirmed"
		riskDesc = "Treat as exposed to both future signature forgery and (where used for key exchange) Harvest-Now-Decrypt-Later."
		migrateStep = "Phase 3 — PQC migration (only where the full stack supports it): confirm the certificate's usage, then migrate signatures to ML-DSA (FIPS 204) and/or key establishment to ML-KEM (FIPS 203) / a hybrid group accordingly. Deploy the matching certificates and trust chain, then validate interoperability with every client."
	}

	subject := "This certificate"
	if isDatabase {
		subject = "This database root CA"
	}

	rec := fmt.Sprintf("%s (%s) uses a classical algorithm (RSA/ECDSA) vulnerable to Shor's algorithm on a future CRQC. Function: %s. %s Remediate in phases. IMPORTANT: enforcing TLS 1.3 + full certificate validation (and adding a PQC root to the trust store) are hardening prerequisites — they do NOT by themselves make the connection quantum-resistant. The entire path must be PQC-capable: CA signature → certificate signature (ML-DSA, FIPS 204) and TLS key establishment (ML-KEM, FIPS 203, or a hybrid group). FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) address different functions — do not conflate them.", subject, algoText, funcDesc, riskDesc)

	hardeningStep := "Phase 1 — Hardening (prerequisite, NOT yet PQC): require TLS 1.3 where supported (TLS 1.2 minimum), enforce full certificate-chain + hostname validation, and remove trust in expired/weak/unneeded CAs. Confirm this certificate's signature algorithm and expiry."
	readinessStep := "Phase 2 — PQC readiness assessment: determine whether the serving stack, its TLS library, and EACH client support PQC/hybrid TLS (capabilities differ widely — do NOT assume a single provider like liboqs / Bouncy Castle applies everywhere). Identify where the chain is RSA/ECDSA-only and whether key establishment is classical or hybrid."
	if isDatabase {
		hardeningStep = "Phase 1 — Hardening (prerequisite, NOT yet PQC): require TLS 1.3 where the DB supports it (TLS 1.2 minimum), enforce full chain + hostname validation (PostgreSQL: sslmode=verify-full with the correct sslrootcert), and remove trust in expired/weak/unneeded CAs. Confirm this certificate's signature algorithm and expiry."
		readinessStep = "Phase 2 — PQC readiness assessment: determine whether this specific database engine, its TLS library, and EACH client driver support PQC/hybrid TLS (capabilities differ widely across libpq, JDBC, ODBC, SQL Server, Oracle, MySQL — do NOT assume a single provider like liboqs / Bouncy Castle applies everywhere). Identify where the chain is RSA/ECDSA-only and whether key establishment is classical or hybrid."
	}
	verifyStep := "Phase 4 — Verification: prove it on a LIVE connection — confirm the negotiated certificate algorithm, chain trust, TLS version, TLS signature algorithm, and key-exchange/KEM — not just the static certificate file."

	// Inspection command: a Windows cert-store provider path cannot be read by
	// `openssl x509 -in` (it expects a file), so use Get-ChildItem there instead.
	inspectCmd := `openssl x509 -in "` + path + `" -noout -text | grep -E "(Signature Algorithm|Public Key Algorithm|Public-Key|Issuer|Subject|Not Before|Not After)"`
	if runtime.GOOS == "windows" && (strings.Contains(path, "certificate::") || strings.Contains(lowerPath, "currentuser") || strings.Contains(lowerPath, "localmachine")) {
		inspectCmd = "Get-ChildItem Cert: -Recurse | Where-Object { $_.Thumbprint } | Format-List Subject, Issuer, Thumbprint, SignatureAlgorithm, NotBefore, NotAfter, PublicKey"
	}

	// Live-verification port: default 443, or a database port inferred from the cert name.
	port := "443"
	hostPlaceholder := "<host>"
	psqlLine := ""
	if isDatabase {
		hostPlaceholder = "<db-host>"
		port = "5432" // PostgreSQL default
		if strings.Contains(lowerName, "mysql") || strings.Contains(lowerName, "maria") {
			port = "3306"
		} else if strings.Contains(lowerName, "mssql") || strings.Contains(lowerName, "sqlserver") {
			port = "1433"
		} else if strings.Contains(lowerName, "oracle") {
			port = "2484"
		}
		psqlLine = "\n\n# (3) POSTGRES client check — confirm full verification against the intended CA bundle:\n# psql \"host=<db-host> port=" + port + " sslmode=verify-full sslrootcert=ca.crt\" -c \"SHOW ssl;\""
	}

	snippet := "# (1) INSPECT the certificate (algorithm, key size, validity) — inspection only, does NOT prove what the server uses:\n" +
		inspectCmd +
		"\n\n# (2) VERIFY the LIVE TLS session actually negotiated (proves cert-in-use, chain, TLS version and\n" +
		"#     key-exchange group). Replace " + hostPlaceholder + " with the real endpoint:\n" +
		"openssl s_client -connect " + hostPlaceholder + ":" + port + " -servername " + hostPlaceholder + " -tls1_3 -showcerts </dev/null 2>/dev/null \\\n" +
		"  | grep -E \"(Protocol|Cipher|Server Temp Key|Peer signature|Verify return code)\"\n" +
		"#     \"Server Temp Key: X25519MLKEM768\" would confirm hybrid PQC key exchange is actually in use." +
		psqlLine

	return RemediationPlan{
		Recommendation: rec,
		Steps:          []string{hardeningStep, readinessStep, migrateStep, verifyStep},
		CodeSnippet:    snippet,
	}
}

// GenerateRemediation is the standard wrapper for backwards compatibility
func GenerateRemediation(assetType string, algorithm string, keySize int, name string, description string, path string) RemediationPlan {
	return GenerateRemediationWithUsage(assetType, algorithm, keySize, name, description, path, false, false)
}
