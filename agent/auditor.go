package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

type AuditResult struct {
	ID                   string   `json:"id"`
	Type                 string   `json:"type"`
	Name                 string   `json:"name"`
	Path                 string   `json:"path,omitempty"`
	Algorithm            string   `json:"algorithm"`
	KeySize              int      `json:"keySize,omitempty"`
	HashAlgorithm        string   `json:"hashAlgorithm,omitempty"`
	QuantumThreat        string   `json:"quantumThreat,omitempty"`
	IsVulnerable         bool     `json:"isVulnerable"`
	RiskLevel            string   `json:"riskLevel"`
	Status               string   `json:"status"`
	Description          string   `json:"description"`
	Recommendation       string   `json:"recommendation"`
	RemediationSteps     []string `json:"remediationSteps,omitempty"`
	CodeSnippet          string   `json:"codeSnippet,omitempty"`
	Explainer            string   `json:"explainer"`
	ComplianceViolations []string `json:"complianceViolations"`
}

type LineViolation struct {
	LineNumber  int    `json:"lineNumber"`
	LineContent string `json:"lineContent"`
	Issue       string `json:"issue"`
	RiskLevel   string `json:"riskLevel"`
	Fix         string `json:"fix"`
}

type ConfigAuditResult struct {
	FileName       string          `json:"fileName"`
	IsVulnerable   bool            `json:"isVulnerable"`
	Violations     []LineViolation `json:"violations"`
	Summary        string          `json:"summary"`
	Recommendation string          `json:"recommendation"`
}

func generateID() string {
	rand.Seed(time.Now().UnixNano())
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, 8)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func estimateRsaKeySize(base64Data string) int {
	// Heuristics based on base64 character count
	charCount := len(base64Data)
	if charCount > 650 {
		return 4096
	}
	if charCount > 340 {
		return 2048
	}
	return 1024
}

// AuditSSHKey audits public SSH key strings
func AuditSSHKey(keyString string, label string, path string) AuditResult {
	clean := strings.TrimSpace(keyString)
	parts := strings.Fields(clean)

	if len(parts) < 2 {
		return AuditResult{
			ID:             generateID(),
			Type:           "ssh_key",
			Name:           label,
			Path:           path,
			Algorithm:      "Unknown",
			IsVulnerable:   true,
			RiskLevel:      "critical",
			Status:         "Quantum Vulnerable",
			QuantumThreat:  "Shor's Algorithm (DLP/Factorization)",
			Description:    "Invalid or malformed SSH public key format.",
			Recommendation: "Ensure key is formatted as '<key-type> <base64> [comment]'.",
			Explainer:      "Failed to parse public key fields.",
		}
	}

	keyType := parts[0]
	base64Data := parts[1]
	comment := label
	if len(parts) > 2 {
		comment = strings.Join(parts[2:], " ")
	}

	algorithm := "Unknown"
	keySize := 0
	isVulnerable := true
	riskLevel := "high"
	description := ""
	recommendation := ""
	explainer := ""
	complianceViolations := []string{}
	quantumThreat := "Shor's Algorithm (DLP/Factorization)"

	switch keyType {
	case "ssh-rsa":
		algorithm = "RSA"
		keySize = estimateRsaKeySize(base64Data)
		isVulnerable = true
		if keySize < 2048 {
			riskLevel = "critical"
		} else {
			riskLevel = "high"
		}
		description = fmt.Sprintf("Vulnerable SSH public key utilizing the RSA-%d algorithm.", keySize)
		explainer = "RSA depends on prime factorization. Shor's algorithm running on a quantum computer solves integer factorization in cubic time, breaking RSA of any bit strength."
		complianceViolations = []string{"CNSA 2.0", "NIST SP 800-208", "EO 14028"}
		quantumThreat = "Shor's Algorithm (Asymmetric Factorization)"

	case "ssh-dss":
		algorithm = "DSA"
		keySize = 1024
		isVulnerable = true
		riskLevel = "critical"
		description = "Legacy SSH public key using the insecure DSA algorithm."
		explainer = "DSA is classically broken and completely vulnerable to Shor's algorithm solving discrete logarithms."
		complianceViolations = []string{"NIST SP 800-131A", "CNSA 2.0", "EO 14028"}
		quantumThreat = "Shor's Algorithm (Classically Broken)"

	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		algorithm = "ECDSA"
		if strings.Contains(keyType, "nistp256") {
			keySize = 256
		} else if strings.Contains(keyType, "nistp384") {
			keySize = 384
		} else {
			keySize = 521
		}
		isVulnerable = true
		riskLevel = "high"
		description = fmt.Sprintf("Vulnerable Elliptic Curve signature (ECDSA) public key on curve P-%d.", keySize)
		explainer = "Elliptic curves rely on the discrete log problem. Shor's algorithm breaks elliptic curves even faster than RSA due to smaller key parameters."
		complianceViolations = []string{"CNSA 2.0", "NIST SP 800-208", "EO 14028"}
		quantumThreat = "Shor's Algorithm (Discrete Log)"

	case "ssh-ed25519":
		algorithm = "Ed25519"
		keySize = 256
		isVulnerable = true
		riskLevel = "high"
		description = "Vulnerable modern classical Elliptic Curve Signature (Ed25519) public key."
		explainer = "Although Ed25519 is classically secure, the elliptic curve discrete logarithm problem is easily solved by a quantum computer running Shor's algorithm."
		complianceViolations = []string{"CNSA 2.0", "NIST SP 800-208"}
		quantumThreat = "Shor's Algorithm (Discrete Log)"

	case "sntrup761x25519-sha512@openssh.com":
		algorithm = "sntrup761-x25519 (Hybrid)"
		keySize = 858
		isVulnerable = false
		riskLevel = "secure"
		description = "Quantum-safe hybrid key exchange key combining Streamlined NTRU Prime 761 and Curve25519."
		recommendation = "Maintain deployment. Fully compliant with OpenSSH hybrid post-quantum standards."
		explainer = "Lattice-based NTRU Prime secures the exchange from quantum analysis; Curve25519 provides classical assurance."
		complianceViolations = []string{}
		quantumThreat = "Post-Quantum Resilient (Protected against Shor & HNDL)"

	default:
		if strings.Contains(strings.ToLower(keyType), "ml-dsa") || strings.Contains(strings.ToLower(keyType), "dilithium") {
			algorithm = "ML-DSA"
			isVulnerable = false
			riskLevel = "secure"
			description = "NIST Standard Post-Quantum Digital Signature Algorithm (ML-DSA)."
			recommendation = "Secure. Keep monitored."
			explainer = "ML-DSA lattice schemes are secure against both classical and quantum algorithms."
			complianceViolations = []string{}
			quantumThreat = "Post-Quantum Secure"
		} else {
			algorithm = keyType
			isVulnerable = true
			riskLevel = "medium"
			description = fmt.Sprintf("Unrecognized key type: %s.", keyType)
			explainer = "Assume any classical asymmetric key type is quantum-vulnerable unless mathematically proven otherwise."
			complianceViolations = []string{"NIST SP 800-208"}
			quantumThreat = "Shor's Algorithm Risk"
		}
	}

	status := "Quantum Vulnerable"
	if !isVulnerable {
		status = "Post-Quantum Secure"
	}

	plan := GenerateRemediation("ssh_key", algorithm, keySize, label, description, path)
	if recommendation == "" {
		recommendation = plan.Recommendation
	}

	return AuditResult{
		ID:                   generateID(),
		Type:                 "ssh_key",
		Name:                 comment,
		Path:                 path,
		Algorithm:            algorithm,
		KeySize:              keySize,
		QuantumThreat:        quantumThreat,
		IsVulnerable:         isVulnerable,
		RiskLevel:            riskLevel,
		Status:               status,
		Description:          description,
		Recommendation:       recommendation,
		RemediationSteps:     plan.Steps,
		CodeSnippet:          plan.CodeSnippet,
		Explainer:            explainer,
		ComplianceViolations: complianceViolations,
	}
}

// AuditPEMCertificate audits raw PEM file blocks (certificates and keys)
func AuditPEMCertificate(pemString string, label string, path string) AuditResult {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return AuditResult{
			ID:             generateID(),
			Type:           "certificate",
			Name:           label,
			Path:           path,
			Algorithm:      "Unknown",
			IsVulnerable:   true,
			RiskLevel:      "critical",
			Status:         "Quantum Vulnerable",
			QuantumThreat:  "Malformed Encoding",
			Description:    "Failed to decode PEM certificate body. Check headers.",
			Recommendation: "Verify PEM syntax includes '-----BEGIN CERTIFICATE-----'.",
			Explainer:      "Malformed file encoding.",
		}
	}

	assetType := "certificate"
	if strings.Contains(block.Type, "PRIVATE KEY") {
		assetType = "private_key"
	}

	algorithm := "RSA"
	keySize := 2048
	isVulnerable := true
	riskLevel := "high"
	description := ""
	explainer := ""
	complianceViolations := []string{"CNSA 2.0", "NIST SP 800-208", "EO 14028"}
	quantumThreat := "Shor's Algorithm (Asymmetric Factorization/DLP)"

	isKeyEstablishment := false
	isSignature := false

	// Native x509 certificate parsing
	if block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			isKeyEstablishment = cert.KeyUsage&(x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment|x509.KeyUsageKeyAgreement) != 0
			isSignature = cert.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0

			for _, eku := range cert.ExtKeyUsage {
				if eku == x509.ExtKeyUsageServerAuth {
					isKeyEstablishment = true
				}
				if eku == x509.ExtKeyUsageClientAuth || eku == x509.ExtKeyUsageCodeSigning || eku == x509.ExtKeyUsageTimeStamping {
					isSignature = true
				}
			}

			// Extract parameters natively
			switch cert.PublicKeyAlgorithm {
			case x509.RSA:
				algorithm = "RSA"
				if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok && rsaKey != nil && rsaKey.N != nil {
					keySize = rsaKey.N.BitLen()
				}
				if keySize < 2048 {
					riskLevel = "critical"
				}
				explainer = "RSA prime factorization is solved in polynomial time by Shor's Algorithm."
			case x509.ECDSA:
				algorithm = "ECDSA"
				keySize = 256
				if ecdsaKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok && ecdsaKey != nil && ecdsaKey.Params() != nil {
					keySize = ecdsaKey.Params().BitSize
				}
				explainer = "Elliptic curve discrete log problem is solved by Shor's Algorithm faster than RSA."
			default:
				algorithm = cert.PublicKeyAlgorithm.String()
			}

			funcTag := "General TLS Certificate"
			if isKeyEstablishment && !isSignature {
				funcTag = "Key Establishment / Encryption"
				quantumThreat = "Harvest Now, Decrypt Later (HNDL) & Shor's Algorithm"
				explainer = "Certificate utilized for Key Establishment. 🚨 Active HNDL concern: Encrypted traffic recorded today can be retroactively decrypted by a future quantum computer."
				complianceViolations = []string{"CNSA 2.0", "NIST FIPS 203 (ML-KEM)", "EO 14028"}
			} else if isSignature && !isKeyEstablishment {
				funcTag = "Authentication / Digital Signature"
				quantumThreat = "Shor's Algorithm (Signature Forgery & Spoofing)"
				explainer = "Certificate utilized for Authentication / Digital Signature. ⚠️ Future Shor's Risk: No immediate HNDL data interception; signatures can be forged once a CRQC exists."
				complianceViolations = []string{"CNSA 2.0", "NIST FIPS 204 (ML-DSA)", "EO 14028"}
			} else if isKeyEstablishment && isSignature {
				funcTag = "Dual: Key Establishment (HNDL) & Authentication (Shor's)"
				quantumThreat = "Active HNDL (Key Exchange) & Shor's (Signatures)"
				explainer = "Dual-purpose certificate. Subject to both active Harvest Now Decrypt Later (HNDL) traffic recording and future Shor's signature forgery."
				complianceViolations = []string{"CNSA 2.0", "NIST FIPS 203 (ML-KEM)", "NIST FIPS 204 (ML-DSA)"}
			}

			description = fmt.Sprintf("Quantum-vulnerable [%s] utilizing %s-%d.", funcTag, algorithm, keySize)
		}
	}

	if description == "" {
		// Heuristics fallback for key files
		base64Len := len(block.Bytes)
		if strings.Contains(block.Type, "RSA") || base64Len > 400 {
			algorithm = "RSA"
			if base64Len > 800 {
				keySize = 4096
			} else if base64Len > 250 {
				keySize = 2048
			} else {
				keySize = 1024
			}
			if keySize < 2048 {
				riskLevel = "critical"
			}
			description = fmt.Sprintf("Quantum-vulnerable RSA-%d %s file.", keySize, strings.ToLower(block.Type))
			explainer = "Shor's Algorithm factoring prime moduli. Plaintext private keys on disk also vulnerable to credential harvesting."
		} else {
			algorithm = "ECDSA / ECDH"
			keySize = 256
			description = fmt.Sprintf("Quantum-vulnerable Elliptic Curve %s file.", strings.ToLower(block.Type))
			explainer = "Discrete logarithm solved in polynomial time via Shor's Algorithm."
		}
	}

	status := "Quantum Vulnerable"
	if !isVulnerable {
		status = "Post-Quantum Secure"
	}

	plan := GenerateRemediationWithUsage(assetType, algorithm, keySize, label, description, path, isKeyEstablishment, isSignature)

	return AuditResult{
		ID:                   generateID(),
		Type:                 assetType,
		Name:                 label,
		Path:                 path,
		Algorithm:            algorithm,
		KeySize:              keySize,
		QuantumThreat:        quantumThreat,
		IsVulnerable:         isVulnerable,
		RiskLevel:            riskLevel,
		Status:               status,
		Description:          description,
		Recommendation:       plan.Recommendation,
		RemediationSteps:     plan.Steps,
		CodeSnippet:          plan.CodeSnippet,
		Explainer:            explainer,
		ComplianceViolations: complianceViolations,
	}
}

// AuditConfigFile audits server configuration files for protocols
func AuditConfigFile(fileName string, content string) ConfigAuditResult {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var violations []LineViolation
	isVulnerable := false
	lineNum := 0

	lowerName := strings.ToLower(fileName)
	isNginx := strings.Contains(lowerName, "nginx") || strings.Contains(content, "ssl_ciphers") || strings.Contains(content, "ssl_protocols")
	isSSH := strings.Contains(lowerName, "ssh") || strings.Contains(content, "KexAlgorithms") || strings.Contains(content, "Ciphers")

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if isNginx {
			if strings.HasPrefix(line, "ssl_protocols") {
				if strings.Contains(line, "TLSv1.0") || strings.Contains(line, "TLSv1.1") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "Obsolete TLS versions (TLSv1.0/1.1) enabled.",
						RiskLevel:   "critical",
						Fix:         "Force TLSv1.3 and TLSv1.2 only.",
					})
				}
				if !strings.Contains(line, "TLSv1.3") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "TLSv1.3 is not explicitly enabled. TLSv1.3 is required for post-quantum curves.",
						RiskLevel:   "high",
						Fix:         "Update protocols to: 'ssl_protocols TLSv1.2 TLSv1.3;'",
					})
				}
			}

			if strings.HasPrefix(line, "ssl_ciphers") {
				if strings.Contains(line, "RC4") || strings.Contains(line, "3DES") || strings.Contains(line, "MD5") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "Classically broken algorithms (RC4, 3DES, MD5) enabled (also annihilated by Grover's Algorithm).",
						RiskLevel:   "critical",
						Fix:         "Replace with modern AEAD-only ciphers (AES-256-GCM / Chacha20-Poly1305).",
					})
				}
				if strings.Contains(line, "AES128") || strings.Contains(line, "aes128") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "Symmetric cipher AES-128 weakened by Grover's Algorithm (effective security halved to 64 bits).",
						RiskLevel:   "high",
						Fix:         "Upgrade to AES-256 ciphers (e.g. TLS_AES_256_GCM_SHA384) to preserve 128-bit quantum resistance under CNSA 2.0.",
					})
				}
				if !strings.Contains(line, "X25519MLKEM768") && !strings.Contains(line, "Kyber") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "No Post-Quantum key exchange curves (ML-KEM / Kyber) enabled: Active Harvest Now, Decrypt Later (HNDL) risk.",
						RiskLevel:   "medium",
						Fix:         "Prepend PQ hybrid curves (e.g. X25519+MLKEM768) to protect recorded traffic from retrospective decryption.",
					})
				}
			}
		} else if isSSH {
			if strings.HasPrefix(line, "KexAlgorithms") {
				if strings.Contains(line, "diffie-hellman-group1-sha1") || strings.Contains(line, "diffie-hellman-group14-sha1") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "Weak Diffie-Hellman ciphers with SHA-1 enabled (broken classically + Shor factorization).",
						RiskLevel:   "critical",
						Fix:         "Decommission SHA-1 Diffie-Hellman algorithms.",
					})
				}
				if !strings.Contains(line, "sntrup761x25519") && !strings.Contains(line, "mlkem") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "Post-Quantum KEX (sntrup761x25519-sha512 / ML-KEM) not enabled: Active Harvest Now, Decrypt Later (HNDL) risk.",
						RiskLevel:   "medium",
						Fix:         "Prepend 'sntrup761x25519-sha512@openssh.com' to KexAlgorithms to protect SSH sessions against HNDL.",
					})
				}
			}
			if strings.HasPrefix(line, "Ciphers") {
				if strings.Contains(line, "aes128") || strings.Contains(line, "aes-128") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "Symmetric cipher AES-128 weakened by Grover's Algorithm (effective security halved to 64 bits).",
						RiskLevel:   "high",
						Fix:         "Upgrade symmetric ciphers to AES-256 (aes256-gcm@openssh.com / aes256-ctr) to maintain 128-bit quantum security.",
					})
				}
				if strings.Contains(line, "3des-cbc") || strings.Contains(line, "blowfish-cbc") || strings.Contains(line, "arcfour") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "Weak symmetric CBC/legacy ciphers enabled (broken classically and destroyed by Grover's Algorithm).",
						RiskLevel:   "critical",
						Fix:         "Restrict ciphers to AES-256-GCM and Chacha20-Poly1305.",
					})
				}
			}
		} else {
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "sha1") || strings.Contains(lineLower, "md5") {
				isVulnerable = true
				violations = append(violations, LineViolation{
					LineNumber:  lineNum,
					LineContent: line,
					Issue:       "Insecure hash reference (SHA-1 / MD5) detected: Collision resistance collapsed under Grover's Algorithm.",
					RiskLevel:   "high",
					Fix:         "Migrate hashing to SHA-384 or SHA-512 for CNSA 2.0 compliance.",
				})
			}
		}
	}

	summary := fmt.Sprintf("No obvious quantum-vulnerable configurations found in %s.", fileName)
	recommend := "Maintain config."
	if isVulnerable {
		summary = fmt.Sprintf("Discovered %d vulnerabilities in config %s.", len(violations), fileName)
		recommend = "Update configuration parameters to enforce post-quantum algorithms."
	}

	return ConfigAuditResult{
		FileName:       fileName,
		IsVulnerable:   isVulnerable,
		Violations:     violations,
		Summary:        summary,
		Recommendation: recommend,
	}
}

// CycloneDX 1.6 CBOM Data Structures
type CBOMProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CBOMAlgoProperties struct {
	Primitive                string `json:"primitive"`
	Curve                    string `json:"curve,omitempty"`
	NistQuantumSecurityLevel int    `json:"nistQuantumSecurityLevel"`
}

// cdxAssetType maps an internal asset type to a valid CycloneDX 1.6
// cryptoProperties.assetType enum value.
func cdxAssetType(t string) string {
	switch strings.ToLower(t) {
	case "certificate", "ca_root":
		return "certificate"
	case "private_key", "public_key", "ssh_key", "key":
		return "related-crypto-material"
	case "network_probe", "protocol", "config":
		return "protocol"
	default:
		return "algorithm"
	}
}

// cdxPrimitive maps an algorithm name to a valid CycloneDX algorithmProperties.primitive.
func cdxPrimitive(algo string) string {
	a := strings.ToLower(algo)
	switch {
	case strings.Contains(a, "rsa"):
		return "pke"
	case strings.Contains(a, "ecdsa"), strings.Contains(a, "ed25519"), strings.Contains(a, "dsa"):
		return "signature"
	case strings.Contains(a, "ecdh"), strings.Contains(a, "kem"), strings.Contains(a, "mlkem"), strings.Contains(a, "x25519"):
		return "kem"
	case strings.Contains(a, "aes"), strings.Contains(a, "chacha"):
		return "ae"
	case strings.Contains(a, "hmac"):
		return "mac"
	case strings.Contains(a, "sha"), strings.Contains(a, "md5"):
		return "hash"
	default:
		return "unknown"
	}
}

type CBOMCryptoProperties struct {
	AssetType          string             `json:"assetType"`
	AlgorithmProperties CBOMAlgoProperties `json:"algorithmProperties"`
}

type CBOMComponent struct {
	Type             string               `json:"type"`
	BomRef           string               `json:"bom-ref"`
	Name             string               `json:"name"`
	CryptoProperties CBOMCryptoProperties `json:"cryptoProperties"`
	Properties       []CBOMProperty       `json:"properties"`
}

type CBOMMetadata struct {
	Timestamp string `json:"timestamp"`
	Component struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"component"`
}

type CycloneDXCBOM struct {
	BomFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     CBOMMetadata    `json:"metadata"`
	Components   []CBOMComponent `json:"components"`
}

// GenerateCycloneDXCBOM produces a standardized CycloneDX 1.6 Cryptographic Bill of Materials
func GenerateCycloneDXCBOM(assets []AuditResult, hostname string, osName string) ([]byte, error) {
	cbom := CycloneDXCBOM{
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: fmt.Sprintf("urn:uuid:quarkshield-cbom-%s-%d", generateID(), time.Now().Unix()),
		Version:      1,
	}
	cbom.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	cbom.Metadata.Component.Type = "device"
	cbom.Metadata.Component.Name = fmt.Sprintf("%s (%s)", hostname, osName)

	for _, a := range assets {
		qLevel := 0
		if !a.IsVulnerable {
			qLevel = 3
		}

		curve := ""
		if strings.Contains(a.Algorithm, "P-") || strings.Contains(a.Algorithm, "25519") {
			curve = a.Algorithm
		}
		comp := CBOMComponent{
			Type:   "cryptographic-asset",
			BomRef: a.ID,
			Name:   a.Name,
			CryptoProperties: CBOMCryptoProperties{
				AssetType: cdxAssetType(a.Type),
				AlgorithmProperties: CBOMAlgoProperties{
					Primitive:                cdxPrimitive(a.Algorithm),
					Curve:                    curve,
					NistQuantumSecurityLevel: qLevel,
				},
			},
			Properties: []CBOMProperty{
				{Name: "quarkshield:algorithm", Value: a.Algorithm},
				{Name: "quarkshield:keyLength", Value: fmt.Sprintf("%d", a.KeySize)},
				{Name: "quarkshield:quantumStatus", Value: a.Status},
				{Name: "quarkshield:riskLevel", Value: a.RiskLevel},
				{Name: "quarkshield:recommendation", Value: a.Recommendation},
				{Name: "quarkshield:explainer", Value: a.Explainer},
			},
		}
		cbom.Components = append(cbom.Components, comp)
	}

	return json.MarshalIndent(cbom, "", "  ")
}

// AuditDERCertificate audits binary DER encoded certificates (.cer, .crt, .der)
func AuditDERCertificate(cert *x509.Certificate, fileName string, path string) AuditResult {
	algorithm := "RSA"
	keySize := 2048
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		algorithm = "RSA"
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok && rsaKey != nil && rsaKey.N != nil {
			keySize = rsaKey.N.BitLen()
		}
	case x509.ECDSA:
		algorithm = "ECDSA"
		keySize = 256
		if ecdsaKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok && ecdsaKey != nil && ecdsaKey.Params() != nil {
			keySize = ecdsaKey.Params().BitSize
		}
	default:
		algorithm = cert.PublicKeyAlgorithm.String()
	}

	riskLevel := "high"
	if keySize < 2048 {
		riskLevel = "critical"
	}

	subj := cert.Subject.CommonName
	if subj == "" {
		subj = cert.Subject.String()
	}
	if subj == "" {
		subj = fileName
	}

	// Analyze X.509 KeyUsage and ExtendedKeyUsage for functional PQC triaging
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

	quantumThreat := "Shor's Algorithm (Asymmetric Factorization/DLP)"
	explainer := "Asymmetric algorithm breakable via Shor's algorithm."
	complianceViolations := []string{"CNSA 2.0", "NIST FIPS 204", "EO 14028"}
	funcTag := "General Cryptographic Asset"

	if isKeyEstablishment && !isSignature {
		funcTag = "Key Establishment / Transport Encryption"
		quantumThreat = "Harvest Now, Decrypt Later (HNDL) & Shor's Algorithm"
		explainer = "Certificate utilized for Key Establishment. 🚨 Active HNDL concern: Encrypted traffic recorded today can be retroactively decrypted by a future quantum computer."
		complianceViolations = []string{"CNSA 2.0", "NIST FIPS 203 (ML-KEM)", "EO 14028"}
	} else if isSignature && !isKeyEstablishment {
		funcTag = "Authentication / Digital Signature"
		quantumThreat = "Shor's Algorithm (Signature Forgery & Spoofing)"
		explainer = "Certificate utilized for Authentication / Digital Signature. ⚠️ Future Shor's Risk: No immediate HNDL data interception; signatures can be forged once a CRQC exists."
		complianceViolations = []string{"CNSA 2.0", "NIST FIPS 204 (ML-DSA)", "EO 14028"}
	} else if isKeyEstablishment && isSignature {
		funcTag = "Dual: Key Establishment (HNDL) & Authentication (Shor's)"
		quantumThreat = "Active HNDL (Key Exchange) & Shor's (Signatures)"
		explainer = "Dual-purpose certificate. Subject to both active Harvest Now Decrypt Later (HNDL) traffic recording and future Shor's signature forgery."
		complianceViolations = []string{"CNSA 2.0", "NIST FIPS 203 (ML-KEM)", "NIST FIPS 204 (ML-DSA)"}
	}

	desc := fmt.Sprintf("X.509 DER Certificate [%s] at %s. Subject: %s. Expiry: %s", funcTag, path, subj, cert.NotAfter.Format("2006-01-02"))
	plan := GenerateRemediationWithUsage("certificate", algorithm, keySize, fileName, desc, path, isKeyEstablishment, isSignature)

	return AuditResult{
		ID:                   generateID(),
		Type:                 "certificate",
		Name:                 fmt.Sprintf("%s (%s-%d)", fileName, algorithm, keySize),
		Path:                 path,
		Algorithm:            fmt.Sprintf("%s-%d", algorithm, keySize),
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

