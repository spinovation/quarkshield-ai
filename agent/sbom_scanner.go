package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// SbomComponentMetadata holds detailed SBOM attributes for telemetry & CycloneDX export
type SbomComponentMetadata struct {
	Ecosystem      string   `json:"ecosystem"` // "os_pkg", "npm", "pypi", "golang"
	Version        string   `json:"version"`
	License        string   `json:"license"`
	CveList        []string `json:"cveList"`
	RemediationCmd string   `json:"remediationCmd"`
}

// RunSbomScanWithProgress audits workstation software packages, runtimes, and dependencies for CVEs and PQC agility
func RunSbomScanWithProgress(ctx context.Context, onProgress func(currentPath string, scannedCount int, foundCount int)) ([]AuditResult, int, error) {
	var findings []AuditResult
	scannedCount := 0
	lastReport := time.Now()

	reportProgress := func(msg string) {
		scannedCount++
		if onProgress != nil && time.Since(lastReport) > 60*time.Millisecond {
			onProgress(msg, scannedCount, len(findings))
			lastReport = time.Now()
		}
	}

	// 1. Audit OpenSSL
	if ctx != nil && ctx.Err() != nil {
		return findings, scannedCount, ctx.Err()
	}
	reportProgress("Auditing OpenSSL cryptographic library & runtime...")
	if res, ok := auditOpenSslPackage(); ok {
		findings = append(findings, res)
	}

	// 2. Audit OpenSSH
	if ctx != nil && ctx.Err() != nil {
		return findings, scannedCount, ctx.Err()
	}
	reportProgress("Auditing OpenSSH client & server key exchange suites...")
	if res, ok := auditOpenSshPackage(); ok {
		findings = append(findings, res)
	}

	// 3. Audit cURL
	if ctx != nil && ctx.Err() != nil {
		return findings, scannedCount, ctx.Err()
	}
	reportProgress("Auditing cURL network transport & TLS backends...")
	if res, ok := auditCurlPackage(); ok {
		findings = append(findings, res)
	}

	// 4. Audit Git
	if ctx != nil && ctx.Err() != nil {
		return findings, scannedCount, ctx.Err()
	}
	reportProgress("Auditing Git cryptographic transport & signing...")
	if res, ok := auditGitPackage(); ok {
		findings = append(findings, res)
	}

	// 5. Audit Python Cryptography
	if ctx != nil && ctx.Err() != nil {
		return findings, scannedCount, ctx.Err()
	}
	reportProgress("Auditing Python cryptography runtimes & modules...")
	if res, ok := auditPythonCrypto(); ok {
		findings = append(findings, res)
	}

	// 6. Audit System Package Managers (Homebrew on macOS, dpkg/rpm on Linux, Program Files on Windows)
	if ctx != nil && ctx.Err() != nil {
		return findings, scannedCount, ctx.Err()
	}
	reportProgress("Auditing system package manager manifests...")
	pkgFindings := auditSystemPackageManagerPackages(ctx, reportProgress)
	findings = append(findings, pkgFindings...)

	// 7. Audit Project / Repository Manifests (package.json, requirements.txt, go.mod)
	if ctx != nil && ctx.Err() != nil {
		return findings, scannedCount, ctx.Err()
	}
	reportProgress("Auditing project dependencies (package.json, requirements.txt, go.mod)...")
	manifestFindings := auditProjectManifests(ctx, reportProgress)
	findings = append(findings, manifestFindings...)

	if onProgress != nil {
		onProgress("Software Bill of Materials (SBOM) audit complete.", scannedCount, len(findings))
	}

	return findings, scannedCount, nil
}

// -----------------------------------------------------------------------------
// Component Auditing Implementations
// -----------------------------------------------------------------------------

func auditOpenSslPackage() (AuditResult, bool) {
	binPath := findExecutable("openssl", []string{
		"/opt/homebrew/bin/openssl",
		"/usr/local/bin/openssl",
		"/usr/bin/openssl",
		"C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe",
		"C:\\Program Files\\Git\\usr\\bin\\openssl.exe",
	})
	if binPath == "" {
		return AuditResult{}, false
	}

	out, err := exec.Command(binPath, "version").CombinedOutput()
	versionStr := strings.TrimSpace(string(out))
	if err != nil || versionStr == "" {
		versionStr = "OpenSSL 3.0 (Installed)"
	}

	res := AuditResult{
		ID:        "pkg-openssl",
		Type:      "package",
		Name:      "openssl",
		Path:      binPath,
		Algorithm: "TLS 1.3 / AES-256-GCM / SHA-256 / Classical RSA-ECC",
	}

	lowerVer := strings.ToLower(versionStr)
	if strings.Contains(lowerVer, "1.1.1") || strings.Contains(lowerVer, "1.0.") {
		res.IsVulnerable = true
		res.RiskLevel = "critical"
		res.Status = "Critical Vulnerability (OpenSSL 1.x EOL)"
		res.QuantumThreat = "Shor's Factorization (RSA/ECC Only)"
		res.Description = fmt.Sprintf("%s. OpenSSL 1.1.1 reached official End-of-Life in Sept 2023. Vulnerable to CVE-2023-0464, CVE-2023-0286, and lacks lattice PQC agility.", versionStr)
		res.Recommendation = getUpgradeCommand("openssl", "brew install openssl@3", "sudo apt-get --only-upgrade install openssl libssl-dev", "winget upgrade ShiningLight.OpenSSL")
		res.CodeSnippet = res.Recommendation
		res.RemediationSteps = []string{
			"Upgrade OpenSSL to supported 3.x release series.",
			"Install the OpenSSL OQS Provider (liboqs / oqsprovider) for native ML-KEM and ML-DSA support.",
			"Deprecate legacy RSA/ECDSA key pairs and re-issue credentials using hybrid PQC.",
		}
		res.Explainer = "OpenSSL 1.x lacks cryptographic agility and modular provider architecture. Classical RSA and ECC public keys are crackable by Shor's algorithm."
		res.ComplianceViolations = []string{"NIST SP 800-131A", "CNSA 2.0", "CISA KEV"}
	} else if strings.Contains(lowerVer, "3.0.") && (strings.Contains(lowerVer, "3.0.0") || strings.Contains(lowerVer, "3.0.1") || strings.Contains(lowerVer, "3.0.2") || strings.Contains(lowerVer, "3.0.7") || strings.Contains(lowerVer, "3.0.12")) {
		res.IsVulnerable = true
		res.RiskLevel = "high"
		res.Status = "Vulnerable (CVE-2024-0727)"
		res.QuantumThreat = "Classical Provider Architecture"
		res.Description = fmt.Sprintf("%s. Vulnerable to CVE-2024-0727 (PKCS12 NULL pointer dereference) and requires upgrading to 3.0.13+ or 3.3+.", versionStr)
		res.Recommendation = getUpgradeCommand("openssl", "brew upgrade openssl@3", "sudo apt-get --only-upgrade install openssl libssl-dev", "winget upgrade ShiningLight.OpenSSL")
		res.CodeSnippet = res.Recommendation
		res.RemediationSteps = []string{
			"Update OpenSSL to 3.0.13 or 3.3.x.",
			"Enable oqsprovider for hybrid post-quantum key exchange.",
		}
		res.Explainer = "OpenSSL 3.x provider architecture enables post-quantum hybrid algorithms, but installed version contains unpatched vulnerabilities."
		res.ComplianceViolations = []string{"NIST SP 800-52r2"}
	} else {
		res.IsVulnerable = false
		res.RiskLevel = "secure"
		res.Status = "Post-Quantum Agile (OpenSSL 3.x)"
		res.QuantumThreat = "PQC Modular Provider Enabled"
		res.Description = fmt.Sprintf("%s. Modern OpenSSL 3.x cryptographic architecture with provider agility.", versionStr)
		res.Recommendation = "Maintain OpenSSL 3.x updates. Enable oqsprovider for ML-KEM-768 key encapsulation."
		res.Explainer = "OpenSSL 3.x supports pluggable providers. Compatible with NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)."
		res.ComplianceViolations = []string{}
	}

	return res, true
}

func auditOpenSshPackage() (AuditResult, bool) {
	binPath := findExecutable("ssh", []string{
		"/usr/bin/ssh",
		"/usr/local/bin/ssh",
		"/opt/homebrew/bin/ssh",
		"C:\\Windows\\System32\\OpenSSH\\ssh.exe",
		"C:\\Program Files\\OpenSSH\\ssh.exe",
	})
	if binPath == "" {
		return AuditResult{}, false
	}

	cmd := exec.Command(binPath, "-V")
	out, _ := cmd.CombinedOutput()
	versionStr := strings.TrimSpace(string(out))
	if versionStr == "" {
		versionStr = "OpenSSH (Installed)"
	}

	res := AuditResult{
		ID:        "pkg-openssh",
		Type:      "package",
		Name:      "openssh",
		Path:      binPath,
		Algorithm: "SSH-2.0 / sntrup761x25519-sha512 / mlkem768x25519-sha256",
	}

	verMatch := regexp.MustCompile(`OpenSSH_([0-9]+)\.([0-9]+)`).FindStringSubmatch(versionStr)
	isOld := false
	isPqcReady := false
	if len(verMatch) >= 3 {
		major, _ := strconv.Atoi(verMatch[1])
		minor, _ := strconv.Atoi(verMatch[2])
		if major < 9 || (major == 9 && minor < 8) {
			isOld = true
		}
		if major > 9 || (major == 9 && minor >= 8) {
			isPqcReady = true
		}
	}

	if isOld {
		res.IsVulnerable = true
		res.RiskLevel = "critical"
		res.Status = "Critical Vulnerability (CVE-2024-6387 regreSSHion)"
		res.QuantumThreat = "Shor's Factorization & Harvest-Now-Decrypt-Later"
		res.Description = fmt.Sprintf("%s. Signal handler race condition allows unauthenticated remote code execution as root on glibc systems (CVE-2024-6387). Lacks default ML-KEM-768 post-quantum key exchange.", versionStr)
		res.Recommendation = getUpgradeCommand("openssh", "brew install openssh && brew link openssh", "sudo apt-get --only-upgrade install openssh-client openssh-server", "winget upgrade Microsoft.OpenSSH.Beta")
		res.CodeSnippet = res.Recommendation
		res.RemediationSteps = []string{
			"Upgrade OpenSSH to version 9.8p1 or newer.",
			"Add 'KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com' to ~/.ssh/config.",
			"Deprecate RSA and DSA host keys in /etc/ssh/sshd_config.",
		}
		res.Explainer = "OpenSSH versions prior to 9.8 suffer from regreSSHion (CVE-2024-6387) and do not enable post-quantum ML-KEM key exchange by default."
		res.ComplianceViolations = []string{"CNSA 2.0", "NIST SP 800-208", "CISA KEV"}
	} else if isPqcReady {
		res.IsVulnerable = false
		res.RiskLevel = "secure"
		res.Status = "Post-Quantum Default (ML-KEM / sntrup761)"
		res.QuantumThreat = "Resilient against Harvest-Now-Decrypt-Later"
		res.Description = fmt.Sprintf("%s. Modern OpenSSH with post-quantum hybrid key exchange enabled by default.", versionStr)
		res.Recommendation = "Maintain OpenSSH 9.8+ configuration. Verify ~/.ssh/config uses mlkem768x25519-sha256."
		res.Explainer = "OpenSSH 9.8+ employs hybrid post-quantum key encapsulation (ML-KEM-768 + X25519) to defeat retrospective quantum decryption."
		res.ComplianceViolations = []string{}
	} else {
		res.IsVulnerable = true
		res.RiskLevel = "medium"
		res.Status = "Classical SSH Configuration"
		res.QuantumThreat = "Harvest Now Decrypt Later (HNDL)"
		res.Description = fmt.Sprintf("%s. Supports classical Diffie-Hellman and ECDH key exchanges.", versionStr)
		res.Recommendation = "Upgrade to OpenSSH 9.8+ and configure hybrid PQC KEX."
		res.Explainer = "SSH traffic negotiated over classical ECDH can be harvested and decrypted retrospectively."
		res.ComplianceViolations = []string{"CNSA 2.0"}
	}

	return res, true
}

func auditCurlPackage() (AuditResult, bool) {
	binPath := findExecutable("curl", []string{
		"/usr/bin/curl",
		"/usr/local/bin/curl",
		"/opt/homebrew/bin/curl",
		"C:\\Windows\\System32\\curl.exe",
		"C:\\Program Files\\cURL\\bin\\curl.exe",
	})
	if binPath == "" {
		return AuditResult{}, false
	}

	out, err := exec.Command(binPath, "--version").CombinedOutput()
	lines := strings.Split(string(out), "\n")
	firstLine := ""
	if len(lines) > 0 {
		firstLine = strings.TrimSpace(lines[0])
	}
	if err != nil || firstLine == "" {
		firstLine = "curl 8.x (Installed)"
	}

	res := AuditResult{
		ID:        "pkg-curl",
		Type:      "package",
		Name:      "curl",
		Path:      binPath,
		Algorithm: "TLS 1.3 / HTTPS Network Transport",
	}

	verMatch := regexp.MustCompile(`curl ([0-9]+)\.([0-9]+)\.?([0-9]*)`).FindStringSubmatch(firstLine)
	isVuln := false
	if len(verMatch) >= 3 {
		major, _ := strconv.Atoi(verMatch[1])
		minor, _ := strconv.Atoi(verMatch[2])
		if major < 8 || (major == 8 && minor < 4) {
			isVuln = true
		}
	}

	if isVuln {
		res.IsVulnerable = true
		res.RiskLevel = "critical"
		res.Status = "Critical Vulnerability (CVE-2023-38545)"
		res.QuantumThreat = "Classical Transport Stack"
		res.Description = fmt.Sprintf("%s. SOCKS5 heap buffer overflow vulnerability (CVE-2023-38545) allows remote code execution during hostname resolution.", firstLine)
		res.Recommendation = getUpgradeCommand("curl", "brew upgrade curl", "sudo apt-get --only-upgrade install curl libcurl4", "winget upgrade cURL.cURL")
		res.CodeSnippet = res.Recommendation
		res.RemediationSteps = []string{
			"Upgrade curl to version 8.4.0 or newer.",
			"Verify that TLS 1.3 is enabled in client requests.",
		}
		res.Explainer = "curl < 8.4.0 contains a CVSS 9.8 remote buffer overflow flaw when resolving hostnames over SOCKS5 proxies."
		res.ComplianceViolations = []string{"CISA KEV"}
	} else {
		res.IsVulnerable = false
		res.RiskLevel = "secure"
		res.Status = "Patched Transport (curl 8.4+)"
		res.QuantumThreat = "TLS 1.3 Agility Supported"
		res.Description = fmt.Sprintf("%s. Secure network transport library.", firstLine)
		res.Recommendation = "Maintain curl updates. Ensure HTTPS endpoints negotiate TLS 1.3."
		res.Explainer = "Up-to-date cURL client supporting modern TLS 1.3 ciphersuites."
		res.ComplianceViolations = []string{}
	}

	return res, true
}

func auditGitPackage() (AuditResult, bool) {
	binPath := findExecutable("git", []string{
		"/usr/bin/git",
		"/usr/local/bin/git",
		"/opt/homebrew/bin/git",
		"C:\\Program Files\\Git\\cmd\\git.exe",
	})
	if binPath == "" {
		return AuditResult{}, false
	}

	out, _ := exec.Command(binPath, "--version").CombinedOutput()
	versionStr := strings.TrimSpace(string(out))
	if versionStr == "" {
		versionStr = "git (Installed)"
	}

	res := AuditResult{
		ID:        "pkg-git",
		Type:      "package",
		Name:      "git",
		Path:      binPath,
		Algorithm: "SHA-1 / SHA-256 / SSH Commit Signing",
	}

	res.IsVulnerable = false
	res.RiskLevel = "secure"
	res.Status = "Cryptographic Agility Ready"
	res.QuantumThreat = "SHA-1 to SHA-256 Transition"
	res.Description = fmt.Sprintf("%s. Source control engine supporting SSH signing and SHA-256 object formats.", versionStr)
	res.Recommendation = "Configure Git to sign commits using SSH keys backed by ML-DSA or ed25519."
	res.Explainer = "Git 2.28+ supports SSH commit signing, allowing direct integration with post-quantum signing agents."
	res.ComplianceViolations = []string{}

	return res, true
}

func auditPythonCrypto() (AuditResult, bool) {
	pyBin := findExecutable("python3", []string{
		"/usr/bin/python3",
		"/usr/local/bin/python3",
		"/opt/homebrew/bin/python3",
		"C:\\Python312\\python.exe",
		"C:\\Program Files\\Python312\\python.exe",
	})
	if pyBin == "" {
		pyBin = findExecutable("python", nil)
	}
	if pyBin == "" {
		return AuditResult{}, false
	}

	out, err := exec.Command(pyBin, "-c", "import cryptography; print(cryptography.__version__)").CombinedOutput()
	if err != nil || len(out) == 0 {
		return AuditResult{}, false
	}
	ver := strings.TrimSpace(string(out))

	res := AuditResult{
		ID:        "pkg-python-cryptography",
		Type:      "package",
		Name:      "cryptography (Python)",
		Path:      pyBin,
		Algorithm: "PyCA / OpenSSL Backend / Classical & Hybrid",
	}

	verParts := strings.Split(ver, ".")
	isVuln := false
	if len(verParts) >= 2 {
		major, _ := strconv.Atoi(verParts[0])
		minor, _ := strconv.Atoi(verParts[1])
		if major < 42 || (major == 42 && minor == 0) {
			isVuln = true
		}
	}

	if isVuln {
		res.IsVulnerable = true
		res.RiskLevel = "high"
		res.Status = "Vulnerable (CVE-2024-26130)"
		res.QuantumThreat = "Shor's Factorization (RSA/ECC PyCA)"
		res.Description = fmt.Sprintf("Python cryptography %s. NULL pointer dereference in PKCS12 serialization (CVE-2024-26130).", ver)
		res.Recommendation = "pip install --upgrade 'cryptography>=42.0.4'"
		res.CodeSnippet = "pip install --upgrade 'cryptography>=42.0.4'"
		res.RemediationSteps = []string{
			"Run: pip install --upgrade 'cryptography>=42.0.4'",
			"Verify installed version: python3 -c 'import cryptography; print(cryptography.__version__)'",
		}
		res.Explainer = "Python cryptography library wraps OpenSSL; versions prior to 42.0.4 suffer from memory safety vulnerabilities in PKCS12 parsing."
		res.ComplianceViolations = []string{"NIST SP 800-52r2"}
	} else {
		res.IsVulnerable = false
		res.RiskLevel = "secure"
		res.Status = "PQC Ready (PyCA 42+)"
		res.QuantumThreat = "Hybrid Agility Ready"
		res.Description = fmt.Sprintf("Python cryptography %s. Modern cryptographic primitives with OpenSSL 3.x binding.", ver)
		res.Recommendation = "Maintain Python cryptography package updates."
		res.Explainer = "Up-to-date Python cryptography runtime."
		res.ComplianceViolations = []string{}
	}

	return res, true
}

// -----------------------------------------------------------------------------
// Package Manager & Manifest Auditing
// -----------------------------------------------------------------------------

func auditSystemPackageManagerPackages(ctx context.Context, reportProgress func(string)) []AuditResult {
	var results []AuditResult

	if runtime.GOOS == "darwin" {
		// Audit Homebrew installed packages
		brewBin, err := exec.LookPath("brew")
		if err == nil && brewBin != "" {
			reportProgress("Auditing Homebrew packages (brew list --versions)...")
			out, err := exec.Command(brewBin, "list", "--versions").CombinedOutput()
			if err == nil {
				scanner := bufio.NewScanner(strings.NewReader(string(out)))
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						pkgName := parts[0]
						pkgVer := parts[1]
						if isRelevantCryptoPkg(pkgName) {
							results = append(results, createPkgAuditResult(pkgName, pkgVer, "Homebrew (macOS)", "/opt/homebrew/Cellar/"+pkgName))
						}
					}
				}
			}
		}
	} else if runtime.GOOS == "linux" {
		// Audit dpkg or rpm packages
		dpkgBin, err := exec.LookPath("dpkg-query")
		if err == nil && dpkgBin != "" {
			reportProgress("Auditing Debian/Ubuntu packages (dpkg-query)...")
			out, err := exec.Command(dpkgBin, "-W", "-f=${Package} ${Version}\n").CombinedOutput()
			if err == nil {
				scanner := bufio.NewScanner(strings.NewReader(string(out)))
				for scanner.Scan() {
					parts := strings.Fields(scanner.Text())
					if len(parts) >= 2 {
						pkgName := parts[0]
						pkgVer := parts[1]
						if isRelevantCryptoPkg(pkgName) {
							results = append(results, createPkgAuditResult(pkgName, pkgVer, "dpkg (Linux)", "/var/lib/dpkg/info/"+pkgName))
						}
					}
				}
			}
		}
	} else if runtime.GOOS == "windows" {
		// Audit Windows installed applications via winget or Program Files
		reportProgress("Auditing Windows application runtimes...")
		programPaths := []string{
			"C:\\Program Files\\PuTTY\\putty.exe",
			"C:\\Program Files\\WireGuard\\wireguard.exe",
			"C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe",
		}
		for _, p := range programPaths {
			if _, err := os.Stat(p); err == nil {
				base := filepath.Base(p)
				name := strings.TrimSuffix(base, ".exe")
				results = append(results, createPkgAuditResult(name, "Installed", "Windows Application", p))
			}
		}
	}

	return results
}

func auditProjectManifests(ctx context.Context, reportProgress func(string)) []AuditResult {
	var results []AuditResult
	homeDir, _ := os.UserHomeDir()
	curDir, _ := os.Getwd()

	searchRoots := []string{curDir}
	if homeDir != "" && homeDir != curDir {
		// Include common project folders
		for _, sub := range []string{"Projects", "Developer", "Code", "workspace", "src"} {
			p := filepath.Join(homeDir, sub)
			if fi, err := os.Stat(p); err == nil && fi.IsDir() {
				searchRoots = append(searchRoots, p)
			}
		}
	}

	manifestFiles := []string{"package.json", "go.mod", "requirements.txt"}
	visitedManifests := make(map[string]bool)

	for _, root := range searchRoots {
		if ctx != nil && ctx.Err() != nil {
			break
		}
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if ctx != nil && ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := strings.ToLower(d.Name())
				if name == "node_modules" || name == ".git" || name == "dist" || name == "vendor" || name == "build" {
					return filepath.SkipDir
				}
				// Cap recursion depth to 4 levels for speed
				rel, _ := filepath.Rel(root, path)
				if strings.Count(rel, string(os.PathSeparator)) > 4 {
					return filepath.SkipDir
				}
				return nil
			}

			fileName := d.Name()
			for _, m := range manifestFiles {
				if fileName == m && !visitedManifests[path] {
					visitedManifests[path] = true
					reportProgress(fmt.Sprintf("Inspecting manifest: %s...", path))
					findings := parseManifestForCryptoDependencies(path, fileName)
					results = append(results, findings...)
					break
				}
			}

			// Limit total parsed manifests to 20 for rapid endpoint responsiveness
			if len(visitedManifests) >= 20 {
				return filepath.SkipDir
			}
			return nil
		})
	}

	return results
}

func parseManifestForCryptoDependencies(filePath, fileName string) []AuditResult {
	var findings []AuditResult
	data, err := os.ReadFile(filePath)
	if err != nil || len(data) == 0 {
		return findings
	}

	content := string(data)

	if fileName == "package.json" {
		var pkgJson struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if err := json.Unmarshal(data, &pkgJson); err == nil {
			allDeps := make(map[string]string)
			for k, v := range pkgJson.Dependencies {
				allDeps[k] = v
			}
			for k, v := range pkgJson.DevDependencies {
				allDeps[k] = v
			}

			for depName, depVer := range allDeps {
				cleanVer := strings.TrimLeft(depVer, "^~>=<")
				if depName == "jsonwebtoken" {
					isVuln := strings.HasPrefix(cleanVer, "8.") || strings.HasPrefix(cleanVer, "7.") || strings.HasPrefix(cleanVer, "6.")
					findings = append(findings, AuditResult{
						ID:             fmt.Sprintf("pkg-npm-jsonwebtoken-%s", filepath.Base(filepath.Dir(filePath))),
						Type:           "package",
						Name:           "jsonwebtoken",
						Path:           filePath,
						Algorithm:      "RSA-2048 / HMAC-SHA256 / ECDSA (JWT)",
						IsVulnerable:   isVuln,
						RiskLevel:      ternary(isVuln, "critical", "secure"),
						Status:         ternary(isVuln, "Critical CVE-2022-23529", "PQC Ready"),
						QuantumThreat:  "Shor's Factorization (RSA JWTs)",
						Description:    fmt.Sprintf("npm/jsonwebtoken@%s in %s. Insecure key retrieval allows remote code execution when verifying untrusted tokens with malicious key objects.", depVer, filePath),
						Recommendation: "npm install jsonwebtoken@^9.0.2",
						CodeSnippet:    "npm install jsonwebtoken@^9.0.2",
						RemediationSteps: []string{
							"Run: npm install jsonwebtoken@^9.0.2",
							"Adopt hybrid ML-DSA signatures for JWT token verification.",
						},
						Explainer:            "JSON Web Tokens signed using RSA or ECDSA are breakable in polynomial time by quantum Shor's algorithm.",
						ComplianceViolations: []string{"CNSA 2.0", "CISA KEV"},
					})
				} else if depName == "axios" {
					isVuln := strings.HasPrefix(cleanVer, "0.") || (strings.HasPrefix(cleanVer, "1.") && cleanVer < "1.7.4")
					findings = append(findings, AuditResult{
						ID:             fmt.Sprintf("pkg-npm-axios-%s", filepath.Base(filepath.Dir(filePath))),
						Type:           "package",
						Name:           "axios",
						Path:           filePath,
						Algorithm:      "HTTPS Client / TLS 1.3 Transport",
						IsVulnerable:   isVuln,
						RiskLevel:      ternary(isVuln, "high", "secure"),
						Status:         ternary(isVuln, "High CVE-2023-45857 (CSRF)", "Patched"),
						QuantumThreat:  "TLS Session Exposure",
						Description:    fmt.Sprintf("npm/axios@%s in %s. Confidential headers forwarded during cross-domain redirects (CVE-2023-45857).", depVer, filePath),
						Recommendation: "npm install axios@^1.7.4",
						CodeSnippet:    "npm install axios@^1.7.4",
						RemediationSteps: []string{
							"Run: npm install axios@^1.7.4",
						},
						Explainer:            "Network client used for API integrations.",
						ComplianceViolations: []string{"NIST SP 800-52r2"},
					})
				}
			}
		}
	} else if fileName == "go.mod" {
		if strings.Contains(content, "golang.org/x/crypto") {
			findings = append(findings, AuditResult{
				ID:                   fmt.Sprintf("pkg-go-crypto-%s", filepath.Base(filepath.Dir(filePath))),
				Type:                 "package",
				Name:                 "golang.org/x/crypto",
				Path:                 filePath,
				Algorithm:            "Go Cryptography / SSH / OpenPGP",
				IsVulnerable:         false,
				RiskLevel:            "secure",
				Status:               "Active Go Crypto Module",
				QuantumThreat:        "PQC Posture Monitoring",
				Description:          fmt.Sprintf("Go cryptography module referenced in %s.", filePath),
				Recommendation:       "go get -u golang.org/x/crypto@latest",
				CodeSnippet:          "go get -u golang.org/x/crypto@latest",
				Explainer:            "Standard Go cryptographic module repository.",
				ComplianceViolations: []string{},
			})
		}
	} else if fileName == "requirements.txt" {
		if strings.Contains(content, "cryptography") {
			findings = append(findings, AuditResult{
				ID:                   fmt.Sprintf("pkg-py-crypto-%s", filepath.Base(filepath.Dir(filePath))),
				Type:                 "package",
				Name:                 "cryptography (Python Dependency)",
				Path:                 filePath,
				Algorithm:            "PyCA / OpenSSL Primitives",
				IsVulnerable:         false,
				RiskLevel:            "secure",
				Status:               "Python Dependency",
				QuantumThreat:        "Classical & Hybrid Primitives",
				Description:          fmt.Sprintf("Python cryptography package required by %s.", filePath),
				Recommendation:       "pip install --upgrade 'cryptography>=42.0.4'",
				CodeSnippet:          "pip install --upgrade 'cryptography>=42.0.4'",
				Explainer:            "Python PyCA cryptography library.",
				ComplianceViolations: []string{},
			})
		}
	}

	return findings
}

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

func findExecutable(name string, knownPaths []string) string {
	if p, err := exec.LookPath(name); err == nil && p != "" {
		return p
	}
	for _, p := range knownPaths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

func isRelevantCryptoPkg(name string) bool {
	lower := strings.ToLower(name)
	targets := []string{
		"openssl", "libssl", "openssh", "curl", "libcurl", "gnupg", "gpg",
		"wireguard", "openvpn", "strongswan", "ca-certificates", "certbot",
		"libssh", "libssh2", "bouncycastle", "sodium", "libsodium",
	}
	for _, t := range targets {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

func createPkgAuditResult(name, version, ecosystem, path string) AuditResult {
	res := AuditResult{
		ID:        fmt.Sprintf("pkg-%s-%s", ecosystem, name),
		Type:      "package",
		Name:      name,
		Path:      path,
		Algorithm: "OS Package / Security Runtime",
	}

	lower := strings.ToLower(name)
	if strings.Contains(lower, "openssl") && strings.Contains(version, "1.1.1") {
		res.IsVulnerable = true
		res.RiskLevel = "critical"
		res.Status = "Critical Vulnerability (OpenSSL 1.x EOL)"
		res.QuantumThreat = "Shor's Factorization (RSA/ECC Only)"
		res.Description = fmt.Sprintf("%s (%s) version %s is End-of-Life.", name, ecosystem, version)
		res.Recommendation = "Upgrade to OpenSSL 3.x series."
		res.ComplianceViolations = []string{"NIST SP 800-131A", "CNSA 2.0"}
	} else {
		res.IsVulnerable = false
		res.RiskLevel = "secure"
		res.Status = "Installed Runtime"
		res.QuantumThreat = "PQC Posture Audited"
		res.Description = fmt.Sprintf("%s (%s) version %s installed.", name, ecosystem, version)
		res.Recommendation = "Maintain regular security updates."
		res.ComplianceViolations = []string{}
	}

	return res
}

func getUpgradeCommand(pkg, brewCmd, aptCmd, wingetCmd string) string {
	switch runtime.GOOS {
	case "darwin":
		return brewCmd
	case "linux":
		return aptCmd
	case "windows":
		return wingetCmd
	default:
		return brewCmd
	}
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
