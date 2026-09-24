package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

func isCandidateCryptoFile(path string, fileName string) bool {
	lower := strings.ToLower(fileName)
	ext := strings.ToLower(filepath.Ext(fileName))

	// Explicitly ignore common non-crypto binaries, source code & media immediately
	switch ext {
	case ".exe", ".dll", ".sys", ".iso", ".zip", ".tar", ".gz", ".7z", ".rar",
		".mp4", ".mkv", ".avi", ".mov", ".mp3", ".wav", ".jpg", ".jpeg", ".png",
		".gif", ".ico", ".webp", ".pdf", ".docx", ".xlsx", ".pptx", ".msi",
		".dmg", ".pkg", ".class", ".jar", ".bin", ".dat", ".vmdk", ".tmp", ".log",
		".pst", ".ost", ".db", ".sqlite", ".db3", ".mdb", ".txt", ".md", ".html",
		".css", ".js", ".ts", ".tsx", ".jsx", ".map", ".pyc", ".py", ".go", ".c",
		".cpp", ".h", ".cs", ".java", ".rs", ".php", ".rb", ".swift", ".kt", ".dart":
		return false
	}

	// High-confidence cryptographic certificate / key extensions
	switch ext {
	case ".pem", ".crt", ".cer", ".key", ".pub", ".pfx", ".p12", ".der", ".ovpn":
		return true
	}

	// JSON credential / key files only (Skip generic package.json, tsconfig.json, etc.)
	if ext == ".json" {
		if strings.Contains(lower, "key") || strings.Contains(lower, "secret") ||
			strings.Contains(lower, "cred") || strings.Contains(lower, "token") ||
			strings.Contains(lower, "cert") || strings.Contains(lower, "auth") ||
			strings.Contains(lower, "service_account") || strings.Contains(lower, "service-account") ||
			strings.Contains(lower, "firebase") || strings.Contains(lower, "gcloud") ||
			strings.HasPrefix(lower, "sa-") || strings.HasPrefix(lower, "id_") {
			return true
		}
		return false
	}

	// Config files - inspect standard server/service/network configs
	if ext == ".conf" || ext == ".config" || ext == ".cfg" || ext == ".cnf" || ext == ".env" || ext == ".yaml" || ext == ".yml" || ext == ".ovpn" {
		return true
	}

	// Known cryptographic file basenames without extensions (e.g. SSH keys)
	if strings.HasPrefix(lower, "id_") ||
		strings.Contains(lower, "known_hosts") ||
		strings.Contains(lower, "authorized_keys") ||
		strings.Contains(lower, "sshd_config") ||
		strings.Contains(lower, "nginx.conf") {
		return true
	}

	// Inside dedicated credential directories (~/.ssh, ~/.gnupg, /etc/ssh, OpenVPN), inspect files < 256KB
	dir := strings.ToLower(filepath.Dir(path))
	if strings.Contains(dir, ".ssh") || strings.Contains(dir, ".gnupg") || strings.Contains(dir, "etc/ssh") || strings.Contains(dir, "openvpn") {
		return true
	}

	return false
}

// RunScan is a backwards-compatible wrapper for RunScanWithProgress
func RunScan(quick bool, customPath string) ([]AuditResult, int, error) {
	return RunScanWithProgress(context.Background(), quick, customPath, nil)
}

// RunScanWithProgress audits the workstation with real-time path updates and cancellation support
func RunScanWithProgress(ctx context.Context, quick bool, customPath string, onProgress func(currentPath string, scannedCount int, foundCount int)) ([]AuditResult, int, error) {
	osName := runtime.GOOS
	var targetPaths []string

	if quick {
		homeDir, _ := os.UserHomeDir()
		if homeDir != "" {
			targetPaths = append(targetPaths, filepath.Join(homeDir, ".ssh"))
			targetPaths = append(targetPaths, filepath.Join(homeDir, ".kube"))
			targetPaths = append(targetPaths, filepath.Join(homeDir, ".gnupg"))
			targetPaths = append(targetPaths, filepath.Join(homeDir, ".aws"))
			targetPaths = append(targetPaths, filepath.Join(homeDir, ".azure"))
			targetPaths = append(targetPaths, filepath.Join(homeDir, "Downloads"))
			targetPaths = append(targetPaths, filepath.Join(homeDir, "Documents"))
			targetPaths = append(targetPaths, filepath.Join(homeDir, "Desktop"))
			targetPaths = append(targetPaths, filepath.Join(homeDir, "certs"))
			targetPaths = append(targetPaths, filepath.Join(homeDir, "certificates"))
			targetPaths = append(targetPaths, filepath.Join(homeDir, "ssl"))
			targetPaths = append(targetPaths, filepath.Join(homeDir, "keys"))
		}
		if osName == "darwin" || osName == "linux" {
			targetPaths = append(targetPaths, "/etc/ssl/certs")
			targetPaths = append(targetPaths, "/etc/ssh")
			targetPaths = append(targetPaths, "/etc/wireguard")
		}
		if osName == "windows" {
			if homeDir != "" {
				oneDrive := filepath.Join(homeDir, "OneDrive")
				if _, err := os.Stat(oneDrive); err == nil {
					targetPaths = append(targetPaths, filepath.Join(oneDrive, "Documents"))
					targetPaths = append(targetPaths, filepath.Join(oneDrive, "Desktop"))
					targetPaths = append(targetPaths, filepath.Join(oneDrive, "Downloads"))
				}
			}
			appData := os.Getenv("APPDATA")
			if appData != "" {
				targetPaths = append(targetPaths, filepath.Join(appData, "OpenVPN"))
				targetPaths = append(targetPaths, filepath.Join(appData, "WireGuard"))
			}
			localAppData := os.Getenv("LOCALAPPDATA")
			if localAppData != "" {
				targetPaths = append(targetPaths, filepath.Join(localAppData, "Programs", "Git", "usr", "ssl", "certs"))
			}
			programData := os.Getenv("ProgramData")
			if programData != "" {
				targetPaths = append(targetPaths, filepath.Join(programData, "ssh"))
			}
			systemRoot := os.Getenv("SystemRoot")
			if systemRoot == "" {
				systemRoot = "C:\\Windows"
			}
			targetPaths = append(targetPaths, filepath.Join(systemRoot, "System32", "OpenSSH"))
		}
	} else {
		if customPath == "" {
			customPath = "."
		}
		absPath, err := filepath.Abs(customPath)
		if err != nil {
			return []AuditResult{}, 0, err
		}
		targetPaths = append(targetPaths, absPath)
	}

	assets := []AuditResult{}
	configViolations := []AuditResult{}
	scannedFilesCount := 0
	lastReportTime := time.Now()

	for _, targetPath := range targetPaths {
		if _, err := os.Stat(targetPath); os.IsNotExist(err) {
			continue // Skip non-existent directories in quick mode
		}

		_ = filepath.WalkDir(targetPath, func(path string, d fs.DirEntry, err error) error {
			if ctx != nil && ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				return nil
			}

			// Throttle live UI progress updates (every 80ms)
			if onProgress != nil && time.Since(lastReportTime) > 80*time.Millisecond {
				onProgress(path, scannedFilesCount, len(assets)+len(configViolations))
				lastReportTime = time.Now()
			}

			if d.IsDir() {
				// Avoid recursive junction loops and reparse points on Windows
				if d.Type()&os.ModeSymlink != 0 || d.Type()&os.ModeIrregular != 0 {
					return filepath.SkipDir
				}
				name := d.Name()
				lowerName := strings.ToLower(name)

				// Windows junction loops to skip
				if lowerName == "application data" || lowerName == "history" || lowerName == "temporary internet files" {
					return filepath.SkipDir
				}

				// Enforce absolute max depth guard (25 levels) to prevent any cyclic junction traps
				if strings.Count(path, string(os.PathSeparator)) > 25 {
					return filepath.SkipDir
				}

				// In quick mode, limit search depth to 4 directory levels below target
				if quick {
					rel, errRel := filepath.Rel(targetPath, path)
					if errRel == nil {
						depth := strings.Count(rel, string(os.PathSeparator))
						if depth > 4 {
							return filepath.SkipDir
						}
					}
				}

				// Skip build caches, node_modules, and pure OS update/manifest caches
				// (Note: $Recycle.Bin and C:\Windows legitimate directories are audited for residual crypto)
				if (strings.HasPrefix(name, ".") && name != ".ssh" && name != ".kube" && name != ".gnupg" && name != ".aws" && name != ".azure") ||
					lowerName == "node_modules" || lowerName == "dist" || lowerName == "vendor" || lowerName == "build" ||
					lowerName == "temp" || lowerName == "tmp" ||
					lowerName == "system volume information" || lowerName == "cache" ||
					lowerName == "winsxs" || lowerName == "driverstore" || lowerName == "softwaredistribution" ||
					lowerName == "windowsapps" || lowerName == "assembly" || lowerName == "servicing" ||
					lowerName == "package cache" || lowerName == "installer" || lowerName == "catroot" ||
					lowerName == "catroot2" || lowerName == "prefetch" || lowerName == "microsoft.net" ||
					lowerName == "systemapps" || lowerName == "recovery" || lowerName == "msocache" ||
					lowerName == "syswow64" || lowerName == "wbem" || lowerName == "spool" ||
					lowerName == "logfiles" || lowerName == "dism" || lowerName == "winevt" {
					return filepath.SkipDir
				}

				return nil
			}

			// Only inspect candidate cryptographic files
			fileName := d.Name()
			if !isCandidateCryptoFile(path, fileName) {
				return nil
			}

			info, err := d.Info()
			if err != nil || info.Size() == 0 || info.Size() > 2*1024*1024 { // Skip 0B or >2MB
				return nil
			}

			scannedFilesCount++
			contentBytes, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			content := string(contentBytes)
			trimmed := strings.TrimSpace(content)

			if strings.Contains(content, "-----BEGIN ") {
				// PEM certificate or private key
				audit := AuditPEMCertificate(content, fileName, path)
				assets = append(assets, audit)
			} else if cert, err := x509.ParseCertificate(contentBytes); err == nil {
				// Binary DER certificate (.cer, .crt, .der)
				audit := AuditDERCertificate(cert, fileName, path)
				assets = append(assets, audit)
			} else if strings.HasPrefix(trimmed, "ssh-") || strings.HasPrefix(trimmed, "ecdsa-") {
				// SSH Public Key
				audit := AuditSSHKey(content, fileName, path)
				assets = append(assets, audit)
			} else if strings.HasSuffix(fileName, ".conf") || strings.HasSuffix(fileName, ".config") ||
				strings.Contains(fileName, "sshd_config") || strings.Contains(fileName, "nginx.conf") ||
				strings.HasSuffix(fileName, ".ovpn") || strings.HasSuffix(fileName, ".cfg") ||
				strings.HasSuffix(fileName, ".cnf") || strings.HasSuffix(fileName, ".env") ||
				strings.HasSuffix(fileName, ".yaml") || strings.HasSuffix(fileName, ".yml") {
				// Server / VPN Config Auditor
				audit := AuditConfigFile(fileName, content)
				if audit.IsVulnerable {
					for i, v := range audit.Violations {
						threat := "Symmetric/Protocol Config"
						algo := "Symmetric/Protocol Config"
						if strings.Contains(v.Issue, "Grover") || strings.Contains(v.Issue, "AES-128") || strings.Contains(v.Issue, "3DES") {
							threat = "Grover's Algorithm (Key Halving)"
							algo = "AES-128 / Symmetric Cipher"
						} else if strings.Contains(v.Issue, "Diffie-Hellman") || strings.Contains(v.Issue, "Shor") {
							threat = "Shor's Algorithm (Discrete Log)"
							algo = "Diffie-Hellman (Classical KEX)"
						} else if strings.Contains(v.Issue, "HNDL") || strings.Contains(v.Issue, "Harvest Now") || strings.Contains(v.Issue, "TLS") {
							threat = "Harvest Now, Decrypt Later (HNDL)"
							algo = "Classical TLS / KEX Protocol"
						}
						configViolations = append(configViolations, AuditResult{
							ID:                   fmt.Sprintf("cli-cfg-%s-%d", generateID(), i),
							Type:                 "config",
							Name:                 fmt.Sprintf("%s:Line %d", fileName, v.LineNumber),
							Path:                 path,
							Algorithm:            algo,
							QuantumThreat:        threat,
							IsVulnerable:         true,
							RiskLevel:            v.RiskLevel,
							Status:               "Quantum Vulnerable",
							Description:          fmt.Sprintf("%s (%s)", v.Issue, path),
							Recommendation:       v.Fix,
							Explainer:            fmt.Sprintf("Configuration at line %d permits: \"%s\"", v.LineNumber, v.LineContent),
							ComplianceViolations: []string{"CNSA 2.0", "NIST SP 800-208", "EO 14028"},
						})
					}
				}
			}

			return nil
		})

		if ctx != nil && ctx.Err() != nil {
			return assets, scannedFilesCount, ctx.Err()
		}
	}

	// Audit Native Operating System Certificate Stores & TLS Configurations (Windows, macOS, Linux)
	storeDesc := "Operating System Native Security Store"
	if osName == "windows" {
		storeDesc = "Windows Certificate Store (Cert:\\LocalMachine, Cert:\\CurrentUser) & Schannel"
	} else if osName == "darwin" {
		storeDesc = "macOS Security Keychains (/Library/Keychains, login.keychain) & System TLS"
	} else if osName == "linux" {
		storeDesc = "Linux System Trust Stores (/etc/ssl/certs, /etc/pki) & Crypto Policies"
	}

	if onProgress != nil {
		onProgress(storeDesc, scannedFilesCount, len(assets)+len(configViolations))
	}
	sysAssets, sysViolations := AuditPlatformSystemStores()
	if len(sysAssets) > 0 {
		assets = append(assets, sysAssets...)
		scannedFilesCount += len(sysAssets)
	}
	if len(sysViolations) > 0 {
		configViolations = append(configViolations, sysViolations...)
	}

	allFindings := append(assets, configViolations...)
	if allFindings == nil {
		allFindings = []AuditResult{}
	}
	return allFindings, scannedFilesCount, nil
}

func main() {
	// 1. Define Command-Line Flags
	pathFlag := flag.String("path", ".", "Target local directory path to scan")
	serverFlag := flag.String("server", "https://quarkshield.ai", "QuarkShield central server URL")
	tokenFlag := flag.String("token", "", "QuarkShield.AI Fleet Enrollment Token or License Key")
	licenseFlag := flag.String("license", "", "QuarkShield Enterprise/Partner License Key")
	registerFlag := flag.Bool("register", false, "Register findings in the central fleet database")
	outputFlag := flag.String("output", "", "Output file path to save report")
	quickFlag := flag.Bool("quick", false, "Quick scan common credential directories (~/.ssh, /etc/ssl, etc.)")
	cbomFlag := flag.Bool("cbom", false, "Format output as standardized CycloneDX 1.6 CBOM JSON")
	guiFlag := flag.Bool("gui", false, "Launch interactive Post-Quantum Guard Web GUI")
	uninstallFlag := flag.Bool("uninstall", false, "Uninstall Post-Quantum Guard from this workstation")
	probeFlag := flag.String("probe", "", "Active outbound TCP/TLS socket probe against target (e.g. microsoft.com:443)")

	flag.StringVar(pathFlag, "p", ".", "Target directory path (shorthand)")
	flag.StringVar(serverFlag, "s", "https://quarkshield.ai", "Server URL (shorthand)")
	flag.StringVar(tokenFlag, "t", "", "Fleet enrollment token or license key (shorthand)")
	flag.StringVar(licenseFlag, "l", "", "License key (shorthand)")
	flag.StringVar(licenseFlag, "key", "", "License key alias")
	flag.StringVar(licenseFlag, "k", "", "License key shorthand")
	flag.BoolVar(registerFlag, "r", false, "Register findings (shorthand)")
	flag.StringVar(outputFlag, "o", "", "Output file (shorthand)")
	flag.BoolVar(quickFlag, "q", false, "Quick scan mode (shorthand)")
	flag.BoolVar(cbomFlag, "c", false, "CycloneDX CBOM format (shorthand)")
	flag.BoolVar(guiFlag, "g", false, "Launch Post-Quantum Guard Web GUI (shorthand)")
	flag.BoolVar(uninstallFlag, "u", false, "Uninstall shorthand")

	// Filter out macOS Finder Process Serial Number arguments (e.g. -psn_0_1234567)
	if runtime.GOOS == "darwin" {
		var filtered []string
		for _, a := range os.Args {
			if !strings.HasPrefix(a, "-psn_") {
				filtered = append(filtered, a)
			}
		}
		os.Args = filtered
	}

	flag.Parse()

	tokenVal := strings.TrimSpace(*tokenFlag)
	licVal := strings.TrimSpace(*licenseFlag)
	if licVal != "" {
		if tokenVal == "" {
			tokenVal = licVal
		}
		if _, err := ActivateLicense(licVal); err == nil {
			fmt.Println("✓ Local license successfully activated.")
		}
	} else if strings.HasPrefix(strings.ToUpper(tokenVal), "QS-") {
		if _, err := ActivateLicense(tokenVal); err == nil {
			fmt.Println("✓ Local license successfully activated from license key.")
		}
	}

	// Handle Active Network & TLS Probe
	if *probeFlag != "" {
		fmt.Printf("==================================================\n")
		fmt.Printf(" 🌐 QuarkShield Active Network & TLS PQC Prober\n")
		fmt.Printf(" Target: %s\n", *probeFlag)
		fmt.Printf("==================================================\n")

		findings, err := ProbeEndpoint(*probeFlag)
		if err != nil {
			fmt.Printf("❌ Probe error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✦ Captured %d cryptographic findings from %s:\n\n", len(findings), *probeFlag)
		for i, f := range findings {
			statusIcon := "❌"
			if !f.IsVulnerable {
				statusIcon = "✅"
			}
			fmt.Printf(" [%d] %s %s [%s]\n", i+1, statusIcon, f.Name, f.Status)
			fmt.Printf("     Algorithm: %s (Key Size: %d)\n", f.Algorithm, f.KeySize)
			fmt.Printf("     Threat:    %s\n", f.QuantumThreat)
			fmt.Printf("     Detail:    %s\n", f.Description)
			fmt.Printf("     Fix:       %s\n\n", f.Recommendation)
		}

		if *outputFlag != "" {
			var outData []byte
			if *cbomFlag {
				hName, _ := os.Hostname()
				outData, _ = GenerateCycloneDXCBOM(findings, hName, runtime.GOOS)
			} else {
				outData, _ = json.MarshalIndent(findings, "", "  ")
			}
			_ = os.WriteFile(*outputFlag, outData, 0644)
			fmt.Printf("✦ Report saved to: %s\n", *outputFlag)
		}
		return
	}

	// Handle Uninstall
	if *uninstallFlag {
		unregisterWindowsUninstall()
		fmt.Println("==================================================")
		fmt.Println(" 🛡️ QuarkShield Post-Quantum Guard")
		fmt.Println("    Uninstalled successfully from this workstation.")
		fmt.Println("    Background services & registry removed.")
		fmt.Println("==================================================")
		if runtime.GOOS == "windows" {
			exePath, err := os.Executable()
			if err == nil {
				cmdDel := exec.Command("cmd.exe", "/c", "timeout /t 2 >nul & del /f /q \""+exePath+"\"")
				hideConsole(cmdDel)
				_ = cmdDel.Start()
			}
		}
		os.Exit(0)
	}

	// 2. Interactive Post-Quantum Guard GUI Mode
	// If executed with zero arguments (double-clicked in Windows/Mac/Linux Explorer) OR explicitly with --gui:
	if len(os.Args) == 1 || *guiFlag {
		err := StartGUI(48291, *serverFlag, *tokenFlag)
		if err != nil {
			fmt.Printf("❌ Failed to start Post-Quantum Guard GUI: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 3. Headless CLI Mode (for scripts, Intune, Jamf, Ansible, CI/CD)
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}
	localIP := getLocalIP()
	osName := runtime.GOOS
	archName := runtime.GOARCH

	fmt.Printf("==================================================\n")
	fmt.Printf(" 🛡️ QuarkShield.AI Host PQC Scanner (v2.0.0)\n")
	fmt.Printf(" Host: %s (%s/%s) | IP: %s\n", hostname, osName, archName, localIP)
	fmt.Printf("==================================================\n")

	if *quickFlag {
		fmt.Printf("✦ Quick Mode: Auditing standard credential directories...\n")
	} else {
		fmt.Printf("Scanning target: %s\n", *pathFlag)
	}

	allFindings, scannedFilesCount, err := RunScan(*quickFlag, *pathFlag)
	if err != nil {
		fmt.Printf("❌ Scan error: %v\n", err)
		os.Exit(1)
	}

	assetsCount := 0
	configCount := 0
	for _, f := range allFindings {
		if f.Type == "config" {
			configCount++
		} else {
			assetsCount++
		}
	}

	fmt.Printf("--------------------------------------------------\n")
	fmt.Printf(" Scan Complete:\n")
	fmt.Printf(" • Scanned Files: %d\n", scannedFilesCount)
	fmt.Printf(" • Cryptographic Assets: %d\n", assetsCount)
	fmt.Printf(" • Configuration Vulnerabilities: %d\n", configCount)
	fmt.Printf(" • Total Findings: %d\n", len(allFindings))
	fmt.Printf("--------------------------------------------------\n")

	// 4. Serialize Output (CycloneDX 1.6 CBOM vs Standard JSON)
	var outputBytes []byte
	if *cbomFlag {
		cbomData, err := GenerateCycloneDXCBOM(allFindings, hostname, osName)
		if err != nil {
			fmt.Printf("Failed to generate CycloneDX CBOM: %v\n", err)
			outputBytes, _ = json.MarshalIndent(allFindings, "", "  ")
		} else {
			outputBytes = cbomData
		}
	} else {
		outputBytes, _ = json.MarshalIndent(allFindings, "", "  ")
	}

	// 5. Save to Local Scan History & Optional Output File
	cliScanType := "full"
	if *quickFlag {
		cliScanType = "quick"
	} else if *pathFlag != "" {
		cliScanType = "custom"
	}
	_, _ = SaveScanResult(cliScanType, *pathFlag, scannedFilesCount, allFindings)

	if *outputFlag != "" {
		err := os.WriteFile(*outputFlag, outputBytes, 0644)
		if err != nil {
			fmt.Printf("Failed to write report to %s: %v\n", *outputFlag, err)
		} else {
			fmt.Printf("✓ Report saved to %s\n", *outputFlag)
		}
	} else if !*registerFlag && tokenVal == "" {
		fmt.Println(string(outputBytes))
	}

	// 6. Send Telemetry to QuarkShield.AI Central Platform
	if tokenVal != "" || *registerFlag {
		lic := GetLicenseInfo()

		// If a license key was provided or token starts with QS-, try activating if not yet licensed
		if !lic.IsLicensed && strings.HasPrefix(strings.ToUpper(tokenVal), "QS-") {
			_, _ = ActivateLicense(tokenVal)
			lic = GetLicenseInfo()
		}

		// Only block if NEITHER a token/key was supplied NOR does the machine have an active license
		if tokenVal == "" && (!lic.IsLicensed || lic.Tier == "trial" || lic.IsExpired) {
			fmt.Println("❌ Error: Fleet synchronization requires an active License Key or Fleet Enrollment Token.")
			fmt.Println("   Pass --token <TOKEN_OR_KEY> or --license <KEY> to enroll this device.")
			os.Exit(1)
		}

		fmt.Printf("📡 Transmitting telemetry to QuarkShield server at %s...\n", *serverFlag)
		err := SendFleetTelemetry(*serverFlag, tokenVal, hostname, osName, archName, localIP, allFindings, lic.LicenseKey, lic.TenantName)
		if err != nil {
			fmt.Printf("❌ Telemetry failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Success! Machine '%s' enrolled and %d assets synchronized.\n", hostname, len(allFindings))
	}
}
