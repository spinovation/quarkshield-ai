package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

//go:embed web/index.html web/app_icon.png web/quarkshield-logo.png
var embeddedWebFS embed.FS

type ScanRequest struct {
	Quick bool   `json:"quick"`
	Path  string `json:"path"`
}

type SyncRequest struct {
	ServerUrl string        `json:"serverUrl"`
	Token     string        `json:"token"`
	Findings  []AuditResult `json:"findings"`
}

type ScanState struct {
	sync.Mutex
	Running      bool          `json:"running"`
	Canceled     bool          `json:"canceled"`
	Complete     bool          `json:"complete"`
	CurrentPath  string        `json:"currentPath"`
	ScannedFiles int           `json:"scannedFiles"`
	FoundAssets  int           `json:"foundAssets"`
	Error        string        `json:"error,omitempty"`
	Findings     []AuditResult `json:"findings,omitempty"`
	cancelFunc   context.CancelFunc
}

var (
	cachedFindings   []AuditResult
	findingsMutex    sync.Mutex
	currentScanState = &ScanState{}
)

// openBrowser opens the default web browser across OS platforms
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default: // linux, bsd, etc.
		cmd = exec.Command("xdg-open", url)
	}
	hideConsole(cmd)
	_ = cmd.Start()
}

// Register Windows Add/Remove Programs entry on first run
func registerWindowsUninstall() {
	if runtime.GOOS != "windows" {
		return
	}
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	key := `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\QuarkShieldPostQuantumGuard`
	c1 := exec.Command("reg", "add", key, "/v", "DisplayName", "/d", "QuarkShield Post-Quantum Guard", "/f")
	hideConsole(c1)
	_ = c1.Run()

	c2 := exec.Command("reg", "add", key, "/v", "DisplayVersion", "/d", "2.0.0", "/f")
	hideConsole(c2)
	_ = c2.Run()

	c3 := exec.Command("reg", "add", key, "/v", "Publisher", "/d", "Fedmitigate LLC", "/f")
	hideConsole(c3)
	_ = c3.Run()

	c4 := exec.Command("reg", "add", key, "/v", "DisplayIcon", "/d", exePath, "/f")
	hideConsole(c4)
	_ = c4.Run()

	c5 := exec.Command("reg", "add", key, "/v", "UninstallString", "/d", fmt.Sprintf("\"%s\" --uninstall", exePath), "/f")
	hideConsole(c5)
	_ = c5.Run()

	c6 := exec.Command("reg", "add", key, "/v", "NoModify", "/t", "REG_DWORD", "/d", "1", "/f")
	hideConsole(c6)
	_ = c6.Run()

	c7 := exec.Command("reg", "add", key, "/v", "NoRepair", "/t", "REG_DWORD", "/d", "1", "/f")
	hideConsole(c7)
	_ = c7.Run()
}

func unregisterWindowsUninstall() {
	if runtime.GOOS != "windows" {
		return
	}
	removeDesktopAndStartMenuShortcuts()
	key := `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\QuarkShieldPostQuantumGuard`
	c := exec.Command("reg", "delete", key, "/f")
	hideConsole(c)
	_ = c.Run()
}

// StartGUI launches the local embedded Post-Quantum Guard Web UI
func StartGUI(preferredPort int, defaultServer string, defaultToken string) error {
	// 0. Single-instance upgrade: if an existing QuarkShield Guard instance is already running on the port,
	// gracefully tell the previous background process to exit so the new version takes over immediately.
	checkURL := fmt.Sprintf("http://127.0.0.1:%d/api/status", preferredPort)
	client := http.Client{Timeout: 800 * time.Millisecond}
	resp, errCheck := client.Get(checkURL)
	if errCheck == nil && resp.StatusCode == http.StatusOK {
		_ = resp.Body.Close()
		exitURL := fmt.Sprintf("http://127.0.0.1:%d/api/exit", preferredPort)
		_, _ = client.Post(exitURL, "application/json", nil)
		time.Sleep(900 * time.Millisecond)
	}

	// Detach console immediately so no black command prompt window lingers
	detachConsole()
	createDesktopAndStartMenuShortcuts()
	registerWindowsUninstall()
	InitLicense()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "workstation"
	}
	localIP := getLocalIP()
	osName := runtime.GOOS
	archName := runtime.GOARCH

	mux := http.NewServeMux()

	// 1. Serve Embedded Single-Page Post-Quantum Guard GUI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		htmlBytes, err := embeddedWebFS.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "Failed to load embedded UI", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		_, _ = w.Write(htmlBytes)
	})

	// Serve App Icon & Favicon & Logo
	mux.HandleFunc("/quarkshield-logo.png", func(w http.ResponseWriter, r *http.Request) {
		imgBytes, err := embeddedWebFS.ReadFile("web/quarkshield-logo.png")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(imgBytes)
	})
	mux.HandleFunc("/app_icon.png", func(w http.ResponseWriter, r *http.Request) {
		imgBytes, err := embeddedWebFS.ReadFile("web/app_icon.png")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(imgBytes)
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		imgBytes, err := embeddedWebFS.ReadFile("web/app_icon.png")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(imgBytes)
	})

	// 2. Host Metadata API
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		lic := GetLicenseInfo()
		userHome, _ := os.UserHomeDir()
		cfg := LoadEnrollmentConfig()
		compName := GetFriendlyComputerName()
		hwUUID := GetHardwareUUID()

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"hostname":        hostname,
			"computerName":    compName,
			"hardwareUuid":    hwUUID,
			"os":              osName,
			"arch":            archName,
			"ip":              localIP,
			"home":            userHome,
			"serverUrl":       cfg.ServerURL,
			"token":           cfg.Token,
			"isEnrolled":      cfg.Token != "",
			"autoSync":        cfg.AutoSyncEnabled,
			"syncIntervalMin": cfg.SyncIntervalMin,
			"lastSyncTime":    cfg.LastSyncTime,
			"license":         lic,
		})
	})

	// License Management APIs
	mux.HandleFunc("/api/license", HandleLicenseAPI)
	mux.HandleFunc("/api/license/activate", HandleActivateLicenseAPI)

	// 3. Asynchronous Scan Management APIs with Live Progress & Cancel
	mux.HandleFunc("/api/scan/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ScanRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		currentScanState.Lock()
		if currentScanState.Running {
			currentScanState.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"started": false,
				"message": "A scan is already actively running.",
			})
			return
		}

		lic := GetLicenseInfo()
		if !lic.CanScan {
			currentScanState.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"started": false,
				"error":   "Your 7-day trial has expired. Please activate a partner or corporate license key.",
			})
			return
		}

		ctx, cancel := context.WithCancel(context.Background())
		currentScanState.Running = true
		currentScanState.Canceled = false
		currentScanState.Complete = false
		currentScanState.CurrentPath = "Initializing post-quantum cryptographic auditor..."
		currentScanState.ScannedFiles = 0
		currentScanState.FoundAssets = 0
		currentScanState.Error = ""
		currentScanState.Findings = nil
		currentScanState.cancelFunc = cancel
		currentScanState.Unlock()

		go func(quick bool, targetPath string, scanCtx context.Context) {
			defer func() {
				if r := recover(); r != nil {
					currentScanState.Lock()
					currentScanState.Running = false
					currentScanState.Error = fmt.Sprintf("Audit engine recovered from unexpected fault: %v", r)
					currentScanState.CurrentPath = "Scan terminated safely."
					currentScanState.Unlock()
				}
			}()

			findings, scannedCount, err := RunScanWithProgress(scanCtx, quick, targetPath, func(curPath string, scanned int, found int) {
				currentScanState.Lock()
				currentScanState.CurrentPath = curPath
				currentScanState.ScannedFiles = scanned
				currentScanState.FoundAssets = found
				currentScanState.Unlock()
			})

			currentScanState.Lock()
			defer currentScanState.Unlock()
			currentScanState.Running = false

			if err != nil {
				if errors.Is(err, context.Canceled) || scanCtx.Err() != nil {
					currentScanState.Canceled = true
					currentScanState.CurrentPath = "Scan canceled by user."
					currentScanState.Findings = findings
					currentScanState.FoundAssets = len(findings)
				} else {
					currentScanState.Error = err.Error()
					currentScanState.CurrentPath = "Scan error: " + err.Error()
				}
			} else {
				currentScanState.Complete = true
				currentScanState.ScannedFiles = scannedCount
				currentScanState.FoundAssets = len(findings)
				currentScanState.Findings = findings
				currentScanState.CurrentPath = "Audit complete."

				findingsMutex.Lock()
				cachedFindings = findings
				findingsMutex.Unlock()

				scanType := "full"
				if quick {
					scanType = "quick"
				} else if targetPath != "" {
					scanType = "custom"
				}
				_, _ = SaveScanResult(scanType, targetPath, scannedCount, findings)
			}
		}(req.Quick, req.Path, ctx)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"started": true,
		})
	})

	mux.HandleFunc("/api/scan/progress", func(w http.ResponseWriter, r *http.Request) {
		currentScanState.Lock()
		defer currentScanState.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(currentScanState)
	})

	mux.HandleFunc("/api/scan/cancel", func(w http.ResponseWriter, r *http.Request) {
		currentScanState.Lock()
		if currentScanState.cancelFunc != nil {
			currentScanState.cancelFunc()
		}
		currentScanState.Canceled = true
		currentScanState.Running = false
		currentScanState.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"canceled": true,
		})
	})

	// Network TLS Probe API
	mux.HandleFunc("/api/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		type ProbeReq struct {
			Target string `json:"target"`
		}
		var req ProbeReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		target := strings.TrimSpace(req.Target)
		if target == "" {
			target = "cloudflare.com"
		}

		findings, err := ProbeEndpoint(target)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   err.Error(),
			})
			return
		}

		findingsMutex.Lock()
		cachedFindings = findings
		findingsMutex.Unlock()

		cleanHost := strings.TrimPrefix(target, "https://")
		cleanHost = strings.TrimPrefix(cleanHost, "http://")
		cleanHost = strings.Split(cleanHost, "/")[0]
		if strings.Contains(cleanHost, ":") {
			h, _, errH := net.SplitHostPort(cleanHost)
			if errH == nil {
				cleanHost = h
			}
		}

		isPQSecure := false
		suiteStr := ""
		keySizeStr := ""
		threatLevel := "CRITICAL"
		detailedAudit := ""
		remediation := ""
		explainer := ""

		for _, f := range findings {
			if f.Type == "network_probe" {
				if !f.IsVulnerable {
					isPQSecure = true
					threatLevel = "SECURE"
				}
				if strings.Contains(f.Name, "Key Exchange") {
					suiteStr = f.Algorithm
					keySizeStr = fmt.Sprintf("%d-bit", f.KeySize)
					detailedAudit = f.Description
					remediation = f.Recommendation
					explainer = f.Explainer
				}
			}
		}

		if suiteStr == "" && len(findings) > 0 {
			suiteStr = findings[0].Algorithm
			keySizeStr = fmt.Sprintf("%d-bit", findings[0].KeySize)
			detailedAudit = findings[0].Description
			remediation = findings[0].Recommendation
			explainer = findings[0].Explainer
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":            true,
			"target":             target,
			"host":               cleanHost,
			"protocolSuite":      suiteStr,
			"publicKeySize":      keySizeStr,
			"quantumThreatLevel": threatLevel,
			"isSecure":           isPQSecure,
			"detailedAudit":      detailedAudit,
			"remediation":        remediation,
			"explainer":          explainer,
			"findings":           findings,
			"count":              len(findings),
		})
	})

	// Legacy synchronous endpoint
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ScanRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		lic := GetLicenseInfo()
		if !lic.CanScan {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Your 7-day trial has expired. Please activate a partner or corporate license key.",
			})
			return
		}

		findings, scannedCount, err := RunScan(req.Quick, req.Path)
		if err != nil {
			http.Error(w, fmt.Sprintf("Scan failed: %v", err), http.StatusInternalServerError)
			return
		}

		findingsMutex.Lock()
		cachedFindings = findings
		findingsMutex.Unlock()

		scanType := "full"
		if req.Quick {
			scanType = "quick"
		} else if req.Path != "" {
			scanType = "custom"
		}
		_, _ = SaveScanResult(scanType, req.Path, scannedCount, findings)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":       "complete",
			"scannedFiles": scannedCount,
			"findings":     findings,
			"count":        len(findings),
		})
	})

	// Scan History APIs
	mux.HandleFunc("/api/scans", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		list, err := ListScanHistory()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(list)
	})

	mux.HandleFunc("/api/scans/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		rec, err := GetLatestScanResult()
		if err != nil || rec == nil {
			// Check if findings currently in memory, auto-persist to disk so user doesn't lose current scan
			findingsMutex.Lock()
			currentFindingsLen := len(cachedFindings)
			var inMemFindings []AuditResult
			if currentFindingsLen > 0 {
				inMemFindings = make([]AuditResult, currentFindingsLen)
				copy(inMemFindings, cachedFindings)
			}
			findingsMutex.Unlock()

			if currentFindingsLen > 0 {
				rec, err = SaveScanResult("quick", "Workstation Audit", currentFindingsLen, inMemFindings)
				if err == nil && rec != nil {
					_ = json.NewEncoder(w).Encode(rec)
					return
				}
			}

			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "No scan history found."})
			return
		}
		_ = json.NewEncoder(w).Encode(rec)
	})

	mux.HandleFunc("/api/scans/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		type DelReq struct {
			ID string `json:"id"`
		}
		var req DelReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.ID == "" {
			req.ID = r.URL.Query().Get("id")
		}
		if req.ID == "" {
			http.Error(w, "Missing scan id", http.StatusBadRequest)
			return
		}
		err := DeleteScanResult(req.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})

	mux.HandleFunc("/api/scans/get", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "Missing scan id", http.StatusBadRequest)
			return
		}
		rec, err := GetScanResult(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rec)
	})

	mux.HandleFunc("/api/scans/load", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		type LoadReq struct {
			ID string `json:"id"`
		}
		var req LoadReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.ID == "" {
			http.Error(w, "Missing scan id", http.StatusBadRequest)
			return
		}

		rec, err := GetScanResult(req.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		findingsMutex.Lock()
		cachedFindings = rec.Findings
		findingsMutex.Unlock()

		currentScanState.Lock()
		currentScanState.Running = false
		currentScanState.Complete = true
		currentScanState.Canceled = false
		currentScanState.Error = ""
		currentScanState.ScannedFiles = rec.ScannedFiles
		currentScanState.FoundAssets = len(rec.Findings)
		currentScanState.Findings = rec.Findings
		currentScanState.CurrentPath = fmt.Sprintf("Loaded historical scan from %s", rec.DateFormatted)
		currentScanState.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":          true,
			"record":           rec,
			"findings":         rec.Findings,
			"totalAssets":      len(rec.Findings),
			"scannedFiles":     rec.ScannedFiles,
			"targetPath":       rec.TargetPath,
			"quantumRiskScore": rec.QuantumRiskScore,
			"vulnerableCount":  rec.VulnerableCount,
		})
	})

	// 4. Synchronize Findings to QuarkShield Cloud Fleet
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Enforce non-trial active license guard to avoid cross-data pollution
		lic := GetLicenseInfo()
		if !lic.IsLicensed || lic.Tier == "trial" || lic.IsExpired {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Fleet synchronization requires an activated Partner Evaluation or Corporate Enterprise license key. 7-Day Trial instances cannot sync telemetry to avoid cross-tenant pollution.",
			})
			return
		}

		var req SyncRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		cfg := LoadEnrollmentConfig()
		token := strings.TrimSpace(req.Token)
		if token == "" {
			token = cfg.Token
		}
		if token == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid sync request: missing Fleet Enrollment Token"})
			return
		}

		srv := strings.TrimSpace(req.ServerUrl)
		if srv == "" {
			srv = cfg.ServerURL
		}
		if srv == "" {
			srv = "https://quarkshield.ai"
		}

		findings := req.Findings
		if len(findings) == 0 {
			findingsMutex.Lock()
			findings = cachedFindings
			findingsMutex.Unlock()
		}
		if len(findings) == 0 {
			if latest, err := GetLatestScanResult(); err == nil && latest != nil && len(latest.Findings) > 0 {
				findings = latest.Findings
			}
		}

		err := SendFleetTelemetry(srv, token, hostname, osName, archName, localIP, findings, lic.LicenseKey, lic.TenantName)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("Enrolled machine '%s' and synchronized %d assets.", hostname, len(findings)),
		})
	})

	// 4b. Enrollment Config API (Permanent Token & Scheduling Settings)
	mux.HandleFunc("/api/enrollment", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			var newCfg EnrollmentConfig
			_ = json.NewDecoder(r.Body).Decode(&newCfg)
			cfg := LoadEnrollmentConfig()
			if newCfg.ServerURL != "" {
				cfg.ServerURL = strings.TrimSpace(newCfg.ServerURL)
			}
			if newCfg.Token != "" {
				cfg.Token = strings.TrimSpace(newCfg.Token)
			}
			cfg.AutoSyncEnabled = newCfg.AutoSyncEnabled
			if newCfg.SyncIntervalMin > 0 {
				cfg.SyncIntervalMin = newCfg.SyncIntervalMin
			}
			_ = SaveEnrollmentConfig(cfg)
			_ = json.NewEncoder(w).Encode(cfg)
			return
		}
		_ = json.NewEncoder(w).Encode(LoadEnrollmentConfig())
	})

	// 5. Download CycloneDX 1.6 CBOM JSON
	mux.HandleFunc("/api/cbom", func(w http.ResponseWriter, r *http.Request) {
		findingsMutex.Lock()
		findings := cachedFindings
		findingsMutex.Unlock()

		cbomBytes, err := GenerateCycloneDXCBOM(findings, hostname, osName)
		if err != nil {
			http.Error(w, fmt.Sprintf("CBOM generation failed: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"cyclonedx-cbom-%s.json\"", hostname))
		_, _ = w.Write(cbomBytes)
	})

	// 6. Graceful Exit API
	var server *http.Server
	mux.HandleFunc("/api/exit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "shutting_down"})
		go func() {
			time.Sleep(500 * time.Millisecond)
			if server != nil {
				_ = server.Close()
			}
			os.Exit(0)
		}()
	})

	// 7. Complete Uninstall API
	mux.HandleFunc("/api/uninstall", func(w http.ResponseWriter, r *http.Request) {
		unregisterWindowsUninstall()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "uninstalled"})
		go func() {
			time.Sleep(600 * time.Millisecond)
			if server != nil {
				_ = server.Close()
			}
			if runtime.GOOS == "windows" {
				exePath, err := os.Executable()
				if err == nil {
					cmdDel := exec.Command("cmd.exe", "/c", "timeout /t 2 >nul & del /f /q \""+exePath+"\"")
					hideConsole(cmdDel)
					_ = cmdDel.Start()
				}
			} else if runtime.GOOS == "darwin" {
				exePath, err := os.Executable()
				if err == nil {
					targetToRemove := exePath
					if strings.Contains(exePath, ".app/Contents/MacOS") {
						parts := strings.Split(exePath, ".app/Contents/MacOS")
						targetToRemove = parts[0] + ".app"
					}
					cmdDel := exec.Command("sh", "-c", "sleep 1; rm -rf \""+targetToRemove+"\"")
					_ = cmdDel.Start()
				}
			}
			os.Exit(0)
		}()
	})

	// 8. Native Folder Picker API
	mux.HandleFunc("/api/browse", func(w http.ResponseWriter, r *http.Request) {
		selectedPath := pickFolderOS()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"path": selectedPath})
	})

	// Find an available port starting at preferredPort
	port := preferredPort
	var listener net.Listener
	var err error

	for attempts := 0; attempts < 10; attempts++ {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		listener, err = net.Listen("tcp", addr)
		if err == nil {
			break
		}
		port++
	}

	if listener == nil {
		// Fallback to dynamic port assigned by OS
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("failed to bind local GUI server: %w", err)
		}
		port = listener.Addr().(*net.TCPAddr).Port
	}

	serverURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	server = &http.Server{
		Handler: mux,
	}

	fmt.Println("==================================================")
	fmt.Printf(" 🛡️ QuarkShield Post-Quantum Guard Active\n")
	fmt.Printf(" 🌐 Interface URL: %s\n", serverURL)
	fmt.Println("    Opening your default web browser now...")
	fmt.Println("    (Press Ctrl+C in this console or click Exit to quit)")
	// Launch default web browser
	go func() {
		time.Sleep(350 * time.Millisecond)
		openBrowser(serverURL)
	}()

	// Background Automated Daily Sync Worker
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cfg := LoadEnrollmentConfig()
			if !cfg.AutoSyncEnabled || cfg.Token == "" {
				continue
			}

			shouldSync := false
			if cfg.LastSyncTime == "" {
				shouldSync = true
			} else {
				lastT, err := time.Parse(time.RFC3339, cfg.LastSyncTime)
				if err != nil || time.Since(lastT) >= time.Duration(cfg.SyncIntervalMin)*time.Minute {
					shouldSync = true
				}
			}

			if shouldSync {
				currentScanState.Lock()
				isRunning := currentScanState.Running
				currentScanState.Unlock()
				if isRunning {
					continue
				}

				lic := GetLicenseInfo()
				if !lic.IsLicensed || lic.Tier == "trial" || lic.IsExpired {
					continue
				}

				findings, _, errScan := RunScan(true, "")
				if errScan == nil && len(findings) > 0 {
					_ = SendFleetTelemetry(cfg.ServerURL, cfg.Token, hostname, osName, archName, localIP, findings, lic.LicenseKey, lic.TenantName)
				}
			}
		}
	}()

	return server.Serve(listener)
}
