package main

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
	Mode  string `json:"mode,omitempty"`
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
	ScanType     string        `json:"scanType,omitempty"`
	Findings     []AuditResult `json:"findings,omitempty"`
	cancelFunc   context.CancelFunc
	// generation increments on every start; a finishing goroutine only publishes
	// its result if it is still the current generation (cancel-then-start race).
	generation uint64
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
		cmd = exec.Command(winSystem32("rundll32.exe"), "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default: // linux, bsd, etc.
		cmd = exec.Command("xdg-open", url)
	}
	hideConsole(cmd)
	_ = cmd.Start()
}

// isManagedInstall reports whether QuarkShield was installed by the Windows
// installer, which drops a ".managed_install" marker next to the exe and owns the
// Start-Menu shortcut + Add/Remove Programs entry. In that case the app must not
// self-create duplicates.
func isManagedInstall() bool {
	exePath, err := os.Executable()
	if err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(exePath), ".managed_install")); err == nil {
		return true
	}
	return false
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
	c1 := exec.Command(winSystem32("reg.exe"), "add", key, "/v", "DisplayName", "/d", "QuarkShield Post-Quantum Guard", "/f")
	hideConsole(c1)
	_ = c1.Run()

	c2 := exec.Command(winSystem32("reg.exe"), "add", key, "/v", "DisplayVersion", "/d", "2.0.0", "/f")
	hideConsole(c2)
	_ = c2.Run()

	c3 := exec.Command(winSystem32("reg.exe"), "add", key, "/v", "Publisher", "/d", "Fedmitigate LLC", "/f")
	hideConsole(c3)
	_ = c3.Run()

	c4 := exec.Command(winSystem32("reg.exe"), "add", key, "/v", "DisplayIcon", "/d", exePath, "/f")
	hideConsole(c4)
	_ = c4.Run()

	c5 := exec.Command(winSystem32("reg.exe"), "add", key, "/v", "UninstallString", "/d", fmt.Sprintf("\"%s\" --uninstall", exePath), "/f")
	hideConsole(c5)
	_ = c5.Run()

	c6 := exec.Command(winSystem32("reg.exe"), "add", key, "/v", "NoModify", "/t", "REG_DWORD", "/d", "1", "/f")
	hideConsole(c6)
	_ = c6.Run()

	c7 := exec.Command(winSystem32("reg.exe"), "add", key, "/v", "NoRepair", "/t", "REG_DWORD", "/d", "1", "/f")
	hideConsole(c7)
	_ = c7.Run()
}

func unregisterWindowsUninstall() {
	if runtime.GOOS != "windows" {
		return
	}
	removeDesktopAndStartMenuShortcuts()
	key := `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\QuarkShieldPostQuantumGuard`
	c := exec.Command(winSystem32("reg.exe"), "delete", key, "/f")
	hideConsole(c)
	_ = c.Run()
}

// StartGUI launches the local embedded Post-Quantum Guard Web UI
// localGuard protects the local GUI HTTP server from other websites and from
// DNS-rebinding attacks (DEF-41). The GUI listens on 127.0.0.1 and previously
// had no Origin/Host/CSRF checks, so any page the user visited could drive it:
// exfiltrate scan results, re-point the agent's server/token, or uninstall it.
//
// The guard enforces, for /api/* requests:
//   - Host must be a loopback address on this port (blocks DNS rebinding, where
//     an attacker's domain resolves to 127.0.0.1 but carries its own Host).
//   - Sec-Fetch-Site (sent by modern browsers) must be same-origin/none; any
//     cross-site or same-site request (fetch, form, img, navigation) is refused.
//   - If an Origin header is present it must be this exact local origin.
//
// No permissive CORS headers are ever sent, so cross-origin reads are blocked.
func localGuard(next http.Handler, port int, apiToken string) http.Handler {
	allowedHosts := map[string]bool{
		fmt.Sprintf("127.0.0.1:%d", port): true,
		fmt.Sprintf("localhost:%d", port): true,
		fmt.Sprintf("[::1]:%d", port):     true,
	}
	allowedOrigins := map[string]bool{
		fmt.Sprintf("http://127.0.0.1:%d", port): true,
		fmt.Sprintf("http://localhost:%d", port): true,
		fmt.Sprintf("http://[::1]:%d", port):     true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if !allowedHosts[r.Host] {
				http.Error(w, "Forbidden (host)", http.StatusForbidden)
				return
			}
			if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
				http.Error(w, "Forbidden (cross-site)", http.StatusForbidden)
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && !allowedOrigins[origin] {
				http.Error(w, "Forbidden (origin)", http.StatusForbidden)
				return
			}
			// EVERY /api call requires the per-install token (set as a cookie when the
			// dashboard page is served, or read from the 0600 config). GET responses
			// include the enrollment token and license, so reads are gated too: a
			// non-browser local process without the cookie gets nothing.
			if apiToken != "" {
				c, err := r.Cookie("qs_local_token")
				if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(apiToken)) != 1 {
					http.Error(w, "Forbidden (token)", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func StartGUI(preferredPort int, defaultServer string, defaultToken string) error {
	// 0. Single-instance upgrade: if an existing QuarkShield Guard instance is already running on the port,
	// gracefully tell the previous background process to exit so the new version takes over immediately.
	checkURL := fmt.Sprintf("http://127.0.0.1:%d/api/status", preferredPort)
	client := http.Client{Timeout: 800 * time.Millisecond}
	existingTok := LoadEnrollmentConfig().LocalAPIToken
	checkReq, _ := http.NewRequest(http.MethodGet, checkURL, nil)
	if existingTok != "" {
		checkReq.AddCookie(&http.Cookie{Name: "qs_local_token", Value: existingTok})
	}
	resp, errCheck := client.Do(checkReq)
	if errCheck == nil && resp.StatusCode == http.StatusOK {
		_ = resp.Body.Close()
		exitURL := fmt.Sprintf("http://127.0.0.1:%d/api/exit", preferredPort)
		// Authenticate the shutdown to the running instance with the shared token
		// (both instances read it from the same 0600 config).
		if req, e := http.NewRequest(http.MethodPost, exitURL, nil); e == nil {
			req.Header.Set("Content-Type", "application/json")
			if existingTok != "" {
				req.AddCookie(&http.Cookie{Name: "qs_local_token", Value: existingTok})
			}
			_, _ = client.Do(req)
		}
		time.Sleep(900 * time.Millisecond)
	}

	// Detach console immediately so no black command prompt window lingers
	detachConsole()
	// When installed via the Windows installer, it owns the shortcuts and the
	// Add/Remove Programs entry — don't self-create duplicates.
	if !isManagedInstall() {
		createDesktopAndStartMenuShortcuts()
		registerWindowsUninstall()
	}
	InitLicense()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "workstation"
	}
	localIP := getLocalIP()
	osName := runtime.GOOS
	archName := runtime.GOARCH

	// Per-install token gating state-changing local API calls. Persisted in the
	// 0600 enrollment config; delivered to the legitimate dashboard as a cookie.
	apiCfg := LoadEnrollmentConfig()
	if apiCfg.LocalAPIToken == "" {
		apiCfg.LocalAPIToken = randToken()
		_ = SaveEnrollmentConfig(apiCfg)
	}
	localAPIToken := apiCfg.LocalAPIToken

	mux := http.NewServeMux()

	// 1. Serve Embedded Single-Page Post-Quantum Guard GUI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		htmlBytes, err := embeddedWebFS.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "Failed to load embedded UI", http.StatusInternalServerError)
			return
		}
		// Hand the dashboard the local API token so its POSTs authenticate.
		http.SetCookie(w, &http.Cookie{Name: "qs_local_token", Value: localAPIToken, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
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
		currentScanState.ScanType = req.Mode
		currentScanState.Findings = nil
		currentScanState.cancelFunc = cancel
		currentScanState.generation++
		myGen := currentScanState.generation
		currentScanState.Unlock()

		go func(quick bool, targetPath string, mode string, scanCtx context.Context) {
			defer func() {
				if r := recover(); r != nil {
					currentScanState.Lock()
					if currentScanState.generation != myGen {
						currentScanState.Unlock()
						return
					}
					currentScanState.Running = false
					currentScanState.Error = fmt.Sprintf("Audit engine recovered from unexpected fault: %v", r)
					currentScanState.CurrentPath = "Scan terminated safely."
					currentScanState.Unlock()
				}
			}()

			progressCb := func(curPath string, scanned int, found int) {
				currentScanState.Lock()
				if currentScanState.generation != myGen {
					currentScanState.Unlock()
					return
				}
				currentScanState.CurrentPath = curPath
				currentScanState.ScannedFiles = scanned
				currentScanState.FoundAssets = found
				currentScanState.Unlock()
			}

			var findings []AuditResult
			var scannedCount int
			var err error

			if strings.ToLower(mode) == "sbom" {
				findings, scannedCount, err = RunSbomScanWithProgress(scanCtx, progressCb)
			} else {
				findings, scannedCount, err = RunScanWithProgress(scanCtx, quick, targetPath, progressCb)
			}

			currentScanState.Lock()
			defer currentScanState.Unlock()
			if currentScanState.generation != myGen {
				// A newer scan was started after this one was canceled; discard.
				return
			}
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
				if strings.ToLower(mode) == "sbom" {
					scanType = "sbom"
				} else if quick {
					scanType = "quick"
				} else if targetPath != "" {
					scanType = "custom"
				}

				currentScanState.ScanType = scanType
				_, _ = SaveScanResult(scanType, targetPath, scannedCount, findings)
			}
		}(req.Quick, req.Path, req.Mode, ctx)

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
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
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

		var req SyncRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		cfg := LoadEnrollmentConfig()
		token := strings.TrimSpace(req.Token)
		if token == "" {
			token = cfg.Token
		}

		if strings.HasPrefix(strings.ToUpper(token), "QS-") {
			_, _ = ActivateLicense(token)
		}

		lic := GetLicenseInfo()

		if token == "" && (!lic.IsLicensed || lic.Tier == "trial" || lic.IsExpired) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Fleet synchronization requires an activated Partner Evaluation or Corporate Enterprise license key or Fleet Enrollment Token.",
			})
			return
		}

		if token == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid sync request: missing Fleet Enrollment Token or License Key"})
			return
		}

		// Destination is the ENROLLED server only, never a caller-supplied URL, so
		// a local process cannot POST /api/sync with its own serverUrl and redirect
		// telemetry (findings + the fleet token) to an attacker host. Change the
		// server through /api/enrollment, which persists it to the config.
		srv := strings.TrimSpace(cfg.ServerURL)
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
			_ = json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&newCfg)
			cfg := LoadEnrollmentConfig()
			if newCfg.ServerURL != "" {
				srv := strings.TrimSpace(newCfg.ServerURL)
				if err := validateServerURL(srv); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
				cfg.ServerURL = strings.TrimRight(srv, "/")
			}
			if newCfg.Token != "" {
				cfg.Token = strings.TrimSpace(newCfg.Token)
			}
			cfg.AutoSyncEnabled = newCfg.AutoSyncEnabled
			if newCfg.SyncIntervalMin > 0 {
				if newCfg.SyncIntervalMin < 5 {
					newCfg.SyncIntervalMin = 5
				}
				cfg.SyncIntervalMin = newCfg.SyncIntervalMin
			}
			_ = SaveEnrollmentConfig(cfg)
			cfg.LocalAPIToken = "" // never expose the API gate token over HTTP
			_ = json.NewEncoder(w).Encode(cfg)
			return
		}
		cfg := LoadEnrollmentConfig()
		cfg.LocalAPIToken = ""
		_ = json.NewEncoder(w).Encode(cfg)
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
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
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
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
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
					scheduleSelfDelete(exePath)
				}
			} else if runtime.GOOS == "darwin" {
				exePath, err := os.Executable()
				if err == nil {
					targetToRemove := exePath
					if strings.Contains(exePath, ".app/Contents/MacOS") {
						parts := strings.Split(exePath, ".app/Contents/MacOS")
						targetToRemove = parts[0] + ".app"
					}
					scheduleSelfDelete(targetToRemove)
				}
			}
			os.Exit(0)
		}()
	})

	// 8. Native Folder Picker API
	mux.HandleFunc("/api/browse", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
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
		Handler: localGuard(mux, port, localAPIToken),
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

	// Alias listener on port 41723 to ensure any references redirect to the active port
	if port != 41723 {
		go func() {
			aliasListener, aliasErr := net.Listen("tcp", "127.0.0.1:41723")
			if aliasErr == nil {
				defer aliasListener.Close()
				_ = http.Serve(aliasListener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					target := fmt.Sprintf("http://127.0.0.1:%d%s", port, r.RequestURI)
					http.Redirect(w, r, target, http.StatusTemporaryRedirect)
				}))
			}
		}()
	}

	// DEF-39: once enrolled, install/refresh the persistent background service
	// (macOS LaunchAgent) so pulls + scheduled syncs keep running when the app is
	// closed. No-op on Windows; Linux uses systemd via install-linux.sh.
	go func() {
		if c := LoadEnrollmentConfig(); c.Token != "" {
			ensureBackgroundService(c.ServerURL)
		}
	}()

	// Background worker: on-demand command polling (DEF-38) + automated daily sync.
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cfg := LoadEnrollmentConfig()
			if cfg.Token == "" {
				continue
			}

			// On-demand poll: honor an admin "Pull Telemetry" (scan_and_sync) request
			// within ~2 min while the app is running, independent of the daily timer and
			// of AutoSyncEnabled (an operator-initiated pull should always be serviced).
			forceSync := false
			if cmds, err := FetchAgentCommands(cfg.ServerURL, cfg.Token); err == nil {
				for _, c := range cmds {
					if c == "scan_and_sync" {
						forceSync = true
					}
				}
			}

			shouldSync := forceSync
			if !shouldSync && cfg.AutoSyncEnabled {
				if cfg.LastSyncTime == "" {
					shouldSync = true
				} else {
					lastT, err := time.Parse(time.RFC3339, cfg.LastSyncTime)
					if err != nil || time.Since(lastT) >= time.Duration(cfg.SyncIntervalMin)*time.Minute {
						shouldSync = true
					}
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
				if cfg.Token == "" && (!lic.IsLicensed || lic.Tier == "trial" || lic.IsExpired) {
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
