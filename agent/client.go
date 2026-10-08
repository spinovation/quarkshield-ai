package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// EnrollmentConfig represents permanently persisted fleet connection settings
type EnrollmentConfig struct {
	ServerURL       string `json:"serverUrl"`
	Token           string `json:"token"`
	TenantName      string `json:"tenantName,omitempty"`
	HardwareUUID    string `json:"hardwareUuid,omitempty"`
	ComputerName    string `json:"computerName,omitempty"`
	AutoSyncEnabled bool   `json:"autoSyncEnabled"`
	SyncIntervalMin int    `json:"syncIntervalMinutes"`
	LastSyncTime    string `json:"lastSyncTime,omitempty"`
	// LocalAPIToken gates state-changing calls to the local dashboard API. It is
	// set into a cookie when the dashboard page is served, so only a client that
	// loaded the page (or can read this 0600 config) can drive those endpoints.
	LocalAPIToken string `json:"localApiToken,omitempty"`
}

var (
	enrollmentMu sync.RWMutex
)

func getEnrollmentConfigPath() string {
	if runtime.GOOS == "windows" {
		localApp := os.Getenv("LOCALAPPDATA")
		if localApp != "" {
			dir := filepath.Join(localApp, "QuarkShield")
			_ = os.MkdirAll(dir, 0700)
			return filepath.Join(dir, "enrollment.json")
		}
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "."
	}
	dir := filepath.Join(home, ".quarkshield")
	_ = os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "enrollment.json")
}

// LoadEnrollmentConfig reads persistent configuration or initializes defaults
func LoadEnrollmentConfig() EnrollmentConfig {
	enrollmentMu.RLock()
	defer enrollmentMu.RUnlock()

	cfgPath := getEnrollmentConfigPath()
	var cfg EnrollmentConfig
	if data, err := os.ReadFile(cfgPath); err == nil {
		_ = json.Unmarshal(data, &cfg)
	}

	if cfg.ServerURL == "" {
		cfg.ServerURL = "https://quarkshield.ai"
	}
	if cfg.SyncIntervalMin <= 0 {
		cfg.SyncIntervalMin = 1440 // 24 hours default
	}
	if cfg.HardwareUUID == "" {
		cfg.HardwareUUID = GetHardwareUUID()
	}
	if cfg.ComputerName == "" {
		cfg.ComputerName = GetFriendlyComputerName()
	}

	return cfg
}

// SaveEnrollmentConfig permanently stores the enrollment settings
func SaveEnrollmentConfig(cfg EnrollmentConfig) error {
	enrollmentMu.Lock()
	defer enrollmentMu.Unlock()

	if cfg.HardwareUUID == "" {
		cfg.HardwareUUID = GetHardwareUUID()
	}
	if cfg.ComputerName == "" {
		cfg.ComputerName = GetFriendlyComputerName()
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(getEnrollmentConfigPath(), data, 0600)
}

// FleetPayload represents the JSON body sent to QuarkShield.AI /api/scan/agent/ingest
type FleetPayload struct {
	Hostname     string        `json:"hostname"`
	ComputerName string        `json:"computer_name,omitempty"`
	HardwareUUID string        `json:"hardware_uuid,omitempty"`
	OS           string        `json:"os"`
	Arch         string        `json:"arch"`
	IP           string        `json:"ip"`
	AgentVersion string        `json:"agent_version"`
	Token        string        `json:"token,omitempty"`
	LicenseKey   string        `json:"license_key,omitempty"`
	TenantName   string        `json:"tenant_name,omitempty"`
	Assets       []AuditResult `json:"assets"`
}

// SendFleetTelemetry sends scan findings to the centralized QuarkShield.AI endpoint
func SendFleetTelemetry(serverURL string, token string, hostname string, osName string, archName string, ip string, assets []AuditResult, licenseKey string, tenantName string) error {
	if assets == nil {
		assets = []AuditResult{}
	}

	hwUUID := GetHardwareUUID()
	compName := GetFriendlyComputerName()

	// If token wasn't explicitly supplied, check persistent enrollment
	cfg := LoadEnrollmentConfig()
	if token == "" && cfg.Token != "" {
		token = cfg.Token
	}
	if serverURL == "" && cfg.ServerURL != "" {
		serverURL = cfg.ServerURL
	}
	if serverURL == "" {
		serverURL = "https://quarkshield.ai"
	}

	// Enforce TLS for telemetry: never ship the fleet token + findings in
	// cleartext. Allow plain http only for an explicit loopback/dev server.
	if err := validateServerURL(serverURL); err != nil {
		return err
	}

	payloadObj := FleetPayload{
		Hostname:     hostname,
		ComputerName: compName,
		HardwareUUID: hwUUID,
		OS:           osName,
		Arch:         archName,
		IP:           ip,
		AgentVersion: "2.2.1",
		Token:        token,
		LicenseKey:   licenseKey,
		TenantName:   tenantName,
		Assets:       assets,
	}

	payload, err := json.Marshal(payloadObj)
	if err != nil {
		return fmt.Errorf("failed to serialize fleet telemetry: %v", err)
	}

	cleanServer := strings.TrimRight(serverURL, "/")
	url := fmt.Sprintf("%s/api/scan/agent/ingest", cleanServer)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create http request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Connector-Token", token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to QuarkShield server at %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return fmt.Errorf("server returned error code %d: %s", resp.StatusCode, string(body))
	}

	// Persist successful enrollment so future manual or scheduled syncs require zero token entry
	cfg.ServerURL = cleanServer
	cfg.Token = token
	cfg.TenantName = tenantName
	cfg.HardwareUUID = hwUUID
	cfg.ComputerName = compName
	cfg.LastSyncTime = time.Now().UTC().Format(time.RFC3339)
	_ = SaveEnrollmentConfig(cfg)
	return nil
}

// validateServerURL accepts https URLs, or plain http ONLY to a loopback host.
// The previous check was a substring match ("localhost"), which accepted
// http://localhost.attacker.com and shipped the fleet token in cleartext.
func validateServerURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid server URL %q", raw)
	}
	host := strings.ToLower(u.Hostname())
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("refusing to send telemetry over plaintext http to %s; use https", raw)
	default:
		return fmt.Errorf("unsupported server URL scheme %q (use https)", u.Scheme)
	}
}

// RegisterAssets (legacy fallback)
func RegisterAssets(serverURL string, assets []AuditResult) error {
	if assets == nil {
		assets = []AuditResult{}
	}
	payload, err := json.Marshal(assets)
	if err != nil {
		return fmt.Errorf("failed to serialize scan findings: %v", err)
	}

	url := fmt.Sprintf("%s/api/assets", serverURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create http request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to QuarkShield server at %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return fmt.Errorf("server returned error code %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ReportADCS posts the discovered Active Directory Certificate Services inventory
// to the server's push endpoint (POST /api/scan/adcs/report). The fleet
// enrollment token authenticates and resolves the tenant server-side.
func ReportADCS(serverURL string, token string, caName string, assets []ADCSAsset) error {
	if err := validateServerURL(serverURL); err != nil {
		return err
	}
	cleanServer := strings.TrimRight(serverURL, "/")
	body := map[string]interface{}{
		"caName": caName,
		"token":  token,
		"assets": assets,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/api/scan/adcs/report", cleanServer)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Connector-Token", token)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}
	return nil
}

// FetchAgentCommands polls the server for pending on-demand commands for this
// machine (DEF-38). The fleet token authenticates and resolves the tenant; the
// server returns the machine's pending commands and marks them dispatched.
func FetchAgentCommands(serverURL string, token string) ([]string, error) {
	// The fleet token travels with this request: never send it to a plaintext or
	// non-loopback http URL, even one persisted by an older (laxer) build.
	if err := validateServerURL(serverURL); err != nil {
		return nil, err
	}
	cleanServer := strings.TrimRight(serverURL, "/")
	hostname, _ := os.Hostname()
	body := map[string]string{
		"token":         token,
		"hardware_uuid": GetHardwareUUID(),
		"hostname":      hostname,
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", cleanServer+"/api/scan/agent/commands", bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Connector-Token", token)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("commands request failed (HTTP %d)", resp.StatusCode)
	}
	var parsed struct {
		Commands []struct {
			Command string `json:"command"`
		} `json:"commands"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return nil, err
	}
	out := []string{}
	for _, c := range parsed.Commands {
		out = append(out, c.Command)
	}
	return out, nil
}
