package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// QuarkShield Master HMAC Secret for Offline License Verification
const LicenseSigningSecret = "QuarkShield_PQC_Fleet_Master_License_Secret_2026"

type LicenseState struct {
	InstallID  string    `json:"installId"`
	FirstRun   time.Time `json:"firstRun"`
	TrialDays  int       `json:"trialDays"`
	Tier       string    `json:"tier"` // "trial", "partner", "corporate"
	Status     string    `json:"status"`
	LicenseKey string    `json:"licenseKey,omitempty"`
	TenantName string    `json:"tenantName,omitempty"`
	Seats      int       `json:"seats,omitempty"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type LicenseInfoResponse struct {
	Tier          string `json:"tier"`
	Status        string `json:"status"`
	DaysRemaining int    `json:"daysRemaining"`
	ExpiresAt     string `json:"expiresAt"`
	IsExpired     bool   `json:"isExpired"`
	IsLicensed    bool   `json:"isLicensed"`
	TenantName    string `json:"tenantName,omitempty"`
	Seats         int    `json:"seats,omitempty"`
	LicenseKey    string `json:"licenseKey,omitempty"`
	CanScan       bool   `json:"canScan"`
}

type ActivateLicenseRequest struct {
	Key string `json:"key"`
}

var (
	licenseMu      sync.RWMutex
	currentLicense LicenseState
)

func getLicenseStoragePath() string {
	if runtime.GOOS == "windows" {
		localApp := os.Getenv("LOCALAPPDATA")
		if localApp != "" {
			dir := filepath.Join(localApp, "QuarkShield")
			_ = os.MkdirAll(dir, 0755)
			return filepath.Join(dir, "license.json")
		}
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "."
	}
	dir := filepath.Join(home, ".quarkshield")
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "license.json")
}

// InitLicense initializes the 7-day trial or loads an existing license
func InitLicense() LicenseState {
	licenseMu.Lock()
	defer licenseMu.Unlock()

	path := getLicenseStoragePath()
	if data, err := os.ReadFile(path); err == nil {
		var loaded LicenseState
		if err := json.Unmarshal(data, &loaded); err == nil && !loaded.FirstRun.IsZero() {
			currentLicense = loaded
			refreshLicenseStatus(&currentLicense)
			saveLicenseToFile(currentLicense)

			// If license was previously activated, authoritatively sync seat count with server in background
			if currentLicense.LicenseKey != "" {
				go func(licKey string) {
					if resp, err := QueryServerLicenseVerify(licKey); err == nil && resp != nil && resp.Valid {
						licenseMu.Lock()
						currentLicense.Seats = resp.Seats
						if resp.TenantName != "" {
							currentLicense.TenantName = resp.TenantName
						}
						if resp.Tier != "" {
							currentLicense.Tier = resp.Tier
						}
						saveLicenseToFile(currentLicense)
						licenseMu.Unlock()
					}
				}(currentLicense.LicenseKey)
			}

			return currentLicense
		}
	}

	// Initialize fresh 7-day trial
	now := time.Now().UTC()
	currentLicense = LicenseState{
		InstallID: generateID(),
		FirstRun:  now,
		TrialDays: 7,
		Tier:      "trial",
		Status:    "active",
		ExpiresAt: now.AddDate(0, 0, 7),
	}
	saveLicenseToFile(currentLicense)
	return currentLicense
}

func refreshLicenseStatus(l *LicenseState) {
	now := time.Now().UTC()
	if now.After(l.ExpiresAt) {
		l.Status = "expired"
	} else {
		l.Status = "active"
	}
}

func saveLicenseToFile(l LicenseState) {
	path := getLicenseStoragePath()
	if data, err := json.MarshalIndent(l, "", "  "); err == nil {
		_ = os.WriteFile(path, data, 0600)
	}
}

// ValidateLicenseKey validates offline cryptographic license keys
// Key format: QS-{TIER}-{TENANT}-{EXPIRES_HEX}-{SIGNATURE_HEX}
// Example: QS-PARTNER-DEMO-67CE3400-8F9A12B3
//
//	QS-CORP-ACME-6945A800-4C3D82E1
func ValidateLicenseKey(key string) (tier string, tenant string, expiresAt time.Time, err error) {
	key = strings.TrimSpace(strings.ToUpper(key))
	parts := strings.Split(key, "-")
	if len(parts) != 5 || parts[0] != "QS" {
		return "", "", time.Time{}, fmt.Errorf("invalid license key format. Expected QS-[TIER]-[TENANT]-[EXPIRY]-[SIG]")
	}

	tier = strings.ToLower(parts[1])
	if tier != "partner" && tier != "corp" && tier != "trial" {
		return "", "", time.Time{}, fmt.Errorf("unrecognized license tier: %s", parts[1])
	}
	if tier == "corp" {
		tier = "corporate"
	}

	tenant = parts[2]
	expiryHex := parts[3]
	sigHex := parts[4]

	expSec, err := strconv.ParseInt(expiryHex, 16, 64)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("invalid expiry encoding in license key")
	}
	expiresAt = time.Unix(expSec, 0).UTC()

	// Verify HMAC-SHA256 signature
	dataToSign := fmt.Sprintf("%s:%s:%s", parts[1], tenant, expiryHex)
	mac := hmac.New(sha256.New, []byte(LicenseSigningSecret))
	mac.Write([]byte(dataToSign))
	expectedSig := hex.EncodeToString(mac.Sum(nil))[:8] // Truncated to 8 hex chars for compact key

	if !strings.EqualFold(sigHex, expectedSig) {
		// Backwards compatible check for demo testing
		if sigHex != "TESTKEY1" && sigHex != "QUARK001" {
			return "", "", time.Time{}, fmt.Errorf("cryptographic signature verification failed for license key")
		}
	}

	return tier, tenant, expiresAt, nil
}

// GenerateLicenseKey creates a valid cryptographically signed license key
func GenerateLicenseKey(tier string, tenant string, expiresAt time.Time) string {
	tier = strings.ToUpper(tier)
	if tier == "CORPORATE" {
		tier = "CORP"
	}
	tenant = strings.ToUpper(strings.ReplaceAll(tenant, " ", ""))
	if tenant == "" {
		tenant = "CLIENT"
	}
	expiryHex := fmt.Sprintf("%X", expiresAt.Unix())

	dataToSign := fmt.Sprintf("%s:%s:%s", tier, tenant, expiryHex)
	mac := hmac.New(sha256.New, []byte(LicenseSigningSecret))
	mac.Write([]byte(dataToSign))
	sig := strings.ToUpper(hex.EncodeToString(mac.Sum(nil))[:8])

	return fmt.Sprintf("QS-%s-%s-%s-%s", tier, tenant, expiryHex, sig)
}

// GetLicenseInfo returns current license details for UI
func GetLicenseInfo() LicenseInfoResponse {
	licenseMu.RLock()
	defer licenseMu.RUnlock()

	now := time.Now().UTC()
	isExpired := now.After(currentLicense.ExpiresAt)
	daysRemaining := int(currentLicense.ExpiresAt.Sub(now).Hours() / 24)
	if daysRemaining < 0 {
		daysRemaining = 0
	}

	isLicensed := currentLicense.Tier == "corporate" || currentLicense.Tier == "partner"
	canScan := !isExpired || isLicensed

	status := "active"
	if isExpired {
		status = "expired"
	}

	return LicenseInfoResponse{
		Tier:          currentLicense.Tier,
		Status:        status,
		DaysRemaining: daysRemaining,
		ExpiresAt:     currentLicense.ExpiresAt.Format("2006-01-02"),
		IsExpired:     isExpired,
		IsLicensed:    isLicensed,
		TenantName:    currentLicense.TenantName,
		Seats:         currentLicense.Seats,
		LicenseKey:    currentLicense.LicenseKey,
		CanScan:       canScan,
	}
}

// ServerLicenseVerifyResponse models the response from POST /api/scan/license/verify
type ServerLicenseVerifyResponse struct {
	Valid        bool   `json:"valid"`
	LicenseKey   string `json:"licenseKey"`
	Seats        int    `json:"seats"`
	Tier         string `json:"tier"`
	TenantName   string `json:"tenantName"`
	DisplayName  string `json:"displayName,omitempty"`
	CustomerId   string `json:"customerId,omitempty"`
	DurationDays int    `json:"durationDays,omitempty"`
	ExpiresAt    string `json:"expiresAt"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
}

// QueryServerLicenseVerify queries the central QuarkShield platform for authoritative license metadata
func QueryServerLicenseVerify(key string) (*ServerLicenseVerifyResponse, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("empty license key")
	}

	serverURL := "https://quarkshield.ai"
	endpoint := fmt.Sprintf("%s/api/scan/license/verify", serverURL)

	reqBody, _ := json.Marshal(map[string]string{"key": key})
	client := &http.Client{Timeout: 4 * time.Second}
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errData map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&errData)
		errMsg := "License verification rejected by central server"
		if msg, ok := errData["error"].(string); ok {
			errMsg = msg
		}
		return nil, fmt.Errorf("%s", errMsg)
	}

	var result ServerLicenseVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ActivateLicense applies a license key
func ActivateLicense(key string) (LicenseInfoResponse, error) {
	key = strings.TrimSpace(key)

	// 1. First attempt central authoritative verification via QuarkShield.ai API
	srvResp, srvErr := QueryServerLicenseVerify(key)
	if srvErr == nil && srvResp != nil && srvResp.Valid {
		licenseMu.Lock()
		currentLicense.LicenseKey = key
		currentLicense.Tier = srvResp.Tier
		if currentLicense.Tier == "corp" {
			currentLicense.Tier = "corporate"
		}
		currentLicense.TenantName = srvResp.TenantName
		currentLicense.Seats = srvResp.Seats
		if currentLicense.Seats <= 0 {
			if currentLicense.Tier == "corporate" {
				currentLicense.Seats = 100
			} else {
				currentLicense.Seats = 10
			}
		}
		currentLicense.Status = "active"
		if parsedExp, err := time.Parse("2006-01-02", srvResp.ExpiresAt); err == nil {
			currentLicense.ExpiresAt = parsedExp
		} else if parsedIso, err := time.Parse(time.RFC3339, srvResp.ExpiresAt); err == nil {
			currentLicense.ExpiresAt = parsedIso
		}
		saveLicenseToFile(currentLicense)
		licenseMu.Unlock()
		return GetLicenseInfo(), nil
	}

	// 2. If server explicitly rejected due to revocation
	if srvErr != nil && strings.Contains(strings.ToLower(srvErr.Error()), "revoked") {
		return GetLicenseInfo(), srvErr
	}

	// 3. Fallback: Cryptographic offline HMAC validation (for air-gapped workstations)
	tier, tenant, expiresAt, err := ValidateLicenseKey(key)
	if err != nil {
		return GetLicenseInfo(), err
	}

	licenseMu.Lock()
	currentLicense.LicenseKey = key
	currentLicense.Tier = tier
	currentLicense.TenantName = tenant
	currentLicense.ExpiresAt = expiresAt
	currentLicense.Status = "active"
	// Set default seats to 100 for corporate (authoritative fix), 10 for partner
	if tier == "corporate" {
		currentLicense.Seats = 100
	} else {
		currentLicense.Seats = 10
	}
	saveLicenseToFile(currentLicense)
	licenseMu.Unlock()

	return GetLicenseInfo(), nil
}

// HandleLicenseAPI handles GET /api/license
func HandleLicenseAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		return
	}

	info := GetLicenseInfo()
	_ = json.NewEncoder(w).Encode(info)
}

// HandleActivateLicenseAPI handles POST /api/license/activate
func HandleActivateLicenseAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req ActivateLicenseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
		http.Error(w, `{"error":"License key is required"}`, http.StatusBadRequest)
		return
	}

	info, err := ActivateLicense(req.Key)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"license": info,
		"message": fmt.Sprintf("Successfully activated %s license for %s.", info.Tier, info.TenantName),
	})
}
