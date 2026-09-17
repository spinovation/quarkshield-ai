package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type ScanSummary struct {
	ID               string    `json:"id"`
	Timestamp        time.Time `json:"timestamp"`
	DateFormatted    string    `json:"dateFormatted"`
	ScanType         string    `json:"scanType"` // "quick", "full", "custom", "network_probe"
	TargetPath       string    `json:"targetPath"`
	ScannedFiles     int       `json:"scannedFiles"`
	FoundAssets      int       `json:"foundAssets"`
	VulnerableCount  int       `json:"vulnerableCount"`
	QuantumRiskScore int       `json:"quantumRiskScore"`
	RiskLevel        string    `json:"riskLevel"`
}

type StoredScanRecord struct {
	ScanSummary
	Hostname string        `json:"hostname"`
	OS       string        `json:"os"`
	Arch     string        `json:"arch"`
	Findings []AuditResult `json:"findings"`
}

var scanStoreMu sync.RWMutex

// getScanStorageDir returns the OS-specific local directory for scan history
func getScanStorageDir() string {
	if runtime.GOOS == "windows" {
		localApp := os.Getenv("LOCALAPPDATA")
		if localApp != "" {
			dir := filepath.Join(localApp, "QuarkShield", "scans")
			_ = os.MkdirAll(dir, 0755)
			return dir
		}
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "."
	}
	dir := filepath.Join(home, ".quarkshield", "scans")
	_ = os.MkdirAll(dir, 0755)
	return dir
}

// SaveScanResult writes a scan record to local JSON storage
func SaveScanResult(scanType string, targetPath string, scannedFiles int, findings []AuditResult) (*StoredScanRecord, error) {
	scanStoreMu.Lock()
	defer scanStoreMu.Unlock()

	dir := getScanStorageDir()
	now := time.Now()
	id := fmt.Sprintf("scan_%d", now.UnixNano()/1e6)

	vulnerableCount := 0
	criticalCount := 0
	highCount := 0
	mediumCount := 0

	for _, f := range findings {
		if f.IsVulnerable {
			vulnerableCount++
			switch strings.ToLower(f.RiskLevel) {
			case "critical":
				criticalCount++
			case "high":
				highCount++
			case "medium":
				mediumCount++
			}
		}
	}

	riskScore := 0
	if len(findings) > 0 {
		riskScore = (criticalCount * 25) + (highCount * 15) + (mediumCount * 5)
		if riskScore > 100 {
			riskScore = 100
		}
		if vulnerableCount > 0 && riskScore < 25 {
			riskScore = 30
		}
	}

	riskLevel := "secure"
	if criticalCount > 0 {
		riskLevel = "critical"
	} else if highCount > 0 {
		riskLevel = "high"
	} else if mediumCount > 0 {
		riskLevel = "medium"
	} else if vulnerableCount > 0 {
		riskLevel = "low"
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "local-workstation"
	}

	record := StoredScanRecord{
		ScanSummary: ScanSummary{
			ID:               id,
			Timestamp:        now,
			DateFormatted:    now.Format("Jan 02, 2006 15:04:05 MST"),
			ScanType:         scanType,
			TargetPath:       targetPath,
			ScannedFiles:     scannedFiles,
			FoundAssets:      len(findings),
			VulnerableCount:  vulnerableCount,
			QuantumRiskScore: riskScore,
			RiskLevel:        riskLevel,
		},
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Findings: findings,
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize scan record: %w", err)
	}

	filePath := filepath.Join(dir, id+".json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to save scan to %s: %w", filePath, err)
	}

	return &record, nil
}

// ListScanHistory retrieves chronological list of prior scan summaries
func ListScanHistory() ([]ScanSummary, error) {
	scanStoreMu.RLock()
	defer scanStoreMu.RUnlock()

	dir := getScanStorageDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []ScanSummary{}, nil
	}

	var list []ScanSummary
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var rec StoredScanRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}

		if rec.ID == "" {
			rec.ID = strings.TrimSuffix(entry.Name(), ".json")
		}
		if rec.DateFormatted == "" && !rec.Timestamp.IsZero() {
			rec.DateFormatted = rec.Timestamp.Format("Jan 02, 2006 15:04:05 MST")
		}

		list = append(list, rec.ScanSummary)
	}

	// Sort descending by timestamp
	sort.Slice(list, func(i, j int) bool {
		return list[i].Timestamp.After(list[j].Timestamp)
	})

	if len(list) > 100 {
		list = list[:100]
	}

	return list, nil
}

// GetScanResult loads a full stored scan record by its ID
func GetScanResult(id string) (*StoredScanRecord, error) {
	scanStoreMu.RLock()
	defer scanStoreMu.RUnlock()

	cleanID := filepath.Base(id)
	if !strings.HasSuffix(cleanID, ".json") {
		cleanID += ".json"
	}

	dir := getScanStorageDir()
	filePath := filepath.Join(dir, cleanID)

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("scan record not found: %w", err)
	}

	var rec StoredScanRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("failed to parse scan record: %w", err)
	}

	return &rec, nil
}

// GetLatestScanResult returns the most recent stored scan, or nil if none exists
func GetLatestScanResult() (*StoredScanRecord, error) {
	history, err := ListScanHistory()
	if err != nil || len(history) == 0 {
		return nil, fmt.Errorf("no stored scans found")
	}
	return GetScanResult(history[0].ID)
}

// DeleteScanResult deletes a stored scan record by its ID
func DeleteScanResult(id string) error {
	scanStoreMu.Lock()
	defer scanStoreMu.Unlock()

	cleanID := filepath.Base(id)
	if !strings.HasSuffix(cleanID, ".json") {
		cleanID += ".json"
	}

	dir := getScanStorageDir()
	filePath := filepath.Join(dir, cleanID)
	return os.Remove(filePath)
}
