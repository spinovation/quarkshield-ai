package main

import (
	"testing"
	"time"
)

func TestLicenseLifecycle(t *testing.T) {
	// 1. Test Default Trial Initialization
	lic := InitLicense()
	if lic.Tier != "trial" {
		t.Fatalf("expected tier trial, got %s", lic.Tier)
	}
	if lic.TrialDays != 7 {
		t.Fatalf("expected trialDays 7, got %d", lic.TrialDays)
	}
	if lic.Status != "active" {
		t.Fatalf("expected status active, got %s", lic.Status)
	}

	// 2. Test Key Generation & Offline Validation
	exp := time.Now().AddDate(0, 3, 0).UTC() // 90 days
	partnerKey := GenerateLicenseKey("partner", "BETA_PARTNER", exp)
	t.Logf("Generated Partner Key: %s", partnerKey)

	tier, tenant, expParsed, err := ValidateLicenseKey(partnerKey)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if tier != "partner" {
		t.Fatalf("expected tier partner, got %s", tier)
	}
	if tenant != "BETA_PARTNER" {
		t.Fatalf("expected tenant BETA_PARTNER, got %s", tenant)
	}
	if expParsed.Unix() != exp.Unix() {
		t.Fatalf("expected exp %d, got %d", exp.Unix(), expParsed.Unix())
	}

	// 3. Test Corporate License Key Generation
	corpExp := time.Now().AddDate(1, 0, 0).UTC() // 1 year
	corpKey := GenerateLicenseKey("corporate", "ACME_CORP", corpExp)
	t.Logf("Generated Corporate Key: %s", corpKey)

	tierCorp, tenantCorp, _, errCorp := ValidateLicenseKey(corpKey)
	if errCorp != nil {
		t.Fatalf("corp validation failed: %v", errCorp)
	}
	if tierCorp != "corporate" {
		t.Fatalf("expected tier corporate, got %s", tierCorp)
	}
	if tenantCorp != "ACME_CORP" {
		t.Fatalf("expected tenant ACME_CORP, got %s", tenantCorp)
	}

	// 4. Test Tamper Resistance (Invalid Signature)
	tamperedKey := partnerKey[:len(partnerKey)-2] + "FF"
	_, _, _, errTamper := ValidateLicenseKey(tamperedKey)
	if errTamper == nil {
		t.Fatalf("expected error on tampered key, but got nil")
	}

	// 5. Test Activation
	info, errAct := ActivateLicense(corpKey)
	if errAct != nil {
		t.Fatalf("activation failed: %v", errAct)
	}
	if !info.IsLicensed {
		t.Fatalf("expected isLicensed true")
	}
	if info.TenantName != "ACME_CORP" {
		t.Fatalf("expected tenant ACME_CORP, got %s", info.TenantName)
	}
}
