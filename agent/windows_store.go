//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// AuditWindowsCertStore queries Windows Cert:\CurrentUser\My, Cert:\LocalMachine\My, and Personal stores
func AuditWindowsCertStore() []AuditResult {
	var results []AuditResult

	psScript := `Get-ChildItem -Path Cert:\CurrentUser\My, Cert:\LocalMachine\My, Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -and $_.Subject -notmatch '^CN=Microsoft' } | Select-Object -First 40 | ForEach-Object {
		$k = $_.PublicKey.Key
		$algo = $_.PublicKey.Oid.FriendlyName
		# Read the REAL key size via the modern getters so ECDSA reports its curve
		# size (256/384) instead of a bogus 2048 default. 0 = unknown (never 2048).
		$size = 0
		try { $rsa = $_.GetRSAPublicKey(); if ($rsa) { $size = $rsa.KeySize } } catch {}
		if ($size -eq 0) { try { $ec = $_.GetECDsaPublicKey(); if ($ec) { $size = $ec.KeySize } } catch {} }
		if ($size -eq 0 -and $k) { $size = $k.KeySize }
		$issuer = $_.Issuer -replace '\r|\n', ' '
		$subj = $_.Subject -replace '\r|\n', ' '
		"$($_.Thumbprint)|$subj|$issuer|$algo|$size|$($_.NotAfter.ToString('yyyy-MM-dd'))|$($_.PSParentPath)"
	}`

	cmd := exec.Command(winPowerShell(), "-NoProfile", "-NonInteractive", "-Command", psScript)
	hideConsole(cmd)
	out, err := cmd.Output()
	if err != nil {
		// Read failure (locked-down PowerShell, non-elevated, WOW64) — record it
		// so the scan is not scored "secure" on an unread certificate store.
		RecordCollectorError("windows_cert_store", err)
		return results
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "|") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 6 {
			continue
		}

		thumbprint := parts[0]
		subject := parts[1]
		issuer := parts[2]
		algo := parts[3]
		size := parts[4]
		expiry := parts[5]
		storePath := "Windows Certificate Store"
		if len(parts) >= 7 && parts[6] != "" {
			storePath = parts[6]
		}

		au := strings.ToUpper(algo)
		cleanAlgo := "RSA"
		switch {
		case strings.Contains(au, "ECDSA") || strings.Contains(au, "ECC") || strings.Contains(au, "ELLIPTIC") || strings.Contains(au, "ECPUBLICKEY"):
			cleanAlgo = "ECDSA"
		case strings.Contains(au, "RSA"):
			cleanAlgo = "RSA"
		case strings.Contains(au, "DSA"):
			cleanAlgo = "DSA"
		case strings.Contains(au, "ED25519"):
			cleanAlgo = "Ed25519"
		case au != "":
			cleanAlgo = algo // keep the real algorithm rather than mislabel as RSA
		}

		// Real key size from the agent (0 = unknown; never a bogus 2048 default).
		sizeInt := 0
		if n, err := strconv.Atoi(strings.TrimSpace(size)); err == nil && n > 0 {
			sizeInt = n
		}
		riskLevel := "high"
		if cleanAlgo == "RSA" && sizeInt > 0 && sizeInt < 2048 {
			riskLevel = "critical"
		} else if sizeInt == 1024 || sizeInt == 512 {
			riskLevel = "critical"
		}

		shortID := thumbprint
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}

		algoLabel := cleanAlgo
		if sizeInt > 0 {
			algoLabel = fmt.Sprintf("%s-%d", cleanAlgo, sizeInt)
		}

		desc := fmt.Sprintf("Windows Certificate Store asset (%s). Subject: %s. Issuer: %s. Expiry: %s. Thumbprint: %s", storePath, subject, issuer, expiry, thumbprint)
		plan := GenerateRemediation("certificate", cleanAlgo, sizeInt, subject, desc, storePath)

		vulnerable := algoIsQuantumVulnerable(cleanAlgo)

		// Context matters for credibility:
		// - A cert in a Root/CA trust store is a PUBLIC TRUST ANCHOR the operator
		//   does NOT own and cannot revoke/re-key — it is inventory/awareness, not
		//   an urgent action item. The CA operator migrates it.
		// - An EXPIRED cert has no active key-establishment exposure.
		lowerStore := strings.ToLower(storePath)
		isTrustAnchor := strings.Contains(lowerStore, "root") || strings.Contains(lowerStore, "authroot") ||
			strings.Contains(lowerStore, "\\ca") || strings.Contains(lowerStore, "certificateauthority")
		isExpired := false
		if t, perr := time.Parse("2006-01-02", strings.TrimSpace(expiry)); perr == nil && t.Before(time.Now()) {
			isExpired = true
		}

		status := certStatus(vulnerable)
		recommendation := plan.Recommendation
		steps := plan.Steps
		snippet := plan.CodeSnippet
		explainer := "Classical asymmetric keys can be forged using Shor's Algorithm once a cryptographically-relevant quantum computer exists; sub-2048-bit RSA is additionally weak against classical attacks."
		if isTrustAnchor {
			if riskLevel == "high" || riskLevel == "critical" {
				riskLevel = "low"
			}
			status = "Trust Anchor (informational)"
			recommendation = "Inventory/awareness only — this is a public trust-anchor (root/intermediate CA) in the system trust store. You do not own this key and cannot re-key it; the CA operator is responsible for its post-quantum migration. Remove it only if your organization no longer needs to trust this CA."
			explainer = "Root/intermediate CA certificates use classical algorithms that a future quantum computer could forge, but they are public trust anchors managed by the CA — not operator-owned keys requiring re-key."
			// Inventory/awareness steps — NOT the generic migration steps (which would
			// contradict "you cannot re-key this" for a root you do not own).
			steps, snippet = TrustAnchorRemediation("Get-ChildItem Cert: -Recurse | Where-Object { $_.Thumbprint -eq '" + thumbprint + "' } | Format-List Subject, Issuer, Thumbprint, NotAfter, SignatureAlgorithm")
		}
		if isExpired {
			if riskLevel == "high" || riskLevel == "critical" {
				riskLevel = "low"
			}
			desc += fmt.Sprintf(" NOTE: EXPIRED on %s — retained only to validate previously-issued signatures; no active key-establishment exposure.", expiry)
		}

		results = append(results, AuditResult{
			ID:                   fmt.Sprintf("win-cert-%s", shortID),
			Type:                 "certificate",
			Name:                 fmt.Sprintf("Cert Store: %s", subject),
			Path:                 fmt.Sprintf("%s — Thumbprint: %s", storePath, thumbprint),
			Algorithm:            algoLabel,
			KeySize:              sizeInt,
			QuantumThreat:        "Shor's Algorithm (Asymmetric Factorization/DLP)",
			IsVulnerable:         vulnerable,
			RiskLevel:            riskLevel,
			Status:               status,
			Description:          desc,
			Recommendation:       recommendation,
			RemediationSteps:     steps,
			CodeSnippet:          snippet,
			Explainer:            explainer,
			ComplianceViolations: []string{"CNSA 2.0", "NIST FIPS 204", "EO 14028"},
		})
	}

	return results
}

// AuditWindowsSchannel checks for enabled legacy TLS protocols and weak symmetric ciphers in Windows Schannel
func AuditWindowsSchannel() []AuditResult {
	var results []AuditResult

	psScript := `
	$findings = @()
	# Protocols: report ONLY when a protocol is EXPLICITLY enabled in the registry.
	# On modern Windows these keys are ABSENT and the OS default is disabled, so
	# absence must NOT be treated as "enabled" (that produced false positives,
	# e.g. flagging TLS 1.0 / 3DES on machines where the keys don't exist).
	$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
	foreach ($p in $protocols) {
		$k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$p\Client"
		$props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
		if ($props -ne $null) {
			if ($props.Enabled -eq 1 -or ($props.DisabledByDefault -eq 0 -and $props.Enabled -ne 0)) {
				$findings += "PROTO:$p"
			}
		}
	}
	# Ciphers: enumerate the ACTUAL enabled TLS cipher suites and flag weak ones.
	# This reflects the truly negotiable set (Get-TlsCipherSuite) instead of
	# inferring from the legacy SCHANNEL\Ciphers registry, which is usually absent.
	try {
		$weak = Get-TlsCipherSuite | Where-Object { $_.Name -match '3DES|_DES_|RC4|RC2|_NULL_|MD5|EXPORT' }
		foreach ($w in $weak) { $findings += ("CIPHER:" + $w.Name) }
	} catch {}
	$findings -join ";"
	`

	cmd := exec.Command(winPowerShell(), "-NoProfile", "-NonInteractive", "-Command", psScript)
	hideConsole(cmd)
	out, err := cmd.Output()
	if err != nil {
		RecordCollectorError("windows_schannel", err)
		return results
	}

	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return results
	}

	items := strings.Split(raw, ";")
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		if strings.HasPrefix(item, "CIPHER:") {
			suite := strings.TrimPrefix(item, "CIPHER:")
			up := strings.ToUpper(suite)
			slug := strings.ToLower(strings.ReplaceAll(suite, "_", "-"))
			// 3DES is a Grover (quantum) concern; RC4/DES/NULL/MD5/EXPORT are
			// CLASSICALLY broken — label the threat accordingly rather than
			// calling everything a quantum/Grover problem.
			isTripleDES := strings.Contains(up, "3DES")
			threat := "Classically Broken (pre-quantum)"
			explainer := fmt.Sprintf("Cipher suite %s uses a classically broken primitive (RC4/DES/NULL/MD5/EXPORT class) and must be disabled regardless of quantum considerations.", suite)
			status := "Weak / Broken"
			risk := "critical"
			if isTripleDES {
				threat = "Grover's Algorithm (Key Halving)"
				explainer = fmt.Sprintf("Cipher suite %s uses 3DES (112-bit effective key); Grover's search lowers effective symmetric security below acceptable thresholds (NIST SP 800-131A / CNSA 2.0) and 3DES is deprecated classically.", suite)
				status = "Quantum Vulnerable"
				risk = "high"
			}
			results = append(results, AuditResult{
				ID:             fmt.Sprintf("win-cipher-%s", slug),
				Type:           "config",
				Name:           fmt.Sprintf("Enabled weak TLS cipher suite: %s", suite),
				Path:           fmt.Sprintf("Get-TlsCipherSuite -Name '%s' (enabled TLS cipher suite)", suite),
				Algorithm:      suite,
				QuantumThreat:  threat,
				IsVulnerable:   true,
				RiskLevel:      risk,
				Status:         status,
				Description:    fmt.Sprintf("Windows Schannel has the weak cipher suite %s enabled (confirmed via Get-TlsCipherSuite).", suite),
				Recommendation: fmt.Sprintf("Disable the cipher suite and enforce AES-256-GCM under CNSA 2.0: Disable-TlsCipherSuite -Name '%s'.", suite),
				RemediationSteps: []string{
					"Open an elevated PowerShell prompt.",
					fmt.Sprintf("Disable-TlsCipherSuite -Name '%s'", suite),
					"Prefer TLS 1.3 / AES-256-GCM suites via Group Policy (Computer Configuration > Administrative Templates > Network > SSL Configuration Settings).",
				},
				CodeSnippet:          fmt.Sprintf("Disable-TlsCipherSuite -Name '%s'", suite),
				Explainer:            explainer,
				ComplianceViolations: []string{"CNSA 2.0", "NIST SP 800-131A", "PCI-DSS 4.0"},
			})
		} else {
			proto := strings.TrimPrefix(item, "PROTO:")
			slug := strings.ToLower(strings.ReplaceAll(proto, " ", ""))
			plan := GenerateRemediation("config", proto, 0, fmt.Sprintf("Windows Schannel: %s Enabled", proto), proto, "")

			results = append(results, AuditResult{
				ID:                   fmt.Sprintf("win-schannel-%s", slug),
				Type:                 "config",
				Name:                 fmt.Sprintf("Windows Schannel: %s Enabled", proto),
				Path:                 fmt.Sprintf("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\%s", proto),
				Algorithm:            fmt.Sprintf("Legacy Protocol (%s)", proto),
				QuantumThreat:        "Harvest Now, Decrypt Later (HNDL)",
				IsVulnerable:         true,
				RiskLevel:            "critical",
				Status:               "Quantum Vulnerable",
				Description:          fmt.Sprintf("Windows Schannel cryptographic subsystem permits obsolete %s protocol negotiation.", proto),
				Recommendation:       plan.Recommendation,
				RemediationSteps:     plan.Steps,
				CodeSnippet:          plan.CodeSnippet,
				Explainer:            "Legacy protocols permit Harvest-Now-Decrypt-Later interception and quantum decryption of recorded sessions.",
				ComplianceViolations: []string{"CNSA 2.0", "NIST SP 800-52r2", "PCI-DSS 4.0"},
			})
		}
	}

	return results
}

// AuditPlatformSystemStores dispatches Windows Certificate Store and Schannel protocol audits
func AuditPlatformSystemStores() ([]AuditResult, []AuditResult) {
	certs := AuditWindowsCertStore()
	schannel := AuditWindowsSchannel()
	return certs, schannel
}
