//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// AuditWindowsCertStore queries Windows Cert:\CurrentUser\My, Cert:\LocalMachine\My, and Personal stores
func AuditWindowsCertStore() []AuditResult {
	var results []AuditResult

	psScript := `Get-ChildItem -Path Cert:\CurrentUser\My, Cert:\LocalMachine\My, Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -and $_.Subject -notmatch '^CN=Microsoft' } | Select-Object -First 40 | ForEach-Object {
		$k = $_.PublicKey.Key
		$algo = if ($k) { $k.KeyExchangeAlgorithm } else { $_.PublicKey.Oid.FriendlyName }
		$size = if ($k) { $k.KeySize } else { 2048 }
		$issuer = $_.Issuer -replace '\r|\n', ' '
		$subj = $_.Subject -replace '\r|\n', ' '
		"$($_.Thumbprint)|$subj|$issuer|$algo|$size|$($_.NotAfter.ToString('yyyy-MM-dd'))|$($_.PSParentPath)"
	}`

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psScript)
	hideConsole(cmd)
	out, err := cmd.Output()
	if err != nil {
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

		cleanAlgo := "RSA"
		if strings.Contains(strings.ToUpper(algo), "ECDSA") || strings.Contains(strings.ToUpper(algo), "ECC") {
			cleanAlgo = "ECDSA"
		} else if strings.Contains(strings.ToUpper(algo), "RSA") {
			cleanAlgo = "RSA"
		}

		riskLevel := "high"
		sizeInt := 2048
		if strings.Contains(size, "1024") {
			riskLevel = "critical"
			sizeInt = 1024
		} else if strings.Contains(size, "512") {
			riskLevel = "critical"
			sizeInt = 512
		} else if strings.Contains(size, "4096") {
			sizeInt = 4096
		}

		shortID := thumbprint
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}

		dispSubject := subject
		if len(dispSubject) > 45 {
			dispSubject = dispSubject[:45] + "..."
		}

		desc := fmt.Sprintf("Windows Certificate Store asset (%s). Subject: %s. Issuer: %s. Expiry: %s", storePath, subject, issuer, expiry)
		plan := GenerateRemediation("certificate", cleanAlgo, sizeInt, subject, desc, storePath)

		results = append(results, AuditResult{
			ID:                   fmt.Sprintf("win-cert-%s", shortID),
			Type:                 "certificate",
			Name:                 fmt.Sprintf("Cert Store: %s", dispSubject),
			Path:                 storePath,
			Algorithm:            fmt.Sprintf("%s-%s", cleanAlgo, size),
			KeySize:              sizeInt,
			QuantumThreat:        "Shor's Algorithm (Asymmetric Factorization/DLP)",
			IsVulnerable:         true,
			RiskLevel:            riskLevel,
			Status:               "Quantum Vulnerable",
			Description:          desc,
			Recommendation:       plan.Recommendation,
			RemediationSteps:     plan.Steps,
			CodeSnippet:          plan.CodeSnippet,
			Explainer:            "Classical asymmetric keys in the Windows Certificate Store can be forged using Shor's Algorithm on a cryptanalytically relevant quantum computer.",
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
	$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
	foreach ($p in $protocols) {
		$clientKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$p\Client"
		$cDisabled = (Get-ItemProperty -Path $clientKey -ErrorAction SilentlyContinue).DisabledByDefault
		$cEnabled = (Get-ItemProperty -Path $clientKey -ErrorAction SilentlyContinue).Enabled
		
		# On Windows 10/11, TLS 1.0 and 1.1 are active if not explicitly disabled
		if ($cDisabled -ne 1 -and $cEnabled -ne 0) {
			$findings += "PROTO:$p"
		}
	}
	$ciphers = @("Triple DES 168", "RC4 128/128", "RC4 56/128", "RC4 40/128", "DES 56/56")
	foreach ($c in $ciphers) {
		$cipherKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$c"
		$cEnabled = (Get-ItemProperty -Path $cipherKey -ErrorAction SilentlyContinue).Enabled
		# In Schannel, 3DES is enabled by default on Windows unless explicitly disabled
		if ($c -eq "Triple DES 168") {
			if ($cEnabled -ne 0) {
				$findings += "CIPHER:$c"
			}
		} else {
			if ($cEnabled -eq 1) {
				$findings += "CIPHER:$c"
			}
		}
	}
	$findings -join ";"
	`

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psScript)
	hideConsole(cmd)
	out, err := cmd.Output()
	if err != nil {
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
			cipher := strings.TrimPrefix(item, "CIPHER:")
			slug := strings.ToLower(strings.ReplaceAll(cipher, " ", ""))
			results = append(results, AuditResult{
				ID:                   fmt.Sprintf("win-cipher-%s", slug),
				Type:                 "config",
				Name:                 fmt.Sprintf("Windows Schannel Cipher: %s", cipher),
				Path:                 fmt.Sprintf("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\%s", cipher),
				Algorithm:            fmt.Sprintf("%s (Grover Weakened)", cipher),
				QuantumThreat:        "Grover's Algorithm (Key Halving)",
				IsVulnerable:         true,
				RiskLevel:            "high",
				Status:               "Quantum Vulnerable",
				Description:          fmt.Sprintf("Windows Schannel permits legacy cipher %s which is broken by Grover's Algorithm (effective security halved to 56/64 bits).", cipher),
				Recommendation:       fmt.Sprintf("Disable %s in Windows Schannel registry and enforce AES-256-GCM under CNSA 2.0 standards.", cipher),
				RemediationSteps: []string{
					fmt.Sprintf("Open elevated PowerShell: New-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\%s' -Force", cipher),
					fmt.Sprintf("Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\%s' -Name 'Enabled' -Value 0 -Type DWord", cipher),
					"Enforce modern AES-256 GCM cipher suites via Group Policy (Computer Configuration > Administrative Templates > Network > SSL Configuration Settings).",
				},
				CodeSnippet:          fmt.Sprintf("New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\%s' -Name 'Enabled' -Value 0 -PropertyType DWORD -Force", cipher),
				Explainer:            fmt.Sprintf("%s has short block/key lengths. Grover's quantum search reduces effective symmetric security below acceptable thresholds (NIST SP 800-131A / CNSA 2.0).", cipher),
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

