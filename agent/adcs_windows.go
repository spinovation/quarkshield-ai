//go:build windows

package main

import (
	"os/exec"
	"strings"
)

// DiscoverADCS enumerates Active Directory Certificate Services on a
// domain-joined Windows host using the built-in certutil tool. It returns the
// discovered certificate assets and the CA's common name.
//
// It lists issued certificates (Disposition=20) with their public-key algorithm
// and length, which is the concrete cryptographic inventory of what the CA has
// issued. Requires rights to query the CA (typically run on or near the CA host).
func DiscoverADCS() ([]ADCSAsset, string, error) {
	caName := detectCAName()

	// Issued certificates with the columns the parser expects.
	out, err := exec.Command("certutil",
		"-view",
		"-restrict", "Disposition=20",
		"-out", "CommonName,CertificateTemplate,PublicKeyAlgorithm,PublicKeyLength,NotAfter",
		"csv",
	).Output()
	if err != nil {
		return nil, caName, err
	}

	assets := parseCertutilCSV(string(out))

	// Include the CA certificate itself if we can read it.
	if ca := discoverCACert(caName); ca != nil {
		assets = append([]ADCSAsset{*ca}, assets...)
	}
	return assets, caName, nil
}

func detectCAName() string {
	out, err := exec.Command("certutil", "-getreg", "CA\\CommonName").Output()
	if err != nil {
		return "Enterprise CA"
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "CommonName REG_SZ = ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "CommonName REG_SZ = "))
		}
	}
	return "Enterprise CA"
}

func discoverCACert(caName string) *ADCSAsset {
	// certutil -ca.cert emits the CA cert; -dump summarizes algorithm + length.
	out, err := exec.Command("certutil", "-ca.cert", "-dump").Output()
	if err != nil {
		return nil
	}
	text := string(out)
	alg := ""
	size := 0
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		if strings.Contains(l, "Public Key Algorithm") {
			alg = l
		}
		if strings.Contains(strings.ToLower(l), "public key length") || strings.Contains(l, "bit") {
			size = atoi(extractDigits(l))
		}
	}
	if alg == "" {
		return nil
	}
	algo, vuln, risk, threat := classifyADCSAlgo(alg, size)
	return &ADCSAsset{Name: caName + " (CA certificate)", Type: "ca_root", Algo: algo, Size: size, Vuln: vuln, Risk: risk, Threat: "Enterprise trust root. " + threat}
}

func extractDigits(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		} else if b.Len() > 0 {
			break
		}
	}
	return b.String()
}
