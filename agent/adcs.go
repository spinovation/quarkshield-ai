package main

import (
	"encoding/csv"
	"strconv"
	"strings"
)

func itoa(n int) string { return strconv.Itoa(n) }
func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// ADCSAsset is one cryptographic object discovered from Active Directory
// Certificate Services (an issued certificate or CA certificate).
type ADCSAsset struct {
	Name     string `json:"name"`
	Type     string `json:"type"`   // ca_root | certificate | template
	Algo     string `json:"algo"`
	Size     int    `json:"size"`
	Vuln     bool   `json:"vuln"`
	Risk     string `json:"risk"`
	Threat   string `json:"threat"`
	Template string `json:"template,omitempty"`
	NotAfter string `json:"expiresAt,omitempty"`
}

// classifyADCSAlgo maps a certutil "Public Key Algorithm" value (a display name
// like "RSA"/"ECC" or an OID) plus a key length to an algorithm label and its
// quantum vulnerability.
func classifyADCSAlgo(alg string, size int) (string, bool, string, string) {
	a := strings.ToLower(strings.TrimSpace(alg))
	switch {
	case strings.Contains(a, "rsa"), strings.Contains(a, "1.2.840.113549.1.1.1"):
		if size == 0 {
			size = 2048
		}
		risk := "high"
		if size <= 2048 {
			risk = "critical"
		}
		return "RSA-" + itoa(size), true, risk, "Shor's algorithm factors the RSA modulus on a CRQC."
	case strings.Contains(a, "ecdsa"), strings.Contains(a, "ecc"), strings.Contains(a, "1.2.840.10045.2.1"):
		if size == 0 {
			size = 256
		}
		return "ECDSA-P" + itoa(size), true, "critical", "Elliptic-curve discrete log solved by Shor's algorithm."
	case strings.Contains(a, "dsa"):
		return "DSA-" + itoa(size), true, "critical", "DSA is quantum-vulnerable (discrete log)."
	case strings.Contains(a, "ed25519"):
		return "Ed25519", true, "critical", "Edwards-curve signatures are quantum-vulnerable."
	default:
		if a == "" {
			return "unknown", false, "low", "Unclassified AD CS key."
		}
		return alg, false, "low", "Unclassified AD CS key algorithm."
	}
}

// parseCertutilCSV parses the CSV emitted by:
//
//	certutil -view -restrict "Disposition=20" \
//	  -out "CommonName,CertificateTemplate,PublicKeyAlgorithm,PublicKeyLength,NotAfter" csv
//
// It is OS-independent and unit-tested. Unknown/missing columns are tolerated.
func parseCertutilCSV(data string) []ADCSAsset {
	out := []ADCSAsset{}
	r := csv.NewReader(strings.NewReader(strings.TrimSpace(data)))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return out
	}
	// Build a header index (case-insensitive, spaces/punctuation stripped).
	idx := map[string]int{}
	for i, h := range rows[0] {
		idx[normHeader(h)] = i
	}
	get := func(row []string, keys ...string) string {
		for _, k := range keys {
			if i, ok := idx[k]; ok && i < len(row) {
				return strings.TrimSpace(row[i])
			}
		}
		return ""
	}
	for _, row := range rows[1:] {
		if len(row) == 0 {
			continue
		}
		alg := get(row, "publickeyalgorithm", "publickeyalgorithmname")
		if alg == "" {
			continue
		}
		size := atoi(get(row, "publickeylength", "publickeysize"))
		name := get(row, "commonname", "issuedcommonname", "subject")
		tmpl := get(row, "certificatetemplate", "certificatetemplatename", "template")
		if name == "" {
			name = tmpl
		}
		if name == "" {
			name = "AD CS certificate"
		}
		algo, vuln, risk, threat := classifyADCSAlgo(alg, size)
		out = append(out, ADCSAsset{
			Name:     name,
			Type:     "certificate",
			Algo:     algo,
			Size:     size,
			Vuln:     vuln,
			Risk:     risk,
			Threat:   threat,
			Template: tmpl,
			NotAfter: get(row, "notafter", "certificateexpirationdate", "certificateexpiration"),
		})
	}
	return out
}

func normHeader(h string) string {
	h = strings.ToLower(h)
	var b strings.Builder
	for _, c := range h {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		}
	}
	return b.String()
}
