package main

import "testing"

func TestParseCertutilCSV(t *testing.T) {
	// Representative certutil -view ... csv output.
	sample := `"Common Name","Certificate Template","Public Key Algorithm","Public Key Length","Not After"
"dc01.contoso.local","DomainController","RSA","2048","1/1/2027 10:00 AM"
"user@contoso.local","User","ECC","256","2/2/2027 10:00 AM"
"legacy.contoso.local","WebServer","RSA","4096","3/3/2027 10:00 AM"
"vpn.contoso.local","IPSec","1.2.840.10045.2.1","384","4/4/2027 10:00 AM"`

	assets := parseCertutilCSV(sample)
	if len(assets) != 4 {
		t.Fatalf("expected 4 assets, got %d", len(assets))
	}
	want := []struct {
		algo string
		vuln bool
		size int
	}{
		{"RSA-2048", true, 2048},
		{"ECDSA-P256", true, 256},
		{"RSA-4096", true, 4096},
		{"ECDSA-P384", true, 384},
	}
	for i, w := range want {
		if assets[i].Algo != w.algo || assets[i].Vuln != w.vuln || assets[i].Size != w.size {
			t.Errorf("row %d: got %s vuln=%v size=%d, want %s vuln=%v size=%d",
				i, assets[i].Algo, assets[i].Vuln, assets[i].Size, w.algo, w.vuln, w.size)
		}
	}
	if assets[0].Template != "DomainController" {
		t.Errorf("expected template DomainController, got %q", assets[0].Template)
	}
}

func TestClassifyADCSAlgo(t *testing.T) {
	cases := []struct {
		in   string
		size int
		algo string
		vuln bool
	}{
		{"RSA", 2048, "RSA-2048", true},
		{"ECC", 256, "ECDSA-P256", true},
		{"1.2.840.113549.1.1.1", 3072, "RSA-3072", true},
		{"", 0, "unknown", false},
	}
	for _, c := range cases {
		algo, vuln, _, _ := classifyADCSAlgo(c.in, c.size)
		if algo != c.algo || vuln != c.vuln {
			t.Errorf("classify(%q,%d): got %s/%v want %s/%v", c.in, c.size, algo, vuln, c.algo, c.vuln)
		}
	}
}
