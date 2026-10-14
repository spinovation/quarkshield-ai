package main

import (
	"strings"
	"testing"
)

// TestIsServerServicePkg guards the contract with the server-side Threat Graph R8
// rule (server/src/lib/threatGraph/topology.ts SERVICE_SIGNATURES): the agent must
// collect these OS-package names headlessly so the server can draw service/database
// nodes and classify the host as a server. If this drifts, R8 silently stops firing.
func TestIsServerServicePkg(t *testing.T) {
	match := []string{
		"openssh-server",
		"nginx", "nginx-core",
		"postgresql", "postgresql-16", "postgresql-server", "postgres",
		"mysql-server", "mariadb-server", "mariadb", "mysql-community-server",
		"mongodb-org-server", "mongodb-server", "mongod", "mongodb",
		"redis", "redis-server",
		"mssql-server",
		"elasticsearch", "opensearch",
		"httpd", "apache2",
		"NGINX", // case-insensitive
	}
	for _, name := range match {
		if !isServerServicePkg(name) {
			t.Errorf("expected %q to be recognized as a server-service package", name)
		}
	}

	noMatch := []string{
		"", "openssh-client", "libnginx-mod-http", "postgresql-client",
		"redis-tools", "python3", "coreutils", "vim",
	}
	for _, name := range noMatch {
		if isServerServicePkg(name) {
			t.Errorf("did not expect %q to be treated as a server-service package", name)
		}
	}
}

// TestCreatePkgAuditResultEcosystem ensures OS-package findings carry a canonical
// ecosystem token. The server only treats a package as a server service when its
// stored ecosystem is in SERVER_ECOSYSTEMS (os_pkg/deb/rpm/apk/brew/chocolatey/winget);
// the previous descriptive strings ("dpkg (Debian/Ubuntu)", ...) never matched.
func TestCreatePkgAuditResultEcosystem(t *testing.T) {
	serverEcosystems := map[string]bool{
		"os_pkg": true, "deb": true, "rpm": true, "apk": true,
		"brew": true, "chocolatey": true, "winget": true,
	}
	res := createPkgAuditResult("openssh-server", "1:9.6p1-3", "deb", "/var/lib/dpkg/info/openssh-server")
	if !serverEcosystems[res.Ecosystem] {
		t.Fatalf("ecosystem %q is not a server-recognized token", res.Ecosystem)
	}
	if res.Type != "package" {
		t.Errorf("expected type 'package', got %q", res.Type)
	}
	if !strings.HasPrefix(res.Purl, "pkg:deb/openssh-server@") {
		t.Errorf("expected canonical purl, got %q", res.Purl)
	}
}
