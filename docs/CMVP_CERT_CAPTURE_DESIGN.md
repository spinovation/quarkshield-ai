# CMVP Certificate Capture — Design Note

**Status:** Scoped (not built) · **Author:** QuarkShield · **Date:** 2026-11-07
**Related:** [CRYPTO_USAGE_DEPENDENCY_MAP_AND_IMPACT_ANALYSIS.md](CRYPTO_USAGE_DEPENDENCY_MAP_AND_IMPACT_ANALYSIS.md)

## 1. Problem

A CBOM today documents, per asset: cryptographic **asset** (type/name/path),
**algorithm**, **key size**, and **hash algorithm** (`AuditResult`, `agent/auditor.go:17`).
It does **not** record the **CMVP validation certificate** of the *module* that provides
the cryptography. Federal buyers (GSA PQC RFI, Army TCS-PSS) increasingly ask for the
underlying **FIPS 140-2/140-3 CMVP certificate number** — i.e. "which *validated module*
is actually performing this AES/RSA/ECDSA operation, and is that validation current?"

Algorithm ≠ validation. OpenSSL 3.x can run AES-256 in a FIPS-validated provider
(Cert #4282-class) **or** in a non-validated build. The CBOM must say which.

## 2. What already exists (reuse, don't rebuild)

- **Module fingerprinting.** The SBOM path already resolves module **name + version**:
  OpenSSL via version regex → PURL (`agent/sbom_scanner.go:150`, `pkg:generic/openssl@<ver>`),
  Windows Schannel providers (`agent/windows_store.go`), AD CS (`agent/adcs*.go`).
- **Per-asset record** with a stable JSON contract and an existing free-text
  `ComplianceViolations []string`.
- **Server CBOM ingest + console render** keyed on the asset record.

The correlation layer is the only genuinely new work.

## 3. Design

### 3.1 Data model — new optional fields on `AuditResult`

```go
// FIPS module validation (CMVP). All optional; absent ⇒ "not determined".
ModuleName     string `json:"moduleName,omitempty"`     // e.g. "OpenSSL FIPS Provider"
ModuleVersion  string `json:"moduleVersion,omitempty"`  // e.g. "3.0.8"
CmvpCertId     string `json:"cmvpCertId,omitempty"`     // e.g. "4282"
CmvpStatus     string `json:"cmvpStatus,omitempty"`     // active | historical | revoked | none | unverified
FipsLevel      string `json:"fipsLevel,omitempty"`      // "140-2" | "140-3"
```

Additive and `omitempty` → backward-compatible with the current agent/console contract
and the QSG `posture:read` token consumers. No migration risk for existing rows.

### 3.2 Correlation source — a bundled CMVP map

NIST publishes the CMVP Validated Modules List. We ship a **vendored, versioned
lookup file** (`agent/data/cmvp_modules.json`) rather than calling NIST at scan time
(air-gapped scans must work; no scan-time network dependency).

```jsonc
{
  "source": "NIST CMVP Validated Modules List",
  "generated": "2026-11-07",
  "modules": [
    { "match": {"name": "openssl", "versionRange": ">=3.0.0 <3.1.0", "provider": "fips"},
      "certId": "4282", "fipsLevel": "140-2", "status": "active" }
  ]
}
```

Match precedence: exact module+version+provider → version-range → name-only (⇒
`cmvpStatus: "unverified"`, never a guessed cert id).

### 3.3 Resolution logic (`agent/cmvp.go`, new)

```
resolveCMVP(moduleName, moduleVersion, providerHint) -> (certId, status, fipsLevel)
```

1. If no module resolved for the asset → `CmvpStatus = "none"` (e.g. a raw PEM key file
   has no owning validated module).
2. Look up the fingerprint in the bundled map.
3. **Provider gate** (critical, avoids false "validated" claims): a module is only
   `active`/`historical` if it is actually invoked in FIPS mode. Where detectable
   (OpenSSL `fips=yes` provider, CNG FIPS policy flag) set accordingly; otherwise
   `unverified` — "a validated module exists for this version, but FIPS mode was not
   confirmed on this host."

### 3.4 Server + console

- Ingest stores the five fields on the asset row (nullable columns, `ADD COLUMN IF
  NOT EXISTS` via the deploy.sh server-side SQL step — same pattern as DEF-48).
- CBOM export surfaces `cmvpCertId` / `cmvpStatus`.
- Console asset row: a small badge — `CMVP #4282 (active)` / `No FIPS validation` /
  `Validated module, FIPS mode unconfirmed`.

## 4. Honesty constraints (non-negotiable)

- **Never emit a cert id without a version+provider match.** Name-only ⇒ `unverified`.
- **"Validated module present" ≠ "operating in validated mode."** The provider gate
  keeps these distinct; the console wording must too.
- Absent data renders as **"not determined,"** never as pass/fail.

## 5. Scope / effort

| Item | Effort |
|---|---|
| `AuditResult` fields + JSON | XS |
| Bundled `cmvp_modules.json` (seed: OpenSSL, BoringCrypto, CNG/BCrypt, wolfSSL, common HSMs) | M (data curation) |
| `agent/cmvp.go` resolver + provider gate | S |
| Wire into sbom_scanner / store paths | S |
| Server columns + CBOM export + console badge | S |
| Map refresh job (periodic NIST re-vendor) | S |

**Out of scope (v1):** live NIST API calls at scan time; validating HSM firmware certs;
CAVP algorithm-cert (vs CMVP module-cert) correlation — a later extension.

## 6. RFP-safe statement once shipped

> "QuarkShield documents every cryptographic asset, algorithm, and key size, and
> correlates the providing module to its NIST CMVP validation certificate — reporting
> the certificate number and whether the module is operating in a validated FIPS mode,
> or flagging where no current validation applies."

Until shipped, the honest line is: **asset + algorithm + key size are captured today;
CMVP certificate correlation is near-term roadmap (this note).**
