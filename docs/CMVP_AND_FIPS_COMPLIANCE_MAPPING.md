# 🔏 QuarkShield — CMVP & FIPS Compliance Mapping
**Feature Design & Scoping Specification**
**Status: 🟡 ROADMAP / OPPORTUNITY — not shipped. This document designs a capability; it does not describe current behavior unless a section is explicitly marked "Today."**
**Owner: Platform / Scanner Engineering · Drafted: 2026-11-13 · NIST refs: FIPS 140-2 / 140-3 (CMVP), SP 800-131A Rev. 2, FIPS 203 (ML-KEM) / 204 (ML-DSA) / 205 (SLH-DSA), SP 800-140-series, NSA CNSA 2.0**

---

## 0. Provenance — why this, why now

Two distinct federal questions keep arriving on the same opportunities (GSA FAS "PQC Readiness & Validation" RFI; Army TCS-PSS CSO; FDA/CDRH PQC research), and QuarkShield today answers neither in a structured, attestable way:

1. **"Is this algorithm FIPS-approved, and for how much longer?"** — a statement about the *algorithm and its parameters* against **SP 800-131A Rev. 2** transitions (RSA/ECDSA/SHA key-size deprecations) and the new PQC standards **FIPS 203/204/205**.
2. **"Is the cryptography actually performed by a CMVP-*validated module* — cert #, vendor, and is that validation still Active?"** — a statement about the *module*, against **FIPS 140-2/140-3** and the NIST **Cryptographic Module Validation Program (CMVP)** Validated Modules List.

These are **different claims**, and conflating them is the single most common compliance error in the inventory market. AES-256 is a FIPS-approved algorithm *always*; whether a given host runs it inside **CMVP cert #4282**-class OpenSSL FIPS provider, inside a non-validated build, or inside a module whose validation has moved to **Historical**, is a separate fact that only module correlation can establish. A buyer who needs "FIPS 140-3 validated" cannot accept "uses AES-256" as the answer.

A sibling design note, [`CMVP_CERT_CAPTURE_DESIGN.md`](CMVP_CERT_CAPTURE_DESIGN.md) (commit `15cdd2a`, 2026-11-07), already scopes the **collection plumbing** for claim (2): optional `AuditResult` module fields, a vendored `cmvp_modules.json`, an agent-side resolver with a provider gate, and server columns + a console badge. **This document does not redo that work.** It designs the **compliance-mapping and reporting layer** that sits on top of it: the structured FIPS-approval taxonomy for claim (1), the reference data and refresh strategy behind both claims, the two-axis compliance model that keeps "approved algorithm" and "validated module" distinct, and how the combined posture surfaces in the roadmap engine, CBOM, console, and an attestation export — with entitlement gating. §2 states the boundary between the two docs precisely.

This also complements — does not replace — the functional-triage work in [`PQC_FUNCTIONAL_ANALYSIS_AND_REMEDIATION.md`](PQC_FUNCTIONAL_ANALYSIS_AND_REMEDIATION.md) (*what kind of problem is this algorithm — HNDL vs forgery?*) and the dependency/size work in [`CRYPTO_USAGE_DEPENDENCY_MAP_AND_IMPACT_ANALYSIS.md`](CRYPTO_USAGE_DEPENDENCY_MAP_AND_IMPACT_ANALYSIS.md) (*what breaks if I rotate it?*). Those answer *threat urgency* and *blast radius*. **This** doc answers *compliance standing*: **approved? validated? still current? by whose certificate?**

---

## 1. What QuarkShield has Today (verified in code)

| Capability | Where | What it gives us |
| :--- | :--- | :--- |
| **Per-asset algorithm + key size + hash** | `assets` table `CREATE` at `server/src/models/schema.sql:34-50` (`algorithm`, `key_size`, `hash_algorithm`); agent `AuditResult` at `agent/auditor.go:16-44` | The raw material a FIPS-approval verdict is computed *from* — but no FIPS-approval field and no transition/sunset date. |
| **Free-text compliance labels** | `assets.compliance_violations TEXT[]` (`schema.sql:34-50`); populated as string arrays at `agent/auditor.go:523`, `agent/windows_store.go:152`, `agent/linux_store.go:309,487`, `agent/macos_store.go:147-157`, and server-side `fleetController.ts:843`, `gitScanController.ts:218` | Strings like `"NIST FIPS 203 (ML-KEM)"`, `"NIST SP 800-131A"`, `"FIPS 140-3"`. **Human-readable, not queryable:** no enum, no status, no cert id, no CHECK constraint — you cannot `WHERE fips_status = 'disallowed'`. |
| **Crypto *purpose* taxonomy** | `CryptoPurpose` enum `server/src/lib/threatGraph/types.ts:186-189`; `PURPOSE_META` with per-purpose NIST `standard` at `server/src/lib/roadmapReport.ts:51-60` | Every finding maps to a dominant NIST *target* standard (e.g. key establishment → `FIPS 203 (ML-KEM)`). This is the **target**, not the **current approval status** of what's deployed. |
| **Remediation-by-family NIST refs** | `REMEDIATION_BY_FAMILY` at `server/src/lib/roadmapReport.ts:151-160` (`standard` field: `'NIST SP 800-131A'`, `'NIST FIPS 203 / 204'`, `'NIST FIPS 180-4 / 202'`, …) | Per-family target standards in the roadmap — again the destination, not a structured source-approval verdict. |
| **CBOM `nistQuantumSecurityLevel`** | `server/src/lib/cyclonedx.ts:61` `nqsl = isVulnerable ? 0 : 3`; emitted at `cyclonedx.ts:84,94,101` | A CycloneDX 1.6 field is already populated — but **crudely binary** off `isVulnerable`, not derived from FIPS approval or parameter set. A FIPS-aware mapping is a direct, concrete upgrade (§6.3). |
| **Deterministic roadmap + exec report** | `RoadmapReport` interface `roadmapReport.ts:99-111`; `buildRoadmapReport()` aggregates purpose + migration friction | The surface a compliance-posture rollup plugs into, with the same no-invented-numbers discipline. |
| **Module name + version fingerprinting** | OpenSSL version regex → PURL `agent/sbom_scanner.go:150-162` (`pkg:generic/openssl@<ver>`); Windows/AD CS store scanners | The input key for CMVP module lookup. (The correlation itself is scoped in `CMVP_CERT_CAPTURE_DESIGN.md`, not built.) |
| **Entitlement + service-token plumbing** | `RISK_ASSURANCE_ADDON` / `requireRiskAssuranceEntitlement` `server/src/middleware/auth.ts:398,543`; `QSG_ADDON` `:402`; service-token scope `posture:read` `server/src/middleware/serviceToken.ts:29` | The gate this capability inherits (§7). |

### 1.1 The honest gaps

1. **No structured FIPS-approval status.** `compliance_violations` is a free-text `TEXT[]`. There is no column that says, per asset, *approved / deprecated / restricted / disallowed / legacy-use-only* against **SP 800-131A Rev. 2**, and no **sunset/transition date** (e.g. "RSA-2048 signature generation disallowed after 2030-12-31"). Reporting cannot aggregate it, and the roadmap cannot order by *regulatory deadline* — only by quantum risk.
2. **No approved-vs-validated distinction.** Nothing in the schema expresses the central two-axis fact: an *approved algorithm* may or may not be running in a *validated module*. The `CMVP_CERT_CAPTURE_DESIGN.md` fields capture the module side; there is no field pairing it with the algorithm-approval side into a single compliance verdict.
3. **No reference data for either axis.** There is no bundled SP 800-131A transition table and no bundled CMVP validated-modules map in the repo today. Both must be vendored, versioned, and refreshed (§5).
4. **`nistQuantumSecurityLevel` is misleadingly derived.** `cyclonedx.ts:61` sets it to `0`/`3` purely from `isVulnerable` — an auditor reading the CBOM may over- or under-read it. It should reflect the FIPS parameter set, or be omitted where unknown.

---

## 2. Boundary with the CMVP certificate-capture note (no duplication)

| Concern | `CMVP_CERT_CAPTURE_DESIGN.md` (commit `15cdd2a`) | **This document** |
| :--- | :--- | :--- |
| Get the providing module's **cert #** onto an asset row | ✅ owns it: `AuditResult.{ModuleName,ModuleVersion,CmvpCertId,CmvpStatus,FipsLevel}`, agent `cmvp.go` resolver, provider gate, ingest columns, console badge | consumes these fields; does not redefine them |
| **FIPS *algorithm* approval** (SP 800-131A, FIPS 203/204/205) as a structured status + sunset date | — out of scope there | ✅ owns it: `fips_status`, `fips_standard`, `transition_date` |
| **Two-axis compliance verdict** (approved-algorithm × validated-module) | — | ✅ owns it: the 2×2 model + derived `compliance_verdict` |
| **Reference data** (SP 800-131A transition table; CMVP list sourcing/refresh) | mentions a vendored `cmvp_modules.json` for the module side | ✅ owns the *data strategy* for both tables: source, format, versioning, refresh job, air-gap posture |
| **Reporting / attestation surface** (roadmap rollup, CBOM upgrade, console compliance view, FIPS attestation export) | console badge per asset only | ✅ owns the aggregate posture, report sections, CBOM `nistQuantumSecurityLevel` fix, attestation export |
| **Entitlement gating** | — | ✅ defines it |

**Rule of thumb:** the capture note answers *"which validated module, if any, performs this operation?"* for one asset. This doc answers *"what is the fleet's FIPS compliance posture, and is each algorithm both approved and validated — with the certificate and the deadline?"* The capture note is a **dependency** of this doc's module axis; its fields are reused verbatim, never re-specified.

---

## 3. Feature definition

Two compliance axes, resolved per finding and rolled up per scope:

- **A1 — FIPS Algorithm Compliance (algorithm axis).** Map each finding's `algorithm` + `key_size` + `purpose` to a structured **FIPS-approval status** against SP 800-131A Rev. 2 and FIPS 203/204/205, with the governing standard and the **transition/sunset date**. Answers: *approved · acceptable-until-\<date\> · restricted · disallowed · post-quantum-approved · non-FIPS*.
- **A2 — CMVP Module Validation (module axis).** Using the module fields captured per `CMVP_CERT_CAPTURE_DESIGN.md`, map each finding to a **validated module**: cert #, module name/vendor, validation status (**Active / Historical / Revoked / none / unverified**), FIPS level (140-2/140-3), and sunset/transition date. Answers: *performed by a validated module, operating in validated mode?*

The product of the two axes is a single, honest **compliance verdict** (§4.2) that a federal buyer can read directly:

> *"Approved algorithm (ML-KEM-768, FIPS 203), performed by CMVP cert #4986 (Active, FIPS 140-3) — fully compliant."*
> *"Approved algorithm (AES-256), but no validated module confirmed on this host — approved-but-unvalidated."*
> *"RSA-2048 signature generation — disallowed after 2030-12-31 under SP 800-131A Rev. 2 — remediate."*

Both axes **reuse the existing `assets` row and the deterministic roadmap engine**; no parallel store.

### 3.1 Prerequisites to capture a CMVP certificate

A CMVP certificate is **not** a property of any artifact QuarkShield discovers today (a cert file, a PEM key, a TLS endpoint, an SBOM package). It is a property of the **cryptographic module** — the library/build — that *performs* the operation. `RTC.der` tells us "RSA-2048"; it tells us nothing about whether OpenSSL, Windows CNG, BoringCrypto, or an HSM generated or uses that key, and only that module can carry a cert #. So the prerequisite is **observing the module, not the artifact** — the capability QuarkShield mostly lacks today. Five pillars, all required before a cert # can be honestly asserted:

| # | Prerequisite | What it means | Today (verified) | Build |
| :-- | :--- | :--- | :--- | :--- |
| **P-a** | **Module identity: library + exact version + operating environment** | A CMVP validation is scoped to a *specific module version on a specific tested platform* (e.g. "OpenSSL FIPS Provider 3.0.0, cert #4282, tested on RHEL 8 / x86-64"). All three are needed to name a cert. | Partial, **package-level only**: OpenSSL version→PURL `agent/sbom_scanner.go:150-162`; Windows Schannel / AD CS scanners. **Not linked to the asset that uses it.** | **Largest item.** Resolve a providing module per finding, with OS/arch/platform as the operating environment. |
| **P-b** | **FIPS-mode confirmation (the "provider gate")** | A validated module being *installed* ≠ the crypto *running through it in approved mode*. Must detect the module is selected and active: OpenSSL `fips` provider loaded (`fips=yes`) + `fipsmodule.cnf` wired; Windows CNG FIPS policy flag + self-test; Java BC-FIPS approved-only. | **None.** Only a crypto-policy *recommendation* exists (`agent/linux_store.go:301`). No FIPS-mode state is read. | Agent probes per platform. Absent → status `unverified`, never `active`. |
| **P-c** | **Reference data: NIST CMVP validated-modules list** | Versioned map (module name, version, environment) → cert #, vendor, **status (Active / Historical / Revoked)**, sunset date. | **Not in repo.** Scoped as `agent/data/cmvp_modules.json` in the capture note; no file committed. | Vendored, offline-refreshed, air-gap-safe, `version`-stamped (§5.2). |
| **P-d** | **Correlation logic + honesty gate** | Match precedence: exact module+version+environment+provider → version-range → name-only ⇒ `unverified`, **never a guessed cert id**; carry confidence + evidence. | — | `agent/cmvp.go` resolver (capture note). |
| **P-e** | **Transport** | Optional `AuditResult` fields (ModuleName/ModuleVersion/CmvpCertId/CmvpStatus/FipsLevel) → ingest → columns → report. | `AuditResult` has no module fields (`agent/auditor.go:16-44`). | Additive fields + columns (capture note + §7.1). |

**The honest caveat (state it to buyers):** for many discovered assets **there is no providing module to find** — a lone cert file, a PEM private key, an SSH key are *data*, not running modules. Real CMVP correlation is only strong where QuarkShield can see the module, in descending order of confidence and ascending order of effort:

1. **KMS/HSM connectors** — AWS KMS FIPS endpoints, CloudHSM, Luna, nShield publish their *own* CMVP certs; the connector reports them with little inference. `pkiConnectorController.ts:43,106` already tracks provider type and today captures **no module metadata** — the **lowest-effort, highest-confidence** path.
2. **Agent host scans** — library present on the box (strongest for endpoints, needs P-a + P-b).
3. **SBOM/package scans** — version-only, usually `unverified`.

Everywhere else the correct, non-overclaiming value is `cmvp_status = none` ("no owning validated module observed") — itself a reportable compliance fact, not a blank.

### 3.2 CAVP extension — the algorithm-implementation layer (A2′)

CMVP and **CAVP** (Cryptographic Algorithm Validation Program) are distinct and must never be conflated:

- **CMVP (A2, this spec)** validates a **module** → one cert # per module/version/environment.
- **CAVP (A2′, extension)** validates a **single algorithm implementation** (e.g. "AES-256-GCM, cert #A1234") against the NIST test vectors (ACVP). A CMVP module cert **bundles** the CAVP algorithm certs of every algorithm it was validated for.

Why the extension is worth having: a module can be CMVP-validated yet the *specific algorithm or mode* an asset uses may not be on that module's CAVP list (e.g. a validated module that never had SHA-3 or a particular curve tested). CAVP correlation lets QuarkShield answer the sharper question *"is the exact algorithm + mode this asset uses covered by the module's validation?"* — the difference between "the module is validated" and "**this operation** is validated."

Design: additive, layered on A2, **never blocking the CMVP verdict**.
- Each `cmvp_modules.json` entry gains an optional `cavpAlgorithms: [{algo, mode, certId}]` list (populated from the module's CAVP references on the CMVP record).
- A1's resolved algorithm+mode is checked against that list → a sub-status `cavp_covered ∈ {covered, not_covered, unknown}`.
- Surfaces as a refinement on the verdict: `compliant` (CMVP active **and** `cavp_covered`) vs `compliant_module_algo_unverified` (module validated, this algorithm not confirmed on its CAVP list).
- **Data source:** the NIST CAVP Algorithm Validation lists, vendored alongside the CMVP map and refreshed by the same offline job (§5.2).
- **Honesty:** absent CAVP data ⇒ `cavp_covered = unknown`, which **does not downgrade** a CMVP `compliant` verdict — it only adds precision when present. CAVP is additive evidence, never a new failure mode invented from missing data.

CAVP is the **last** stage of the roadmap (§9, Stage 6): it has no value until CMVP module capture (P-a…P-e) exists to attach it to.

---

## 4. The two-axis compliance model

### 4.1 Axis A1 — FIPS algorithm status (deterministic, from a versioned table)

A pure resolver `fipsAlgorithmStatus({algorithm, keySize, purpose, hashAlgorithm})` → `{ fipsStatus, fipsStandard, transitionDate?, rationale }`, driven by a **versioned reference constant** (§5.1), never AI-invented — same philosophy as `roadmapReport.ts`.

| `fips_status` | Meaning | Examples (SP 800-131A Rev. 2 / FIPS 203-205) |
| :--- | :--- | :--- |
| `approved` | FIPS-approved, no near-term sunset | AES-256, SHA-256/384, RSA-3072+ (where permitted), ECDSA P-384 |
| `pq_approved` | Approved PQC standard | ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) |
| `acceptable` | Approved but with a published sunset — carries `transition_date` | RSA-2048 / ECDSA P-256 signature use pending 112-bit-strength transitions |
| `restricted` | Legacy/verification-only or constrained use | SHA-1 (verification of legacy signatures only); 3DES (decrypt-only legacy) |
| `disallowed` | Not approved for the detected use | RSA < 2048; SHA-1 for signature *generation*; MD5; DES; 1024-bit DH |
| `non_fips` | Not a FIPS-approved algorithm at all | non-NIST curves, proprietary ciphers |
| `unknown` | Cannot classify (unparsed/ambiguous) | renders as "not determined," never pass/fail |

`transition_date` makes the roadmap orderable by **regulatory deadline**, not only quantum risk — the dimension §6.1 adds to the Mosca verdict.

### 4.2 Axis A2 × A1 → `compliance_verdict`

The capture note supplies `cmvp_status ∈ {active, historical, revoked, none, unverified}`. Crossed with `fips_status`, a small deterministic table yields the verdict shown to the buyer:

| algorithm (A1) ↓ \ module (A2) → | `active` | `historical` | `revoked` | `none` / `unverified` |
| :--- | :--- | :--- | :--- | :--- |
| `approved` / `pq_approved` | **compliant** | **validated_sunsetting** | **validated_revoked** | **approved_unvalidated** |
| `acceptable` (has sunset) | **compliant_until** | **validated_sunsetting** | **validated_revoked** | **approved_unvalidated** |
| `restricted` | **restricted_use** | restricted_use | restricted_use | restricted_use |
| `disallowed` / `non_fips` | **noncompliant** | noncompliant | noncompliant | **noncompliant** |
| `unknown` | **not_determined** | not_determined | not_determined | **not_determined** |

The three verdicts federal reviewers care about most and that no "list of algorithms" can produce:
- **`approved_unvalidated`** — the approved algorithm is *not* confirmed to run in a validated module. This is the gap the task calls out and the one most inventories silently pass.
- **`validated_sunsetting` / `validated_revoked`** — a module cert that has moved to Historical/Revoked; still "validated" on paper, no longer current.
- **`compliant_until <date>`** — approved today, with a hard SP 800-131A deadline.

**Honesty constraint (non-negotiable, inherited from the capture note):** a module match is only `active`/`historical` when FIPS mode is actually confirmed by the provider gate; otherwise `unverified` → verdict `approved_unvalidated`, never `compliant`. Absent data is `not_determined`, never a pass or a fail.

---

## 5. Reference data — sourcing, format, refresh

Two vendored, versioned tables ship with the product. **Neither is queried at scan time** (air-gapped fleets must work — same constraint as `CMVP_CERT_CAPTURE_DESIGN.md`). Both are refreshed by an offline job and committed as data.

### 5.1 SP 800-131A transition table (`server/src/data/fips_algorithm_status.json`)

Hand-curated from SP 800-131A Rev. 2 and the FIPS 203/204/205 final standards — small, slow-moving, high-trust. Matched by algorithm family + key-size range + use (signature-gen vs verify vs key-transport, keyed off `CryptoPurpose`).

```jsonc
{
  "source": "NIST SP 800-131A Rev. 2; FIPS 203/204/205",
  "version": "2026-11-13",
  "rules": [
    { "match": {"family": "RSA", "use": "signature_generation", "minBits": 2048, "maxBits": 3071},
      "status": "acceptable", "standard": "SP 800-131A Rev. 2", "transitionDate": "2030-12-31" },
    { "match": {"family": "RSA", "maxBits": 2047},
      "status": "disallowed", "standard": "SP 800-131A Rev. 2" },
    { "match": {"family": "SHA-1", "use": "signature_generation"},
      "status": "disallowed", "standard": "SP 800-131A Rev. 2" },
    { "match": {"family": "ML-KEM"}, "status": "pq_approved", "standard": "FIPS 203" },
    { "match": {"family": "ML-DSA"}, "status": "pq_approved", "standard": "FIPS 204" },
    { "match": {"family": "SLH-DSA"}, "status": "pq_approved", "standard": "FIPS 205" }
  ]
}
```

*Dates are illustrative of the schema; the committed table carries the exact published transition dates and is reviewed on each NIST revision.*

### 5.2 CMVP validated-modules map (owned by `CMVP_CERT_CAPTURE_DESIGN.md`)

The module-match file (`agent/data/cmvp_modules.json`) is defined there. This doc adds only the **data-sourcing and refresh policy** that both axes share:

- **Source:** the NIST CMVP **Validated Modules Search** (csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules). The validated list and the "modules in process" / "implementation under test" lists are published and exportable.
- **Refresh:** an **offline re-vendor job** (not scan-time) fetches the current list, diffs cert status (Active→Historical→Revoked transitions, new sunset dates), regenerates the JSON with a `version` date, and opens a PR. Cadence: monthly, or on a known transition event. The agent and server ship whatever version was committed; the console shows the `version` so a stale map is visible, never silent.
- **Air-gap:** because resolution is against the vendored file, an isolated fleet gets correct answers for the map version it was given, with an explicit "map as of \<date\>" provenance line.

---

## 6. How a finding becomes a verdict (evidence trail)

```
asset row (algorithm, key_size, hash, purpose)
   │
   ├── A1: fipsAlgorithmStatus() ──▶ {fips_status, fips_standard, transition_date}
   │        (server-side, from fips_algorithm_status.json)
   │
   ├── A2: module fields from CMVP_CERT_CAPTURE_DESIGN.md
   │        {cmvp_cert_id, cmvp_status, fips_level}  (agent resolver + provider gate)
   │
   └── crossProduct(A1, A2) ──▶ compliance_verdict  (+ confidence from A2's provider gate)
```

Every verdict carries **provenance**: the SP 800-131A rule id that fired, the CMVP map `version`, and the A2 confidence (`measured` FIPS-mode vs `unverified`). The same discipline the graph enforces (`TrRelationship.confidence/evidence`) — an *unverified* module must never render as *validated*.

### 6.1 Into `roadmapReport.ts`

`buildRoadmapReport()` (interface at `roadmapReport.ts:99-111`) gains a **`fipsCompliance`** block, data-derived like `purposeBreakdown`/`migrationFriction`:

```ts
fipsCompliance: {
  total: number;
  byVerdict: Record<ComplianceVerdict, number>;   // compliant / approved_unvalidated / noncompliant / compliant_until / …
  disallowedNow: number;                           // SP 800-131A disallowed — act regardless of quantum timeline
  sunsetting: { algo: string; transitionDate: string; count: number }[];  // orderable by deadline
  approvedUnvalidated: number;                     // the headline "uses it but can't prove validation" count
  cmvpMapVersion: string;                          // provenance
}
```

- **A new ordering dimension:** a `disallowed`/`compliant_until` finding gets a deadline-aware priority bump, so a regulatory sunset can outrank a lower quantum risk. Still deterministic.
- **Mosca refinement:** today Mosca is quantum X+Y>Z. Add a *compliance-now* overlay — "N algorithms are already disallowed under SP 800-131A regardless of CRQC timing" — the fact buyers act on first.
- **Exec report** gains a **"FIPS & CMVP Compliance Posture"** section (HTML/PDF/DOCX via `reportController.ts`), mirroring how `purposeBreakdown` is rendered.

### 6.2 Console / UI

- Per-asset **compliance verdict chip** beside the existing CMVP badge from the capture note: `Compliant · CMVP #4986 (Active)` / `Approved algorithm — no validated module` / `Disallowed after 2030-12-31`.
- A scope-level **compliance posture tile**: `% from validated modules · # approved-but-unvalidated · # disallowed-now`, alongside existing posture tiles.
- A filter: *show only `approved_unvalidated`* / *`noncompliant`* — the queryable view the free-text array can't give today.

### 6.3 CBOM / CycloneDX (fix the crude `nqsl`)

- Replace the binary `nqsl` (`cyclonedx.ts:61`) with a FIPS-parameter-aware mapping: emit `nistQuantumSecurityLevel` from the actual FIPS 203/204/205 **security category** when known (ML-KEM-768 → cat 3, ML-KEM-1024 → cat 5, …), and **omit** it where unknown rather than asserting `0`/`3`.
- Add CycloneDX crypto `properties`: `quarkshield:fipsStatus`, `quarkshield:fipsStandard`, `quarkshield:transitionDate`, `quarkshield:cmvpCertId`, `quarkshield:cmvpStatus`, `quarkshield:complianceVerdict` — so the compliance mapping is portable in the standard artifact, not QuarkShield-only.

### 6.4 FIPS attestation export (new, gated)

A one-click **FIPS/CMVP Compliance Attestation** (PDF/CSV): per-asset algorithm, FIPS status + standard, transition date, module name/vendor, CMVP cert #, validation status, and verdict — with the SP 800-131A table version and CMVP map version stamped on it. This is the artifact that answers a GSA/Army/FDA "provide your FIPS 140-3 validation evidence" ask directly. Gated per §7.

---

## 7. Data model (additive, back-compatible)

Design principle: **extend, don't fork** — same as the sibling specs and the DEF-48 `ADD COLUMN IF NOT EXISTS` pattern already in `schema.sql:54-63`.

### 7.1 `assets` columns (nullable ALTERs — existing rows + ingest unaffected)

```sql
-- server/src/models/schema.sql (append). Module columns (cmvp_*) are OWNED by
-- CMVP_CERT_CAPTURE_DESIGN.md; listed here only to show the full verdict input.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS fips_status        VARCHAR(24);  -- A1: approved|pq_approved|acceptable|restricted|disallowed|non_fips|unknown
ALTER TABLE assets ADD COLUMN IF NOT EXISTS fips_standard      VARCHAR(40);  -- 'SP 800-131A Rev. 2' | 'FIPS 203' | …
ALTER TABLE assets ADD COLUMN IF NOT EXISTS fips_transition_date DATE;       -- NULL unless a published sunset applies
ALTER TABLE assets ADD COLUMN IF NOT EXISTS compliance_verdict VARCHAR(28);  -- derived (§4.2); recomputed at ingest/report time
-- cmvp_cert_id / cmvp_status / fips_level: see CMVP_CERT_CAPTURE_DESIGN.md (do not re-add here if that note lands first)
CREATE INDEX IF NOT EXISTS idx_assets_fips_status ON assets(fips_status);
CREATE INDEX IF NOT EXISTS idx_assets_compliance_verdict ON assets(compliance_verdict);
```

A1 is **server-computed at ingest** from the vendored table (no agent change, unlike A2). `compliance_verdict` is derived and safe to recompute on report; it is persisted for the queryable console filter. Legacy rows stay `NULL` → render "not determined" until re-scanned. Mirrors the `purpose`-column rollout (`schema.sql:63`, populated at every ingest site).

### 7.2 No new table

A1 is per-asset and lives on the row. The scope-level rollup (§6.1) is computed on demand in `roadmapReport.ts`, exactly like `purposeBreakdown`/`migrationFriction` — no new persistence.

---

## 8. Entitlement gating

- **Core / teaser (all plans):** the per-asset `fips_status` chip and the scope-level **counts** (`# disallowed-now`, `# approved_unvalidated`). This is a strong top-of-funnel hook and cheap to compute — it should not sit behind the add-on.
- **`risk_assurance` add-on** (`requireRiskAssuranceEntitlement`, `auth.ts:543`): the full compliance posture view, the per-asset module correlation drill-down, and the **FIPS attestation export** (§6.4). Same gate as the Risk Graph / blast-radius features.
- **QSG `posture:read` service token** (`serviceToken.ts:29`): the aggregate verdict counts are additive, backward-compatible JSON fields on the existing posture payload — QSG consumers that read `/api/fleet/cbom` keep working; new fields are `omitempty`/nullable, consistent with the capture note's contract promise.

Recommendation: **counts are core; the attestation + drill-down are the upsell** — same split the dependency-map spec recommends for "what-breaks."

---

## 9. Implementation roadmap — CMVP, then CAVP, step by step

Ordered so that **RFP-citable value ships before the hardest collection work**, and the module axis is built cheapest-first. Each stage has a clear exit criterion; a stage is "done" only when a buyer-facing fact is true and demo-safe. Stages 1–2 are server-only (no agent rebuild); Stages 3–6 need agent/connector work.

### 9.1 The six stages

| Stage | Goal (buyer-facing exit criterion) | Builds | Prereq | Effort | Agent rebuild? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1 — Algorithm axis (A1)** | *"N algorithms are disallowed under SP 800-131A today; M are approved but sunset by \<date\>."* Visible to every tenant. | Vendor `fips_algorithm_status.json` (§5.1); pure `fipsAlgorithmStatus()` + DB-free tests; `fips_status`/`fips_standard`/`fips_transition_date` columns computed at every ingest site; per-asset chip + core counts tile (ungated); deadline-aware roadmap ordering (§6.1). | §5.1, §7.1 | **M** | No |
| **2 — CBOM honesty fix** | CBOM `nistQuantumSecurityLevel` reflects the real FIPS parameter set (or is omitted), plus `quarkshield:fipsStatus`/`fipsStandard`/`transitionDate` properties. | Replace `cyclonedx.ts:61` binary `nqsl`; add crypto properties (§6.3). | Stage 1 | **S** | No |
| **3 — CMVP via connectors (A2, cheapest/highest-confidence)** | *"This KMS/HSM-backed key is performed by CMVP cert #\<n\> (Active, FIPS 140-3)."* | Vendor `cmvp_modules.json` (§5.2) + offline refresh job; teach KMS/HSM connectors (`pkiConnectorController.ts`) to report module name/vendor/cert for AWS KMS FIPS, CloudHSM, Luna, nShield; populate `cmvp_*` fields on those assets. Prereqs **P-c, P-d, P-e**. | Stages 1, §3.1 | **M** (data curation) | No (connector-side) |
| **4 — CMVP module identity on hosts (A2, P-a)** | *"OpenSSL FIPS Provider 3.0.0 on this host → cert #4282 (environment: RHEL 8 / x86-64)."* | Agent resolves providing module + version + operating environment per finding (extend `sbom_scanner.go` fingerprinting and tie it to the asset); new `AuditResult` module fields; `agent/cmvp.go` resolver with match-precedence gate. | Stage 3 | **M–L** | **Yes** |
| **5 — Verdict + posture view + FIPS-mode gate (A2, P-b)** | *"Approved algorithm **and** validated module in confirmed FIPS mode → compliant"* vs `approved_unvalidated`. Full posture view + filters (gated); FIPS attestation export (§6.4). | Agent FIPS-mode probes per platform (OpenSSL provider state, CNG policy, BC-FIPS) → confidence `measured` vs `unverified`; cross-product `compliance_verdict` (§4.2); gated posture view + attestation PDF/CSV; provenance stamping. | Stage 4 | **M** | **Yes** |
| **6 — CAVP extension (A2′)** | *"The exact algorithm + mode this asset uses is on the module's CAVP list"* → `compliant` vs `compliant_module_algo_unverified`. | Vendor CAVP lists; add `cavpAlgorithms[]` to `cmvp_modules.json`; compute `cavp_covered`; surface as verdict refinement (§3.2). | Stage 5 | **M** (data curation) | No (data + server) |

### 9.2 Sequencing rationale

- **Ship Stages 1–2 first.** Server-only, no agent rebuild, and they produce the *regulatory-deadline* and *approved-but-unvalidated-count* facts that are demo-safe and RFP-citable **now** — the GSA/Army/FDA asks can be partially answered before any module work exists.
- **Stage 3 before Stage 4.** Connector-reported CMVP certs are high-confidence with almost no inference and no agent rebuild, so they prove the module axis end-to-end on KMS/HSM assets while the harder host-side identification (Stage 4) is built. This is the lowest-risk way to get a real cert # on screen.
- **Stage 4 then Stage 5 (never skip the gate).** Module *identity* (P-a) and FIPS-*mode* (P-b) are separate; identity without the mode gate can only yield `unverified`. Stage 5 is what turns `approved_unvalidated` into `compliant`, and it is where the honesty discipline matters most — ship them in order, never fold the gate into Stage 4.
- **Stage 6 (CAVP) last.** It is pure refinement with no value until Stages 3–5 attach a module to the finding; it must never block or downgrade a CMVP verdict when its data is absent.

### 9.3 Dependency view

```
Stage 1 (A1) ──┬─▶ Stage 2 (CBOM fix)
               │
               └─▶ Stage 3 (CMVP via connectors) ─▶ Stage 4 (host module identity, P-a)
                                                      │
                                                      └─▶ Stage 5 (FIPS-mode gate + verdict, P-b)
                                                            │
                                                            └─▶ Stage 6 (CAVP, A2′)
```

**Recommended first slice:** Stages 1 + 2 + 3 — the full picture *minus* host-side identification — covers the algorithm axis for the whole fleet and real CMVP certs for all KMS/HSM-backed keys, with zero agent rebuild.

---

## 10. Risks, honesty, and positioning

- **Framing (critical):** this is a **roadmap/opportunity** feature. Do **not** claim structured FIPS compliance mapping or CMVP verdicts as shipped. What is demo-safe **Today**: algorithm/key-size capture, free-text NIST labels, the purpose taxonomy, and the CBOM — plus the sizing/threat work of the sibling specs. The honest current line: *"QuarkShield captures every algorithm and key size and labels the governing NIST standard; structured FIPS-approval status, CMVP certificate correlation, and a compliance verdict are near-term roadmap (this spec + `CMVP_CERT_CAPTURE_DESIGN.md`)."*
- **Approved ≠ validated — never blur it.** The entire value is keeping A1 and A2 distinct. The UI wording, the CBOM properties, and the attestation must each state both independently; a "compliant" verdict requires *both* an approved algorithm *and* a confirmed validated module in FIPS mode.
- **Reference-data freshness is the moat and the liability.** A stale SP 800-131A date or a missed Active→Historical transition is a wrong compliance claim. The `version` stamp must be visible everywhere the data is used, and the refresh job is not optional.
- **QuarkShield itself is not CMVP-validated** (memory: `quarkshield-cmvp-cert-capture`). This capability reports *others'* module validation; it must never imply QuarkShield is a validated cryptographic module. The attestation footer states QuarkShield's role as evidence producer, not validator.
- **Free-text `compliance_violations` coexistence.** Keep the existing array for backward compatibility; the new structured columns are the queryable source of truth. Do not silently drop the old field consumers rely on.

---

## 11. One-line summary for the deck

> **Competitors tell you an algorithm is "FIPS-ish." QuarkShield will tell you whether it is FIPS-*approved*, for how much longer, *and* whether a current CMVP-*validated module* actually performs it — by certificate number — so "we use AES-256" never again passes for "we are FIPS 140-3 validated."**

---

*Related code: `server/src/lib/roadmapReport.ts`, `server/src/lib/cyclonedx.ts`, `server/src/lib/threatGraph/types.ts`, `server/src/models/schema.sql`, `server/src/controllers/{fleetController,gitScanController,reportController}.ts`, `server/src/middleware/{auth,serviceToken}.ts`, `agent/{auditor,sbom_scanner}.go`.*
*Related docs: [`CMVP_CERT_CAPTURE_DESIGN.md`](CMVP_CERT_CAPTURE_DESIGN.md), [`PQC_FUNCTIONAL_ANALYSIS_AND_REMEDIATION.md`](PQC_FUNCTIONAL_ANALYSIS_AND_REMEDIATION.md), [`CRYPTO_USAGE_DEPENDENCY_MAP_AND_IMPACT_ANALYSIS.md`](CRYPTO_USAGE_DEPENDENCY_MAP_AND_IMPACT_ANALYSIS.md). Related memory: quarkshield-cmvp-cert-capture, quarkshield-scanner-accuracy, quarkshield-federal-gtm, gsa-pqc-rfi, quarkshield-qsg-service-token.*
