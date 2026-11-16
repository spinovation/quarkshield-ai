# 🔏 QuarkShield — CMVP & FIPS Compliance Mapping
**Feature Design & Scoping Specification**
**Status: 🟡 ROADMAP / OPPORTUNITY — Stage 1 (FIPS algorithm axis) is live in production (2026-11-14); Stage 2 (CBOM honesty fix) is live (2026-11-15); Stage 3 (CMVP module axis for KMS / vault connector keys) is live (2026-11-15); Stage 4 (module identity on hosts) and Stage 5 (FIPS-mode gate, verdict, evidence export) are live on the server (2026-11-16) and need agent 2.3.2 to produce host data; Stage 6 (CAVP coverage) is built, not deployed. This document designs a capability; it does not describe current behavior unless a section is explicitly marked "Today" or ✅ (see §9.1a–§9.1f).**
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

1. **No structured FIPS-approval status.** `compliance_violations` is a free-text `TEXT[]`. There is no column that says, per asset, *approved / deprecated / restricted / disallowed / legacy-use-only* against **SP 800-131A Rev. 2**, and no **sunset/transition date** (e.g. "RSA-2048 deprecated after 2030, disallowed after 2035 — NIST IR 8547 draft"). Reporting cannot aggregate it, and the roadmap cannot order by *regulatory deadline* — only by quantum risk.
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
> *"RSA-1024 — disallowed under SP 800-131A Rev. 2 — non-compliant today. RSA-2048 — approved until 2035-12-31 (NIST IR 8547 draft)."*

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
| `not_applicable` | Not an algorithm instance: a package/module row, assessed by CMVP (A2) instead | SBOM `openssl` package row |
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

### 5.1 FIPS algorithm table — ✅ built as `server/src/lib/fipsAlgorithmStatus.ts`

Hand-curated, small, slow-moving, high-trust. **Implemented as a versioned TS constant, not a JSON file**: the server `tsconfig.json` has no `resolveJsonModule`, so `tsc` would not emit a `.json` table into `dist/` (same convention as the size table in `threatGraph/sizeImpact.ts`). `FIPS_TABLE_VERSION` is bumped on every change and stamped on every report. Rules match algorithm family + key size/curve + use (signature vs non-signature, keyed off `CryptoPurpose`). Every result carries a `ruleId` (evidence trail) and a `draft` flag.

| Basis | What the table encodes |
| :--- | :--- |
| SP 800-131A Rev. 2 | RSA/DH < 2048 and ECC < 224-bit disallowed; 3DES encryption disallowed after 2023-12-31; MD5/DES not approved; SHA-1 disallowed for signature generation |
| FIPS 186-5 | DSA retired for signature generation (→ `restricted`, verify-only); EdDSA approved |
| FIPS 203 / 204 / 205, SP 800-208 | ML-KEM / ML-DSA / SLH-DSA / LMS-XMSS → `pq_approved`; hybrid `X25519MLKEM768` approved via its ML-KEM component |
| SP 800-56A Rev. 3, SP 800-186 | X25519/X448 key agreement alone and non-NIST curves (secp256k1, Brainpool) → `non_fips` |
| SP 800-52 Rev. 2 | SSL and TLS 1.0/1.1 → `disallowed` |
| NIST SHA-1 retirement (Dec 2022) | SHA-1 non-signature use acceptable until 2030-12-31 |
| **NIST IR 8547 (initial public draft)** | Quantum-vulnerable public key: 112-bit strength (RSA-2048, P-224, DH-2048) deprecated after 2030-12-31; **all** disallowed after 2035-12-31. Flagged `draft: true` and labelled "draft" everywhere it surfaces. |

**Correction to the earlier draft of this spec:** RSA-2048 is *not* "disallowed after 2030-12-31". Under IR 8547 (draft) it is *deprecated* after 2030 and *disallowed* after 2035. `fips_transition_date` stores the hard (disallowed-after) date; the deprecation date is carried in the result and rationale.

**Honesty rules in the resolver:** a finding naming several primitives (cert key + signature hash, cipher-suite parts) takes the **worst** status, and `unknown` outranks the approved states, so an unsized `ECDHE` makes a suite "not determined", never "approved". A missing RSA/DH key size or EC curve gives `unknown`, never a guess. Pre-standard names (Kyber/Dilithium/SPHINCS+) are `unknown` until confirmed as final ML-KEM/ML-DSA/SLH-DSA. Package/SBOM rows are `not_applicable`: they are modules (axis A2), not algorithm instances.

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
   │        (server-side, lib/fipsAlgorithmStatus.ts)
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

- Per-asset **compliance verdict chip** beside the existing CMVP badge from the capture note: `Compliant · CMVP #4986 (Active)` / `Approved algorithm — no validated module` / `Approved until 2035-12-31 (draft)`.
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

> **As built (Stage 1):** A1 is **computed on read and not persisted**. An earlier cut wrote `fips_status / fips_standard / fips_transition_date` at every ingest site, but review found no code read them. The roadmap and console recompute with the resolver anyway, which is required for legacy rows and is lossless (the stored copy dropped the `draft` flag and rationale). A stored copy would also go stale on every `FIPS_TABLE_VERSION` change. Add the A1 columns only when a SQL-side filter actually needs them, together with a `fips_table_version` stamp so stale rows are detectable. The block below is the **target** shape for Stage 5's `compliance_verdict`.

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

A1 is **server-computed** from the vendored table (no agent change, unlike A2); as built it is computed on read (see the note above). `compliance_verdict` is derived and safe to recompute on report; it is persisted for the queryable console filter. Legacy rows stay `NULL` → render "not determined" until re-scanned. Mirrors the `purpose`-column rollout (`schema.sql:63`, populated at every ingest site).

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
| **1 — Algorithm axis (A1)** ✅ | *"N algorithms are disallowed under SP 800-131A today; M are approved but sunset by \<date\>."* Visible to every tenant. | Versioned table `lib/fipsAlgorithmStatus.ts` (§5.1); pure `fipsAlgorithmStatus()` + DB-free tests; status computed on read (not persisted, §7.1); per-asset chip + core counts tile (ungated); deadline-aware roadmap ordering (§6.1). | §5.1, §7.1 | **M** | No |
| **2 — CBOM honesty fix** ✅ | CBOM `nistQuantumSecurityLevel` reflects the real FIPS parameter set (or is omitted), plus `quarkshield:fipsStatus`/`fipsStandard`/`transitionDate` properties. | Replace `cyclonedx.ts:61` binary `nqsl`; add crypto properties (§6.3). | Stage 1 | **S** | No |
| **3 — CMVP via connectors (A2, cheapest/highest-confidence)** ✅ | *"This KMS/HSM-backed key is performed by CMVP cert #\<n\> (Active, FIPS 140-3)."* | Vendor `cmvp_modules.json` (§5.2) + offline refresh job; teach KMS/HSM connectors (`pkiConnectorController.ts`) to report module name/vendor/cert for AWS KMS FIPS, CloudHSM, Luna, nShield; populate `cmvp_*` fields on those assets. Prereqs **P-c, P-d, P-e**. | Stages 1, §3.1 | **M** (data curation) | No (connector-side) |
| **4 — CMVP module identity on hosts (A2, P-a)** ✅ built | *"OpenSSL FIPS Provider 3.0.0 on this host → cert #4282 (environment: RHEL 8 / x86-64)."* | Agent resolves providing module + version + operating environment per finding (extend `sbom_scanner.go` fingerprinting and tie it to the asset); new `AuditResult` module fields; `agent/cmvp.go` resolver with match-precedence gate. | Stage 3 | **M–L** | **Yes** |
| **5 — Verdict + posture view + FIPS-mode gate (A2, P-b)** ✅ built | *"Approved algorithm **and** validated module in confirmed FIPS mode → compliant"* vs `approved_unvalidated`. Full posture view + filters (gated); FIPS attestation export (§6.4). | Agent FIPS-mode probes per platform (OpenSSL provider state, CNG policy, BC-FIPS) → confidence `measured` vs `unverified`; cross-product `compliance_verdict` (§4.2); gated posture view + attestation PDF/CSV; provenance stamping. | Stage 4 | **M** | **Yes** |
| **6 — CAVP extension (A2′)** | *"The exact algorithm + mode this asset uses is on the module's CAVP list"* → `compliant` vs `compliant_module_algo_unverified`. | Vendor CAVP lists; add `cavpAlgorithms[]` to `cmvp_modules.json`; compute `cavp_covered`; surface as verdict refinement (§3.2). | Stage 5 | **M** (data curation) | No (data + server) |

### 9.1a Stage 1 — implemented 2026-11-14

Axis A1 is built end to end, server-side, with **no agent rebuild**.

- **Resolver:** `server/src/lib/fipsAlgorithmStatus.ts`, with `fipsAlgorithmStatus()` and `FIPS_TABLE_VERSION`. It is pure, deterministic, and the one source of truth (§5.1 lists the rules and honesty rules).
- **No schema change, computed on read:** the roadmap rollup and the console API compute status from `algorithm/key_size/hash/purpose/type` with the one resolver, so every row, including legacy rows, is judged with the current table version. When `purpose` is missing, signature-bearing *types* (certificate, CA root, signature, SSH key, keystore) are treated as signatures, so a legacy SHA-1-signed certificate is still disallowed. Persistence is deferred (§7.1).
- **Roadmap:** `RoadmapReport.fipsCompliance` covers disallowed-now, approved-with-sunset ordered earliest first, not-determined, module rows, and the table version. Each priority carries `fipsStatus`. A group gets a compliance-now bump of up to ×1.3, in proportion to the share of its instances that are disallowed or non-FIPS. Its rationale states that share ("N of M instances — weakest … — is disallowed") rather than implying the whole group fails. Mosca gains a compliance-now clause, and the narrative facts gain a FIPS line.
- **Exec report:** a "FIPS Algorithm Compliance" section in HTML, PDF and DOCX (`reportController.ts`), with the honesty note.
- **Console (ungated):** the portal-data API adds `fipsStatus/fipsStandard/fipsTransitionDate/fipsDraft` per asset. `TenantPortal.tsx` gets a per-row FIPS chip (tooltip shows the standard, sunset, draft flag and "CMVP not yet assessed") and a "FIPS Non-Compliant Algorithms" KPI tile.
- **Wording discipline:** nothing says "validated" or "compliant" for an approved algorithm. Approved instances are counted as *"CMVP module validation not yet determined"* (`approvedModuleUndetermined`) until Stage 3–5 supply the module axis.
- **Review hardening (2026-11-14):** an independent review led to these fixes, each with a regression test:
  - underscore-style IANA suite names are now tokenized, so `TLS_RSA_WITH_DES_CBC_SHA` is disallowed and RC4 suites are non-FIPS;
  - a key-establishment finding with no identifiable key exchange is `unknown`, not approved on the strength of its cipher;
  - a SHA-1-signed certificate with a NULL purpose is disallowed;
  - in a `DHE-RSA-…` suite the RSA modulus is no longer read as the DH group size;
  - "OpenSSL 3…" no longer matches the SSLv3 rule;
  - the FIPS rollup is no longer capped at 5000 groups;
  - the deck counts Shor-breakable public-key assets with `isClassicalAsymmetric()` rather than the scanner's broader `is_vulnerable` flag.
- **Verified:** DB-free tests in `server/test/fipsAlgorithmStatus.test.ts` (resolver, rollup and deck facts); the full server suite passes; server and UI `tsc --noEmit` are clean; `vite build` succeeds. An end-to-end run against a scratch Postgres checked that legacy NULL-purpose rows are assessed correctly in `buildRoadmapReport`.
- **Not verified:** the console chip and tile were not viewed in a running browser, because the portal needs a signed-in tenant session.

### 9.1b Stage 2 — implemented and deployed 2026-11-15

The server CBOM no longer asserts a NIST level it cannot support. Server-side only, **no agent rebuild**.

- **Level:** `nistQuantumSecurityLevel` was `0` or `3` from the scanner's vulnerable flag, so AES-128 and ML-KEM-1024 both exported as "category 3". It is now:
  - `0` for an asset the scanner flags as vulnerable. The scanner's verdict is not overridden: an unflagged row that names a classical public-key algorithm (a trust anchor, a list of supported algorithms) gets no level rather than `0`, so the export matches the console's counts;
  - the real NIST category when the name states one — `nistSecurityCategory()` in `lib/fipsAlgorithmStatus.ts` covers the FIPS 203/204/205 parameter sets and the reference primitives the categories are defined by (AES-128/192/256 → 1/3/5, SHA-256/384 → 2/4);
  - **omitted** otherwise (a PQ family with no parameter set, pre-standard Kyber/Dilithium, LMS/XMSS, SHA-512, cipher suites).
- **Effect on production data (read-only check, 2026-11-15, 893 assets):** 570 flagged assets stay at `0`; of 323 unflagged assets that all exported as `3`, 13 now carry a real category (10 at 3, 3 at 5) and 310 carry none. Most of those are descriptive labels with no parameter set (`ML-KEM (Kyber)` ×179, `SLH-DSA (SPHINCS+)` ×23, `ML-DSA (Dilithium)` ×11) and OS-package rows (×59). Capturing the parameter set at scan time is what would turn them into real categories.
- **Properties** on every component: `quarkshield:fipsStatus`, `quarkshield:fipsStandard`, `quarkshield:fipsDeprecatedAfter`, `quarkshield:transitionDate` (the hard sunset), `quarkshield:fipsDraftGuidance` (when a date relies on draft IR 8547), `quarkshield:fipsTableVersion`, and `quarkshield:cmvpStatus = not-assessed`. The `cmvpCertId` and `complianceVerdict` properties from §6.3 wait for Stages 3–5.
- **Explicit vulnerability flag:** `quarkshield:quantumVulnerable` (`true`/`false`). Because the level can now be absent, consumers must not infer "safe" from it. The central console reads the flag first and shows "NIST level not stated" instead of a guessed level.
- **Inputs:** the fleet CBOM query now selects `assets.purpose`, so the resolver judges signature use correctly (a SHA-1-signed certificate is disallowed).
- **Consumer compatibility:** QSG (`qsg-control/src/cyclonedx.rs`) treats level `0` as not ready, level ≥ 1 as ready, and otherwise falls back to `quarkshield:quantumStatus`. Vulnerable assets are unchanged. A non-vulnerable asset with no stated category now depends on that status text and may read as "unknown" rather than "ready".
- **Tenant-portal export:** the client-side CBOM builder in `TenantPortal.tsx` no longer writes level 3 for every non-vulnerable asset (it writes 0 or omits the field) and carries the FIPS status properties.
- **Verified:** `server/test/cyclonedx.test.ts` (12 DB-free tests); full server suite and security-regression suite pass; server and UI `tsc --noEmit` clean.
- **Not done:**
  - the agent's own local CBOM export (`agent/auditor.go`) still writes a binary level and needs an agent rebuild;
  - the tenant-portal builder still emits a non-schema `assetType: "key"` and a placeholder attestation hash, which are outside this stage;
  - not exercised against a live database or viewed in a browser.

### 9.1c Stage 3 — implemented and deployed 2026-11-15

The module axis (A2) now exists for keys discovered by the KMS / vault connectors. Server-side only, **no agent rebuild**. A connector must be re-synced once before its keys carry a module.

- **Two layers, kept apart** (`server/src/lib/cmvpModules.ts`):
  - *Observation.* Each connector records which module holds a key, from a fact its API returned for that key, as a stable module key plus the fact itself (`assets.crypto_module`, `assets.crypto_module_evidence`; also in `pki_synced_assets.raw_metadata`).
  - *Reference data.* `CMVP_MODULES` maps a module key to the certificate(s) the provider publishes for it, with status, level and sunset as read from the NIST certificate page. Versioned by `CMVP_MAP_VERSION`.
- **Resolved on read, not stored.** The certificate, status and sunset are looked up when the console or CBOM is built. NIST moves certificates to Historical; a stored copy would go stale. This departs from the capture note's `cmvp_cert_id` / `cmvp_status` columns for the same reason A1 is not persisted (§7.1).
- **What each connector reads:**

  | Connector | API fact | Module keys |
  | :--- | :--- | :--- |
  | AWS KMS | `Origin` + region | `aws-kms-hsm`, `aws-kms-china`, `aws-cloudhsm-key-store`, `aws-external-key-store` |
  | Azure Key Vault | vault host, key type (`RSA` vs `RSA-HSM`), `hsmPlatform` | `azure-managed-hsm`, `azure-kv-hsm-platform2`, `azure-kv-hsm-platform1`, `azure-kv-hsm`, `azure-kv-software` |
  | Google Cloud KMS | `protectionLevel` | `gcp-kms-software`, `gcp-kms-hsm`, `gcp-kms-hsm-single-tenant`, `gcp-kms-external` |
  | HashiCorp Vault | version string from `sys/seal-status` | `vault-enterprise-fips1403`, `vault-enterprise-fips1402`, `vault-enterprise-non-fips`, `vault-community` |

- **Certificates in map version 2026-11-15** (each read from its NIST page that day):

  | Module key | Cert | NIST module name | Standard / level | Status | Sunset |
  | :--- | :--- | :--- | :--- | :--- | :--- |
  | `aws-kms-hsm` | #4884 | AWS Key Management Service HSM | FIPS 140-3 / 3 | Active | 2029-11-17 |
  | `azure-managed-hsm` | #4700 | NITROXIII CNN35XX-NFBE HSM Family (Marvell) | FIPS 140-3 / 3 | Active | 2029-05-29 |
  | `vault-enterprise-fips1403` | #4735 | BoringCrypto (Google, LLC) | FIPS 140-3 / 1 | Active | 2029-07-22 |
  | `vault-enterprise-fips1402` | #3678 | BoringCrypto (Google, LLC) | FIPS 140-2 / 1 | Historical | — |

- **Where no certificate is reported, and why:**
  - *Google Cloud KMS (software and HSM).* Google states FIPS 140-3 Level 1 (BoringCrypto) and Level 3 HSMs, but ties Cloud KMS to no certificate number and names no HSM vendor. Status `unverified`.
  - *Azure Key Vault vault keys (platforms 1, 2, software).* Microsoft states the level per platform but its Key Vault documentation gives no certificate number for vault keys; #4700 is linked from the Managed HSM pages only. Status `unverified`. Certificates #3718 and #2643 appear only in a Microsoft Q&A answer and are not used.
  - *AWS CloudHSM key stores.* The certificate depends on the cluster's HSM type (#4703 for hsm2m.medium, #4218 Historical for hsm1.medium) and on its FIPS mode, which the KMS connector does not read. Status `unverified`.
  - *External key stores (AWS XKS, Google EKM).* The module is outside the provider. Status `unverified`.
  - *AWS China Regions and Vault Community.* The provider states there is no FIPS validation. Status `none`.
- **Wording discipline.** A certificate is what the *provider* publishes for the service, labelled `provider-reported`. A customer cannot see the HSM firmware behind one key (AWS itself says its fleet is "validated or in the process of validation"), so this is a service-level statement and the console tooltip says QuarkShield did not test the module. No compliance verdict is produced; that is Stage 5.
- **CBOM:** `quarkshield:cmvpStatus` is `active | historical | revoked | none | unverified` for these assets and stays `not-assessed` for all others. Added when known: `cmvpModule`, `cmvpCertId`, `cmvpCertUrl`, `cmvpFipsLevel`, `cmvpSunsetDate`, `cmvpBasis`, `cmvpEvidence`, `cmvpMapVersion`.
- **Console:** a module chip under the FIPS chip on the asset row (`CMVP #4884 · FIPS 140-3 L3`, `Module not verified`, `No validated module`), with the basis and caveats in the tooltip.
- **Verified:** `server/test/cmvpModules.test.ts` (DB-free); full server suite and security-regression suite pass; server and UI `tsc --noEmit` clean.
- **Not verified:** no connector was synced against a live AWS, Azure, Google Cloud or Vault account, and the chip was not viewed in a browser. That a Vault FIPS build reports its suffix in the `sys/seal-status` version string is inferred from HashiCorp's documented build names.
- **Not done:**
  - no offline refresh job for the map (§5.2); refresh is manual: re-read the NIST pages, edit `CMVP_MODULES`, bump `CMVP_MAP_VERSION`;
  - CloudHSM, Luna and nShield are not separate connectors, so nothing reports them;
  - the roadmap rollup and exec report still count approved algorithms as "module validation not yet determined" and do not use the module axis;
  - the connector's own asset list (`EnterprisePkiVaults.tsx`) does not show the module.

### 9.1d Stage 4 — implemented 2026-11-15, server side deployed 2026-11-16 (needs agent 2.3.2)

The agent now reports which cryptographic modules are on a host, and the server compares that identity with a certificate map. **Needs an agent rebuild**: agents before 2.3.2 send no module report and their hosts are unchanged.

- **What Stage 4 says, and what it does not.** Identity is not validation. A host module never resolves to `active`, `historical` or `revoked`; its status is `unverified` (or `none`). The most it gets is a **candidate certificate**: "this module's identity matches what certificate #N was issued for". Whether the module runs in FIPS-approved mode is not checked (that is Stage 5), and every candidate says so.
- **Agent: observation only** (`agent/crypto_module*.go`). The agent names no certificate. It sends a host module report in fleet telemetry (`crypto_modules`):

  | Platform | Module | Read from |
  | :--- | :--- | :--- |
  | Linux | OpenSSL library version; for OpenSSL 3, whether a FIPS provider module file is in the library's modules directory and the name and version that provider reports | `/usr/bin/openssl version`, `version -m`, `list -providers -provider fips` |
  | Linux | Operating environment | `/etc/os-release`, CPU architecture |
  | Windows | CNG Cryptographic Primitives Library, identified by the Windows build | registry `CurrentVersion` (build and update revision); file version of `bcryptprimitives.dll` as evidence |
  | macOS | Apple corecrypto, identified by the macOS release (it has no version of its own to read) | `sw_vers` |
  | macOS | LibreSSL behind `/usr/bin/openssl` | `openssl version` |

- **Which findings are tied to a module.** Only where the host itself says which module does the work:
  - the OpenSSL package finding is that library;
  - SSH configuration findings are carried out by the library `ssh -V` reports;
  - Windows Schannel protocol and cipher-suite findings are carried out by Windows CNG.

  Certificate files, PEM and SSH keys, keystore files, the Linux crypto-policy finding and remote endpoints are **not** tied to a module: they are data, or have no single module, and stay `not-assessed`.
- **Server: reference data and comparison** (`server/src/lib/hostCryptoModules.ts`), deviating from the capture note's `agent/cmvp.go` resolver so the map can be corrected without an agent rebuild. Stored: `assets.crypto_module` (family key), `assets.crypto_module_detail` (name, version, FIPS provider, operating environment), `fleet_machines.crypto_modules` (the host report). The candidate is resolved on read.
- **Match precedence (P-d).**

  | Match | Meaning |
  | :--- | :--- |
  | `exact` | Module version, operating system release and CPU architecture are all as tested |
  | `release` | Same operating system release, but this host's build is not the tested build (Windows after any update; every macOS match, because corecrypto's own version cannot be read) |
  | `version` | Same module version, but the operating system or CPU architecture is not on the tested list |
  | none | No row matches. Nothing is inferred from a family name or a near version |

  For OpenSSL the FIPS provider's self-reported name **and** full version string (including the distribution's build hash) must both equal a row. The hardware model is never compared.
- **Certificates in the host map** (each read from its NIST certificate page, or the NIST-hosted Security Policy where the page omits versions, on 2026-11-15):

  | Module | Version as reported | Cert | Standard | Status | Sunset |
  | :--- | :--- | :--- | :--- | :--- | :--- |
  | OpenSSL FIPS Provider (upstream) | 3.5.9 | #5586 | 140-3 L1 | Active | 2031-11-12 |
  | OpenSSL FIPS Provider (upstream) | 3.1.2 | #4985 | 140-3 L1 | Active | 2030-03-10 |
  | OpenSSL FIPS Provider (upstream) | 3.0.8, 3.0.9 | #4811 | 140-2 L1 | Historical | — |
  | RHEL 9 OpenSSL FIPS Provider | 3.0.7-cda111b5812c30d4 | #5573 | 140-3 L1 | Active | 2029-10-28 |
  | RHEL 9 OpenSSL FIPS Provider | 3.0.7-395c1a240fbfffd8 | #4857 | 140-3 L1 | Historical | — |
  | RHEL 9 OpenSSL FIPS Provider | 3.0.1-3f45e68ee408cd9c | #4746 | 140-3 L1 | Historical | — |
  | Ubuntu 22.04 OpenSSL module | 3.0.5-0ubuntu0.1+Fips2.1 | #4794 | 140-3 L1 | Active | 2029-09-10 |
  | Ubuntu 24.04 OpenSSL module | 3.0.13-0ubuntu3+Fips1 | #5115 | 140-3 L1 | Active | 2031-01-05 |
  | Amazon Linux 2023 OpenSSL FIPS Provider | 3.2.2-799901ad7ab41d45 | #5438 | 140-3 L1 | Active | 2031-07-26 |
  | Amazon Linux 2023 OpenSSL FIPS Provider | 3.0.8-d694bfa693b76001 | #5021 | 140-3 L1 | Active | 2030-05-25 |
  | Oracle Linux 9 OpenSSL FIPS Provider | 3.0.7-b27cdeb3ba51be46 | #5294 | 140-3 L1 | Active | 2029-08-24 |
  | Windows CNG primitives library | Windows 11 22H2 (22621), Server 2022 (20348) | #5410 | 140-3 L1 | Active | 2031-08-30 |
  | Windows CNG primitives library | builds 19042, 19043, 20348, 22000 | #4825 | 140-2 L1 | Historical | — |
  | Windows CNG primitives library | builds 18362, 18363, 19041 | #4536 | 140-2 L1 | Historical | — |
  | Windows CNG primitives library | builds 15063–17763 (incl. Server 2019) | #3197 | 140-2 L1 | Historical | — |
  | Apple corecrypto, macOS 15 | Apple silicon / Intel | #5184 / #5217 | 140-3 L1 | Active | 2031-03-10 / 2031-03-29 |
  | Apple corecrypto, macOS 14 | Apple silicon / Intel | #5216 / #5201 | 140-3 L1 | Active | 2031-03-29 / 2031-03-18 |
  | Apple corecrypto, macOS 13 | Apple silicon / Intel | #5065 / #5348 | 140-3 L1 | Active | 2030-09-21 / 2030-01-22 |
  | Apple corecrypto, macOS 12 | Intel | #4951 | 140-3 L1 | Active | 2027-01-26 |
  | Apple corecrypto, macOS 12 | Apple silicon | #4817 | 140-3 L1 | Historical | — |

- **No candidate, and why:**
  - *Windows 10 21H2 / 22H2, Windows 11 23H2 / 24H2, Windows Server 2025, macOS 26.* No certificate on the map date (several are on NIST's in-process lists). Most current Windows desktops fall here.
  - *OpenSSL 3 with no FIPS provider module installed.* Status `none`: in OpenSSL 3 only the FIPS provider is a validated module.
  - *RHEL 8, Ubuntu 20.04, SUSE.* Certificates exist, but the module version on them is not what the host reports at run time, so no row is listed.
  - *LibreSSL.* No certificate recorded in the map.
  - *Rocky, AlmaLinux, Windows Server 2019 Datacenter Core (#4687) and others.* Not curated yet.
- **CBOM** (host assets only): `quarkshield:cmvpStatus` is `unverified` or `none`; `cmvpBasis=host-observed`; `cmvpModule`, `cmvpModuleVersion`, `cmvpOperatingEnvironment`; when a row matches, `cmvpCandidateId`, `cmvpCandidateUrl`, `cmvpCandidateMatch`, `cmvpCandidateCertificateStatus`; always `cmvpFipsMode=not-checked` and `cmvpNote`. `cmvpCertId` stays reserved for provider-reported certificates (Stage 3) and is never set for a host asset.
- **Console:** the module chip on tied findings (`<module> <version> · candidate CMVP #N`), and the host's modules listed under the operating system on the machine row. Tooltips state that this is a match on identity, not a validation claim.
- **Verified:**
  - agent parsers and linking rules (`agent/crypto_module_test.go`); builds for Linux, Windows and macOS;
  - detection run for real on macOS 26 (arm64), Red Hat UBI 9.9 and Debian 12 containers. The UBI 9.9 host reported library 3.5.9 with FIPS provider `3.0.7-cda111b5812c30d4`, which is certificate #5573's version;
  - end to end: the real Linux agent's telemetry posted to a local server and database, three findings tied to the module, read back through the CBOM and console code;
  - `server/test/hostCryptoModules.test.ts`; full server and security-regression suites; server and UI `tsc --noEmit`.
- **Not verified:**
  - the Windows probe has never run on Windows (it compiles; its output parser is tested with sample text);
  - no Intel Mac, no Ubuntu Pro FIPS, Amazon Linux or Oracle Linux host was scanned; their rows rest on the version strings in the Security Policies;
  - the console chip and machine row were not viewed in a browser.
- **Not done:**
  - no compliance verdict and no FIPS-mode check (Stage 5);
  - the agent's own local CBOM export does not carry module properties; only the server's does;
  - GnuTLS, NSS, libgcrypt, the kernel crypto API, Java and Go crypto modules are not identified;
  - nginx / Apache TLS configuration is not tied to a module;
  - the roadmap rollup and exec report do not use the module axis;
  - map refresh is manual, as in Stage 3.

### 9.1e Stage 5 — implemented and server side deployed 2026-11-16 (needs agent 2.3.2)

The FIPS-mode gate, the compliance verdict and the evidence export. Stage 4's sentence "a host module never resolves to `active`" is replaced by the gate below; everything else in §9.1d stands.

- **The gate** (`server/src/lib/hostCryptoModules.ts`). A host module's candidate certificate becomes its reported certificate, with the status NIST gives it, only when **both** hold:
  1. the identity match is `exact` (module version, operating system release and CPU architecture all as tested), and
  2. the host facts the agent read satisfy the rule that certificate's Security Policy sets for approved mode.

  Anything less stays `unverified`, keeps the candidate, and says which fact was missing or off.
- **Agent: facts only** (`ModeFact` in `agent/crypto_module*.go`). The agent reports what it read and where; it draws no conclusion.

  | Fact | Read from |
  | :--- | :--- |
  | `linux.kernel.fips_enabled` | `/proc/sys/crypto/fips_enabled` |
  | `linux.crypto_policy.current` / `.config` | `/etc/crypto-policies/state/current`, `/etc/crypto-policies/config` |
  | `linux.kernel.cmdline_fips` | `fips=` on `/proc/cmdline` |
  | `openssl.default_providers` | providers shown `status: active` by plain `openssl list -providers` |
  | `windows.fips_policy.enabled` / `.mdm_enabled` | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy` |

  A file that cannot be read produces no fact. Absence is never reported as "off".
- **Mode rules** (`MODE_RULES`), each restating a Security Policy read on 2026-11-15:

  | Rule | Certificates | Confirmed when |
  | :--- | :--- | :--- |
  | `rhel-system-fips` | RHEL 9 #5573 / #4857 / #4746, Oracle Linux 9 #5294, Amazon Linux 2023 #5438 / #5021 | kernel flag is 1, applied crypto policy starts with `FIPS`, and the fips provider is active with no provider other than `base` beside it |
  | `ubuntu-system-fips` | Ubuntu 22.04 #4794, 24.04 #5115 | kernel flag is 1 and the fips provider is active with no provider other than `base` beside it |
  | `windows-default` | Windows #5410 | on the validated build only: the Security Policy makes approved mode the module's normal operation and names no setting |
  | `windows-fips-policy` | Windows #4825 | the FIPS security policy value is 1 |

  - The RHEL Security Policy says to verify with `fips-mode-setup --check`; the two files behind that command are taken from Red Hat's script. For Oracle and Amazon the same two files are assumed, not documented by those vendors.
  - "No other provider" follows the Security Policies' statement that when another OpenSSL provider is invoked the validated module is not the one in use.
- **No rule, so never confirmed:**
  - *Upstream OpenSSL FIPS providers (#5586, #4985, #4811).* Their Security Policies define approved mode by the installed module configuration (`fipsmodule.cnf` settings), which the agent does not read, and they name no system-wide switch.
  - *Apple corecrypto.* Approved mode is the default with no configuration, but the module's own version cannot be read from the host, so its match is never `exact`.
  - *Windows #4536, #3197.* Their Security Policies were not read.
- **What this means in practice.** On hosts, `compliant` is reachable today for RHEL 9, Oracle Linux 9, Amazon Linux 2023 and Ubuntu Pro FIPS systems that run the exact validated provider build in system FIPS mode, and for Windows on the exact validated build (10.0.22621.30001 / 10.0.20348.30000). A Windows machine with any later cumulative update is a different build and stays `unverified`. This is deliberate: the certificate is for a specific binary. Loosening it is a product decision, not a data fix.
- **Verdict** (`server/src/lib/complianceVerdict.ts`): the §4.2 table, unchanged. `not-assessed` (no module observed) is treated as `none` / `unverified`, so an approved algorithm in a certificate file reads `approved_unvalidated`. Added `not_applicable` for package rows. `compliant` is unreachable without an `active` module status.
- **Where the verdict appears:**
  - console: a verdict chip on assets that have a module, a tile "In a validated module" with counts that filter the asset table, and the FIPS-mode evidence in tooltips;
  - CBOM: `quarkshield:complianceVerdict` on every component; for host assets `cmvpFipsMode` (`confirmed` / `off` / `not-determined`) and `cmvpFipsModeEvidence`; `cmvpCertId` is now set for a host asset that passed the gate;
  - evidence export: `GET /api/compliance/fips-attestation.csv`, gated by the Risk Assurance add-on (§8) and by support access for platform sessions. One row per asset, stamped with both table versions and a header saying it is evidence as observed, not a certification. CSV only.
- **What "confirmed" does and does not mean.** It describes the module's configuration as read from the host. It does not show that every application uses that module (Go, Java, NSS, GnuTLS and statically linked programs do not), and QuarkShield did not test the module. Exports say so.
- **Verified:**
  - gate, rules, verdict table and CSV (`server/test/hostCryptoModules.test.ts`); agent parsers (`agent/crypto_module_test.go`); full server and security-regression suites; server and UI `tsc --noEmit`; agent builds for Linux, Windows, macOS;
  - the real Linux agent in a Red Hat UBI 9.9 container with FIPS off: facts reported, ingested into a local server and database, module left `unverified` with mode `off`, evidence CSV built from the stored rows; the export endpoint refuses a request with no session.
- **Not verified:**
  - **no host in real FIPS mode was scanned.** The `confirmed` path is covered by unit tests only;
  - the Windows probe, including the FIPS policy read, has never run on Windows;
  - the console tile, chips and export button were not viewed in a browser; the export endpoint was not called with a signed-in, entitled session.
- **Not done:**
  - PDF form of the evidence export (§6.4 asks for PDF and CSV);
  - the roadmap rollup, exec report and QSG posture payload do not use the verdict (§6.1, §8);
  - `compliance_verdict` is not persisted (§7.1); it is computed on read, as A1 is;
  - Java (BC-FIPS) mode probes named in the Stage 5 row.

### 9.1f Stage 6 — implemented 2026-11-16 (not deployed)

CAVP coverage: for an asset whose module has a reported certificate, is the asset's algorithm on that certificate's approved-algorithm list? Server only; no agent change and no schema change.

- **Data** (`server/src/lib/cavpData.ts`, generated). The "Approved Algorithms" list from each module's NIST CMVP certificate page, with the CAVP validation numbers NIST prints beside each name. 22 of the 27 certificates in the two module maps have a structured list (every FIPS 140-3 certificate); 1,205 entries. Pages were read on 2026-11-15 and 2026-11-16; the file is stamped `CAVP_DATA_READ = 2026-11-16`.
  - The five without a list are FIPS 140-2 certificates (#3197, #3678, #4536, #4811, #4825), whose pages use a different layout. All five are Historical, so none can produce `compliant` and coverage would change nothing for them.
  - Rebuild: save the certificate pages, then `python3 scripts/build-cavp-data.py <dir> [date]` from `server/`. The script reads only certificates named in the module maps and fetches nothing itself. There is still no scheduled refresh job (§5.2).
  - §3.2 proposed `cavpAlgorithms[]` inside a `cmvp_modules.json`. The maps are TypeScript, so the lists live in their own generated file keyed by certificate number instead.
- **Coverage** (`server/src/lib/cavpCoverage.ts`). The asset's recorded algorithm text is turned into one or more needs (for example `ECDHE-RSA-AES128-GCM-SHA256` needs AES-GCM, ECDH key agreement, RSA signature and SHA2-256), and each need is looked up on the list.

  | Result | When |
  | :--- | :--- |
  | `covered` | every need has an entry on the list of a certificate reported for the module |
  | `not_covered` | every reported certificate has a list, and none covers every need |
  | `unknown` | no certificate is reported; or a reported certificate has no list; or the algorithm text maps to nothing CAVP-testable |

  With several certificates, one that covers is enough, and a certificate without a list blocks `not_covered`.
- **Granularity, stated in every result.** The certificate page lists algorithm and mode. Key sizes, curves, digest sizes inside a signature scheme and other tested capabilities are on the individual CAVP validations, which are not read. `covered` therefore means "this algorithm, and the mode if one was observed, was tested in this module", not "these exact parameters were". Where the asset names no mode (`AES-256`), the match is on the family and the result says the mode was not observed.
- **Verdict** (`complianceVerdict.ts`). One new value, `compliant_module_algo_unverified`: approved algorithm, module with a current certificate, algorithm not on its list. Only `not_covered` produces it, and only from `compliant` or `compliant_until`. `covered` and `unknown` change nothing, coverage never improves a verdict, and a verdict that was not compliant is untouched. Tests enumerate the whole table to hold that.
- **What it catches today, from the real lists:**
  - ML-KEM, ML-DSA and SLH-DSA are on one list only: upstream OpenSSL 3.5.9 (#5586). An ML-DSA key in AWS KMS (#4884), or ML-KEM negotiated on a RHEL 9 host in FIPS mode (#5573), is an approved algorithm in a validated module that was not validated for it.
  - EdDSA is likewise only on #5586; an Ed25519 SSH host key on RHEL 9 in FIPS mode is refined.
  - Triple-DES is absent from the Windows #5410 list.
- **Where it appears:**
  - console: the verdict chip "Validated module · algorithm not on its list", the coverage note and validation numbers in the chip tooltip, and a count with a filter link on the "In a Validated Module" tile;
  - CBOM (server and console exports): `quarkshield:cavpCovered`, `cavpValidations`, `cavpNote`, `cavpMapVersion`, present only where a certificate is reported; `complianceVerdict` uses the refinement;
  - evidence CSV: columns "Algorithm on module CAVP list", "CAVP validations", "CAVP note", a `# CAVP algorithm lists` version line, and a sentence in the reading note. The cells are blank where no certificate is reported.
- **Also fixed here (both left from earlier stages, found by using the console):**
  - the console's own CBOM export wrote `cmvpFipsMode = not-checked` for every host module and omitted the verdict. It now writes the Stage 5 state and evidence, and `quarkshield:complianceVerdict`;
  - the filter links on the "In a Validated Module" tile filtered the Asset Inventory table on the other sub-tab, so clicking them changed nothing under the tile. They now filter the table the tile sits above, and "show compliant" includes the sunset variant, as the tile's number does.
- **Verified:** `server/test/cavpCoverage.test.ts` (data integrity, name mapping, coverage against the real lists, the verdict table, CSV and CBOM); full server and security-regression suites; server and UI `tsc --noEmit`.
  - In a browser, against a local server and database seeded with three AWS KMS keys, two findings on a RHEL 9 host in FIPS mode and one plain certificate, signed in as a tenant admin: the verdict chips and their tooltips, the tile count, each filter link, and the evidence CSV downloaded with an entitled session (and refused with 403 for a tenant without the Risk Assurance add-on). This is also the first time the Stage 5 tile, chips and export were exercised in a browser.
- **Not verified / not done:**
  - coverage is reachable on real data only for cloud keys (Stage 3) until agent 2.3.2 reports host modules, and no customer KMS connector has been synced against a live account;
  - parameter-level coverage (key size, curve) by reading the individual CAVP validations;
  - lists for the five FIPS 140-2 certificates;
  - the roadmap rollup, exec report and QSG posture payload still do not use the verdict (unchanged from Stage 5).

### 9.2 Sequencing rationale

- **Ship Stages 1–2 first.** Server-only, no agent rebuild, and they produce the *regulatory-deadline* and *approved-but-module-undetermined* facts that are demo-safe and RFP-citable **now** — the GSA/Army/FDA asks can be partially answered before any module work exists.
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
