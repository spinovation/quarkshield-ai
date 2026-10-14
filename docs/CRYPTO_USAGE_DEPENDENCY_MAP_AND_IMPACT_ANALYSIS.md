# 🔗 QuarkShield — Crypto Usage / Dependency Map & "What-Breaks" Impact Analysis
**Feature Design & Scoping Specification**
**Status: 🟡 ROADMAP / OPPORTUNITY — not shipped. This document designs a capability; it does not describe current behavior unless a section is explicitly marked "Today."**
**Owner: Platform / Scanner Engineering · Drafted: 2026-10-13 · NIST refs: FIPS 203 / 204 / 205, SP 800-131A, NSA CNSA 2.0, OMB M-23-02**

---

## 0. Provenance — why this, why now

On **2026-10-13**, a knowledgeable commenter on Ganapati's *"From Framework to Practice"* LinkedIn post made a point that cuts to the core of the PQC-inventory market:

> *"A list of algorithms is not an inventory."*

The argument: a credible cryptographic inventory must answer three questions that a flat algorithm list cannot —
1. **Where** are keys generated vs. stored vs. trusted (not just "where was a key-shaped thing found")?
2. **What depends** on a given RSA/ECDSA key or signature — i.e. *what breaks if I rotate or replace it*?
3. **What breaks** physically when ML-KEM key sizes and ML-DSA signature sizes hit real systems with fixed buffers, slots, and packet limits?

A code audit confirms this is a **real QuarkShield gap** and maps directly to the *"Crypto Purpose / Dependencies"* row rated only **"Moderate"** on the competitive scorecard (appendix slide 18 of the *From-Framework-to-Practice* deck). This spec designs the feature that moves that row to a differentiator.

This complements — does not replace — the existing functional-triage work in [`PQC_FUNCTIONAL_ANALYSIS_AND_REMEDIATION.md`](PQC_FUNCTIONAL_ANALYSIS_AND_REMEDIATION.md), which already decouples *confidentiality (HNDL)* from *authenticity (forgery)* urgency. That doc answers *"what kind of problem is this algorithm?"*. **This** doc answers *"what else falls over when I fix it, and will the fix even fit?"*

---

## 1. What QuarkShield has Today (verified in code)

| Capability | Where | What it gives us |
| :--- | :--- | :--- |
| **Discovery + per-asset location** | `server/src/models/schema.sql:29-53` (`assets` table); `source` labels in `server/src/lib/roadmapReport.ts:71-84` | One row per finding, tagged `source` ∈ {`endpoint_deploy`, `git_repo`, `cloud_kms`, `enterprise_pki`, `pqc_proxy`} + `path`/`source_ref`. This is **location-of-discovery**, not lifecycle. |
| **Partial software-dependency detection** | `server/src/controllers/gitScanController.ts:322-399` | Scans `package.json` / `requirements.txt` for vulnerable crypto libraries; emits `category:'dependency'` findings. |
| **Live key-exchange measurement** | `server/src/controllers/pqcProxyController.ts:43-131` | Measures the **actual negotiated KE group** on upstream TLS and records a "measured upstream TLS" asset — real evidence, not inference. |
| **Crypto *purpose* taxonomy** | `server/src/lib/threatGraph/cryptoPurpose.ts`; enum `CryptoPurpose` in `threatGraph/types.ts:186-189` | Every finding is already classified: `ssh_authentication \| tls_certificate \| key_establishment \| rsa_key_transport \| code_or_data_signing \| ca_trust_anchor \| symmetric \| configuration \| unknown`. **This is half of "crypto purpose" already built.** |
| **Topology / Risk Graph** | `server/src/lib/threatGraph/{engine,topology,store}.ts`; UI `ui/src/components/ThreatRiskGraph/` | Host/connection graph. Node types incl. `service`, `database`, `tls_endpoint`, `kms`, `repo`. Edge kinds (`RelKind`, `types.ts:170-172`): `connects_to \| serves \| stores_data_in \| authenticates_via \| trusts \| ssh_to \| deployed_from \| network_adjacent \| runs`. Inference rules R1–R9 in `topology.ts:7-15`. Entitlement-gated to `risk_assurance` plan. |
| **Deterministic roadmap + Mosca** | `server/src/lib/roadmapReport.ts` | Aggregates `assets` into priorities, remediation-by-family, 4-phase CNSA 2.0 roadmap, Mosca X+Y>Z verdict. All numbers data-derived. |

### 1.1 The three honest gaps

1. **No reverse-dependency edge.** `CryptoNode.asset_id` (`types.ts:192-204`) links a finding to the *host it was found on* — never to the *services, certs, or systems that consume it*. There is **no `used_by` / `consumed_by` / `depends_on` column anywhere** in `schema.sql` (the lone `depends_on` reference is an unrelated field in `pqcProxyController.ts:457`). So we cannot answer *"what breaks if I rotate this key."*
2. **No key-lifecycle state.** We record *where found*. We do **not** distinguish **generated-at** vs **stored-at** vs **trusted-by**. Fragments exist (`pki_synced_assets.rotation_enabled / .expires_at`, the `trusts` edge from topology R4) but no lifecycle model.
3. **No size / "what-breaks" analysis.** Nothing in the codebase models the physical consequences of PQC object sizes (ML-DSA sigs ~50× Ed25519; ML-KEM-768 ~35× X25519) against fixed system limits (handshake buffers, cert-chain caps, firmware signature slots, smartcard/HSM storage, MTU, QUIC amplification). This is the highest-value, lowest-coverage gap.

---

## 2. Feature definition

Three sub-capabilities, delivered in order of value/effort:

- **F1 — Crypto Usage Map (reverse dependency):** for any finding, answer *"what consumes this?"* — the services, endpoints, certs, trust stores, and pipelines that depend on this specific key/algorithm, with a confidence + evidence trail.
- **F2 — Key Lifecycle Locations:** resolve each key into **generated-at**, **stored-at**, and **trusted-by** locations (distinct roles for the same key material), so rotation planning knows *where the authoritative copy lives* and *who will break when it changes*.
- **F3 — "What-Breaks" Size-Impact Analysis:** given a proposed classical→PQC migration, flag every consuming system whose fixed limits are violated by the larger PQC objects, with the specific constraint and a remediation.

All three **reuse the existing `threatGraph` graph layer** rather than inventing a parallel store.

---

## 3. Proposed data model

Design principle: **extend, don't fork.** The graph (`threatGraph/topology.ts` + `tr_relationships` + `RelKind`) already infers asset→asset edges and classifies crypto purpose. We add (a) a few asset-schema columns, (b) new edge kinds, (c) one new derived table for impact findings.

### 3.1 `assets` table extensions (additive ALTERs — nullable, back-compatible)

```sql
-- server/src/models/schema.sql (append; all nullable so existing rows + ingest unaffected)
ALTER TABLE assets ADD COLUMN IF NOT EXISTS purpose        VARCHAR(40);   -- mirrors CryptoPurpose enum (persist the classification we already compute)
ALTER TABLE assets ADD COLUMN IF NOT EXISTS lifecycle_role VARCHAR(20);   -- 'generated' | 'stored' | 'trusted' | 'in_use' (NULL = unknown/legacy)
ALTER TABLE assets ADD COLUMN IF NOT EXISTS service_name   VARCHAR(255);  -- logical service this finding belongs to (e.g. "payments-api")
ALTER TABLE assets ADD COLUMN IF NOT EXISTS key_fingerprint VARCHAR(128); -- SPKI/SHA-256 thumbprint — correlates the SAME key across generated/stored/trusted rows
ALTER TABLE assets ADD COLUMN IF NOT EXISTS pqc_target     VARCHAR(60);   -- chosen replacement (e.g. 'ML-DSA-65','SLH-DSA-128s','X25519MLKEM768') once planned
```

Why `key_fingerprint` is the keystone: lifecycle roles are **one key seen in three places**. A fingerprint (SubjectPublicKeyInfo SHA-256, or an HSM/KMS key-id hash) is what lets us say *"the key generated on HSM-7 is the same key stored in Vault and trusted by 40 endpoints"* — collapsing N discovery rows into one lifecycle object. Without it, lifecycle is guesswork.

> **Why not a central `assets` TypeScript interface?** There isn't one today — the DB row is untyped and projected into `SrcCryptoFinding` (`threatGraph/types.ts:25-41`). Adding these columns means extending that projection + the Go agent's `AuditResult` (`agent/auditor.go:17-41`), covered in §7.

### 3.2 New `RelKind` edge kinds (crypto-usage edges)

Extend the enum in `server/src/lib/threatGraph/types.ts:170-172`:

```ts
export type RelKind =
  | 'connects_to' | 'serves' | 'stores_data_in' | 'authenticates_via'
  | 'trusts' | 'ssh_to' | 'deployed_from' | 'network_adjacent' | 'runs'
  // NEW — crypto usage/dependency edges (crypto node → consuming asset/service):
  | 'secured_by'     // service/endpoint is secured by THIS key/cert  (reverse of "what breaks")
  | 'signed_by'      // artifact/firmware/code is signed by THIS signing key
  | 'key_stored_in'  // key material physically resides in THIS store (HSM/KMS/keystore/smartcard)
  | 'key_generated_by' // key was generated by THIS system/ceremony
  | 'chains_to';     // cert chains to THIS issuer/CA (cert-chain sizing + trust)
```

These are **crypto-node→asset** edges (today edges are asset→asset only). `TrRelationship` (`types.ts:174-184`) already carries `confidence`, `rule_id`, `evidence` — we reuse all three so every usage edge is explainable, exactly like the existing R1–R9 topology.

### 3.3 New derived table: `tr_impact_findings` ("what breaks")

One row per (consuming system × proposed PQC migration × violated constraint). Derived — rebuilt with the rest of the `tr_*` tables in `store.ts` `persist()`, keyed by `tenant_key`, with full JSON in `data`:

```sql
CREATE TABLE IF NOT EXISTS tr_impact_findings (
  id            VARCHAR(160) PRIMARY KEY,
  tenant_key    VARCHAR(255) NOT NULL,
  crypto_id     VARCHAR(160),          -- the CryptoNode being migrated
  consumer_id   VARCHAR(160),          -- the TrAsset that breaks (via a usage edge)
  constraint_id VARCHAR(60),           -- 'tls_record' | 'cert_chain' | 'firmware_slot' | 'smartcard_apdu' | 'hsm_object' | 'mtu_frag' | 'quic_amp'
  from_algo     VARCHAR(80),           -- e.g. 'Ed25519' / 'RSA-2048' / 'X25519'
  to_algo       VARCHAR(80),           -- e.g. 'ML-DSA-65' / 'SLH-DSA-128s' / 'ML-KEM-768'
  size_before   INTEGER,               -- bytes (sig or pubkey/ciphertext)
  size_after    INTEGER,               -- bytes
  limit_bytes   INTEGER,               -- the system limit being tested against
  severity      VARCHAR(20),           -- 'blocker' | 'degraded' | 'advisory'
  verdict       VARCHAR(20),           -- 'breaks' | 'tight' | 'ok'
  rationale     TEXT,
  remediation   TEXT,
  data          JSONB,
  created_at    TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tr_impact_tenant ON tr_impact_findings(tenant_key);
```

---

## 4. F3 — the "What-Breaks" size-impact engine (the differentiator)

A **deterministic** engine (same philosophy as `roadmapReport.ts` — no AI-invented numbers). Two inputs: (a) a size table of classical vs PQC object sizes; (b) a constraint table of real system limits. For every crypto node with a `pqc_target` and at least one usage edge, cross-join against the constraints of each consuming system and emit `tr_impact_findings`.

### 4.1 Object-size reference table (bytes)

| Object | Classical | Size | PQC replacement | Size | Blow-up |
| :--- | :--- | ---: | :--- | ---: | ---: |
| **Signature** | Ed25519 | 64 | ML-DSA-65 | 3,309 | **~52×** |
| Signature | ECDSA P-256 | ~72 | ML-DSA-65 | 3,309 | ~46× |
| Signature | RSA-2048 | 256 | ML-DSA-65 | 3,309 | ~13× |
| Signature (firmware root) | ECDSA P-384 | ~104 | SLH-DSA-128s | 7,856 | **~75×** |
| Signature (firmware root) | ECDSA P-384 | ~104 | SLH-DSA-128f | 17,088 | ~164× |
| **Public key** | X25519 | 32 | ML-KEM-768 (ek) | 1,184 | **~37×** |
| KEM ciphertext | X25519 share | 32 | ML-KEM-768 (ct) | 1,088 | ~34× |
| Signing public key | Ed25519 | 32 | ML-DSA-65 | 1,952 | ~61× |

*(Sizes are NIST FIPS 203/204/205 final-standard values; stored as a versioned constant so they track parameter-set choices.)*

### 4.2 Constraint table (`constraint_id` → real-world limit + why it breaks)

| `constraint_id` | Limit modeled | What breaks | Typical remediation |
| :--- | :--- | :--- | :--- |
| `tls_record` | TLS record 16,384 B; ClientHello/cert flight buffers on constrained stacks | ML-KEM key share + ML-DSA cert chain can exceed small-stack handshake buffers → handshake failure | Enable TLS cert compression (RFC 8879); raise buffer; hybrid only where needed |
| `cert_chain` | Max cert-chain bytes a client/embedded TLS stack will accept | ML-DSA leaf+intermediate+root chain balloons 5–15 KB → rejected by IoT/legacy clients | Shorter chains, ML-DSA-44 leaves, intermediate suppression, cert compression |
| `firmware_slot` | Fixed signature slot in secure-boot header (often 256/384/512 B) | 3.3 KB ML-DSA / 7.8 KB+ SLH-DSA **cannot physically fit** a slot sized for RSA/ECDSA | Firmware header re-layout; stateful HBS (LMS/XMSS) where one-time use fits; next-rev silicon |
| `smartcard_apdu` | Smartcard APDU ~255 B (short) / extended-APDU support varies | PQC keys/sigs exceed short-APDU; many deployed readers lack extended APDU | Chaining, extended APDU only on verified readers, off-card signing |
| `hsm_object` | HSM/KMS key-object + throughput limits; PKCS#11 attribute sizes | Larger key objects + slower ML-DSA ops cut HSM signing throughput; storage caps on key count | HSM firmware with native ML-DSA; capacity planning; batch signing |
| `mtu_frag` | Path MTU (~1,500 B) / IKEv2 fragmentation | ML-KEM IKEv2 payloads fragment → drops on middleboxes that block fragments | IKEv2 fragmentation (RFC 7383); MTU tuning |
| `quic_amp` | QUIC 3× anti-amplification limit before address validation | Large PQC ServerHello+cert exceeds 3× client-initial → extra RTT or stall | Retry/address-validation tuning; cert compression; defer full chain |

### 4.3 Verdict logic (deterministic)

```
size_after vs limit_bytes:
  size_after  > limit            → verdict 'breaks',   severity 'blocker'
  size_after  > 0.8 * limit      → verdict 'tight',    severity 'degraded'
  else                           → verdict 'ok'        (not emitted unless --verbose)
```

Output example (one `tr_impact_findings` row, rendered in UI):

> 🔴 **BLOCKER** — Rotating the firmware signing key `fw-root-2021` (ECDSA-P384 → **SLH-DSA-128s**) breaks **12 IoT gateways**: the secure-boot header reserves a **384-byte** signature slot; SLH-DSA-128s is **7,856 bytes** (20× over). *Remediation: header re-layout required, or adopt LMS/XMSS stateful HBS for the boot chain; coordinate with next firmware revision.*

This is the sentence a CISO cannot get from any "list of algorithms."

---

## 5. How it feeds the existing outputs

### 5.1 Into `roadmapReport.ts`

`buildRoadmapReport()` (`roadmapReport.ts:120`) gains an optional **impact-weighted** dimension without changing its deterministic nature:

- **New field** `RoadmapReport.impact: { blockers: number; degraded: number; topBlockers: ImpactFinding[] }` — counted from `tr_impact_findings` for the scope.
- **Priority re-ranking:** the `score` in the priority scorer (`roadmapReport.ts:163`) gains an `impactMult` (e.g. ×1.4 when a finding has ≥1 `blocker` impact edge) — a key that is *hard to migrate* and *widely consumed* should outrank a trivial isolated one. Still deterministic, still data-derived.
- **Mosca refinement (`roadmapReport.ts:200`):** today Mosca is X+Y>Z on vuln %. Add **migration-friction (Y)** sourced from blocker counts — "Y is longer than you think: N systems need firmware/hardware changes, not config." This is exactly the Mosca insight the comment was reaching for.
- **Roadmap phases (`:192`):** Phase 3 (firmware/PKI) actions become specific — "Re-layout secure-boot headers on 12 gateways before SLH-DSA adoption" instead of the generic line.

### 5.2 Into the Risk Graph UI

Reuse `ui/src/components/ThreatRiskGraph/`:
- `GraphView.tsx` renders the new `secured_by`/`signed_by`/`key_stored_in`/`chains_to` edges (distinct styling), so selecting a crypto node **highlights its blast radius**.
- `AssetDetail.tsx` gains a **"What breaks if I rotate this"** panel driven by `tr_impact_findings` for the selected node.
- New overview tile: **"Migration blockers"** count alongside existing posture tiles.
- `threatGraphController.ts` adds `/threat-graph/impact` and `/threat-graph/impact/:cryptoId` to `routes.ts:350-362`.

### 5.3 CBOM / CycloneDX

Emit the usage edges + impact as CycloneDX `dependencies` and a vendor extension (`server/src/lib/cyclonedx.ts`), so the dependency map is portable and standards-aligned — not a QuarkShield-only artifact.

---

## 6. How edges get populated (reuse topology R1–R9, add R10–R13)

Extend `server/src/lib/threatGraph/topology.ts` `inferTopology` (rule catalog at `topology.ts:7-15`) with crypto-usage rules. Each carries `confidence` + `evidence` like the existing rules:

| Rule | Edge | Source signal | Confidence |
| :--- | :--- | :--- | :--- |
| **R10** cert→service | `secured_by` | A `tls_certificate` finding's SAN/DNS names match a `service`/`tls_endpoint` asset (builds on existing R2 `serves`). | High (measured) |
| **R11** signing-key→artifact | `signed_by` | A `code_or_data_signing` / `ca_trust_anchor` purpose finding + SBOM/git provenance (`deployed_from`, R5). | Medium (inferred) |
| **R12** key→store | `key_stored_in` + `lifecycle_role='stored'` | `source ∈ {cloud_kms, enterprise_pki}` or agent keystore scan → the KMS/HSM/keystore asset. Fingerprint-correlated. | High |
| **R13** cert→issuer | `chains_to` | X.509 AKI/issuer linkage from cert parsing → the CA node (builds on R4 `trusts`). Feeds `cert_chain` sizing. | High (parsed) |
| (lifecycle) key→generator | `key_generated_by` + `lifecycle_role='generated'` | KMS/HSM "origin=generated" metadata (`pki_synced_assets.raw_metadata`) or ceremony attestation. | Medium–High |

`key_fingerprint` collapses the generated/stored/trusted rows of the same key into one lifecycle object across these rules.

---

## 7. Agent collection plug-in points

The graph is only as good as the evidence. Three collection extensions (all additive to the Go agent, `agent/`):

1. **Cert parsing for SANs + chain + issuer (R10/R13):** `auditor.go` already parses certs — emit SAN DNS names, chain depth/bytes, and AKI/issuer into `AuditResult`. Low effort, high value; purely local.
2. **Keystore / trust-store inventory (R12, lifecycle `stored`/`trusted`):** extend SBOM-style collection (see [`quarkshield-headless-sbom-audit`]) to enumerate OS/app trust stores and keystores (PEM dirs, JKS, PKCS#12, Windows cert store), emitting `lifecycle_role` + `key_fingerprint`. This is what makes "trusted-by" real.
3. **Network-probe cert-chain sizing (R10, `cert_chain`/`tls_record`):** `prober.go` already measures the negotiated group — also record the **served chain byte-size** per endpoint (`type:'network_probe'`). Feeds the `cert_chain`/`quic_amp` constraints with *measured* numbers.

KMS/HSM-origin metadata for `key_generated_by` comes from the connector side (`pkiConnectorController.ts`, `pki_synced_assets.raw_metadata`) — no agent change needed.

Ingest unchanged in shape: these ride the existing `POST /api/scan/agent/ingest` → `ingestTelemetry` path (`fleetController.ts:628`); new `AuditResult` fields map to the new `assets` columns in the UPSERT (`fleetController.ts:1000-1033`).

---

## 8. Phased build plan

| Phase | Scope | Depends on | Effort | Ships as |
| :--- | :--- | :--- | :--- | :--- |
| **P0 — Persist purpose** ✅ | Add `purpose` column; write the `CryptoPurpose` we already compute (`cryptoPurpose.ts`) into `assets`. No new collection. | — | **S** | Internal; unlocks querying by purpose |
| **P1a — Purpose in roadmap** ✅ | Consume persisted `purpose` in `roadmapReport.ts`: purpose breakdown, HNDL-vs-forgery urgency split, HNDL-aware priority scoring, rendered in exec report. | P0 | **S** | Purpose breakdown + sharper priorities in the exec report |
| **P1b — Blast-radius (reverse-dependency)** ✅ | Compute "what breaks if I rotate this key" over the *existing* topology edges (server-only). Dedicated `secured_by`/`chains_to` edges deferred — they need agent cert-parsing. | P0 | **M** | "What depends on this key" via API |
| **P2 — What-Breaks engine (F3)** | Size + constraint tables, verdict logic, `tr_impact_findings`, roadmap `impact` field + Mosca friction, UI blockers tile. | P1 | **M** | The headline differentiator |
| **P3 — Lifecycle (F2)** | `key_fingerprint` correlation, keystore/trust-store agent scan (§7.2), `key_stored_in`/`key_generated_by`, lifecycle roles. | P1, agent work | **L** | generated/stored/trusted map |
| **P4 — Portability** | CycloneDX `dependencies` + impact extension; CI gate can fail on new `blocker` impacts. | P2 | **S–M** | Standards-aligned export |

### 8.1 P0 — implemented 2026-10-13

The smallest slice is landed (branch `claude/recursing-chaplygin-b3bcc3`). It persists the `CryptoPurpose` classification — which the graph layer already computes in `cryptoPurpose.ts` — onto the `assets` row **at ingest time**, so the inventory is queryable by *what the key/cert is for*, not just its algorithm. Zero new collection and zero new classification logic: every write-site calls the one existing `classifyPurpose()` so there is a single source of truth.

- **Schema:** `assets.purpose VARCHAR(40)` (nullable, additive ALTER) + `idx_assets_purpose` — `server/src/models/schema.sql`. Legacy rows stay `NULL` until re-scanned; nothing breaks.
- **All four ingest sites populated** (no misleading half-NULL column):
  - endpoint bulk ingest — `fleetController.ts` `ingestTelemetry` UPSERT (classifier per asset);
  - git repo scan — `gitScanController.ts` findings insert (classifier per finding);
  - KMS/PKI connector sync — `pkiConnectorController.ts` CBOM syndication (classifier per discovered key);
  - hybrid-TLS proxy — `pqcProxyController.ts` both inserts written as `key_establishment` (definitionally key-exchange assets).
- **Verified:** `npx tsc --noEmit` clean after `npm install`.

### 8.2 P1 (partial) — purpose in the roadmap engine, implemented 2026-10-13

The persisted `purpose` is now consumed by the deterministic roadmap engine (`roadmapReport.ts`) and surfaced in the executive report — the "priority-by-purpose" half of P1. (The Risk-Graph UI purpose facet and the usage-edge inference R10/R13 remain to do.)

- **HNDL-vs-forgery urgency split.** New `purposeMeta()` maps each `CryptoPurpose` to an urgency: key establishment / RSA key transport → *immediate (Harvest-Now-Decrypt-Later)*; TLS cert / code signing / CA trust anchor / SSH auth → *planned (forgery)*; symmetric / config → *hardening*; unknown → *review*. Mirrors `PQC_FUNCTIONAL_ANALYSIS_AND_REMEDIATION.md`.
- **New `RoadmapReport.purposeBreakdown[]`** — vulnerable assets grouped by purpose (count + urgency + NIST target), ordered immediate-HNDL first. Rendered as a "Cryptographic Purpose Breakdown" section in all three export formats (HTML / PDF / DOCX) in `reportController.ts`.
- **HNDL-aware priority scoring.** A dominant purpose of `key_establishment` / `rsa_key_transport` adds a ×1.15 multiplier, so an HNDL key outranks an equally-breakable *signing* key of the same algorithm; the purpose is also named in each priority's rationale (and carried as `Priority.purpose` / `purposeLabel`).
- **Narrative** now states the HNDL vs signature/trust split.
- **Tests:** `server/test/roadmapPurpose.test.ts` (7, DB-free) — all pass. `npx tsc --noEmit` clean.
- **Legacy-safe:** NULL `purpose` (un-rescanned rows) resolves to `unknown`/review; all queries `COALESCE` it.

### 8.3 P1b — crypto blast-radius (reverse-dependency), implemented 2026-10-13

The reverse-dependency question — *"what breaks if I rotate/replace this key or cert?"* — is now answerable, computed over the topology edges QuarkShield **already** infers (R1–R9). No new collection, no agent change, no invented edges.

- **Pure core** `server/src/lib/threatGraph/blastRadius.ts` — `cryptoBlastRadius(crypto, assetsById, relationships)`. Walks edges out from the asset holding the finding; for each 1-hop neighbour it records the edge kind, direction, confidence, evidence, and a `relies_on_host_key` flag computed from a per-`RelKind` semantics table (e.g. a host that *serves* a client, or a CA key a client *trusts*, means the neighbour breaks on rotation; an upstream the host merely *connects_to* does not). Consumers sort first.
- **API** `GET /threat-graph/crypto/:id/blast-radius` (`threatGraphController.getCryptoBlastRadius`) — same `requireRiskAssuranceEntitlement` gate as the rest of the graph; reads `tr_nodes`/`tr_assets`/`tr_relationships`.
- **Honesty built into the payload.** The `note` states it is a 1-hop view from inferred topology, confidence is per-edge, and absence of edges is not proof of no dependents. It explicitly says the dedicated certificate-SAN (`secured_by`) and issuer-chain (`chains_to`) edges still require **agent cert-parsing** (§7.1) and are not yet collected — so we never overclaim.
- **Deferred (needs agent work, out of this server-only slice):** SAN/issuer-keyed edges, and the Risk-Graph UI blast-radius panel (the API is ready for it).
- **Tests:** `server/test/blastRadius.test.ts` (7, DB-free) — all pass; `npx tsc --noEmit` clean.

**Recommended next slice:** P0 → P2 on the *signing/firmware* path only (the most visceral "it literally won't fit" story), then broaden. P2 can demo on `firmware_slot` + `cert_chain` constraints with measured chain sizes from P1 — a compelling PoC with modest agent work.

---

## 9. Risks, honesty, and positioning

- **Framing (critical):** This is a **roadmap/opportunity** feature. Do **not** claim a crypto usage-dependency map or "what-breaks" analysis as shipped. What *is* shipped and demo-safe today: discovery + location + `source`, the crypto `purpose` taxonomy, live KE measurement, and the host/connection Risk Graph. The sizing math (§4.1) is real and citable now even before the engine exists — useful for briefings.
- **Inference honesty:** usage edges must carry `confidence` + `evidence` (the graph already enforces this). An *inferred* `signed_by` must never render as *measured*. Mirror the existing discipline in `pqcProxyController.ts` where an unread KE group is treated as exposed, not assumed safe.
- **`source` is free-form:** two overlapping vocabularies (`assets.source` vs `sbom_components.source`) with no DB CHECK. Before building on it, consider a CHECK constraint or a shared TS enum — otherwise lifecycle rules keyed off `source` will be brittle.
- **Entitlement:** all graph features are gated to the `risk_assurance` add-on (`store.ts:184`); this feature inherits that gate. Decide whether "what-breaks" is a `risk_assurance` upsell or a core scanner capability (recommendation: the *blocker count* is core/teaser; the full blast-radius graph is the add-on).
- **Scope discipline:** the size/constraint tables are the moat and must be maintained as a versioned reference as NIST parameter sets and deployment realities evolve.

---

## 10. One-line summary for the deck

> **Competitors ship a list of algorithms. QuarkShield will ship the dependency graph underneath it — *what uses this key, what breaks when you rotate it, and whether the post-quantum replacement physically fits the systems that depend on it.***

---

*Related code: `server/src/lib/roadmapReport.ts`, `server/src/lib/threatGraph/{types,topology,engine,store,cryptoPurpose}.ts`, `server/src/controllers/{fleetController,gitScanController,pqcProxyController,pkiConnectorController,threatGraphController}.ts`, `server/src/models/schema.sql`, `agent/{auditor,prober,sbom_scanner}.go`.*
*Related docs: [`PQC_FUNCTIONAL_ANALYSIS_AND_REMEDIATION.md`](PQC_FUNCTIONAL_ANALYSIS_AND_REMEDIATION.md), [`ACTIVE_NETWORK_TLS_PQC_PROBING.md`](ACTIVE_NETWORK_TLS_PQC_PROBING.md). Related memory: quarkshield-scanner-accuracy, quarkshield-threat-risk-graph-deploy, quarkshield-headless-sbom-audit, quarkshield-federal-gtm.*
