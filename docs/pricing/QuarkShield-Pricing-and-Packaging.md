# QuarkShield — Pricing & Packaging Model

**Status:** Internal draft · v0.1 · 2026-10-07
**Owner:** Sridhar G.S.
**Positioning:** QuarkShield is a **continuous quantum-readiness product**, not a one-time scanner. Pricing is **recurring and per-managed-endpoint**. The recurring value is ongoing posture monitoring, drift detection, daily compliance snapshots, and multi-year migration tracking toward CNSA 2.0 / NIST (2030 & 2035) deadlines.

> This document reconciles two previously separate workstreams:
> 1. The **in-product seat/tier billing model** already implemented in the server (`BILL-1 … BILL-7`, `QUARKSHIELD_PLANS`).
> 2. The **regional/sovereign instance cost+margin model** drafted in `QS Scanner/Pricing/`.
> Where the two disagreed, this doc states a single recommended number and flags the open decision.

---

## 1. Pricing unit (the thing we meter)

**1 seat = 1 managed endpoint = 1 enrolled agent = one `fleet_machines` row, scoped per tenant.**

- The agent enrolls with a fleet token / license key (`qs_flt_…`); the token's tenant is authoritative (BILL-1), so a device can never be double-counted across tenant spellings.
- Deduplication is `hardware_uuid`-first, so a reimaged or renamed host does **not** consume a second seat (BILL-1 / DEF-35).
- Seat cap enforced at enrollment: `seatLimit = max(admin_licenses.seats, admin_clients.mca_limit)`; at cap, new enrollment returns `403 Seat limit reached`.
- **Not metered:** repositories, Vault/PKI connectors, PQC proxy gateways, CI/Git scans. These create `assets`, never `fleet_machines`. They are **gated by tier**, not charged per-unit (metering integrations would punish the lock-in we want).

This is the single source of truth for every number below. All list prices are **per seat per year** unless stated.

---

## 2. Editions (commercial SaaS — shared multi-tenant)

These map 1:1 to the plans already live in `billingController.ts` (`QUARKSHIELD_PLANS`) and the landing page. Internal tier vocabulary note: the plan key `scale` resolves to the DB tier `growth`; `admin_clients.subscription_tier` uses `entry | growth | enterprise`.

| Edition | Plan key / DB tier | Seats incl. | Monthly list | Annual list | **Effective $/seat/yr (annual)** |
|---|---|---|---|---|---|
| **Entry** — PQC Assessment | `entry` / `entry` | 5 | $300/mo ($3,600/yr) | **$3,000/yr** | **$600** |
| **Scale** — Growth Fleet | `scale` / `growth` | 50 | $2,500/mo ($30,000/yr) | **$25,000/yr** | **$500** |
| **Enterprise** — Enterprise Pro | `enterprise` / `enterprise` | 250 | $10,000/mo ($120,000/yr) | **$100,000/yr** | **$400** |
| **Sovereign / Gov** | custom license | custom | — | instance fee + per-seat (see §7) | **$480 base × region multiplier** |

**The per-seat price already declines with scale — $600 → $500 → $400 — so volume breaks are built into the edition ladder, not bolted on.** Annual billing is ~17% cheaper than paying monthly (the monthly plan is the premium, pay-as-you-go option).

### What's in each edition (feature gating)

| Capability | Entry | Scale | Enterprise | Sovereign/Gov |
|---|---|---|---|---|
| Quantum Risk Score + CycloneDX 1.6 CBOM | ✅ | ✅ | ✅ | ✅ |
| Local/zero-exfil audit | ✅ | ✅ | ✅ | ✅ |
| Continuous drift detection + daily snapshots | — | ✅ | ✅ | ✅ |
| Central Plane console + MDM group enrollment (Intune/Jamf) | — | ✅ | ✅ | ✅ |
| **Integrations & Gateways** (PKI/Vault connectors, PQC proxy, Remote Git/CI scan) — *gated by BILL-2* | — | ✅ | ✅ | ✅ |
| QS Copilot AI (incl. offline/SCIF mode) | — | — | ✅ | ✅ |
| Dedicated subdomain + 2FA/RBAC | — | — | ✅ | ✅ |
| Dedicated isolated instance + data residency | — | — | — | ✅ |

**Gating is already enforced in code:** `requireIntegrationsEntitlement` blocks integration *writes* for `entry` tenants; `INTEGRATION_TIERS = {growth, enterprise, corporate, corp, partner}`. GET/DELETE stay open (a downgraded tenant can still view/remove, never silently lose data).

---

## 3. Cost + margin rationale (why these seat prices)

Commercial editions run on the **shared multi-tenant platform** (single VPS, Docker Compose, per-tenant subdomains). Infra is amortized across all tenants, so the marginal infra cost of one additional seat is on the order of a few dollars per year. The per-seat price is therefore **value-based**, recovering R&D, ongoing crypto-intelligence updates (new algorithms, CNSA 2.0 tracking), support, and platform ops — not a cost-plus markup on a dedicated box.

- **Gross margin on shared-platform seats is ~90%+** on infra; the real "cost" being recovered is engineering + support + go-to-market.
- The declining $/seat ($600→$500→$400) reflects lower per-seat support and sales cost at larger fleets, and competitive positioning against six-figure incumbents (competitor TCO cited internally at $250K–$1M+/yr).
- **Floor:** do not discount below **$300/seat/yr** on shared platform without approval — below that the support + crypto-intel cost base is no longer safely covered at smaller fleets.

The cost+margin discipline applies in full to **sovereign instances** (§7), where infra is *dedicated* and therefore a real, per-region cost line.

---

## 4. Volume breaks (beyond the edition ladder)

The editions already step the price down. For fleets that outgrow Enterprise's included 250 seats, use these **marginal per-seat adds** (annual):

| Cumulative managed endpoints | Marginal $/seat/yr | Notes |
|---|---|---|
| 1 – 5 | $600 | Entry |
| 6 – 50 | $500 | Scale |
| 51 – 250 | $400 | Enterprise |
| 251 – 1,000 | **$340** | Enterprise + volume |
| 1,001 – 5,000 | **$290** | |
| 5,001+ | **Custom** | Floor $250/seat/yr; quote via custom checkout |

Custom/large deals use `createCustomCheckoutSession` (arbitrary amount, tier defaults to `enterprise`). Keep the **floor at $250/seat/yr** on shared platform.

---

## 5. Term & commitment (annual vs multi-year)

License terms in code are `monthly` (30-day) or `annual` (365-day); Stripe trial = **14 days**.

| Term | Discount vs monthly list | Rationale |
|---|---|---|
| Monthly (pay-as-you-go) | 0% (list) | Max flexibility, highest effective price |
| **Annual** (default) | ~17% | Matches `annualAmountCents` already in code |
| **2-year prepaid** | +5% off annual | Lock in ahead of 2027/2030 mandate rush |
| **3-year prepaid** | +10% off annual | Aligns to CNSA 2.0 migration horizon; preferred for Gov/Enterprise |

Multi-year is priced off the **annual** rate, not monthly. Price-protect the per-seat rate for the committed term (no uplift on co-term adds within the term).

---

## 6. Track 1 vs Track 2 packaging

QuarkShield has two product tracks; both apply to federal and commercial buyers.

- **Track 2 — pure PQC scanning / remediation** (`fleetController`, `gitScanController`, `ciGateController`, `pkiConnectorController`, `pqcProxyController`, CBOM). This is the **base product** in every edition.
- **Track 1 — control-centric OSCAL compliance** (`projectController`, `oscal.ts`, `controlCatalog.ts`, `poamExcel.ts`): Projects = authorization boundaries assessed against NIST 800-53 r5 / 800-171 r2 / r3, auto-seeded from the CBOM, exporting OSCAL SSP + POA&M (and FedRAMP/eMASS-style POA&M `.xlsx`).

### Packaging recommendation

| | Track 2 (scanning) | Track 1 (OSCAL compliance) |
|---|---|---|
| Entry | ✅ core | — |
| Scale | ✅ core | **Compliance add-on** (+$150/seat/yr, min 25 seats) |
| Enterprise | ✅ core | ✅ **included** |
| Sovereign/Gov | ✅ core | ✅ **included** (compliance is the federal buying reason) |

**Rationale:** compliance evidence (SSP/POA&M generation) is the highest-value capability for regulated and federal buyers and the natural reason Enterprise/Gov buy. Bundling it into Enterprise defends the $400/seat tier; offering it as a paid add-on at Scale creates a clean upsell path without a full tier jump.

> ⚠️ **Code gap to close:** Track 1 OSCAL routes (`/projects…`, `/oscal/ssp`, `/oscal/poam`, `/poam.xlsx`) are currently **ungated** — any authenticated tenant can use them regardless of tier. To realize the packaging above, add a `requireComplianceEntitlement` gate (mirroring `requireIntegrationsEntitlement`, BILL-2) keyed to Enterprise/Gov + the Scale add-on SKU. **Until that ships, Track 1 is effectively free to all tiers.** This is an open engineering item, not a pricing decision.

CMMC / FedRAMP full compliance engines are a **separate product** (FedMitigate), not QuarkShield — keep them out of QuarkShield SKUs and cross-sell instead.

---

## 7. Sovereign / regional instance pricing (dedicated, data-resident)

For buyers that require data residency or government cloud (GovCloud/FedRAMP, GDPR/EU, India DPDP Act), QuarkShield is deployed as an **isolated single-tenant instance** rather than on the shared platform. Because infra is dedicated, pricing is **cost + margin** with an explicit per-region cost line.

**Formula:** `Annual price = Sovereign Instance Fee (fixed) + (managed endpoints × base per-endpoint × regional multiplier)`
Base per-endpoint = **$480/yr** (a ~20% premium over the shared Enterprise $400, reflecting the dedicated box).

| Region | Annual instance **cost** (infra+ops+compliance) | **Instance Fee** (list) | Multiplier | **Per-endpoint** (list) | Tenancy |
|---|---|---|---|---|---|
| **India** (DPDP) | ~$12.7k | $15,000 | ×0.75 | $360 | Dedicated |
| **EMEA** (GDPR) | ~$14.0k | $24,000 | ×1.15 | $550 | Dedicated |
| **APAC** | ~$14.2k | $24,000 | ×1.10 | $530 | Dedicated |
| **Gov — in customer boundary** (FedRAMP inherited) | ~$18.0k | $36,000 | ×1.30 | $625 | Dedicated |
| **Gov — QuarkShield-owned FedRAMP** | ~$58.0k (incl. ~$40k FedRAMP amort.) | $90,000 | ×1.30 | $625 | Dedicated |

- **Cloud choice:** AWS GovCloud recommended over Azure Gov (~$445/mo vs ~$675/mo for equivalent HA).
- **India ×0.75** reflects local market pricing; this is an open decision (local vs global parity — see §9).
- **Gov premium** (×1.30 + higher instance fee) covers FedRAMP/compliance overhead; recommend **in-customer-boundary first** (sell inside the customer's existing ATO) while QuarkShield's own FedRAMP is in flight (6–12 month marathon).

### Worked margin checks (instance fee + representative fleet)

| Region | Example | Revenue | Cost | **Gross margin** |
|---|---|---|---|---|
| India | $15k + 100 × $360 | $51,000 | $12.7k | **75%** |
| EMEA | $24k + 100 × $550 | $79,000 | $14.0k | **82%** |
| Gov in-boundary | $36k + 100 × $625 | $98,500 | $18.0k | **82%** |
| Gov own-FedRAMP | $90k + 250 × $625 | $246,250 | $58.0k | **76%** |

All clear the **75% target floor**; smaller fleets lean on the instance fee, larger fleets on per-endpoint — both stay healthy.

---

## 8. Reconciling seat price with the sovereign instance cost model

The two models are deliberately consistent:

1. **Shared platform** amortizes one fixed infra cost across all tenants → per-seat price can fall to **$400** at Enterprise with ~90% infra margin, and the customer pays **no instance fee**.
2. **Sovereign instance** cannot amortize — each region is a real dedicated cost. The **Instance Fee** recovers that fixed per-region cost (and is sized so even a small fleet clears margin); the **per-endpoint base rises to $480** (+20% over shared Enterprise) to reflect dedicated operation; the **regional multiplier** then tunes for local cost/compliance/market.
3. So a buyer's choice is explicit: **shared = cheaper per seat, no residency**; **sovereign = instance fee + richer per-seat, full residency**. The $480 base sits just above the shared Enterprise $400, so there's no arbitrage where a large shared fleet would be cheaper to run as sovereign — the instance fee keeps sovereign correctly priced as the premium, residency-driven option.
4. **Margin target is uniform (~75%+ at the instance level, ~90% infra on shared seats)**, so discounting one model never undercuts the other.

---

## 9. Federal vs commercial differences

| Dimension | Commercial | Federal / Gov |
|---|---|---|
| Deployment | Shared multi-tenant SaaS | **Dedicated sovereign instance** (GovCloud, in-boundary first) |
| Primary buying reason | Track 2 scanning + drift | **Track 1 OSCAL compliance** (SSP/POA&M, CNSA 2.0, OMB M-26-15) |
| Purchase motion | Self-serve Stripe up to Enterprise; custom above | Contract vehicles (SEWP/GSA/Tradewinds), teaming (e.g. Scalar) |
| Term | Monthly or annual | Annual + option years; multi-year preferred |
| Per-seat | $400–$600 shared ladder | $625/endpoint (×1.30) + instance fee |
| Trial | 14-day self-serve | Pilot/PoC (scoped, time-boxed), not self-serve |
| Compliance engines | Cross-sell FedMitigate | Cross-sell FedMitigate (CMMC/FedRAMP) |
| AI | QS Copilot (cloud) | QS Copilot **offline/SCIF/air-gapped** |

Federal pricing is never below the commercial Enterprise effective rate; the Gov multiplier and instance fee are a floor, not a ceiling.

---

## 10. Key pricing decisions (summary)

1. **Unit = 1 managed endpoint**, recurring, deduped by `hardware_uuid`; integrations/connectors are gated, never metered.
2. **Four editions:** Entry $3k/5, Scale $25k/50, Enterprise $100k/250 (annual), + custom Sovereign — all matching code today.
3. **Built-in volume break:** $600 → $500 → $400/seat/yr, extending to $340/$290/custom beyond 250, floor $250.
4. **Annual default (~17% off monthly); 2yr +5%, 3yr +10%** off annual, price-protected for term.
5. **Track 2 = base in every edition; Track 1 OSCAL = included at Enterprise/Gov, paid add-on (+$150/seat) at Scale.**
6. **Sovereign = Instance Fee + ($480 base × regional multiplier)**; cost+margin, ~75%+ margin floor; AWS GovCloud; in-boundary-first for Gov.
7. **Shared vs sovereign reconcile** via the instance fee + $480 base so sovereign is always the correctly-priced premium, residency-driven option.

---

## 11. Open questions (need your decision)

1. **Track 1 gating gap:** OSCAL routes are ungated in code. Approve building `requireComplianceEntitlement` and the Scale "Compliance add-on" SKU? Until then Track 1 is free to all tiers — ship the gate, keep it free deliberately, or price Track 1 differently?
2. **Compliance add-on price:** is **+$150/seat/yr (min 25 seats)** at Scale the right upsell, or should Track 1 be Enterprise-only (cleaner, fewer SKUs)?
3. **Volume-break floors:** confirm $340 / $290 / $250 marginal rates above 250 seats — or hold a firmer floor?
4. **Multi-year discounts:** confirm 2yr +5% / 3yr +10% off annual.
5. **Sovereign instance fees & multipliers:** confirm India $15k/×0.75, EMEA $24k/×1.15, APAC $24k/×1.10, Gov $36k (boundary) / $90k (own-FedRAMP) /×1.30 — carried from the regional pricing draft.
6. **India local pricing (×0.75):** keep local-market discount or move to global parity?
7. **Gov FedRAMP cost:** absorb into base (in-boundary-first) or pass the ~$40k/yr amortization through as the $90k instance fee once we own our ATO?
8. **Base per-endpoint for sovereign = $480** (+20% over Enterprise $400) — right premium, or anchor to a different number?
9. **Three tier vocabularies** (`entry/growth/enterprise` vs `partner/corporate/corp` vs plan key `entry/scale/enterprise`) coexist in code. Not a pricing blocker, but worth normalizing before we publish a price list — flag for an engineering cleanup?

---

## 12. Cost model & 30%-margin floor rate card

> **These are bottom-up planning estimates, not from AWS/Stripe invoices.** Swap in actuals as you get them. Assumptions: shared-platform AWS infra amortized across installed base + **$5/seat/yr** marginal ingest/storage; blended loaded labor **$90–100/hr**; Stripe **2.9% of ACV**; GovCloud ≈ **+40%** on infra and **single-tenant (no amortization)**. "Margin" = `(price − fully-loaded COGS) / price`. The 30% floor price = `COGS ÷ 0.70`.

### 12.1 Fully-loaded COGS per commercial edition (AWS commercial, shared multi-tenant)

| Cost line (annual) | Entry (5) | Scale (50) | Enterprise (250) |
|---|--:|--:|--:|
| AWS infra (shared alloc + $5/seat marginal; integrations/subdomain/2FA) | $100 | $550 | $2,000 |
| QS Copilot LLM inference | — | — | $1,500 |
| Payment processing (Stripe 2.9% of ACV) | $87 | $725 | $2,900 |
| Support / customer success (loaded labor) | $180 | $1,080 | $6,000 |
| Crypto-intelligence content updates (alloc) | $80 | $500 | $1,800 |
| Security & compliance — SOC 2 etc. (alloc) | $60 | $350 | $1,500 |
| Observability / SaaS tooling (alloc) | $40 | $300 | $1,200 |
| G&A allocation | $90 | $500 | $2,500 |
| **Total fully-loaded COGS** | **≈ $640** | **≈ $4,005** | **≈ $19,400** |
| **COGS per seat** | ~$128 | ~$80 | ~$78 |

### 12.2 Current price vs margin (are we profitable? — yes)

| Edition | Current annual price | COGS | **Gross margin today** |
|---|--:|--:|--:|
| Entry | $3,000 | ~$640 | **~79%** |
| Scale | $25,000 | ~$4,005 | **~84%** |
| Enterprise | $100,000 | ~$19,400 | **~81%** |

### 12.3 30%-margin **floor** rate card (minimum defensible price = COGS ÷ 0.70)

| Edition | COGS | **30% floor (bundle)** | **30% floor $/seat/yr** | Current $/seat |
|---|--:|--:|--:|--:|
| Entry (5) | $640 | **$950** | ~$190 | $600 |
| Scale (50) | $4,005 | **$5,720** | ~$114 | $500 |
| Enterprise (250) | $19,400 | **$27,720** | ~$111 | $400 |

**The 30% floor is ~$110–190/seat/yr — well below the current $400–600/seat list.** Entry's floor is highest per-seat because fixed costs spread over only 5 seats. Read this table as a **deal-desk guardrail: never discount a commercial deal below the floor column.** It is not a target — pricing at the floor would forfeit ~80 points of margin.

### 12.4 AWS GovCloud / sovereign (dedicated, single-tenant — the AWS Gov ask)

Gov editions run on **GovCloud, dedicated per customer**, so infra is a real per-instance cost with no amortization. Priced as **Instance Fee + per-endpoint** (§7). Per-endpoint Gov cost is tiny (~$10–15/seat on GovCloud), so **the instance fee, not the seat, is the margin constraint.**

| Gov variant | Fully-loaded instance COGS/yr | Current instance fee | **30% floor fee (COGS÷0.70)** | Verdict |
|---|--:|--:|--:|---|
| In customer boundary (inherited ATO) | ~$24,000 (infra ~$18k + support ~$5k + admin ~$1k) | $36,000 | **$34,300** | ✅ clears 30% (33%) |
| QuarkShield-owned FedRAMP | ~$68,000 (infra ~$58k incl. ~$40k FedRAMP amort + support ~$8k + admin ~$2k) | $90,000 | **$97,100** | ⚠️ **below 30% (24%)** |

**Finding:** the in-boundary Gov instance fee ($36k) holds a 33% margin, but the **own-FedRAMP fee ($90k) only yields ~24%** once support + admin are loaded on top of the $58k infra. Two ways to fix:
1. **Raise own-FedRAMP instance fee to ~$97k** (holds 30% on a single Gov tenant), or
2. **Keep $90k but only once the ~$40k/yr FedRAMP amortization is spread across ≥2 Gov tenants** — at 2 tenants the per-instance FedRAMP load halves (~$20k), instance COGS drops to ~$48k, and $90k clears **~47%**. So $90k is safe *at scale*, thin *for the first Gov logo*.

Gov per-endpoint ($625, ×1.30) clears 30% by a wide margin regardless — leave it.

### 12.5 Takeaways

- Commercial editions run **~79–84% gross margin today** — far above a 30% floor; the floor rate card (~$110–190/seat) is a **discount guardrail**, not a list price.
- Biggest cost drivers that will move these numbers as you scale: **support/CSM labor** (Enterprise) and **payment processing** (flat 2.9% of whatever you charge).
- **Only real margin risk in the whole model is the first own-FedRAMP Gov instance** at the current $90k fee — raise to ~$97k solo, or hold $90k and require a 2-tenant minimum before standing up our own FedRAMP boundary.

---

### Appendix — code references (grounding)

- Plan constants: `server/src/controllers/billingController.ts` (`QUARKSHIELD_PLANS`, trial 14d, term 30/365d, license-key HMAC format).
- Seat enforcement: `server/src/controllers/fleetController.ts` (`seatLimit = max(license.seats, mca_limit)`, 403 at cap; expired-license reject DEF-22).
- Entitlement / gating: `server/src/middleware/auth.ts` (`INTEGRATION_TIERS`, `TIER_RANK`, `requireIntegrationsEntitlement`, BILL-2/BILL-3 central-plane).
- Admin plan writes: `server/src/controllers/adminController.ts` (BILL-2b).
- Track 1 (OSCAL): `server/src/lib/oscal.ts`, `controlCatalog.ts`, `poamExcel.ts`, `server/src/controllers/projectController.ts`, routes `server/src/routes/routes.ts`.
- Schema: `server/src/models/schema.sql` (`admin_clients`, `admin_licenses`, `fleet_tokens`, `fleet_machines`, `projects`, `project_controls`).
- Regional cost+margin source: `QS Scanner/Pricing/QuarkShield-Regional-Pricing.md` (internal, outside repo).
