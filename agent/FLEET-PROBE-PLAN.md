# Fleet Probe — Feature Spec

**Status:** proposed (not started). Written 2026-10-08.
**Owner:** Ganapati Sridhar
**Related:** `agent/PUSH-UPGRADE-PLAN.md` (shares the same console→agent command channel), Threat & Risk Graph (consumes the output).

---

## 1. Why

The Threat & Risk Graph draws connectivity arrows (`connects_to`, `serves`) from **endpoints**, and endpoints come from only two inputs today:

- **R1** — PQC proxy upstreams
- **R3** — agent `network_probe` findings (an active outbound TLS handshake to a target)

Agents currently collect **inventory** (certs, keys, SBOM, CBOM — *what is on each host*) but not **topology** (*what each host connects to*). Confirmed on production for the Spinovation tenant: **443 certificate findings but 0 `network_probe` findings**, so there is nothing for hosts or their 443 certs to attach to, and the architecture view looks disconnected. This is accurate, not a bug — the connectivity data simply isn't being collected.

`ProbeEndpoint(host:port)` already exists in the agent (`agent/prober.go:16`) and emits `network_probe` findings, but it can only be invoked **locally**, one target at a time:

- CLI: `quarkshield-scanner --probe microsoft.com:443` (`agent/main.go:375`)
- Agent dashboard probe box (`agent/gui.go:507`)

**Goal:** let an admin trigger probes from the console against one host, a Workstation Group, or the whole fleet, with a target list — so `network_probe` findings flow back and the graph populates `connects_to` / `serves` arrows from real data.

## 2. What exists today (≈80% of the plumbing)

| Piece | Where | State |
|---|---|---|
| Command queue | `fleet_commands` table; `enqueuePullCommand`, `enqueueBulkPullCommand` (`server/src/controllers/fleetController.ts:1208`, `:1309`) | Works, but **hardcodes `command = 'scan_and_sync'`** (`:1223`) |
| Agent command poll | `FetchAgentCommands` (`agent/client.go:292`) hitting `POST /api/scan/agent/commands` | Works, but returns **bare command strings, no parameters** (`:322` `Commands []struct { Command string }`) |
| Agent dispatch | daemon loop (`agent/main.go:480`) | Only handles `if c == "scan_and_sync"` (`:482`) |
| The probe itself | `ProbeEndpoint` (`agent/prober.go:16`) | Works; emits `network_probe` findings |
| Findings upload | existing sync/report path | Works; would carry probe findings back unchanged |
| Graph consumption | R3/R2 in `server/src/lib/threatGraph/topology.ts` | Works; already keys off `type = 'network_probe'` and `certificate` |

## 3. The gaps (all additive)

1. **Parameterized commands.** The console→agent protocol passes a bare string. It needs to carry a command *type* plus *args* (the probe targets). This is the one shared dependency with push-upgrade.
2. **A `probe` command type** on the server, with enqueue endpoints (single machine + scope) that accept a target list.
3. **A `probe` dispatch on the agent** → run `ProbeEndpoint` per target → attach findings to the next sync.
4. **A console trigger UI** — a "Probe endpoints" action in Fleet Overview (per-host and fleet/group-wide) with a target input.

## 4. Design

### 4.1 Command protocol (shared with push-upgrade)
Evolve `fleet_commands` from a bare command string to a typed, parameterized command:

- Schema (additive, idempotent): `ALTER TABLE fleet_commands ADD COLUMN IF NOT EXISTS args JSONB DEFAULT '{}'::jsonb;` (keep `command` as the type discriminator; existing `'scan_and_sync'` rows keep working with empty args).
- `GET/POST /api/scan/agent/commands` response gains an `args` object per command:
  ```json
  { "commands": [ { "id": "cmd-…", "command": "probe", "args": { "targets": ["api.internal:443","db.internal:5432"] } } ] }
  ```
- Agent `FetchAgentCommands` returns `[]{ Command string; Args map[string]any }` instead of `[]string`. Backward compatible: a missing/empty `args` behaves exactly as today.

### 4.2 Server
- `enqueueProbeCommand(machineId, targets[])` and `enqueueProbeForScope(tenant, {group|all}, targets[])` — mirror the existing pull enqueuers, inserting `command='probe'`, `args={targets}`.
- Routes (behind `requireAuth` + `requireTenantAccess` + `requireTenantAdmin`, same guards as fleet pulls):
  - `POST /api/fleet/machines/:machineId/probe` `{ targets: string[] }`
  - `POST /api/fleet/probe-bulk` `{ group?: string, targets: string[] }`
- **Target validation (critical — see §5):** reject empty, cap count (e.g. ≤ 25/command), require `host:port`, enforce an allow-policy, strip anything that isn't a hostname/IP + port.
- After findings sync back, the existing `rebuildAfter()` ingest hook already rebuilds the tenant's graph — no extra wiring.

### 4.3 Agent
- In the daemon dispatch (`agent/main.go:480`), add:
  ```go
  case "probe":
      for _, t := range cmd.Args.Targets {        // validated server-side, re-validated here
          if findings, err := ProbeEndpoint(t); err == nil {
              collected = append(collected, findings...)
          }
      }
      // include collected network_probe findings in the next sync upload
  ```
- Re-validate targets agent-side (defense in depth): host:port shape, per-command cap, per-run timeout, and honor a local opt-out (see §5). `ProbeEndpoint` already sets a dial timeout.
- **Requires an agent rebuild + re-sign + republish** (the dashboard/handlers are compiled into the binary via `//go:embed`), and endpoints must run the new build. Fits the existing release pipeline (`notarize_build.command`).

### 4.4 UI (console)
- Fleet Overview: a **"Probe endpoints"** action — per-machine (row action) and bulk (toolbar, scoped to All / a Workstation Group).
- A small dialog: target list (textarea, one `host:port` per line), with inline validation and a confirmation showing how many hosts × how many targets will run.
- Surface results: once findings sync, the machine's crypto/CBOM view and the Threat & Risk Graph show the new `network_probe` findings + `connects_to`/`serves` arrows.

### 4.5 Target sourcing
- **Phase 1 (this spec):** admin supplies the target list explicitly. Simple, predictable, auditable.
- **Phase 2 (roadmap P2 — not here):** agent auto-discovers its own outbound connections / listening sockets and proposes targets, so no manual list is needed. Bigger scope; this is the "agent topology collectors" item already on the Threat & Risk Graph roadmap.

## 5. Security (this is the sharp edge)

Driving outbound connections across a fleet from a central console is a powerful capability and must be constrained. Agents already make outbound TLS (local `--probe`), so the *behavior* isn't new — but **fleet-wide, admin-triggered** probing changes the blast radius.

- **Who can trigger:** tenant admins for their own fleet only; enforce `requireTenantAccess` + `requireTenantAdmin`; platform admins may act cross-tenant via the existing super-role path. Never allow a tenant to target another tenant's hosts or arbitrary third parties beyond policy.
- **SSRF / internal recon abuse:** a compromised console account could turn the fleet into a distributed port/host scanner. Mitigate with: a **per-tenant target allow-policy** (optional allowlist of host/CIDR+port the tenant has attested it owns), a hard **per-command target cap**, **per-machine rate limiting** (no more than N probe commands / window), and probing **TLS ports only** (the probe is a TLS handshake, not a general port scan).
- **Agent-side opt-out / guardrails:** honor a local config flag to disable remote probing on sensitive hosts; re-validate every target; enforce a total time budget per command; never probe loopback/metadata endpoints (`169.254.169.254`, etc.) — reuse `isPrivateHost`/SSRF guards already in `server/src/utils/ssrf.ts` and mirror them in the agent.
- **Audit trail:** every enqueued probe command records who, when, which scope, and which targets; results are attributable to the command id. Surface in an admin activity log.
- **Consent / legal:** probing is active, not passive. Document that the admin asserts authorization to probe the listed targets from their own hosts. Keep it opt-in per tenant.
- **No secrets in targets:** targets are host:port only; reject anything with credentials/paths/query strings (don't let a target smuggle data out via a URL).

## 6. Correlation impact (what lights up)

Once `network_probe` findings arrive for a tenant:
- **R3** `connects_to` — host → each probed endpoint (the core connectivity backbone).
- **R2** `serves` — the tenant's existing certificate findings whose DNS names match a probed endpoint now attach to it (for Spinovation: up to 443 certs become eligible to form `serves` arrows).
- Endpoints gain real crypto posture (TLS version, KEM/curve, classical-vs-hybrid) → feeds HNDL/MITM threat rules (TR-04/TR-05) with evidence.

## 7. Phasing & rough effort

| Phase | Scope | Effort (rough) |
|---|---|---|
| 0 | Prove the chain manually: `--probe` 2–3 real endpoints on one host, re-sync, rebuild, confirm arrows | ~0 (ops only) |
| 1 | Parameterized command protocol (server + agent) — the shared channel | S–M |
| 2 | `probe` command type, enqueue endpoints, validation + security guards | M |
| 3 | Agent `probe` dispatch + findings upload; **agent rebuild/sign/publish** | M |
| 4 | Fleet Overview "Probe endpoints" UI (single + scoped) | M |
| 5 | Audit log, rate limits, per-tenant target allow-policy | M |

Phases 1–3 deliver a working end-to-end fleet probe (admin triggers via API, arrows populate). Phase 4 makes it usable in the UI. Phase 5 hardens it for multi-tenant production.

## 8. Overlap with push-upgrade

Phase 1 (parameterized commands) is the **same channel** push-upgrade needs (`agent/PUSH-UPGRADE-PLAN.md`, task_aaa58040): a typed, parameterized command from console → agent, polled on check-in, acted on, and acknowledged. Build the channel once; `probe` and `upgrade` become two command types over it. Recommend sequencing Phase 1 jointly so both features share one protocol, one audit path, and one set of agent-side guards.

## 9. Open decisions (need owner input)

1. **Target policy:** free-form admin target list, or require a per-tenant allowlist of attested host/CIDR+port before any probe runs? (Security vs. friction.)
2. **Trigger scope default:** single host only to start, or allow fleet/group-wide from day one?
3. **TLS-only** probing confirmed (no general TCP port sweep)?
4. **Agent opt-out granularity:** per-host flag, per-group, or tenant-wide kill switch?
5. **Do Phase 1 jointly with push-upgrade**, or ship fleet-probe's own minimal command extension first?

## 10. Test plan (when built)

- Unit: command protocol round-trip (bare `scan_and_sync` still works; `probe` with/without args); target validator (host:port shape, caps, SSRF/loopback rejection).
- Integration: enqueue probe (single + scope) → agent polls → `ProbeEndpoint` runs → findings sync → `rebuildAfter` → `tr_relationships` gains `connects_to`, certs gain `serves`.
- Security: cross-tenant target rejected (403); rate limit enforced; private/metadata targets rejected; non-admin denied.
- Regression: `npm run test:security` (30/30) and threat-graph tests stay green; existing `scan_and_sync` pull unaffected.
