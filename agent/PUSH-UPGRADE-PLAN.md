# QuarkShield — Remote Agent Push-Upgrade: Implementation Plan

**Goal:** Upgrade a deployed agent to a new version *from the admin console* — no manual
re-install on each endpoint. Admin clicks "Push update" → endpoints download the new
signed binary, verify it, swap, and restart.

**Status of the groundwork:** ~90% of the plumbing already exists. The command channel,
per-endpoint version reporting, the signed-binary download host, and service
install/uninstall are all live. The only genuinely new work is: (1) a new command string,
(2) agent-side **verified** download-swap-restart, (3) a server enqueue endpoint, (4) a UI
button + "out-of-date" indicator.

---

## 1. Existing building blocks (reuse, don't rebuild)

| Capability | Where | Notes |
|---|---|---|
| Agent → server command poll | `agent/client.go:267` `FetchAgentCommands` → `POST /api/scan/agent/commands` | Currently decodes only `command`; **drops `details`** |
| Command handlers (3) | `gui.go` worker, `main.go` `--daemon`, `main.go` `--poll` | Each hardcodes `if c == "scan_and_sync"` — no switch |
| Server enqueue (single + bulk) | `fleetController.ts:1162 enqueuePullCommand`, `:1262 enqueueBulkPullCommand` | Hardcode `'scan_and_sync'` |
| Server dispatch | `fleetController.ts:1520 agentFetchCommands` | Already `SELECT id, command, details`; marks `dispatched` |
| Command table | `schema.sql:133` `fleet_commands(command VARCHAR(50), details TEXT)` | **No schema change needed** for `'upgrade'` + `details` |
| Version reporting | agent `client.go:151` → server `fleetController.ts:898` (`fleet_machines.agent_version`) → UI `App.tsx:2232` | One-way; never compared today |
| Signed-binary host | `/downloads/...` (served from container) | Same host releases already publish to |
| Service lifecycle | `ensureBackgroundService` / `removeBackgroundService`, Windows `scheduleSelfDelete` (`main.go:605`) | Reuse for post-swap restart |
| Pull button pattern | `TenantPortal.tsx:1102 handlePullWorkstation` + button `:3717` | Clone for "Push update" |

---

## 2. Design

### 2.1 Command shape
Server enqueues into `fleet_commands`:
- `command = 'upgrade'`
- `details = {"version":"2.3.0","sha256":"<hex>","url":"/downloads/quarkshield-scanner-windows-amd64.exe"}` (JSON string)

The agent resolves the **absolute** download URL as `enrolledServerURL + details.url` and
**ignores any host in `details`** — the binary may only come from the server the agent is
already enrolled to (`EnrollmentConfig.ServerURL`). This prevents a tampered/injected
command from pulling a binary off an attacker host.

### 2.2 ⚠️ Security — this is the critical part
A naive "download a URL and replace myself" turns the fleet channel into remote code
execution. The agent MUST NOT swap an unverified binary. Verification, in order:

1. **SHA-256 pin:** the server supplies the expected `sha256` in `details`; the agent hashes
   the downloaded file and aborts on mismatch.
2. **Signature check (defense in depth):**
   - Windows: `WinVerifyTrust` / `signtool verify /pa` → must chain to the Fedmitigate/Azure cert.
   - macOS: `codesign --verify --deep --strict` + `spctl -a -t exec` (notarized).
   - Linux: verify a detached signature (or at minimum the pinned SHA-256; Linux builds are unsigned today).
3. **Version sanity:** refuse to "upgrade" to the same or an older version unless `details.force=true`.
4. **HTTPS only:** reuse the existing TLS-enforcement guard already in `client.go:139`.

Only after 1–3 pass does the agent perform the swap.

### 2.3 Atomic swap + restart (per-OS)
- Download to a temp file **next to** the current binary (same volume, so rename is atomic).
- Windows: a running `.exe` can't be overwritten in place → rename current to `*.old`,
  rename temp to the real name, re-launch, let the new process delete `*.old`
  (mirror the existing `scheduleSelfDelete` trick in `main.go:605`).
- macOS/Linux: `rename(2)` temp → target (atomic), then re-exec / restart the service via
  the existing service plumbing.
- Report the new `agent_version` on the next sync so the console reflects success.
- **Rollback:** keep `*.old` until the new binary's first successful telemetry sync; if the
  new process fails to start or sync within N minutes, restore `*.old`.

### 2.4 Make the version real
`agent/client.go:151` is a hardcoded `"2.2.1"` literal. Change `AgentVersion` to a build-time
`-ldflags "-X main.AgentVersion=..."` variable (wire into `build_all_and_sign.sh`) so the
server can reliably detect drift and confirm a successful upgrade.

### 2.5 Server: "latest version" + drift
- Add a `LATEST_AGENT_VERSION` constant (or a tiny `agent_releases` row) on the server.
- Compute `outOfDate = semver(agent_version) < LATEST_AGENT_VERSION` in the machines list
  (`fleetController.ts:163`).
- Expose it so the UI can badge out-of-date endpoints and enable the button only for them.

---

## 3. Work breakdown

**Agent (Go)** — the bulk of the effort:
- [ ] `client.go`: return `details` from `FetchAgentCommands` (extend the decode struct).
- [ ] `client.go`: `AgentVersion` → build var.
- [ ] New `agent/updater.go`: `PerformUpgrade(details)` — resolve URL against enrolled server,
      download, SHA-256 check, signature check, atomic swap, restart, rollback guard.
- [ ] Add `case "upgrade": PerformUpgrade(...)` to the 3 handlers (`gui.go`, `main.go` daemon, `main.go` poll).
- [ ] Per-OS swap/restart (windows_*, darwin/linux) — reuse service plumbing.

**Server (TS):**
- [ ] `enqueueUpgradeCommand` (clone `enqueuePullCommand`, `fleetController.ts:1162`) — insert
      `command='upgrade'`, `details=<json>`; **admin-only** auth.
- [ ] `LATEST_AGENT_VERSION` + `outOfDate` in machines list.
- [ ] Route: `POST /api/fleet/machines/:machineId/upgrade` (+ optional bulk `/api/fleet/upgrade-bulk`).

**UI (React):**
- [ ] `handlePushUpgrade` (mirror `handlePullWorkstation`, `TenantPortal.tsx:1102`).
- [ ] "Push update" button next to "Pull Telemetry"; show "Agent v2.2.1 — update available"
      badge when `outOfDate`; bulk "Update all out-of-date" action.

**Release/CI:**
- [ ] `build_all_and_sign.sh` emits the per-binary SHA-256 manifest the server reads into `details`.
- [ ] Wire `-ldflags` version injection.

---

## 4. Effort & risk
- **Effort:** ~1–2 focused days. The channel, version plumbing, download host, and service
  lifecycle already exist; the real code is the verified swap/restart in `updater.go`.
- **Risk:** medium-but-contained. The swap/restart is the only delicate part — mitigated by
  SHA-256 + signature verification, atomic rename, and the `*.old` rollback guard. Mixed-version
  fleets are already safe (telemetry is backward-compatible).
- **Rollout:** ship the *receiving* agent first (so endpoints can accept upgrades), then the
  server/UI to send them. The first push-upgrade can only ever target agents that already
  contain the upgrade handler — so this version (the one that adds it) must still be installed
  the old way once; every version after can be pushed.

---

## 5. Relationship to the threat-modeling feature — no impact
The "threat modeling" in the product is **not** a feature that touches the agent, the command
channel, or the CBOM pipeline:
- `aiController.ts` (STRIDE etc., ~line 975) is **static knowledge content the AI assistant
  returns in chat** — it does not read agent data or the command channel.
- The `threatModel` object in `adminController.ts:2508/2576` is just inline fields in the
  **`/api/probe`** (agentless server-side TLS probe) JSON response — a separate code path from
  both the agent remediation (`recommender.go`) and the upgrade channel.

Neither consumes the agent's `quantumThreat`/`explainer`/`recommendation` fields we edited in
the 2.2.1 remediation work, and neither interacts with `fleet_commands`. **Push-upgrade and the
threat-modeling feature are orthogonal — building one does not affect the other.**

*(Minor consistency note, not a blocker: the `/api/probe` response hardcodes
`shorsRisk: 'Signature Forgery Risk …'`. It's accurate wording, but it's a second, parallel
place threat text lives. If you ever want one source of truth for threat phrasing, that probe
object is the other spot to align — unrelated to this plan.)*
