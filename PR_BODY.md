## Summary

Production security hardening across the server, Go agent, React UI and infra. Closes every open finding from the 2026-10-07 review (see `CODE_REVIEW_2026-10-07.md`) plus everything a three-agent re-review of the diff surfaced, each verified by hand.

**Server:** server-side session revocation; change-password requires a session and uses bcrypt everywhere; destructive admin routes limited to superadmin/root_admin; tenant user and operator management is create-only with role allow-lists and self-protection; 2FA re-enrol requires a code; cross-tenant leaks closed in reports, CI gate, git scan cache, SBOM and AI copilot; PKI connector SSRF guard covers config endpoints; probe/proxy connect to the pre-verified IP; git clone hardened; telemetry-supplied commands no longer pasted into the downloadable fix script; fabricated SBOM template no longer seeded into real tenants; transactional ingest with caps and cross-tenant collision guard; per-concern rate limits with token-keyed agent buckets; CORS no longer reflects any origin in production; public seeded license keys revoked on boot; demo rows and hardcoded customer credentials removed; indexes added.

**Agent:** local API requires the gate token on every method and never returns it; destructive endpoints POST-only; offline license activation refused for public-secret builds; bounded symlink-aware file reads; owner-only permissions with migration; strict server URL validation on every token-bearing request.

**UI:** no privilege inferred from email strings; session synced from `/api/auth/me`; JWT no longer stored in web storage; logout revokes server-side; login only on explicit success; all fabricated fallback data removed; client-asserted admin headers removed.

**Infra:** deploy script generates secrets and refuses placeholders; `DB_PASSWORD` required; container runs as `node` with a runtime-generated TLS key; `.env` no longer mounted; firewall unit fails safe; systemd token in a 0600 EnvironmentFile; signing scripts no longer load the server `.env`.

## Verification

- `server`: `tsc` clean; `npm run test:security` 28/28
- `ui`: `tsc` clean
- `agent`: `go build`, `go vet`, `go test` clean on darwin/linux/windows
- `docker compose config` valid

## Before deploying (read)

- Seeded/public license keys are revoked on first boot: re-issue tokens from the admin console and re-enroll agents.
- `DB_PASSWORD`, `TWO_FACTOR_ENC_KEY`, `CONNECTOR_ENC_KEY` must be set on existing servers.
- Release agent builds require `LICENSE_SIGNING_SECRET` (and `FEDMITIGATE_P12_PASSWORD` for local signing).
- Logout now ends sessions on all devices.

## Not fixed in code (needs a decision)

- Distributing the self-made "FedMitigate" root CA to customers; replace with a real code-signing certificate and retire the Trust-* scripts.
- 32-bit truncated license signature (format migration).
- Schema applied on every boot with errors swallowed (needs a migration tool); unencrypted on-host backups.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
