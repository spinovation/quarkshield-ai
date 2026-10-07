# QuarkShield Agent — Signed Release Checklist

Reusable checklist for cutting a signed Windows / macOS / Linux agent build and
publishing it to the download host. **This release: v2.1.0 → v2.2.0** (scanner
classification-accuracy + trust-anchor + remediation-messaging fixes).

---

## 0. Pre-flight
- [ ] Land the code on `main`:
  ```bash
  git checkout main && git merge fix/scanner-accuracy-and-privacy
  ```
- [ ] Clean build on all targets:
  ```bash
  cd agent && for os in windows linux darwin; do GOOS=$os GOARCH=amd64 go build -o /dev/null ./...; done && GOOS=windows go vet ./...
  ```
- [ ] Confirm the console (server+UI) is already deployed (the display fixes). The agent build only carries the agent-side fixes.

## 1. Version bump
- [ ] `agent/client.go` → `AgentVersion: "2.2.0"` (currently 2.1.0).
- [ ] Bump the installer version in `agent/installer/quarkshield.iss` (AppVersion) to match.
- [ ] Commit the bump.

## 2. Build + sign the binaries
- [ ] Run the master build+sign script from the repo root:
  ```bash
  ./build_all_and_sign.sh
  ```
  (produces `quarkshield-scanner-{darwin-arm64,darwin-amd64,darwin-universal,linux-amd64,linux-arm64,windows-amd64.exe}` in `agent/binaries/`)
- [ ] **macOS notarize** (if not done by the script): `./notarize_build.command`
  - Apple ID **sridhargs@yahoo.com**, team **4ADVSK467Z**, the **19-char app-specific password** (enter once — double-paste = 38 chars = 401).
  - A **403 "required agreement missing"** → accept the current Apple Developer Program License Agreement at developer.apple.com, then re-run.
- [ ] **Windows Azure code-signing** on `quarkshield-scanner-windows-amd64.exe`.
- [ ] Linux: no signing (plain build is fine).

## 3. Windows installer
- [ ] Rebuild `QuarkShield-Setup.exe` from `agent/installer/quarkshield.iss` (Dockerized Inno Setup) with the **signed** windows binary embedded.
- [ ] Azure-sign the `QuarkShield-Setup.exe` itself.
- [ ] (Also refresh `QuarkShield-macOS.dmg` if you ship the DMG.)

## 4. Verify signatures locally (before publishing)
- [ ] macOS: `codesign -dv --verbose=4 agent/binaries/quarkshield-scanner-darwin-arm64` and `spctl -a -vvv -t install <dmg>` (Gatekeeper pass).
- [ ] Windows: `signtool verify /pa /v QuarkShield-Setup.exe` (valid chain to FedMitigate CA).
- [ ] Sanity: each new binary contains the expected strings
  ```bash
  strings agent/binaries/quarkshield-scanner-windows-amd64.exe | grep -i "Get-TlsCipherSuite"   # P1 Schannel fix present
  ```

## 5. Publish to the download host
> `/downloads` is served from the CONTAINER path `/app/agent/binaries` (Dockerfile COPY), **not** a host volume — so you MUST rebuild the container (`deploy.sh`) after updating binaries.
- [ ] Push binaries:
  ```bash
  rsync -avz agent/binaries/ root@13.140.40.99:/opt/desktop-pqc-scanner/agent/binaries/
  ```
- [ ] Rebuild + restart the console container:
  ```bash
  ssh root@13.140.40.99 'cd /opt/desktop-pqc-scanner && ./deploy.sh'
  ```

## 6. Verify the downloads are current
- [ ] Sizes/dates on `https://quarkshield.ai/downloads/` match the freshly built binaries.
- [ ] Download each platform binary and confirm it runs / reports `2.2.0`.
- [ ] Confirm the website download buttons point at the new artifacts (watch for the stale `QuarkShield-Setup.exe` link noted earlier).

## 7. Smoke test on a real endpoint (the important part — prove the P1 fixes)
Run the new agent on a **Windows** box and confirm in the console:
- [ ] **No Schannel false positives** — 3DES/TLS1.0/1.1/SSL2/3 only appear if actually enabled (cross-check with `Get-TlsCipherSuite` and the Protocols registry).
- [ ] **Cert assets show the full subject + thumbprint** in the path (verify one in `certmgr.msc`).
- [ ] **ECDSA roots show the real curve size** (e.g. ECDSA-256/384), not `ECDSA-2048`.
- [ ] **Trust-store roots read "Trust Anchor (informational)," low risk** — recommendation says *inventory/awareness*, NOT "revoke & re-key."
- [ ] **Expired certs** are downgraded + annotated ("EXPIRED on … no active exposure").
- [ ] The **Inspect → verification command runs** (no `certutil -dump` ERROR_FILE_NOT_FOUND).
- [ ] Repeat a quick check on **macOS** and **Linux** (trust-anchor framing on `/etc/ssl/certs` and system-root keychain).

## 8. Fleet rollout
- [ ] Existing endpoints: the persistent daemon updates on its schedule, or re-run the installer / `install.sh`. Trigger a **Pull** from the console to refresh sooner.
- [ ] After each endpoint re-scans, old bogus rows (ECDSA-2048, Schannel FPs, truncated names) are **overwritten** with corrected data.

## 9. Post-release verification
- [ ] Spot-check the console: vulnerable counts look sane (trust anchors no longer inflate "critical"), DigiCert/Thawte roots show full names + thumbprints, no phantom registry paths.
- [ ] Run a couple of the new remediation commands from a prospect's perspective (they're being checked via AI) — confirm they execute and read accurately.

## 10. Rollback
- [ ] Keep the previous signed binaries (tag `v2.1.0`) available; if a regression appears, `rsync` the old binaries back + `deploy.sh`. Agent telemetry is backward-compatible, so mixed-version fleets are safe during rollout.

---
*Owner: FedMitigate LLC. Build host: local macOS (signing creds there). Download host/console: VPS 13.140.40.99.*
