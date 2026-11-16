# Console push-upgrade — design and operating notes

A tenant admin can update out-of-date agents from the console instead of
re-installing them. First push-capable agent release: **2.3.2**
(`MIN_PUSH_UPGRADE_VERSION` in `server/src/lib/agentRelease.ts`). Older agents
ignore the command, so they must be installed once by hand; every later release
can be pushed.

## Trust model

An `upgrade` command makes an agent replace and re-run its own executable — on
Linux as root. The channel therefore must not be able to deliver anything except
a genuine QuarkShield release, **even if the console, its database, or the
download directory is compromised**. The server is a courier, not an authority.

| # | Check (agent side, in order) | Defeats |
|---|---|---|
| 1 | Ed25519 signature over the exact manifest bytes, verified against the key compiled into the agent (`agent/release_keys.go`) | forged or altered commands; a compromised server/DB |
| 2 | Manifest version must be newer; `force` allows the same version, never an older one | replaying an old signed release |
| 3 | Download only from the server the agent already polls, HTTPS, plain file under `/downloads/`, no redirects | pointing the agent at another host |
| 4 | SHA-256 from the signed manifest, checked while streaming | a swapped binary in the download directory |
| 5 | OS publisher signature: Authenticode `CN=Fedmitigate LLC` issued by a Microsoft ID Verified CA (Windows); Developer ID team `4ADVSK467Z`, plus Gatekeeper for the app (macOS) | defence in depth if the release key leaks |
| 6 | Self-test: the staged build must run and report exactly the manifest version | a build that cannot start; manifest/binary mismatch |

The release **private key never leaves the release machine**
(`agent/.env.release-key`, git-ignored). It is not on the server.

Local opt-out, honoured even for a valid command: `QUARKSHIELD_DISABLE_UPGRADE=1`
or an `upgrade.disabled` file next to the enrollment config.

Known limit: an attacker who controls the server could push a genuine release
that is newer than the installed one but not the latest. They cannot push
anything unsigned or older.

## Flow

1. `build_all_and_sign.sh` writes `agent-manifest.json` (version + path, SHA-256
   and size of each build) and signs it → `agent-manifest.json.sig`. It refuses
   to do so unless the Windows exe is Azure-signed, the macOS app is notarized,
   and the built binary reports the release version. Both files are published
   with the binaries.
2. Console: `GET /api/fleet/machines` annotates each machine with
   `latestVersion`, `upgradeState` (`current` / `pushable` / `manual` /
   `unsupported` / `unknown`) and `upgradeInFlight`.
3. A tenant admin clicks **Update agent** (one endpoint) or **Update agents (N)**
   → `POST /api/fleet/machines/:id/upgrade` or `POST /api/fleet/upgrade-bulk`
   (`requireTenantAdmin`, audit-logged as `fleet_upgrade_enqueue`). The server
   queues an `upgrade` command whose `args` are the manifest and signature,
   verbatim.
4. The agent picks it up at its next poll (≤ 2 min), runs checks 1–6, then:
   - renames the current build to `*.old` and the new one into place
     (Linux/Windows: the executable; macOS app: the whole `.app` bundle, so its
     signature and notarization stay intact);
   - starts a watchdog from the previous build and restarts into the new one.
5. The new build confirms the upgrade on its first successful authenticated poll
   and deletes `*.old`. If no confirmation arrives within 10 minutes the
   watchdog restores the previous build and restarts it.
6. The next telemetry carrying the new version closes the command
   (`status = completed`).

A daemon whose executable is replaced by another process (the GUI applying the
upgrade, a rollback, a manual re-install) restarts into it on its next tick.

## Platform notes

- **Linux**: the systemd unit is sandboxed (`ProtectSystem=full`), so the daemon
  can only swap its binary if it lives in a directory the unit allows.
  `install-linux.sh` now installs to `/opt/quarkshield/` (linked from
  `/usr/local/bin`) with `ReadWritePaths=/opt/quarkshield`. Hosts installed with
  an older installer refuse a push cleanly ("cannot create staging directory");
  re-run the installer once. Under systemd the watchdog runs as a transient unit
  (`systemd-run`) so a crash-looping new build cannot take it down.
- **macOS**: an agent running from `QuarkShield.app` takes the notarized app
  archive (`darwin/app`); a bare binary takes `darwin/<arch>`. The user needs
  write access to the folder holding the app (admins have it for `/Applications`).
- **Windows**: the daemon is a per-user Scheduled Task. A per-machine install in
  `Program Files` is not writable by it, so the push is refused cleanly.

## Release-key handling

- Back up `agent/.env.release-key` somewhere offline. If it is lost, agents can
  only be upgraded by re-installing.
- Rotation: add the new public key to `releasePublicKeys`, ship one release
  signed with the old key, then sign with the new key and drop the old one.
- Tooling: `go run ./tools/relsign keygen|pubkey|sign|verify` (run from `agent/`).

## Test coverage

- `agent/updater_test.go`: signature, version rules, URL rules, hash, archive
  extraction, confirmation, macOS publisher check (against real signed code).
- `server/test/agentRelease.test.ts`: manifest loading and upgrade-state logic.
- End to end on Linux under **systemd** (container, the real installer and unit
  file, real binaries, throwaway key, rollback window shortened to 45 s): swapped
  binary refused, untrusted signature refused, broken release rolled back while
  the service was restarted mid-window, good release upgraded and confirmed with
  the service's main pid unchanged, watchdog running as its own transient unit
  outside the service's control group, uninstaller, desktop-host install.
- End to end through the **real console** (local server and database, tenant
  admin in a browser): "Update agent" and "Update agents (N)" queue the command,
  the endpoint upgrades, and the console shows the new version at the next poll.
- macOS **app-bundle swap** in an isolated folder (test builds with the publisher
  check stubbed, because only a notarized build can pass it): broken release
  rolled back and relaunched, good release upgraded and confirmed.
- macOS **publisher check** against the published, notarized 2.3.1 app archive:
  downloaded, hash-checked, unpacked, accepted by `codesign` and Gatekeeper, then
  correctly refused at the self-test (2.3.1 predates `--agent-version`).
- **Not yet exercised**: the Windows path (compiles only); one continuous macOS
  run with a notarized 2.3.2+ build (publisher check and swap were tested
  separately); a launchd-managed macOS agent; the manifest step of a full signed
  release build.
- **Known limitation**: the watchdog does not survive a reboot. A host that
  reboots inside the 10-minute window keeps the new build; if that build cannot
  reach the server it is not rolled back automatically.
