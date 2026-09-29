# QuarkShield Windows Installer (Inno Setup)

Turns the portable `quarkshield-scanner-windows-amd64.exe` into a proper installed
app: copies it to `Program Files\QuarkShield\`, adds a Start-Menu entry (and
optional Desktop icon + auto-start), registers a clean uninstaller, drops a
`.managed_install` marker (so the agent doesn't self-create duplicate shortcuts),
and launches the local dashboard after install.

Output: `QuarkShield-Setup.exe` → published at
`https://quarkshield.ai/downloads/QuarkShield-Setup.exe` (the website's primary
Windows download; the portable `.exe` and CLI `.zip` remain as alternatives).

## Recommended: build via the main pipeline (macOS/Linux/Windows)

`build_all_and_sign.sh` now compiles **and signs** the installer automatically as
part of the Windows stage, provided **Docker is running**. It compiles the
`.iss` inside the `amake/innosetup` image (Wine + Inno Setup bundled), then signs
the resulting setup exe with Azure Trusted Signing, and syncs it into every
download directory. No Windows box or system-wide Wine required.

```
./build_all_and_sign.sh          # installer built + signed + synced with everything else
```

If Docker is absent, the step is skipped cleanly (the portable `.exe`/`.zip`
still ship) and prints a warning.

## Manual build (standalone)

### Option A — Docker (any OS with Docker)
From `agent/`:
```
docker run --rm --platform linux/amd64 -v "$PWD:/work" amake/innosetup \
  /DMyAppVersion=1.0.0 installer/quarkshield.iss
```
Output: `agent/installer/Output/QuarkShield-Setup.exe`

### Option B — native Windows
Install **Inno Setup 6** (https://jrsoftware.org/isdl.php → `ISCC.exe`), then from
`agent/installer/`:
```
ISCC.exe /DMyAppVersion=1.0.0 quarkshield.iss
```

Prerequisites either way: the **signed** `agent/quarkshield-scanner-windows-amd64.exe`
(build + Azure-sign it first) and `agent/app_icon.ico` (already in the repo).

## Sign the installer (if built manually)
So the installer itself shows "Fedmitigate LLC" rather than "Unknown Publisher":
```
python3 ../sign_azure.py Output/QuarkShield-Setup.exe
```
(A local `osslsigncode verify` on macOS reports a chain error because the Mac
trust store lacks Microsoft's CS root — this is cosmetic; Windows verifies fine.)

## Publish
```
cp Output/QuarkShield-Setup.exe ../binaries/QuarkShield-Setup.exe
# then rsync + ./deploy.sh
```

## SmartScreen note
The installer is Authenticode-signed, so it shows the verified publisher, but
Microsoft SmartScreen "reputation" builds separately with download volume. Early
downloads may still see an "unrecognized app" prompt until reputation accrues (an
EV certificate would grant instant reputation).
