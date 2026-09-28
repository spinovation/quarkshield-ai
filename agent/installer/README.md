# QuarkShield Windows Installer (Inno Setup)

Turns the portable `quarkshield-scanner-windows-amd64.exe` into a proper installed
app: copies it to `Program Files\QuarkShield\`, adds a Start-Menu entry (and
optional Desktop icon + auto-start), registers a clean uninstaller, and launches
the local dashboard after install.

## Prerequisites
- **Inno Setup 6** installed (Windows): https://jrsoftware.org/isdl.php  (provides `ISCC.exe`)
- The **signed** agent exe present at `agent/quarkshield-scanner-windows-amd64.exe`
  (build + Azure-sign it first via `build_all_and_sign.sh`).
- `agent/app_icon.ico` (already in the repo).

> Inno Setup only compiles on **Windows** (or Linux/macOS via Wine). Do this on a
> Windows box or a Windows CI runner — not on the Mac build host.

## Build the installer
From `agent/installer/` on Windows:
```
ISCC.exe /DMyAppVersion=1.0.0 quarkshield.iss
```
Output: `agent/installer/Output/QuarkShield-Setup.exe`

## Sign the installer (so the installer itself shows "Fedmitigate LLC")
Sign the produced setup exe with Azure Trusted Signing, same as the agent:
```
python3 ../sign_azure.py Output/QuarkShield-Setup.exe
```
(Or on Windows, use the Trusted Signing signtool dlib per your Azure setup.)

## Publish
Copy the signed installer into the download set and deploy:
```
cp Output/QuarkShield-Setup.exe ../binaries/QuarkShield-Setup.exe
# then rsync + ./deploy.sh   → served at https://quarkshield.ai/downloads/QuarkShield-Setup.exe
```
Point the website "Download .exe (Installer)" button at `/downloads/QuarkShield-Setup.exe`.

## Note: avoid duplicate Start-Menu shortcuts
The agent currently self-creates a Start-Menu/Desktop shortcut on first run
(`gui_windows.go: createDesktopAndStartMenuShortcuts`). When distributed via this
installer, that would produce a second shortcut. Recommended follow-up: gate that
self-shortcut behavior behind an env/flag (e.g. skip when a
`QUARKSHIELD_INSTALLED=1` marker or an install registry key is present) so the
installer owns shortcut creation. Low-risk code change in the Go agent.
