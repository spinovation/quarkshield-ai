#!/usr/bin/env bash
# ==============================================================================
# QuarkShield Agent Build & Azure Trusted Signing Automation
# ==============================================================================
set -e
# The agent's offline license check is only meaningful when a PRIVATE signing
# secret is compiled in; the default in license.go is public. Require it.
if [ -z "${LICENSE_SIGNING_SECRET:-}" ] || [ "${#LICENSE_SIGNING_SECRET}" -lt 32 ]; then
  echo "❌ LICENSE_SIGNING_SECRET must be set (>=32 chars) and match the server's value before building release binaries." >&2
  exit 1
fi
GO_LDFLAGS="-s -w -X main.LicenseSigningSecret=${LICENSE_SIGNING_SECRET}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================"
echo " 🛡️ Building QuarkShield Windows Agent with Azure Trusted Signing"
echo "======================================================================"

# 0. Regenerate the Windows resource (.syso) so the exe embeds the CURRENT app_icon.ico.
#    The .syso files are gitignored and NOT committed, and `go build` links whatever
#    .syso happen to be on disk — so without this step a Windows build would ship a stale
#    (or default Go) icon. goversioninfo rebuilds all four arch resources from versioninfo.json
#    (IconPath: app_icon.ico). Skip gracefully if the tool isn't installed.
if command -v goversioninfo >/dev/null 2>&1; then
  echo "🎨 [0/4] Embedding app icon into Windows resources (goversioninfo)..."
  goversioninfo -platform-specific -icon=app_icon.ico versioninfo.json
else
  echo "   ⚠️ goversioninfo not found — Windows exe may keep a stale/default icon."
  echo "      Install it:  go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest"
fi

# 1. Compile Windows amd64 binary with embedded syso resources
echo "⚙️ [1/4] Compiling quarkshield-scanner-windows-amd64.exe..."
GOOS=windows GOARCH=amd64 go build -ldflags="$GO_LDFLAGS" -o quarkshield-scanner-windows-amd64.exe .

# 2. Authenticode Sign via Azure Trusted Signing or local FedMitigate PKI fallback
echo "🔑 [2/4] Authenticode Signing (FedMitigate LLC)..."
SIGNED=false
if [ -f ".env.signing" ] || [ -n "$AZURE_CLIENT_ID" ]; then
  echo "   Attempting Azure Trusted Signing..."
  if python3 sign_azure.py quarkshield-scanner-windows-amd64.exe; then
    SIGNED=true
  fi
fi

if [ "$SIGNED" = false ]; then
  echo "   Signing via FedMitigate PKI Code Signing certificate + DigiCert RFC3161 Timestamp..."
  rm -f quarkshield-scanner-windows-amd64.exe.signed
  if command -v osslsigncode >/dev/null 2>&1; then
    osslsigncode sign \
      -pkcs12 certs/fedmitigate-codesign.p12 \
      -pass "${FEDMITIGATE_P12_PASSWORD:?set FEDMITIGATE_P12_PASSWORD for local signing}" \
      -h sha256 \
      -n "QuarkShield Post-Quantum Guard" \
      -i "https://quarkshield.ai" \
      -ts http://timestamp.digicert.com \
      -in quarkshield-scanner-windows-amd64.exe \
      -out quarkshield-scanner-windows-amd64.exe.signed || \
    osslsigncode sign \
      -pkcs12 certs/fedmitigate-codesign.p12 \
      -pass "${FEDMITIGATE_P12_PASSWORD:?set FEDMITIGATE_P12_PASSWORD for local signing}" \
      -h sha256 \
      -n "QuarkShield Post-Quantum Guard" \
      -i "https://quarkshield.ai" \
      -in quarkshield-scanner-windows-amd64.exe \
      -out quarkshield-scanner-windows-amd64.exe.signed
    
    if [ -f quarkshield-scanner-windows-amd64.exe.signed ]; then
      mv quarkshield-scanner-windows-amd64.exe.signed quarkshield-scanner-windows-amd64.exe
      echo "   ✓ Authenticode signed successfully!"
    fi
  else
    echo "   ⚠️ osslsigncode not installed, skipping local signature"
  fi
fi

# 3. Package clean zip archive for distribution.
#    NOTE: the FedMitigate self-signed root CA + Trust-FedMitigate.* scripts are
#    deliberately NOT bundled anymore — the exe is now signed by Azure Trusted
#    Signing (publicly trusted Microsoft chain), so asking users to install a
#    private root CA is obsolete and a trust red flag. Do not re-add them.
echo "📦 [3/4] Creating distribution ZIP..."
rm -f quarkshield-scanner-windows.zip
zip -9 quarkshield-scanner-windows.zip \
  quarkshield-scanner-windows-amd64.exe \
  app_icon.ico \
  uninstall.bat \
  README.txt

# 4. Sync binaries across distribution points
echo "🔄 [4/4] Syncing to binaries and UI downloads..."
mkdir -p binaries
cp -f quarkshield-scanner-windows-amd64.exe binaries/
cp -f quarkshield-scanner-windows.zip binaries/

# Also support legacy pqc-scanner name aliases
cp -f quarkshield-scanner-windows-amd64.exe binaries/pqc-scanner-windows-amd64.exe
cp -f quarkshield-scanner-windows.zip binaries/pqc-scanner-windows.zip

for DL_DIR in "../ui/public/downloads" "../ui/dist/downloads" "../public/downloads"; do
  if [ -d "$DL_DIR" ]; then
    cp -f quarkshield-scanner-windows-amd64.exe "$DL_DIR/"
    cp -f quarkshield-scanner-windows.zip "$DL_DIR/"
    cp -f quarkshield-scanner-windows-amd64.exe "$DL_DIR/pqc-scanner-windows-amd64.exe"
    cp -f quarkshield-scanner-windows.zip "$DL_DIR/pqc-scanner-windows.zip"
  fi
done

echo "======================================================================"
echo "✅ Build & Azure Trusted Signing Complete!"
echo "======================================================================"
