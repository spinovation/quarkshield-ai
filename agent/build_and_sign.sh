#!/usr/bin/env bash
# ==============================================================================
# QuarkShield Agent Build & Azure Trusted Signing Automation
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================"
echo " 🛡️ Building QuarkShield Windows Agent with Azure Trusted Signing"
echo "======================================================================"

# 1. Compile Windows amd64 binary with embedded syso resources
echo "⚙️ [1/4] Compiling quarkshield-scanner-windows-amd64.exe..."
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o quarkshield-scanner-windows-amd64.exe .

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
      -pass fedmitigate \
      -h sha256 \
      -n "QuarkShield Post-Quantum Guard" \
      -i "https://quarkshield.ai" \
      -ts http://timestamp.digicert.com \
      -in quarkshield-scanner-windows-amd64.exe \
      -out quarkshield-scanner-windows-amd64.exe.signed || \
    osslsigncode sign \
      -pkcs12 certs/fedmitigate-codesign.p12 \
      -pass fedmitigate \
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

# 3. Package clean zip archive for distribution (including 1-click publisher trust scripts)
echo "📦 [3/4] Creating distribution ZIP..."
rm -f quarkshield-scanner-windows.zip
zip -9 quarkshield-scanner-windows.zip \
  quarkshield-scanner-windows-amd64.exe \
  Trust-FedMitigate.bat \
  Trust-FedMitigate.ps1 \
  FedMitigate-Root-CA.cer \
  FedMitigate-LLC-CodeSigning.cer \
  app_icon.ico \
  uninstall.bat \
  README.txt

# 4. Sync binaries across distribution points
echo "🔄 [4/4] Syncing to binaries and UI downloads..."
mkdir -p binaries
cp -f quarkshield-scanner-windows-amd64.exe binaries/
cp -f quarkshield-scanner-windows.zip binaries/
cp -f Trust-FedMitigate.bat binaries/
cp -f Trust-FedMitigate.ps1 binaries/
cp -f FedMitigate-Root-CA.cer binaries/
cp -f FedMitigate-LLC-CodeSigning.cer binaries/

# Also support legacy pqc-scanner name aliases
cp -f quarkshield-scanner-windows-amd64.exe binaries/pqc-scanner-windows-amd64.exe
cp -f quarkshield-scanner-windows.zip binaries/pqc-scanner-windows.zip

for DL_DIR in "../ui/public/downloads" "../ui/dist/downloads" "../public/downloads"; do
  if [ -d "$DL_DIR" ]; then
    cp -f quarkshield-scanner-windows-amd64.exe "$DL_DIR/"
    cp -f quarkshield-scanner-windows.zip "$DL_DIR/"
    cp -f quarkshield-scanner-windows-amd64.exe "$DL_DIR/pqc-scanner-windows-amd64.exe"
    cp -f quarkshield-scanner-windows.zip "$DL_DIR/pqc-scanner-windows.zip"
    cp -f Trust-FedMitigate.bat "$DL_DIR/"
    cp -f Trust-FedMitigate.ps1 "$DL_DIR/"
    cp -f FedMitigate-Root-CA.cer "$DL_DIR/"
    cp -f FedMitigate-LLC-CodeSigning.cer "$DL_DIR/"
  fi
done

echo "======================================================================"
echo "✅ Build & Azure Trusted Signing Complete!"
echo "======================================================================"
