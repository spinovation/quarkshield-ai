#!/usr/bin/env bash
# =========================================================================
#  QuarkShield Post-Quantum Guard - macOS Trust & Activation Assistant
#  Developer: Ganapati Sridhar (Developer ID: 4ADVSK467Z)
#  Publisher: FedMitigate LLC
# =========================================================================
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "========================================================================="
echo "  🛡️ QuarkShield Post-Quantum Guard - macOS Security & Trust Setup"
echo "  Developer: Ganapati Sridhar (Developer ID: 4ADVSK467Z)"
echo "  Publisher: FedMitigate LLC"
echo "========================================================================="
echo ""

# 1. Clear quarantine attributes applied by browser download
TARGETS=(
  "$DIR/QuarkShield.app"
  "/Applications/QuarkShield.app"
  "$DIR/quarkshield-scanner"
  "$DIR/quarkshield-scanner-darwin-universal"
)

FOUND=0
for APP in "${TARGETS[@]}"; do
  if [ -e "$APP" ]; then
    FOUND=1
    echo "[*] Granting full execution trust to: $APP"
    xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true
    xattr -cr "$APP" 2>/dev/null || true
    chmod +x "$APP/Contents/MacOS/quarkshield-scanner" 2>/dev/null || true
    chmod +x "$APP" 2>/dev/null || true
    spctl --add "$APP" 2>/dev/null || true
    echo "[+] Authorized: $APP"
  fi
done

if [ $FOUND -eq 0 ]; then
  echo "[!] Notice: QuarkShield.app was not detected in this folder or /Applications."
  echo "    Please drag QuarkShield.app into /Applications and double-click this script again."
else
  echo ""
  echo "========================================================================="
  echo "✅ Trust established! QuarkShield is fully authorized to run on macOS."
  echo "========================================================================="
  echo ""
  echo "Starting QuarkShield Post-Quantum Guard..."
  if [ -d "/Applications/QuarkShield.app" ]; then
    open "/Applications/QuarkShield.app"
  elif [ -d "$DIR/QuarkShield.app" ]; then
    open "$DIR/QuarkShield.app"
  fi
fi

sleep 2
exit 0
