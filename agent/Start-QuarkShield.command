#!/usr/bin/env bash
# =========================================================================
#  QuarkShield Post-Quantum Guard - macOS Launcher
#  Published by FedMitigate LLC
# =========================================================================
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "========================================================================="
echo "  QuarkShield Post-Quantum Guard - FedMitigate LLC"
echo "========================================================================="
echo "Configuring permissions and launching QuarkShield.app..."

# Remove quarantine attribute applied by browser download
xattr -cr QuarkShield.app 2>/dev/null || true
chmod +x QuarkShield.app/Contents/MacOS/quarkshield-scanner 2>/dev/null || true

# Launch application
open QuarkShield.app
echo "QuarkShield Post-Quantum Guard launched in default web browser."
echo "You may close this terminal window."
sleep 2
exit 0
