#!/usr/bin/env bash
# ==============================================================================
# QuarkShield Post-Quantum Guard — Linux Uninstaller
# ==============================================================================
set -e

echo "=================================================="
echo " 🗑️ QuarkShield.ai Post-Quantum Guard Uninstaller"
echo "=================================================="

pkill -f "quarkshield-scanner" 2>/dev/null || true

SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
fi

echo "Removing binaries..."
$SUDO rm -f /usr/local/bin/quarkshield-scanner /usr/local/bin/pqc-scanner "$HOME/.local/bin/quarkshield-scanner" 2>/dev/null || true

echo "Removing desktop shortcuts..."
rm -f "$HOME/.local/share/applications/quarkshield.desktop" "$HOME/Desktop/quarkshield.desktop" 2>/dev/null || true

echo "Removing systemd services..."
if [ -f /etc/systemd/system/quarkshield.service ]; then
  $SUDO systemctl stop quarkshield 2>/dev/null || true
  $SUDO systemctl disable quarkshield 2>/dev/null || true
  $SUDO rm -f /etc/systemd/system/quarkshield.service 2>/dev/null || true
  $SUDO systemctl daemon-reload 2>/dev/null || true
fi

echo "=================================================="
echo "✅ QuarkShield has been completely removed from this Linux system."
echo "=================================================="
