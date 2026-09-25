#!/usr/bin/env bash
# ==============================================================================
# QuarkShield Post-Quantum Guard — Linux 1-Click Installer
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=================================================="
echo " 🛡️ QuarkShield.ai Post-Quantum Guard (Linux)"
echo "=================================================="

ARCH="$(uname -m)"
BINARY_SOURCE=""

if [ "$ARCH" = "x86_64" ]; then
  if [ -f "$SCRIPT_DIR/quarkshield-scanner-linux-amd64" ]; then
    BINARY_SOURCE="$SCRIPT_DIR/quarkshield-scanner-linux-amd64"
  elif [ -f "$SCRIPT_DIR/quarkshield-scanner" ]; then
    BINARY_SOURCE="$SCRIPT_DIR/quarkshield-scanner"
  fi
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
  if [ -f "$SCRIPT_DIR/quarkshield-scanner-linux-arm64" ]; then
    BINARY_SOURCE="$SCRIPT_DIR/quarkshield-scanner-linux-arm64"
  elif [ -f "$SCRIPT_DIR/quarkshield-scanner" ]; then
    BINARY_SOURCE="$SCRIPT_DIR/quarkshield-scanner"
  fi
fi

if [ -z "$BINARY_SOURCE" ]; then
  echo "❌ Error: Could not find matching Linux binary for architecture: $ARCH"
  exit 1
fi

INSTALL_DIR="/usr/local/bin"
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    SUDO=""
  fi
else
  SUDO=""
fi

echo "📦 Installing binary to: $INSTALL_DIR/quarkshield-scanner..."
$SUDO cp -f "$BINARY_SOURCE" "$INSTALL_DIR/quarkshield-scanner"
$SUDO chmod +x "$INSTALL_DIR/quarkshield-scanner"

# Install Desktop Entry if GUI environment exists
if [ -n "$XDG_CURRENT_DESKTOP" ] || [ -d "$HOME/.local/share/applications" ]; then
  APP_DIR="$HOME/.local/share/applications"
  mkdir -p "$APP_DIR"
  cat << 'EOF' > "$APP_DIR/quarkshield.desktop"
[Desktop Entry]
Type=Application
Name=QuarkShield Post-Quantum Guard
Comment=Post-Quantum Cryptographic Vulnerability Scanner
Exec=/usr/local/bin/quarkshield-scanner --gui
Icon=security-high
Terminal=false
Categories=Security;System;
EOF
  chmod +x "$APP_DIR/quarkshield.desktop" 2>/dev/null || true
  echo "✓ Desktop application launcher registered."
fi

echo "=================================================="
echo "✅ QuarkShield Linux Agent successfully installed!"
echo "   Command: quarkshield-scanner"
echo ""
echo "🚀 Quick Start:"
echo "   • Launch interactive Web GUI: quarkshield-scanner --gui"
echo "   • Run fast cryptographic audit: quarkshield-scanner --quick"
echo "   • Probe TLS endpoint: quarkshield-scanner --probe <hostname>:443"
echo "   • Export CycloneDX CBOM: quarkshield-scanner --cbom -o cbom.json"
echo "=================================================="
