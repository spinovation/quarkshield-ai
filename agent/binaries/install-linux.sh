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

# ---------------------------------------------------------------------------
# DEF-39: install the persistent daemon as a systemd service so admin "Pull
# Telemetry" / bulk pulls and scheduled syncs run continuously (no GUI needed).
# Token comes from $1 or $QS_TOKEN; without one, we skip and print how to enable.
# ---------------------------------------------------------------------------
QS_TOKEN="${1:-${QS_TOKEN:-}}"
if command -v systemctl >/dev/null 2>&1 && { [ "$(id -u)" -eq 0 ] || [ -n "${SUDO}" ]; }; then
  if [ -n "$QS_TOKEN" ]; then
    EXEC="$INSTALL_DIR/quarkshield-scanner --daemon --server https://quarkshield.ai --token $QS_TOKEN"
  else
    # No token on the command line — the daemon will read the enrollment config
    # written by a prior `quarkshield-scanner` run for this user.
    EXEC="$INSTALL_DIR/quarkshield-scanner --daemon --server https://quarkshield.ai"
  fi
  echo "🛠️  Installing persistent daemon (systemd service quarkshield)..."
  $SUDO tee /etc/systemd/system/quarkshield.service >/dev/null << EOF
[Unit]
Description=QuarkShield Post-Quantum Guard Cryptographic Auditor (persistent daemon)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$EXEC
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now quarkshield.service 2>/dev/null && \
    echo "✓ Daemon enabled & started (journalctl -u quarkshield -f to watch)." || \
    echo "⚠️ Service installed but not started — enroll first, then: $SUDO systemctl restart quarkshield"
  if [ -z "$QS_TOKEN" ]; then
    echo "   ℹ️  No token provided. Enroll once (quarkshield-scanner --token <TOKEN> --quick --register),"
    echo "      then: $SUDO systemctl restart quarkshield"
  fi
else
  echo "ℹ️  systemd not available or not root — skipping persistent-daemon install."
  echo "    To run the daemon manually: quarkshield-scanner --daemon --token <TOKEN>"
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
