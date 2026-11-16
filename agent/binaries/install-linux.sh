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

# System-wide installs keep the binary in its own root-only directory and link it
# into PATH. The daemon is sandboxed (ProtectSystem=full → /usr is read-only to
# it), so a console push-upgrade can only swap the binary if it lives in a
# directory the unit explicitly allows: ReadWritePaths=$APP_DIR below.
APP_DIR="/opt/quarkshield"
if [ "$INSTALL_DIR" = "/usr/local/bin" ]; then
  echo "📦 Installing binary to: $APP_DIR/quarkshield-scanner (linked from $INSTALL_DIR)..."
  $SUDO mkdir -p "$APP_DIR"
  $SUDO chown root:root "$APP_DIR"
  $SUDO chmod 755 "$APP_DIR"
  # Install via a temp name + rename so a running daemon is never half-overwritten.
  $SUDO cp -f "$BINARY_SOURCE" "$APP_DIR/quarkshield-scanner.install"
  $SUDO chmod 755 "$APP_DIR/quarkshield-scanner.install"
  $SUDO mv -f "$APP_DIR/quarkshield-scanner.install" "$APP_DIR/quarkshield-scanner"
  $SUDO rm -f "$INSTALL_DIR/quarkshield-scanner"
  $SUDO ln -s "$APP_DIR/quarkshield-scanner" "$INSTALL_DIR/quarkshield-scanner"
else
  echo "📦 Installing binary to: $INSTALL_DIR/quarkshield-scanner..."
  cp -f "$BINARY_SOURCE" "$INSTALL_DIR/quarkshield-scanner"
  chmod +x "$INSTALL_DIR/quarkshield-scanner"
fi

# Install Desktop Entry if GUI environment exists
if [ -n "$XDG_CURRENT_DESKTOP" ] || [ -d "$HOME/.local/share/applications" ]; then
  # Own variable: APP_DIR is the binary's install directory and is written into
  # the systemd unit (ReadWritePaths) further down.
  DESKTOP_DIR="$HOME/.local/share/applications"
  mkdir -p "$DESKTOP_DIR"
  cat << 'EOF' > "$DESKTOP_DIR/quarkshield.desktop"
[Desktop Entry]
Type=Application
Name=QuarkShield Post-Quantum Guard
Comment=Post-Quantum Cryptographic Vulnerability Scanner
Exec=/usr/local/bin/quarkshield-scanner --gui
Icon=security-high
Terminal=false
Categories=Security;System;
EOF
  chmod +x "$DESKTOP_DIR/quarkshield.desktop" 2>/dev/null || true
  echo "✓ Desktop application launcher registered."
fi

# ---------------------------------------------------------------------------
# DEF-39: install the persistent daemon as a systemd service so admin "Pull
# Telemetry" / bulk pulls and scheduled syncs run continuously (no GUI needed).
# Token comes from $1 or $QS_TOKEN; without one, we skip and print how to enable.
# ---------------------------------------------------------------------------
QS_TOKEN="${1:-${QS_TOKEN:-}}"
if command -v systemctl >/dev/null 2>&1 && { [ "$(id -u)" -eq 0 ] || [ -n "${SUDO}" ]; }; then
  # The enrollment token is a bearer credential. Keep it OUT of the unit file and
  # the process argument list (both world-readable); the daemon reads QS_TOKEN
  # from a root-only EnvironmentFile instead.
  EXEC="$INSTALL_DIR/quarkshield-scanner --daemon --server https://quarkshield.ai"
  $SUDO mkdir -p /etc/quarkshield
  $SUDO chmod 700 /etc/quarkshield
  if [ -n "$QS_TOKEN" ]; then
    printf 'QS_TOKEN=%s\n' "$QS_TOKEN" | $SUDO tee /etc/quarkshield/env >/dev/null
  else
    $SUDO touch /etc/quarkshield/env
  fi
  $SUDO chmod 600 /etc/quarkshield/env
  echo "🛠️  Installing persistent daemon (systemd service quarkshield)..."
  $SUDO tee /etc/systemd/system/quarkshield.service >/dev/null << EOF
[Unit]
Description=QuarkShield Post-Quantum Guard Cryptographic Auditor (persistent daemon)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# systemd sets no HOME without User=; give the daemon a dedicated state dir so its
# enrollment/config/scan records live in /var/lib/quarkshield (not "/.quarkshield").
StateDirectory=quarkshield
StateDirectoryMode=0700
Environment=HOME=/var/lib/quarkshield
EnvironmentFile=-/etc/quarkshield/env
ExecStart=$EXEC
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true
# The one place the sandboxed daemon may write outside its state directory: its
# own install directory, so a verified console push-upgrade can swap the binary.
ReadWritePaths=$APP_DIR

[Install]
WantedBy=multi-user.target
EOF
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now quarkshield.service 2>/dev/null && \
    echo "✓ Daemon enabled & started (journalctl -u quarkshield -f to watch)." || \
    echo "⚠️ Service installed but not started — enroll first, then: $SUDO systemctl restart quarkshield"
  if [ -z "$QS_TOKEN" ]; then
    echo "   ℹ️  No token provided. Add it later with:"
    echo "      echo 'QS_TOKEN=<TOKEN>' | $SUDO tee /etc/quarkshield/env >/dev/null && $SUDO systemctl restart quarkshield"
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
