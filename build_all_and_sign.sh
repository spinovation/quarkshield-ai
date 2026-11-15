#!/usr/bin/env bash
# ==============================================================================
# QuarkShield Master Build, Code-Signing & Packaging Automation
# Ensures 100% of Windows and macOS releases are automatically signed and trusted.
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
AGENT_DIR="$SCRIPT_DIR/agent"

# Release version: single source of truth = the AgentReleaseVersion constant in
# agent/client.go (shown in the GUI header chip + reported in telemetry). An
# explicit APP_VERSION env var overrides it; only falls back to 1.0.0 if neither.
APP_VERSION="${APP_VERSION:-$(grep -oE 'AgentReleaseVersion = "[0-9.]+"' "$AGENT_DIR/client.go" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)}"
APP_VERSION="${APP_VERSION:-1.0.0}"
export APP_VERSION
echo "   • Release version: ${APP_VERSION}"

echo "======================================================================"
echo " 🛡️ Starting QuarkShield Master Cross-Platform Build & Sign Pipeline"
echo "======================================================================"

cd "$AGENT_DIR"

# Proves a Windows file really carries our publicly trusted Authenticode signature
# (Azure Trusted Signing: CN=Fedmitigate LLC issued by a Microsoft ID Verified CA)
# and that the signed digest matches the file. The signing tool's exit status alone
# is not proof. osslsigncode's own exit status is unusable on macOS — without the
# Microsoft root in a CA bundle it reports the chain as "Failed" even for a good
# signature — so this reads the signer and the digests from its output instead.
verify_trusted_signature() {
  local f="$1" out cur calc
  if ! command -v osslsigncode >/dev/null 2>&1; then
    echo "   ❌ osslsigncode is not installed — cannot prove $f is signed (brew install osslsigncode)." >&2
    return 1
  fi
  out="$(osslsigncode verify -in "$f" 2>&1 || true)"
  if ! printf '%s\n' "$out" | grep -q "Subject: CN=Fedmitigate LLC,"; then
    echo "   ❌ $f has no Fedmitigate LLC signature." >&2
    return 1
  fi
  if ! printf '%s\n' "$out" | grep -q "Issuer : CN=Microsoft ID Verified"; then
    echo "   ❌ $f is not signed by a Microsoft ID Verified CA (self-signed fallback?)." >&2
    return 1
  fi
  cur="$(printf '%s\n' "$out" | awk -F': ' '/^Current message digest/ {print $2; exit}' | tr -d '[:space:]')"
  calc="$(printf '%s\n' "$out" | awk -F': ' '/^Calculated message digest/ {print $2; exit}' | tr -d '[:space:]')"
  if [ -z "$cur" ] || [ "$cur" != "$calc" ]; then
    echo "   ❌ $f signature digest does not match the file." >&2
    return 1
  fi
  return 0
}

# ------------------------------------------------------------------------------
# 1. WINDOWS BUILD & AZURE TRUSTED SIGNING
# ------------------------------------------------------------------------------
echo "⚙️ [1/4] Building and Signing Windows Agent (x86_64)..."
GOOS=windows GOARCH=amd64 go build -ldflags="$GO_LDFLAGS" -o quarkshield-scanner-windows-amd64.exe .

SIGNED_WIN=false
if [ -f ".env.signing" ] || [ -n "$AZURE_CLIENT_ID" ]; then
  echo "   Applying Microsoft Azure Trusted Signing..."
  if python3 sign_azure.py quarkshield-scanner-windows-amd64.exe; then
    SIGNED_WIN=true
    echo "   ✓ Azure Trusted Signature successfully applied (Fedmitigate LLC / Microsoft Root CA)!"
  fi
fi

if [ "$SIGNED_WIN" = false ]; then
  echo "   Falling back to FedMitigate PKI Code Signing certificate + DigiCert RFC3161 Timestamp..."
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
      echo "   ✓ Local Authenticode signature applied!"
    fi
  fi
fi

# Package Windows ZIP with 1-click publisher trust scripts
echo "📦 Packaging quarkshield-scanner-windows.zip..."
rm -f quarkshield-scanner-windows.zip
# NOTE: FedMitigate self-signed CA + Trust-FedMitigate.* deliberately NOT bundled —
# the exe is Azure Trusted Signing (publicly trusted); a private root CA is obsolete.
zip -9 quarkshield-scanner-windows.zip \
  quarkshield-scanner-windows-amd64.exe \
  app_icon.ico \
  uninstall.bat \
  README.txt

# Build the Windows Inno Setup installer (Program Files + Start Menu + uninstaller).
# ISCC is Windows-only, so on macOS/Linux we compile it inside the amake/innosetup
# Docker image (bundles Wine + Inno Setup). Skipped cleanly if Docker is absent.
echo "📥 Building Windows installer (QuarkShield-Setup.exe)..."
rm -f QuarkShield-Setup.exe installer/Output/QuarkShield-Setup.exe
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if docker run --rm --platform linux/amd64 -v "$AGENT_DIR:/work" amake/innosetup \
       /DMyAppVersion="${APP_VERSION:-1.0.0}" installer/quarkshield.iss; then
    if [ -f installer/Output/QuarkShield-Setup.exe ]; then
      cp -f installer/Output/QuarkShield-Setup.exe QuarkShield-Setup.exe
      # Sign the installer itself so it shows "Fedmitigate LLC" (not "Unknown Publisher").
      # An unsigned installer must never reach the download directories: the 2.3.0
      # one did (signing failed, the build only warned) and antivirus heuristics
      # flagged it for a prospect. So a signing failure stops the build here.
      if python3 sign_azure.py QuarkShield-Setup.exe && verify_trusted_signature QuarkShield-Setup.exe; then
        echo "   ✓ Installer signed and verified (Fedmitigate LLC / Microsoft ID Verified CA)!"
      elif [ "${ALLOW_UNSIGNED_INSTALLER:-}" = "1" ]; then
        echo "   ⚠️  Installer is NOT signed — kept only because ALLOW_UNSIGNED_INSTALLER=1. Local testing only; do not publish."
      else
        rm -f QuarkShield-Setup.exe installer/Output/QuarkShield-Setup.exe
        echo "❌ Installer signing failed — build stopped, nothing staged." >&2
        echo "   Check agent/.env.signing (Azure client secret may have expired), jsign and osslsigncode, then re-run." >&2
        echo "   For a local, never-published test build only: ALLOW_UNSIGNED_INSTALLER=1." >&2
        exit 1
      fi
    fi
  else
    echo "   ⚠️  Inno Setup compile failed — skipping installer (portable .exe still ships)."
  fi
else
  echo "   ⚠️  Docker not available — skipping installer build (portable .exe still ships)."
fi

# ------------------------------------------------------------------------------
# 2. MACOS BUILD, CODE SIGNING & DMG / ZIP PACKAGING
# ------------------------------------------------------------------------------
echo "🍏 [2/4] Building macOS Universal Agent (.app, .dmg, .zip)..."
GOOS=darwin GOARCH=arm64 go build -ldflags="$GO_LDFLAGS" -o quarkshield-scanner-darwin-arm64 .
GOOS=darwin GOARCH=amd64 go build -ldflags="$GO_LDFLAGS" -o quarkshield-scanner-darwin-amd64 .
lipo -create -output quarkshield-scanner-darwin-universal quarkshield-scanner-darwin-amd64 quarkshield-scanner-darwin-arm64

APP_STAGE="/tmp/quarkshield_app_stage_$$"
rm -rf "$APP_STAGE"
mkdir -p "$APP_STAGE/QuarkShield.app/Contents/MacOS"
mkdir -p "$APP_STAGE/QuarkShield.app/Contents/Resources"
cp -f quarkshield-scanner-darwin-universal "$APP_STAGE/QuarkShield.app/Contents/MacOS/quarkshield-scanner"
chmod +x "$APP_STAGE/QuarkShield.app/Contents/MacOS/quarkshield-scanner"
if [ -f Info.plist ]; then
  cp -f Info.plist "$APP_STAGE/QuarkShield.app/Contents/Info.plist"
fi
if [ -f app_icon.icns ]; then
  cp -f app_icon.icns "$APP_STAGE/QuarkShield.app/Contents/Resources/AppIcon.icns"
fi

# Detect Apple Developer ID
SIGN_IDENTITY=""
if security find-identity -v -p codesigning 2>/dev/null | grep -q "Developer ID Application"; then
  SIGN_IDENTITY=$(security find-identity -v -p codesigning | grep "Developer ID Application" | head -n 1 | sed -E 's/.*"([^"]+)".*/\1/')
  echo "🔑 Detected Apple Developer ID: $SIGN_IDENTITY"
fi

# Notarize + staple (Apple's trust ticket → Gatekeeper opens the app with no warning).
# Credentials (one of):
#   NOTARY_PROFILE=<name>   (recommended; created once via:
#       xcrun notarytool store-credentials <name> --apple-id you@example.com --team-id 4ADVSK467Z --password <app-specific-pw>)
#   or NOTARY_APPLE_ID + NOTARY_PASSWORD (app-specific) + NOTARY_TEAM_ID
notarize_and_staple() {
  local target="$1" args=()
  if [ -n "${NOTARY_PROFILE:-}" ]; then
    args=(--keychain-profile "$NOTARY_PROFILE")
  elif [ -n "${NOTARY_APPLE_ID:-}" ] && [ -n "${NOTARY_PASSWORD:-}" ] && [ -n "${NOTARY_TEAM_ID:-}" ]; then
    args=(--apple-id "$NOTARY_APPLE_ID" --password "$NOTARY_PASSWORD" --team-id "$NOTARY_TEAM_ID")
  else
    echo "⚠️  Notarization SKIPPED for $(basename "$target") — set NOTARY_PROFILE (recommended)"
    echo "    or NOTARY_APPLE_ID/NOTARY_PASSWORD/NOTARY_TEAM_ID. Build is SIGNED but Gatekeeper will still warn."
    return 0
  fi
  case "$target" in
    *.app)
      local nz="/tmp/notarize_$$.zip"
      ditto -c -k --keepParent "$target" "$nz"
      echo "🍏 Notarizing $(basename "$target") (Apple scan — may take a few minutes)..."
      xcrun notarytool submit "$nz" "${args[@]}" --wait && xcrun stapler staple "$target" || echo "❌ Notarization failed for $(basename "$target")"
      rm -f "$nz" ;;
    *)
      echo "🍏 Notarizing $(basename "$target")..."
      xcrun notarytool submit "$target" "${args[@]}" --wait && xcrun stapler staple "$target" || echo "❌ Notarization failed for $(basename "$target")" ;;
  esac
}

# Strip extended attributes and resource forks from staging bundle
dot_clean -m "$APP_STAGE/QuarkShield.app" 2>/dev/null || true
xattr -cr "$APP_STAGE/QuarkShield.app" 2>/dev/null || true

if [ -n "$SIGN_IDENTITY" ]; then
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" quarkshield-scanner-darwin-arm64
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" quarkshield-scanner-darwin-amd64
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" quarkshield-scanner-darwin-universal
  codesign --force --deep --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP_STAGE/QuarkShield.app"
else
  echo "ℹ️ Signing macOS bundle with hardened runtime & bundle identifier (com.fedmitigate.quarkshield)..."
  codesign --force --options runtime --identifier "com.fedmitigate.quarkshield" --sign - "$APP_STAGE/QuarkShield.app/Contents/MacOS/quarkshield-scanner"
  codesign --force --deep --options runtime --identifier "com.fedmitigate.quarkshield" --sign - "$APP_STAGE/QuarkShield.app"
fi

# Notarize + staple the app BEFORE packaging so the ZIP and DMG both carry the trust ticket.
if [ -n "$SIGN_IDENTITY" ]; then
  notarize_and_staple "$APP_STAGE/QuarkShield.app"
fi

# Update /Applications/QuarkShield.app if installed
if [ -d "/Applications/QuarkShield.app" ]; then
  echo "🔄 Updating /Applications/QuarkShield.app with signed release bundle..."
  rm -rf /Applications/QuarkShield.app
  cp -R "$APP_STAGE/QuarkShield.app" /Applications/QuarkShield.app
fi

# Package macOS ZIP with 1-click Trust Scripts
echo "📦 Packaging quarkshield-scanner-macos.zip..."
ZIP_STAGE="/tmp/zip_stage_$$"
rm -rf "$ZIP_STAGE" quarkshield-scanner-macos.zip
mkdir -p "$ZIP_STAGE"
cp -R "$APP_STAGE/QuarkShield.app" "$ZIP_STAGE/"
cp Start-QuarkShield.command "$ZIP_STAGE/"
cp Trust-QuarkShield.command "$ZIP_STAGE/"
cp README-macOS.txt "$ZIP_STAGE/README.txt"
(cd "$ZIP_STAGE" && zip -9 -r "$AGENT_DIR/quarkshield-scanner-macos.zip" QuarkShield.app Start-QuarkShield.command Trust-QuarkShield.command README.txt)
rm -rf "$ZIP_STAGE"

# Package macOS DMG Disk Image
echo "💿 Generating QuarkShield-macOS.dmg..."
STAGE_DIR="/tmp/dmg_stage_$$"
rm -rf "$STAGE_DIR" QuarkShield-macOS.dmg
mkdir -p "$STAGE_DIR"
cp -R "$APP_STAGE/QuarkShield.app" "$STAGE_DIR/"
ln -s /Applications "$STAGE_DIR/Applications"
cp Start-QuarkShield.command "$STAGE_DIR/"
cp Trust-QuarkShield.command "$STAGE_DIR/"
cp README-macOS.txt "$STAGE_DIR/README.txt"
hdiutil create -volname "QuarkShield Guard" -srcfolder "$STAGE_DIR" -ov -format UDZO QuarkShield-macOS.dmg
rm -rf "$STAGE_DIR" "$APP_STAGE"
rm -rf QuarkShield.app 2>/dev/null || true

if [ -n "$SIGN_IDENTITY" ]; then
  codesign --force --timestamp --sign "$SIGN_IDENTITY" QuarkShield-macOS.dmg
  # Notarize + staple the DMG itself so the download passes Gatekeeper on mount.
  notarize_and_staple QuarkShield-macOS.dmg
fi

# ------------------------------------------------------------------------------
# 3. LINUX BUILDS
# ------------------------------------------------------------------------------
echo "🐧 [3/4] Building Linux Agents (amd64, arm64)..."
GOOS=linux GOARCH=amd64 go build -ldflags="$GO_LDFLAGS" -o quarkshield-scanner-linux-amd64 .
GOOS=linux GOARCH=arm64 go build -ldflags="$GO_LDFLAGS" -o quarkshield-scanner-linux-arm64 .

# Package Linux Release Tarball & Zip with 1-Click Installer
echo "📦 Packaging quarkshield-scanner-linux.tar.gz and .zip..."
LINUX_STAGE="/tmp/linux_stage_$$"
rm -rf "$LINUX_STAGE" quarkshield-scanner-linux.tar.gz quarkshield-scanner-linux.zip
mkdir -p "$LINUX_STAGE"
cp -f quarkshield-scanner-linux-amd64 "$LINUX_STAGE/"
cp -f quarkshield-scanner-linux-arm64 "$LINUX_STAGE/"
cp -f install-linux.sh "$LINUX_STAGE/install.sh"
cp -f uninstall-linux.sh "$LINUX_STAGE/uninstall.sh"
cp -f quarkshield.service "$LINUX_STAGE/"
cp -f web/app_icon.png "$LINUX_STAGE/app_icon.png" 2>/dev/null || true
cp -f README-linux.txt "$LINUX_STAGE/README.txt"
chmod +x "$LINUX_STAGE/install.sh" "$LINUX_STAGE/uninstall.sh" "$LINUX_STAGE/quarkshield-scanner-linux-amd64" "$LINUX_STAGE/quarkshield-scanner-linux-arm64"
tar -czf "$AGENT_DIR/quarkshield-scanner-linux.tar.gz" -C "$LINUX_STAGE" .
(cd "$LINUX_STAGE" && zip -9 -r "$AGENT_DIR/quarkshield-scanner-linux.zip" .)
rm -rf "$LINUX_STAGE"

# ------------------------------------------------------------------------------
# 3b. SIGNED RELEASE MANIFEST (console push-upgrade)
# ------------------------------------------------------------------------------
# Agents only apply a pushed upgrade whose manifest is signed by the release key
# they were built to trust (agent/release_keys.go). The private key stays on this
# machine (agent/.env.release-key, git-ignored) and is never deployed.
# SKIP_RELEASE_MANIFEST=1 builds without one (that release cannot be pushed).
rm -f agent-manifest.json agent-manifest.json.sig
if [ "${SKIP_RELEASE_MANIFEST:-}" = "1" ]; then
  echo "⚠️  SKIP_RELEASE_MANIFEST=1 — no signed manifest; this build cannot be pushed from the console."
else
  echo "🧾 Building the signed release manifest (agent-manifest.json)..."
  RELEASE_KEY_FILE="${RELEASE_SIGNING_KEY_FILE:-$AGENT_DIR/.env.release-key}"
  if [ ! -f "$RELEASE_KEY_FILE" ]; then
    echo "❌ Release signing key not found at $RELEASE_KEY_FILE." >&2
    echo "   Restore it from your backup. (SKIP_RELEASE_MANIFEST=1 builds without push-upgrade.)" >&2
    exit 1
  fi
  # Everything an agent will check must already be true here, or the push would
  # be refused on every endpoint.
  HOST_BIN="quarkshield-scanner-$(go env GOHOSTOS)-$(go env GOHOSTARCH)"
  BUILT_VERSION="$(./"$HOST_BIN" --agent-version 2>/dev/null || true)"
  if [ "$BUILT_VERSION" != "$APP_VERSION" ]; then
    echo "❌ $HOST_BIN reports version '$BUILT_VERSION' but the release is '$APP_VERSION'." >&2
    exit 1
  fi
  if ! verify_trusted_signature quarkshield-scanner-windows-amd64.exe; then
    echo "❌ The Windows agent is not Azure-signed — agents would refuse this upgrade." >&2
    exit 1
  fi
  APP_CHECK="/tmp/manifest_app_check_$$"
  rm -rf "$APP_CHECK" && mkdir -p "$APP_CHECK"
  unzip -q quarkshield-scanner-macos.zip -d "$APP_CHECK"
  if ! spctl -a -t exec "$APP_CHECK/QuarkShield.app" 2>/dev/null; then
    rm -rf "$APP_CHECK"
    echo "❌ QuarkShield.app in the macOS zip is not notarized — agents would refuse this upgrade." >&2
    exit 1
  fi
  rm -rf "$APP_CHECK"

  python3 - "$APP_VERSION" <<'PYEOF'
import hashlib, json, os, sys, datetime
version = sys.argv[1]
artifacts = {
    "windows/amd64": "quarkshield-scanner-windows-amd64.exe",
    "linux/amd64":   "quarkshield-scanner-linux-amd64",
    "linux/arm64":   "quarkshield-scanner-linux-arm64",
    "darwin/amd64":  "quarkshield-scanner-darwin-amd64",
    "darwin/arm64":  "quarkshield-scanner-darwin-arm64",
    "darwin/app":    "quarkshield-scanner-macos.zip",
}
out = {}
for key, name in artifacts.items():
    h = hashlib.sha256()
    with open(name, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    out[key] = {"path": "/downloads/" + name, "sha256": h.hexdigest(), "size": os.path.getsize(name)}
manifest = {
    "product": "quarkshield-agent",
    "version": version,
    "generatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "artifacts": out,
}
with open("agent-manifest.json", "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
PYEOF
  go run ./tools/relsign sign "$RELEASE_KEY_FILE" agent-manifest.json
  # The signature must verify against a key the agents actually trust.
  MANIFEST_OK=false
  for PUB in $(grep -oE '"[A-Za-z0-9+/]{43}="' release_keys.go | tr -d '"'); do
    if go run ./tools/relsign verify "$PUB" agent-manifest.json >/dev/null 2>&1; then MANIFEST_OK=true; fi
  done
  if [ "$MANIFEST_OK" != true ]; then
    rm -f agent-manifest.json agent-manifest.json.sig
    echo "❌ The manifest signature does not match any key in agent/release_keys.go (wrong key file?)." >&2
    exit 1
  fi
  echo "   ✓ Release manifest for ${APP_VERSION} signed and verified."
fi

# ------------------------------------------------------------------------------
# 4. SYNCHRONIZE ALL ARTIFACTS ACROSS DOWNLOAD DIRECTORIES
# ------------------------------------------------------------------------------
echo "🔄 [4/4] Synchronizing release artifacts to all distribution targets..."
mkdir -p binaries
cp -f quarkshield-scanner-darwin-arm64 binaries/
cp -f quarkshield-scanner-darwin-amd64 binaries/
cp -f quarkshield-scanner-darwin-universal binaries/
cp -f quarkshield-scanner-macos.zip binaries/
cp -f QuarkShield-macOS.dmg binaries/
cp -f Start-QuarkShield.command binaries/
cp -f Trust-QuarkShield.command binaries/
cp -f quarkshield-scanner-windows-amd64.exe binaries/
cp -f quarkshield-scanner-windows.zip binaries/
[ -f QuarkShield-Setup.exe ] && cp -f QuarkShield-Setup.exe binaries/
cp -f quarkshield-scanner-linux-amd64 binaries/
cp -f quarkshield-scanner-linux-arm64 binaries/
cp -f quarkshield-scanner-linux.tar.gz binaries/
cp -f quarkshield-scanner-linux.zip binaries/
cp -f install-linux.sh binaries/
cp -f uninstall-linux.sh binaries/
cp -f quarkshield.service binaries/
cp -f README-linux.txt binaries/
# Signed release manifest: replace it, or remove a stale one from an older release.
rm -f binaries/agent-manifest.json binaries/agent-manifest.json.sig
[ -f agent-manifest.json.sig ] && cp -f agent-manifest.json agent-manifest.json.sig binaries/

# Aliases for backwards compatibility
cp -f quarkshield-scanner-darwin-arm64 binaries/pqc-scanner-darwin-arm64
cp -f quarkshield-scanner-darwin-amd64 binaries/pqc-scanner-darwin-amd64
cp -f quarkshield-scanner-macos.zip binaries/pqc-scanner-macos.zip
cp -f quarkshield-scanner-windows-amd64.exe binaries/pqc-scanner-windows-amd64.exe
cp -f quarkshield-scanner-windows.zip binaries/pqc-scanner-windows.zip
cp -f quarkshield-scanner-linux-amd64 binaries/pqc-scanner-linux-amd64
cp -f quarkshield-scanner-linux-arm64 binaries/pqc-scanner-linux-arm64
cp -f quarkshield-scanner-linux.tar.gz binaries/pqc-scanner-linux.tar.gz
cp -f quarkshield-scanner-linux.zip binaries/pqc-scanner-linux.zip
cp -f quarkshield-scanner-linux-amd64 binaries/pqc-scanner

for DL_DIR in "$SCRIPT_DIR/ui/public/downloads" "$SCRIPT_DIR/ui/dist/downloads" "$SCRIPT_DIR/public/downloads"; do
  if [ -d "$DL_DIR" ]; then
    cp -f quarkshield-scanner-darwin-arm64 "$DL_DIR/"
    cp -f quarkshield-scanner-darwin-amd64 "$DL_DIR/"
    cp -f quarkshield-scanner-darwin-universal "$DL_DIR/"
    cp -f quarkshield-scanner-macos.zip "$DL_DIR/"
    cp -f QuarkShield-macOS.dmg "$DL_DIR/"
    cp -f Start-QuarkShield.command "$DL_DIR/"
    cp -f Trust-QuarkShield.command "$DL_DIR/"
    cp -f quarkshield-scanner-windows-amd64.exe "$DL_DIR/"
    cp -f quarkshield-scanner-windows.zip "$DL_DIR/"
    [ -f QuarkShield-Setup.exe ] && cp -f QuarkShield-Setup.exe "$DL_DIR/"
    cp -f quarkshield-scanner-linux-amd64 "$DL_DIR/"
    cp -f quarkshield-scanner-linux-arm64 "$DL_DIR/"
    cp -f quarkshield-scanner-linux.tar.gz "$DL_DIR/"
    cp -f quarkshield-scanner-linux.zip "$DL_DIR/"
    cp -f install-linux.sh "$DL_DIR/"
    cp -f uninstall-linux.sh "$DL_DIR/"
    cp -f quarkshield.service "$DL_DIR/"
    cp -f README-linux.txt "$DL_DIR/"
    rm -f "$DL_DIR/agent-manifest.json" "$DL_DIR/agent-manifest.json.sig"
    [ -f agent-manifest.json.sig ] && cp -f agent-manifest.json agent-manifest.json.sig "$DL_DIR/"
    cp -f quarkshield-scanner-darwin-arm64 "$DL_DIR/pqc-scanner-darwin-arm64"
    cp -f quarkshield-scanner-darwin-amd64 "$DL_DIR/pqc-scanner-darwin-amd64"
    cp -f quarkshield-scanner-macos.zip "$DL_DIR/pqc-scanner-macos.zip"
    cp -f quarkshield-scanner-windows-amd64.exe "$DL_DIR/pqc-scanner-windows-amd64.exe"
    cp -f quarkshield-scanner-windows.zip "$DL_DIR/pqc-scanner-windows.zip"
    cp -f quarkshield-scanner-linux-amd64 "$DL_DIR/pqc-scanner-linux-amd64"
    cp -f quarkshield-scanner-linux-arm64 "$DL_DIR/pqc-scanner-linux-arm64"
    cp -f quarkshield-scanner-linux.tar.gz "$DL_DIR/pqc-scanner-linux.tar.gz"
    cp -f quarkshield-scanner-linux.zip "$DL_DIR/pqc-scanner-linux.zip"
  fi
done

echo "======================================================================"
echo "✅ Master Cross-Platform Build & Sign Completed Successfully!"
echo "   • Windows: Authenticode Signed via Azure Trusted Signing (Fedmitigate LLC)"
echo "   • macOS:   Hardened Runtime + Bundled 1-Click Trust Assistants (DMG & ZIP)"
echo "   • Linux:   Statically linked amd64 & arm64 binaries"
echo "======================================================================"
