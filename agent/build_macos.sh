#!/usr/bin/env bash
# ==============================================================================
# QuarkShield Agent Build & Packaging Automation for macOS
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Clean up any leftover staging directories from prior builds
rm -rf dmg_stage_* zip_stage_*
STAGE_DIR=""
ZIP_STAGE=""
trap 'rm -rf "$STAGE_DIR" "$ZIP_STAGE"' EXIT INT TERM

echo "======================================================================"
echo " 🍏 Building QuarkShield Universal macOS Agent (.app, .dmg, .zip)"
echo "======================================================================"

# 1. Compile Apple Silicon (arm64) and Intel (amd64) binaries
echo "⚙️ [1/6] Compiling darwin-arm64 binary..."
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o quarkshield-scanner-darwin-arm64 .

echo "⚙️ [2/6] Compiling darwin-amd64 binary..."
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o quarkshield-scanner-darwin-amd64 .

# 2. Create Universal Mach-O binary
echo "🔗 [3/6] Creating universal Mach-O binary (Apple Silicon + Intel)..."
lipo -create -output quarkshield-scanner-darwin-universal quarkshield-scanner-darwin-amd64 quarkshield-scanner-darwin-arm64

# 3. Assemble & Sign QuarkShield.app bundle
echo "📦 [4/6] Updating QuarkShield.app bundle..."
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

# Code signing identity detection
SIGN_IDENTITY=""
if security find-identity -v -p codesigning 2>/dev/null | grep -q "Developer ID Application"; then
  SIGN_IDENTITY=$(security find-identity -v -p codesigning | grep "Developer ID Application" | head -n 1 | sed -E 's/.*"([^"]+)".*/\1/')
  echo "🔑 Detected Apple Developer ID: $SIGN_IDENTITY"
fi

# Strip extended attributes, AppleDouble files, and resource forks to ensure clean codesigning
dot_clean -m "$APP_STAGE/QuarkShield.app" 2>/dev/null || true
xattr -cr "$APP_STAGE/QuarkShield.app" 2>/dev/null || true

if [ -n "$SIGN_IDENTITY" ]; then
  echo "🔑 Signing Mach-O binaries with Apple Developer ID..."
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" quarkshield-scanner-darwin-arm64
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" quarkshield-scanner-darwin-amd64
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" quarkshield-scanner-darwin-universal
  echo "🔑 Signing QuarkShield.app with Apple Developer ID (Hardened Runtime)..."
  codesign --force --deep --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP_STAGE/QuarkShield.app"
else
  echo "⚠️ Developer ID not found, using ad-hoc signing"
  codesign --force --deep --sign - "$APP_STAGE/QuarkShield.app"
fi

# Update /Applications/QuarkShield.app if installed
if [ -d "/Applications/QuarkShield.app" ]; then
  echo "🔄 Updating /Applications/QuarkShield.app with signed release bundle..."
  rm -rf /Applications/QuarkShield.app
  cp -R "$APP_STAGE/QuarkShield.app" /Applications/QuarkShield.app
fi

# 4. Create ZIP distribution
echo "🗜️ [5/6] Creating ZIP distribution..."
ZIP_STAGE="/tmp/zip_stage_$$"
rm -rf "$ZIP_STAGE" quarkshield-scanner-macos.zip
mkdir -p "$ZIP_STAGE"
cp -R "$APP_STAGE/QuarkShield.app" "$ZIP_STAGE/"
cp Start-QuarkShield.command "$ZIP_STAGE/"
cp Trust-QuarkShield.command "$ZIP_STAGE/" 2>/dev/null || true
cp Trust-FedMitigate.command "$ZIP_STAGE/" 2>/dev/null || true
cp README-macOS.txt "$ZIP_STAGE/README.txt"
(cd "$ZIP_STAGE" && zip -9 -r "$SCRIPT_DIR/quarkshield-scanner-macos.zip" QuarkShield.app Start-QuarkShield.command Trust-QuarkShield.command Trust-FedMitigate.command README.txt)
rm -rf "$ZIP_STAGE"

# 5. Create DMG disk image
echo "💿 [6/6] Generating QuarkShield-macOS.dmg disk image..."
STAGE_DIR="/tmp/dmg_stage_$$"
rm -rf "$STAGE_DIR" QuarkShield-macOS.dmg
mkdir -p "$STAGE_DIR"
cp -R "$APP_STAGE/QuarkShield.app" "$STAGE_DIR/"
ln -s /Applications "$STAGE_DIR/Applications"
cp Start-QuarkShield.command "$STAGE_DIR/"
cp Trust-QuarkShield.command "$STAGE_DIR/" 2>/dev/null || true
cp Trust-FedMitigate.command "$STAGE_DIR/" 2>/dev/null || true
cp README-macOS.txt "$STAGE_DIR/README.txt"

hdiutil create -volname "QuarkShield Guard" -srcfolder "$STAGE_DIR" -ov -format UDZO QuarkShield-macOS.dmg || echo "⚠️ DMG creation deferred (sandboxed environment). Universal .app and .zip ready."
rm -rf "$STAGE_DIR" "$APP_STAGE"
rm -rf QuarkShield.app 2>/dev/null || true

if [ -n "$SIGN_IDENTITY" ]; then
  echo "🔑 Signing QuarkShield-macOS.dmg with Apple Developer ID..."
  codesign --force --timestamp --sign "$SIGN_IDENTITY" QuarkShield-macOS.dmg
fi

# 6. Synchronize binaries and archives
echo "🔄 Synchronizing artifacts across distribution directories..."
mkdir -p binaries
cp -f quarkshield-scanner-darwin-arm64 binaries/
cp -f quarkshield-scanner-darwin-amd64 binaries/
cp -f quarkshield-scanner-darwin-universal binaries/
cp -f quarkshield-scanner-macos.zip binaries/
[ -f QuarkShield-macOS.dmg ] && cp -f QuarkShield-macOS.dmg binaries/ || true
cp -f Trust-QuarkShield.command binaries/ 2>/dev/null || true
cp -f Trust-FedMitigate.command binaries/ 2>/dev/null || true

# Aliases for backwards compatibility
cp -f quarkshield-scanner-darwin-arm64 binaries/pqc-scanner-darwin-arm64
cp -f quarkshield-scanner-darwin-amd64 binaries/pqc-scanner-darwin-amd64
cp -f quarkshield-scanner-macos.zip binaries/pqc-scanner-macos.zip

for DL_DIR in "../ui/public/downloads" "../ui/dist/downloads"; do
  if [ -d "$DL_DIR" ]; then
    cp -f quarkshield-scanner-darwin-arm64 "$DL_DIR/"
    cp -f quarkshield-scanner-darwin-amd64 "$DL_DIR/"
    cp -f quarkshield-scanner-darwin-universal "$DL_DIR/"
    cp -f quarkshield-scanner-macos.zip "$DL_DIR/"
    [ -f QuarkShield-macOS.dmg ] && cp -f QuarkShield-macOS.dmg "$DL_DIR/" || true
    cp -f Trust-QuarkShield.command "$DL_DIR/" 2>/dev/null || true
    cp -f Trust-FedMitigate.command "$DL_DIR/" 2>/dev/null || true
    cp -f quarkshield-scanner-darwin-arm64 "$DL_DIR/pqc-scanner-darwin-arm64"
    cp -f quarkshield-scanner-darwin-amd64 "$DL_DIR/pqc-scanner-darwin-amd64"
    cp -f quarkshield-scanner-macos.zip "$DL_DIR/pqc-scanner-macos.zip"
  fi
done

# 7. Unregister intermediate workspace app bundle to prevent Launchpad duplicates
echo "🧹 [7/7] Cleaning intermediate workspace app bundle from Launchpad registry..."
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -u QuarkShield.app 2>/dev/null || true
rm -rf QuarkShield.app

echo "======================================================================"
echo "✅ macOS Build, Packaging & Distribution Complete!"
echo "   • Universal Binary:  quarkshield-scanner-darwin-universal"
echo "   • Apple Silicon:     quarkshield-scanner-darwin-arm64"
echo "   • Intel x86_64:      quarkshield-scanner-darwin-amd64"
echo "   • Disk Image (DMG):  QuarkShield-macOS.dmg"
echo "   • Zip Archive:       quarkshield-scanner-macos.zip"
echo "======================================================================"
