========================================================================
 QuarkShield Post-Quantum Cryptographic Desktop Guard for macOS
 Published by FedMitigate LLC
 Universal Binary (Apple Silicon M1/M2/M3/M4 & Intel x86_64)
========================================================================

QUICK START:
1. Drag "QuarkShield.app" into your "/Applications" folder.
2. Double-click "QuarkShield.app" to launch the interactive Post-Quantum
   Guard Web GUI in your browser (http://127.0.0.1:48291).

FIRST-TIME LAUNCH & SECURITY TRUST:
QuarkShield is digitally signed with an Apple Developer ID certificate:
Developer ID Application: Ganapati Sridhar (4ADVSK467Z)

To launch and establish full trust on macOS:

Option A (1-Click Trust & Launch):
- Double-click "Trust-QuarkShield.command" (or "Start-QuarkShield.command").
  This immediately authorizes QuarkShield with Gatekeeper, clears any browser
  download quarantine attributes, and launches the app.

Option B:
- Right-click (or Control-click) "QuarkShield.app", select "Open" from
  the menu, and click "Open" in the dialog.

Option C (Terminal):
- Open Terminal and run:
  xattr -cr /Applications/QuarkShield.app
  open /Applications/QuarkShield.app

AUDITING MACOS ASSETS:
The macOS scanner automatically discovers:
- macOS System Keychains (/Library/Keychains, login.keychain-db, SystemRoots)
- OpenSSH keys and configurations (~/.ssh/id_rsa, ~/.ssh/config, /etc/ssh)
- Developer certificates, GPG keys, and local TLS configs
- Post-Quantum readiness scoring against NIST FIPS 203, 204, and CNSA 2.0

ACTIVE OUTBOUND TLS PROBE:
Audit any external server or API endpoint for post-quantum hybrid key exchange:
/Applications/QuarkShield.app/Contents/MacOS/quarkshield-scanner --probe "cloudflare.com"

ENTERPRISE FLEET & MDM DEPLOYMENT (Jamf / Kandji / Munki):
Run silent cryptographic discovery and register with QuarkShield Central:
/Applications/QuarkShield.app/Contents/MacOS/quarkshield-scanner --token "YOUR_FLEET_TOKEN" --register --quick

TO UNINSTALL:
- In GUI: Click "🗑️ Uninstall" in the top bar.
- Or simply move "QuarkShield.app" to Trash.

Publisher: FedMitigate LLC | Washington, D.C.
Support: support@quarkshield.ai | https://quarkshield.ai
========================================================================
