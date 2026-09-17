========================================================================
 QuarkShield Post-Quantum Cryptographic Desktop Guard v2.1
 Published by FedMitigate LLC
 Microsoft Authenticode Digitally Signed
========================================================================

QUICK START:
1. Double-click "quarkshield-scanner-windows-amd64.exe" to launch the 
   interactive Desktop GUI in your web browser (http://127.0.0.1:48291).
   
2. Publisher Verification:
   This binary is signed and verified under Microsoft Azure Trusted Signing:
   - Publisher: Fedmitigate LLC (Sheridan, WY)
   - Root Authority: Microsoft Identity Verification Root Certificate Authority
   - Windows SmartScreen and UAC will natively recognize the publisher.

3. Shortcuts:
   A Desktop shortcut and Start Menu shortcut will automatically be created
   on first launch with the official QuarkShield shield icon.

4. Licensing & Fleet Sync:
   The scanner runs in a 7-day offline evaluation mode by default.
   To link with your centralized QuarkShield Fleet or activate a license:
   - In GUI: Click "⏱️ 7-Day Trial" or "🌐 Connect to Fleet" in the top bar.
   - Or run via PowerShell / Command Prompt:
     .\quarkshield-scanner-windows-amd64.exe --token "QS-CORP-..."

ACTIVE OUTBOUND TLS PROBE:
- Audit any external server or API endpoint for post-quantum hybrid key exchange:
  .\quarkshield-scanner-windows-amd64.exe --probe "cloudflare.com"

SILENT / MDM ENTERPRISE DEPLOYMENT (Intune / GPO / SCCM):
  quarkshield-scanner-windows-amd64.exe --token "QS-CORP-..." --register

TO UNINSTALL:
- Run "uninstall.bat" or click "🗑️ Uninstall" in the GUI.

Publisher: FedMitigate LLC | Reston, VA & Sheridan, WY
Support: support@quarkshield.ai | https://quarkshield.ai
========================================================================
