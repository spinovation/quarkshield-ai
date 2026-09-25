======================================================================
 QuarkShield.AI Post-Quantum Guard — Linux Deployment & Usage Guide
======================================================================

QuarkShield is a zero-dependency, statically-linked Post-Quantum
Cryptographic Auditor and Software Bill of Materials (SBOM) engine.

1. ARCHITECTURES SUPPORTED:
   • x86_64 / amd64 (Intel & AMD Linux)
   • aarch64 / arm64 (AWS Graviton, Ampere, Raspberry Pi 4/5)

2. INSTALLATION (3 OPTIONS):

   Option A — Instant 1-Click Online Installer:
     curl -fsSL https://quarkshield.ai/api/scan/agent/install.sh | sudo bash -s -- --token YOUR_FLEET_TOKEN

   Option B — Local Package Installer:
     sudo chmod +x install-linux.sh
     sudo ./install-linux.sh

   Option C — Manual Binary Execution:
     chmod +x quarkshield-scanner-linux-amd64
     ./quarkshield-scanner-linux-amd64 --quick

3. MODES OF OPERATION:

   • Interactive Web GUI:
     quarkshield-scanner --gui
     (Launches embedded web dashboard on http://127.0.0.1:48291)

   • Quick Workstation / Host Audit:
     quarkshield-scanner --quick

   • Custom Path Cryptographic Audit:
     quarkshield-scanner --path /etc/nginx/ssl

   • Active Outbound TLS Socket Probe:
     quarkshield-scanner --probe api.github.com:443

   • Standardized CycloneDX 1.6 CBOM Export:
     quarkshield-scanner --cbom -o cbom-report.json

   • Fleet Registration & Continuous Sync:
     quarkshield-scanner --server https://quarkshield.ai --token <YOUR_TOKEN> --register --quick

4. BACKGROUND SYSTEMD SERVICE (OPTIONAL):
   To run QuarkShield continuously as a managed systemd background service:
     sudo cp quarkshield.service /etc/systemd/system/
     sudo systemctl daemon-reload
     sudo systemctl enable --now quarkshield

5. UNINSTALLATION:
   sudo ./uninstall-linux.sh

======================================================================
Copyright (c) 2026 FedMitigate LLC. All rights reserved.
Official Website: https://quarkshield.ai
Documentation: https://quarkshield.ai/docs/LINUX_USER_GUIDE.md
======================================================================
