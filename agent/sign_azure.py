#!/usr/bin/env python3
"""
QuarkShield Automated Azure Trusted Signing Pipeline
Signs Windows executables (.exe) and packages using Azure Trusted Signing (formerly ACS)
Certificate Authority: Microsoft ID Verified CS AOC CA 03
Publisher: CN=Fedmitigate LLC, O=Fedmitigate LLC, L=Sheridan, S=Wyoming, C=US

Credentials are loaded securely from .env.signing or environment variables.
"""

import os
import sys
import json
import urllib.parse
import urllib.request
import subprocess

def load_env_file(filepath):
    """Load key-value pairs from .env file if it exists."""
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key not in os.environ:
                        os.environ[key] = val

# Automatically check for local .env.signing
script_dir = os.path.dirname(os.path.abspath(__file__))
load_env_file(os.path.join(script_dir, ".env.signing"))
load_env_file(os.path.join(script_dir, "../.env"))

def get_azure_token(tenant_id, client_id, client_secret):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": "https://codesigning.azure.net/.default"
    }
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    
    with urllib.request.urlopen(req, timeout=30) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        return res["access_token"]

def sign_binary(target_path, tenant_id=None, client_id=None, client_secret=None,
                account=None, profile=None, endpoint=None, tsa_url=None):
    tenant_id = tenant_id or os.environ.get("AZURE_TENANT_ID")
    client_id = client_id or os.environ.get("AZURE_CLIENT_ID")
    client_secret = client_secret or os.environ.get("AZURE_CLIENT_SECRET")
    account = account or os.environ.get("AZURE_CODE_SIGNING_ACCOUNT", "fedmitigatesigning2026")
    profile = profile or os.environ.get("AZURE_CERT_PROFILE", "FedMitigate")
    endpoint = endpoint or os.environ.get("AZURE_ENDPOINT", "eus.codesigning.azure.net")
    tsa_url = tsa_url or os.environ.get("AZURE_TSA_URL", "http://timestamp.acs.microsoft.com")

    if not all([tenant_id, client_id, client_secret]):
        print("[-] Missing Azure credentials. Set AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET in .env.signing or environment.", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(target_path):
        print(f"[-] Target file not found: {target_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Authenticating with Microsoft Azure Entra ID (Tenant: {tenant_id[:8]}...)...")
    token = get_azure_token(tenant_id, client_id, client_secret)
    print("[+] Successfully acquired Azure Trusted Signing OAuth2 bearer token.")

    # Strip existing signature if present using osslsigncode if available
    osslsigncode_bin = subprocess.run(["which", "osslsigncode"], capture_output=True, text=True).stdout.strip()
    if osslsigncode_bin:
        clean_tmp = target_path + ".clean"
        strip_res = subprocess.run([osslsigncode_bin, "remove-signature", target_path, clean_tmp],
                                   capture_output=True)
        if strip_res.returncode == 0 and os.path.exists(clean_tmp):
            os.replace(clean_tmp, target_path)
            print("[+] Stripped legacy/unsigned Authenticode blocks.")

    # Locate jsign
    jsign_bin = subprocess.run(["which", "jsign"], capture_output=True, text=True).stdout.strip() or "/opt/homebrew/bin/jsign"
    if not os.path.exists(jsign_bin):
        print(f"[-] Jsign executable not found at {jsign_bin}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Applying Authenticode Signature via Azure Trusted Signing...")
    print(f"    Account:  {account}")
    print(f"    Profile:  {profile}")
    print(f"    Endpoint: {endpoint}")
    print(f"    Target:   {target_path}")

    cmd = [
        jsign_bin,
        "--storetype", "TRUSTEDSIGNING",
        "--keystore", endpoint,
        "--alias", f"{account}/{profile}",
        "--storepass", token,
        "--alg", "SHA-256",
        "--name", "QuarkShield Post-Quantum Guard",
        "--url", "https://quarkshield.ai",
        "--tsaurl", tsa_url,
        "-m", "RFC3161",
        target_path
    ]

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[-] Signing failed (code {res.returncode}):\n{res.stderr}\n{res.stdout}", file=sys.stderr)
        sys.exit(res.returncode)

    print(f"[+] Successfully signed {target_path}!")
    print(f"    Output: {res.stdout.strip()}")

    # Verify signature if osslsigncode is available
    if osslsigncode_bin:
        print("[*] Verifying embedded Authenticode signature...")
        v_res = subprocess.run([osslsigncode_bin, "verify", target_path], capture_output=True, text=True)
        print(v_res.stdout)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sign_azure.py <path-to-exe>")
        sys.exit(1)
    sign_binary(sys.argv[1])
