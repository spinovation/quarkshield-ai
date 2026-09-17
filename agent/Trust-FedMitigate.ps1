<#
.SYNOPSIS
    Installs the FedMitigate LLC Code Signing Certificate into Windows Trusted Publisher store.
.DESCRIPTION
    This script adds FedMitigate LLC and FedMitigate Root Certificate Authority to
    the CurrentUser and LocalMachine Trusted Publishers and Root Certification Authorities stores.
    After running this, Windows will verify all QuarkShield packages as signed by 'Verified Publisher: FedMitigate LLC'.
#>

[CmdletBinding()]
param()

$CertDir = $PSScriptRoot
if (-not $CertDir) { $CertDir = (Get-Location).Path }

$RootCert = Join-Path $CertDir "FedMitigate-Root-CA.cer"
$CodeSignCert = Join-Path $CertDir "FedMitigate-LLC-CodeSigning.cer"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  FedMitigate LLC - Trusted Publisher Installation       " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

if (-not (Test-Path $RootCert)) {
    Write-Error "Root certificate not found at: $RootCert"
    exit 1
}

try {
    # 1. Install Root CA into CurrentUser Root
    Write-Host "[*] Installing FedMitigate Root CA into Trusted Root store..." -ForegroundColor Yellow
    Import-Certificate -FilePath $RootCert -CertStoreLocation "Cert:\CurrentUser\Root" | Out-Null
    Write-Host "[+] Trusted Root CA installed successfully." -ForegroundColor Green

    # 2. Install Code Signing cert into CurrentUser TrustedPublisher
    if (Test-Path $CodeSignCert) {
        Write-Host "[*] Installing FedMitigate LLC into Trusted Publishers store..." -ForegroundColor Yellow
        Import-Certificate -FilePath $CodeSignCert -CertStoreLocation "Cert:\CurrentUser\TrustedPublisher" | Out-Null
        Write-Host "[+] Trusted Publisher certificate installed successfully." -ForegroundColor Green
    }

    # 3. If running as Administrator, also install to LocalMachine
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Host "[*] Administrator privileges detected. Installing for all users on this machine..." -ForegroundColor Yellow
        Import-Certificate -FilePath $RootCert -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
        if (Test-Path $CodeSignCert) {
            Import-Certificate -FilePath $CodeSignCert -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
        }
        Write-Host "[+] Machine-wide Trusted Publisher configured." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "[SUCCESS] FedMitigate LLC is now configured as a Trusted Publisher on this system." -ForegroundColor Green
    Write-Host "QuarkShield Post-Quantum Guard binaries are fully verified and trusted." -ForegroundColor Green
} catch {
    Write-Error "Failed to install certificates: $_"
    exit 1
}
