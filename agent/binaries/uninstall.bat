@echo off
title QuarkShield Post-Quantum Guard Uninstaller
echo ==================================================
echo  QuarkShield.AI Post-Quantum Guard Uninstaller
echo ==================================================
echo.
echo Stopping all running scanner services...
taskkill /F /IM quarkshield* /T >nul 2>&1
echo.
echo Removing Windows registrations...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\QuarkShieldPostQuantumGuard" /f >nul 2>&1
echo.
echo Cleaning up files...
del /f /q "%~dp0quarkshield-scanner-windows-amd64.exe" >nul 2>&1
del /f /q "%USERPROFILE%\Downloads\*quarkshield*.exe" >nul 2>&1
echo.
echo ==================================================
echo [OK] QuarkShield Post-Quantum Guard has been
echo      completely removed from this workstation.
echo ==================================================
echo.
pause
