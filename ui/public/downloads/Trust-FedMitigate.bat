@echo off
title QuarkShield - Trust FedMitigate LLC Publisher
echo ========================================================
echo   Configuring FedMitigate LLC as Trusted Publisher...
echo ========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Trust-FedMitigate.ps1"
echo.
pause
