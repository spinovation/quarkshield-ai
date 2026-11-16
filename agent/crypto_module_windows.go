//go:build windows

package main

import (
	"path/filepath"
	"runtime"
	"strings"
)

// One PowerShell call: OS identity from the registry, then the file version of the CNG
// primitives library. Fields are pipe-separated; nothing is written.
const windowsModuleProbe = `$v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$f = Join-Path $env:SystemRoot 'System32\bcryptprimitives.dll'
$fv = ''
try { $fv = (Get-Item $f -ErrorAction Stop).VersionInfo.ProductVersion } catch {}
$p = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -ErrorAction SilentlyContinue
"$($v.ProductName)|$($v.DisplayVersion)|$($v.CurrentMajorVersionNumber).$($v.CurrentMinorVersionNumber).$($v.CurrentBuild).$($v.UBR)|$fv|$($p.Enabled)|$($p.MDMEnabled)"`

var (
	winProbeDone bool
	winProbeEnv  OperatingEnvironment
	winCNGFile   string
	winModeFacts []ModeFact
)

func windowsProbe() {
	if winProbeDone {
		return
	}
	winProbeDone = true
	winProbeEnv = OperatingEnvironment{ID: "windows", Arch: runtime.GOARCH}
	out, err := runProbe(winPowerShell(), "-NoProfile", "-NonInteractive", "-Command", windowsModuleProbe)
	if err != nil {
		RecordCollectorError("windows_crypto_module", err)
		return
	}
	name, display, version, fileVersion := parseWindowsProbe(out)
	winProbeEnv.Name = strings.TrimSpace(name + " " + display)
	winProbeEnv.Version = version
	winCNGFile = fileVersion
	const key = `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy`
	enabled, mdm := parseWindowsFipsPolicy(out)
	if enabled != "" {
		winModeFacts = append(winModeFacts, ModeFact{Name: "windows.fips_policy.enabled", Value: enabled, Source: key + `\Enabled`})
	}
	if mdm != "" {
		winModeFacts = append(winModeFacts, ModeFact{Name: "windows.fips_policy.mdm_enabled", Value: mdm, Source: key + `\MDMEnabled`})
	}
}

func detectPlatformModeFacts() []ModeFact {
	windowsProbe()
	return winModeFacts
}

func detectOperatingEnvironment() OperatingEnvironment {
	windowsProbe()
	return winProbeEnv
}

func detectPlatformModules(env OperatingEnvironment) []CryptoModule {
	windowsProbe()
	mods := []CryptoModule{}
	// The CNG primitives library is validated per Windows build, so the OS build is its
	// identity; the DLL's own file version is carried as evidence.
	if env.Version != "" {
		mods = append(mods, CryptoModule{
			Ref:      moduleRef(ModuleWindowsCNG, env.Version),
			Key:      ModuleWindowsCNG,
			Name:     "Windows Cryptographic Primitives Library (bcryptprimitives.dll)",
			Version:  env.Version,
			Evidence: "Registry CurrentVersion: " + env.Name + " build " + env.Version + "; bcryptprimitives.dll file version " + orUnknown(winCNGFile) + ".",
		})
	}
	return mods
}

func orUnknown(s string) string {
	if s == "" {
		return "not read"
	}
	return s
}

func sshBinaryPath() string {
	return existingFile(filepath.Join(windowsDir(), "System32", "OpenSSH", "ssh.exe"))
}
