//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
}

// detachConsole closes and detaches the Windows console window so it doesn't linger on screen
func detachConsole() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	freeConsole := kernel32.NewProc("FreeConsole")
	_, _, _ = freeConsole.Call()
}

// createDesktopAndStartMenuShortcuts installs .lnk shortcuts on user's Desktop and Start Menu
func createDesktopAndStartMenuShortcuts() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	exeDir := filepath.Dir(exePath)

	psScript := fmt.Sprintf(`
$ws = New-Object -ComObject WScript.Shell
$exe = '%s'
$dir = '%s'
$desk = [System.Environment]::GetFolderPath('Desktop')
$progs = [System.Environment]::GetFolderPath('Programs')

if ($desk -and (Test-Path $desk)) {
    $s1 = $ws.CreateShortcut("$desk\QuarkShield Post-Quantum Guard.lnk")
    $s1.TargetPath = $exe
    $s1.WorkingDirectory = $dir
    $s1.Description = 'QuarkShield Post-Quantum Cryptographic Guard'
    $s1.IconLocation = "$exe,0"
    $s1.Save()
}

if ($progs -and (Test-Path $progs)) {
    $s2 = $ws.CreateShortcut("$progs\QuarkShield Post-Quantum Guard.lnk")
    $s2.TargetPath = $exe
    $s2.WorkingDirectory = $dir
    $s2.Description = 'QuarkShield Post-Quantum Cryptographic Guard'
    $s2.IconLocation = "$exe,0"
    $s2.Save()
}
`, exePath, exeDir)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psScript)
	hideConsole(cmd)
	_ = cmd.Run()
}

// removeDesktopAndStartMenuShortcuts cleans up shortcuts on uninstall
func removeDesktopAndStartMenuShortcuts() {
	psScript := `
$desk = [System.Environment]::GetFolderPath('Desktop')
$progs = [System.Environment]::GetFolderPath('Programs')
if ($desk) { Remove-Item "$desk\QuarkShield Post-Quantum Guard.lnk" -ErrorAction SilentlyContinue }
if ($progs) { Remove-Item "$progs\QuarkShield Post-Quantum Guard.lnk" -ErrorAction SilentlyContinue }
`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psScript)
	hideConsole(cmd)
	_ = cmd.Run()
}

// pickFolderOS opens a native Windows folder browser dialog guaranteed to be in the foreground
func pickFolderOS() string {
	psScript := `try {
    Add-Type -AssemblyName System.Windows.Forms
    $f = New-Object System.Windows.Forms.Form
    $f.TopMost = $true
    $f.TopLevel = $true
    $f.ShowInTaskbar = $true
    $f.StartPosition = 'CenterScreen'
    $f.WindowState = 'Normal'
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Select Directory or Drive to Audit for Post-Quantum Readiness'
    $dlg.RootFolder = 'MyComputer'
    $dlg.SelectedPath = 'C:\'
    $dlg.ShowNewFolderButton = $false
    $res = $dlg.ShowDialog($f)
    if ($res -eq [System.Windows.Forms.DialogResult]::OK) {
        [Console]::Out.Write($dlg.SelectedPath)
    }
    $f.Dispose()
} catch {
    $s = New-Object -ComObject Shell.Application
    $f = $s.BrowseForFolder(0, 'Select Directory to Audit', 0x00000010, 17)
    if ($f) { [Console]::Out.Write($f.Self.Path) }
}`

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-Sta",
		"-WindowStyle", "Hidden",
		"-Command", psScript,
	)
	// Do NOT set CREATE_NO_WINDOW here: Windows needs the process to be treated as
	// an interactive desktop session so the WinForms dialog can be elevated to the foreground.
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
