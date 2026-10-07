; ==============================================================================
; QuarkShield Post-Quantum Guard - Windows Installer (Inno Setup)
; Build on Windows:  ISCC.exe quarkshield.iss   (or via a Windows CI runner / Wine)
; Expects the signed agent exe at: ..\quarkshield-scanner-windows-amd64.exe
; and the icon at:                 ..\app_icon.ico
; Output:  Output\QuarkShield-Setup.exe   (sign this with Azure Trusted Signing after)
; ==============================================================================

#define MyAppName "QuarkShield Post-Quantum Guard"
#define MyAppShortName "QuarkShield"
#define MyAppPublisher "Fedmitigate LLC"
#define MyAppURL "https://quarkshield.ai"
#define MyAppExeName "quarkshield-scanner.exe"
#ifndef MyAppVersion
  #define MyAppVersion "2.2.1"
#endif

[Setup]
AppId={{C15D3395-6650-4353-963B-5ACFCE240045}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppShortName}
DefaultGroupName={#MyAppShortName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
OutputDir=Output
OutputBaseFilename=QuarkShield-Setup
SetupIconFile=..\app_icon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Per-user install by default (no admin prompt); switch to "admin" for Program Files.
PrivilegesRequiredOverridesAllowed=dialog
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "launchonstartup"; Description: "Start QuarkShield automatically when I sign in"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
Source: "..\quarkshield-scanner-windows-amd64.exe"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: ignoreversion
Source: "..\app_icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\app_icon.ico"
Name: "{group}\Uninstall {#MyAppShortName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\app_icon.ico"; Tasks: desktopicon

[Registry]
; Optional auto-start at sign-in (only if the user ticks the task)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "QuarkShield"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue; Tasks: launchonstartup

[Run]
; Launch the local scanner GUI right after install (opens 127.0.0.1 dashboard in the browser)
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppShortName}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Remove the managed-install marker (and app dir) on uninstall.
Type: files; Name: "{app}\.managed_install"

[Code]
{ Drop a marker so the agent knows the installer owns shortcuts + Add/Remove entry
  (agent/gui.go: isManagedInstall) and won't self-create duplicates. }
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    SaveStringToFile(ExpandConstant('{app}\.managed_install'), 'installed', False);
end;
