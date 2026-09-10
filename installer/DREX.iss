#define MyAppName "DREX"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "DREX Team"
#define MyAppExeName "DREX.exe"

[Setup]
AppId={{7B95768E-17A2-4A0B-B5DC-DF65A7CE0B9B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\DREX
DefaultGroupName=DREX
OutputDir=..\build\installer
OutputBaseFilename=DREX-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName=DREX
VersionInfoDescription=DREX Secure Data Recovery and Sanitization Platform
VersionInfoProductName=DREX
VersionInfoProductVersion={#MyAppVersion}
Uninstallable=yes

[Files]
Source: "..\build\dist\DREX.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\DREX"; Filename: "{app}\DREX.exe"
Name: "{autodesktop}\DREX"; Filename: "{app}\DREX.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\DREX.exe"; Description: "Launch DREX"; Flags: nowait postinstall skipifsilent
