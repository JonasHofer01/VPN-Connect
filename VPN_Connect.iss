; VPN_Connect.iss
; Inno Setup Script für VPN Connect

#ifndef AppVersion
  #define AppVersion "3.1.0"
#endif

[Setup]
AppName=VPN Connect
AppVersion={#AppVersion}
DefaultDirName={commonpf}\VPN Connect
DefaultGroupName=VPN Connect
OutputDir=dist
OutputBaseFilename=VPN_Connect_Setup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
CloseApplications=force
CloseApplicationsFilter=*.exe
AppMutex=Global\VPNConnectMutex
UninstallDisplayIcon={app}\VPN_Connect.exe
WizardStyle=modern

[Languages]
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\VPN_Connect.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\VPN Connect"; Filename: "{app}\VPN_Connect.exe"
Name: "{group}\{cm:UninstallProgram,VPN Connect}"; Filename: "{uninstallexe}"
Name: "{userdesktop}\VPN Connect"; Filename: "{app}\VPN_Connect.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\VPN_Connect.exe"; Description: "{cm:LaunchProgram,VPN Connect}"; Flags: nowait postinstall skipifsilent
Filename: "{app}\VPN_Connect.exe"; Flags: nowait; Check: IsSilent

[Code]
function IsSilent: Boolean;
begin
  Result := WizardSilent;
end;
