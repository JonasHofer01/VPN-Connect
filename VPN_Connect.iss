; VPN_Connect.iss
; Inno Setup Script für VPN Connect

#ifndef AppVersion
  #define AppVersion "4.0.12"
#endif

[Setup]
AppName=VPN Connect
AppVersion={#AppVersion}
DefaultDirName={commonpf}\VPN Connect
DefaultGroupName=VPN Connect
OutputDir=dist
OutputBaseFilename=VPN_Connect_Setup
SetupIconFile=assets\app_icon.ico
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
Source: "assets\app_icon.ico"; DestDir: "{app}\assets"; Flags: ignoreversion

[Icons]
Name: "{group}\VPN Connect"; Filename: "{app}\VPN_Connect.exe"
Name: "{group}\{cm:UninstallProgram,VPN Connect}"; Filename: "{uninstallexe}"
Name: "{userdesktop}\VPN Connect"; Filename: "{app}\VPN_Connect.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\VPN_Connect.exe"; Description: "{cm:LaunchProgram,VPN Connect}"; Flags: nowait postinstall skipifsilent runascurrentuser
Filename: "{app}\VPN_Connect.exe"; Flags: nowait runascurrentuser; Check: IsSilent

[Code]
function IsSilent: Boolean;
begin
  Result := WizardSilent;
end;
