
#define MyAppName "AllamSec"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "AllamSec"
#define MyAppExeName "AllamSec.exe"
#define BuildDir GetEnv("LOCALAPPDATA") + "\AllamSecDist\AllamSec"

[Setup]
AppId={{A5B97A3E-7B52-48D1-A2C9-6B7E4F2D1A10}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\AllamSec-v1.1.0
DefaultGroupName=AllamSec v1.1.0
OutputDir=installer-output
OutputBaseFilename=AllamSec-Setup-v1.1.0
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#BuildDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\AllamSec"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall AllamSec"; Filename: "{uninstallexe}"
Name: "{autodesktop}\AllamSec v1.1.0"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch AllamSec"; Flags: nowait postinstall skipifsilent
