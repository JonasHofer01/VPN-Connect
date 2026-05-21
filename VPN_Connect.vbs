Option Explicit

Dim fso, shell, scriptDir, appScript, pythonExe

Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("Shell.Application")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
appScript = fso.BuildPath(scriptDir, "vpn_connect.py")

If Not fso.FileExists(appScript) Then
    MsgBox "vpn_connect.py wurde nicht gefunden:" & vbCrLf & appScript, vbCritical, "VPN Connect"
    WScript.Quit 1
End If

pythonExe = fso.BuildPath(scriptDir, ".venv\Scripts\pythonw.exe")
If Not fso.FileExists(pythonExe) Then
    pythonExe = fso.BuildPath(scriptDir, ".venv\Scripts\python.exe")
End If
If Not fso.FileExists(pythonExe) Then
    pythonExe = "pythonw.exe"
End If

shell.ShellExecute pythonExe, """" & appScript & """", scriptDir, "runas", 1
