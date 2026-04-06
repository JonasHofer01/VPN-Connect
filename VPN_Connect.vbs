' VPN Connect Launcher
' Startet vpn_connect.py ueber das signierte pythonw.exe (umgeht Smart App Control)

Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")

' Pfad zum Skript ermitteln
scriptDir = FSO.GetParentFolderName(WScript.ScriptFullName)
pyScript = FSO.BuildPath(scriptDir, "vpn_connect.py")

' Python-Pfade durchsuchen
pythonExe = ""

' 1. Versuche venv im Projektordner
venvPython = FSO.BuildPath(scriptDir, ".venv\Scripts\pythonw.exe")
If FSO.FileExists(venvPython) Then
    pythonExe = venvPython
End If

' 2. Versuche System-Python (verschiedene Versionen)
If pythonExe = "" Then
    Dim versions
    versions = Array("3.14", "3.13", "3.12", "3.11", "3.10")
    For Each ver In versions
        On Error Resume Next
        Dim regPath
        regPath = WshShell.RegRead("HKLM\SOFTWARE\Python\PythonCore\" & ver & "\InstallPath\")
        If Err.Number = 0 And regPath <> "" Then
            Dim candidate
            candidate = regPath & "pythonw.exe"
            If FSO.FileExists(candidate) Then
                pythonExe = candidate
                Exit For
            End If
        End If
        Err.Clear
        On Error GoTo 0
    Next
End If

' 3. Fallback: pythonw.exe im PATH
If pythonExe = "" Then
    pythonExe = "pythonw.exe"
End If

' Direkt starten - das Skript selbst fordert Admin-Rechte an via ShellExecuteW
WshShell.CurrentDirectory = scriptDir
WshShell.Run """" & pythonExe & """ """ & pyScript & """", 0, False
