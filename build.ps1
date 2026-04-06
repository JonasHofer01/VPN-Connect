# VPN_Connect Build-Skript
# Baut die EXE mit korrektem runtime_tmpdir (umgeht AppLocker DLL-Blockierung)

Write-Host "=== VPN_Connect Build ===" -ForegroundColor Cyan

$venv = Join-Path $PSScriptRoot ".venv\Scripts\pyinstaller.exe"
if (-not (Test-Path $venv)) {
    Write-Host "FEHLER: PyInstaller nicht gefunden. Bitte zuerst: pip install pyinstaller" -ForegroundColor Red
    exit 1
}

& $venv --noconfirm `
    --onefile `
    --windowed `
    --name VPN_Connect `
    --uac-admin `
    --runtime-tmpdir "C:\ProgramData\VPNConnect" `
    (Join-Path $PSScriptRoot "vpn_connect.py")

if ($LASTEXITCODE -eq 0) {
    $src = Join-Path $PSScriptRoot "dist\VPN_Connect.exe"
    $dst = Join-Path $PSScriptRoot "VPN_Connect.exe"
    Copy-Item $src $dst -Force
    $size = [math]::Round((Get-Item $dst).Length / 1MB, 1)
    Write-Host "`nBuild erfolgreich! VPN_Connect.exe ($size MB)" -ForegroundColor Green
} else {
    Write-Host "`nBuild fehlgeschlagen!" -ForegroundColor Red
}

