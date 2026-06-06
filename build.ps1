# VPN_Connect Build-Skript
# Baut die EXE mit korrektem runtime_tmpdir (umgeht AppLocker DLL-Blockierung)

Write-Host "=== VPN_Connect Build ===" -ForegroundColor Cyan

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$venv = Join-Path $PSScriptRoot ".venv\Scripts\pyinstaller.exe"
$icon = Join-Path $PSScriptRoot "assets\app_icon.ico"
$iconScript = Join-Path $PSScriptRoot "tools\generate_app_icon.py"

if (-not (Test-Path $venv)) {
    Write-Host "FEHLER: PyInstaller nicht gefunden. Bitte zuerst: pip install pyinstaller" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $icon)) {
    if ((Test-Path $python) -and (Test-Path $iconScript)) {
        Write-Host "Erstelle App-Icon..." -ForegroundColor Cyan
        & $python $iconScript
    }
    if (-not (Test-Path $icon)) {
        Write-Host "FEHLER: App-Icon nicht gefunden: $icon" -ForegroundColor Red
        exit 1
    }
}

& $venv --noconfirm `
    --onefile `
    --windowed `
    --name VPN_Connect `
    --uac-admin `
    --icon $icon `
    --runtime-tmpdir "C:\ProgramData\VPNConnect" `
    (Join-Path $PSScriptRoot "vpn_connect.py")

if ($LASTEXITCODE -eq 0) {
    $src = Join-Path $PSScriptRoot "dist\VPN_Connect.exe"
    $dst = Join-Path $PSScriptRoot "VPN_Connect.exe"
    Copy-Item $src $dst -Force
    $size = [math]::Round((Get-Item $dst).Length / 1MB, 1)
    Write-Host "`nBuild erfolgreich! VPN_Connect.exe ($size MB)" -ForegroundColor Green

    # Inno Setup Compiler (iscc.exe) suchen
    $iscc = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    if (-not (Test-Path $iscc)) {
        # Fallback auf PATH-Suche
        $iscc = Get-Command iscc -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    }

    if ($iscc) {
        Write-Host "`nErstelle Installer mit Inno Setup..." -ForegroundColor Cyan
        & $iscc /DAppVersion="4.0.8" (Join-Path $PSScriptRoot "VPN_Connect.iss")
        if ($LASTEXITCODE -eq 0) {
            $setupPath = Join-Path $PSScriptRoot "dist\VPN_Connect_Setup.exe"
            $setupSize = [math]::Round((Get-Item $setupPath).Length / 1MB, 1)
            Write-Host "Installer erfolgreich erstellt! dist\VPN_Connect_Setup.exe ($setupSize MB)" -ForegroundColor Green
        } else {
            Write-Host "Installer-Build fehlgeschlagen!" -ForegroundColor Red
        }
    } else {
        Write-Host "`nHINWEIS: Inno Setup (ISCC.exe) nicht gefunden. Installer-Build übersprungen." -ForegroundColor Yellow
        Write-Host "Installieren Sie Inno Setup 6, um Installer-Builds lokal zu erstellen." -ForegroundColor Yellow
    }
} else {
    Write-Host "`nBuild fehlgeschlagen!" -ForegroundColor Red
}
