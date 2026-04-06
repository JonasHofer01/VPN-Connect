# VPN Connect

Eine Windows-Desktop-App zum Verbinden mit WireGuard VPN, Wake-on-LAN via UpSnap und RDP-Zugriff – alles in einem Tool.

![Screenshot](https://img.shields.io/badge/Platform-Windows-blue)
![Python](https://img.shields.io/badge/Python-3.12+-green)

## Features

- **WireGuard VPN** – Tunnel verbinden/trennen mit einem Klick
- **UpSnap Integration** – Geräte per Wake-on-LAN aufwecken
- **RDP** – Remote-Desktop direkt aus der App starten
- **Auto-Update** – Neue Versionen werden automatisch von GitHub heruntergeladen

## Installation

### Variante A: EXE (empfohlen)

1. Lade die neueste `VPN_Connect.exe` von den [Releases](https://github.com/JonasHofer01/VPN-Connect/releases) herunter
2. Doppelklick → UAC-Prompt bestätigen (Admin-Rechte nötig für WireGuard)

> **Hinweis:** Falls Smart App Control aktiv ist, kann die EXE blockiert werden.
> In dem Fall: Windows-Sicherheit → App- & Browsersteuerung → Smart App Control → **Aus**.
> Alternativ den `VPN_Connect.vbs` Launcher nutzen (verwendet das signierte `pythonw.exe`).

### Variante B: Python-Skript

1. Python 3.12+ installieren
2. `pip install PyQt6`
3. `VPN_Connect.vbs` doppelklicken oder `pythonw.exe vpn_connect.py` ausführen

## Entwicklung

```bash
# Repository klonen
git clone https://github.com/JonasHofer01/VPN-Connect.git
cd VPN-Connect

# Virtual Environment erstellen
python -m venv .venv
.venv\Scripts\activate

# Abhängigkeiten installieren
pip install -r requirements.txt

# App starten
python vpn_connect.py

# EXE bauen
.\build.ps1
```

## Projektstruktur

```
vpn_connect.py      # Hauptprogramm (PyQt6 GUI)
VPN_Connect.vbs     # Launcher (umgeht Smart App Control)
build.ps1           # Build-Skript (erstellt EXE via PyInstaller)
requirements.txt    # Python-Abhängigkeiten
.github/workflows/  # CI/CD (GitHub Actions)
```

## Release erstellen

```bash
# Version in vpn_connect.py anpassen (APP_VERSION = "1.3.0")
git add -A
git commit -m "Release v1.3.0"
git tag v1.3.0
git push origin main --tags
```

GitHub Actions baut dann automatisch die EXE und erstellt ein Release.

## Voraussetzungen

- [WireGuard](https://www.wireguard.com/install/) muss installiert sein
- `.conf`-Dateien im selben Ordner oder unter `C:\Program Files\WireGuard\Data\Configurations`

## Lizenz

MIT
