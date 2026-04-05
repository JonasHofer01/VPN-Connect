# VPN Connect

Eine Windows-Desktop-App zum Verbinden mit WireGuard VPN, Wake-on-LAN via UpSnap und RDP-Zugriff – alles in einem Tool.

![Screenshot](https://img.shields.io/badge/Platform-Windows-blue)
![Python](https://img.shields.io/badge/Python-3.12+-green)

## Features

- **WireGuard VPN** – Tunnel verbinden/trennen mit einem Klick
- **UpSnap Integration** – Geräte per Wake-on-LAN aufwecken
- **RDP** – Remote-Desktop direkt aus der App starten
- **Auto-Update** – Neue Versionen werden automatisch von GitHub heruntergeladen
- **Einzelne EXE** – Kein Python-Installation nötig

## Installation

1. Lade die neueste `VPN_Connect.exe` von den [Releases](https://github.com/JonasHofer01/VPN-Connect/releases) herunter
2. Doppelklick → UAC-Prompt bestätigen (Admin-Rechte nötig für WireGuard)
3. Fertig!

## Entwicklung

```bash
# Repository klonen
git clone https://github.com/JonasHofer01/VPN-Connect.git
cd VPN-Connect

# Virtual Environment erstellen
python -m venv .venv
.venv\Scripts\activate

# Abhängigkeiten installieren
pip install pyinstaller

# EXE bauen
pyinstaller --onefile --windowed --name VPN_Connect --uac-admin vpn_connect.py
```

## Release erstellen

Ein neues Release wird automatisch gebaut, wenn ein Git-Tag gepusht wird:

```bash
# Version in vpn_connect.py anpassen (APP_VERSION = "1.1.0")
git add -A
git commit -m "Release v1.1.0"
git tag v1.1.0
git push origin main --tags
```

GitHub Actions baut dann automatisch die EXE und erstellt ein Release.

## Voraussetzungen

- [WireGuard](https://www.wireguard.com/install/) muss installiert sein
- `.conf`-Dateien im selben Ordner wie die EXE oder unter `C:\Program Files\WireGuard\Data\Configurations`

## Lizenz

MIT

