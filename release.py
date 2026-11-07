import os
import re
import subprocess
import sys
import hashlib

def calculate_sha256(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

def update_file(filepath, pattern, replacement):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    new_content = re.sub(pattern, replacement, content)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)

def main():
    print("Starte Release-Prozess...")

    # 1. Aktuelle Version aus vpn_connect.py auslesen
    with open('vpn_connect.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    match = re.search(r'APP_VERSION\s*=\s*"(\d+)\.(\d+)\.(\d+)"', content)
    if not match:
        print("Fehler: Konnte APP_VERSION in vpn_connect.py nicht finden.")
        sys.exit(1)
        
    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    new_patch = patch + 1
    new_version = f"{major}.{minor}.{new_patch}"
    new_tag = f"v{new_version}"
    
    print(f"Aktuelle Version: {major}.{minor}.{patch}")
    print(f"Neue Version: {new_version} ({new_tag})")
    
    # 2. Version in Dateien aktualisieren
    print("Aktualisiere Dateien...")
    update_file('vpn_connect.py', r'APP_VERSION\s*=\s*"\d+\.\d+\.\d+"', f'APP_VERSION = "{new_version}"')
    update_file('VPN_Connect.iss', r'#define AppVersion "\d+\.\d+\.\d+"', f'#define AppVersion "{new_version}"')
    update_file('build.ps1', r'/DAppVersion="\d+\.\d+\.\d+"', f'/DAppVersion="{new_version}"')

    # 3. Git Commit und Push
    print("Erstelle Git Commit...")
    try:
        subprocess.run(["git", "add", "vpn_connect.py", "VPN_Connect.iss", "build.ps1"], check=True)
        subprocess.run(["git", "commit", "-m", f"Bump version to {new_version}"], check=True)
        
        print("Pushe zum Repository...")
        subprocess.run(["git", "push", "origin", "main"], check=True)
        
        print(f"Erstelle Git Tag {new_tag}...")
        subprocess.run(["git", "tag", new_tag], check=True)
        subprocess.run(["git", "push", "origin", new_tag], check=True)
        
        print("\nGit Push und Tag-Erstellung erfolgreich!")
        print("Der GitHub Actions CI/CD-Workflow wurde getriggert.")
        print(f"Er wird die EXE und das Setup bauen und das Release {new_tag} automatisch erstellen.")
    except subprocess.CalledProcessError as e:
        print(f"Fehler bei Git-Operationen: {e}")
        sys.exit(1)

    print("Release-Prozess lokal abgeschlossen!")

if __name__ == "__main__":
    main()
