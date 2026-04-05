import subprocess
import time
import socket
import os
import sys
import ctypes
import signal
import atexit
import json
import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, List, Tuple
from urllib import request, error

# =============================================================================
#  KONFIGURATION
# =============================================================================

APP_VERSION = "1.2.0"
GITHUB_REPO = "JonasHofer01/VPN-Connect"   # owner/repo

CONFIG_BASE = r"C:\Program Files\WireGuard\Data\Configurations"
TARGET_IP = "192.168.178.5"
TARGET_PORT = 8090

WG_CONFIG_CONTENT = ""

# Konsole verstecken
if sys.platform == "win32":
    try:
        ctypes.windll.kernel32.FreeConsole()
    except Exception:
        pass

SW_HIDE = 0
CREATE_NO_WINDOW = 0x08000000
STARTUPINFO = subprocess.STARTUPINFO()
STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW
STARTUPINFO.wShowWindow = SW_HIDE

# =============================================================================
#  LOGGING
# =============================================================================

# Im PyInstaller-Onefile-Modus liegt __file__ in einem Temp-Verzeichnis,
# daher das Log neben die .exe / das Script legen.
if getattr(sys, 'frozen', False):
    _base_dir = os.path.dirname(sys.executable)
else:
    _base_dir = os.path.dirname(os.path.abspath(__file__))

log_file = os.path.join(_base_dir, "vpn_debug.log")

# Log-Rotation: wenn > 1 MB, alte Datei löschen
try:
    if os.path.exists(log_file) and os.path.getsize(log_file) > 1_000_000:
        os.remove(log_file)
except OSError:
    pass

logging.basicConfig(filename=log_file, level=logging.DEBUG,
                    format="%(asctime)s - %(levelname)s - %(message)s")

_app: Optional["VPNApp"] = None


def log(msg: str, level: str = "info") -> None:
    getattr(logging, level, logging.info)(msg)
    if _app:
        _app.append_log(msg)


# =============================================================================
#  ADMIN
# =============================================================================

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def run_as_admin() -> None:
    args = []
    for arg in sys.argv:
        args.append(f'"{arg}"' if " " in arg else arg)
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(args), _base_dir, 1)


# =============================================================================
#  HILFSFUNKTIONEN
# =============================================================================

def _run_silent(cmd: list, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, startupinfo=STARTUPINFO,
                          creationflags=CREATE_NO_WINDOW, **kw)


def extract_tunnel_name(config_path: str) -> str:
    fn = os.path.basename(config_path)
    return fn[:-11] if fn.endswith(".conf.dpapi") else os.path.splitext(fn)[0]


# =============================================================================
#  WIREGUARD
# =============================================================================

# Trackt ob WIR den Tunnel installiert haben (vs. bereits laufend)
_we_installed_tunnel = False


def collect_all_configs() -> List[Tuple[str, str]]:
    configs: List[Tuple[str, str]] = []
    try:
        for f in os.listdir(_base_dir):
            if f.endswith(".conf") and not f.endswith(".conf.dpapi"):
                configs.append((f"{f}  (lokal)", os.path.join(_base_dir, f)))
    except Exception:
        pass
    if "REPLACE_ME" not in WG_CONFIG_CONTENT and len(WG_CONFIG_CONTENT.strip()) > 10:
        p = os.path.join(_base_dir, "embedded_tunnel.conf")
        with open(p, "w") as fh:
            fh.write(WG_CONFIG_CONTENT)
        configs.append(("embedded_tunnel.conf  (eingebettet)", p))
    if os.path.exists(CONFIG_BASE):
        try:
            for f in sorted(os.listdir(CONFIG_BASE)):
                if f.endswith(".conf.dpapi"):
                    configs.append((f[:-11] + "  (System)",
                                    os.path.join(CONFIG_BASE, f)))
        except Exception as e:
            log(f"Scan-Fehler: {e}", "error")
    return configs


def _service_state(tunnel_name: str) -> str:
    """Gibt 'RUNNING', 'STOPPED', oder '' zurück."""
    sn = f"WireGuardTunnel${tunnel_name}"
    try:
        r = _run_silent(["sc", "query", sn],
                        capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return ""
        for line in r.stdout.splitlines():
            if "STATE" in line:
                if "RUNNING" in line:
                    return "RUNNING"
                if "STOPPED" in line:
                    return "STOPPED"
        return "UNKNOWN"
    except Exception:
        return ""


def wait_for_tunnel(tunnel_name: str, timeout: int = 30) -> bool:
    log(f"Warte auf Tunnel '{tunnel_name}' (max {timeout}s)...")
    start = time.time()
    while time.time() - start < timeout:
        if _cancel_event.is_set():
            log("Tunnel-Warten abgebrochen.", "warning")
            return False
        try:
            if _service_state(tunnel_name) != "RUNNING":
                raise RuntimeError("not running")
            r = _run_silent(["netsh", "interface", "show", "interface"],
                            capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if tunnel_name in line and ("Connected" in line or "Verbunden" in line):
                    log(f"Tunnel '{tunnel_name}' ist aktiv.")
                    return True
        except Exception:
            pass
        elapsed = int(time.time() - start)
        log(f"  Aufbau... ({elapsed}s/{timeout}s)")
        time.sleep(1)
    log(f"Timeout nach {timeout}s.", "warning")
    return False


def check_connection(ip: str, port: int, timeout: int = 5,
                     retries: int = 5, delay: float = 2.0) -> bool:
    for i in range(1, retries + 1):
        if _cancel_event.is_set():
            return False
        log(f"Verbindungstest {ip}:{port} ({i}/{retries})...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            log(f"Verbunden mit {ip}:{port}")
            return True
        except socket.timeout:
            log(f"Timeout", "warning")
        except ConnectionRefusedError:
            log(f"Abgelehnt", "warning")
        except Exception as e:
            log(f"Fehler: {e}", "warning")
        if i < retries:
            time.sleep(delay)
    log(f"Nicht erreichbar: {ip}:{port}", "error")
    return False


def _wait_service_gone(tn: str, timeout: int = 15) -> bool:
    """Wartet bis der Dienst komplett entfernt ist."""
    for _ in range(timeout):
        if not _service_state(tn):
            return True
        time.sleep(1)
    return not _service_state(tn)


# ── Dialog-Auto-Schließer ────────────────────────────────────────────────

_dismiss_running = False


def _start_dialog_dismisser():
    """Startet einen permanenten Hintergrund-Thread der WireGuard-Fehler-Dialoge
    automatisch schließt, solange die App läuft."""
    global _dismiss_running
    if _dismiss_running:
        return
    _dismiss_running = True
    threading.Thread(target=_dialog_dismisser_loop, daemon=True).start()


def _dialog_dismisser_loop():
    """Permanenter Loop: findet und schließt WireGuard-Fehler-Dialoge via EnumWindows."""
    import ctypes.wintypes as wt

    user32   = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32

    # --- API-Signaturen setzen ---
    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)

    user32.EnumWindows.argtypes         = [WNDENUMPROC, wt.LPARAM]
    user32.GetWindowTextW.argtypes      = [wt.HWND, ctypes.c_wchar_p, ctypes.c_int]
    user32.GetClassNameW.argtypes       = [wt.HWND, ctypes.c_wchar_p, ctypes.c_int]
    user32.IsWindowVisible.argtypes     = [wt.HWND]
    user32.IsWindowVisible.restype      = wt.BOOL
    user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
    user32.GetWindowThreadProcessId.restype  = wt.DWORD
    user32.FindWindowExW.argtypes       = [wt.HWND, wt.HWND, ctypes.c_wchar_p, ctypes.c_wchar_p]
    user32.FindWindowExW.restype        = wt.HWND
    user32.SendMessageW.argtypes        = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
    user32.PostMessageW.argtypes        = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
    kernel32.OpenProcess.argtypes       = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.OpenProcess.restype        = wt.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wt.HANDLE, wt.DWORD, ctypes.c_wchar_p, ctypes.POINTER(wt.DWORD)]
    kernel32.QueryFullProcessImageNameW.restype  = wt.BOOL
    kernel32.CloseHandle.argtypes       = [wt.HANDLE]

    PROCESS_QUERY_LIMITED = 0x1000
    BM_CLICK    = 0x00F5
    WM_CLOSE    = 0x0010
    WM_COMMAND  = 0x0111
    IDOK        = 1

    # Alle Titel die WireGuard-Fehler-Dialoge tragen können
    BAD_TITLES  = {"Fehler", "Error", "WireGuard", "Tunnel Error"}

    def _get_proc_name(hwnd: int) -> str:
        pid = wt.DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not pid.value:
            return ""
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED, False, pid.value)
        if not h:
            return ""
        buf   = ctypes.create_unicode_buffer(512)
        size  = wt.DWORD(512)
        kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size))
        kernel32.CloseHandle(h)
        return os.path.basename(buf.value).lower()

    def _close_hwnd(hwnd: int):
        # Methode 1: OK-Button direkt klicken
        btn = user32.FindWindowExW(hwnd, None, "Button", None)
        if btn:
            user32.SendMessageW(btn, BM_CLICK, 0, 0)
        # Methode 2: WM_COMMAND IDOK
        user32.PostMessageW(hwnd, WM_COMMAND, IDOK, 0)
        # Methode 3: WM_CLOSE
        user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)

    while True:
        try:
            found: list[int] = []

            @WNDENUMPROC
            def _cb(hwnd, _):
                if not user32.IsWindowVisible(hwnd):
                    return True
                title_buf = ctypes.create_unicode_buffer(256)
                user32.GetWindowTextW(hwnd, title_buf, 256)
                title = title_buf.value

                cls_buf = ctypes.create_unicode_buffer(64)
                user32.GetClassNameW(hwnd, cls_buf, 64)
                cls = cls_buf.value

                # Dialog-Klasse (#32770) gehört WireGuard
                if cls == "#32770" and _get_proc_name(hwnd) == "wireguard.exe":
                    found.append(hwnd)
                    return True
                # Fallback: bekannte Titel
                if title in BAD_TITLES and cls in ("#32770", "TaskManagerWindow"):
                    found.append(hwnd)
                return True

            user32.EnumWindows(_cb, 0)

            for hwnd in found:
                title_buf = ctypes.create_unicode_buffer(256)
                user32.GetWindowTextW(hwnd, title_buf, 256)
                log(f"WireGuard-Dialog geschlossen: '{title_buf.value}'")
                _close_hwnd(hwnd)
                time.sleep(0.3)

        except Exception:
            pass
        time.sleep(0.2)


# ── Cancel-Mechanismus ───────────────────────────────────────────────────

_cancel_event = threading.Event()


def connect_vpn(config_path: Optional[str]) -> Optional[str]:
    global _we_installed_tunnel
    _we_installed_tunnel = False
    _cancel_event.clear()

    if not config_path:
        log("Keine Konfiguration.", "error")
        return None

    tn = extract_tunnel_name(config_path)
    sn = f"WireGuardTunnel${tn}"
    log(f"Tunnel: {tn}")

    # Dialog-Schließer sicherstellen
    _start_dialog_dismisser()

    # Bereits laufend?
    if _service_state(tn) == "RUNNING":
        log(f"'{sn}' laeuft bereits.")
        _we_installed_tunnel = False
        return config_path

    if _cancel_event.is_set():
        log("Verbindung abgebrochen.", "warning")
        return None

    # Alten Dienst aufräumen (Reste vom letzten Mal)
    state = _service_state(tn)
    if state:
        log(f"Raeume alten Dienst auf: {sn} (state={state})")
        if state == "RUNNING":
            _run_silent(["sc.exe", "stop", sn],
                        capture_output=True, text=True, timeout=10)
            time.sleep(2)
        _run_silent(["sc.exe", "delete", sn],
                    capture_output=True, text=True, timeout=10)
        _wait_service_gone(tn)

    if _cancel_event.is_set():
        log("Verbindung abgebrochen.", "warning")
        return None

    # Tunnel installieren via WireGuard Manager
    try:
        log(f"Installiere Tunnel: {config_path}")
        _run_silent(["wireguard", "/installtunnelservice", config_path],
                    check=True, capture_output=True)
        _we_installed_tunnel = True
        if wait_for_tunnel(tn):
            log("Tunnel aktiviert.")
            return config_path
        else:
            log("Tunnel konnte nicht aktiviert werden.", "warning")
            return config_path  # trotzdem zurückgeben, Verbindung kann klappen
    except subprocess.CalledProcessError as e:
        log(f"Aktivierung fehlgeschlagen (rc={e.returncode}).", "error")
    except FileNotFoundError:
        log("WireGuard nicht gefunden.", "error")
    return None


def disconnect_vpn(config_path: str) -> None:
    global _we_installed_tunnel
    if not config_path:
        return
    tn = extract_tunnel_name(config_path)
    sn = f"WireGuardTunnel${tn}"

    # Dialog-Schließer sicherstellen
    _start_dialog_dismisser()

    state = _service_state(tn)
    if not state:
        log(f"Dienst '{sn}' existiert nicht – nichts zu tun.")
        _we_installed_tunnel = False
        return

    # Dienst stoppen (sc.exe = Konsolen-App → zeigt selbst keine GUI-Dialoge)
    if state == "RUNNING":
        log(f"Stoppe Tunnel: {tn}")
        try:
            _run_silent(["sc.exe", "stop", sn],
                        capture_output=True, text=True, timeout=15)
            for _ in range(10):
                time.sleep(1)
                if _service_state(tn) != "RUNNING":
                    break
            log("Tunnel gestoppt.")
        except Exception as e:
            log(f"Stopp Fehler: {e}", "warning")

    # Dienst löschen wenn WIR ihn erstellt haben
    if _we_installed_tunnel:
        log(f"Entferne Tunnel-Dienst: {tn}")
        try:
            _run_silent(["sc.exe", "delete", sn],
                        capture_output=True, text=True, timeout=15)
            if _wait_service_gone(tn, timeout=10):
                log("Tunnel-Dienst entfernt.")
            else:
                log("Dienst konnte nicht vollständig entfernt werden.", "warning")
        except Exception as e:
            log(f"Entfernen Fehler: {e}", "warning")

    _we_installed_tunnel = False


# =============================================================================
#  UPSNAP
# =============================================================================

class UpSnapClient:
    def __init__(self, base_url: str, user: str = "", pw: str = ""):
        self.base_url = base_url.rstrip("/")
        self.token: Optional[str] = None
        if user and pw:
            self._auth(user, pw)

    def _req(self, method: str, path: str, data: Optional[dict] = None) -> Optional[dict]:
        url = f"{self.base_url}{path}"
        hdr = {"Content-Type": "application/json"}
        if self.token:
            hdr["Authorization"] = f"Bearer {self.token}"
        body = json.dumps(data).encode("utf-8") if data else None
        r = request.Request(url, data=body, headers=hdr, method=method)
        try:
            with request.urlopen(r, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except error.HTTPError as e:
            log(f"UpSnap {e.code}: {e.reason}", "warning")
        except Exception as e:
            log(f"UpSnap Fehler: {e}", "warning")
        return None

    def _auth(self, user: str, pw: str) -> bool:
        log("UpSnap: Anmeldung...")
        for ep, label in (
            ("/api/collections/_superusers/auth-with-password", "Superuser"),
            ("/api/admins/auth-with-password", "Admin"),
            ("/api/collections/users/auth-with-password", "User"),
        ):
            r = self._req("POST", ep, {"identity": user, "password": pw})
            if r and "token" in r:
                self.token = r["token"]
                log(f"UpSnap: Angemeldet als {label}.")
                return True
        log("UpSnap: Login fehlgeschlagen.", "error")
        return False

    def get_devices(self) -> List[dict]:
        r = self._req("GET", "/api/collections/devices/records")
        return r.get("items", []) if r else []

    def wake(self, did: str) -> bool:
        r = self._req("GET", f"/api/upsnap/wake/{did}")
        if r is not None:
            log("WoL gesendet.")
            return True
        return False


# =============================================================================
#  CLEANUP
# =============================================================================

_active_config: Optional[str] = None


def _cleanup_temp_rdp():
    """Löscht alle temporären _vpn_*.rdp Dateien."""
    temp = os.environ.get("TEMP", "")
    if not temp:
        return
    try:
        for f in os.listdir(temp):
            if f.startswith("_vpn_") and f.endswith(".rdp"):
                try:
                    os.remove(os.path.join(temp, f))
                except OSError:
                    pass
    except OSError:
        pass


def _cleanup():
    global _active_config
    if _active_config:
        disconnect_vpn(_active_config)
        _active_config = None
    _cleanup_temp_rdp()


def _sig(s, _):
    _cleanup()
    sys.exit(0)


atexit.register(_cleanup)
signal.signal(signal.SIGINT, _sig)
if hasattr(signal, "SIGBREAK"):
    signal.signal(signal.SIGBREAK, _sig)


# =============================================================================
#  AUTO-UPDATE
# =============================================================================

def _parse_version(tag: str) -> tuple:
    """'v1.2.3' oder '1.2.3' → (1, 2, 3)"""
    tag = tag.lstrip("vV").strip()
    parts = []
    for p in tag.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def check_for_update() -> Optional[dict]:
    """Prüft GitHub Releases auf eine neuere Version.
    Gibt {tag, url, size} zurück oder None."""
    api = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
    try:
        req = request.Request(api, headers={"Accept": "application/vnd.github+json",
                                            "User-Agent": "VPN-Connect-Updater"})
        with request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        remote_tag = data.get("tag_name", "")
        if not remote_tag:
            return None

        if _parse_version(remote_tag) <= _parse_version(APP_VERSION):
            log(f"Kein Update (lokal={APP_VERSION}, remote={remote_tag}).")
            return None

        # .exe-Asset finden
        for asset in data.get("assets", []):
            if asset["name"].lower().endswith(".exe"):
                log(f"Update verfügbar: {remote_tag} (aktuell: {APP_VERSION})")
                return {
                    "tag": remote_tag,
                    "url": asset["browser_download_url"],
                    "size": asset.get("size", 0),
                    "name": asset["name"],
                }
        log("Release ohne .exe-Asset.", "warning")
    except Exception as e:
        log(f"Update-Check fehlgeschlagen: {e}", "warning")
    return None


def download_update(url: str, dest: str, progress_cb=None) -> bool:
    """Lädt die neue EXE herunter. progress_cb(bytes_done, total)."""
    try:
        req = request.Request(url, headers={"User-Agent": "VPN-Connect-Updater"})
        with request.urlopen(req, timeout=60) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            done = 0
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    done += len(chunk)
                    if progress_cb:
                        progress_cb(done, total)
        log(f"Download abgeschlossen: {dest}")
        return True
    except Exception as e:
        log(f"Download fehlgeschlagen: {e}", "error")
        # Aufräumen
        try:
            os.remove(dest)
        except OSError:
            pass
        return False


def apply_update(new_exe: str) -> None:
    """Benennt die laufende EXE um, verschiebt die neue an deren Stelle
    und startet neu."""
    if not getattr(sys, 'frozen', False):
        log("Update nur als EXE möglich.", "warning")
        return

    current = sys.executable
    backup = current + ".old"

    try:
        # Alte Backup-Datei entfernen
        if os.path.exists(backup):
            os.remove(backup)

        # Laufende EXE umbenennen (Windows erlaubt rename, nicht overwrite)
        os.rename(current, backup)
        log(f"Alte EXE umbenannt → {os.path.basename(backup)}")

        # Neue EXE an Original-Pfad verschieben
        os.rename(new_exe, current)
        log("Neue EXE installiert.")

        # Neue EXE starten mit --cleanup Flag
        subprocess.Popen([current, "--cleanup"])
        log("Neustart...")
        sys.exit(0)

    except Exception as e:
        log(f"Update-Installation fehlgeschlagen: {e}", "error")
        # Rollback
        try:
            if not os.path.exists(current) and os.path.exists(backup):
                os.rename(backup, current)
                log("Rollback erfolgreich.")
        except Exception:
            pass


def _cleanup_old_exe():
    """Löscht die alte .exe.old nach einem Update-Neustart."""
    if not getattr(sys, 'frozen', False):
        return
    old = sys.executable + ".old"
    if os.path.exists(old):
        for _ in range(5):
            try:
                os.remove(old)
                log(f"Alte Version gelöscht: {os.path.basename(old)}")
                return
            except PermissionError:
                time.sleep(1)
        log("Alte Version konnte nicht gelöscht werden.", "warning")


# =============================================================================
#  FARBSCHEMA
# =============================================================================

C = {
    "bg":       "#0f0f17",
    "card":     "#1a1a2e",
    "surface":  "#242438",
    "border":   "#2d2d44",
    "fg":       "#e2e2ef",
    "dim":      "#6e6e8a",
    "accent":   "#6c63ff",
    "accent_h": "#857dff",
    "green":    "#4ade80",
    "red":      "#f87171",
    "yellow":   "#fbbf24",
    "orange":   "#fb923c",
    "cyan":     "#22d3ee",
}


# =============================================================================
#  GUI
# =============================================================================

class VPNApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"VPN Connect  v{APP_VERSION}")
        self.root.configure(bg=C["bg"])
        self.root.resizable(True, True)
        self.root.minsize(800, 520)
        self.root.geometry("800x560")

        self.configs: List[Tuple[str, str]] = []
        self.active_config: Optional[str] = None
        self.vpn_connected = False
        self.upsnap: Optional[UpSnapClient] = None
        self._device_widgets: List[tk.Widget] = []
        self._log_visible = False
        self._auto_refresh_id = None   # after()-ID für Auto-Refresh

        self._setup_styles()
        self._build_ui()
        self._load_configs()
        self._load_credentials()   # gespeicherte Credentials laden

        # Im Hintergrund nach Updates suchen
        threading.Thread(target=self._check_update_bg, daemon=True).start()

        # Dialog-Dismisser sofort starten (schließt WireGuard-Fehlerdialoge)
        _start_dialog_dismisser()

    # ── Styles ────────────────────────────────────────────────────────────

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use("clam")

        s.configure("TFrame", background=C["bg"])
        s.configure("Card.TFrame", background=C["card"], relief="flat")
        s.configure("TLabel", background=C["bg"], foreground=C["fg"],
                    font=("Segoe UI", 10))
        s.configure("H1.TLabel", background=C["bg"], foreground=C["fg"],
                    font=("Segoe UI", 18, "bold"))
        s.configure("H2.TLabel", background=C["bg"], foreground=C["dim"],
                    font=("Segoe UI", 10, "bold"))
        s.configure("Card.TLabel", background=C["card"], foreground=C["fg"],
                    font=("Segoe UI", 10))
        s.configure("Dim.TLabel", background=C["card"], foreground=C["dim"],
                    font=("Segoe UI", 9))
        s.configure("Status.TLabel", background=C["bg"], font=("Segoe UI", 11, "bold"))

        for name, bg, fg, bg_a in [
            ("Connect.TButton", C["accent"],  "#ffffff",  C["accent_h"]),
            ("Disconnect.TButton", C["red"],   "#ffffff",  "#fca5a5"),
            ("Action.TButton",  C["surface"], C["fg"],    C["border"]),
            ("Login.TButton",   C["accent"],  "#ffffff",  C["accent_h"]),
            ("Cancel.TButton",  C["orange"],  "#000000",  C["yellow"]),
        ]:
            s.configure(name, background=bg, foreground=fg,
                        font=("Segoe UI", 9, "bold"), padding=(14, 7),
                        borderwidth=0)
            s.map(name,
                  background=[("active", bg_a), ("disabled", C["surface"])],
                  foreground=[("disabled", C["dim"])])

        s.configure("Small.TButton", background=C["surface"], foreground=C["fg"],
                    font=("Segoe UI", 9), padding=(10, 5), borderwidth=0)
        s.map("Small.TButton",
              background=[("active", C["border"]), ("disabled", C["bg"])],
              foreground=[("disabled", C["dim"])])

        s.configure("Toggle.TButton", background=C["bg"], foreground=C["dim"],
                    font=("Segoe UI", 9), padding=(4, 2), borderwidth=0)
        s.map("Toggle.TButton", background=[("active", C["bg"])])

        s.configure("Update.TButton", background=C["green"], foreground="#000000",
                    font=("Segoe UI", 9, "bold"), padding=(10, 5), borderwidth=0)
        s.map("Update.TButton",
              background=[("active", "#86efac"), ("disabled", C["surface"])],
              foreground=[("disabled", C["dim"])])

        s.configure("TEntry", fieldbackground=C["surface"], foreground=C["fg"],
                    insertcolor=C["fg"], font=("Segoe UI", 10), borderwidth=0)

        s.configure("Vertical.TScrollbar", background=C["surface"],
                    troughcolor=C["card"], borderwidth=0, arrowsize=0)

    # ── Layout ────────────────────────────────────────────────────────────

    def _build_ui(self):
        pad = 20

        # ── Scrollbares Hauptfenster ──
        self._canvas = tk.Canvas(self.root, bg=C["bg"], highlightthickness=0,
                                  borderwidth=0)
        vsb = ttk.Scrollbar(self.root, orient="vertical",
                             command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        outer = ttk.Frame(self._canvas)
        self._outer_id = self._canvas.create_window(
            (0, 0), window=outer, anchor="nw")

        def _on_frame(e):
            self._canvas.configure(scrollregion=self._canvas.bbox("all"))

        def _on_canvas(e):
            self._canvas.itemconfig(self._outer_id, width=e.width)

        def _on_wheel(e):
            self._canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")

        outer.bind("<Configure>", _on_frame)
        self._canvas.bind("<Configure>", _on_canvas)
        self._canvas.bind_all("<MouseWheel>", _on_wheel)

        # ── Header ──
        hdr = ttk.Frame(outer)
        hdr.pack(fill="x", padx=pad, pady=(pad, 16))

        ttk.Label(hdr, text="VPN Connect", style="H1.TLabel").pack(side="left")

        # Update-Button (initial versteckt)
        self.btn_update = ttk.Button(hdr, text="⬆ Update verfügbar",
                                      style="Update.TButton",
                                      command=self._on_update)
        self._update_info: Optional[dict] = None

        status_box = ttk.Frame(hdr)
        status_box.pack(side="right")
        self.status_dot = tk.Canvas(status_box, width=12, height=12,
                                     bg=C["bg"], highlightthickness=0)
        self.status_dot.pack(side="left", padx=(0, 6), pady=2)
        self._draw_dot(C["red"])
        self.status_label = ttk.Label(status_box, text="Getrennt",
                                       style="Status.TLabel", foreground=C["red"])
        self.status_label.pack(side="left")

        # ── WireGuard Sektion ──
        ttk.Label(outer, text="WIREGUARD KANAL", style="H2.TLabel").pack(
            anchor="w", padx=pad, pady=(0, 6))

        wg = tk.Frame(outer, bg=C["card"], padx=14, pady=14)
        wg.pack(fill="x", padx=pad, pady=(0, 16))

        self.config_listbox = tk.Listbox(
            wg, height=3, bg=C["surface"], fg=C["fg"],
            selectbackground=C["accent"], selectforeground="#ffffff",
            font=("Segoe UI", 10), bd=0, highlightthickness=0,
            activestyle="none", relief="flat",
        )
        self.config_listbox.pack(fill="x", pady=(0, 10))

        btn_row = tk.Frame(wg, bg=C["card"])
        btn_row.pack(fill="x")

        self.btn_connect = ttk.Button(btn_row, text="Verbinden",
                                       style="Connect.TButton",
                                       command=self._on_connect)
        self.btn_connect.pack(side="left")

        self.btn_disconnect = ttk.Button(btn_row, text="Trennen",
                                          style="Disconnect.TButton",
                                          command=self._on_disconnect,
                                          state="disabled")
        self.btn_disconnect.pack(side="left", padx=(8, 0))

        self.btn_cancel = ttk.Button(btn_row, text="Abbrechen",
                                      style="Cancel.TButton",
                                      command=self._on_cancel)
        # initial versteckt – wird nur während Verbindungsaufbau angezeigt

        self.btn_browser = ttk.Button(btn_row, text="Im Browser oeffnen",
                                       style="Action.TButton",
                                       command=self._on_open_browser,
                                       state="disabled")
        self.btn_browser.pack(side="left", padx=(8, 0))

        # ── UpSnap Sektion ──
        ttk.Label(outer, text="UPSNAP  /  WAKE ON LAN", style="H2.TLabel").pack(
            anchor="w", padx=pad, pady=(0, 6))

        snap = tk.Frame(outer, bg=C["card"], padx=14, pady=14)
        snap.pack(fill="x", padx=pad, pady=(0, 12))

        login_row = tk.Frame(snap, bg=C["card"])
        login_row.pack(fill="x", pady=(0, 8))

        lbl_cfg = {"bg": C["card"], "fg": C["dim"], "font": ("Segoe UI", 9)}

        tk.Label(login_row, text="E-Mail", **lbl_cfg).pack(side="left")
        self.entry_user = ttk.Entry(login_row, width=22)
        self.entry_user.pack(side="left", padx=(6, 12))

        tk.Label(login_row, text="Passwort", **lbl_cfg).pack(side="left")
        self.entry_pass = ttk.Entry(login_row, width=16, show="*")
        self.entry_pass.pack(side="left", padx=(6, 12))

        self.btn_login = ttk.Button(login_row, text="Anmelden",
                                     style="Login.TButton",
                                     command=self._on_upsnap_login)
        self.btn_login.pack(side="left")
        # Enter-Taste → Anmelden
        self.entry_pass.bind("<Return>", lambda _: self._on_upsnap_login())
        self.entry_user.bind("<Return>", lambda _: self.entry_pass.focus())

        self.btn_refresh_devices = ttk.Button(login_row, text="Aktualisieren",
                                               style="Small.TButton",
                                               command=self._on_refresh_devices,
                                               state="disabled")
        self.btn_refresh_devices.pack(side="left", padx=(8, 0))

        sep = tk.Frame(snap, bg=C["border"], height=1)
        sep.pack(fill="x", pady=(4, 8))

        self.device_frame = tk.Frame(snap, bg=C["card"])
        self.device_frame.pack(fill="x")

        self.upsnap_hint = tk.Label(
            self.device_frame, text="Anmelden um Geraete anzuzeigen",
            bg=C["card"], fg=C["dim"], font=("Segoe UI", 9))
        self.upsnap_hint.pack(pady=4)

        # ── Log Toggle ──
        self.log_toggle = ttk.Button(outer, text="[+] Log",
                                      style="Toggle.TButton",
                                      command=self._toggle_log)
        self.log_toggle.pack(anchor="w", padx=pad, pady=(4, 0))

        self.log_frame = tk.Frame(outer, bg=C["card"], padx=8, pady=8)

        self.log_text = tk.Text(
            self.log_frame, height=8, bg=C["surface"], fg=C["dim"],
            font=("Consolas", 9), bd=0, highlightthickness=0,
            wrap="word", state="disabled", insertbackground=C["fg"],
        )
        sb2 = ttk.Scrollbar(self.log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb2.set)
        sb2.pack(side="right", fill="y")
        self.log_text.pack(fill="both", expand=True)

    # ── Status-Punkt ──────────────────────────────────────────────────────

    def _draw_dot(self, color: str):
        self.status_dot.delete("all")
        self.status_dot.create_oval(1, 1, 11, 11, fill=color, outline=color)

    def _set_status(self, text: str, color: str):
        self._draw_dot(color)
        self.status_label.configure(text=text, foreground=color)

    # ── Log ───────────────────────────────────────────────────────────────

    def _toggle_log(self):
        if self._log_visible:
            self.log_frame.pack_forget()
            self.log_toggle.configure(text="[+] Log")
            self._log_visible = False
        else:
            self.log_frame.pack(fill="x", padx=20, pady=(4, 20))
            self.log_toggle.configure(text="[-] Log")
            self._log_visible = True

    def append_log(self, msg: str):
        def _do():
            self.log_text.configure(state="normal")
            self.log_text.insert("end", f"[{time.strftime('%H:%M:%S')}] {msg}\n")
            # Max 500 Zeilen behalten
            line_count = int(self.log_text.index("end-1c").split(".")[0])
            if line_count > 500:
                self.log_text.delete("1.0", f"{line_count - 500}.0")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        self.root.after(0, _do)

    # ── Configs ───────────────────────────────────────────────────────────

    def _load_configs(self):
        self.configs = collect_all_configs()
        self.config_listbox.delete(0, "end")
        if not self.configs:
            self.config_listbox.insert("end", "  Keine Konfigurationen gefunden")
            self.btn_connect.configure(state="disabled")
        else:
            for name, _ in self.configs:
                self.config_listbox.insert("end", f"  {name}")
            self.config_listbox.selection_set(0)

    # ── Auto-Update ───────────────────────────────────────────────────────

    def _check_update_bg(self):
        """Wird in einem Hintergrund-Thread aufgerufen."""
        info = check_for_update()
        if info:
            self._update_info = info
            self.root.after(0, self._show_update_btn)

    def _show_update_btn(self):
        info = self._update_info
        if not info:
            return
        tag = info["tag"]
        size_mb = info.get("size", 0) / (1024 * 1024)
        self.btn_update.configure(
            text=f"⬆ Update {tag}  ({size_mb:.1f} MB)")
        self.btn_update.pack(side="left", padx=(16, 0))

    def _on_update(self):
        info = self._update_info
        if not info:
            return
        if not messagebox.askyesno(
            "Update",
            f"Version {info['tag']} herunterladen und installieren?\n\n"
            f"Die App wird nach dem Update automatisch neu gestartet."):
            return

        self.btn_update.configure(state="disabled", text="⬆ Lade herunter...")

        def work():
            dest = os.path.join(_base_dir, "VPN_Connect_new.exe")
            def progress(done, total):
                if total > 0:
                    pct = int(done / total * 100)
                    self.root.after(0,
                        lambda: self.btn_update.configure(
                            text=f"⬆ {pct}%  ({done // 1024 // 1024}/{total // 1024 // 1024} MB)"))

            ok = download_update(info["url"], dest, progress)
            if ok:
                self.root.after(0, lambda: self._apply_update(dest))
            else:
                self.root.after(0, lambda: (
                    self.btn_update.configure(state="normal",
                                              text="⬆ Download fehlgeschlagen"),
                    messagebox.showerror("Update", "Download fehlgeschlagen.")))

        threading.Thread(target=work, daemon=True).start()

    def _apply_update(self, new_exe: str):
        log("Installiere Update...")
        # VPN trennen falls verbunden
        if self.active_config:
            disconnect_vpn(self.active_config)
        apply_update(new_exe)

    # ── VPN Connect ───────────────────────────────────────────────────────

    def _on_connect(self):
        sel = self.config_listbox.curselection()
        if not sel or not self.configs:
            return
        _, path = self.configs[sel[0]]
        self.btn_connect.configure(state="disabled")
        self.btn_cancel.pack(side="left", padx=(8, 0))  # Abbrechen zeigen
        self._set_status("Verbinde...", C["yellow"])

        def work():
            global _active_config
            r = connect_vpn(path)
            if _cancel_event.is_set():
                # Abgebrochen – aufräumen falls nötig
                if r:
                    disconnect_vpn(r)
                self.root.after(0, self._disconnected)
                self.root.after(0, lambda: self.btn_cancel.pack_forget())
                return
            if r:
                self.active_config = r
                _active_config = r
                self.vpn_connected = True
                ok = check_connection(TARGET_IP, TARGET_PORT, retries=5, delay=2.0)
                self.root.after(0, lambda: self._connected(ok))
            else:
                self.root.after(0, self._disconnected)
            self.root.after(0, lambda: self.btn_cancel.pack_forget())
        threading.Thread(target=work, daemon=True).start()

    def _on_cancel(self):
        """Bricht den Verbindungsaufbau ab."""
        log("Abbrechen angefordert...")
        _cancel_event.set()
        self.btn_cancel.configure(state="disabled", text="Abbreche...")
        self._set_status("Abbreche...", C["orange"])

    def _connected(self, reachable: bool):
        self._set_status("Verbunden", C["green"])
        self.btn_connect.configure(state="disabled")
        self.btn_disconnect.configure(state="normal")
        self.btn_browser.configure(state="normal" if reachable else "disabled")
        if reachable:
            log(f"Ziel {TARGET_IP}:{TARGET_PORT} erreichbar.")
        else:
            log("Ziel noch nicht erreichbar.", "warning")

    def _disconnected(self):
        self._set_status("Getrennt", C["red"])
        self.btn_connect.configure(state="normal")
        self.btn_disconnect.configure(state="disabled")
        self.btn_browser.configure(state="disabled")
        self.btn_cancel.pack_forget()
        self.btn_cancel.configure(state="normal", text="Abbrechen")
        self.vpn_connected = False
        self.active_config = None

    # ── VPN Disconnect ────────────────────────────────────────────────────

    def _on_disconnect(self):
        global _active_config
        self.btn_disconnect.configure(state="disabled")
        self._set_status("Trenne...", C["yellow"])

        def work():
            if self.active_config:
                disconnect_vpn(self.active_config)
                _active_config = None
            self.root.after(0, self._disconnected)
        threading.Thread(target=work, daemon=True).start()

    # ── Browser ───────────────────────────────────────────────────────────

    def _on_open_browser(self):
        url = f"http://{TARGET_IP}:{TARGET_PORT}"
        log(f"Oeffne {url}...")

        # Methode 1: rundll32 – öffnet URL zuverlässig auch aus Admin-Prozessen
        try:
            subprocess.Popen(["rundll32", "url.dll,FileProtocolHandler", url])
            log("Browser geöffnet (rundll32).")
            return
        except Exception as e:
            log(f"rundll32 fehlgeschlagen: {e}", "warning")

        # Methode 2: explorer.exe – läuft immer als normaler Benutzer
        try:
            subprocess.Popen(["explorer", url])
            log("Browser geöffnet (explorer).")
            return
        except Exception as e:
            log(f"explorer fehlgeschlagen: {e}", "warning")

        # Methode 3: webbrowser-Modul als letzter Fallback
        try:
            import webbrowser
            webbrowser.open(url)
            log("Browser geöffnet (webbrowser).")
        except Exception as e:
            log(f"Browser-Fehler: {e}", "error")

    # ── Credentials (speichern/laden) ─────────────────────────────────────

    _CRED_FILE = os.path.join(_base_dir, "vpn_settings.json")

    def _save_credentials(self, user: str, pw: str):
        try:
            with open(self._CRED_FILE, "w", encoding="utf-8") as f:
                json.dump({"user": user, "pw": pw}, f)
        except OSError:
            pass

    def _load_credentials(self):
        try:
            if os.path.exists(self._CRED_FILE):
                with open(self._CRED_FILE, "r", encoding="utf-8") as f:
                    d = json.load(f)
                self.entry_user.insert(0, d.get("user", ""))
                self.entry_pass.insert(0, d.get("pw", ""))
        except Exception:
            pass

    # ── Auto-Refresh ──────────────────────────────────────────────────────

    def _start_auto_refresh(self):
        """Startet automatisches Aktualisieren der Geräteliste alle 30s."""
        self._stop_auto_refresh()
        self._auto_refresh_id = self.root.after(30_000, self._auto_refresh_tick)

    def _stop_auto_refresh(self):
        if self._auto_refresh_id:
            self.root.after_cancel(self._auto_refresh_id)
            self._auto_refresh_id = None

    def _auto_refresh_tick(self):
        if self.upsnap and self.vpn_connected:
            def work():
                try:
                    devs = self.upsnap.get_devices()
                    self.root.after(0, lambda: self._show_devices(devs))
                except Exception:
                    pass
            threading.Thread(target=work, daemon=True).start()
        # Nächster Tick in 30s
        self._auto_refresh_id = self.root.after(30_000, self._auto_refresh_tick)

    # ── UpSnap Login ──────────────────────────────────────────────────────

    def _on_upsnap_login(self):
        u = self.entry_user.get().strip()
        p = self.entry_pass.get().strip()
        if not u or not p:
            messagebox.showinfo("UpSnap", "E-Mail und Passwort eingeben.")
            return
        self.btn_login.configure(state="disabled")

        def work():
            try:
                c = UpSnapClient(f"http://{TARGET_IP}:{TARGET_PORT}", u, p)
                if c.token:
                    self.upsnap = c
                    devs = c.get_devices()
                    self.root.after(0, lambda: self._show_devices(devs))
                    self.root.after(0, lambda: self.btn_refresh_devices.configure(state="normal"))
                    # Credentials speichern und Auto-Refresh starten
                    self.root.after(0, lambda: self._save_credentials(u, p))
                    self.root.after(0, self._start_auto_refresh)
                else:
                    self.root.after(0, lambda: self.btn_login.configure(state="normal"))
            except Exception as e:
                log(f"UpSnap Login Fehler: {e}", "error")
                self.root.after(0, lambda: self.btn_login.configure(state="normal"))
        threading.Thread(target=work, daemon=True).start()

    def _on_refresh_devices(self):
        """Geräteliste aktualisieren."""
        if not self.upsnap:
            return
        self.btn_refresh_devices.configure(state="disabled")
        log("Geräteliste wird aktualisiert...")

        def work():
            try:
                devs = self.upsnap.get_devices()
            except Exception as e:
                log(f"Geräteliste Fehler: {e}", "error")
                devs = []
            self.root.after(0, lambda: self._show_devices(devs))
            self.root.after(0, lambda: self.btn_refresh_devices.configure(state="normal"))
        threading.Thread(target=work, daemon=True).start()

    def _show_devices(self, devices: List[dict]):
        for w in self._device_widgets:
            w.destroy()
        self._device_widgets.clear()
        self.upsnap_hint.pack_forget()

        if not devices:
            lbl = tk.Label(self.device_frame, text="Keine Geraete.",
                           bg=C["card"], fg=C["dim"], font=("Segoe UI", 9))
            lbl.pack(pady=4)
            self._device_widgets.append(lbl)
            self.btn_login.configure(state="normal")
            return

        for d in devices:
            row = tk.Frame(self.device_frame, bg=C["surface"], pady=7, padx=12)
            row.pack(fill="x", pady=2)
            self._device_widgets.append(row)
            row.columnconfigure(1, weight=1)

            name  = d.get("name", "?")
            ip    = d.get("ip", "?")
            online = d.get("status") == "online"
            dot_c  = C["green"] if online else C["dim"]

            # Status-Punkt (Canvas)
            dot = tk.Canvas(row, width=10, height=10, bg=C["surface"],
                            highlightthickness=0)
            dot.create_oval(1, 1, 9, 9, fill=dot_c, outline=dot_c)
            dot.grid(row=0, column=0, padx=(0, 8), sticky="w")

            # Name
            tk.Label(row, text=name, bg=C["surface"], fg=C["fg"],
                     font=("Segoe UI", 10), anchor="w"
                     ).grid(row=0, column=1, sticky="w")

            # IP
            tk.Label(row, text=ip, bg=C["surface"], fg=C["dim"],
                     font=("Segoe UI", 9), anchor="w"
                     ).grid(row=0, column=2, padx=(8, 12), sticky="w")

            # Status-Label (Offline / Einschalten... / Online)
            init_txt = "Online" if online else "Offline"
            init_col = C["green"] if online else C["dim"]
            status_lbl = tk.Label(row, text=init_txt, bg=C["surface"],
                                  fg=init_col, font=("Segoe UI", 8, "bold"),
                                  width=11, anchor="w")
            status_lbl.grid(row=0, column=3, padx=(0, 10), sticky="w")

            # Buttons
            btns = tk.Frame(row, bg=C["surface"])
            btns.grid(row=0, column=4, sticky="e")

            did, dip, dn = d.get("id", ""), ip, name
            btn_refs: List[ttk.Button] = []

            if online:
                b = ttk.Button(btns, text="RDP", style="Small.TButton",
                               command=lambda x=dip, n=dn, bl=btn_refs,
                                              sl=status_lbl:
                               self._on_rdp(x, n, bl, sl))
                b.pack(side="left", padx=(0, 4))
                btn_refs.append(b)
            else:
                b1 = ttk.Button(btns, text="WoL", style="Small.TButton",
                                command=lambda x=did, n=dn, bl=btn_refs,
                                               sl=status_lbl:
                                self._on_wake(x, n, bl, sl))
                b1.pack(side="left", padx=(0, 4))

                b2 = ttk.Button(btns, text="WoL + RDP", style="Small.TButton",
                                command=lambda x=did, y=dip, n=dn,
                                               bl=btn_refs, sl=status_lbl:
                                self._on_wake_rdp(x, y, n, bl, sl))
                b2.pack(side="left", padx=(0, 4))

                btn_refs += [b1, b2]

        self.btn_login.configure(state="normal")

    # ── Hilfsmethoden für Device-Status ──────────────────────────────────

    @staticmethod
    def _set_device_status(status_lbl: tk.Label,
                           text: str, color: str):
        """Setzt den Status-Text eines Geräts (thread-safe via after)."""
        try:
            status_lbl.configure(text=text, fg=color)
        except tk.TclError:
            pass  # Widget bereits zerstört

    @staticmethod
    def _set_btns(btn_refs: list, state: str):
        for b in btn_refs:
            try:
                b.configure(state=state)
            except tk.TclError:
                pass

    # ── Device Actions ────────────────────────────────────────────────────

    def _on_wake(self, did: str, name: str,
                 btn_refs: list, status_lbl: tk.Label):
        if not self.upsnap:
            return
        self._set_btns(btn_refs, "disabled")
        self._set_device_status(status_lbl, "WoL senden...", C["yellow"])
        log(f"WoL -> '{name}'")

        def work():
            self.upsnap.wake(did)
            self.root.after(0, lambda: self._set_device_status(
                status_lbl, "Einschalten...", C["orange"]))
            self.root.after(3000, lambda: self._set_btns(btn_refs, "normal"))
            self.root.after(3000, lambda: self._set_device_status(
                status_lbl, "Offline", C["dim"]))
        threading.Thread(target=work, daemon=True).start()

    def _on_rdp(self, ip: str, name: str,
                btn_refs: list = None, status_lbl: tk.Label = None):
        log(f"RDP -> '{name}' ({ip})")
        if btn_refs:
            self._set_btns(btn_refs, "disabled")
        if status_lbl:
            self._set_device_status(status_lbl, "RDP starten...", C["cyan"])
        try:
            rdp_path = os.path.join(
                os.environ.get("TEMP", _base_dir), f"_vpn_{name}.rdp")
            with open(rdp_path, "w") as f:
                f.write(f"full address:s:{ip}\n")
                f.write("prompt for credentials:i:1\n")
                f.write("authentication level:i:0\n")
            subprocess.Popen(["explorer.exe", rdp_path])
            log(f"RDP gestartet: {rdp_path}")
            if status_lbl:
                self.root.after(2000, lambda: self._set_device_status(
                    status_lbl, "Online", C["green"]))
            # Temp-Datei nach 8s löschen (mstsc hat sie dann schon gelesen)
            def _del():
                time.sleep(8)
                try:
                    os.remove(rdp_path)
                    log(f"Temp-RDP gelöscht: {rdp_path}")
                except OSError:
                    pass
            threading.Thread(target=_del, daemon=True).start()
        except Exception as e:
            log(f"RDP Fehler: {e}", "error")
        finally:
            if btn_refs:
                self.root.after(3000, lambda: self._set_btns(btn_refs, "normal"))

    def _on_wake_rdp(self, did: str, ip: str, name: str,
                     btn_refs: list, status_lbl: tk.Label):
        if not self.upsnap:
            return
        self._set_btns(btn_refs, "disabled")
        self._set_device_status(status_lbl, "WoL senden...", C["yellow"])
        log(f"WoL + RDP -> '{name}'")

        def work():
            self.upsnap.wake(did)
            self.root.after(0, lambda: self._set_device_status(
                status_lbl, "Einschalten...", C["orange"]))
            log(f"Warte auf '{name}' (max 120s)...")
            t0 = time.time()
            while time.time() - t0 < 120:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((ip, 3389))
                    s.close()
                    log(f"'{name}' bereit!")
                    self.root.after(0, lambda: self._set_device_status(
                        status_lbl, "Online", C["green"]))
                    time.sleep(3)
                    self.root.after(0, lambda: self._on_rdp(
                        ip, name, btn_refs, status_lbl))
                    return
                except Exception:
                    pass
                elapsed = int(time.time() - t0)
                self.root.after(0, lambda e=elapsed: self._set_device_status(
                    status_lbl, f"Warte {e}s...", C["orange"]))
                log(f"  Warte... ({elapsed}s)")
                time.sleep(2)

            log(f"'{name}' nicht erreichbar.", "warning")
            self.root.after(0, lambda: self._set_device_status(
                status_lbl, "Timeout", C["red"]))
            self.root.after(0, lambda: self._set_btns(btn_refs, "normal"))
            # messagebox muss im main thread laufen
            self.root.after(0, lambda: self._ask_rdp_anyway(
                ip, name, btn_refs, status_lbl))

        threading.Thread(target=work, daemon=True).start()

    def _ask_rdp_anyway(self, ip, name, btn_refs, status_lbl):
        """Fragt ob RDP trotzdem gestartet werden soll (im main thread)."""
        if messagebox.askyesno("Timeout",
                                f"'{name}' antwortet nicht.\nRDP trotzdem starten?"):
            self._on_rdp(ip, name, btn_refs, status_lbl)



# =============================================================================
#  MAIN
# =============================================================================

def main():
    global _app

    # Nach Update: alte EXE aufräumen
    if "--cleanup" in sys.argv:
        _cleanup_old_exe()

    if not is_admin():
        run_as_admin()
        sys.exit()

    root = tk.Tk()
    _app = VPNApp(root)

    def on_close():
        global _active_config
        if _app.active_config:
            if not messagebox.askyesno("Beenden",
                                        "VPN ist verbunden.\nTrennen und beenden?"):
                return
            disconnect_vpn(_app.active_config)
        _active_config = None
        _app.active_config = None
        _app._stop_auto_refresh()
        _cleanup_temp_rdp()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()

