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
import base64
import hashlib
from typing import Optional, List, Tuple
from urllib import request, error

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QListWidget, QFrame,
    QScrollArea, QTextEdit, QMessageBox, QSystemTrayIcon, QMenu,
    QCheckBox, QDialog, QFormLayout, QDialogButtonBox,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor, QPainter, QAction, QPixmap, QIcon
from PyQt6.QtGui import QKeySequence, QShortcut

# =============================================================================
#  KONFIGURATION
# =============================================================================

APP_VERSION = "1.7.1"
GITHUB_REPO = "JonasHofer01/VPN-Connect"   # owner/repo

CONFIG_BASE = r"C:\Program Files\WireGuard\Data\Configurations"
# IP und Port werden aus vpn_settings.json geladen (nicht hardcodiert)
TARGET_IP = ""
TARGET_PORT = 8090

WG_CONFIG_CONTENT = ""

# Konsole verstecken
if sys.platform == "win32":
    try:
        ctypes.windll.kernel32.FreeConsole()
    except Exception:
        pass
    # Nach FreeConsole sind stdout/stderr Handles ungueltig → umleiten
    try:
        if sys.stdout is None or sys.stdout.closed:
            sys.stdout = open(os.devnull, "w")
        if sys.stderr is None or sys.stderr.closed:
            sys.stderr = open(os.devnull, "w")
    except Exception:
        sys.stdout = open(os.devnull, "w")
        sys.stderr = open(os.devnull, "w")

SW_HIDE = 0
CREATE_NO_WINDOW = 0x08000000
STARTUPINFO = subprocess.STARTUPINFO()
STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW
STARTUPINFO.wShowWindow = SW_HIDE

# =============================================================================
#  LOGGING
# =============================================================================

if getattr(sys, 'frozen', False):
    _base_dir = os.path.dirname(sys.executable)
else:
    _base_dir = os.path.dirname(os.path.abspath(__file__))

log_file = os.path.join(_base_dir, "vpn_debug.log")

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
        _app.sig.log_signal.emit(msg)


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
    for _ in range(timeout):
        if not _service_state(tn):
            return True
        time.sleep(1)
    return not _service_state(tn)


# ── Dialog-Auto-Schließer ────────────────────────────────────────────────

_dismiss_running = False


def _start_dialog_dismisser():
    global _dismiss_running
    if _dismiss_running:
        return
    _dismiss_running = True
    threading.Thread(target=_dialog_dismisser_loop, daemon=True).start()


def _dialog_dismisser_loop():
    import ctypes.wintypes as wt

    user32   = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32

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
        btn = user32.FindWindowExW(hwnd, None, "Button", None)
        if btn:
            user32.SendMessageW(btn, BM_CLICK, 0, 0)
        user32.PostMessageW(hwnd, WM_COMMAND, IDOK, 0)
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

                if cls == "#32770" and _get_proc_name(hwnd) == "wireguard.exe":
                    found.append(hwnd)
                    return True
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

    _start_dialog_dismisser()

    if _service_state(tn) == "RUNNING":
        log(f"'{sn}' laeuft bereits.")
        _we_installed_tunnel = False
        return config_path

    if _cancel_event.is_set():
        log("Verbindung abgebrochen.", "warning")
        return None

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
            return config_path
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

    _start_dialog_dismisser()

    state = _service_state(tn)
    if not state:
        log(f"Dienst '{sn}' existiert nicht – nichts zu tun.")
        _we_installed_tunnel = False
        return

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
        self._user = user
        self._pw = pw
        self._last_status: int = 0          # letzter HTTP-Statuscode
        if user and pw:
            self._auth(user, pw)

    def _req(self, method: str, path: str, data: Optional[dict] = None,
             silent: bool = False) -> Optional[dict]:
        url = f"{self.base_url}{path}"
        hdr = {"Content-Type": "application/json"}
        if self.token:
            hdr["Authorization"] = f"Bearer {self.token}"
        body = json.dumps(data).encode("utf-8") if data else None
        r = request.Request(url, data=body, headers=hdr, method=method)
        try:
            with request.urlopen(r, timeout=10) as resp:
                self._last_status = resp.status
                return json.loads(resp.read().decode("utf-8"))
        except error.HTTPError as e:
            self._last_status = e.code
            if not silent:
                log(f"UpSnap {e.code}: {e.reason}", "warning")
        except Exception as e:
            self._last_status = 0
            if not silent:
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

    def reauth(self) -> bool:
        """Token erneuern (nach Ablauf / 401)."""
        if not self._user or not self._pw:
            return False
        log("UpSnap: Token erneuern...")
        return self._auth(self._user, self._pw)

    def get_devices(self) -> Optional[List[dict]]:
        """Geräteliste holen.
        Gibt None zurück bei API-Fehler (Netz, Token), [] bei leerer Liste."""
        r = self._req("GET", "/api/collections/devices/records", silent=True)
        if r is None:
            return None          # Fehler – Display NICHT leeren
        return r.get("items", [])

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
    tag = tag.lstrip("vV").strip()
    parts = []
    for p in tag.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def check_for_update() -> Optional[dict]:
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
    except error.HTTPError as e:
        if e.code == 404:
            log("Kein Release auf GitHub vorhanden – Update-Check uebersprungen.")
        else:
            log(f"Update-Check fehlgeschlagen: HTTP {e.code}", "warning")
    except Exception as e:
        log(f"Update-Check fehlgeschlagen: {e}", "warning")
    return None


def download_update(url: str, dest: str, progress_cb=None) -> bool:
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
        try:
            os.remove(dest)
        except OSError:
            pass
        return False


def apply_update(new_exe: str) -> None:
    if not getattr(sys, 'frozen', False):
        log("Update nur als EXE möglich.", "warning")
        return

    current = sys.executable
    backup = current + ".old"

    try:
        if os.path.exists(backup):
            os.remove(backup)

        os.rename(current, backup)
        log(f"Alte EXE umbenannt → {os.path.basename(backup)}")

        os.rename(new_exe, current)
        log("Neue EXE installiert.")

        subprocess.Popen([current, "--cleanup"])
        log("Neustart...")
        sys.exit(0)

    except Exception as e:
        log(f"Update-Installation fehlgeschlagen: {e}", "error")
        try:
            if not os.path.exists(current) and os.path.exists(backup):
                os.rename(backup, current)
                log("Rollback erfolgreich.")
        except Exception:
            pass


def _cleanup_old_exe():
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
#  GLOBAL STYLESHEET
# =============================================================================

GLOBAL_QSS = f"""
QMainWindow {{
    background-color: {C['bg']};
}}
QWidget {{
    color: {C['fg']};
    font-family: 'Segoe UI';
    font-size: 10pt;
}}
QScrollArea {{
    background-color: {C['bg']};
    border: none;
}}
QScrollBar:vertical {{
    background: {C['card']};
    width: 8px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {C['surface']};
    min-height: 30px;
    border-radius: 4px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}
QLabel {{
    background: transparent;
}}
QLineEdit {{
    background-color: {C['surface']};
    color: {C['fg']};
    border: 1px solid {C['border']};
    border-radius: 4px;
    padding: 5px 8px;
    font-size: 10pt;
}}
QLineEdit:focus {{
    border: 1px solid {C['accent']};
}}
QListWidget {{
    background-color: {C['surface']};
    color: {C['fg']};
    border: none;
    border-radius: 4px;
    padding: 4px;
    font-size: 10pt;
    outline: none;
}}
QListWidget::item {{
    padding: 4px 8px;
    border-radius: 3px;
}}
QListWidget::item:selected {{
    background-color: {C['accent']};
    color: #ffffff;
}}
QListWidget::item:hover {{
    background-color: {C['border']};
}}
QTextEdit {{
    background-color: {C['surface']};
    color: {C['dim']};
    border: none;
    border-radius: 4px;
    padding: 6px;
    font-family: 'Consolas';
    font-size: 9pt;
}}
QPushButton {{
    border: none;
    border-radius: 4px;
    padding: 7px 14px;
    font-weight: bold;
    font-size: 9pt;
}}
QPushButton:disabled {{
    background-color: {C['surface']};
    color: {C['dim']};
}}
"""


# =============================================================================
#  SIGNALE (thread-safe GUI-Kommunikation)
# =============================================================================

class AppSignals(QObject):
    log_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str, str)           # text, color
    connected_signal = pyqtSignal(bool)             # reachable
    disconnected_signal = pyqtSignal()
    cancel_done_signal = pyqtSignal()
    show_devices_signal = pyqtSignal(list)
    enable_login_signal = pyqtSignal()
    logged_in_signal = pyqtSignal()
    update_available_signal = pyqtSignal(dict)
    update_progress_signal = pyqtSignal(str)
    update_failed_signal = pyqtSignal()
    apply_update_signal = pyqtSignal(str)
    device_status_signal = pyqtSignal(object, str, str)  # label, text, color
    btns_state_signal = pyqtSignal(list, bool)            # btn_refs, enabled
    trigger_rdp_signal = pyqtSignal(str, str, list, object, str, str)  # ip, name, btns, lbl, user, pw
    ask_rdp_signal = pyqtSignal(str, str, list, object, str, str)      # ip, name, btns, lbl, user, pw
    ping_result_signal = pyqtSignal(str)              # "{ms} ms" or "---"
    reconnect_signal = pyqtSignal()                   # trigger auto-reconnect
    auto_login_signal = pyqtSignal()                  # trigger upsnap auto-login
    vpn_ip_signal = pyqtSignal(str)                   # VPN tunnel IP
    history_updated_signal = pyqtSignal()
    transfer_signal = pyqtSignal(str)                  # "↓ X MB  ↑ Y MB"


# =============================================================================
#  CUSTOM WIDGETS
# =============================================================================

class DotWidget(QWidget):
    """Kleiner farbiger Punkt."""
    def __init__(self, color: str = C["red"], size: int = 12, parent=None):
        super().__init__(parent)
        self._color = color
        self._size = size
        self.setFixedSize(size, size)

    def set_color(self, color: str):
        self._color = color
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QColor(self._color))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(1, 1, self._size - 2, self._size - 2)
        p.end()


def _make_btn(text: str, bg: str, fg: str, hover: str,
              parent=None) -> QPushButton:
    btn = QPushButton(text, parent)
    btn.setStyleSheet(f"""
        QPushButton {{
            background-color: {bg}; color: {fg};
            border: none; border-radius: 4px;
            padding: 7px 14px; font-weight: bold; font-size: 9pt;
        }}
        QPushButton:hover {{ background-color: {hover}; }}
        QPushButton:disabled {{
            background-color: {C['surface']}; color: {C['dim']};
        }}
    """)
    return btn


# =============================================================================
#  GUI
# =============================================================================

class VPNApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"VPN Connect  v{APP_VERSION}")
        self.setMinimumSize(800, 520)
        self.resize(800, 560)
        self.setToolTip(
            "Tastaturkuerzel:\n"
            "  Strg+K   Verbinden\n"
            "  Strg+D   Trennen\n"
            "  Strg+L   Log ein/aus\n"
            "  Strg+H   Verlauf ein/aus"
        )

        self.configs: List[Tuple[str, str]] = []
        self.active_config: Optional[str] = None
        self.vpn_connected = False
        self.upsnap: Optional[UpSnapClient] = None
        self._device_widgets: List[QWidget] = []
        self._log_visible = False
        self._update_info: Optional[dict] = None
        self._history_visible = False
        self._session_start_time: float = 0
        self._session_config_name: str = ""
        self._favorites: List[str] = []        # device IDs
        self._rdp_users: dict = {}             # device_name -> username
        self._rdp_passwords: dict = {}         # device_name -> password (base64)
        self._devices_hash: str = ""           # Hash der Geräteliste (Smart-Refresh)
        self._active_ops: set = set()          # Device-IDs mit laufenden Operationen
        self._refresh_in_progress: bool = False  # verhindert parallele API-Aufrufe

        # Debounce-Timer für Settings (verhindert zu häufiges Schreiben bei schnellen Änderungen)
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(300)
        self._save_timer.timeout.connect(self._save_settings)

        # Connection duration
        self._connect_time: float = 0
        self._duration_timer = QTimer(self)
        self._duration_timer.setInterval(1000)
        self._duration_timer.timeout.connect(self._update_duration)

        # Ping
        self._ping_timer = QTimer(self)
        self._ping_timer.setInterval(5000)
        self._ping_timer.timeout.connect(self._ping_tick)

        # Auto-Reconnect
        self._reconnect_retries = 0
        self._watchdog_timer = QTimer(self)
        self._watchdog_timer.setInterval(10_000)
        self._watchdog_timer.timeout.connect(self._watchdog_tick)

        # Signale
        self.sig = AppSignals()
        self._connect_signals()

        # Auto-Refresh Timer (alle 3 Sekunden)
        self._auto_refresh_timer = QTimer(self)
        self._auto_refresh_timer.setInterval(3_000)
        self._auto_refresh_timer.timeout.connect(self._auto_refresh_tick)

        # Transfer-Stats Timer
        self._transfer_timer = QTimer(self)
        self._transfer_timer.setInterval(5_000)
        self._transfer_timer.timeout.connect(self._transfer_tick)

        self._loading = True          # blockiert _save_settings während gesamter Initialisierung
        self._build_ui()
        self._setup_tray()
        self._load_configs()
        self._load_credentials()      # setzt _loading=False am Ende selbst

        # Update-Check im Hintergrund
        threading.Thread(target=self._check_update_bg, daemon=True).start()

        # Dialog-Dismisser
        _start_dialog_dismisser()

    # ── Signale verbinden ──────────────────────────────────────────────────

    def _connect_signals(self):
        self.sig.log_signal.connect(self._append_log)
        self.sig.status_signal.connect(self._set_status)
        self.sig.connected_signal.connect(self._connected)
        self.sig.disconnected_signal.connect(self._disconnected)
        self.sig.cancel_done_signal.connect(lambda: self.btn_cancel.hide())
        self.sig.show_devices_signal.connect(self._show_devices)
        self.sig.enable_login_signal.connect(
            lambda: self.btn_login.setEnabled(True))
        self.sig.logged_in_signal.connect(self._on_logged_in)
        self.sig.update_available_signal.connect(self._show_update_btn)
        self.sig.update_progress_signal.connect(
            lambda t: self.btn_update.setText(t))
        self.sig.update_failed_signal.connect(self._on_update_failed)
        self.sig.apply_update_signal.connect(self._apply_update)
        self.sig.device_status_signal.connect(self._set_device_status_slot)
        self.sig.btns_state_signal.connect(self._set_btns_slot)
        self.sig.trigger_rdp_signal.connect(
            lambda ip, name, bl, sl, u, pw: self._on_rdp(ip, name, bl, sl, username=u, password=pw))
        self.sig.ask_rdp_signal.connect(self._ask_rdp_anyway)
        self.sig.ping_result_signal.connect(self._update_ping_label)
        self.sig.reconnect_signal.connect(self._on_auto_reconnect)
        self.sig.auto_login_signal.connect(self._try_auto_login)
        self.sig.vpn_ip_signal.connect(self._update_ip_label)
        self.sig.history_updated_signal.connect(self._refresh_history_ui)
        self.sig.transfer_signal.connect(self._update_transfer_label)

    # ── Layout ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        pad = 20

        # Zentrales Widget mit Scroll-Bereich
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.setCentralWidget(scroll)

        outer = QWidget()
        outer.setStyleSheet(f"background-color: {C['bg']};")
        scroll.setWidget(outer)
        main_layout = QVBoxLayout(outer)
        main_layout.setContentsMargins(pad, pad, pad, pad)
        main_layout.setSpacing(0)

        # ── Header ──
        hdr = QHBoxLayout()
        hdr.setContentsMargins(0, 0, 0, 16)

        title = QLabel("VPN Connect")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {C['fg']};")
        hdr.addWidget(title)

        # Update-Button (initial versteckt)
        self.btn_update = _make_btn("⬆ Update verfügbar", C["green"], "#000000", "#86efac")
        self.btn_update.clicked.connect(self._on_update)
        self.btn_update.hide()
        hdr.addWidget(self.btn_update)

        hdr.addStretch()

        # Duration Label
        self.duration_label = QLabel("")
        self.duration_label.setFont(QFont("Consolas", 10))
        self.duration_label.setStyleSheet(f"color: {C['dim']};")
        self.duration_label.hide()
        hdr.addWidget(self.duration_label)
        hdr.addSpacing(10)

        # Ping Label
        self.ping_label = QLabel("")
        self.ping_label.setFont(QFont("Consolas", 10))
        self.ping_label.setStyleSheet(f"color: {C['dim']};")
        self.ping_label.hide()
        hdr.addWidget(self.ping_label)
        hdr.addSpacing(14)

        # VPN-IP Label
        self.vpn_ip_label = QLabel("")
        self.vpn_ip_label.setFont(QFont("Consolas", 10))
        self.vpn_ip_label.setStyleSheet(f"color: {C['cyan']};")
        self.vpn_ip_label.setToolTip("VPN-Tunnel IP-Adresse")
        self.vpn_ip_label.hide()
        hdr.addWidget(self.vpn_ip_label)
        hdr.addSpacing(14)

        # Transfer-Stats Label
        self.transfer_label = QLabel("")
        self.transfer_label.setFont(QFont("Consolas", 10))
        self.transfer_label.setStyleSheet(f"color: {C['dim']};")
        self.transfer_label.setToolTip("VPN Datentransfer")
        self.transfer_label.hide()
        hdr.addWidget(self.transfer_label)
        hdr.addSpacing(14)

        # Status
        status_box = QHBoxLayout()
        status_box.setSpacing(6)
        self.status_dot = DotWidget(C["red"])
        status_box.addWidget(self.status_dot)
        self.status_label = QLabel("Getrennt")
        self.status_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.status_label.setStyleSheet(f"color: {C['red']};")
        status_box.addWidget(self.status_label)
        hdr.addLayout(status_box)

        main_layout.addLayout(hdr)

        # ── WireGuard Sektion ──
        wg_header = QLabel("WIREGUARD KANAL")
        wg_header.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        wg_header.setStyleSheet(f"color: {C['dim']};")
        main_layout.addWidget(wg_header)
        main_layout.addSpacing(6)

        wg_card = QFrame()
        wg_card.setStyleSheet(f"""
            QFrame {{ background-color: {C['card']}; border-radius: 8px; }}
        """)
        wg_layout = QVBoxLayout(wg_card)
        wg_layout.setContentsMargins(14, 14, 14, 14)
        wg_layout.setSpacing(10)

        self.config_listbox = QListWidget()
        self.config_listbox.setMaximumHeight(80)
        self.config_listbox.itemDoubleClicked.connect(
            lambda: self._on_connect() if not self.vpn_connected else None)
        self.config_listbox.currentRowChanged.connect(lambda: self._save_settings())
        wg_layout.addWidget(self.config_listbox)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        self.btn_connect = _make_btn("Verbinden", C["accent"], "#ffffff", C["accent_h"])
        self.btn_connect.clicked.connect(self._on_connect)
        btn_row.addWidget(self.btn_connect)

        self.btn_disconnect = _make_btn("Trennen", C["red"], "#ffffff", "#fca5a5")
        self.btn_disconnect.clicked.connect(self._on_disconnect)
        self.btn_disconnect.setEnabled(False)
        btn_row.addWidget(self.btn_disconnect)

        self.btn_cancel = _make_btn("Abbrechen", C["orange"], "#000000", C["yellow"])
        self.btn_cancel.clicked.connect(self._on_cancel)
        self.btn_cancel.hide()
        btn_row.addWidget(self.btn_cancel)

        self.btn_browser = _make_btn("Im Browser oeffnen", C["surface"], C["fg"], C["border"])
        self.btn_browser.clicked.connect(self._on_open_browser)
        self.btn_browser.setEnabled(False)
        btn_row.addWidget(self.btn_browser)

        btn_row.addStretch()
        wg_layout.addLayout(btn_row)

        # Auto-Reconnect Checkbox
        self.chk_auto_reconnect = QCheckBox("Auto-Reconnect bei Verbindungsverlust")
        self.chk_auto_reconnect.setStyleSheet(f"""
            QCheckBox {{ color: {C['dim']}; font-size: 9pt; }}
            QCheckBox::indicator {{ width: 14px; height: 14px; }}
            QCheckBox::indicator:unchecked {{
                border: 1px solid {C['border']}; border-radius: 3px;
                background: {C['surface']};
            }}
            QCheckBox::indicator:checked {{
                border: 1px solid {C['accent']}; border-radius: 3px;
                background: {C['accent']};
            }}
        """)
        self.chk_auto_reconnect.stateChanged.connect(lambda: self._save_settings())
        wg_layout.addWidget(self.chk_auto_reconnect)

        # Auto-Connect beim Start Checkbox
        self.chk_auto_connect = QCheckBox("Automatisch verbinden beim Start")
        self.chk_auto_connect.setStyleSheet(f"""
            QCheckBox {{ color: {C['dim']}; font-size: 9pt; }}
            QCheckBox::indicator {{ width: 14px; height: 14px; }}
            QCheckBox::indicator:unchecked {{
                border: 1px solid {C['border']}; border-radius: 3px;
                background: {C['surface']};
            }}
            QCheckBox::indicator:checked {{
                border: 1px solid {C['accent']}; border-radius: 3px;
                background: {C['accent']};
            }}
        """)
        self.chk_auto_connect.stateChanged.connect(lambda: self._save_settings())
        wg_layout.addWidget(self.chk_auto_connect)

        main_layout.addWidget(wg_card)
        main_layout.addSpacing(16)

        # ── Server / Ziel-Einstellungen ──
        srv_header = QLabel("SERVER / ZIEL")
        srv_header.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        srv_header.setStyleSheet(f"color: {C['dim']};")
        main_layout.addWidget(srv_header)
        main_layout.addSpacing(6)

        srv_card = QFrame()
        srv_card.setStyleSheet(f"QFrame {{ background-color: {C['card']}; border-radius: 8px; }}")
        srv_layout = QHBoxLayout(srv_card)
        srv_layout.setContentsMargins(14, 10, 14, 10)
        srv_layout.setSpacing(8)

        lbl_ip = QLabel("IP / Hostname:")
        lbl_ip.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
        srv_layout.addWidget(lbl_ip)

        self.entry_target_ip = QLineEdit()
        self.entry_target_ip.setPlaceholderText("z.B. 192.168.1.10")
        self.entry_target_ip.setFixedWidth(180)
        self.entry_target_ip.editingFinished.connect(self._apply_server_settings)
        srv_layout.addWidget(self.entry_target_ip)

        srv_layout.addSpacing(10)

        lbl_port = QLabel("Port:")
        lbl_port.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
        srv_layout.addWidget(lbl_port)

        self.entry_target_port = QLineEdit()
        self.entry_target_port.setPlaceholderText("8090")
        self.entry_target_port.setFixedWidth(70)
        self.entry_target_port.editingFinished.connect(self._apply_server_settings)
        srv_layout.addWidget(self.entry_target_port)

        srv_layout.addStretch()
        main_layout.addWidget(srv_card)
        main_layout.addSpacing(16)

        # ── UpSnap Sektion ──
        snap_header = QLabel("UPSNAP  /  WAKE ON LAN")
        snap_header.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        snap_header.setStyleSheet(f"color: {C['dim']};")
        main_layout.addWidget(snap_header)
        main_layout.addSpacing(6)

        snap_card = QFrame()
        snap_card.setStyleSheet(f"""
            QFrame {{ background-color: {C['card']}; border-radius: 8px; }}
        """)
        snap_layout = QVBoxLayout(snap_card)
        snap_layout.setContentsMargins(14, 14, 14, 14)
        snap_layout.setSpacing(8)

        login_row = QHBoxLayout()
        login_row.setSpacing(6)

        self.lbl_email = QLabel("E-Mail")
        self.lbl_email.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
        login_row.addWidget(self.lbl_email)
        self.entry_user = QLineEdit()
        self.entry_user.setFixedWidth(180)
        self.entry_user.returnPressed.connect(lambda: self.entry_pass.setFocus())
        self.entry_user.editingFinished.connect(lambda: self._save_settings())
        login_row.addWidget(self.entry_user)

        login_row.addSpacing(6)

        self.lbl_pw = QLabel("Passwort")
        self.lbl_pw.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
        login_row.addWidget(self.lbl_pw)
        self.entry_pass = QLineEdit()
        self.entry_pass.setFixedWidth(140)
        self.entry_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.entry_pass.returnPressed.connect(self._on_upsnap_login)
        self.entry_pass.editingFinished.connect(lambda: self._save_settings())
        login_row.addWidget(self.entry_pass)

        login_row.addSpacing(6)

        self.btn_login = _make_btn("Anmelden", C["accent"], "#ffffff", C["accent_h"])
        self.btn_login.clicked.connect(self._on_upsnap_login)
        login_row.addWidget(self.btn_login)

        login_row.addStretch()
        snap_layout.addLayout(login_row)

        # Separator
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {C['border']};")
        snap_layout.addWidget(sep)

        # Geräte-Info-Zeile (Count + Zeitstempel)
        self.device_info_label = QLabel("")
        self.device_info_label.setStyleSheet(
            f"color: {C['dim']}; font-size: 8pt;")
        self.device_info_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.device_info_label.hide()
        snap_layout.addWidget(self.device_info_label)

        # Device-Bereich
        self.device_frame = QVBoxLayout()
        self.device_frame.setSpacing(2)
        self.upsnap_hint = QLabel("Anmelden um Geraete anzuzeigen")
        self.upsnap_hint.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
        self.upsnap_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.device_frame.addWidget(self.upsnap_hint)
        snap_layout.addLayout(self.device_frame)

        main_layout.addWidget(snap_card)
        main_layout.addSpacing(12)

        # ── Log Toggle ──
        self.log_toggle = QPushButton("[+] Log")
        self.log_toggle.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {C['dim']};
                border: none; font-size: 9pt; padding: 4px 2px;
                text-align: left;
            }}
            QPushButton:hover {{ color: {C['fg']}; }}
        """)
        self.log_toggle.clicked.connect(self._toggle_log)
        main_layout.addWidget(self.log_toggle, alignment=Qt.AlignmentFlag.AlignLeft)

        # Log Frame
        self.log_frame = QFrame()
        self.log_frame.setStyleSheet(f"background-color: {C['card']}; border-radius: 6px;")
        log_layout = QVBoxLayout(self.log_frame)
        log_layout.setContentsMargins(8, 8, 8, 8)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        self.log_text.setMaximumHeight(200)
        log_layout.addWidget(self.log_text)

        self.log_frame.hide()
        main_layout.addWidget(self.log_frame)

        # ── Verbindungshistorie ──
        self.history_toggle = QPushButton("[+] Verbindungshistorie")
        self.history_toggle.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {C['dim']};
                border: none; font-size: 9pt; padding: 4px 2px;
                text-align: left;
            }}
            QPushButton:hover {{ color: {C['fg']}; }}
        """)
        self.history_toggle.clicked.connect(self._toggle_history)
        main_layout.addWidget(self.history_toggle, alignment=Qt.AlignmentFlag.AlignLeft)

        self.history_frame = QFrame()
        self.history_frame.setStyleSheet(f"background-color: {C['card']}; border-radius: 6px;")
        hist_layout = QVBoxLayout(self.history_frame)
        hist_layout.setContentsMargins(8, 8, 8, 8)
        hist_layout.setSpacing(4)
        self.history_list_widget = QWidget()
        self.history_list_layout = QVBoxLayout(self.history_list_widget)
        self.history_list_layout.setContentsMargins(0, 0, 0, 0)
        self.history_list_layout.setSpacing(2)
        hist_layout.addWidget(self.history_list_widget)
        btn_clear_hist = QPushButton("Verlauf leeren")
        btn_clear_hist.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {C['dim']};
                border: none; font-size: 8pt; padding: 2px;
                text-align: right;
            }}
            QPushButton:hover {{ color: {C['red']}; }}
        """)
        btn_clear_hist.clicked.connect(self._clear_history)
        hist_layout.addWidget(btn_clear_hist, alignment=Qt.AlignmentFlag.AlignRight)
        self.history_frame.hide()
        main_layout.addWidget(self.history_frame)

        main_layout.addStretch()

        # ── Tastaturkürzel ──
        QShortcut(QKeySequence("Ctrl+K"), self).activated.connect(
            lambda: self._on_connect() if not self.vpn_connected else None)
        QShortcut(QKeySequence("Ctrl+D"), self).activated.connect(
            lambda: self._on_disconnect() if self.vpn_connected else None)
        QShortcut(QKeySequence("Ctrl+L"), self).activated.connect(self._toggle_log)
        QShortcut(QKeySequence("Ctrl+H"), self).activated.connect(self._toggle_history)

    # ── Status ─────────────────────────────────────────────────────────────

    def _set_status(self, text: str, color: str):
        self.status_dot.set_color(color)
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color}; background: transparent;")

    # ── Log ────────────────────────────────────────────────────────────────

    def _toggle_log(self):
        if self._log_visible:
            self.log_frame.hide()
            self.log_toggle.setText("[+] Log")
            self._log_visible = False
        else:
            self.log_frame.show()
            self.log_toggle.setText("[-] Log")
            self._log_visible = True

    def _append_log(self, msg: str):
        self.log_text.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
        # Max 500 Zeilen
        doc = self.log_text.document()
        if doc.blockCount() > 500:
            cursor = self.log_text.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            cursor.movePosition(cursor.MoveOperation.Down,
                                cursor.MoveMode.KeepAnchor,
                                doc.blockCount() - 500)
            cursor.removeSelectedText()
        sb = self.log_text.verticalScrollBar()
        sb.setValue(sb.maximum())

    # Kompatibilitäts-Wrapper
    def append_log(self, msg: str):
        self.sig.log_signal.emit(msg)

    # ── Configs ────────────────────────────────────────────────────────────

    def _load_configs(self):
        self.configs = collect_all_configs()
        self.config_listbox.clear()
        if not self.configs:
            self.config_listbox.addItem("  Keine Konfigurationen gefunden")
            self.btn_connect.setEnabled(False)
        else:
            for name, _ in self.configs:
                self.config_listbox.addItem(f"  {name}")
            self.config_listbox.setCurrentRow(0)

    # ── Auto-Update ────────────────────────────────────────────────────────

    def _check_update_bg(self):
        info = check_for_update()
        if info:
            self._update_info = info
            self.sig.update_available_signal.emit(info)

    def _show_update_btn(self, info: dict):
        tag = info["tag"]
        size_mb = info.get("size", 0) / (1024 * 1024)
        self.btn_update.setText(f"⬆ Update {tag}  ({size_mb:.1f} MB)")
        self.btn_update.show()

    def _on_update(self):
        info = self._update_info
        if not info:
            return
        reply = QMessageBox.question(
            self, "Update",
            f"Version {info['tag']} herunterladen und installieren?\n\n"
            f"Die App wird nach dem Update automatisch neu gestartet.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.btn_update.setEnabled(False)
        self.btn_update.setText("⬆ Lade herunter...")

        def work():
            dest = os.path.join(_base_dir, "VPN_Connect_new.exe")

            def progress(done, total):
                if total > 0:
                    pct = int(done / total * 100)
                    self.sig.update_progress_signal.emit(
                        f"⬆ {pct}%  ({done // 1024 // 1024}/{total // 1024 // 1024} MB)")

            ok = download_update(info["url"], dest, progress)
            if ok:
                self.sig.apply_update_signal.emit(dest)
            else:
                self.sig.update_failed_signal.emit()

        threading.Thread(target=work, daemon=True).start()

    def _on_update_failed(self):
        self.btn_update.setEnabled(True)
        self.btn_update.setText("⬆ Download fehlgeschlagen")
        QMessageBox.critical(self, "Update", "Download fehlgeschlagen.")

    def _apply_update(self, new_exe: str):
        log("Installiere Update...")
        if self.active_config:
            disconnect_vpn(self.active_config)
        apply_update(new_exe)

    # ── VPN Connect ────────────────────────────────────────────────────────

    def _on_connect(self):
        sel = self.config_listbox.currentRow()
        if sel < 0 or not self.configs:
            return
        _, path = self.configs[sel]
        self.btn_connect.setEnabled(False)
        self.btn_cancel.show()
        self._set_status("Verbinde...", C["yellow"])

        def work():
            global _active_config
            r = connect_vpn(path)
            if _cancel_event.is_set():
                if r:
                    disconnect_vpn(r)
                self.sig.disconnected_signal.emit()
                self.sig.cancel_done_signal.emit()
                return
            if r:
                self.active_config = r
                _active_config = r
                self.vpn_connected = True
                ok = check_connection(TARGET_IP, TARGET_PORT, retries=5, delay=2.0)
                self.sig.connected_signal.emit(ok)
            else:
                self.sig.disconnected_signal.emit()
            self.sig.cancel_done_signal.emit()
        threading.Thread(target=work, daemon=True).start()

    def _on_cancel(self):
        log("Abbrechen angefordert...")
        _cancel_event.set()
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.setText("Abbreche...")
        self._set_status("Abbreche...", C["orange"])

    def _connected(self, reachable: bool):
        self._set_status("Verbunden", C["green"])
        self.btn_connect.setEnabled(False)
        self.btn_disconnect.setEnabled(True)
        self.btn_browser.setEnabled(reachable)
        if reachable:
            log(f"Ziel {TARGET_IP}:{TARGET_PORT} erreichbar.")
        else:
            log("Ziel noch nicht erreichbar.", "warning")

        # Duration-Timer starten
        self._connect_time = time.time()
        self.duration_label.setText("00:00:00")
        self.duration_label.show()
        self._duration_timer.start()

        # Ping starten
        self.ping_label.show()
        self._ping_timer.start()
        self._ping_tick()  # sofort einmal pingen

        # Transfer-Stats starten
        self._transfer_timer.start()
        self._transfer_tick()

        # Watchdog starten
        self._reconnect_retries = 0
        if self.chk_auto_reconnect.isChecked():
            self._watchdog_timer.start()

        # Config-Auswahl speichern
        self._save_settings()

        # Verbindungshistorie starten
        sel = self.config_listbox.currentRow()
        self._session_config_name = self.configs[sel][0].strip() if self.configs and sel >= 0 else "?"
        self._session_start_time = time.time()

        # VPN-IP ermitteln
        if self.active_config:
            tn = extract_tunnel_name(self.active_config)
            threading.Thread(target=self._fetch_vpn_ip, args=(tn,), daemon=True).start()

        # Toast-Benachrichtigung
        self._notify("VPN verbunden", f"{self._session_config_name} – Verbunden!")

        # Tray-Tooltip
        if hasattr(self, '_tray') and self._tray:
            self._tray.setToolTip(f"VPN Connect - Verbunden")
            self._tray_act_toggle.setText("Trennen")

        # Auto-Login bei UpSnap
        QTimer.singleShot(500, lambda: self.sig.auto_login_signal.emit())

    def _disconnected(self):
        self._set_status("Getrennt", C["red"])
        self.btn_connect.setEnabled(True)
        self.btn_disconnect.setEnabled(False)
        self.btn_browser.setEnabled(False)
        self.btn_cancel.hide()
        self.btn_cancel.setEnabled(True)
        self.btn_cancel.setText("Abbrechen")
        self.vpn_connected = False
        self.active_config = None

        # Timer stoppen
        self._duration_timer.stop()
        self.duration_label.hide()
        self._ping_timer.stop()
        self.ping_label.hide()
        self.vpn_ip_label.hide()
        self._watchdog_timer.stop()
        self._transfer_timer.stop()
        self.transfer_label.hide()
        self._stop_auto_refresh()
        self._refresh_in_progress = False
        self._active_ops.clear()

        # History-Eintrag abschließen
        if self._session_start_time > 0:
            duration = int(time.time() - self._session_start_time)
            self._add_history_entry(self._session_config_name, self._session_start_time, duration)
            self._session_start_time = 0

        # Toast
        self._notify("VPN getrennt", "Verbindung wurde beendet.")

        # Tray-Tooltip
        if hasattr(self, '_tray') and self._tray:
            self._tray.setToolTip(f"VPN Connect - Getrennt")
            self._tray_act_toggle.setText("Verbinden")

    # ── VPN Disconnect ─────────────────────────────────────────────────────

    def _on_disconnect(self):
        global _active_config
        self.btn_disconnect.setEnabled(False)
        self._set_status("Trenne...", C["yellow"])

        # Watchdog SOFORT stoppen – verhindert Auto-Reconnect während manuellem Trennen
        self._watchdog_timer.stop()
        self._reconnect_retries = 0

        def work():
            global _active_config
            if self.active_config:
                disconnect_vpn(self.active_config)
                _active_config = None
            self.sig.disconnected_signal.emit()

        threading.Thread(target=work, daemon=True).start()

    # ── Browser ────────────────────────────────────────────────────────────

    def _on_open_browser(self):
        url = f"http://{TARGET_IP}:{TARGET_PORT}"
        log(f"Oeffne {url}...")

        try:
            subprocess.Popen(["rundll32", "url.dll,FileProtocolHandler", url])
            log("Browser geöffnet (rundll32).")
            return
        except Exception as e:
            log(f"rundll32 fehlgeschlagen: {e}", "warning")

        try:
            subprocess.Popen(["explorer", url])
            log("Browser geöffnet (explorer).")
            return
        except Exception as e:
            log(f"explorer fehlgeschlagen: {e}", "warning")

        try:
            import webbrowser
            webbrowser.open(url)
            log("Browser geöffnet (webbrowser).")
        except Exception as e:
            log(f"Browser-Fehler: {e}", "error")

    # ── Settings / Credentials ─────────────────────────────────────────────

    _CRED_FILE = os.path.join(_base_dir, "vpn_settings.json")

    def _save_settings(self):
        """Alle Einstellungen atomar in eine Datei speichern."""
        if getattr(self, '_loading', False):
            return
        # Laufende Einstellungen aus UI lesen
        u = self.entry_user.text().strip()
        p = self.entry_pass.text().strip()
        try:
            # Bestehende Daten laden um History/andere Keys zu erhalten
            data: dict = {}
            if os.path.exists(self._CRED_FILE):
                try:
                    with open(self._CRED_FILE, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    data = {}

            data.update({
                "v": 2,
                "user": u,
                "pw_b64": base64.b64encode(p.encode("utf-8")).decode("ascii") if p else "",
                "last_config": self.config_listbox.currentRow(),
                "auto_reconnect": self.chk_auto_reconnect.isChecked(),
                "auto_connect": self.chk_auto_connect.isChecked(),
                "favorites": self._favorites,
                "rdp_users": self._rdp_users,
                "rdp_passwords": self._rdp_passwords,
                "target_ip": self.entry_target_ip.text().strip(),
                "target_port": int(self.entry_target_port.text().strip() or TARGET_PORT),
            })

            # Atomar schreiben: erst in .tmp, dann umbenennen
            tmp = self._CRED_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            # os.replace ist atomar auf Windows (überschreibt bestehende Datei)
            os.replace(tmp, self._CRED_FILE)

        except OSError:
            pass

    def _schedule_save(self):
        """Verzögertes Speichern (Debounce 300 ms) – für häufige Änderungen."""
        self._save_timer.start()  # restart bei jedem Aufruf

    def _save_credentials(self, user: str, pw: str):
        """Credentials setzen und sofort speichern."""
        self.entry_user.setText(user)
        self.entry_pass.setText(pw)
        self._save_settings()

    def _save_favorites(self):
        """Favoriten/RDP-User speichern – nutzt die zentrale Speicherfunktion."""
        self._save_settings()

    def _load_credentials(self):
        self._loading = True
        try:
            if not os.path.exists(self._CRED_FILE):
                return
            with open(self._CRED_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)

            self.entry_user.setText(d.get("user", ""))

            # Passwort: v2=base64, v1=plaintext
            if d.get("v", 1) >= 2 and d.get("pw_b64"):
                pw = base64.b64decode(d["pw_b64"].encode("ascii")).decode("utf-8")
                self.entry_pass.setText(pw)
            elif d.get("pw"):
                self.entry_pass.setText(d["pw"])
                QTimer.singleShot(500, self._save_settings)

            # Letzte Config
            idx = d.get("last_config", 0)
            if 0 <= idx < self.config_listbox.count():
                self.config_listbox.setCurrentRow(idx)

            # Auto-Reconnect
            self.chk_auto_reconnect.setChecked(d.get("auto_reconnect", False))

            # Auto-Connect
            self.chk_auto_connect.setChecked(d.get("auto_connect", False))

            # Favoriten & RDP-User & RDP-Passwörter
            self._favorites = d.get("favorites", [])
            self._rdp_users = d.get("rdp_users", {})
            self._rdp_passwords = d.get("rdp_passwords", {})

            # Server IP + Port laden und anwenden
            saved_ip = d.get("target_ip", "")
            saved_port = d.get("target_port", TARGET_PORT)
            if saved_ip:
                self.entry_target_ip.setText(saved_ip)
            self.entry_target_port.setText(str(saved_port))
            self._apply_server_settings(save=False)

            # Auto-Connect beim Start
            _auto_connect = d.get("auto_connect", False) and bool(self.configs)

        except Exception:
            _auto_connect = False
        finally:
            self._loading = False

        if _auto_connect:
            QTimer.singleShot(800, self._on_connect)

    def _apply_server_settings(self, save: bool = True):
        """IP + Port aus den Feldern übernehmen und global setzen."""
        global TARGET_IP, TARGET_PORT
        ip = self.entry_target_ip.text().strip()
        port_txt = self.entry_target_port.text().strip()
        try:
            port = int(port_txt) if port_txt else TARGET_PORT
        except ValueError:
            port = TARGET_PORT
        TARGET_IP = ip
        TARGET_PORT = port
        # Browser-Button nur aktiv wenn IP gesetzt und verbunden
        if hasattr(self, 'btn_browser'):
            self.btn_browser.setEnabled(
                self.vpn_connected and bool(TARGET_IP))
        if save:
            self._save_settings()

    # ── Auto-Refresh ───────────────────────────────────────────────────────

    def _start_auto_refresh(self):
        self._auto_refresh_timer.start()

    def _stop_auto_refresh(self):
        self._auto_refresh_timer.stop()

    def _auto_refresh_tick(self):
        if not self.upsnap or not self.vpn_connected:
            return
        if self._refresh_in_progress:
            return                              # vorherigen Aufruf abwarten
        self._refresh_in_progress = True

        def work():
            try:
                devs = self.upsnap.get_devices()
                if devs is not None:
                    # Erfolg – Geräteliste aktualisieren
                    self.sig.show_devices_signal.emit(devs)
                elif self.upsnap._last_status in (401, 403):
                    # Token abgelaufen → automatisch neu anmelden
                    log("UpSnap Token abgelaufen – erneuere...", "warning")
                    if self.upsnap.reauth():
                        devs2 = self.upsnap.get_devices()
                        if devs2 is not None:
                            self.sig.show_devices_signal.emit(devs2)
                # devs is None ohne 401 = Netzwerkfehler → Display unverändert lassen
            except Exception:
                pass
            finally:
                self._refresh_in_progress = False

        threading.Thread(target=work, daemon=True).start()

    # ── UpSnap Login ───────────────────────────────────────────────────────

    def _on_upsnap_login(self):
        # Wenn bereits angemeldet → Abmelden
        if self.upsnap is not None:
            self._on_logout()
            return

        u = self.entry_user.text().strip()
        p = self.entry_pass.text().strip()
        if not u or not p:
            QMessageBox.information(self, "UpSnap", "E-Mail und Passwort eingeben.")
            return
        self.btn_login.setEnabled(False)

        def work():
            try:
                c = UpSnapClient(f"http://{TARGET_IP}:{TARGET_PORT}", u, p)
                if c.token:
                    self.upsnap = c
                    devs = c.get_devices()
                    self.sig.show_devices_signal.emit(devs)
                    self.sig.logged_in_signal.emit()
                    # Credentials speichern (muss im Main-Thread)
                    QTimer.singleShot(0, lambda: self._save_credentials(u, p))
                    QTimer.singleShot(0, self._start_auto_refresh)
                else:
                    self.sig.enable_login_signal.emit()
            except Exception as e:
                log(f"UpSnap Login Fehler: {e}", "error")
                self.sig.enable_login_signal.emit()
        threading.Thread(target=work, daemon=True).start()

    def _on_logged_in(self):
        """UI nach erfolgreichem Login umschalten."""
        self.btn_login.setText("Abmelden")
        self.btn_login.setEnabled(True)
        self.lbl_email.hide()
        self.entry_user.hide()
        self.lbl_pw.hide()
        self.entry_pass.hide()

    def _on_logout(self):
        """Abmelden und UI zurücksetzen."""
        self.upsnap = None
        self._stop_auto_refresh()
        self._devices_hash = ""
        self._refresh_in_progress = False

        # Geräte-Widgets entfernen
        for w in self._device_widgets:
            w.setParent(None)
            w.deleteLater()
        self._device_widgets.clear()
        self.upsnap_hint.show()
        self.device_info_label.hide()

        # UI zurücksetzen
        self.btn_login.setText("Anmelden")
        self.lbl_email.show()
        self.entry_user.show()
        self.lbl_pw.show()
        self.entry_pass.show()
        log("UpSnap abgemeldet.")

    # ── Device-Anzeige ─────────────────────────────────────────────────────

    def _show_devices(self, devices: List[dict]):
        # Smart-Refresh: Hash berechnen (nur relevante Felder)
        hash_data = [(d.get("id", ""), d.get("name", ""), d.get("ip", ""),
                       d.get("status", "")) for d in devices]
        new_hash = hashlib.md5(json.dumps(hash_data, sort_keys=True).encode()).hexdigest()

        # Rebuild unterdrücken wenn aktive Operationen laufen
        if self._active_ops:
            # Info-Label trotzdem aktualisieren
            self._update_device_info(devices)
            return

        # Kein Rebuild wenn sich nichts geändert hat
        if new_hash == self._devices_hash:
            self._update_device_info(devices)
            return

        self._devices_hash = new_hash

        # Alte Widgets entfernen
        for w in self._device_widgets:
            w.setParent(None)
            w.deleteLater()
        self._device_widgets.clear()
        self.upsnap_hint.hide()

        if not devices:
            lbl = QLabel("Keine Geraete.")
            lbl.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.device_frame.addWidget(lbl)
            self._device_widgets.append(lbl)
            self.btn_login.setEnabled(True)
            self._update_device_info(devices)
            return

        # Favoriten zuerst sortieren
        def _sort_key(dev):
            return (0 if dev.get("id", "") in self._favorites else 1, dev.get("name", ""))
        devices_sorted = sorted(devices, key=_sort_key)

        for d in devices_sorted:
            row = QFrame()
            row.setStyleSheet(f"""
                QFrame {{ background-color: {C['surface']}; border-radius: 4px; }}
            """)
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(12, 7, 12, 7)
            row_layout.setSpacing(8)

            name  = d.get("name", "?")
            ip    = d.get("ip", "?")
            online = d.get("status") == "online"
            dot_c  = C["green"] if online else C["dim"]

            dot = DotWidget(dot_c, 10)
            row_layout.addWidget(dot)

            name_lbl = QLabel(name)
            name_lbl.setStyleSheet(f"color: {C['fg']}; font-size: 10pt;")
            row_layout.addWidget(name_lbl)

            ip_lbl = QLabel(ip)
            ip_lbl.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
            row_layout.addWidget(ip_lbl)

            row_layout.addStretch()

            # Status-Label
            init_txt = "Online" if online else "Offline"
            init_col = C["green"] if online else C["dim"]
            status_lbl = QLabel(init_txt)
            status_lbl.setFixedWidth(80)
            status_lbl.setStyleSheet(
                f"color: {init_col}; font-size: 8pt; font-weight: bold;")
            row_layout.addWidget(status_lbl)

            # Buttons
            did, dip, dn = d.get("id", ""), ip, name
            btn_refs: List[QPushButton] = []

            # Favoriten-Stern
            is_fav = did in self._favorites
            star_col = C["yellow"] if is_fav else C["dim"]
            star_btn = QPushButton("★" if is_fav else "☆")
            star_btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent; color: {star_col};
                    border: none; font-size: 14pt; padding: 0 4px;
                }}
                QPushButton:hover {{ color: {C['yellow']}; }}
            """)
            star_btn.setToolTip("Favorit")
            star_btn.clicked.connect(
                lambda checked, x=did, b=star_btn: self._toggle_favorite(x, b))
            row_layout.addWidget(star_btn)

            if online:
                b = _make_btn("RDP", C["surface"], C["fg"], C["border"])
                b.setStyleSheet(b.styleSheet().replace(
                    "font-weight: bold;", "font-weight: normal; font-size: 9pt;"))
                b.clicked.connect(
                    lambda checked, x=dip, n=dn, bl=btn_refs, sl=status_lbl:
                    self._on_rdp_with_user(x, n, bl, sl))
                row_layout.addWidget(b)
                btn_refs.append(b)
            else:
                b1 = _make_btn("WoL", C["surface"], C["fg"], C["border"])
                b1.setStyleSheet(b1.styleSheet().replace(
                    "font-weight: bold;", "font-weight: normal; font-size: 9pt;"))
                b1.clicked.connect(
                    lambda checked, x=did, n=dn, bl=btn_refs, sl=status_lbl:
                    self._on_wake(x, n, bl, sl))
                row_layout.addWidget(b1)

                b2 = _make_btn("WoL + RDP", C["surface"], C["fg"], C["border"])
                b2.setStyleSheet(b2.styleSheet().replace(
                    "font-weight: bold;", "font-weight: normal; font-size: 9pt;"))
                b2.clicked.connect(
                    lambda checked, x=did, y=dip, n=dn, bl=btn_refs, sl=status_lbl:
                    self._on_wake_rdp(x, y, n, bl, sl))
                row_layout.addWidget(b2)

                btn_refs += [b1, b2]

            self.device_frame.addWidget(row)
            self._device_widgets.append(row)

        self.btn_login.setEnabled(True)
        self._update_device_info(devices)

    def _update_device_info(self, devices: List[dict]):
        """Geräte-Count und Zeitstempel aktualisieren."""
        total = len(devices)
        online = sum(1 for d in devices if d.get("status") == "online")
        ts = time.strftime("%H:%M:%S")
        self.device_info_label.setText(
            f"{total} Geräte ({online} online)  •  Aktualisiert: {ts}")
        self.device_info_label.show()

    # ── Device-Status Hilfsfunktionen ──────────────────────────────────────

    def _set_device_status_slot(self, lbl, text: str, color: str):
        """Slot für thread-safe Status-Update."""
        try:
            lbl.setText(text)
            lbl.setStyleSheet(
                f"color: {color}; font-size: 8pt; font-weight: bold;")
        except RuntimeError:
            pass

    @staticmethod
    def _set_device_status(status_lbl: QLabel, text: str, color: str):
        """Direkt im Main-Thread aufrufen."""
        try:
            status_lbl.setText(text)
            status_lbl.setStyleSheet(
                f"color: {color}; font-size: 8pt; font-weight: bold;")
        except RuntimeError:
            pass

    def _set_btns_slot(self, btn_refs: list, enabled: bool):
        for b in btn_refs:
            try:
                b.setEnabled(enabled)
            except RuntimeError:
                pass

    @staticmethod
    def _set_btns(btn_refs: list, enabled: bool):
        for b in btn_refs:
            try:
                b.setEnabled(enabled)
            except RuntimeError:
                pass

    # ── Device-Actions ─────────────────────────────────────────────────────

    def _on_wake(self, did: str, name: str,
                 btn_refs: list, status_lbl: QLabel):
        if not self.upsnap:
            return
        self._active_ops.add(did)
        self._set_btns(btn_refs, False)
        self._set_device_status(status_lbl, "WoL senden...", C["yellow"])
        log(f"WoL -> '{name}'")

        def work():
            try:
                self.upsnap.wake(did)
                self.sig.device_status_signal.emit(status_lbl, "Einschalten...", C["orange"])
                self._notify("Wake-on-LAN", f"'{name}' wird aufgeweckt...")
                time.sleep(3)
                self.sig.device_status_signal.emit(status_lbl, "Offline", C["dim"])
                self.sig.btns_state_signal.emit(btn_refs, True)
            finally:
                self._active_ops.discard(did)
        threading.Thread(target=work, daemon=True).start()

    def _on_rdp_with_user(self, ip: str, name: str,
                           btn_refs: list = None, status_lbl: QLabel = None):
        """RDP mit optionalem Benutzernamen- und Passwort-Dialog."""
        user, pw = self._ask_rdp_credentials(name)
        self._on_rdp(ip, name, btn_refs, status_lbl, username=user, password=pw)

    def _on_rdp(self, ip: str, name: str,
                btn_refs: list = None, status_lbl: QLabel = None,
                username: Optional[str] = None, password: Optional[str] = None):
        log(f"RDP -> '{name}' ({ip})")
        if btn_refs:
            self._set_btns(btn_refs, False)
        if status_lbl:
            self._set_device_status(status_lbl, "RDP starten...", C["cyan"])
        try:
            # Credentials via cmdkey hinterlegen (ermöglicht automatisches Login)
            if username and password:
                try:
                    _run_silent(
                        ["cmdkey", f"/add:{ip}", f"/user:{username}", f"/pass:{password}"],
                        capture_output=True, timeout=10)
                    log(f"RDP: Credentials für {ip} hinterlegt.")
                except Exception as e:
                    log(f"cmdkey Fehler: {e}", "warning")

            rdp_path = os.path.join(
                os.environ.get("TEMP", _base_dir), f"_vpn_{name}.rdp")
            with open(rdp_path, "w") as f:
                f.write(f"full address:s:{ip}\n")
                # Kein Credential-Prompt wenn cmdkey gesetzt
                f.write(f"prompt for credentials:i:{'0' if (username and password) else '1'}\n")
                f.write("authentication level:i:0\n")
                if username:
                    f.write(f"username:s:{username}\n")
            subprocess.Popen(["explorer.exe", rdp_path])
            log(f"RDP gestartet: {rdp_path}")
            if status_lbl:
                QTimer.singleShot(2000, lambda: self.sig.device_status_signal.emit(
                    status_lbl, "Online", C["green"]))

            def _del():
                time.sleep(8)
                try:
                    os.remove(rdp_path)
                    log(f"Temp-RDP gelöscht: {rdp_path}")
                except OSError:
                    pass
                # cmdkey-Eintrag nach 10s wieder entfernen
                if username and password:
                    time.sleep(2)
                    try:
                        _run_silent(["cmdkey", f"/delete:{ip}"],
                                    capture_output=True, timeout=10)
                        log(f"RDP: Credentials für {ip} entfernt.")
                    except Exception:
                        pass
            threading.Thread(target=_del, daemon=True).start()
        except Exception as e:
            log(f"RDP Fehler: {e}", "error")
        finally:
            if btn_refs:
                QTimer.singleShot(3000, lambda: self.sig.btns_state_signal.emit(btn_refs, True))

    def _on_wake_rdp(self, did: str, ip: str, name: str,
                     btn_refs: list, status_lbl: QLabel):
        if not self.upsnap:
            return
        # Credentials im Main-Thread abfragen (vor dem Hintergrund-Thread)
        user, pw = self._ask_rdp_credentials(name)
        self._active_ops.add(did)
        self._set_btns(btn_refs, False)
        self._set_device_status(status_lbl, "WoL senden...", C["yellow"])
        log(f"WoL + RDP -> '{name}'")

        def work():
            try:
                self.upsnap.wake(did)
                self.sig.device_status_signal.emit(status_lbl, "Einschalten...", C["orange"])
                log(f"Warte auf '{name}' (max 120s)...")
                t0 = time.time()
                reachable = False
                while time.time() - t0 < 120:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(3)
                        s.connect((ip, 3389))
                        s.close()
                        reachable = True
                        break
                    except (OSError, socket.error):
                        pass
                    elapsed = int(time.time() - t0)
                    self.sig.device_status_signal.emit(
                        status_lbl, f"Warte {elapsed}s...", C["orange"])
                    log(f"  Warte... ({elapsed}s)")
                    time.sleep(2)

                if reachable:
                    log(f"'{name}' bereit!")
                    self.sig.device_status_signal.emit(status_lbl, "Online", C["green"])
                    time.sleep(3)
                    self.sig.trigger_rdp_signal.emit(ip, name, btn_refs, status_lbl,
                                                     user or "", pw or "")
                    return

                log(f"'{name}' nicht erreichbar.", "warning")
                self.sig.device_status_signal.emit(status_lbl, "Timeout", C["red"])
                self.sig.btns_state_signal.emit(btn_refs, True)
                self.sig.ask_rdp_signal.emit(ip, name, btn_refs, status_lbl,
                                              user or "", pw or "")
            finally:
                self._active_ops.discard(did)

        threading.Thread(target=work, daemon=True).start()

    def _ask_rdp_anyway(self, ip, name, btn_refs, status_lbl, user="", pw=""):
        reply = QMessageBox.question(
            self, "Timeout",
            f"'{name}' antwortet nicht.\nRDP trotzdem starten?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._on_rdp(ip, name, btn_refs, status_lbl,
                         username=user or None, password=pw or None)

    # ── Duration Timer ──────────────────────────────────────────────────────

    def _update_duration(self):
        if self._connect_time > 0:
            elapsed = int(time.time() - self._connect_time)
            h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
            self.duration_label.setText(f"{h:02d}:{m:02d}:{s:02d}")
            self.duration_label.setStyleSheet(f"color: {C['green']};")

    # ── Ping ──────────────────────────────────────────────────────────────

    def _ping_tick(self):
        def work():
            try:
                t0 = time.time()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((TARGET_IP, TARGET_PORT))
                s.close()
                ms = int((time.time() - t0) * 1000)
                self.sig.ping_result_signal.emit(f"{ms} ms")
            except Exception:
                self.sig.ping_result_signal.emit("---")
        threading.Thread(target=work, daemon=True).start()

    def _update_ping_label(self, text: str):
        self.ping_label.setText(f"Ping: {text}")
        if text == "---":
            self.ping_label.setStyleSheet(f"color: {C['red']};")
        else:
            try:
                ms = int(text.replace(" ms", ""))
                if ms < 50:
                    self.ping_label.setStyleSheet(f"color: {C['green']};")
                elif ms < 150:
                    self.ping_label.setStyleSheet(f"color: {C['yellow']};")
                else:
                    self.ping_label.setStyleSheet(f"color: {C['orange']};")
            except ValueError:
                self.ping_label.setStyleSheet(f"color: {C['dim']};")

    # ── Transfer-Stats ─────────────────────────────────────────────────────

    def _transfer_tick(self):
        """VPN-Datentransfer im Hintergrund abfragen."""
        if not self.active_config:
            return
        tn = extract_tunnel_name(self.active_config)

        def work():
            try:
                r = _run_silent(
                    ["wg", "show", tn, "transfer"],
                    capture_output=True, text=True, timeout=5)
                if r.returncode != 0 or not r.stdout.strip():
                    return
                # Format: <peer_pubkey>\t<rx_bytes>\t<tx_bytes>
                total_rx, total_tx = 0, 0
                for line in r.stdout.strip().splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 3:
                        total_rx += int(parts[1])
                        total_tx += int(parts[2])
                text = f"↓ {self._format_bytes(total_rx)}  ↑ {self._format_bytes(total_tx)}"
                self.sig.transfer_signal.emit(text)
            except Exception:
                pass
        threading.Thread(target=work, daemon=True).start()

    @staticmethod
    def _format_bytes(b: int) -> str:
        """Bytes in lesbare Einheit formatieren."""
        if b < 1024:
            return f"{b} B"
        elif b < 1024 ** 2:
            return f"{b / 1024:.1f} KB"
        elif b < 1024 ** 3:
            return f"{b / 1024 ** 2:.1f} MB"
        else:
            return f"{b / 1024 ** 3:.2f} GB"

    def _update_transfer_label(self, text: str):
        """Transfer-Stats Label aktualisieren (Main-Thread)."""
        self.transfer_label.setText(text)
        self.transfer_label.show()

    # ── Auto-Login UpSnap ─────────────────────────────────────────────────

    def _try_auto_login(self):
        """Nach VPN-Connect automatisch bei UpSnap anmelden, wenn Credentials vorhanden."""
        if self.upsnap is not None:
            # Bereits eingeloggt → Timer sicherstellen + sofortigen Refresh auslösen
            if not self._auto_refresh_timer.isActive():
                self._start_auto_refresh()
            self._auto_refresh_tick()
            return
        u = self.entry_user.text().strip()
        p = self.entry_pass.text().strip()
        if u and p and self.vpn_connected:
            log("Auto-Login bei UpSnap...")
            self._on_upsnap_login()

    # ── Auto-Reconnect / Watchdog ─────────────────────────────────────────

    def _watchdog_tick(self):
        """Prüft ob der VPN-Tunnel noch läuft."""
        if not self.vpn_connected or not self.active_config:
            return
        tn = extract_tunnel_name(self.active_config)
        state = _service_state(tn)
        if state == "RUNNING":
            self._reconnect_retries = 0
            return
        # Unerwarteter Disconnect
        log("Watchdog: VPN-Verbindung verloren!", "warning")
        self._watchdog_timer.stop()
        self.sig.reconnect_signal.emit()

    def _on_auto_reconnect(self):
        if self._reconnect_retries >= 3:
            log("Auto-Reconnect: Max. Versuche (3) erreicht.", "error")
            self._notify("Auto-Reconnect", "Verbindung konnte nicht wiederhergestellt werden.")
            self._disconnected()
            return
        self._reconnect_retries += 1
        log(f"Auto-Reconnect: Versuch {self._reconnect_retries}/3...")
        self._set_status(f"Reconnect {self._reconnect_retries}/3...", C["orange"])
        self._notify("Auto-Reconnect", f"Verbindung verloren – Versuch {self._reconnect_retries}/3...")
        self._on_connect()

    # ── Benachrichtigungen ────────────────────────────────────────────────

    def _notify(self, title: str, msg: str):
        """Toast-Benachrichtigung via System-Tray."""
        if hasattr(self, '_tray') and self._tray and self._tray.isVisible():
            self._tray.showMessage(title, msg,
                                   QSystemTrayIcon.MessageIcon.Information, 3000)

    # ── VPN-IP ────────────────────────────────────────────────────────────

    def _fetch_vpn_ip(self, tunnel_name: str):
        """VPN-Tunnel-IP im Hintergrund ermitteln."""
        try:
            r = _run_silent(
                ["netsh", "interface", "ip", "show", "address", tunnel_name],
                capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                line = line.strip()
                if "IP-Adresse" in line or "IP Address" in line:
                    ip = line.split(":")[-1].strip()
                    if ip:
                        self.sig.vpn_ip_signal.emit(ip)
                        return
        except Exception:
            pass
        self.sig.vpn_ip_signal.emit("")

    def _update_ip_label(self, ip: str):
        if ip:
            self.vpn_ip_label.setText(f"IP: {ip}")
            self.vpn_ip_label.show()
        else:
            self.vpn_ip_label.hide()

    # ── Verbindungshistorie ───────────────────────────────────────────────

    def _add_history_entry(self, config: str, start_ts: float, duration_s: int):
        """Verbindung in den Verlauf eintragen."""
        import datetime
        entry = {
            "config": config,
            "start": datetime.datetime.fromtimestamp(start_ts).strftime("%d.%m.%Y %H:%M"),
            "duration_s": duration_s,
        }
        try:
            path = self._CRED_FILE
            data: dict = {}
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            hist = data.get("history", [])
            hist.insert(0, entry)
            data["history"] = hist[:20]  # max 20 Einträge
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            self.sig.history_updated_signal.emit()
        except Exception:
            pass

    def _toggle_history(self):
        if self._history_visible:
            self.history_frame.hide()
            self.history_toggle.setText("[+] Verbindungshistorie")
            self._history_visible = False
        else:
            self.history_frame.show()
            self.history_toggle.setText("[-] Verbindungshistorie")
            self._history_visible = True
            self._refresh_history_ui()

    def _refresh_history_ui(self):
        """History-Liste neu aufbauen."""
        # Alte Widgets entfernen
        while self.history_list_layout.count():
            w = self.history_list_layout.takeAt(0).widget()
            if w:
                w.deleteLater()
        try:
            if not os.path.exists(self._CRED_FILE):
                return
            with open(self._CRED_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            hist = data.get("history", [])
            if not hist:
                lbl = QLabel("Kein Verlauf vorhanden.")
                lbl.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
                self.history_list_layout.addWidget(lbl)
                return
            for entry in hist:
                d = entry.get("duration_s", 0)
                h, m, s = d // 3600, (d % 3600) // 60, d % 60
                dur_str = f"{h:02d}:{m:02d}:{s:02d}"
                text = f"{entry.get('start','?')}  •  {entry.get('config','?')}  •  {dur_str}"
                row = QLabel(text)
                row.setStyleSheet(f"color: {C['dim']}; font-size: 9pt; padding: 2px 4px;")
                self.history_list_layout.addWidget(row)
        except Exception:
            pass

    def _clear_history(self):
        try:
            if os.path.exists(self._CRED_FILE):
                with open(self._CRED_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data["history"] = []
                with open(self._CRED_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            self._refresh_history_ui()
        except Exception:
            pass

    # ── Favoriten ─────────────────────────────────────────────────────────

    def _load_favorites_and_rdp_users(self):
        """Favoriten und RDP-Benutzernamen aus Settings laden."""
        try:
            if os.path.exists(self._CRED_FILE):
                with open(self._CRED_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._favorites = data.get("favorites", [])
                self._rdp_users = data.get("rdp_users", {})
        except Exception:
            pass

    def _toggle_favorite(self, device_id: str, star_btn: QPushButton):
        if device_id in self._favorites:
            self._favorites.remove(device_id)
            star_btn.setText("☆")
            star_btn.setStyleSheet(star_btn.styleSheet().replace(
                C["yellow"], C["dim"]).replace(C["orange"], C["dim"]))
        else:
            self._favorites.append(device_id)
            star_btn.setText("★")
            star_btn.setStyleSheet(star_btn.styleSheet().replace(
                C["dim"], C["yellow"]))
        self._save_favorites()

    # ── RDP-Credentials Dialog ────────────────────────────────────────────

    def _ask_rdp_credentials(self, device_name: str) -> tuple:
        """Dialog zum Eingeben/Bestätigen von Benutzername und Passwort für RDP.
        Gibt (username, password) zurück. Beide können None sein."""
        saved_user = self._rdp_users.get(device_name, "")
        saved_pw_b64 = self._rdp_passwords.get(device_name, "")
        saved_pw = ""
        if saved_pw_b64:
            try:
                saved_pw = base64.b64decode(saved_pw_b64.encode("ascii")).decode("utf-8")
            except Exception:
                saved_pw = ""

        dlg = QDialog(self)
        dlg.setWindowTitle(f"RDP – {device_name}")
        dlg.setStyleSheet(f"background-color: {C['card']}; color: {C['fg']};")
        layout = QFormLayout(dlg)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        user_edit = QLineEdit(saved_user)
        user_edit.setPlaceholderText("domain\\benutzername oder benutzername")
        user_edit.setStyleSheet(f"""
            QLineEdit {{
                background: {C['surface']}; color: {C['fg']};
                border: 1px solid {C['border']}; border-radius: 4px; padding: 5px 8px;
            }}
        """)
        layout.addRow(QLabel("Benutzername:"), user_edit)

        pw_edit = QLineEdit(saved_pw)
        pw_edit.setPlaceholderText("Passwort (optional)")
        pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
        pw_edit.setStyleSheet(user_edit.styleSheet())
        layout.addRow(QLabel("Passwort:"), pw_edit)

        chk_save = QCheckBox("Zugangsdaten merken")
        chk_save.setChecked(bool(saved_user or saved_pw))
        chk_save.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
        layout.addRow("", chk_save)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Ok).setStyleSheet(
            f"background: {C['accent']}; color: #fff; border-radius: 4px; padding: 6px 14px;")
        btns.button(QDialogButtonBox.StandardButton.Cancel).setStyleSheet(
            f"background: {C['surface']}; color: {C['fg']}; border-radius: 4px; padding: 6px 14px;")
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        layout.addRow(btns)

        if dlg.exec() != QDialog.DialogCode.Accepted:
            return None, None

        user = user_edit.text().strip()
        pw = pw_edit.text()   # Passwort nicht strippen (Leerzeichen erlaubt)

        if chk_save.isChecked():
            if user:
                self._rdp_users[device_name] = user
            elif device_name in self._rdp_users:
                del self._rdp_users[device_name]
            if pw:
                self._rdp_passwords[device_name] = base64.b64encode(
                    pw.encode("utf-8")).decode("ascii")
            elif device_name in self._rdp_passwords:
                del self._rdp_passwords[device_name]
        else:
            # "Merken" abgewählt → gespeicherte Daten löschen
            self._rdp_users.pop(device_name, None)
            self._rdp_passwords.pop(device_name, None)

        self._save_favorites()
        return user or None, pw or None

    # ── System Tray ───────────────────────────────────────────────────────

    def _setup_tray(self):
        """System-Tray-Icon mit Kontextmenü einrichten."""
        # Einfaches Icon generieren (farbiges Quadrat)
        px = QPixmap(64, 64)
        px.fill(QColor(C["accent"]))
        icon = QIcon(px)

        self._tray = QSystemTrayIcon(icon, self)
        self._tray.setToolTip("VPN Connect - Getrennt")

        menu = QMenu()
        act_show = QAction("Anzeigen", self)
        act_show.triggered.connect(self._tray_show)
        menu.addAction(act_show)

        menu.addSeparator()

        self._tray_act_toggle = QAction("Verbinden", self)
        self._tray_act_toggle.triggered.connect(self._tray_toggle_vpn)
        menu.addAction(self._tray_act_toggle)

        menu.addSeparator()

        act_quit = QAction("Beenden", self)
        act_quit.triggered.connect(self._tray_quit)
        menu.addAction(act_quit)

        self._tray.setContextMenu(menu)
        self._tray.activated.connect(self._tray_activated)
        self._tray.show()

    def _tray_show(self):
        self.showNormal()
        self.activateWindow()

    def _tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._tray_show()

    def _tray_toggle_vpn(self):
        if self.vpn_connected:
            self._on_disconnect()
            self._tray_act_toggle.setText("Verbinden")
        else:
            self._on_connect()
            self._tray_act_toggle.setText("Trennen")

    def _tray_quit(self):
        """Wirklich beenden (über Tray)."""
        global _active_config
        self._watchdog_timer.stop()   # kein Auto-Reconnect beim Beenden
        self._reconnect_retries = 0
        if self.active_config:
            disconnect_vpn(self.active_config)
        _active_config = None
        self.active_config = None
        self._stop_auto_refresh()
        self._save_settings()
        _cleanup_temp_rdp()
        if self._tray:
            self._tray.hide()
        QApplication.quit()

    # ── Close Event ────────────────────────────────────────────────────────

    def closeEvent(self, event):
        # Bei verbundenem VPN: In Tray minimieren statt schließen
        if self.vpn_connected and self._tray and self._tray.isVisible():
            self._save_settings()       # ← Settings sofort sichern vor dem Verstecken
            self.hide()
            self._tray.showMessage(
                "VPN Connect",
                "App läuft im Hintergrund weiter.\nDoppelklick auf Tray-Icon zum Öffnen.",
                QSystemTrayIcon.MessageIcon.Information, 3000)
            event.ignore()
            return

        global _active_config
        if self.active_config:
            reply = QMessageBox.question(
                self, "Beenden",
                "VPN ist verbunden.\nTrennen und beenden?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self._watchdog_timer.stop()   # kein Auto-Reconnect beim Beenden
            self._reconnect_retries = 0
            disconnect_vpn(self.active_config)
        _active_config = None
        self.active_config = None
        self._stop_auto_refresh()
        self._save_settings()
        _cleanup_temp_rdp()
        if self._tray:
            self._tray.hide()
        event.accept()


# =============================================================================
#  MAIN
# =============================================================================

def main():
    global _app

    # Immer beim Start aufräumen – löscht .old-Datei von vorherigem Update
    _cleanup_old_exe()

    if not is_admin():
        run_as_admin()
        sys.exit()

    app = QApplication(sys.argv)
    app.setStyleSheet(GLOBAL_QSS)
    app.setStyle("Fusion")

    _app = VPNApp()
    _app.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()

