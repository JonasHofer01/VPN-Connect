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
from typing import Optional, List, Tuple
from urllib import request, error

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QListWidget, QFrame,
    QScrollArea, QTextEdit, QMessageBox,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor, QPainter

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
    enable_refresh_signal = pyqtSignal()
    enable_login_signal = pyqtSignal()
    logged_in_signal = pyqtSignal()
    update_available_signal = pyqtSignal(dict)
    update_progress_signal = pyqtSignal(str)
    update_failed_signal = pyqtSignal()
    apply_update_signal = pyqtSignal(str)
    device_status_signal = pyqtSignal(object, str, str)  # label, text, color
    btns_state_signal = pyqtSignal(list, bool)            # btn_refs, enabled
    trigger_rdp_signal = pyqtSignal(str, str, list, object)  # ip, name, btns, lbl
    ask_rdp_signal = pyqtSignal(str, str, list, object)


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

        self.configs: List[Tuple[str, str]] = []
        self.active_config: Optional[str] = None
        self.vpn_connected = False
        self.upsnap: Optional[UpSnapClient] = None
        self._device_widgets: List[QWidget] = []
        self._log_visible = False
        self._update_info: Optional[dict] = None

        # Signale
        self.sig = AppSignals()
        self._connect_signals()

        # Auto-Refresh Timer
        self._auto_refresh_timer = QTimer(self)
        self._auto_refresh_timer.setInterval(30_000)
        self._auto_refresh_timer.timeout.connect(self._auto_refresh_tick)

        self._build_ui()
        self._load_configs()
        self._load_credentials()

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
        self.sig.enable_refresh_signal.connect(
            lambda: self.btn_refresh_devices.setEnabled(True))
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
            lambda ip, name, bl, sl: self._on_rdp(ip, name, bl, sl))
        self.sig.ask_rdp_signal.connect(self._ask_rdp_anyway)

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
        main_layout.addWidget(wg_card)
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
        login_row.addWidget(self.entry_user)

        login_row.addSpacing(6)

        self.lbl_pw = QLabel("Passwort")
        self.lbl_pw.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
        login_row.addWidget(self.lbl_pw)
        self.entry_pass = QLineEdit()
        self.entry_pass.setFixedWidth(140)
        self.entry_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.entry_pass.returnPressed.connect(self._on_upsnap_login)
        login_row.addWidget(self.entry_pass)

        login_row.addSpacing(6)

        self.btn_login = _make_btn("Anmelden", C["accent"], "#ffffff", C["accent_h"])
        self.btn_login.clicked.connect(self._on_upsnap_login)
        login_row.addWidget(self.btn_login)

        self.btn_refresh_devices = _make_btn("Aktualisieren", C["surface"], C["fg"], C["border"])
        self.btn_refresh_devices.setStyleSheet(
            self.btn_refresh_devices.styleSheet().replace("font-weight: bold;", "font-weight: normal;"))
        self.btn_refresh_devices.clicked.connect(self._on_refresh_devices)
        self.btn_refresh_devices.setEnabled(False)
        login_row.addWidget(self.btn_refresh_devices)

        login_row.addStretch()
        snap_layout.addLayout(login_row)

        # Separator
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {C['border']};")
        snap_layout.addWidget(sep)

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

        main_layout.addStretch()

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

    # ── VPN Disconnect ─────────────────────────────────────────────────────

    def _on_disconnect(self):
        global _active_config
        self.btn_disconnect.setEnabled(False)
        self._set_status("Trenne...", C["yellow"])

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

    # ── Credentials ────────────────────────────────────────────────────────

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
                self.entry_user.setText(d.get("user", ""))
                self.entry_pass.setText(d.get("pw", ""))
        except Exception:
            pass

    # ── Auto-Refresh ───────────────────────────────────────────────────────

    def _start_auto_refresh(self):
        self._auto_refresh_timer.start()

    def _stop_auto_refresh(self):
        self._auto_refresh_timer.stop()

    def _auto_refresh_tick(self):
        if self.upsnap and self.vpn_connected:
            def work():
                try:
                    devs = self.upsnap.get_devices()
                    self.sig.show_devices_signal.emit(devs)
                except Exception:
                    pass
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
                    self.sig.enable_refresh_signal.emit()
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

        # Geräte-Widgets entfernen
        for w in self._device_widgets:
            w.setParent(None)
            w.deleteLater()
        self._device_widgets.clear()
        self.upsnap_hint.show()

        # UI zurücksetzen
        self.btn_login.setText("Anmelden")
        self.lbl_email.show()
        self.entry_user.show()
        self.lbl_pw.show()
        self.entry_pass.show()
        self.btn_refresh_devices.setEnabled(False)
        log("UpSnap abgemeldet.")

    def _on_refresh_devices(self):
        if not self.upsnap:
            return
        self.btn_refresh_devices.setEnabled(False)
        log("Geräteliste wird aktualisiert...")

        def work():
            try:
                devs = self.upsnap.get_devices()
            except Exception as e:
                log(f"Geräteliste Fehler: {e}", "error")
                devs = []
            self.sig.show_devices_signal.emit(devs)
            self.sig.enable_refresh_signal.emit()
        threading.Thread(target=work, daemon=True).start()

    # ── Device-Anzeige ─────────────────────────────────────────────────────

    def _show_devices(self, devices: List[dict]):
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
            return

        for d in devices:
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

            if online:
                b = _make_btn("RDP", C["surface"], C["fg"], C["border"])
                b.setStyleSheet(b.styleSheet().replace(
                    "font-weight: bold;", "font-weight: normal; font-size: 9pt;"))
                b.clicked.connect(
                    lambda checked, x=dip, n=dn, bl=btn_refs, sl=status_lbl:
                    self._on_rdp(x, n, bl, sl))
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
        self._set_btns(btn_refs, False)
        self._set_device_status(status_lbl, "WoL senden...", C["yellow"])
        log(f"WoL -> '{name}'")

        def work():
            self.upsnap.wake(did)
            self.sig.device_status_signal.emit(status_lbl, "Einschalten...", C["orange"])
            QTimer.singleShot(3000, lambda: self.sig.btns_state_signal.emit(btn_refs, True))
            QTimer.singleShot(3000, lambda: self.sig.device_status_signal.emit(
                status_lbl, "Offline", C["dim"]))
        threading.Thread(target=work, daemon=True).start()

    def _on_rdp(self, ip: str, name: str,
                btn_refs: list = None, status_lbl: QLabel = None):
        log(f"RDP -> '{name}' ({ip})")
        if btn_refs:
            self._set_btns(btn_refs, False)
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
                QTimer.singleShot(2000, lambda: self.sig.device_status_signal.emit(
                    status_lbl, "Online", C["green"]))

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
                QTimer.singleShot(3000, lambda: self.sig.btns_state_signal.emit(btn_refs, True))

    def _on_wake_rdp(self, did: str, ip: str, name: str,
                     btn_refs: list, status_lbl: QLabel):
        if not self.upsnap:
            return
        self._set_btns(btn_refs, False)
        self._set_device_status(status_lbl, "WoL senden...", C["yellow"])
        log(f"WoL + RDP -> '{name}'")

        def work():
            self.upsnap.wake(did)
            self.sig.device_status_signal.emit(status_lbl, "Einschalten...", C["orange"])
            log(f"Warte auf '{name}' (max 120s)...")
            t0 = time.time()
            while time.time() - t0 < 120:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((ip, 3389))
                    s.close()
                    log(f"'{name}' bereit!")
                    self.sig.device_status_signal.emit(status_lbl, "Online", C["green"])
                    time.sleep(3)
                    self.sig.trigger_rdp_signal.emit(ip, name, btn_refs, status_lbl)
                    return
                except Exception:
                    pass
                elapsed = int(time.time() - t0)
                self.sig.device_status_signal.emit(
                    status_lbl, f"Warte {elapsed}s...", C["orange"])
                log(f"  Warte... ({elapsed}s)")
                time.sleep(2)

            log(f"'{name}' nicht erreichbar.", "warning")
            self.sig.device_status_signal.emit(status_lbl, "Timeout", C["red"])
            self.sig.btns_state_signal.emit(btn_refs, True)
            self.sig.ask_rdp_signal.emit(ip, name, btn_refs, status_lbl)

        threading.Thread(target=work, daemon=True).start()

    def _ask_rdp_anyway(self, ip, name, btn_refs, status_lbl):
        reply = QMessageBox.question(
            self, "Timeout",
            f"'{name}' antwortet nicht.\nRDP trotzdem starten?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._on_rdp(ip, name, btn_refs, status_lbl)

    # ── Close Event ────────────────────────────────────────────────────────

    def closeEvent(self, event):
        global _active_config
        if self.active_config:
            reply = QMessageBox.question(
                self, "Beenden",
                "VPN ist verbunden.\nTrennen und beenden?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            disconnect_vpn(self.active_config)
        _active_config = None
        self.active_config = None
        self._stop_auto_refresh()
        _cleanup_temp_rdp()
        event.accept()


# =============================================================================
#  MAIN
# =============================================================================

def main():
    global _app

    if "--cleanup" in sys.argv:
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

