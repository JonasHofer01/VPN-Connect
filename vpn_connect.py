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
import logging.handlers
import threading
import base64
import hashlib
import ipaddress
import datetime
import zipfile
import shutil
from typing import Optional, List, Tuple
from urllib import request, error

import ctypes.wintypes as wt

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QListWidget, QFrame,
    QScrollArea, QTextEdit, QMessageBox, QSystemTrayIcon, QMenu,
    QCheckBox, QDialog, QFormLayout, QDialogButtonBox, QComboBox,
    QTabWidget, QSizePolicy,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor, QPainter, QAction, QPixmap, QIcon
from PyQt6.QtGui import QKeySequence, QShortcut

# =============================================================================
#  KONFIGURATION
# =============================================================================

APP_VERSION = "1.9.0"
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

_dpapi_warned = False


def _setup_logging():
    logger = logging.getLogger("vpn_connect")
    logger.setLevel(logging.DEBUG)
    if logger.handlers:
        return logger
    try:
        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    except Exception:
        logging.basicConfig(filename=log_file, level=logging.DEBUG,
                            format="%(asctime)s - %(levelname)s - %(message)s")
        logger = logging.getLogger("vpn_connect")
    logger.propagate = False
    return logger


logger = _setup_logging()

_app: Optional["VPNApp"] = None


def log(msg: str, level: str = "info") -> None:
    getattr(logger, level, logger.info)(msg)
    if _app:
        _app.sig.log_signal.emit(msg)
        if level in ("warning", "error"):
            title = "Warnung" if level == "warning" else "Fehler"
            _app.sig.alert_signal.emit(title, msg, level)


# =============================================================================
#  SECURITY / DPAPI
# =============================================================================

_settings_lock = threading.Lock()


def _dpapi_protect(text: str) -> str:
    """Schuetzt Klartext mit Windows DPAPI und gibt Base64 zurueck."""
    if not text or sys.platform != "win32":
        return ""
    try:
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wt.DWORD),
                        ("pbData", ctypes.POINTER(ctypes.c_byte))]

        data = text.encode("utf-8")
        blob_in = DATA_BLOB(len(data), ctypes.cast(
            ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
        blob_out = DATA_BLOB()

        if ctypes.windll.crypt32.CryptProtectData(
                ctypes.byref(blob_in), None, None, None, None, 0,
                ctypes.byref(blob_out)):
            buf = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return base64.b64encode(buf).decode("ascii")
    except Exception:
        global _dpapi_warned
        if not _dpapi_warned:
            log("DPAPI Schutz fehlgeschlagen – Passwörter werden nicht gespeichert.", "warning")
            _dpapi_warned = True
    return ""


def _dpapi_unprotect(token: str) -> str:
    """Entschluesselt DPAPI-geschuetzten Base64-Blob. Liefert '' bei Fehler."""
    if not token or sys.platform != "win32":
        return ""
    try:
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wt.DWORD),
                        ("pbData", ctypes.POINTER(ctypes.c_byte))]

        raw = base64.b64decode(token.encode("ascii"))
        blob_in = DATA_BLOB(len(raw), ctypes.cast(
            ctypes.create_string_buffer(raw), ctypes.POINTER(ctypes.c_byte)))
        blob_out = DATA_BLOB()
        if ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(blob_in), None, None, None, None, 0,
                ctypes.byref(blob_out)):
            buf = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return buf.decode("utf-8")
    except Exception:
        pass
    return ""


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


def _default_gateway() -> Optional[str]:
    """Best effort Default-Gateway (IPv4) via 'route print'."""
    try:
        r = _run_silent(["route", "print", "0.0.0.0"],
                        capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "0.0.0.0":
                return parts[2]
    except Exception:
        pass
    return None


def _parse_networks(items: List[str]) -> List[ipaddress._BaseNetwork]:
    nets = []
    for item in items:
        try:
            if "/" in item:
                nets.append(ipaddress.ip_network(item, strict=False))
            else:
                nets.append(ipaddress.ip_network(item + "/32", strict=False))
        except Exception:
            continue
    return nets


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
_dismiss_stop = threading.Event()


def _start_dialog_dismisser():
    global _dismiss_running
    if _dismiss_running:
        return
    _dismiss_running = True
    _dismiss_stop.clear()
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

    while not _dismiss_stop.is_set():
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

    _dismiss_stop.clear()
    _dismiss_running = False


def _stop_dialog_dismisser():
    _dismiss_stop.set()


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

        exe_asset = None
        sha_asset = None
        for asset in data.get("assets", []):
            if asset["name"].lower().endswith(".exe"):
                exe_asset = asset
            if any(asset["name"].lower().endswith(suf) for suf in
                   (".sha256", ".sha256.txt", ".sha256sum")):
                sha_asset = asset

        if exe_asset:
            sha_hex = None
            if sha_asset:
                try:
                    sha_hex = _fetch_sha256(sha_asset["browser_download_url"])
                    log("SHA256 aus Release-Asset geladen.")
                except Exception as e:
                    log(f"SHA256 konnte nicht geladen werden: {e}", "warning")

            if not sha_hex:
                log("Kein SHA256-Hash im Release gefunden – Update abgebrochen.", "error")
                return None

            log(f"Update verfügbar: {remote_tag} (aktuell: {APP_VERSION})")
            return {
                "tag": remote_tag,
                "url": exe_asset["browser_download_url"],
                "size": exe_asset.get("size", 0),
                "name": exe_asset["name"],
                "sha": sha_hex,
            }
        else:
            log("Release ohne .exe-Asset.", "warning")
    except error.HTTPError as e:
        if e.code == 404:
            log("Kein Release auf GitHub vorhanden – Update-Check uebersprungen.")
        else:
            log(f"Update-Check fehlgeschlagen: HTTP {e.code}", "warning")
    except Exception as e:
        log(f"Update-Check fehlgeschlagen: {e}", "warning")
    return None


def _fetch_sha256(url: str) -> str:
    """Liest ein SHA256-File und gibt den Hex-String zurück."""
    req = request.Request(url, headers={"User-Agent": "VPN-Connect-Updater"})
    with request.urlopen(req, timeout=10) as resp:
        txt = resp.read().decode("utf-8", errors="ignore")
    first = txt.strip().split()[0]
    if len(first) >= 64 and all(c in "0123456789abcdefABCDEF" for c in first[:64]):
        return first[:64].lower()
    raise ValueError("Kein gültiger SHA256-Hash gefunden.")


def download_update(url: str, dest: str, progress_cb=None,
                    expected_size: int = 0, expected_sha: Optional[str] = None) -> bool:
    try:
        req = request.Request(url, headers={"User-Agent": "VPN-Connect-Updater"})
        with request.urlopen(req, timeout=60) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            done = 0
            hasher = hashlib.sha256()
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    done += len(chunk)
                    hasher.update(chunk)
                    if progress_cb:
                        progress_cb(done, total)
        if expected_size and done != expected_size:
            log(f"Download-Größe stimmt nicht ({done} != {expected_size})", "error")
            os.remove(dest)
            return False

        file_sha = hasher.hexdigest()
        if expected_sha and file_sha.lower() != expected_sha.lower():
            log(f"SHA256 stimmt nicht überein (erwartet {expected_sha}, erhalten {file_sha})", "error")
            os.remove(dest)
            return False
        if expected_sha is None:
            log("Kein Hash angegeben – Sicherheitscheck schlägt fehl.", "error")
            os.remove(dest)
            return False

        log(f"Download abgeschlossen: {dest} (SHA256 {file_sha})")
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
    if not os.path.exists(new_exe):
        log(f"Update-Datei fehlt: {new_exe}", "error")
        return

    # Signatur prüfen
    try:
        r = _run_silent(["signtool", "verify", "/pa", new_exe],
                        capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            log(f"Signaturprüfung fehlgeschlagen: {r.stdout or r.stderr}", "error")
            return
        log("Signaturprüfung erfolgreich.")
    except Exception as e:
        log(f"Signaturprüfung konnte nicht ausgeführt werden: {e}", "error")
        return

    current = sys.executable
    backup = current + ".old"
    pid = os.getpid()

    # Hilfsskript schreiben, das nach Prozessende ersetzt
    temp_dir = os.environ.get("TEMP", _base_dir)
    updater_ps1 = os.path.join(temp_dir, "_vpn_updater.ps1")

    script = """$ErrorActionPreference = "Stop"
$current = "{current}"
$new = "{new}"
$backup = "{backup}"
$pid = {pid}

try {{
    Wait-Process -Id $pid -Timeout 30 -ErrorAction SilentlyContinue
}} catch {{ }}

function Wait-ForUnlock($path, $retries) {{
    for ($i=0; $i -lt $retries; $i++) {{
        try {{
            $fs = [System.IO.File]::Open($path, 'Open', 'ReadWrite', 'None')
            $fs.Close()
            return $true
        }} catch {{
            Start-Sleep -Milliseconds 500
        }}
    }}
    return $false
}}

if (Test-Path $backup) {{ Remove-Item $backup -Force -ErrorAction SilentlyContinue }}

if (-not (Wait-ForUnlock $current 40)) {{ Write-Host "Datei gesperrt"; exit 1 }}

Move-Item -Force $current $backup
Move-Item -Force $new $current

Start-Process $current "--cleanup"
Remove-Item $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
""".format(current=current, new=new_exe, backup=backup, pid=pid)
    try:
        with open(updater_ps1, "w", encoding="utf-8") as f:
            f.write(script)
        log(f"Updater-Skript geschrieben: {updater_ps1}")
        # Start PowerShell Helper im Hintergrund
        subprocess.Popen(["powershell", "-ExecutionPolicy", "Bypass",
                          "-File", updater_ps1],
                         creationflags=CREATE_NO_WINDOW)
        log("Updater gestartet, Anwendung wird beendet...")
        sys.exit(0)
    except Exception as e:
        log(f"Update-Installation fehlgeschlagen: {e}", "error")


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
#  FARBSCHEMA  –  Windows 11 Fluent Design (Dark)
# =============================================================================

C = {
    # Hintergründe (Layering) – tiefer Blauton mit Kontrast
    "bg":        "#0f172a",
    "card":      "#111827",
    "surface":   "#1f2937",
    "surface_h": "#253248",
    # Rahmen
    "border":    "#233043",
    "border_l":  "#2f3f55",
    # Text
    "fg":        "#e5ecf5",
    "dim":       "#94a3b8",
    # Akzent (Cyan/Teal)
    "accent":    "#22d3ee",
    "accent_h":  "#67e8f9",
    # Semantische Farben
    "green":     "#34d399",
    "red":       "#f87171",
    "yellow":    "#fbbf24",
    "orange":    "#fb923c",
    "cyan":      "#22d3ee",
}

# =============================================================================
#  GLOBAL STYLESHEET
# =============================================================================

GLOBAL_QSS = f"""
QMainWindow {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #0b1222, stop:0.5 #0f172a, stop:1 #0b1a33);
}}
QWidget {{
    color: {C['fg']};
    font-family: 'Segoe UI Variable Text', 'Segoe UI';
    font-size: 10pt;
    background-color: transparent;
}}
QScrollArea {{
    background-color: {C['bg']};
    border: none;
}}
/* Scrollbar – Win11-Stil: schmal, transparent */
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 2px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: rgba(255,255,255,0.18);
    min-height: 30px;
    border-radius: 5px;
}}
QScrollBar::handle:vertical:hover {{
    background: rgba(255,255,255,0.32);
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}
QLabel {{
    background: transparent;
}}
/* Eingabefelder */
QLineEdit {{
    background-color: {C['surface']};
    color: {C['fg']};
    border: 1px solid {C['border']};
    border-radius: 4px;
    padding: 6px 10px;
    selection-background-color: {C['accent']};
    selection-color: #000000;
}}
QLineEdit:hover {{
    border: 1px solid {C['border_l']};
    background-color: {C['surface_h']};
}}
QLineEdit:focus {{
    border: 1px solid {C['accent']};
    background-color: {C['surface_h']};
}}
QLineEdit::placeholder {{
    color: {C['dim']};
}}
/* Listen */
QListWidget {{
    background-color: {C['surface']};
    color: {C['fg']};
    border: 1px solid {C['border']};
    border-radius: 4px;
    padding: 2px;
    outline: none;
}}
QListWidget::item {{
    padding: 6px 10px;
    border-radius: 3px;
}}
QListWidget::item:selected {{
    background-color: rgba(34,211,238,0.20);
    color: {C['fg']};
    border-left: 2px solid {C['accent']};
}}
QListWidget::item:hover:!selected {{
    background-color: rgba(255,255,255,0.06);
}}
/* Log-Textfeld */
QTextEdit {{
    background-color: {C['card']};
    color: {C['dim']};
    border: 1px solid {C['border']};
    border-radius: 4px;
    padding: 6px;
    font-family: 'Cascadia Code', 'Consolas';
    font-size: 9pt;
    selection-background-color: {C['accent']};
    selection-color: #000000;
}}
/* Schaltflächen (Basis – wird meist durch _make_btn überschrieben) */
QPushButton {{
    border: 1px solid {C['border']};
    border-radius: 7px;
    padding: 9px 16px;
    font-size: 9pt;
    font-family: 'Segoe UI Variable Text', 'Segoe UI';
    font-weight: 600;
    background-color: {C['surface']};
    color: {C['fg']};
}}
QPushButton:disabled {{
    background-color: {C['surface']};
    color: rgba(255,255,255,0.36);
    border: 1px solid {C['border']};
}}
/* Checkboxen – Win11-Stil */
QCheckBox {{
    color: {C['fg']};
    font-size: 9pt;
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 3px;
    border: 1px solid {C['border_l']};
    background: transparent;
}}
QCheckBox::indicator:hover {{
    border: 1px solid {C['accent']};
    background: rgba(96,205,255,0.08);
}}
QCheckBox::indicator:checked {{
    background-color: {C['accent']};
    border: 1px solid {C['accent']};
    image: none;
}}
QCheckBox::indicator:checked:hover {{
    background-color: {C['accent_h']};
    border: 1px solid {C['accent_h']};
}}
/* Tabs */
QTabWidget::pane {{
    border: 1px solid {C['border']};
    border-radius: 8px;
    top: -1px;
    background: {C['bg']};
}}
QTabBar::tab {{
    background: {C['surface']};
    color: {C['fg']};
    padding: 8px 14px;
    border: 1px solid {C['border']};
    border-bottom: 0px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 2px;
}}
QTabBar::tab:selected {{
    background: {C['card']};
    border: 1px solid {C['border_l']};
    border-bottom: 1px solid {C['card']};
}}
QTabBar::tab:hover {{
    color: {C['accent']};
}}
/* Dialoge */
QDialog {{
    background-color: {C['card']};
}}
QMessageBox {{
    background-color: {C['card']};
}}
QDialogButtonBox QPushButton {{
    min-width: 80px;
}}
/* Menü (Tray) */
QMenu {{
    background-color: {C['card']};
    border: 1px solid {C['border']};
    border-radius: 8px;
    padding: 4px;
}}
QMenu::item {{
    padding: 6px 16px;
    border-radius: 4px;
    color: {C['fg']};
}}
QMenu::item:selected {{
    background-color: rgba(255,255,255,0.08);
}}
QMenu::separator {{
    height: 1px;
    background: {C['border']};
    margin: 4px 8px;
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
    alert_signal = pyqtSignal(str, str, str)           # title, msg, level


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
    """Erstellt einen Win11-Fluent-styled Button."""
    btn = QPushButton(text, parent)
    # Rahmen-Farbe ableiten
    is_accent = bg in (C["accent"], C["accent_h"])
    is_danger  = bg in (C["red"],)
    if is_accent:
        border_col = C["accent_h"]
        pressed_bg = "rgba(96,205,255,0.65)"
    elif is_danger:
        border_col = "#FF8C8C"
        pressed_bg = "rgba(255,107,107,0.55)"
    else:
        border_col = C["border_l"]
        pressed_bg = "rgba(255,255,255,0.04)"
    btn.setStyleSheet(f"""
        QPushButton {{
            background-color: {bg};
            color: {fg};
            border: 1px solid {border_col};
            border-radius: 4px;
            padding: 6px 16px;
            font-weight: 600;
            font-size: 9pt;
        }}
        QPushButton:hover {{
            background-color: {hover};
            border: 1px solid {hover};
        }}
        QPushButton:pressed {{
            background-color: {pressed_bg};
        }}
        QPushButton:disabled {{
            background-color: {C['surface']};
            color: rgba(255,255,255,0.36);
            border: 1px solid {C['border']};
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
        self._last_target_ip: str = TARGET_IP
        self._last_target_port: int = TARGET_PORT
        self._local_ping_tasks: set = set()
        self._split_excludes: List[str] = []    # CIDR/IP/Domain
        self._schedule_enable: bool = False
        self._schedule_connect: str = ""
        self._schedule_disconnect: str = ""
        self._last_schedule_day: str = ""
        self._did_sched_connect: bool = False
        self._did_sched_disconnect: bool = False
        self._bw_threshold_mb: int = 0
        self._bw_alerted: bool = False
        self._http_check_url: str = ""
        self._routes_added: List[str] = []
        self._session_rx: int = 0
        self._session_tx: int = 0
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
        self._schedule_timer = QTimer(self)
        self._schedule_timer.setInterval(30_000)
        self._schedule_timer.timeout.connect(self._schedule_tick)

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
        self._schedule_timer = QTimer(self)
        self._schedule_timer.setInterval(30_000)
        self._schedule_timer.timeout.connect(self._schedule_tick)

        self._loading = True          # blockiert _save_settings während gesamter Initialisierung
        self._build_ui()
        self._setup_tray()
        self._load_configs()
        self._load_credentials()      # setzt _loading=False am Ende selbst
        self._schedule_timer.start()

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
        self.sig.device_status_signal.connect(self._set_device_status)
        self.sig.btns_state_signal.connect(self._set_btns)
        self.sig.trigger_rdp_signal.connect(
            lambda ip, name, bl, sl, u, pw: self._on_rdp(ip, name, bl, sl, username=u, password=pw))
        self.sig.ask_rdp_signal.connect(self._ask_rdp_anyway)
        self.sig.ping_result_signal.connect(self._update_ping_label)
        self.sig.reconnect_signal.connect(self._on_auto_reconnect)
        self.sig.auto_login_signal.connect(self._try_auto_login)
        self.sig.vpn_ip_signal.connect(self._update_ip_label)
        self.sig.history_updated_signal.connect(self._refresh_history_ui)
        self.sig.transfer_signal.connect(self._update_transfer_label)
        self.sig.status_signal.connect(lambda t, c: self._update_window_title())
        self.sig.alert_signal.connect(self._on_alert)
        self._schedule_timer.start()

    # ── Layout ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        pad = 24

        # Zentrales Widget mit Scroll-Bereich
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.setCentralWidget(scroll)

        outer = QWidget()
        outer.setStyleSheet(f"background-color: {C['bg']};")
        scroll.setWidget(outer)
        main_layout = QVBoxLayout(outer)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(8)

        # ── Header ──
        hdr = QHBoxLayout()
        hdr.setContentsMargins(0, 0, 0, 10)

        title = QLabel("VPN Connect")
        title.setFont(QFont("Segoe UI Variable Display", 22, QFont.Weight.DemiBold))
        title.setStyleSheet(f"color: {C['fg']}; letter-spacing: -0.5px;")
        hdr.addWidget(title)

        subtitle = QLabel("WireGuard · UpSnap · RDP")
        subtitle.setStyleSheet(f"color: {C['dim']}; font-size: 10pt; letter-spacing: 0.2px;")
        hdr.addWidget(subtitle)
        hdr.setSpacing(12)

        # Update-Button (initial versteckt)
        self.btn_update = _make_btn("↑  Update verfügbar", C["green"], "#000000", "#8fdf81")
        self.btn_update.clicked.connect(self._on_update)
        self.btn_update.hide()
        hdr.addWidget(self.btn_update)

        hdr.addStretch()

        # Duration Label
        self.duration_label = QLabel("")
        self.duration_label.setFont(QFont("Segoe UI Variable Text", 9))
        self.duration_label.setStyleSheet(f"color: {C['dim']};")
        self.duration_label.hide()
        hdr.addWidget(self.duration_label)
        hdr.addSpacing(12)

        # Ping Label
        self.ping_label = QLabel("")
        self.ping_label.setFont(QFont("Cascadia Code", 9))
        self.ping_label.setStyleSheet(f"color: {C['dim']};")
        self.ping_label.hide()
        hdr.addWidget(self.ping_label)
        hdr.addSpacing(14)

        # VPN-IP Label
        self.vpn_ip_label = QLabel("")
        self.vpn_ip_label.setFont(QFont("Cascadia Code", 9))
        self.vpn_ip_label.setStyleSheet(f"color: {C['accent']};")
        self.vpn_ip_label.setToolTip("VPN-Tunnel IP-Adresse")
        self.vpn_ip_label.hide()
        hdr.addWidget(self.vpn_ip_label)
        hdr.addSpacing(14)

        # Transfer-Stats Label
        self.transfer_label = QLabel("")
        self.transfer_label.setFont(QFont("Cascadia Code", 9))
        self.transfer_label.setStyleSheet(f"color: {C['dim']};")
        self.transfer_label.setToolTip("VPN Datentransfer")
        self.transfer_label.hide()
        hdr.addWidget(self.transfer_label)
        hdr.addSpacing(14)

        # Status-Badge
        status_box = QHBoxLayout()
        status_box.setSpacing(7)
        self.status_dot = DotWidget(C["red"], size=10)
        status_box.addWidget(self.status_dot)
        self.status_label = QLabel("Getrennt")
        self.status_label.setFont(QFont("Segoe UI Variable Text", 10, QFont.Weight.Medium))
        self.status_label.setStyleSheet(f"color: {C['red']};")
        status_box.addWidget(self.status_label)
        hdr.addLayout(status_box)

        main_layout.addLayout(hdr)

        # Tabs
        tabs = QTabWidget()
        tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {C['border']};
                border-radius: 8px;
                background: {C['bg']};
            }}
            QTabBar::tab {{
                background: {C['surface']};
                color: {C['fg']};
                padding: 8px 14px;
                border: 1px solid {C['border']};
                border-bottom: 0px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background: {C['card']};
                color: {C['fg']};
                border: 1px solid {C['border_l']};
                border-bottom: 1px solid {C['card']};
            }}
        """)
        main_layout.addWidget(tabs)

        # Haupt-Tab
        main_tab = QWidget()
        main_tab_layout = QVBoxLayout(main_tab)
        main_tab_layout.setContentsMargins(8, 10, 8, 10)
        main_tab_layout.setSpacing(8)

        # ── WireGuard Sektion ──
        main_tab_layout.addWidget(self._section_label("WireGuard"))
        wg_card = QFrame()
        wg_card.setStyleSheet(f"""
            QFrame {{
                background-color: {C['card']};
                border: 1px solid {C['border']};
                border-radius: 8px;
            }}
        """)
        wg_card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        wg_card.setMaximumHeight(100)
        wg_layout = QVBoxLayout(wg_card)
        wg_layout.setContentsMargins(10, 8, 10, 8)
        wg_layout.setSpacing(6)

        self.config_listbox = QListWidget()
        self.config_listbox.setMaximumHeight(50)
        self.config_listbox.itemDoubleClicked.connect(
            lambda: self._on_connect() if not self.vpn_connected else None)
        self.config_listbox.currentRowChanged.connect(lambda: self._schedule_save())
        wg_layout.addWidget(self.config_listbox)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        btn_row.setContentsMargins(0, 2, 0, 0)

        self.btn_connect = _make_btn("  Verbinden", C["accent"], "#000000", C["accent_h"])
        self.btn_connect.clicked.connect(self._on_connect)
        btn_row.addWidget(self.btn_connect)

        self.btn_disconnect = _make_btn("  Trennen", C["red"], "#ffffff", "#FF8C8C")
        self.btn_disconnect.clicked.connect(self._on_disconnect)
        self.btn_disconnect.setEnabled(False)
        btn_row.addWidget(self.btn_disconnect)

        self.btn_cancel = _make_btn("  Abbrechen", C["surface"], C["fg"], C["surface_h"])
        self.btn_cancel.clicked.connect(self._on_cancel)
        self.btn_cancel.hide()
        btn_row.addWidget(self.btn_cancel)

        self.btn_browser = _make_btn("  Im Browser öffnen", C["surface"], C["fg"], C["surface_h"])
        self.btn_browser.clicked.connect(self._on_open_browser)
        self.btn_browser.setEnabled(False)
        btn_row.addWidget(self.btn_browser)

        btn_row.addStretch()
        wg_layout.addLayout(btn_row)

        chk_qss = f"""
            QCheckBox {{ color: {C['dim']}; font-size: 9pt; spacing: 8px; }}
            QCheckBox::indicator {{
                width: 16px; height: 16px; border-radius: 3px;
                border: 1px solid {C['border_l']}; background: transparent;
            }}
            QCheckBox::indicator:hover {{
                border: 1px solid {C['accent']}; background: rgba(96,205,255,0.08);
            }}
            QCheckBox::indicator:checked {{
                background: {C['accent']}; border: 1px solid {C['accent']};
            }}
        """

        # (Checkboxen jetzt im Einstellungen-Tab)

        main_tab_layout.addWidget(wg_card)

        # ── UpSnap / Wake on LAN ──
        main_tab_layout.addWidget(self._section_label("UpSnap  ·  Wake on LAN"))

        snap_card = QFrame()
        snap_card.setStyleSheet(f"""
            QFrame {{
                background-color: {C['card']};
                border: 1px solid {C['border']};
                border-radius: 8px;
            }}
        """)
        snap_layout = QVBoxLayout(snap_card)
        snap_layout.setContentsMargins(16, 14, 16, 14)
        snap_layout.setSpacing(10)

        login_row = QHBoxLayout()
        login_row.setSpacing(8)

        self.lbl_email = QLabel("E-Mail")
        self.lbl_email.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
        login_row.addWidget(self.lbl_email)
        self.entry_user = QLineEdit()
        self.entry_user.setFixedWidth(190)
        self.entry_user.returnPressed.connect(lambda: self.entry_pass.setFocus())
        self.entry_user.editingFinished.connect(lambda: self._schedule_save())
        login_row.addWidget(self.entry_user)

        login_row.addSpacing(8)

        self.lbl_pw = QLabel("Passwort")
        self.lbl_pw.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
        login_row.addWidget(self.lbl_pw)
        self.entry_pass = QLineEdit()
        self.entry_pass.setFixedWidth(150)
        self.entry_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.entry_pass.returnPressed.connect(self._on_upsnap_login)
        self.entry_pass.editingFinished.connect(lambda: self._schedule_save())
        login_row.addWidget(self.entry_pass)

        login_row.addSpacing(8)

        self.btn_login = _make_btn("Anmelden", C["accent"], "#000000", C["accent_h"])
        self.btn_login.clicked.connect(self._on_upsnap_login)
        login_row.addWidget(self.btn_login)

        login_row.addStretch()
        snap_layout.addLayout(login_row)

        # Separator
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {C['border']}; border: none;")
        snap_layout.addWidget(sep)

        # Geräte-Info-Zeile
        self.device_info_label = QLabel("")
        self.device_info_label.setStyleSheet(f"color: {C['dim']}; font-size: 8pt;")
        self.device_info_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.device_info_label.hide()
        snap_layout.addWidget(self.device_info_label)

        # Device-Bereich
        self.device_frame = QVBoxLayout()
        self.device_frame.setSpacing(4)
        self.upsnap_hint = QLabel("Anmelden, um Geräte anzuzeigen")
        self.upsnap_hint.setStyleSheet(f"color: {C['dim']}; font-size: 9pt; padding: 8px 0;")
        self.upsnap_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.device_frame.addWidget(self.upsnap_hint)
        snap_layout.addLayout(self.device_frame)

        main_tab_layout.addWidget(snap_card)
        # etwas Luft am Ende, aber ohne großen Stretch
        main_tab_layout.addSpacing(8)

        # Einstellungen-Tab
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)
        settings_layout.setContentsMargins(12, 16, 12, 16)
        settings_layout.setSpacing(14)

        # Server / Ziel
        settings_layout.addWidget(self._section_label("Server / Ziel"))
        srv_card = QFrame()
        srv_card.setStyleSheet(f"""
            QFrame {{
                background-color: {C['card']};
                border: 1px solid {C['border']};
                border-radius: 8px;
            }}
        """)
        srv_layout = QHBoxLayout(srv_card)
        srv_layout.setContentsMargins(16, 12, 16, 12)
        srv_layout.setSpacing(10)

        lbl_ip = QLabel("IP / Hostname")
        lbl_ip.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
        srv_layout.addWidget(lbl_ip)

        self.entry_target_ip = QLineEdit()
        self.entry_target_ip.setPlaceholderText("z. B. 192.168.1.10")
        self.entry_target_ip.setFixedWidth(190)
        self.entry_target_ip.editingFinished.connect(self._apply_server_settings)
        srv_layout.addWidget(self.entry_target_ip)

        srv_layout.addSpacing(12)

        lbl_port = QLabel("Port")
        lbl_port.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
        srv_layout.addWidget(lbl_port)

        self.entry_target_port = QLineEdit()
        self.entry_target_port.setPlaceholderText("8090")
        self.entry_target_port.setFixedWidth(72)
        self.entry_target_port.editingFinished.connect(self._apply_server_settings)
        srv_layout.addWidget(self.entry_target_port)

        srv_layout.addStretch()
        settings_layout.addWidget(srv_card)

        # Verbindung / Verhalten
        settings_layout.addWidget(self._section_label("Verbindung"))
        conn_card = QFrame()
        conn_card.setStyleSheet(f"""
            QFrame {{
                background-color: {C['card']};
                border: 1px solid {C['border']};
                border-radius: 8px;
            }}
        """)
        conn_layout = QVBoxLayout(conn_card)
        conn_layout.setContentsMargins(16, 12, 16, 12)
        conn_layout.setSpacing(8)

        chk_qss = f"""
            QCheckBox {{ color: {C['dim']}; font-size: 9pt; spacing: 8px; }}
            QCheckBox::indicator {{
                width: 16px; height: 16px; border-radius: 3px;
                border: 1px solid {C['border_l']}; background: transparent;
            }}
            QCheckBox::indicator:hover {{
                border: 1px solid {C['accent']}; background: rgba(96,205,255,0.08);
            }}
            QCheckBox::indicator:checked {{
                background: {C['accent']}; border: 1px solid {C['accent']};
            }}
        """

        self.chk_auto_reconnect = QCheckBox("Auto-Reconnect bei Verbindungsverlust")
        self.chk_auto_reconnect.setStyleSheet(chk_qss)
        self.chk_auto_reconnect.stateChanged.connect(lambda: self._schedule_save())
        conn_layout.addWidget(self.chk_auto_reconnect)

        self.chk_auto_connect = QCheckBox("Automatisch verbinden beim Start")
        self.chk_auto_connect.setStyleSheet(chk_qss)
        self.chk_auto_connect.stateChanged.connect(lambda: self._schedule_save())
        conn_layout.addWidget(self.chk_auto_connect)

        conn_layout.addStretch()
        settings_layout.addWidget(conn_card)

        # RDP Auflösung
        settings_layout.addWidget(self._section_label("RDP-Einstellungen"))
        rdp_card = QFrame()
        rdp_card.setStyleSheet(f"""
            QFrame {{
                background-color: {C['card']};
                border: 1px solid {C['border']};
                border-radius: 8px;
            }}
        """)
        rdp_layout = QHBoxLayout(rdp_card)
        rdp_layout.setContentsMargins(16, 12, 16, 12)
        rdp_layout.setSpacing(12)

        rdp_layout.addWidget(QLabel("Auflösung"))
        self.cmb_rdp_res = QComboBox()
        self.cmb_rdp_res.addItem("Auto", None)
        for w, h in [(1920, 1080), (1600, 900), (1366, 768), (1280, 720)]:
            self.cmb_rdp_res.addItem(f"{w} x {h}", (w, h))
        rdp_layout.addWidget(self.cmb_rdp_res)
        rdp_layout.addStretch()
        settings_layout.addWidget(rdp_card)

        # Log (Protokoll)
        self.log_toggle = QPushButton("›  Protokoll")
        self.log_toggle.setStyleSheet(self._expander_btn_qss())
        self.log_toggle.clicked.connect(self._toggle_log)
        settings_layout.addWidget(self.log_toggle, alignment=Qt.AlignmentFlag.AlignLeft)

        self.log_frame = QFrame()
        self.log_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {C['card']};
                border: 1px solid {C['border']};
                border-radius: 6px;
            }}
        """)
        log_layout = QVBoxLayout(self.log_frame)
        log_layout.setContentsMargins(10, 10, 10, 10)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Cascadia Code", 9))
        self.log_text.setMaximumHeight(220)
        log_layout.addWidget(self.log_text)

        self.log_frame.hide()
        settings_layout.addWidget(self.log_frame)
        settings_layout.addSpacing(6)

        # Verbindungshistorie
        self.history_toggle = QPushButton("›  Verbindungshistorie")
        self.history_toggle.setStyleSheet(self._expander_btn_qss())
        self.history_toggle.clicked.connect(self._toggle_history)
        settings_layout.addWidget(self.history_toggle, alignment=Qt.AlignmentFlag.AlignLeft)

        self.history_frame = QFrame()
        self.history_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {C['card']};
                border: 1px solid {C['border']};
                border-radius: 6px;
            }}
        """)
        hist_layout = QVBoxLayout(self.history_frame)
        hist_layout.setContentsMargins(10, 10, 10, 10)
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
        settings_layout.addWidget(self.history_frame)

        # Split-Tunnel
        settings_layout.addWidget(self._section_label("Split-Tunnel (Bypass)"))
        split_card = QFrame()
        split_card.setStyleSheet(f"""
            QFrame {{
                background-color: {C['card']};
                border: 1px solid {C['border']};
                border-radius: 8px;
            }}
        """)
        split_layout = QVBoxLayout(split_card)
        split_layout.setContentsMargins(16, 12, 16, 12)
        split_layout.setSpacing(8)
        split_info = QLabel("CIDR/IP/Domain pro Zeile, wird vom VPN ausgenommen (Route via Standard-Gateway).")
        split_info.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
        split_layout.addWidget(split_info)
        self.split_text = QTextEdit()
        self.split_text.setPlaceholderText("z.B.\n192.168.100.0/24\n10.0.0.5\nexample.com")
        self.split_text.setFixedHeight(100)
        self.split_text.textChanged.connect(self._on_split_changed)
        split_layout.addWidget(self.split_text)
        settings_layout.addWidget(split_card)

        # Zeitplan
        settings_layout.addWidget(self._section_label("Zeitplan Auto-Connect"))
        sched_card = QFrame()
        sched_card.setStyleSheet(f"""
            QFrame {{
                background-color: {C['card']};
                border: 1px solid {C['border']};
                border-radius: 8px;
            }}
        """)
        sched_layout = QHBoxLayout(sched_card)
        sched_layout.setContentsMargins(16, 12, 16, 12)
        sched_layout.setSpacing(10)
        self.chk_schedule = QCheckBox("Zeitplan aktivieren")
        self.chk_schedule.stateChanged.connect(lambda: self._schedule_save())
        sched_layout.addWidget(self.chk_schedule)
        sched_layout.addSpacing(8)
        sched_layout.addWidget(QLabel("Verbinden um"))
        self.entry_sched_connect = QLineEdit()
        self.entry_sched_connect.setPlaceholderText("08:00")
        self.entry_sched_connect.setFixedWidth(70)
        self.entry_sched_connect.editingFinished.connect(self._schedule_save)
        sched_layout.addWidget(self.entry_sched_connect)
        sched_layout.addSpacing(8)
        sched_layout.addWidget(QLabel("Trennen um"))
        self.entry_sched_disconnect = QLineEdit()
        self.entry_sched_disconnect.setPlaceholderText("18:00")
        self.entry_sched_disconnect.setFixedWidth(70)
        self.entry_sched_disconnect.editingFinished.connect(self._schedule_save)
        sched_layout.addWidget(self.entry_sched_disconnect)
        sched_layout.addStretch()
        settings_layout.addWidget(sched_card)

        # Bandbreiten-Warnung
        settings_layout.addWidget(self._section_label("Datenvolumen / Warnung"))
        bw_card = QFrame()
        bw_card.setStyleSheet(f"""
            QFrame {{
                background-color: {C['card']};
                border: 1px solid {C['border']};
                border-radius: 8px;
            }}
        """)
        bw_layout = QHBoxLayout(bw_card)
        bw_layout.setContentsMargins(16, 12, 16, 12)
        bw_layout.setSpacing(10)
        bw_layout.addWidget(QLabel("Warnen bei über"))
        self.entry_bw = QLineEdit()
        self.entry_bw.setPlaceholderText("500")  # MB
        self.entry_bw.setFixedWidth(80)
        self.entry_bw.editingFinished.connect(self._on_bw_changed)
        bw_layout.addWidget(self.entry_bw)
        bw_layout.addWidget(QLabel("MB (Session)"))
        bw_layout.addStretch()
        settings_layout.addWidget(bw_card)

        # HTTP-Check
        settings_layout.addWidget(self._section_label("HTTP Check"))
        http_card = QFrame()
        http_card.setStyleSheet(f"""
            QFrame {{
                background-color: {C['card']};
                border: 1px solid {C['border']};
                border-radius: 8px;
            }}
        """)
        http_layout = QHBoxLayout(http_card)
        http_layout.setContentsMargins(16, 12, 16, 12)
        http_layout.setSpacing(10)
        http_layout.addWidget(QLabel("URL"))
        self.entry_http = QLineEdit()
        self.entry_http.setPlaceholderText("https://example.com/health")
        self.entry_http.setFixedWidth(280)
        self.entry_http.editingFinished.connect(self._on_http_changed)
        http_layout.addWidget(self.entry_http)
        http_layout.addStretch()
        settings_layout.addWidget(http_card)

        # Support-Paket
        support_btn = _make_btn("  Logs exportieren (ZIP)", C["surface"], C["fg"], C["surface_h"])
        support_btn.clicked.connect(self._export_support)
        settings_layout.addWidget(support_btn)

        settings_layout.addStretch()

        tabs.addTab(main_tab, "Haupt")
        tabs.addTab(settings_tab, "Einstellungen")

        # ── Tastaturkürzel ──
        QShortcut(QKeySequence("Ctrl+K"), self).activated.connect(
            lambda: self._on_connect() if not self.vpn_connected else None)
        QShortcut(QKeySequence("Ctrl+D"), self).activated.connect(
            lambda: self._on_disconnect() if self.vpn_connected else None)
        QShortcut(QKeySequence("Ctrl+L"), self).activated.connect(self._toggle_log)
        QShortcut(QKeySequence("Ctrl+H"), self).activated.connect(self._toggle_history)

    # ── Win11 UI-Helfer ────────────────────────────────────────────────────

    @staticmethod
    def _section_label(text: str) -> QLabel:
        """Abschnittsüberschrift im Windows 11 Stil."""
        lbl = QLabel(text)
        lbl.setFont(QFont("Segoe UI Variable Text", 9, QFont.Weight.DemiBold))
        lbl.setStyleSheet(f"color: {C['dim']}; letter-spacing: 0.3px;")
        return lbl

    @staticmethod
    def _expander_btn_qss() -> str:
        """QSS für aufklappbare Sektions-Buttons."""
        return f"""
            QPushButton {{
                background: transparent;
                color: {C['dim']};
                border: none;
                font-size: 9pt;
                font-family: 'Segoe UI Variable Text', 'Segoe UI';
                padding: 4px 2px;
                text-align: left;
            }}
            QPushButton:hover {{ color: {C['fg']}; }}
        """

    # ── Status ─────────────────────────────────────────────────────────────

    def _set_status(self, text: str, color: str):
        self.status_dot.set_color(color)
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color}; background: transparent;")
        self.status_label.setStyleSheet(f"color: {color}; background: transparent;")

    # ── Log ────────────────────────────────────────────────────────────────

    def _toggle_log(self):
        if self._log_visible:
            self.log_frame.hide()
            self.log_toggle.setText("›  Protokoll")
            self._log_visible = False
        else:
            self.log_frame.show()
            self.log_toggle.setText("⌄  Protokoll")
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
            expected_sha = info.get("sha")
            expected_size = info.get("size", 0)

            def progress(done, total):
                if total > 0:
                    pct = int(done / total * 100)
                    self.sig.update_progress_signal.emit(
                        f"⬆ {pct}%  ({done // 1024 // 1024}/{total // 1024 // 1024} MB)")

            if expected_sha:
                log(f"Erwartete SHA256: {expected_sha}")
            else:
                log("Keine SHA256 im Release gefunden – Download ohne Hash-Check.", "warning")

            ok = download_update(info["url"], dest, progress,
                                 expected_size=expected_size,
                                 expected_sha=expected_sha)
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
        self._remove_split_routes()
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
        self._session_rx = 0
        self._session_tx = 0
        self._bw_alerted = False

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
            self._update_window_title(tn)
            self._apply_split_routes()
        else:
            self._update_window_title()

        # Toast-Benachrichtigung
        self._notify("VPN verbunden", f"{self._session_config_name} – Verbunden!")

        # Tray-Tooltip
        if hasattr(self, '_tray') and self._tray:
            tip = "VPN Connect - Verbunden"
            if self.active_config:
                tip += f" ({extract_tunnel_name(self.active_config)})"
            self._tray.setToolTip(tip)
            self._tray_act_toggle.setText("Trennen")
        self._update_window_title()

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
        self._session_rx = 0
        self._session_tx = 0
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

        self._update_window_title()
        self._remove_split_routes()

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
            self._remove_split_routes()
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

    def _read_settings_file(self) -> dict:
        """Settings-Datei lesen. Gibt {} zurück bei Fehler oder fehlender Datei."""
        try:
            with _settings_lock:
                if os.path.exists(self._CRED_FILE):
                    with open(self._CRED_FILE, "r", encoding="utf-8") as f:
                        return json.load(f)
        except Exception:
            pass
        return {}

    def _write_settings_file(self, data: dict) -> None:
        """Settings-Datei atomar schreiben."""
        tmp = self._CRED_FILE + ".tmp"
        with _settings_lock:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, self._CRED_FILE)

    def _save_settings(self):
        """Alle Einstellungen atomar in eine Datei speichern."""
        if getattr(self, '_loading', False):
            return
        self._save_timer.stop()  # sofort, wenn explizit aufgerufen
        u = self.entry_user.text().strip()
        p = self.entry_pass.text().strip()
        enc_pw = _dpapi_protect(p)
        # RDP-Passwoerter: aus Base64 decodieren, dann DPAPI sichern
        rdp_pw_enc: dict = {}
        for host, pw_b64 in self._rdp_passwords.items():
            try:
                pw_plain = base64.b64decode(pw_b64.encode("ascii")).decode("utf-8")
            except Exception:
                pw_plain = ""
            if pw_plain:
                enc = _dpapi_protect(pw_plain)
                if enc:
                    rdp_pw_enc[host] = enc

        try:
            port_txt = self.entry_target_port.text().strip()
            port_val = int(port_txt) if port_txt else TARGET_PORT
        except ValueError:
            port_val = TARGET_PORT

        try:
            data = self._read_settings_file()
            data.update({
                "v": 2,
                "user": u,
                "pw_enc": enc_pw,
                "pw_b64": base64.b64encode(p.encode("utf-8")).decode("ascii") if p else "",
                "last_config": self.config_listbox.currentRow(),
                "auto_reconnect": self.chk_auto_reconnect.isChecked(),
                "auto_connect": self.chk_auto_connect.isChecked(),
                "favorites": self._favorites,
                "rdp_users": self._rdp_users,
                "rdp_passwords": self._rdp_passwords,          # Fallback (alt)
                "rdp_passwords_enc": rdp_pw_enc,
                "target_ip": self.entry_target_ip.text().strip(),
                "target_port": port_val,
                "rdp_resolution": self.cmb_rdp_res.currentData(),
                "split_excludes": self._split_excludes,
                "schedule_enable": self._schedule_enable,
                "schedule_connect": self._schedule_connect,
                "schedule_disconnect": self._schedule_disconnect,
                "bw_threshold_mb": self._bw_threshold_mb,
                "http_check_url": self._http_check_url,
            })
            self._write_settings_file(data)
        except OSError:
            pass

    def _schedule_save(self):
        if getattr(self, '_loading', False):
            return
        if hasattr(self, "chk_schedule"):
            self._schedule_enable = self.chk_schedule.isChecked()
        if hasattr(self, "entry_sched_connect"):
            self._schedule_connect = self.entry_sched_connect.text().strip()
        if hasattr(self, "entry_sched_disconnect"):
            self._schedule_disconnect = self.entry_sched_disconnect.text().strip()
        if hasattr(self, "entry_bw"):
            try:
                self._bw_threshold_mb = max(0, int(self.entry_bw.text().strip() or 0))
            except ValueError:
                self._bw_threshold_mb = 0
        if hasattr(self, "entry_http"):
            self._http_check_url = self.entry_http.text().strip()
        if hasattr(self, "split_text"):
            txt = self.split_text.toPlainText().strip()
            self._split_excludes = [line.strip() for line in txt.splitlines() if line.strip()]
        self._save_timer.start()

    def _load_credentials(self):
        self._loading = True
        _auto_connect = False
        try:
            d = self._read_settings_file()
            if not d:
                return

            self.entry_user.setText(d.get("user", ""))

            # Passwort: bevorzugt DPAPI, sonst Base64, sonst Plaintext
            pw_plain = ""
            if d.get("pw_enc"):
                pw_plain = _dpapi_unprotect(d.get("pw_enc", ""))
            if not pw_plain and d.get("pw_b64"):
                try:
                    pw_plain = base64.b64decode(d["pw_b64"].encode("ascii")).decode("utf-8")
                except Exception:
                    pw_plain = ""
            if not pw_plain and d.get("pw"):
                pw_plain = d["pw"]
                QTimer.singleShot(500, self._save_settings)  # Migriert auf DPAPI
            self.entry_pass.setText(pw_plain)

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
            self._rdp_passwords = {}
            rdp_enc = d.get("rdp_passwords_enc", {})
            if rdp_enc:
                for host, enc in rdp_enc.items():
                    pw_plain = _dpapi_unprotect(enc)
                    if pw_plain:
                        self._rdp_passwords[host] = base64.b64encode(
                            pw_plain.encode("utf-8")).decode("ascii")
            else:
                self._rdp_passwords = d.get("rdp_passwords", {})

            # Server IP + Port laden und anwenden
            saved_ip = d.get("target_ip", "")
            saved_port = d.get("target_port", TARGET_PORT)
            if saved_ip:
                self.entry_target_ip.setText(saved_ip)
            self.entry_target_port.setText(str(saved_port))
            self._apply_server_settings(save=False)

            # RDP Auflösung
            saved_res = d.get("rdp_resolution", None)
            if saved_res:
                for i in range(self.cmb_rdp_res.count()):
                    if self.cmb_rdp_res.itemData(i) == tuple(saved_res):
                        self.cmb_rdp_res.setCurrentIndex(i)
                        break
            self.btn_login.setEnabled(bool(TARGET_IP) and (self.upsnap is None))

            self._split_excludes = d.get("split_excludes", [])
            self._schedule_enable = d.get("schedule_enable", False)
            self._schedule_connect = d.get("schedule_connect", "")
            self._schedule_disconnect = d.get("schedule_disconnect", "")
            self._bw_threshold_mb = int(d.get("bw_threshold_mb", 0) or 0)
            self._http_check_url = d.get("http_check_url", "")
            self.chk_schedule.setChecked(self._schedule_enable)
            self.entry_sched_connect.setText(self._schedule_connect)
            self.entry_sched_disconnect.setText(self._schedule_disconnect)
            self.entry_bw.setText(str(self._bw_threshold_mb or ""))
            self.entry_http.setText(self._http_check_url)
            self.split_text.setPlainText("\n".join(self._split_excludes))

            # Auto-Connect beim Start
            _auto_connect = d.get("auto_connect", False) and bool(self.configs)

        except Exception:
            _auto_connect = False
        finally:
            self._loading = False

        # Bereits laufenden Tunnel erkennen und UI synchronisieren
        if self._detect_existing_tunnel():
            _auto_connect = False

        if _auto_connect:
            QTimer.singleShot(800, self._on_connect)

    def _detect_existing_tunnel(self) -> bool:
        """Erkennt beim Start bereits laufende WireGuard-Tunnel und passt UI an."""
        global _active_config
        for idx, (name, path) in enumerate(self.configs):
            tn = extract_tunnel_name(path)
            if _service_state(tn) == "RUNNING":
                log(f"Aktiven Tunnel erkannt: {tn}")
                self.active_config = path
                _active_config = path
                self.vpn_connected = True
                self.config_listbox.setCurrentRow(idx)
                self.btn_connect.setEnabled(False)
                self.btn_disconnect.setEnabled(True)
                self.btn_cancel.hide()
                self._set_status("Verbunden (erkannt)", C["green"])

                self._reconnect_retries = 0
                self._connect_time = time.time()
                self._session_config_name = name
                self._session_start_time = self._connect_time
                self.duration_label.setText("00:00:00")
                self.duration_label.show()
                self._duration_timer.start()

                self.ping_label.show()
                self._ping_timer.start()
                self._watchdog_timer.start()

                self._transfer_timer.start()
                self._transfer_tick()

                # Browser-Button aktivieren falls Ziel gesetzt
                self.btn_browser.setEnabled(bool(TARGET_IP))

                threading.Thread(target=self._fetch_vpn_ip, args=(tn,), daemon=True).start()

                if hasattr(self, '_tray') and self._tray:
                    self._tray.setToolTip("VPN Connect - Verbunden")
                    self._tray_act_toggle.setText("Trennen")

                self._notify("VPN verbunden", f"{name} – erkannt.")
                QTimer.singleShot(500, lambda: self.sig.auto_login_signal.emit())
                self._update_window_title(tn)
                return True
        return False

    def _on_bw_changed(self):
        try:
            v = int(self.entry_bw.text().strip() or 0)
            self._bw_threshold_mb = max(0, v)
        except ValueError:
            self._bw_threshold_mb = 0
        self._schedule_save()

    def _on_http_changed(self):
        self._http_check_url = self.entry_http.text().strip()
        self._schedule_save()

    def _on_split_changed(self):
        txt = self.split_text.toPlainText().strip()
        self._split_excludes = [line.strip() for line in txt.splitlines() if line.strip()]
        self._schedule_save()

    def _apply_split_routes(self):
        self._remove_split_routes()
        nets = _parse_networks(self._split_excludes)
        if not nets:
            return
        gw = _default_gateway()
        if not gw:
            log("Split-Tunnel: Kein Default-Gateway gefunden.", "warning")
            return
        for net in nets:
            if net.version != 4:
                continue
            try:
                _run_silent(["route", "add", str(net.network_address),
                             "mask", str(net.netmask), gw],
                            capture_output=True, text=True, timeout=5)
                self._routes_added.append(str(net))
                log(f"Split-Tunnel Route gesetzt: {net} -> {gw}")
            except Exception as e:
                log(f"Split-Tunnel Route fehlgeschlagen ({net}): {e}", "warning")

    def _remove_split_routes(self):
        if not self._routes_added:
            return
        for net in self._routes_added:
            try:
                _run_silent(["route", "delete", net],
                            capture_output=True, text=True, timeout=5)
                log(f"Split-Tunnel Route entfernt: {net}")
            except Exception:
                pass
        self._routes_added.clear()

    def _apply_server_settings(self, save: bool = True):
        """IP + Port aus den Feldern übernehmen und global setzen."""
        global TARGET_IP, TARGET_PORT
        ip = self.entry_target_ip.text().strip()
        port_txt = self.entry_target_port.text().strip()
        if not ip:
            QMessageBox.warning(self, "Server", "IP / Hostname darf nicht leer sein.")
            self.entry_target_ip.setText(self._last_target_ip)
            return
        try:
            port = int(port_txt) if port_txt else TARGET_PORT
        except ValueError:
            QMessageBox.warning(self, "Server", "Port ist ungültig.")
            self.entry_target_port.setText(str(self._last_target_port))
            return
        if not (1 <= port <= 65535):
            QMessageBox.warning(self, "Server", "Port muss zwischen 1 und 65535 liegen.")
            self.entry_target_port.setText(str(self._last_target_port))
            return
        TARGET_IP = ip
        TARGET_PORT = port
        self._last_target_ip = ip
        self._last_target_port = port
        # Browser-Button nur aktiv wenn IP gesetzt und verbunden
        if hasattr(self, 'btn_browser'):
            self.btn_browser.setEnabled(
                self.vpn_connected and bool(TARGET_IP))
        if hasattr(self, 'btn_login'):
            self.btn_login.setEnabled(bool(TARGET_IP) and (self.upsnap is None))
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

        if not TARGET_IP:
            QMessageBox.warning(self, "UpSnap",
                                "Bitte IP/Hostname unter 'Server / Ziel' angeben.")
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
                    QTimer.singleShot(0, self._save_settings)
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
                QFrame {{
                    background-color: {C['surface']};
                    border: 1px solid {C['border']};
                    border-radius: 6px;
                }}
                QFrame:hover {{
                    background-color: {C['surface_h']};
                    border: 1px solid {C['border_l']};
                }}
            """)
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(14, 8, 10, 8)
            row_layout.setSpacing(10)

            name  = d.get("name", "?")
            ip    = d.get("ip", "?")
            online = d.get("status") == "online"
            dot_c  = C["green"] if online else C["dim"]

            dot = DotWidget(dot_c, 9)
            row_layout.addWidget(dot)

            name_lbl = QLabel(name)
            name_lbl.setStyleSheet(f"color: {C['fg']}; font-size: 10pt; font-weight: 600;")
            row_layout.addWidget(name_lbl)

            ip_lbl = QLabel(ip)
            ip_lbl.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
            row_layout.addWidget(ip_lbl)

            row_layout.addStretch()

            # Status-Label
            init_txt = "Online" if online else "Offline"
            init_col = C["green"] if online else C["dim"]
            status_lbl = QLabel(init_txt)
            status_lbl.setFixedWidth(70)
            status_lbl.setStyleSheet(
                f"color: {init_col}; font-size: 8pt; font-weight: 600;")
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
                    border: none; font-size: 13pt; padding: 0 4px;
                }}
                QPushButton:hover {{ color: {C['yellow']}; }}
            """)
            star_btn.setToolTip("Favorit")
            star_btn.clicked.connect(
                lambda checked, x=did, b=star_btn: self._toggle_favorite(x, b))
            row_layout.addWidget(star_btn)

            _btn_qss = f"""
                QPushButton {{
                    background: {C['card']}; color: {C['fg']};
                    border: 1px solid {C['border']}; border-radius: 4px;
                    padding: 5px 12px; font-size: 9pt; font-weight: 500;
                }}
                QPushButton:hover {{
                    background: {C['surface_h']}; border: 1px solid {C['border_l']};
                }}
                QPushButton:pressed {{ background: {C['surface']}; }}
                QPushButton:disabled {{
                    background: {C['surface']}; color: rgba(255,255,255,0.3);
                    border: 1px solid {C['border']};
                }}
            """

            if online:
                b = QPushButton("RDP")
                b.setStyleSheet(_btn_qss)
                b.clicked.connect(
                    lambda checked, x=dip, n=dn, bl=btn_refs, sl=status_lbl:
                    self._on_rdp_with_user(x, n, bl, sl))
                row_layout.addWidget(b)
                btn_refs.append(b)
            else:
                b1 = QPushButton("WoL")
                b1.setStyleSheet(_btn_qss)
                b1.clicked.connect(
                    lambda checked, x=did, n=dn, bl=btn_refs, sl=status_lbl:
                    self._on_wake(x, n, bl, sl))
                row_layout.addWidget(b1)

                b2 = QPushButton("WoL + RDP")
                b2.setStyleSheet(_btn_qss)
                b2.clicked.connect(
                    lambda checked, x=did, y=dip, n=dn, bl=btn_refs, sl=status_lbl:
                    self._on_wake_rdp(x, y, n, bl, sl))
                row_layout.addWidget(b2)

                btn_refs += [b1, b2]

            if not online and ip and ip != "?":
                self._check_local_online(ip, status_lbl)

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

    @staticmethod
    def _set_device_status(status_lbl: QLabel, text: str, color: str):
        """Thread-safe Status-Update (Slot + direkt aufrufbar)."""
        try:
            status_lbl.setText(text)
            status_lbl.setStyleSheet(
                f"color: {color}; font-size: 8pt; font-weight: 600;")
        except RuntimeError:
            pass

    @staticmethod
    def _set_btns(btn_refs: list, enabled: bool):
        for b in btn_refs:
            try:
                b.setEnabled(enabled)
            except RuntimeError:
                pass

    def _check_local_online(self, ip: str, status_lbl: QLabel):
        """Fallback: lokales Ping + TCP-Probe, falls UpSnap 'offline' meldet."""
        if not ip or ip in self._local_ping_tasks:
            return
        self._local_ping_tasks.add(ip)

        def work():
            try:
                r = _run_silent(
                    ["ping", "-n", "1", "-w", "800", ip],
                    capture_output=True, text=True, timeout=2)
                if r.returncode == 0:
                    self.sig.device_status_signal.emit(
                        status_lbl, "Online (Ping)", C["green"])
                    return
                # TCP Fallback auf gängige Ports
                for port in (3389, 22, 80):
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(1.0)
                        s.connect((ip, port))
                        s.close()
                        self.sig.device_status_signal.emit(
                            status_lbl, f"Online (tcp {port})", C["green"])
                        return
                    except Exception:
                        continue
            except Exception:
                pass
            finally:
                self._local_ping_tasks.discard(ip)

        threading.Thread(target=work, daemon=True).start()

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
        creds_added = False
        try:
            # Credentials via cmdkey hinterlegen (ermöglicht automatisches Login)
            if username and password:
                try:
                    _run_silent(
                        ["cmdkey", f"/add:{ip}", f"/user:{username}", f"/pass:{password}"],
                        capture_output=True, timeout=10)
                    log(f"RDP: Credentials für {ip} hinterlegt.")
                    creds_added = True
                except Exception as e:
                    log(f"cmdkey Fehler: {e}", "warning")

            rdp_path = os.path.join(
                os.environ.get("TEMP", _base_dir), f"_vpn_{name}.rdp")
            with open(rdp_path, "w") as f:
                f.write(f"full address:s:{ip}\n")
                # Kein Credential-Prompt wenn cmdkey gesetzt
                f.write(f"prompt for credentials:i:{'0' if (username and password) else '1'}\n")
                f.write("authentication level:i:0\n")
                res = self.cmb_rdp_res.currentData() if hasattr(self, "cmb_rdp_res") else None
                if res:
                    w, h = res
                    f.write("screen mode id:i:2\n")
                    f.write(f"desktopwidth:i:{w}\n")
                    f.write(f"desktopheight:i:{h}\n")
                    f.write("session bpp:i:32\n")
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
            if creds_added:
                try:
                    _run_silent(["cmdkey", f"/delete:{ip}"],
                                capture_output=True, timeout=10)
                except Exception:
                    pass
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

                # Optional: Handshake-Frische prüfen (WireGuard)
                tn = extract_tunnel_name(self.active_config) if self.active_config else None
                if tn:
                    try:
                        r = _run_silent(
                            ["wg", "show", tn, "latest-handshakes"],
                            capture_output=True, text=True, timeout=3)
                        if r.returncode == 0 and r.stdout.strip():
                            # Format: <pubkey>\t<unix_ts>
                            ages = []
                            now = int(time.time())
                            for line in r.stdout.strip().splitlines():
                                parts = line.split("\t")
                                if len(parts) >= 2:
                                    try:
                                        ts = int(parts[1])
                                        age = max(0, now - ts)
                                        ages.append(age)
                                    except ValueError:
                                        pass
                            if ages:
                                min_age = min(ages)
                                if min_age > 180:
                                    log(f"WireGuard Handshake alt ({min_age}s)", "warning")
                    except Exception:
                        pass

                # HTTP-Check
                if self._http_check_url:
                    try:
                        req = request.Request(self._http_check_url, method="GET",
                                              headers={"User-Agent": "VPN-Connect-HTTPCheck"})
                        with request.urlopen(req, timeout=3) as resp:
                            if resp.status != 200:
                                log(f"HTTP-Check {self._http_check_url} -> {resp.status}", "warning")
                    except Exception as e:
                        log(f"HTTP-Check fehlgeschlagen: {e}", "warning")
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
                self._session_rx = total_rx
                self._session_tx = total_tx
                self.sig.transfer_signal.emit(text)

                if self._bw_threshold_mb > 0 and not self._bw_alerted:
                    if (total_rx + total_tx) >= self._bw_threshold_mb * 1024 * 1024:
                        self._bw_alerted = True
                        self._notify("Bandbreite", f"Session > {self._bw_threshold_mb} MB")
                        log(f"Datenvolumen überschritten: {self._bw_threshold_mb} MB", "warning")
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

    # ── Zeitplan ────────────────────────────────────────────────────────────

    def _schedule_tick(self):
        if not self._schedule_enable:
            return
        now = datetime.datetime.now()
        day = now.strftime("%Y-%m-%d")
        if day != self._last_schedule_day:
            self._last_schedule_day = day
            self._did_sched_connect = False
            self._did_sched_disconnect = False

        def _parse(txt: str) -> Optional[datetime.time]:
            try:
                h, m = txt.strip().split(":")
                return datetime.time(int(h), int(m))
            except Exception:
                return None

        t_connect = _parse(self._schedule_connect)
        t_disconnect = _parse(self._schedule_disconnect)
        now_time = now.time().replace(second=0, microsecond=0)

        if t_connect and not self._did_sched_connect and now_time >= t_connect:
            if not self.vpn_connected:
                log("Zeitplan: Auto-Connect", "info")
                self._on_connect()
            self._did_sched_connect = True

        if t_disconnect and not self._did_sched_disconnect and now_time >= t_disconnect:
            if self.vpn_connected:
                log("Zeitplan: Auto-Disconnect", "info")
                self._on_disconnect()
            self._did_sched_disconnect = True

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

    def _on_alert(self, title: str, msg: str, level: str = "info"):
        icon = QSystemTrayIcon.MessageIcon.Critical if level == "error" \
               else QSystemTrayIcon.MessageIcon.Warning
        if hasattr(self, '_tray') and self._tray and self._tray.isVisible():
            self._tray.showMessage(title, msg, icon, 4000)
        else:
            # Fallback: Statuslabel einfärben kurz
            self._set_status(title, C["red"] if level == "error" else C["yellow"])
        self._append_log(f"[{title}] {msg}")

    def _export_support(self):
        """Erstellt ein Support-ZIP mit Log und anonymisierten Settings."""
        try:
            dest_dir = os.path.join(os.path.expanduser("~"), "Desktop")
            os.makedirs(dest_dir, exist_ok=True)
            zip_path = os.path.join(dest_dir, "VPN_Support.zip")

            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
                if os.path.exists(log_file):
                    z.write(log_file, arcname="vpn_debug.log")
                # Settings anonymisieren
                data = self._read_settings_file()
                for k in ("pw_enc", "pw_b64", "pw", "rdp_passwords", "rdp_passwords_enc"):
                    if k in data:
                        data[k] = "***"
                z.writestr("vpn_settings_sanitized.json", json.dumps(data, indent=2))
            self._notify("Support-Paket", f"Erstellt: {zip_path}")
            log(f"Support-Paket erstellt: {zip_path}")
        except Exception as e:
            log(f"Support-Paket fehlgeschlagen: {e}", "error")

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

    def _update_window_title(self, tunnel: Optional[str] = None):
        base = f"VPN Connect  v{APP_VERSION}"
        tn = tunnel or (extract_tunnel_name(self.active_config) if self.active_config else "")
        if tn:
            self.setWindowTitle(f"{base}  ·  {tn}")
        else:
            self.setWindowTitle(base)

    # ── Verbindungshistorie ───────────────────────────────────────────────

    def _add_history_entry(self, config: str, start_ts: float, duration_s: int):
        """Verbindung in den Verlauf eintragen (atomares Schreiben)."""
        import datetime
        entry = {
            "config": config,
            "start": datetime.datetime.fromtimestamp(start_ts).strftime("%d.%m.%Y %H:%M"),
            "duration_s": duration_s,
        }
        try:
            data = self._read_settings_file()
            hist = data.get("history", [])
            hist.insert(0, entry)
            data["history"] = hist[:20]
            self._write_settings_file(data)
            self.sig.history_updated_signal.emit()
        except Exception:
            pass

    def _toggle_history(self):
        if self._history_visible:
            self.history_frame.hide()
            self.history_toggle.setText("›  Verbindungshistorie")
            self._history_visible = False
        else:
            self.history_frame.show()
            self.history_toggle.setText("⌄  Verbindungshistorie")
            self._history_visible = True
            self._refresh_history_ui()

    def _refresh_history_ui(self):
        """History-Liste neu aufbauen."""
        while self.history_list_layout.count():
            w = self.history_list_layout.takeAt(0).widget()
            if w:
                w.deleteLater()
        try:
            hist = self._read_settings_file().get("history", [])
            if not hist:
                lbl = QLabel("Kein Verlauf vorhanden.")
                lbl.setStyleSheet(f"color: {C['dim']}; font-size: 9pt;")
                self.history_list_layout.addWidget(lbl)
                return
            for entry in hist:
                d = entry.get("duration_s", 0)
                h, m, s = d // 3600, (d % 3600) // 60, d % 60
                text = (f"{entry.get('start','?')}  ·  "
                        f"{entry.get('config','?')}  ·  "
                        f"{h:02d}:{m:02d}:{s:02d}")
                row = QLabel(text)
                row.setStyleSheet(
                    f"color: {C['dim']}; font-size: 9pt; padding: 4px 6px; border-radius: 3px;")
                self.history_list_layout.addWidget(row)
        except Exception:
            pass

    def _clear_history(self):
        try:
            data = self._read_settings_file()
            data["history"] = []
            self._write_settings_file(data)
            self._refresh_history_ui()
        except Exception:
            pass

    # ── Favoriten ─────────────────────────────────────────────────────────


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
        self._save_settings()

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

        self._save_settings()
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
        self._remove_split_routes()
        _stop_dialog_dismisser()
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
        self._remove_split_routes()
        _stop_dialog_dismisser()
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

