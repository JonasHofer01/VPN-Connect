import subprocess
import time
import webbrowser
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

APP_VERSION = "1.0.0"
GITHUB_REPO = "JonasHofer01/VPN-Connect"   # owner/repo

CONFIG_BASE = r"C:\Program Files\WireGuard\Data\Configurations"
TARGET_IP = "192.168.178.5"
TARGET_PORT = 8090

BROWSER_PATHS = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
)

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


def _find_wireguard_exe() -> str:
    """Findet den Pfad zu wireguard.exe."""
    for p in [
        r"C:\Program Files\WireGuard\wireguard.exe",
        os.path.join(os.environ.get("ProgramFiles", ""), "WireGuard", "wireguard.exe"),
    ]:
        if os.path.isfile(p):
            return p
    import shutil
    found = shutil.which("wireguard")
    if found:
        return found
    return r"C:\Program Files\WireGuard\wireguard.exe"


def _wait_service_gone(tn: str, timeout: int = 15) -> bool:
    """Wartet bis der Dienst komplett entfernt ist."""
    for _ in range(timeout):
        if not _service_state(tn):
            return True
        time.sleep(1)
    return not _service_state(tn)


def _dismiss_error_dialogs(duration: int = 10):
    """Hintergrund-Thread: schließt automatisch alle 'Fehler'-Dialoge
    die von wireguard.exe erzeugt werden (MessageBox).
    Läuft 'duration' Sekunden lang."""
    user32 = ctypes.windll.user32
    WM_CLOSE = 0x0010
    end = time.time() + duration
    while time.time() < end:
        try:
            # Suche nach Fenstern mit Titel "Fehler" (deutscher Windows MessageBox-Titel)
            for title in ("Fehler", "Error"):
                hwnd = user32.FindWindowW(None, title)
                if hwnd:
                    user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
                    log(f"Fehler-Dialog automatisch geschlossen.", "info")
        except Exception:
            pass
        time.sleep(0.3)


def connect_vpn(config_path: Optional[str]) -> Optional[str]:
    global _we_installed_tunnel
    _we_installed_tunnel = False

    if not config_path:
        log("Keine Konfiguration.", "error")
        return None

    tn = extract_tunnel_name(config_path)
    sn = f"WireGuardTunnel${tn}"
    log(f"Tunnel: {tn}")

    # Bereits laufend?
    if _service_state(tn) == "RUNNING":
        log(f"'{sn}' laeuft bereits.")
        _we_installed_tunnel = False
        return config_path

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

    # Dialog-Schließer starten (schließt automatisch "Fehler"-Dialoge)
    threading.Thread(target=_dismiss_error_dialogs, args=(15,), daemon=True).start()

    # Tunnel installieren via WireGuard (funktioniert nur über den Manager)
    try:
        log(f"Installiere Tunnel: {config_path}")
        _run_silent(["wireguard", "/installtunnelservice", config_path],
                    check=True, capture_output=True)
        _we_installed_tunnel = True
        wait_for_tunnel(tn)
        log("Tunnel aktiviert.")
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

    state = _service_state(tn)
    if not state:
        log(f"Dienst '{sn}' existiert nicht – nichts zu tun.")
        _we_installed_tunnel = False
        return

    # Dialog-Schließer starten
    threading.Thread(target=_dismiss_error_dialogs, args=(10,), daemon=True).start()

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


def _cleanup():
    global _active_config
    if _active_config:
        disconnect_vpn(_active_config)
        _active_config = None


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

        self._setup_styles()
        self._build_ui()
        self._load_configs()

        # Im Hintergrund nach Updates suchen
        threading.Thread(target=self._check_update_bg, daemon=True).start()

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
        self._set_status("Verbinde...", C["yellow"])

        def work():
            global _active_config
            r = connect_vpn(path)
            if r:
                self.active_config = r
                _active_config = r
                self.vpn_connected = True
                ok = check_connection(TARGET_IP, TARGET_PORT, retries=5, delay=2.0)
                self.root.after(0, lambda: self._connected(ok))
            else:
                self.root.after(0, self._disconnected)
        threading.Thread(target=work, daemon=True).start()

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
            webbrowser.open(url)
            log("Browser geöffnet (webbrowser).")
        except Exception as e:
            log(f"Browser-Fehler: {e}", "error")

    # ── UpSnap Login ──────────────────────────────────────────────────────

    def _on_upsnap_login(self):
        u = self.entry_user.get().strip()
        p = self.entry_pass.get().strip()
        if not u or not p:
            messagebox.showinfo("UpSnap", "E-Mail und Passwort eingeben.")
            return
        self.btn_login.configure(state="disabled")

        def work():
            c = UpSnapClient(f"http://{TARGET_IP}:{TARGET_PORT}", u, p)
            if c.token:
                self.upsnap = c
                devs = c.get_devices()
                self.root.after(0, lambda: self._show_devices(devs))
                self.root.after(0, lambda: self.btn_refresh_devices.configure(state="normal"))
            else:
                self.root.after(0, lambda: self.btn_login.configure(state="normal"))
        threading.Thread(target=work, daemon=True).start()

    def _on_refresh_devices(self):
        """Geräteliste aktualisieren."""
        if not self.upsnap:
            return
        self.btn_refresh_devices.configure(state="disabled")
        log("Geräteliste wird aktualisiert...")

        def work():
            devs = self.upsnap.get_devices()
            self.root.after(0, lambda: self._show_devices(devs))
            self.root.after(0, lambda: self.btn_refresh_devices.configure(state="normal"))
        threading.Thread(target=work, daemon=True).start()

    def _show_devices(self, devices: List[dict]):
        for w in self._device_widgets:
            w.destroy()
        self._device_widgets.clear()
        self.upsnap_hint.pack_forget()

        if not devices:
            l = tk.Label(self.device_frame, text="Keine Geraete.",
                         bg=C["card"], fg=C["dim"], font=("Segoe UI", 9))
            l.pack(pady=4)
            self._device_widgets.append(l)
            self.btn_login.configure(state="normal")
            return

        for d in devices:
            row = tk.Frame(self.device_frame, bg=C["surface"], pady=7, padx=12)
            row.pack(fill="x", pady=2)
            self._device_widgets.append(row)

            row.columnconfigure(1, weight=1)

            name = d.get("name", "?")
            ip = d.get("ip", "?")
            online = d.get("status") == "online"
            dot_c = C["green"] if online else C["dim"]

            # Status-Punkt
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

            did, dip, dn = d.get("id", ""), ip, name

            # Buttons Frame
            btns = tk.Frame(row, bg=C["surface"])
            btns.grid(row=0, column=3, sticky="e")

            if online:
                # Online: nur RDP anbieten
                ttk.Button(btns, text="RDP", style="Small.TButton",
                           command=lambda x=dip, n=dn: self._on_rdp(x, n)
                           ).pack(side="left", padx=(0, 4))
            else:
                # Offline: WoL und WoL+RDP anbieten
                ttk.Button(btns, text="WoL", style="Small.TButton",
                           command=lambda x=did, n=dn: self._on_wake(x, n)
                           ).pack(side="left", padx=(0, 4))
                ttk.Button(btns, text="WoL + RDP", style="Small.TButton",
                           command=lambda x=did, y=dip, n=dn:
                               self._on_wake_rdp(x, y, n, False)
                           ).pack(side="left", padx=(0, 4))

        self.btn_login.configure(state="normal")

    # ── Device Actions ────────────────────────────────────────────────────

    def _on_wake(self, did: str, name: str):
        if not self.upsnap:
            return
        log(f"WoL -> '{name}'")
        threading.Thread(target=lambda: self.upsnap.wake(did), daemon=True).start()

    def _on_rdp(self, ip: str, name: str):
        log(f"RDP -> '{name}' ({ip})")
        try:
            subprocess.Popen(["mstsc.exe", f"/v:{ip}"],
                             startupinfo=STARTUPINFO,
                             creationflags=CREATE_NO_WINDOW)
        except Exception as e:
            log(f"RDP Fehler: {e}", "error")

    def _on_wake_rdp(self, did: str, ip: str, name: str, online: bool):
        if online:
            self._on_rdp(ip, name)
            return
        if not self.upsnap:
            return
        log(f"WoL + RDP -> '{name}'")

        def work():
            self.upsnap.wake(did)
            log(f"Warte auf '{name}' (max 120s)...")
            t0 = time.time()
            while time.time() - t0 < 120:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((ip, 3389))
                    s.close()
                    log(f"'{name}' bereit!")
                    time.sleep(5)
                    self.root.after(0, lambda: self._on_rdp(ip, name))
                    return
                except Exception:
                    pass
                log(f"  Warte... ({int(time.time() - t0)}s)")
                time.sleep(2)
            log(f"'{name}' nicht erreichbar.", "warning")
            if messagebox.askyesno("Timeout",
                                    f"'{name}' antwortet nicht.\nRDP trotzdem starten?"):
                self.root.after(0, lambda: self._on_rdp(ip, name))

        threading.Thread(target=work, daemon=True).start()


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
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()

