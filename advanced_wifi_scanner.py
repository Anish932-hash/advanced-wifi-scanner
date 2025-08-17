#!/usr/bin/env python3
# EchoFrame Invocation Chamber — Kali-ready consolidated build
# Chunks 1–5 form one file when concatenated in order.

from __future__ import annotations

import os
import sys
import json
import platform
import logging
import hashlib
import base64
import secrets
import shutil
import threading
import queue
import datetime
import importlib.util
import subprocess
import stat
from pathlib import Path
from typing import Any, Dict, Optional, Callable

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ---------- App identity ----------
APP_NAME = "EchoFrame Invocation Chamber"
APP_ID = "echoframe.gui"
APP_VERSION = "1.1.0"

# ---------- Paths & config ----------
HOME = Path.home()
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = HOME / ".local" / "share" / "echoframe"
CONF_DIR = HOME / ".config" / "echoframe"
LOG_DIR = DATA_DIR / "logs"
THEME_DIR = DATA_DIR / "themes"
PLUGIN_DIR = DATA_DIR / "plugins"
ARCHIVE_DIR = DATA_DIR / "archives"
for d in (DATA_DIR, CONF_DIR, LOG_DIR, THEME_DIR, PLUGIN_DIR, ARCHIVE_DIR):
    d.mkdir(parents=True, exist_ok=True)

SETTINGS_FILE = CONF_DIR / "settings.json"
RITUAL_LOG_FILE = LOG_DIR / "ritual.log"

# ---------- Safety banner ----------
SAFETY_BANNER = (
    "Operate only on networks you own or have explicit, written permission to assess."
)

# ---------- Themes ----------
DEFAULT_THEME = "Dark Epoch"
THEMES: Dict[str, Dict[str, str]] = {
    "Dark Epoch": {
        "bg": "#0f1115", "panel": "#161a20", "fg": "#d7f5d0", "muted": "#90a2b2",
        "accent": "#ffcc00", "error": "#ff6b6b", "ok": "#00d084", "glyph": "#7aa2f7",
    },
    "Solar Rebirth": {
        "bg": "#fffaf0", "panel": "#fff1d6", "fg": "#2c2c2c", "muted": "#5a5a5a",
        "accent": "#cc7a00", "error": "#d00000", "ok": "#008a3b", "glyph": "#005cc5",
    },
    "Ashen Memory": {
        "bg": "#1a1b1e", "panel": "#23252a", "fg": "#e6e6e6", "muted": "#9a9a9a",
        "accent": "#c0c0c0", "error": "#ff5c8a", "ok": "#56d364", "glyph": "#8eace3",
    },
}

# ---------- Logging (file + in-memory for GUI) ----------
GUI_LOG_QUEUE: "queue.Queue[str]" = queue.Queue(maxsize=2000)
LOGGER = logging.getLogger(APP_ID)
LOGGER.setLevel(logging.DEBUG)
_fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%Y-%m-%d %H:%M:%S")

class InMemoryLogHandler(logging.Handler):
    def __init__(self, q: queue.Queue):
        super().__init__(level=logging.INFO)
        self.q = q
        self.setFormatter(_fmt)
    def emit(self, record: logging.LogRecord):
        try:
            self.q.put(self.format(record))
        except Exception:
            pass

file_handler = logging.FileHandler(RITUAL_LOG_FILE, encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(_fmt)
LOGGER.addHandler(file_handler)
LOGGER.addHandler(InMemoryLogHandler(GUI_LOG_QUEUE))
LOGGER.info(f"{APP_NAME} v{APP_VERSION} starting…")

# ---------- Settings I/O ----------
DEFAULT_SETTINGS: Dict[str, Any] = {
    "theme": DEFAULT_THEME,
    "owner_gate": {
        "stored": "", "salt": "", "n": 2**14, "r": 8, "p": 1, "dklen": 64,
        "hint": "Your private seal phrase (remember it).",
    },
    "core_module": "",  # path or module name to your existing core script
    "last_paths": {"cap": "", "wordlist": "", "bssid": ""},
    "owner_gate_required": True,
    "archive_logs": True,
    "archive_max_files": 20,
}

def load_settings() -> Dict[str, Any]:
    if SETTINGS_FILE.exists():
        try:
            data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            merged = {**DEFAULT_SETTINGS, **data}
            merged["owner_gate"] = {**DEFAULT_SETTINGS["owner_gate"], **merged.get("owner_gate", {})}
            merged["last_paths"] = {**DEFAULT_SETTINGS["last_paths"], **merged.get("last_paths", {})}
            return merged
        except Exception as e:
            LOGGER.error(f"Failed to load settings: {e}")
    return json.loads(json.dumps(DEFAULT_SETTINGS))

def save_settings(s: Dict[str, Any]) -> None:
    try:
        SETTINGS_FILE.write_text(json.dumps(s, indent=2), encoding="utf-8")
    except Exception as e:
        LOGGER.error(f"Failed to save settings: {e}")

SETTINGS = load_settings()

# ---------- Owner gate (scrypt) ----------
def _scrypt_hash(secret: str, salt_b: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    return hashlib.scrypt(secret.encode("utf-8"), salt=salt_b, n=n, r=r, p=p, dklen=dklen)

def set_owner_gate_secret(secret: str, hint: Optional[str] = None) -> None:
    gate = SETTINGS["owner_gate"]
    salt_b = secrets.token_bytes(16)
    digest = _scrypt_hash(secret, salt_b, gate["n"], gate["r"], gate["p"], gate["dklen"])
    gate["stored"] = base64.b64encode(digest).decode("ascii")
    gate["salt"] = base64.b64encode(salt_b).decode("ascii")
    if hint is not None:
        gate["hint"] = hint
    save_settings(SETTINGS)
    LOGGER.info("Owner gate secret set.")

def verify_owner_secret(secret: str) -> bool:
    gate = SETTINGS["owner_gate"]
    if not gate.get("stored") or not gate.get("salt"):
        set_owner_gate_secret(secret)
        return True
    try:
        salt_b = base64.b64decode(gate["salt"])
        expected = base64.b64decode(gate["stored"])
        digest = _scrypt_hash(secret, salt_b, gate["n"], gate["r"], gate["p"], gate["dklen"])
        return secrets.compare_digest(digest, expected)
    except Exception as e:
        LOGGER.error(f"Owner gate verification error: {e}")
        return False

class OwnerGateDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk, theme: Dict[str, str], hint: str):
        super().__init__(parent)
        self.title("Owner Gate")
        self.resizable(False, False)
        self.configure(bg=theme["panel"])
        self.result: Optional[str] = None
        frm = tk.Frame(self, bg=theme["panel"])
        frm.pack(padx=16, pady=16, fill="both", expand=True)
        tk.Label(frm, text="Enter seal phrase to unlock relic:", bg=theme["panel"], fg=theme["fg"])\
            .grid(row=0, column=0, sticky="w")
        self.entry = ttk.Entry(frm, show="*")
        self.entry.grid(row=1, column=0, sticky="ew", pady=(6, 10))
        frm.columnconfigure(0, weight=1)
        tk.Label(frm, text=f"Hint: {hint}", bg=theme["panel"], fg=theme["muted"])\
            .grid(row=2, column=0, sticky="w", pady=(0, 10))
        btns = tk.Frame(frm, bg=theme["panel"])
        btns.grid(row=3, column=0, sticky="e")
        ttk.Button(btns, text="Unlock", command=self._ok).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side="left")
        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self._cancel())
        self.transient(parent); self.grab_set(); self.entry.focus_set()
    def _ok(self): self.result = self.entry.get(); self.destroy()
    def _cancel(self): self.result = None; self.destroy()

def owner_gate_flow(root: tk.Tk, theme: Dict[str, str]) -> bool:
    if not SETTINGS.get("owner_gate_required", True):
        LOGGER.info("Owner gate disabled by settings."); return True
    dlg = OwnerGateDialog(root, theme, SETTINGS["owner_gate"].get("hint", ""))
    root.wait_window(dlg)
    if dlg.result is None:
        LOGGER.warning("Owner gate canceled."); return False
    if verify_owner_secret(dlg.result):
        LOGGER.info("Owner gate passed."); return True
    LOGGER.error("Owner gate failed.")
    messagebox.showerror("Access Denied", "Seal phrase rejected. Ritual aborted.")
    return False

# ---------- Log archiving ----------
def archive_log_if_needed() -> None:
    try:
        if not SETTINGS.get("archive_logs", True) or not RITUAL_LOG_FILE.exists():
            return
        today = datetime.datetime.now().strftime("%Y%m%d")
        stamp_name = ARCHIVE_DIR / f"ritual_{today}.log"
        if not stamp_name.exists():
            shutil.copy2(RITUAL_LOG_FILE, stamp_name)
        archives = sorted(ARCHIVE_DIR.glob("ritual_*.log"))
        max_files = int(SETTINGS.get("archive_max_files", 20))
        while len(archives) > max_files:
            old = archives.pop(0)
            try: old.unlink()
            except Exception: break
    except Exception as e:
        LOGGER.error(f"Archiving error: {e}")

archive_log_if_needed()

# ---------- Core bridge (preserves your original functions) ----------
CoreFunc = Callable[..., Any]

class CoreBridge:
    def __init__(self):
        self.module = None
        self.funcs: Dict[str, CoreFunc] = {}
    def load(self, module_path_or_name: str) -> None:
        LOGGER.info(f"Loading core module: {module_path_or_name}")
        try:
            if module_path_or_name.endswith(".py") and Path(module_path_or_name).expanduser().exists():
                p = Path(module_path_or_name).expanduser().resolve()
                sys.path.insert(0, str(p.parent))
                self.module = importlib.util.module_from_spec(
                    spec := importlib.util.spec_from_file_location(p.stem, p)
                )
                assert spec and spec.loader
                spec.loader.exec_module(self.module)  # type: ignore
            else:
                self.module = __import__(module_path_or_name)
        except Exception as e:
            LOGGER.error(f"Failed to load core module: {e}")
            self.module = None
        finally:
            # best-effort cleanup; sys.path insertion only when file path used
            pass
    def bind(self, name_in_gui: str, fallback: Optional[CoreFunc] = None) -> None:
        fn = None
        if self.module is not None:
            fn = getattr(self.module, name_in_gui, None)
        self.funcs[name_in_gui] = fn or fallback
    def ensure(self, name: str):
        if name not in self.funcs:
            self.funcs[name] = None
    def call(self, name: str, *args, **kwargs):
        fn = self.funcs.get(name)
        if fn is None:
            raise RuntimeError(f"Core function '{name}' is not bound.")
        return fn(*args, **kwargs)

CORE = CoreBridge()

# Placeholders (safe no-ops) — replaced if your core provides real ones
def _noop_scan_networks(interface: str): LOGGER.info(f"[noop] scan_networks({interface})"); return []
def _noop_capture_handshake(interface: str, bssid: Optional[str] = None, channel: Optional[int] = None):
    LOGGER.info(f"[noop] capture_handshake({interface}, {bssid}, {channel})"); return None
def _noop_crack_handshake(cap_file: Path, wordlist: Path, bssid: Optional[str] = None):
    LOGGER.info(f"[noop] crack_handshake({cap_file}, {wordlist}, {bssid})"); return {"status": "noop"}
def _noop_stop_operations(): LOGGER.info("[noop] stop_operations()")

# Pre-register names; actual functions injected after core load
for name in ("scan_networks", "capture_handshake", "crack_handshake", "stop_operations"):
    CORE.ensure(name)

# ---------- Interfaces (safe + aggressive on Kali) ----------
def list_interfaces_safe() -> list[str]:
    names: set[str] = set()
    try:
        net_dir = Path("/sys/class/net")
        if net_dir.exists():
            for p in net_dir.iterdir():
                if p.name != "lo":
                    names.add(p.name)
    except Exception as e:
        LOGGER.error(f"Interface enumeration error: {e}")
    return sorted(names)

def list_interfaces_aggressive() -> list[str]:
    out = []
    try:
        res = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=False)
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                out.append(line.split()[1])
    except Exception as e:
        LOGGER.error(f"iw dev parsing error: {e}")
    return sorted(set(out))

def list_interfaces_combined() -> list[str]:
    lst = list_interfaces_safe()
    if not lst: lst = list_interfaces_aggressive()
    LOGGER.info(f"Interfaces discovered: {lst}")
    return lst
# ---------- Tk app shell ----------
class EchoFrameApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1024x720")
        self.minsize(900, 600)

        theme_name = SETTINGS.get("theme", DEFAULT_THEME)
        self.theme = THEMES.get(theme_name, THEMES[DEFAULT_THEME])
        self.configure(bg=self.theme["bg"])

        # State
        self.interface_var = tk.StringVar()
        self.cap_file_var = tk.StringVar(value=SETTINGS["last_paths"].get("cap", ""))
        self.wordlist_var = tk.StringVar(value=SETTINGS["last_paths"].get("wordlist", ""))
        self.bssid_var = tk.StringVar(value=SETTINGS["last_paths"].get("bssid", ""))
        self.theme_var = tk.StringVar(value=theme_name)
        self._op_thread: Optional[threading.Thread] = None
        self._op_lock = threading.Lock()

        # Style
        self.style = ttk.Style(self)
        # use a neutral ttk theme for predictability on Kali
        try: self.style.theme_use("clam")
        except Exception: pass
        self._apply_theme_style()

        # Layout scaffold
        self._build_layout()

        # Deferred gate + core load
        self.after(100, self._gate_and_load_core)

    def _apply_theme_style(self):
        t = self.theme
        self.style.configure("TLabel", background=t["bg"], foreground=t["fg"], font=("Segoe UI", 10))
        self.style.configure("TButton", font=("Segoe UI", 10))
        self.style.configure("TEntry", fieldbackground=t["panel"], foreground=t["fg"])
        self.style.configure("TCombobox", fieldbackground=t["panel"], foreground=t["fg"])
        self.style.map("TButton",
            background=[("active", t["accent"])],
            foreground=[("active", t["fg"])],
            relief=[("pressed", "sunken"), ("!pressed", "raised")]
        )

    def _build_layout(self):
        # Top banner
        banner = tk.Frame(self, bg=self.theme["panel"], height=44)
        banner.pack(side="top", fill="x")
        tk.Label(banner, text=APP_NAME, bg=self.theme["panel"], fg=self.theme["accent"],
                 font=("Segoe UI", 14, "bold")).pack(side="left", padx=10)
        tk.Label(banner, text=SAFETY_BANNER, bg=self.theme["panel"], fg=self.theme["muted"],
                 font=("Segoe UI", 9)).pack(side="right", padx=10)

        # Content split
        self.content_frame = tk.Frame(self, bg=self.theme["bg"])
        self.content_frame.pack(side="top", fill="both", expand=True)

        self.controls_frame = tk.Frame(self.content_frame, bg=self.theme["panel"], width=320)
        self.controls_frame.pack(side="left", fill="y")
        self.controls_frame.pack_propagate(False)

        self.output_frame = tk.Frame(self.content_frame, bg=self.theme["bg"])
        self.output_frame.pack(side="left", fill="both", expand=True)

    def _gate_and_load_core(self):
        if not owner_gate_flow(self, self.theme):
            self.destroy(); return

        # Load user's core module if set
        core_mod = SETTINGS.get("core_module", "").strip()
        if core_mod:
            CORE.load(core_mod)
        else:
            LOGGER.info("No core_module set. Using safe no-ops. Set SETTINGS['core_module'] to integrate your script.")

        # Bind expected functions: prefer real module attrs, else no-ops
        CORE.bind("scan_networks", _noop_scan_networks)
        CORE.bind("capture_handshake", _noop_capture_handshake)
        CORE.bind("crack_handshake", _noop_crack_handshake)
        CORE.bind("stop_operations", _noop_stop_operations)
        LOGGER.info("Core functions bound.")

        # Finish UI
        self._init_after_gate()

    # ---------- Post-gate population hooks (implemented in next chunks) ----------
    def _init_after_gate(self): ...
    def _populate_controls(self): ...
    def _populate_output(self): ...
    # ---------- Controls population ----------
    def _populate_controls(self):
        t = self.theme; f = self.controls_frame

        # Interface selector
        tk.Label(f, text="🧠 Interface Glyph", bg=t["panel"], fg=t["fg"], font=("Segoe UI", 10, "bold"))\
            .pack(anchor="w", padx=8, pady=(10, 2))
        self.iface_combo = ttk.Combobox(f, textvariable=self.interface_var,
                                        values=list_interfaces_combined(), state="readonly")
        self.iface_combo.pack(fill="x", padx=8, pady=(0, 8))

        # Capture file
        tk.Label(f, text="📂 Capture File (.cap)", bg=t["panel"], fg=t["fg"], font=("Segoe UI", 10, "bold"))\
            .pack(anchor="w", padx=8, pady=(8, 2))
        cap_frame = tk.Frame(f, bg=t["panel"]); cap_frame.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Entry(cap_frame, textvariable=self.cap_file_var).pack(side="left", fill="x", expand=True)
        ttk.Button(cap_frame, text="Browse", command=self._browse_cap).pack(side="left", padx=(4, 0))

        # Wordlist
        tk.Label(f, text="🔐 Passphrase File", bg=t["panel"], fg=t["fg"], font=("Segoe UI", 10, "bold"))\
            .pack(anchor="w", padx=8, pady=(8, 2))
        wl_frame = tk.Frame(f, bg=t["panel"]); wl_frame.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Entry(wl_frame, textvariable=self.wordlist_var).pack(side="left", fill="x", expand=True)
        ttk.Button(wl_frame, text="Browse", command=self._browse_wordlist).pack(side="left", padx=(4, 0))

        # BSSID
        tk.Label(f, text="📡 Target BSSID", bg=t["panel"], fg=t["fg"], font=("Segoe UI", 10, "bold"))\
            .pack(anchor="w", padx=8, pady=(8, 2))
        ttk.Entry(f, textvariable=self.bssid_var).pack(fill="x", padx=8, pady=(0, 8))

        # Theme selector
        tk.Label(f, text="🕯️ Theme Epoch", bg=t["panel"], fg=t["fg"], font=("Segoe UI", 10, "bold"))\
            .pack(anchor="w", padx=8, pady=(8, 2))
        self.theme_combo = ttk.Combobox(f, textvariable=self.theme_var, values=list(THEMES.keys()), state="readonly")
        self.theme_combo.pack(fill="x", padx=8, pady=(0, 8))
        self.theme_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_selected_theme())

        # Buttons
        self.invoke_btn = ttk.Button(f, text="🔮 Invoke Ritual", command=self._invoke_ritual)
        self.invoke_btn.pack(fill="x", padx=8, pady=(12, 6))
        self.stop_btn = ttk.Button(f, text="⏹ Stop Ritual", command=self._stop_ritual)
        self.stop_btn.pack(fill="x", padx=8, pady=(0, 12))

    def _browse_cap(self):
        file = filedialog.askopenfilename(filetypes=[("Capture Files", "*.cap"), ("All Files", "*.*")])
        if file:
            p = Path(file).expanduser()
            self.cap_file_var.set(str(p))
            SETTINGS["last_paths"]["cap"] = str(p); save_settings(SETTINGS)

    def _browse_wordlist(self):
        file = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file:
            p = Path(file).expanduser()
            self.wordlist_var.set(str(p))
            SETTINGS["last_paths"]["wordlist"] = str(p); save_settings(SETTINGS)

    # ---------- Output/log panel ----------
    def _populate_output(self):
        t = self.theme; f = self.output_frame
        self.log_text = tk.Text(f, bg=t["bg"], fg=t["fg"], insertbackground=t["accent"], wrap="word", state="disabled")
        self.log_text.pack(side="top", fill="both", expand=True, padx=4, pady=4)
        # Tags
        self.log_text.config(state="normal")
        self.log_text.tag_config("info", foreground=t["fg"])
        self.log_text.tag_config("error", foreground=t["error"])
        self.log_text.tag_config("ok", foreground=t["ok"])
        self.log_text.config(state="disabled")

        # Controls under log
        ctrl = tk.Frame(f, bg=t["panel"]); ctrl.pack(side="bottom", fill="x")
        ttk.Button(ctrl, text="💾 Save Log", command=self._save_current_log).pack(side="left", padx=4, pady=4)
        ttk.Button(ctrl, text="🧹 Clear", command=self._clear_log).pack(side="left", padx=4, pady=4)
        ttk.Button(ctrl, text="📜 Archive Now", command=archive_log_if_needed).pack(side="left", padx=4, pady=4)

        # Start polling queue
        self.after(300, self._poll_log_queue)

    def _append_log_line(self, line: str):
        tag = "info"
        ll = line.lower()
        if "error" in ll or "fail" in ll: tag = "error"
        elif "success" in ll or "ok" in ll: tag = "ok"
        self.log_text.config(state="normal")
        self.log_text.insert("end", line + "\n", tag)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _poll_log_queue(self):
        while not GUI_LOG_QUEUE.empty():
            try: msg = GUI_LOG_QUEUE.get_nowait()
            except queue.Empty: break
            else: self._append_log_line(msg)
        self.after(300, self._poll_log_queue)

    def _save_current_log(self):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = ARCHIVE_DIR / f"log_{ts}.txt"
        try:
            text = self.log_text.get("1.0", "end").strip()
            out_file.write_text(text, encoding="utf-8")
            LOGGER.info(f"Log saved to {out_file}")
            messagebox.showinfo("Log Saved", f"Saved to {out_file}")
        except Exception as e:
            LOGGER.error(f"Saving log failed: {e}")
            messagebox.showerror("Save Failed", str(e))

    def _clear_log(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")
    # ---------- Invocation (threaded) ----------
    def _set_controls_state(self, enabled: bool):
        state = ("!disabled" if enabled else "disabled")
        for w in (self.invoke_btn, self.stop_btn, self.iface_combo, self.theme_combo):
            try:
                if isinstance(w, ttk.Combobox):
                    w.configure(state=("readonly" if enabled else "disabled"))
                else:
                    w.state([state])
            except Exception:
                pass

    def _invoke_ritual(self):
        iface = self.interface_var.get().strip()
        cap_path = Path(self.cap_file_var.get().strip()).expanduser()
        wordlist_path = Path(self.wordlist_var.get().strip()).expanduser()
        bssid = self.bssid_var.get().strip()
        theme_epoch = self.theme_var.get()

        if not iface:
            messagebox.showwarning("Missing Interface", "No interface glyph selected.")
            LOGGER.warning("Invocation aborted: interface missing."); return
        if not cap_path.exists():
            messagebox.showwarning("Missing .cap", "Capture file not found.")
            LOGGER.warning("Invocation aborted: .cap missing."); return
        if not wordlist_path.exists():
            messagebox.showwarning("Missing Passphrase File", "Wordlist file not found.")
            LOGGER.warning("Invocation aborted: passphrase file missing."); return

        LOGGER.info(f"🔮 Ritual invoked | iface={iface} bssid={bssid or '<none>'} theme={theme_epoch}")

        def worker():
            try:
                nets = CORE.call("scan_networks", iface)
                LOGGER.info(f"Scan returned {len(nets) if isinstance(nets, (list, tuple)) else 'unknown'} network(s).")

                cap_result = CORE.call("capture_handshake", iface, bssid if bssid else None)
                LOGGER.info(f"Handshake capture result: {cap_result}")

                crack_result = CORE.call("crack_handshake", cap_path, wordlist_path, bssid if bssid else None)
                LOGGER.info(f"Crack result: {crack_result}")

                ok = isinstance(crack_result, dict) and crack_result.get("status") == "success"
                if ok:
                    key = crack_result.get("key", "<unknown>")
                    LOGGER.info(f"✨ Success — Seal phrase recovered: {key}")
                    self._enqueue_ui(lambda: self._survivability_feedback(True, "Ritual completed."))
                else:
                    LOGGER.warning(f"⚠️ Ritual did not yield a key — result={crack_result}")
                    self._enqueue_ui(lambda: self._survivability_feedback(False, "No key recovered."))
            except Exception as e:
                LOGGER.error(f"Ritual execution error: {e}")
                self._enqueue_ui(lambda: messagebox.showerror("Invocation Error", f"{e}"))
            finally:
                self._enqueue_ui(lambda: self._set_controls_state(True))
                with self._op_lock: self._op_thread = None

        with self._op_lock:
            if self._op_thread is not None:
                messagebox.showinfo("Busy", "A ritual is already in progress."); return
            self._set_controls_state(False)
            self._op_thread = threading.Thread(target=worker, name="RitualWorker", daemon=True)
            self._op_thread.start()

    def _enqueue_ui(self, fn: Callable[[], None], delay_ms: int = 0):
        try:
            self.after(delay_ms, fn)
        except Exception:
            pass

    # ---------- Stop capability ----------
    def _stop_ritual(self):
        try:
            CORE.call("stop_operations")
            LOGGER.info("⏹ Ritual halted by operator.")
            self._survivability_feedback(False, "Halted mid-stream.")
        except Exception as e:
            LOGGER.error(f"Stop operation error: {e}")
            messagebox.showerror("Stop Failed", str(e))

    def _survivability_feedback(self, success: bool, reason: str = ""):
        if success:
            msg = f"🛡️ Ritual completed. Survivability confirmed.\n{reason}"
            LOGGER.info(f"Feedback: {msg}")
            messagebox.showinfo("EchoFrame", msg)
        else:
            msg = f"⚠️ Ritual incomplete — calibration required.\n{reason}"
            LOGGER.warning(f"Feedback: {msg}")
            messagebox.showwarning("EchoFrame", msg)

    # ---------- Theme switching ----------
    def _apply_selected_theme(self):
        theme_name = self.theme_var.get()
        if theme_name not in THEMES:
            LOGGER.warning(f"Unknown theme: {theme_name}, defaulting to {DEFAULT_THEME}")
            theme_name = DEFAULT_THEME
        self.theme = THEMES[theme_name]
        SETTINGS["theme"] = theme_name; save_settings(SETTINGS)
        self.configure(bg=self.theme["bg"])
        self._apply_theme_style()
        for w in self.winfo_children():
            self._recolor_widget(w)
        LOGGER.info(f"Theme switched to: {theme_name}")

    def _recolor_widget(self, widget):
        try:
            if isinstance(widget, (tk.Frame, tk.LabelFrame)):
                widget.configure(bg=self.theme["panel"])
            elif isinstance(widget, tk.Label):
                widget.configure(bg=self.theme["panel"], fg=self.theme["fg"])
            elif isinstance(widget, tk.Text):
                widget.configure(bg=self.theme["bg"], fg=self.theme["fg"], insertbackground=self.theme["accent"])
            for child in widget.winfo_children():
                self._recolor_widget(child)
        except tk.TclError:
            pass

    # ---------- Plug-ins ----------
    def _load_plugins(self):
        if not PLUGIN_DIR.exists():
            LOGGER.info("No plugin directory found; skipping."); return
        # Security: warn if world-writable
        try:
            mode = stat.S_IMODE(os.stat(PLUGIN_DIR).st_mode)
            if mode & stat.S_IWOTH:
                LOGGER.warning(f"Plugin dir {PLUGIN_DIR} is world-writable. Tighten permissions (chmod 700).")
        except Exception:
            pass
        for py_file in sorted(PLUGIN_DIR.glob("*.py")):
            try:
                spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                mod = importlib.util.module_from_spec(spec)
                assert spec and spec.loader
                spec.loader.exec_module(mod)  # type: ignore
                LOGGER.info(f"Plug-in loaded: {py_file.name}")
                if hasattr(mod, "register") and callable(mod.register):
                    try: mod.register(self, CORE, LOGGER); LOGGER.info(f"Plug-in registered: {py_file.name}")
                    except Exception as e: LOGGER.error(f"Plug-in register() failed in {py_file.name}: {e}")
            except Exception as e:
                LOGGER.error(f"Failed to load plug-in {py_file.name}: {e}")

    # ---------- Finalise after gate ----------
    def _init_after_gate(self):
        self._populate_controls()
        self._populate_output()
        self._load_plugins()
        LOGGER.info("Chamber fully initialised.")
# ---------- Entry point ----------
def _headless_env_warning():
    """
    Warn if we're running in a headless Linux session (no X/Wayland),
    since Tkinter GUIs won't launch without a display server.
    """
    if platform.system().lower() == "linux" and not os.environ.get("DISPLAY"):
        sys.stderr.write(
            "No DISPLAY found. This GUI requires an X11/Wayland session.\n"
        )
        return True
    return False


def main():
    """
    Initialise and launch the EchoFrame GUI chamber.
    """
    if _headless_env_warning():
        return 1  # Exit early if no display available

    LOGGER.info(f"{APP_NAME} v{APP_VERSION} initialising…")
    app = EchoFrameApp()

    LOGGER.info("Entering mainloop…")
    try:
        app.mainloop()
    except KeyboardInterrupt:
        LOGGER.warning("Mainloop interrupted by keyboard.")
    finally:
        LOGGER.info("Chamber closed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
