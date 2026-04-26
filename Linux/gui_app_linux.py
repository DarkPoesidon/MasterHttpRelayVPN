#!/usr/bin/env python3
"""Desktop GUI wrapper for MasterHttpRelayVPN (Linux)."""

from __future__ import annotations

import asyncio
import atexit
import json
import logging
import os
import queue
import socket
import threading
import traceback
from pathlib import Path

import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

import mitm
from cert_installer import install_ca, is_ca_trusted
from proxy_server import ProxyServer

APP_NAME = "MasterHttpRelayVPN"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8085


class QueueLogHandler(logging.Handler):
    """Push Python logging records to a thread-safe queue."""

    def __init__(self, out_queue: queue.Queue):
        super().__init__()
        self.out_queue = out_queue

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.out_queue.put(("log", self.format(record)))
        except Exception:
            pass


class ToolTip:
    """Simple tooltip widget for Tk controls."""

    def __init__(self, widget, text: str):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _event=None):
        if self.tip_window is not None:
            return
        x = self.widget.winfo_rootx() + 18
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6

        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw,
            text=self.text,
            justify="left",
            background="#fffce8",
            foreground="#1a1a1a",
            relief="solid",
            borderwidth=1,
            padx=8,
            pady=6,
            font=("DejaVu Sans", 9),
            wraplength=360,
        )
        label.pack()

    def _hide(self, _event=None):
        if self.tip_window is not None:
            self.tip_window.destroy()
            self.tip_window = None


class ProxyController:
    """Run ProxyServer in a dedicated daemon thread with its own event loop."""

    def __init__(self, config: dict, out_queue: queue.Queue):
        self.config = config
        self.out_queue = out_queue
        self.thread: threading.Thread | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.server: asyncio.base_events.Server | None = None
        self.started = threading.Event()
        self.start_error: Exception | None = None
        self.running = False

    def start(self) -> None:
        self.started.clear()
        self.start_error = None
        self.thread = threading.Thread(target=self._run, name="ProxyThread", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        try:
            proxy_server = ProxyServer(self.config)
            self.server = self.loop.run_until_complete(
                asyncio.start_server(
                    proxy_server._on_client,
                    self.config.get("listen_host", PROXY_HOST),
                    self.config.get("listen_port", PROXY_PORT),
                )
            )
            self.running = True
            self.out_queue.put(("log", f"Proxy listening on {PROXY_HOST}:{PROXY_PORT}"))
            self.started.set()

            self.loop.run_until_complete(self.server.serve_forever())
        except asyncio.CancelledError:
            self.started.set()
        except Exception as exc:
            self.start_error = exc
            self.out_queue.put(("log", f"Proxy startup failed: {exc}"))
            self.started.set()
        finally:
            self.running = False
            try:
                if self.server is not None:
                    self.server.close()
                    self.loop.run_until_complete(self.server.wait_closed())
            except Exception:
                pass
            try:
                pending = asyncio.all_tasks(self.loop)
                for task in pending:
                    task.cancel()
                if pending:
                    self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            except Exception:
                pass
            self.loop.close()

    def stop(self, timeout: float = 8.0) -> None:
        if not self.thread:
            return

        if self.loop and self.loop.is_running():
            def _shutdown() -> None:
                if self.server is not None:
                    self.server.close()
                for task in asyncio.all_tasks(self.loop):
                    task.cancel()

            self.loop.call_soon_threadsafe(_shutdown)

        self.thread.join(timeout=timeout)


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("MasterHttpRelayVPN")
        self.root.geometry("720x520")
        self.root.minsize(640, 460)

        self.app_dir = self._resolve_app_dir()
        self.config_path = self.app_dir / "config.json"

        self._configure_mitm_storage()

        self.msg_queue: queue.Queue = queue.Queue()
        self.controller: ProxyController | None = None

        self.connected = False
        self.busy = False
        self.show_password = tk.BooleanVar(value=False)
        self.deployment_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.status_text = tk.StringVar(value="Disconnected")
        self.status_hint = tk.StringVar(value="Not connected")

        self._install_logging_bridge()
        self._setup_style()
        self._build_ui()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(120, self._drain_queue)

        atexit.register(self._cleanup_on_exit)

        self._emit_log("Local environment initialized successfully.")
        if not self.config_path.exists():
            self._emit_log("First run detected. Follow Quick Start, then click Connect.")

    def _resolve_app_dir(self) -> Path:
        src_dir = Path(__file__).resolve().parent
        if not getattr(sys, "frozen", False):
            return src_dir

        # On Linux, store runtime data in ~/.local/share/<APP_NAME>.
        xdg_data = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        path = Path(xdg_data) / APP_NAME
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _configure_mitm_storage(self) -> None:
        ca_dir = self.app_dir / "ca"
        ca_dir.mkdir(parents=True, exist_ok=True)
        mitm.CA_DIR = str(ca_dir)
        mitm.CA_KEY_FILE = str(ca_dir / "ca.key")
        mitm.CA_CERT_FILE = str(ca_dir / "ca.crt")

    def _install_logging_bridge(self) -> None:
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)

        queue_handler = QueueLogHandler(self.msg_queue)
        queue_handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s", "%H:%M:%S"))

        for handler in list(root_logger.handlers):
            if isinstance(handler, QueueLogHandler):
                root_logger.removeHandler(handler)

        root_logger.addHandler(queue_handler)

    def _setup_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")

        bg = "#f2f5f9"
        card = "#ffffff"
        accent = "#0f4c81"

        self.root.configure(bg=bg)
        style.configure("Main.TFrame", background=bg)
        style.configure("Card.TFrame", background=card)
        style.configure("TLabel", background=card, foreground="#203040", font=("DejaVu Sans", 10))
        style.configure("Title.TLabel", background=card, foreground="#0b2e4f", font=("DejaVu Sans Bold", 16))
        style.configure("TEntry", padding=6, font=("DejaVu Sans", 10))
        style.configure("Action.TButton", font=("DejaVu Sans Bold", 12), padding=10)
        style.map("Action.TButton", background=[("active", accent), ("!disabled", accent)], foreground=[("!disabled", "white")])

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, style="Main.TFrame", padding=16)
        main.pack(fill="both", expand=True)

        card = ttk.Frame(main, style="Card.TFrame", padding=16)
        card.pack(fill="both", expand=True)

        ttk.Label(card, text="MasterHttpRelayVPN", style="Title.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
        ttk.Label(card, text="Enter your Google Apps Script deployment settings and connect.").grid(
            row=1, column=0, columnspan=3, sticky="w", pady=(2, 14)
        )

        quick_start = (
            "Quick Start (First Run):\n"
            "1) Paste your Google Deployment ID.\n"
            "2) Enter the same Auth Password you set in Code.gs.\n"
            "3) Click Connect and wait for verification.\n"
            "4) A green status means proxy + relay are working.\n"
            "5) Set your system proxy manually to 127.0.0.1:8085."
        )
        ttk.Label(card, text=quick_start, foreground="#2f3f55", justify="left").grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(0, 10)
        )

        ttk.Label(card, text="Google Deployment ID").grid(row=3, column=0, sticky="w")
        self.deployment_entry = ttk.Entry(card, textvariable=self.deployment_var, width=62)
        self.deployment_entry.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(2, 10))

        ttk.Label(card, text="Auth Password").grid(row=5, column=0, sticky="w")
        self.password_entry = ttk.Entry(card, textvariable=self.password_var, width=48, show="*")
        self.password_entry.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(2, 10))

        self.toggle_btn = ttk.Button(card, text="Show", width=10, command=self._toggle_password)
        self.toggle_btn.grid(row=6, column=2, sticky="e", padx=(8, 0), pady=(2, 10))

        self.status_badge = tk.Label(
            card,
            textvariable=self.status_text,
            bg="#7a1c1c",
            fg="white",
            padx=10,
            pady=4,
            font=("DejaVu Sans Bold", 10),
        )
        self.status_badge.grid(row=7, column=0, sticky="w", pady=(0, 8))

        ttk.Label(card, textvariable=self.status_hint, foreground="#5b6779").grid(row=7, column=1, columnspan=2, sticky="e")

        self.connect_btn = ttk.Button(card, text="Connect", style="Action.TButton", command=self.on_connect_disconnect)
        self.connect_btn.grid(row=8, column=0, columnspan=3, sticky="ew", pady=(2, 12))

        ttk.Label(card, text="Status Log").grid(row=9, column=0, sticky="w")

        self.log_box = ScrolledText(card, height=14, wrap="word", font=("Monospace", 9), bg="#0d1117", fg="#e6edf3")
        self.log_box.grid(row=10, column=0, columnspan=3, sticky="nsew", pady=(4, 0))
        self.log_box.configure(state="disabled")

        ToolTip(self.deployment_entry, "Paste the Deployment ID from Google Apps Script > Deploy > Web app.")
        ToolTip(self.password_entry, "Use the same AUTH_KEY value you configured in Code.gs.")
        ToolTip(self.toggle_btn, "Show or hide your password text.")
        ToolTip(self.connect_btn, "Connect: generate config, install cert, start relay, then verify health.")

        card.columnconfigure(0, weight=1)
        card.columnconfigure(1, weight=1)
        card.rowconfigure(10, weight=1)

    def _toggle_password(self) -> None:
        show = self.show_password.get()
        self.show_password.set(not show)
        self.password_entry.configure(show="" if not show else "*")
        self.toggle_btn.configure(text="Hide" if not show else "Show")

    def _emit_log(self, text: str) -> None:
        self.msg_queue.put(("log", text))

    def _emit_state(self, connected: bool) -> None:
        self.msg_queue.put(("state", connected))

    def _emit_status(self, text: str, color: str, hint: str) -> None:
        self.msg_queue.put(("status", {"text": text, "color": color, "hint": hint}))

    def _set_busy(self, busy: bool) -> None:
        self.msg_queue.put(("busy", busy))

    def _append_log(self, text: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _drain_queue(self) -> None:
        while True:
            try:
                event, payload = self.msg_queue.get_nowait()
            except queue.Empty:
                break

            if event == "log":
                self._append_log(payload)
            elif event == "state":
                self.connected = bool(payload)
                self.connect_btn.configure(text="Disconnect" if self.connected else "Connect")
            elif event == "busy":
                self.busy = bool(payload)
                state = "disabled" if self.busy else "normal"
                self.connect_btn.configure(state=state)
                self.toggle_btn.configure(state=state)
            elif event == "status":
                self.status_text.set(payload["text"])
                self.status_hint.set(payload["hint"])
                self.status_badge.configure(bg=payload["color"])

        self.root.after(120, self._drain_queue)

    def _build_config(self, script_id: str, auth_key: str) -> dict:
        return {
            "mode": "apps_script",
            "google_ip": "216.239.38.120",
            "front_domain": "www.google.com",
            "script_id": script_id,
            "auth_key": auth_key,
            "listen_host": PROXY_HOST,
            "listen_port": PROXY_PORT,
            "log_level": "INFO",
            "verify_ssl": True,
            "hosts": {},
        }

    def _write_config(self, config: dict) -> None:
        with self.config_path.open("w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2)

    def _ensure_certificate(self) -> bool:
        from mitm import CA_CERT_FILE, MITMCertManager

        MITMCertManager()  # Ensures CA files exist.

        if is_ca_trusted(CA_CERT_FILE):
            self._emit_log("Certificate already trusted.")
            return True

        self._emit_log("Installing certificate (may require sudo or manual trust)...")
        ok = install_ca(CA_CERT_FILE)
        if ok:
            self._emit_log("Certificate installed successfully.")
        else:
            self._emit_log(
                "Certificate install failed. "
                f"You may need to manually trust: {CA_CERT_FILE}"
            )
        return ok

    def _verify_proxy_health(self) -> bool:
        """Send a small HTTP probe through local proxy to confirm relay path works."""
        probes = [
            "http://example.com/",
            "http://neverssl.com/",
        ]
        for probe_url in probes:
            try:
                self._emit_log(f"Health-check via proxy: {probe_url}")
                with socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=10) as sock:
                    sock.settimeout(10)
                    host = probe_url.split("//", 1)[1].split("/", 1)[0]
                    request = (
                        f"GET {probe_url} HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        "Connection: close\r\n"
                        "User-Agent: MasterHttpRelayVPN-HealthCheck\r\n"
                        "\r\n"
                    ).encode("ascii")
                    sock.sendall(request)
                    data = sock.recv(4096)
                    status_line = data.split(b"\r\n", 1)[0].decode(errors="replace")

                if status_line.startswith("HTTP/") and " 5" not in status_line:
                    self._emit_log(f"Health-check OK: {status_line}")
                    return True
                self._emit_log(f"Health-check received unexpected response: {status_line}")
            except Exception as exc:
                self._emit_log(f"Health-check failed for {probe_url}: {exc}")
        return False

    def on_connect_disconnect(self) -> None:
        if self.busy:
            return

        if self.connected:
            threading.Thread(target=self._disconnect_worker, daemon=True).start()
            return

        script_id = self.deployment_var.get().strip()
        auth_key = self.password_var.get().strip()
        if not script_id or not auth_key:
            messagebox.showerror("Missing Information", "Deployment ID and Auth Password are required.")
            return

        threading.Thread(target=self._connect_worker, args=(script_id, auth_key), daemon=True).start()

    def _connect_worker(self, script_id: str, auth_key: str) -> None:
        self._set_busy(True)
        self._emit_status("Connecting...", "#8a6d1a", "Starting proxy and verifying relay")
        try:
            self._emit_log("Generating config.json...")
            config = self._build_config(script_id, auth_key)
            self._write_config(config)
            self._emit_log(f"Saved config: {self.config_path}")

            self._ensure_certificate()

            self._emit_log("Starting proxy in background thread...")
            self.controller = ProxyController(config, self.msg_queue)
            self.controller.start()

            started = self.controller.started.wait(timeout=12)
            if not started:
                raise RuntimeError("Proxy start timed out.")
            if self.controller.start_error:
                raise self.controller.start_error

            if not self._verify_proxy_health():
                raise RuntimeError("Proxy started but relay health-check failed.")

            self._emit_state(True)
            self._emit_status("Connected", "#1f7a3b", "Verified and working")
            self._emit_log("Connected! Please set your Linux system proxy manually to 127.0.0.1:8085")
        except OSError as exc:
            self._emit_log(f"OS error: {exc}")
            self._emit_log("If the port is already in use, close the conflicting app and retry.")
            self._emit_status("Disconnected", "#7a1c1c", "Connection failed")
            self._safe_disconnect_internal()
        except Exception as exc:
            self._emit_log(f"Connection failed: {exc}")
            self._emit_log(traceback.format_exc().strip())
            self._emit_status("Disconnected", "#7a1c1c", "Connection failed")
            self._safe_disconnect_internal()
        finally:
            self._set_busy(False)

    def _safe_disconnect_internal(self) -> None:
        try:
            if self.controller:
                self.controller.stop()
        except Exception:
            pass
        finally:
            self.controller = None

        self._emit_state(False)
        self._emit_status("Disconnected", "#7a1c1c", "Proxy stopped")

    def _disconnect_worker(self) -> None:
        self._set_busy(True)
        try:
            self._emit_log("Disconnecting...")
            self._safe_disconnect_internal()
            self._emit_log("Disconnected. Remember to remove the manual proxy setting from your system network settings.")
        finally:
            self._set_busy(False)

    def _cleanup_on_exit(self) -> None:
        try:
            self._safe_disconnect_internal()
        except Exception:
            pass

    def on_close(self) -> None:
        if self.busy:
            if not messagebox.askyesno("Please Wait", "A connection task is running. Force close and cleanup?"):
                return

        self._cleanup_on_exit()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
