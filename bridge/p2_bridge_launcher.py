#!/usr/bin/env python3
"""
p2_bridge_launcher.py — Configurator and launcher GUI for the P2-BACnet Bridge.

A friendlier path than editing JSON in Notepad and running PowerShell commands
by hand. Lets the user:
  - Edit site.json (P2 config: network, scanner name, known nodes) via a form
  - Edit bridge_config.json (BACnet identity, polling, address) via a form
  - Build / refresh / inspect manifest.json
  - Launch the bridge in a new console window

The bridge runtime itself is unchanged — this GUI shells out to the same
`p2_bacnet_bridge.py` and `tools/build_manifest.py` you would run from the
command line. So the GUI is optional. Power users can still skip it.

Single file by design (matches the p2_gui.py style of the underlying P2
Scanner project). Stdlib only except for the bridge's existing bacpypes3
dependency. Optional psutil enhances NIC detection but is not required.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import re
from collections import Counter
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import ttk, messagebox, simpledialog
from typing import Any, Dict, List, Optional, Tuple

# Resolve install paths so the GUI works whether launched from its own
# directory or from elsewhere.
HERE = Path(__file__).resolve().parent
SITE_PATH = HERE / "site.json"
BRIDGE_CONFIG_PATH = HERE / "bridge_config.json"
MANIFEST_PATH = HERE / "manifest.json"
#: Diagnostics for the launcher itself. The GUI reports to the user through
#: widgets; this is for the things a user cannot act on -- a child process
#: that would not die, a widget destroyed before its callback fired.
LOG = logging.getLogger(__name__)

LOG_PATH = HERE / "p2_bacnet_bridge.log"

SITE_EXAMPLE = HERE / "site.json.example"
BRIDGE_CONFIG_EXAMPLE = HERE / "bridge_config.json.example"

PYTHON_EXE = sys.executable

# Single source of truth: p2_bridge/__init__.py.__version__.
# Import lazily so the launcher still starts with a helpful error if
# p2_bridge can't be loaded (rather than crashing on a missing import
# before the user-facing error path runs).
try:
    sys.path.insert(0, str(HERE))
    from p2_bridge import __version__ as APP_VERSION  # noqa: E402
except ImportError:
    APP_VERSION = "?"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_local_interfaces() -> List[Tuple[str, str]]:
    """Return [(label, ip), ...] for IPv4 NICs on this host.

    Uses psutil if available (gives interface names like 'Ethernet'). Falls
    back to socket.getaddrinfo, which finds IPs but doesn't label them.
    Always includes 0.0.0.0 (any) and 127.0.0.1 (loopback) at the end.
    """
    results: List[Tuple[str, str]] = []
    try:
        import psutil  # type: ignore
        for ifname, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address and not a.address.startswith("169.254"):
                    results.append((f"{ifname} ({a.address})", a.address))
    except ImportError:
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                ip = info[4][0]
                if ip and not ip.startswith("127."):
                    label = ip
                    if (label, ip) not in results:
                        results.append((label, ip))
        except socket.gaierror:
            pass

    if not any(ip == "127.0.0.1" for _, ip in results):
        results.append(("Loopback (127.0.0.1)", "127.0.0.1"))
    results.append(("Any interface (0.0.0.0)", "0.0.0.0"))
    return results


def parse_bacnet_address(addr: str) -> Tuple[str, int, int]:
    """Parse 'IP/PREFIX:PORT' into (ip, prefix, port). Defaults: /24, :47808."""
    m = re.match(r"^([0-9.]+)(?:/(\d+))?(?::(\d+))?$", addr.strip())
    if not m:
        return ("0.0.0.0", 24, 47808)
    ip = m.group(1)
    prefix = int(m.group(2)) if m.group(2) else 24
    port = int(m.group(3)) if m.group(3) else 47808
    return (ip, prefix, port)


def format_bacnet_address(ip: str, prefix: int, port: int) -> str:
    return f"{ip}/{prefix}:{port}"


def atomic_write_json(path: Path, data: dict) -> None:
    """Write JSON atomically — never leave a half-written file the bridge could pick up."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def load_json_with_fallback(path: Path, fallback: Path) -> dict:
    """Load JSON from path, or from fallback (the .example) if path doesn't exist."""
    src = path if path.exists() else fallback
    if not src.exists():
        return {}
    with open(src, encoding="utf-8") as f:
        return json.load(f)


def strip_comment_keys(d: dict) -> dict:
    """Remove _comment-* keys before saving so they don't accumulate."""
    return {k: v for k, v in d.items() if not k.startswith("_")}


# ─────────────────────────────────────────────────────────────────────────────
# Subprocess output streamer
# ─────────────────────────────────────────────────────────────────────────────

class SubprocessRunner:
    """Run a command, stream stdout/stderr into a Tk Text widget on the main thread.

    Thread-safe: the worker reads bytes off the pipe; the GUI thread polls a
    queue at ~50ms intervals and appends to the widget. Lifted nearly
    verbatim from the queue+drain pattern in p2_gui_workers.py.
    """

    def __init__(self, text_widget: tk.Text, on_finished=None) -> None:
        self.text_widget = text_widget
        self.on_finished = on_finished
        self.q: "queue.Queue[Optional[str]]" = queue.Queue()
        self.proc: Optional[subprocess.Popen] = None
        self.worker: Optional[threading.Thread] = None
        self._running = False
        self._poll_after_id: Optional[str] = None

    @property
    def running(self) -> bool:
        return self._running

    def run(self, args: List[str], cwd: Optional[Path] = None) -> None:
        if self._running:
            return
        self._running = True
        self.text_widget.configure(state="normal")
        self.text_widget.insert("end", f"$ {' '.join(args)}\n")
        self.text_widget.see("end")
        self.text_widget.configure(state="disabled")

        # Force UTF-8 in the child Python so emoji / Unicode in scanner
        # output don't trip cp1252 on Windows. Without this, the child's
        # sys.stdout falls back to the OS code page and any non-ASCII
        # character (e.g. the ✓ in the scanner's progress prints) raises
        # UnicodeEncodeError.
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"

        try:
            self.proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(cwd) if cwd else None,
                env=env,
            )
        except FileNotFoundError as e:
            self._append(f"\n[ERROR] {e}\n")
            self._running = False
            return

        self.worker = threading.Thread(target=self._read_pipe, daemon=True)
        self.worker.start()
        self._poll_queue()

    def stop(self, timeout: float = 5.0) -> None:
        """Terminate the child, and escalate to kill if it ignores that.

        `terminate()` alone is a request. A child that blocks on a socket read
        -- which a scan against an unreachable panel does -- may not act on it,
        and then it outlives the window that started it.
        """
        self._cancel_poll()
        proc = self.proc
        if proc is None or proc.poll() is not None:
            self._running = False
            return
        try:
            proc.terminate()
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=timeout)
        except OSError as e:
            # Already reaped, or the handle is gone. Nothing left to stop.
            LOG.debug("stopping child process: %s", e)
        finally:
            self._running = False

    def _cancel_poll(self) -> None:
        """Drop the pending `after()` callback so it cannot fire post-destroy."""
        if self._poll_after_id is not None:
            try:
                self.text_widget.after_cancel(self._poll_after_id)
            except tk.TclError:
                pass       # widget already destroyed
            self._poll_after_id = None

    def _read_pipe(self) -> None:
        try:
            # Not an `assert`: this runs under -O in a frozen build, where
            # asserts are stripped and this would become an AttributeError
            # inside a thread, which is a silent hang rather than an error.
            if not (self.proc and self.proc.stdout):
                return
            for line in self.proc.stdout:
                self.q.put(line)
        except Exception as e:
            self.q.put(f"[reader error] {e}\n")
        finally:
            if self.proc:
                self.proc.wait()
            self.q.put(None)  # sentinel

    def _poll_queue(self) -> None:
        try:
            while True:
                item = self.q.get_nowait()
                if item is None:
                    self._running = False
                    rc = self.proc.returncode if self.proc else None
                    self._append(f"\n[exit code: {rc}]\n")
                    if self.on_finished:
                        try:
                            self.on_finished(rc)
                        except Exception:
                            pass
                    return
                self._append(item)
        except queue.Empty:
            pass
        if self._running:
            self._poll_after_id = self.text_widget.after(80, self._poll_queue)

    def _append(self, s: str) -> None:
        self.text_widget.configure(state="normal")
        self.text_widget.insert("end", s)
        self.text_widget.see("end")
        self.text_widget.configure(state="disabled")


# ─────────────────────────────────────────────────────────────────────────────
# Main app
# ─────────────────────────────────────────────────────────────────────────────

class BridgeLauncherApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"P2-BACnet Bridge Configurator v{APP_VERSION}")
        self.root.geometry("1000x720")
        self.root.minsize(800, 600)

        # Tracked subprocess for the bridge runtime (Run tab)
        self.bridge_process: Optional[subprocess.Popen] = None

        # State models
        self.site_data: Dict[str, Any] = {}
        self.bridge_data: Dict[str, Any] = {}

        self._build_ui()
        self._load_site()
        self._load_bridge_config()
        self._refresh_manifest_stats()
        self._refresh_run_status()
        self._poll_run_status()

    # ─── UI scaffolding ─────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=8)

        self.tab_site = ttk.Frame(self.notebook)
        self.tab_bridge = ttk.Frame(self.notebook)
        self.tab_manifest = ttk.Frame(self.notebook)
        self.tab_run = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_site, text=" 1. Site (P2 Config) ")
        self.notebook.add(self.tab_bridge, text=" 2. BACnet Config ")
        self.notebook.add(self.tab_manifest, text=" 3. Manifest ")
        self.notebook.add(self.tab_run, text=" 4. Run Bridge ")

        self._build_site_tab()
        self._build_bridge_tab()
        self._build_manifest_tab()
        self._build_run_tab()

        # Status bar at bottom
        self.status_var = tk.StringVar(value="Ready.")
        status = ttk.Label(self.root, textvariable=self.status_var,
                           relief="sunken", anchor="w", padding=(6, 2))
        status.pack(fill="x", side="bottom")

    def active_runners(self) -> List["SubprocessRunner"]:
        """Every SubprocessRunner this window owns, for shutdown.

        Collected by inspection rather than kept in a list, because runners are
        created lazily per tab and a hand-maintained registry is exactly the
        kind of thing that goes stale when a tab is added.
        """
        return [v for v in vars(self).values() if isinstance(v, SubprocessRunner)]

    def set_status(self, msg: str) -> None:
        self.status_var.set(msg)

    # ─── Tab 1: Site config ─────────────────────────────────────────────────

    def _build_site_tab(self) -> None:
        f = self.tab_site
        for c in (1,):
            f.columnconfigure(c, weight=1)

        intro = ttk.Label(f, text=(
            "P2 site identity. These are the same fields as the P2 Scanner's site.json — "
            "you can copy a working site.json from the scanner instead of filling in by hand."
        ), wraplength=900, foreground="#444")
        intro.grid(row=0, column=0, columnspan=3, sticky="w", padx=10, pady=(10, 12))

        ttk.Label(f, text="P2 Network (BLN name):").grid(
            row=1, column=0, sticky="e", padx=(10, 4), pady=4)
        self.site_network_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.site_network_var, width=40).grid(
            row=1, column=1, sticky="ew", padx=4, pady=4)
        ttk.Label(f, text="(your BLN name, e.g. MYBLN)", foreground="#777").grid(
            row=1, column=2, sticky="w", padx=(4, 10), pady=4)

        ttk.Label(f, text="P2 Site:").grid(
            row=2, column=0, sticky="e", padx=(10, 4), pady=4)
        self.site_site_var = tk.StringVar(value="SITE")
        ttk.Entry(f, textvariable=self.site_site_var, width=40).grid(
            row=2, column=1, sticky="ew", padx=4, pady=4)
        ttk.Label(f, text="(usually SITE)", foreground="#777").grid(
            row=2, column=2, sticky="w", padx=(4, 10), pady=4)

        ttk.Label(f, text="Scanner Name:").grid(
            row=3, column=0, sticky="e", padx=(10, 4), pady=4)
        self.site_scanner_var = tk.StringVar(value="P2BRIDGE|5034")
        ttk.Entry(f, textvariable=self.site_scanner_var, width=40).grid(
            row=3, column=1, sticky="ew", padx=4, pady=4)
        ttk.Label(f, text="(format: NAME|5034)", foreground="#777").grid(
            row=3, column=2, sticky="w", padx=(4, 10), pady=4)

        # Nodes frame
        nodes_frame = ttk.LabelFrame(f, text="Known Nodes (PXC controllers)")
        nodes_frame.grid(row=4, column=0, columnspan=3, sticky="nsew",
                         padx=10, pady=(14, 4))
        f.rowconfigure(4, weight=1)
        nodes_frame.columnconfigure(0, weight=1)
        nodes_frame.rowconfigure(0, weight=1)

        # Treeview
        tv_frame = ttk.Frame(nodes_frame)
        tv_frame.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
        tv_frame.columnconfigure(0, weight=1)
        tv_frame.rowconfigure(0, weight=1)

        cols = ("name", "ip")
        self.nodes_tree = ttk.Treeview(tv_frame, columns=cols, show="headings",
                                       height=8, selectmode="browse")
        self.nodes_tree.heading("name", text="Node Name")
        self.nodes_tree.heading("ip", text="IP Address")
        self.nodes_tree.column("name", width=200, anchor="w")
        self.nodes_tree.column("ip", width=150, anchor="w")
        self.nodes_tree.grid(row=0, column=0, sticky="nsew")

        sb = ttk.Scrollbar(tv_frame, orient="vertical",
                           command=self.nodes_tree.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.nodes_tree.configure(yscrollcommand=sb.set)
        self.nodes_tree.bind("<Double-1>", lambda e: self._edit_node())

        # Node buttons
        node_btns = ttk.Frame(nodes_frame)
        node_btns.grid(row=0, column=1, sticky="ns", padx=(0, 6), pady=6)
        ttk.Button(node_btns, text="Add",
                   command=self._add_node).pack(fill="x", pady=2)
        ttk.Button(node_btns, text="Edit",
                   command=self._edit_node).pack(fill="x", pady=2)
        ttk.Button(node_btns, text="Remove",
                   command=self._remove_node).pack(fill="x", pady=2)
        ttk.Separator(node_btns, orient="horizontal").pack(fill="x", pady=8)
        ttk.Button(node_btns, text="Test Connection",
                   command=self._test_node_connection).pack(fill="x", pady=2)
        ttk.Button(node_btns, text="Cold Discover…",
                   command=self._cold_discover).pack(fill="x", pady=2)

        # Footer save/reload
        footer = ttk.Frame(f)
        footer.grid(row=5, column=0, columnspan=3, sticky="ew", padx=10, pady=(4, 10))
        ttk.Button(footer, text="Save site.json",
                   command=self._save_site).pack(side="right", padx=4)
        ttk.Button(footer, text="Reload",
                   command=self._load_site).pack(side="right", padx=4)
        ttk.Label(footer, text=f"File: {SITE_PATH.name}",
                  foreground="#777").pack(side="left")

    def _load_site(self) -> None:
        try:
            self.site_data = load_json_with_fallback(SITE_PATH, SITE_EXAMPLE)
        except Exception as e:
            messagebox.showerror("Load error", f"Could not read site.json: {e}")
            return
        self.site_network_var.set(self.site_data.get("p2_network", ""))
        self.site_site_var.set(self.site_data.get("p2_site", "SITE"))
        self.site_scanner_var.set(self.site_data.get("scanner_name", "P2BRIDGE|5034"))
        self.nodes_tree.delete(*self.nodes_tree.get_children())
        for name, ip in (self.site_data.get("known_nodes") or {}).items():
            self.nodes_tree.insert("", "end", values=(name, ip))
        self.set_status(f"Loaded {SITE_PATH.name}")

    def _save_site(self) -> None:
        net = self.site_network_var.get().strip()
        if not net:
            messagebox.showerror("Validation", "P2 Network (BLN name) is required.")
            return
        scanner = self.site_scanner_var.get().strip() or "P2BRIDGE|5034"
        site = self.site_site_var.get().strip() or "SITE"
        nodes = {}
        for iid in self.nodes_tree.get_children():
            name, ip = self.nodes_tree.item(iid)["values"]
            if name and ip:
                nodes[str(name)] = str(ip)
        if not nodes:
            messagebox.showerror("Validation",
                "At least one known node is required. Use Add or Cold Discover.")
            return

        new_data = strip_comment_keys(self.site_data)
        new_data.update({
            "p2_network": net,
            "p2_site": site,
            "scanner_name": scanner,
            "known_nodes": nodes,
        })
        try:
            atomic_write_json(SITE_PATH, new_data)
        except Exception as e:
            messagebox.showerror("Save error", f"{e}")
            return
        self.site_data = new_data
        self.set_status(f"Saved {SITE_PATH.name}")
        messagebox.showinfo("Saved", f"Wrote {SITE_PATH}")

    def _add_node(self) -> None:
        name = simpledialog.askstring("Add Node", "Node name (e.g. NODE3):", parent=self.root)
        if not name:
            return
        ip = simpledialog.askstring("Add Node", f"IP address for {name}:", parent=self.root)
        if not ip:
            return
        self.nodes_tree.insert("", "end", values=(name.strip().upper(), ip.strip()))

    def _edit_node(self) -> None:
        sel = self.nodes_tree.selection()
        if not sel:
            return
        name, ip = self.nodes_tree.item(sel[0])["values"]
        new_name = simpledialog.askstring("Edit Node", "Node name:",
                                          initialvalue=str(name), parent=self.root)
        if new_name is None:
            return
        new_ip = simpledialog.askstring("Edit Node", "IP address:",
                                        initialvalue=str(ip), parent=self.root)
        if new_ip is None:
            return
        self.nodes_tree.item(sel[0],
                             values=(new_name.strip().upper(), new_ip.strip()))

    def _remove_node(self) -> None:
        sel = self.nodes_tree.selection()
        if not sel:
            return
        name = self.nodes_tree.item(sel[0])["values"][0]
        if messagebox.askyesno("Remove node", f"Remove {name}?"):
            self.nodes_tree.delete(sel[0])

    def _test_node_connection(self) -> None:
        sel = self.nodes_tree.selection()
        if not sel:
            messagebox.showinfo("Test connection",
                "Select a node first.")
            return
        name, ip = self.nodes_tree.item(sel[0])["values"]
        net = self.site_network_var.get().strip()
        scanner = self.site_scanner_var.get().strip() or "P2BRIDGE|5034"
        if not net:
            messagebox.showerror("Test connection",
                "Set P2 Network (BLN name) first.")
            return

        # Run a one-shot --info via the scanner library, capture result
        self.set_status(f"Testing {name} at {ip}…")
        self.root.update_idletasks()

        py = (
            "import sys, p2_scanner as p2; "
            f"p2.P2_NETWORK='{net}'; p2.SCANNER_NAME='{scanner}'; "
            f"info = p2.get_node_info('{ip}', '{str(name).lower()}'); "
            "print('OK', info) if info else (print('FAIL — no response') or sys.exit(1))"
        )
        try:
            test_env = os.environ.copy()
            test_env["PYTHONIOENCODING"] = "utf-8"
            test_env["PYTHONUTF8"] = "1"
            r = subprocess.run(
                [PYTHON_EXE, "-c", py],
                cwd=str(HERE),
                capture_output=True, text=True, timeout=15,
                encoding="utf-8", errors="replace",
                env=test_env,
            )
        except subprocess.TimeoutExpired:
            messagebox.showerror("Test connection",
                f"Timed out after 15s talking to {ip}.\n\n"
                "Check the IP and that you can reach TCP/5033.")
            self.set_status("Test timed out")
            return

        out = (r.stdout or "") + (r.stderr or "")
        if r.returncode == 0 and "OK" in out:
            messagebox.showinfo("Test connection",
                f"{name} ({ip}) responded:\n\n{out.strip()}")
            self.set_status(f"Test OK: {name}")
        else:
            messagebox.showerror("Test connection",
                f"{name} ({ip}) did not respond cleanly.\n\n"
                f"Output:\n{out.strip() or '(no output)'}")
            self.set_status(f"Test failed: {name}")

    def _cold_discover(self) -> None:
        rng = simpledialog.askstring("Cold Discover",
            "IP range to scan (e.g. 192.168.1.0/24, 192.168.1.1-254, "
            "or 192.168.1):",
            parent=self.root)
        if not rng:
            return

        win = tk.Toplevel(self.root)
        win.title("Cold Discover")
        win.geometry("780x500")
        win.transient(self.root)

        text = tk.Text(win, wrap="none", state="disabled",
                       font=("Consolas", 9), bg="#0e0e0e", fg="#ddd")
        text.pack(fill="both", expand=True, padx=6, pady=6)

        btn_frame = ttk.Frame(win)
        btn_frame.pack(fill="x", padx=6, pady=(0, 6))
        close_btn = ttk.Button(btn_frame, text="Close",
                               command=win.destroy)
        close_btn.pack(side="right")

        def on_done(rc):
            self.set_status(f"Cold discover finished (rc={rc})")
            # After save, --save populates site.json on disk; reload to
            # bring those nodes into the GUI.
            self._load_site()

        runner = SubprocessRunner(text, on_finished=on_done)
        # Use scanner's --cold-discover with --save, so it writes site.json
        # alongside us. We then reload our view.
        args = [PYTHON_EXE, "-u", "p2_scanner.py",
                "--cold-discover", "--range", rng,
                "--save", str(SITE_PATH)]
        runner.run(args, cwd=HERE)
        self.set_status("Cold discover running…")

    # ─── Tab 2: Bridge config ───────────────────────────────────────────────

    def _build_bridge_tab(self) -> None:
        f = self.tab_bridge
        f.columnconfigure(1, weight=1)

        intro = ttk.Label(f, text=(
            "BACnet identity and runtime knobs. The defaults work for most installs. "
            "If a supervisor on your network already uses a device instance, pick a different one."
        ), wraplength=900, foreground="#444")
        intro.grid(row=0, column=0, columnspan=3, sticky="w", padx=10, pady=(10, 12))

        # ─── Identity ───
        idn = ttk.LabelFrame(f, text="BACnet Device Identity")
        idn.grid(row=1, column=0, columnspan=3, sticky="ew", padx=10, pady=4)
        idn.columnconfigure(1, weight=1)

        self.bc_instance_var = tk.IntVar(value=599001)
        self.bc_name_var = tk.StringVar(value="P2-Bridge")
        self.bc_desc_var = tk.StringVar(value="P2-to-BACnet Bridge for APOGEE PXC controllers")

        ttk.Label(idn, text="Device instance:").grid(row=0, column=0, sticky="e", padx=4, pady=2)
        ttk.Spinbox(idn, from_=0, to=4194302, increment=1,
                    textvariable=self.bc_instance_var, width=12).grid(
            row=0, column=1, sticky="w", padx=4, pady=2)
        ttk.Label(idn, text="(0..4194302; pick one that doesn't collide on your BACnet net)",
                  foreground="#777").grid(row=0, column=2, sticky="w", padx=4, pady=2)

        ttk.Label(idn, text="Device name:").grid(row=1, column=0, sticky="e", padx=4, pady=2)
        ttk.Entry(idn, textvariable=self.bc_name_var, width=40).grid(
            row=1, column=1, columnspan=2, sticky="w", padx=4, pady=2)

        ttk.Label(idn, text="Description:").grid(row=2, column=0, sticky="e", padx=4, pady=2)
        ttk.Entry(idn, textvariable=self.bc_desc_var).grid(
            row=2, column=1, columnspan=2, sticky="ew", padx=4, pady=2)

        # ─── Network binding ───
        net_lf = ttk.LabelFrame(f, text="BACnet Network Binding")
        net_lf.grid(row=2, column=0, columnspan=3, sticky="ew", padx=10, pady=4)
        net_lf.columnconfigure(1, weight=1)

        ttk.Label(net_lf, text="Bind interface:").grid(row=0, column=0, sticky="e", padx=4, pady=2)
        self.bc_iface_var = tk.StringVar()
        self.bc_iface_combo = ttk.Combobox(net_lf, textvariable=self.bc_iface_var, width=42)
        self.bc_iface_combo.grid(row=0, column=1, sticky="ew", padx=4, pady=2)
        self._populate_iface_combo()
        ttk.Button(net_lf, text="Refresh",
                   command=self._populate_iface_combo).grid(
            row=0, column=2, sticky="w", padx=4, pady=2)

        ttk.Label(net_lf, text="IP / Prefix:").grid(row=1, column=0, sticky="e", padx=4, pady=2)
        self.bc_ip_var = tk.StringVar(value="0.0.0.0")
        self.bc_prefix_var = tk.IntVar(value=24)
        ip_row = ttk.Frame(net_lf)
        ip_row.grid(row=1, column=1, columnspan=2, sticky="w", padx=4, pady=2)
        ttk.Entry(ip_row, textvariable=self.bc_ip_var, width=18).pack(side="left")
        ttk.Label(ip_row, text=" / ").pack(side="left")
        ttk.Spinbox(ip_row, from_=8, to=32, textvariable=self.bc_prefix_var,
                    width=4).pack(side="left")

        ttk.Label(net_lf, text="UDP port:").grid(row=2, column=0, sticky="e", padx=4, pady=2)
        self.bc_port_var = tk.IntVar(value=47808)
        ttk.Spinbox(net_lf, from_=1024, to=65535, increment=1,
                    textvariable=self.bc_port_var, width=8).grid(
            row=2, column=1, sticky="w", padx=4, pady=2)
        ttk.Label(net_lf, text="(47808 = 0xBAC0, the standard)",
                  foreground="#777").grid(row=2, column=2, sticky="w", padx=4, pady=2)

        # When the user picks an interface, fill IP automatically
        self.bc_iface_combo.bind("<<ComboboxSelected>>", self._on_iface_selected)

        # ─── Polling ───
        pl = ttk.LabelFrame(f, text="Polling")
        pl.grid(row=3, column=0, columnspan=3, sticky="ew", padx=10, pady=4)
        pl.columnconfigure(1, weight=1)

        self.bc_analog_int_var = tk.IntVar(value=240)
        self.bc_digital_int_var = tk.IntVar(value=90)

        ttk.Label(pl, text="Analog poll interval (s):").grid(row=0, column=0, sticky="e", padx=4, pady=2)
        ttk.Spinbox(pl, from_=5, to=3600, increment=5,
                    textvariable=self.bc_analog_int_var, width=8).grid(
            row=0, column=1, sticky="w", padx=4, pady=2)
        ttk.Label(pl, text="(actual cycle time depends on point count and PXC speed)",
                  foreground="#777").grid(row=0, column=2, sticky="w", padx=4, pady=2)

        ttk.Label(pl, text="Digital poll interval (s):").grid(row=1, column=0, sticky="e", padx=4, pady=2)
        ttk.Spinbox(pl, from_=5, to=3600, increment=5,
                    textvariable=self.bc_digital_int_var, width=8).grid(
            row=1, column=1, sticky="w", padx=4, pady=2)

        # ─── Advanced (collapsible) ───
        self.bc_advanced_visible = tk.BooleanVar(value=False)
        adv_toggle = ttk.Checkbutton(f, text="Show Advanced",
                                     variable=self.bc_advanced_visible,
                                     command=self._toggle_advanced)
        adv_toggle.grid(row=4, column=0, sticky="w", padx=10, pady=(8, 0))

        self.adv_frame = ttk.LabelFrame(f, text="Advanced")
        self.adv_frame.columnconfigure(1, weight=1)

        self.bc_vendor_id_var = tk.IntVar(value=999)
        self.bc_vendor_name_var = tk.StringVar(value="P2 Bridge Project")
        self.bc_inter_read_var = tk.DoubleVar(value=0.05)
        self.bc_jitter_var = tk.DoubleVar(value=5.0)
        self.bc_log_level_var = tk.StringVar(value="INFO")

        rows = [
            ("Vendor identifier:", self.bc_vendor_id_var, "(999 = test range; register one for production)"),
            ("Vendor name:", self.bc_vendor_name_var, ""),
            ("Inter-read delay (s):", self.bc_inter_read_var, "(politeness pause between point reads)"),
            ("Poll jitter (s):", self.bc_jitter_var, ""),
        ]
        for i, (label, var, hint) in enumerate(rows):
            ttk.Label(self.adv_frame, text=label).grid(row=i, column=0, sticky="e", padx=4, pady=2)
            if isinstance(var, tk.IntVar):
                ttk.Spinbox(self.adv_frame, from_=0, to=99999, increment=1,
                            textvariable=var, width=12).grid(
                    row=i, column=1, sticky="w", padx=4, pady=2)
            elif isinstance(var, tk.DoubleVar):
                ttk.Spinbox(self.adv_frame, from_=0.0, to=999.0, increment=0.05,
                            textvariable=var, width=12).grid(
                    row=i, column=1, sticky="w", padx=4, pady=2)
            else:
                ttk.Entry(self.adv_frame, textvariable=var, width=30).grid(
                    row=i, column=1, sticky="w", padx=4, pady=2)
            if hint:
                ttk.Label(self.adv_frame, text=hint, foreground="#777").grid(
                    row=i, column=2, sticky="w", padx=4, pady=2)

        ttk.Label(self.adv_frame, text="Log level:").grid(
            row=len(rows), column=0, sticky="e", padx=4, pady=2)
        ttk.Combobox(self.adv_frame, textvariable=self.bc_log_level_var,
                     values=["DEBUG", "INFO", "WARNING", "ERROR"], width=10,
                     state="readonly").grid(
            row=len(rows), column=1, sticky="w", padx=4, pady=2)

        # Footer save/reload
        footer = ttk.Frame(f)
        footer.grid(row=6, column=0, columnspan=3, sticky="ew", padx=10, pady=(8, 10))
        ttk.Button(footer, text="Save bridge_config.json",
                   command=self._save_bridge_config).pack(side="right", padx=4)
        ttk.Button(footer, text="Reload",
                   command=self._load_bridge_config).pack(side="right", padx=4)
        ttk.Label(footer, text=f"File: {BRIDGE_CONFIG_PATH.name}",
                  foreground="#777").pack(side="left")

    def _toggle_advanced(self) -> None:
        if self.bc_advanced_visible.get():
            self.adv_frame.grid(row=5, column=0, columnspan=3,
                                sticky="ew", padx=10, pady=4)
        else:
            self.adv_frame.grid_remove()

    def _populate_iface_combo(self) -> None:
        ifaces = get_local_interfaces()
        self.bc_iface_combo["values"] = [label for label, _ip in ifaces]
        self._iface_lookup = {label: ip for label, ip in ifaces}

    def _on_iface_selected(self, _evt=None) -> None:
        label = self.bc_iface_var.get()
        ip = self._iface_lookup.get(label)
        if ip:
            self.bc_ip_var.set(ip)

    def _load_bridge_config(self) -> None:
        try:
            self.bridge_data = load_json_with_fallback(BRIDGE_CONFIG_PATH,
                                                      BRIDGE_CONFIG_EXAMPLE)
        except Exception as e:
            messagebox.showerror("Load error",
                f"Could not read bridge_config.json: {e}")
            return
        d = self.bridge_data
        self.bc_instance_var.set(int(d.get("bacnet_device_instance", 599001)))
        self.bc_name_var.set(d.get("bacnet_device_name", "P2-Bridge"))
        self.bc_desc_var.set(d.get("bacnet_device_description",
            "P2-to-BACnet Bridge for APOGEE PXC controllers"))
        ip, prefix, port = parse_bacnet_address(d.get("bacnet_address", "0.0.0.0/24:47808"))
        self.bc_ip_var.set(ip)
        self.bc_prefix_var.set(prefix)
        self.bc_port_var.set(port)
        self.bc_analog_int_var.set(int(d.get("default_poll_interval_s", 240)))
        self.bc_digital_int_var.set(int(d.get("digital_poll_interval_s", 90)))
        self.bc_vendor_id_var.set(int(d.get("bacnet_vendor_identifier", 999)))
        self.bc_vendor_name_var.set(d.get("bacnet_vendor_name", "P2 Bridge Project"))
        self.bc_inter_read_var.set(float(d.get("inter_read_delay_s", 0.05)))
        self.bc_jitter_var.set(float(d.get("poll_jitter_s", 5.0)))
        self.bc_log_level_var.set(d.get("log_level", "INFO"))
        self.set_status(f"Loaded {BRIDGE_CONFIG_PATH.name}")

    def _save_bridge_config(self) -> None:
        ip = self.bc_ip_var.get().strip()
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            messagebox.showerror("Validation",
                f"Invalid IP address: {ip!r}")
            return
        port = self.bc_port_var.get()
        if not (1024 <= port <= 65535):
            messagebox.showerror("Validation",
                f"Port {port} out of range (1024..65535)")
            return

        # Clamp BACnet identity values to legal ranges before save.
        # Catches the most common bad-config cause (typo'd device instance)
        # before the bridge tries to start with it. Without this, the
        # bridge silently fails at startup with a "instance out of range"
        # deep in bacpypes3.
        clamped: list = []

        device_instance = int(self.bc_instance_var.get())
        if not (0 <= device_instance <= 4194302):
            old = device_instance
            # If it looks like a typo where an extra digit was added
            # (e.g. 5990012 was meant to be 599001), prefer the
            # divided-by-10 correction.
            if 0 <= old // 10 <= 4194302 and old > 4194302:
                device_instance = old // 10
            else:
                device_instance = max(0, min(4194302, device_instance))
            self.bc_instance_var.set(device_instance)
            clamped.append(
                f"bacnet_device_instance: {old} → {device_instance} "
                "(BACnet 22-bit instance limit is 0–4194302)")

        vendor_id = int(self.bc_vendor_id_var.get())
        if not (0 <= vendor_id <= 65535):
            old = vendor_id
            vendor_id = max(0, min(65535, vendor_id))
            self.bc_vendor_id_var.set(vendor_id)
            clamped.append(
                f"bacnet_vendor_identifier: {old} → {vendor_id} "
                "(16-bit, 0–65535)")

        if clamped:
            messagebox.showwarning(
                "Out-of-range values corrected",
                "These values were outside BACnet's legal range and have "
                "been corrected before saving:\n\n"
                + "\n".join(f"  • {c}" for c in clamped))

        new_data = strip_comment_keys(self.bridge_data)
        new_data.update({
            "bacnet_device_instance": device_instance,
            "bacnet_device_name": self.bc_name_var.get().strip() or "P2-Bridge",
            "bacnet_device_description": self.bc_desc_var.get().strip(),
            "bacnet_vendor_identifier": vendor_id,
            "bacnet_vendor_name": self.bc_vendor_name_var.get().strip(),
            "bacnet_address": format_bacnet_address(ip, self.bc_prefix_var.get(), port),
            "default_poll_interval_s": int(self.bc_analog_int_var.get()),
            "digital_poll_interval_s": int(self.bc_digital_int_var.get()),
            "inter_read_delay_s": float(self.bc_inter_read_var.get()),
            "poll_jitter_s": float(self.bc_jitter_var.get()),
            "log_level": self.bc_log_level_var.get(),
            "log_file": new_data.get("log_file", "p2_bacnet_bridge.log"),
        })
        try:
            atomic_write_json(BRIDGE_CONFIG_PATH, new_data)
        except Exception as e:
            messagebox.showerror("Save error", f"{e}")
            return
        self.bridge_data = new_data
        self.set_status(f"Saved {BRIDGE_CONFIG_PATH.name}")
        messagebox.showinfo("Saved", f"Wrote {BRIDGE_CONFIG_PATH}")

    # ─── Tab 3: Manifest ────────────────────────────────────────────────────

    def _build_manifest_tab(self) -> None:
        f = self.tab_manifest
        f.columnconfigure(0, weight=1)
        f.rowconfigure(2, weight=1)

        intro = ttk.Label(f, text=(
            "The manifest is the persistent map of P2 points → BACnet objects. "
            "Build it once after configuring the site. Re-running adds new points; "
            "existing BACnet instance IDs are preserved across rebuilds."
        ), wraplength=900, foreground="#444")
        intro.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 8))

        # Stats panel
        self.manifest_stats_lf = ttk.LabelFrame(f, text="Current manifest")
        self.manifest_stats_lf.grid(row=1, column=0, sticky="ew", padx=10, pady=4)

        self.manifest_stats_var = tk.StringVar(value="(no manifest loaded)")
        ttk.Label(self.manifest_stats_lf, textvariable=self.manifest_stats_var,
                  font=("Consolas", 10), justify="left").pack(
            anchor="w", padx=10, pady=8)

        # Action row
        actions = ttk.Frame(self.manifest_stats_lf)
        actions.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(actions, text="Build / Refresh Manifest",
                   command=self._build_manifest).pack(side="left", padx=4)
        ttk.Button(actions, text="Show Points",
                   command=self._show_manifest).pack(side="left", padx=4)
        ttk.Button(actions, text="Rebuild from scratch",
                   command=self._rebuild_manifest_from_scratch).pack(side="left", padx=4)
        ttk.Separator(actions, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(actions, text="Refresh stats",
                   command=self._refresh_manifest_stats).pack(side="left", padx=4)
        ttk.Button(actions, text="Open in Notepad",
                   command=lambda: self._open_in_notepad(MANIFEST_PATH)).pack(
            side="left", padx=4)

        # Profile + panel-points options row
        opts_frame = ttk.Frame(self.manifest_stats_lf)
        opts_frame.pack(fill="x", padx=8, pady=(0, 8))

        ttk.Label(opts_frame, text="Profile:").pack(side="left", padx=(0, 4))
        self.manifest_profile_var = tk.StringVar(value="all")
        profile_combo = ttk.Combobox(opts_frame, textvariable=self.manifest_profile_var,
                                     values=["all", "operational", "essential"],
                                     state="readonly", width=14)
        profile_combo.pack(side="left", padx=4)

        # Hint label that updates with the selection
        self.profile_hint_var = tk.StringVar()
        ttk.Label(opts_frame, textvariable=self.profile_hint_var,
                  foreground="#777").pack(side="left", padx=(6, 12))

        def update_profile_hint(*_):
            hints = {
                "all": "(every point — full poll cycle)",
                "operational": "(headlines + setpoints + states; no gains/calibration)",
                "essential": "(only the most important points — fastest cycle)",
            }
            self.profile_hint_var.set(hints.get(self.manifest_profile_var.get(), ""))
        self.manifest_profile_var.trace_add("write", update_profile_hint)
        update_profile_hint()

        self.manifest_panel_points_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts_frame, text="Discover panel-internal points",
                        variable=self.manifest_panel_points_var).pack(
            side="left", padx=(8, 0))
        ttk.Label(opts_frame,
                  text="(via opcode 0x0981 — ~20s per panel)",
                  foreground="#777").pack(side="left", padx=(4, 0))

        # Apply-profile-to-existing button
        apply_frame = ttk.Frame(self.manifest_stats_lf)
        apply_frame.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(apply_frame, text="Apply Profile to Existing Manifest →",
                   command=self._apply_profile_to_existing).pack(side="left", padx=4)
        ttk.Label(apply_frame,
                  text="(toggles enabled flag on existing points; preserves instance IDs)",
                  foreground="#777").pack(side="left", padx=4)

        # Output area
        out_lf = ttk.LabelFrame(f, text="Build output")
        out_lf.grid(row=2, column=0, sticky="nsew", padx=10, pady=(8, 10))
        out_lf.columnconfigure(0, weight=1)
        out_lf.rowconfigure(0, weight=1)

        self.manifest_output = tk.Text(out_lf, wrap="none",
                                       state="disabled",
                                       font=("Consolas", 9),
                                       bg="#0e0e0e", fg="#ddd",
                                       insertbackground="#ddd")
        self.manifest_output.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        sb = ttk.Scrollbar(out_lf, orient="vertical",
                           command=self.manifest_output.yview)
        sb.grid(row=0, column=1, sticky="ns", pady=4)
        self.manifest_output.configure(yscrollcommand=sb.set)

        self._manifest_runner = SubprocessRunner(self.manifest_output,
                                                 on_finished=self._on_manifest_done)

    def _refresh_manifest_stats(self) -> None:
        if not MANIFEST_PATH.exists():
            self.manifest_stats_var.set("No manifest.json yet — click Build to walk your site.")
            return
        try:
            with open(MANIFEST_PATH, encoding="utf-8") as fh:
                m = json.load(fh)
        except Exception as e:
            self.manifest_stats_var.set(f"Error reading manifest: {e}")
            return

        pts = m.get("points", [])
        by_type = Counter(p.get("bacnet_object_type", "?") for p in pts)
        by_node = Counter(p.get("node", "?") for p in pts)
        by_dev = Counter((p.get("node", "?"), p.get("device", "?")) for p in pts)

        lines = [
            f"Total points:     {len(pts)}",
            f"Generated:        {m.get('generated_utc', '?')}",
            f"Devices:          {len(by_dev)} across {len(by_node)} node(s)",
            "",
            "By BACnet object type:",
        ]
        for t, c in sorted(by_type.items()):
            lines.append(f"  {t:<14s} {c:>5d}")
        lines.append("")
        lines.append("By node:")
        for n, c in sorted(by_node.items()):
            lines.append(f"  {n:<14s} {c:>5d}")
        self.manifest_stats_var.set("\n".join(lines))

    def _build_manifest(self) -> None:
        if self._manifest_runner.running:
            messagebox.showinfo("Build manifest",
                "A build is already in progress.")
            return
        if not SITE_PATH.exists():
            messagebox.showerror("Build manifest",
                "Save site.json first (tab 1).")
            return
        if not BRIDGE_CONFIG_PATH.exists():
            messagebox.showerror("Build manifest",
                "Save bridge_config.json first (tab 2).")
            return

        args = [PYTHON_EXE, "-u", "tools/build_manifest.py",
                "--site", str(SITE_PATH),
                "--bridge-config", str(BRIDGE_CONFIG_PATH),
                "--out", str(MANIFEST_PATH),
                "--profile", self.manifest_profile_var.get()]
        if not self.manifest_panel_points_var.get():
            args.append("--no-panel-points")
        self._manifest_runner.run(args, cwd=HERE)
        self.set_status(
            f"Building manifest (profile={self.manifest_profile_var.get()})…")

    def _apply_profile_to_existing(self) -> None:
        if self._manifest_runner.running:
            messagebox.showinfo("Apply profile",
                "A manifest operation is already in progress.")
            return
        if not MANIFEST_PATH.exists():
            messagebox.showerror("Apply profile",
                "No manifest yet — build one first.")
            return
        prof = self.manifest_profile_var.get()
        if not messagebox.askyesno("Apply profile",
                f"Apply profile '{prof}' to the existing manifest?\n\n"
                "This toggles the enabled flag on every point based on the "
                "profile. BACnet instance IDs are preserved.\n\n"
                "Continue?"):
            return
        args = [PYTHON_EXE, "-u", "tools/apply_profile.py",
                str(MANIFEST_PATH), "--profile", prof]
        self._manifest_runner.run(args, cwd=HERE)
        self.set_status(f"Applying profile '{prof}' to manifest…")

    def _rebuild_manifest_from_scratch(self) -> None:
        if not messagebox.askyesno("Rebuild manifest",
                "This will discard ALL existing BACnet instance ID assignments.\n\n"
                "Any BACnet supervisor mapped to this bridge will need re-import.\n\n"
                "Continue?"):
            return
        if self._manifest_runner.running:
            return
        if MANIFEST_PATH.exists():
            try:
                MANIFEST_PATH.unlink()
            except Exception as e:
                messagebox.showerror("Rebuild", f"Could not delete: {e}")
                return
        self._build_manifest()

    def _on_manifest_done(self, rc) -> None:
        self.set_status(f"Manifest build finished (rc={rc})")
        self._refresh_manifest_stats()

    def _show_manifest(self) -> None:
        if not MANIFEST_PATH.exists():
            messagebox.showinfo("Show points", "No manifest yet.")
            return
        try:
            with open(MANIFEST_PATH, encoding="utf-8") as fh:
                m = json.load(fh)
        except Exception as e:
            messagebox.showerror("Show points", f"{e}")
            return

        win = tk.Toplevel(self.root)
        win.title(f"Manifest — {len(m.get('points', []))} points")
        win.geometry("1100x600")

        # Filter row
        top = ttk.Frame(win)
        top.pack(fill="x", padx=8, pady=6)
        ttk.Label(top, text="Filter:").pack(side="left")
        filter_var = tk.StringVar()
        filter_entry = ttk.Entry(top, textvariable=filter_var, width=40)
        filter_entry.pack(side="left", padx=4)
        result_var = tk.StringVar(value=f"{len(m.get('points', []))} points")
        ttk.Label(top, textvariable=result_var, foreground="#777").pack(side="left", padx=10)

        # Treeview
        cols = ("node", "device", "slot", "name", "type", "instance", "object_name", "units", "enabled")
        tv = ttk.Treeview(win, columns=cols, show="headings", height=20)
        for c, w in zip(cols, (60, 90, 50, 180, 90, 60, 200, 80, 60)):
            tv.heading(c, text=c)
            tv.column(c, width=w, anchor="w")
        tv.pack(fill="both", expand=True, padx=8, pady=4)
        sb = ttk.Scrollbar(win, orient="vertical", command=tv.yview)
        sb.pack(side="right", fill="y")
        tv.configure(yscrollcommand=sb.set)

        all_points = m.get("points", [])

        def repopulate():
            f = filter_var.get().strip().lower()
            tv.delete(*tv.get_children())
            n = 0
            for p in all_points:
                hay = f"{p.get('node','')} {p.get('device','')} {p.get('name','')} {p.get('object_name','')}".lower()
                if f and f not in hay:
                    continue
                tv.insert("", "end", values=(
                    p.get("node", ""),
                    p.get("device", ""),
                    p.get("slot", ""),
                    p.get("name", ""),
                    p.get("bacnet_object_type", ""),
                    p.get("bacnet_instance", ""),
                    p.get("object_name", ""),
                    p.get("units", ""),
                    "yes" if p.get("enabled", True) else "no",
                ))
                n += 1
            result_var.set(f"{n} of {len(all_points)} points")

        filter_var.trace_add("write", lambda *_: repopulate())
        repopulate()

    def _open_in_notepad(self, path: Path) -> None:
        if not path.exists():
            messagebox.showinfo("Open in Notepad", f"File does not exist: {path}")
            return
        try:
            if sys.platform.startswith("win"):
                subprocess.Popen(["notepad", str(path)])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-t", str(path)])
            else:
                # Best-effort on Linux
                for cmd in (["xdg-open"], ["gedit"], ["nano"]):
                    try:
                        subprocess.Popen(cmd + [str(path)])
                        return
                    except FileNotFoundError:
                        continue
        except Exception as e:
            messagebox.showerror("Open in Notepad", f"{e}")

    # ─── Tab 4: Run ─────────────────────────────────────────────────────────

    def _build_run_tab(self) -> None:
        f = self.tab_run
        f.columnconfigure(0, weight=1)
        f.rowconfigure(2, weight=1)

        intro = ttk.Label(f, text=(
            "Launch the bridge runtime. The bridge runs in its own console window — "
            "you'll see the heartbeat lines and can press Ctrl+C in that window to stop it."
        ), wraplength=900, foreground="#444")
        intro.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 8))

        # Status panel
        st_lf = ttk.LabelFrame(f, text="Bridge status")
        st_lf.grid(row=1, column=0, sticky="ew", padx=10, pady=4)
        st_lf.columnconfigure(1, weight=1)

        ttk.Label(st_lf, text="State:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        self.run_state_var = tk.StringVar(value="stopped")
        self.run_state_label = ttk.Label(st_lf, textvariable=self.run_state_var,
                                         font=("Consolas", 11, "bold"))
        self.run_state_label.grid(row=0, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(st_lf, text="Process:").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        self.run_pid_var = tk.StringVar(value="-")
        ttk.Label(st_lf, textvariable=self.run_pid_var,
                  font=("Consolas", 10)).grid(row=1, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(st_lf, text="Log:").grid(row=2, column=0, sticky="e", padx=4, pady=4)
        self.run_log_var = tk.StringVar(value=str(LOG_PATH))
        ttk.Label(st_lf, textvariable=self.run_log_var,
                  font=("Consolas", 9), foreground="#777").grid(
            row=2, column=1, sticky="w", padx=4, pady=4)

        # Action row
        actions = ttk.Frame(st_lf)
        actions.grid(row=3, column=0, columnspan=2, sticky="w", padx=4, pady=(8, 8))
        self.run_start_btn = ttk.Button(actions, text="Start Bridge",
                                        command=self._start_bridge)
        self.run_start_btn.pack(side="left", padx=4)
        self.run_stop_btn = ttk.Button(actions, text="Stop Bridge",
                                       command=self._stop_bridge, state="disabled")
        self.run_stop_btn.pack(side="left", padx=4)
        ttk.Separator(actions, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(actions, text="Open Log",
                   command=lambda: self._open_in_notepad(LOG_PATH)).pack(
            side="left", padx=4)
        ttk.Button(actions, text="Refresh Status",
                   command=self._refresh_run_status).pack(side="left", padx=4)

        # Recent log lines panel
        log_lf = ttk.LabelFrame(f, text="Last 200 log lines")
        log_lf.grid(row=2, column=0, sticky="nsew", padx=10, pady=(8, 10))
        log_lf.columnconfigure(0, weight=1)
        log_lf.rowconfigure(0, weight=1)

        self.run_log_text = tk.Text(log_lf, wrap="none",
                                    state="disabled",
                                    font=("Consolas", 9),
                                    bg="#0e0e0e", fg="#ddd")
        self.run_log_text.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        sb = ttk.Scrollbar(log_lf, orient="vertical",
                           command=self.run_log_text.yview)
        sb.grid(row=0, column=1, sticky="ns", pady=4)
        self.run_log_text.configure(yscrollcommand=sb.set)

    def _start_bridge(self) -> None:
        if self.bridge_process and self.bridge_process.poll() is None:
            messagebox.showinfo("Start bridge", "Bridge is already running.")
            return
        if not SITE_PATH.exists():
            messagebox.showerror("Start bridge", "Save site.json first (tab 1).")
            return
        if not BRIDGE_CONFIG_PATH.exists():
            messagebox.showerror("Start bridge",
                "Save bridge_config.json first (tab 2).")
            return
        if not MANIFEST_PATH.exists():
            messagebox.showerror("Start bridge",
                "Build the manifest first (tab 3).")
            return

        # Launch in a new console window on Windows so the user can see
        # the bridge's stdout and Ctrl+C it directly. On Unix-likes, just
        # launch detached.
        args = [PYTHON_EXE, "-u", "p2_bacnet_bridge.py",
                "--site", str(SITE_PATH),
                "--bridge-config", str(BRIDGE_CONFIG_PATH),
                "--manifest", str(MANIFEST_PATH)]

        # Force UTF-8 stdout so the scanner's ✓ progress glyph (and
        # anything else non-ASCII) doesn't trip the OS code page on
        # Windows. Same fix that's needed for tools/build_manifest.py.
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"

        kwargs: Dict[str, Any] = {"cwd": str(HERE), "env": env}
        if sys.platform.startswith("win"):
            CREATE_NEW_CONSOLE = 0x00000010
            kwargs["creationflags"] = CREATE_NEW_CONSOLE
        else:
            kwargs["stdout"] = subprocess.DEVNULL
            kwargs["stderr"] = subprocess.DEVNULL
            kwargs["start_new_session"] = True

        try:
            self.bridge_process = subprocess.Popen(args, **kwargs)
        except Exception as e:
            messagebox.showerror("Start bridge", f"{e}")
            return
        self.set_status(f"Started bridge (pid {self.bridge_process.pid})")
        self._refresh_run_status()

    def _stop_bridge(self) -> None:
        if not self.bridge_process or self.bridge_process.poll() is not None:
            self._refresh_run_status()
            return
        try:
            self.bridge_process.terminate()
        except Exception:
            pass
        # Give it a few seconds to shutdown gracefully
        deadline = time.time() + 6
        while time.time() < deadline:
            if self.bridge_process.poll() is not None:
                break
            time.sleep(0.2)
        if self.bridge_process.poll() is None:
            try:
                self.bridge_process.kill()
            except Exception:
                pass
        self.set_status("Bridge stopped")
        self._refresh_run_status()

    def _refresh_run_status(self) -> None:
        running = (self.bridge_process is not None
                   and self.bridge_process.poll() is None)
        if running:
            self.run_state_var.set("RUNNING")
            self.run_state_label.configure(foreground="#1a7f37")
            self.run_pid_var.set(f"PID {self.bridge_process.pid}")
            self.run_start_btn.configure(state="disabled")
            self.run_stop_btn.configure(state="normal")
        else:
            self.run_state_var.set("stopped")
            self.run_state_label.configure(foreground="#777")
            self.run_pid_var.set("-")
            self.run_start_btn.configure(state="normal")
            self.run_stop_btn.configure(state="disabled")

        # Tail the log file
        if LOG_PATH.exists():
            try:
                # Read last ~32KB to get the tail without slurping the whole file
                size = LOG_PATH.stat().st_size
                with open(LOG_PATH, "rb") as fh:
                    if size > 32768:
                        fh.seek(-32768, os.SEEK_END)
                    data = fh.read().decode("utf-8", errors="replace")
                lines = data.splitlines()[-200:]
                self.run_log_text.configure(state="normal")
                self.run_log_text.delete("1.0", "end")
                self.run_log_text.insert("end", "\n".join(lines) + "\n")
                self.run_log_text.see("end")
                self.run_log_text.configure(state="disabled")
            except Exception:
                pass

    def _poll_run_status(self) -> None:
        """Periodically refresh status while window is open."""
        try:
            self._refresh_run_status()
        finally:
            self.root.after(2000, self._poll_run_status)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    root = tk.Tk()
    # Slightly larger default font
    try:
        default_font = tkfont.nametofont("TkDefaultFont")
        default_font.configure(size=10)
    except Exception:
        pass

    app = BridgeLauncherApp(root)

    def on_close():
        if app.bridge_process and app.bridge_process.poll() is None:
            if not messagebox.askyesno("Quit",
                "The bridge is still running. Quit and leave it running?"):
                return
        # The bridge is allowed to outlive the launcher -- that is the point of
        # the question above. A scan or a manifest build is not: it is a child
        # of this window, it is talking to panels, and nothing else will ever
        # reap it. Stop it before the root goes away, or it is orphaned.
        for runner in app.active_runners():
            if runner.running:
                runner.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
