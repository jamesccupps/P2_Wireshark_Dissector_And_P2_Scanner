"""A control panel for the virtual PXC.

The fixture had no entry point at all -- no `main()`, no CLI -- so the only way
to run a panel was to import it and drive it from Python. That is fine for
tests and useless for the thing the fixture is actually for: having a panel up
on a port while you develop a client against it, and being able to break that
panel on purpose while the client is watching.

Everything here drives the existing public API. Nothing in `virtual_pxc.py`
was changed to accommodate a GUI, and the panel does not know this exists.

Threading follows the pattern p2_gui already proved: the panel runs its own
accept and client threads, the GUI touches widgets only on the Tk thread, and
panel activity reaches the log pane through a `logging.Handler` that pushes
onto a `queue.Queue` drained by `root.after`. No widget is touched from a panel
thread.

Run it:  python virtual_pxc_gui.py
"""
from __future__ import annotations

import logging
import queue
import sys
import tkinter as tk
from pathlib import Path
from tkinter import ttk

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import virtual_pxc  # noqa: E402

POLL_MS = 200


class _QueueLogHandler(logging.Handler):
    """Panel threads log here; the Tk thread drains the queue."""

    def __init__(self, q: "queue.Queue[str]") -> None:
        super().__init__()
        self._q = q

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._q.put_nowait(self.format(record))
        except Exception:
            pass          # a full queue must never take the panel down


class ControlPanel:
    # (label, constructor kwarg, default) -- defaults mirror virtual_pxc's own,
    # which are invented names, never a real site's.
    IDENTITY = [
        ("BLN", "bln", "MYBLN"),
        ("Site", "site", "BUILDING1"),
        ("Node", "node", "NODE1"),
        ("Hardware type", "hardware_type", "PXME"),
        ("Version", "version_number", "V2.8.10"),
        ("Firmware build", "firmware_build", "PME1252"),
    ]

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.panel: virtual_pxc.VirtualPxc | None = None
        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self._handler = _QueueLogHandler(self.log_queue)
        self._handler.setFormatter(logging.Formatter("%(levelname)s  %(message)s"))

        root.title("Virtual PXC")
        root.geometry("760x560")

        self._vars: dict[str, tk.StringVar] = {}
        self._build_identity()
        self._build_behaviour()
        self._build_controls()
        self._build_faults()
        self._build_log()

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        root.after(POLL_MS, self._poll)

    # ── layout ───────────────────────────────────────────────────────────

    def _build_identity(self) -> None:
        f = ttk.LabelFrame(self.root, text="Identity")
        f.pack(fill="x", padx=8, pady=(8, 4))
        for i, (label, kwarg, default) in enumerate(self.IDENTITY):
            r, c = divmod(i, 3)
            ttk.Label(f, text=label).grid(row=r, column=c * 2, sticky="e", padx=(8, 2), pady=2)
            v = tk.StringVar(value=default)
            self._vars[kwarg] = v
            ttk.Entry(f, textvariable=v, width=16).grid(row=r, column=c * 2 + 1, padx=(0, 8), pady=2)

        ttk.Label(f, text="Host").grid(row=2, column=0, sticky="e", padx=(8, 2))
        self._vars["host"] = tk.StringVar(value="127.0.0.1")
        ttk.Entry(f, textvariable=self._vars["host"], width=16).grid(row=2, column=1, padx=(0, 8))
        ttk.Label(f, text="Port").grid(row=2, column=2, sticky="e", padx=(8, 2))
        self._vars["port"] = tk.StringVar(value="0")
        ttk.Entry(f, textvariable=self._vars["port"], width=16).grid(row=2, column=3, padx=(0, 8))
        ttk.Label(f, text="(0 = pick a free port)").grid(row=2, column=4, columnspan=2, sticky="w")

    def _build_behaviour(self) -> None:
        f = ttk.LabelFrame(self.root, text="Enforcement")
        f.pack(fill="x", padx=8, pady=4)
        self.strict_framing = tk.BooleanVar(value=True)
        self.strict_opcodes = tk.BooleanVar(value=True)
        self.cov_push = tk.BooleanVar(value=True)
        ttk.Checkbutton(f, text="strict framing (drop a wrong msg_type silently, as a panel does)",
                        variable=self.strict_framing).pack(anchor="w", padx=8)
        ttk.Checkbutton(f, text="strict opcodes", variable=self.strict_opcodes).pack(anchor="w", padx=8)
        ttk.Checkbutton(f, text="COV push enabled", variable=self.cov_push).pack(anchor="w", padx=8)

    def _build_controls(self) -> None:
        f = ttk.Frame(self.root)
        f.pack(fill="x", padx=8, pady=4)
        self.start_btn = ttk.Button(f, text="Start", command=self._start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(f, text="Stop", command=self._stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(6, 12))
        self.status = ttk.Label(f, text="stopped")
        self.status.pack(side="left")

    def _build_faults(self) -> None:
        f = ttk.LabelFrame(self.root, text="Fault injection")
        f.pack(fill="x", padx=8, pady=4)
        self.fault_btns = [
            ttk.Button(f, text="Drop connections", command=self._drop),
            ttk.Button(f, text="Refuse next 1", command=self._refuse),
            ttk.Button(f, text="Push DBCHANGE", command=self._push),
        ]
        for b in self.fault_btns:
            b.pack(side="left", padx=(8, 0), pady=4)
            b.configure(state="disabled")
        ttk.Label(f, text="  (a refused connect SUCCEEDS then dies — what an up-but-not-ready panel does)"
                  ).pack(side="left", padx=8)

    def _build_log(self) -> None:
        f = ttk.LabelFrame(self.root, text="Panel activity")
        f.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        self.log = tk.Text(f, height=14, wrap="none", state="disabled")
        sb = ttk.Scrollbar(f, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        self.log.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

    # ── actions ──────────────────────────────────────────────────────────

    def _start(self) -> None:
        if self.panel is not None:
            return
        kwargs = {k: v.get() for k, v in self._vars.items() if k not in ("port",)}
        try:
            kwargs["port"] = int(self._vars["port"].get() or 0)
        except ValueError:
            self._write("port must be a number\n")
            return
        kwargs.update(strict_framing=self.strict_framing.get(),
                      strict_opcodes=self.strict_opcodes.get(),
                      cov_push_enabled=self.cov_push.get())
        logging.getLogger("virtual_pxc").addHandler(self._handler)
        logging.getLogger("virtual_pxc").setLevel(logging.DEBUG)
        try:
            self.panel = virtual_pxc.VirtualPxc(**kwargs)
            self.panel.start()
        except Exception as exc:                       # a bind failure is the common one
            self._write("start failed: %s: %s\n" % (type(exc).__name__, exc))
            self.panel = None
            return
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        for b in self.fault_btns:
            b.configure(state="normal")

    def _stop(self) -> None:
        if self.panel is None:
            return
        self.panel.stop()
        self.panel = None
        logging.getLogger("virtual_pxc").removeHandler(self._handler)
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        for b in self.fault_btns:
            b.configure(state="disabled")
        self.status.configure(text="stopped")

    def _drop(self) -> None:
        if self.panel:
            self._write("dropped %d connection(s)\n" % self.panel.drop_connections())

    def _refuse(self) -> None:
        if self.panel:
            self.panel.refuse_connections(1)
            self._write("next connection will be accepted then closed\n")

    def _push(self) -> None:
        if self.panel:
            self._write("DBCHANGE reached %d client(s)\n" % self.panel.push_dbchange())

    def _on_close(self) -> None:
        self._stop()
        self.root.destroy()

    # ── the Tk-thread pump ───────────────────────────────────────────────

    def _write(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _poll(self) -> None:
        drained = 0
        while drained < 200:                # bounded: never starve the UI
            try:
                self._write(self.log_queue.get_nowait() + "\n")
            except queue.Empty:
                break
            drained += 1
        if self.panel is not None:
            live = len(getattr(self.panel, "_live_conns", ()))
            self.status.configure(
                text="listening on %s:%d   %d client(s)"
                     % (self.panel.host, self.panel.port, live))
        self.root.after(POLL_MS, self._poll)


def main() -> int:
    root = tk.Tk()
    ControlPanel(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
