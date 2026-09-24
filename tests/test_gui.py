"""The GUI, which had no tests at all.

6,203 lines and 0% coverage is the headline, but the interesting part is
narrower: almost everything here is widgets, and widgets are a poor thing to
assert on. The parts worth pinning are the ones with real failure modes --
the worker-thread plumbing that carries every scan result back to the UI, and
the session history that holds the only copy of what a scan found.

Those need no display. The one test that does construct widgets is gated on Tk
being importable and initialisable, because CI runners frequently have neither.
"""
from __future__ import annotations

import queue
import threading
import time

import pytest

import p2_gui


def _tk_usable() -> bool:
    try:
        import tkinter
        root = tkinter.Tk()
        root.destroy()
        return True
    except Exception:
        return False


needs_tk = pytest.mark.skipif(not _tk_usable(), reason="no usable Tk display")


def _drain(q: "queue.Queue", timeout: float = 5.0):
    """Wait for one item, or fail the test rather than hang the suite."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            return q.get(timeout=0.1)
        except queue.Empty:
            continue
    pytest.fail("nothing arrived on the queue within %.1fs" % timeout)


# ── TaskRunner: every scan result in the application comes back through this ──

def _runner():
    return p2_gui.TaskRunner(queue.Queue(), queue.Queue())


def test_a_completed_task_reports_ok_with_its_return_value():
    r = _runner()
    assert r.submit("t1", lambda: 21 * 2) is True
    task_id, status, value, elapsed = _drain(r.result_queue)
    assert (task_id, status, value) == ("t1", "ok", 42)
    assert elapsed >= 0


def test_a_raising_task_reports_error_and_keeps_the_traceback():
    """The GUI shows the traceback in its log pane, so losing it loses the only
    diagnostic a user ever sees."""
    def boom():
        raise ValueError("expected")

    r = _runner()
    r.submit("t2", boom)
    task_id, status, payload, _ = _drain(r.result_queue)
    exc, tb = payload
    assert (task_id, status) == ("t2", "error")
    assert isinstance(exc, ValueError)
    assert "ValueError" in tb and "expected" in tb


def test_only_one_task_runs_at_a_time():
    """submit() returning False is how every menu action avoids stacking
    concurrent scans onto one panel."""
    release = threading.Event()
    r = _runner()
    assert r.submit("first", release.wait, 5.0) is True
    assert r.busy is True
    assert r.submit("second", lambda: None) is False, "a second task was accepted"
    assert r.current_task == "first"
    release.set()
    _drain(r.result_queue)


def test_the_runner_frees_itself_after_a_task_raises():
    """If _busy survived an exception the GUI would wedge, refusing every
    further action with no way back short of a restart."""
    def boom():
        raise RuntimeError("expected")

    r = _runner()
    r.submit("t3", boom)
    _drain(r.result_queue)
    for _ in range(50):
        if not r.busy:
            break
        time.sleep(0.02)
    assert r.busy is False
    assert r.submit("t4", lambda: "fine") is True
    assert _drain(r.result_queue)[2] == "fine"


def test_a_cancelled_task_is_reported_as_cancelled_not_ok():
    """Cancellation is cooperative, so a function that returns normally after
    cancel() must still be surfaced as cancelled -- otherwise the UI claims a
    partial scan completed."""
    r = _runner()
    started = threading.Event()

    def work():
        started.set()
        for _ in range(100):
            if r.stop_event.is_set():
                return "partial"
            time.sleep(0.01)
        return "whole"

    r.submit("t5", work)
    assert started.wait(5.0)
    r.cancel()
    task_id, status, value, _ = _drain(r.result_queue)
    assert (task_id, status, value) == ("t5", "cancelled", "partial")


def test_a_fresh_submit_does_not_inherit_the_previous_cancel():
    """submit() installs a new stop_event for exactly this reason."""
    r = _runner()
    r.submit("a", lambda: None)
    _drain(r.result_queue)
    r.cancel()                      # cancels a task that already finished
    for _ in range(50):
        if not r.busy:
            break
        time.sleep(0.02)
    r.submit("b", lambda: "ran")
    task_id, status, value, _ = _drain(r.result_queue)
    assert (task_id, status, value) == ("b", "ok", "ran")


# ── QueueWriter: worker stdout is the GUI's log pane ─────────────────────────

def test_worker_output_is_routed_to_the_log_queue():
    q: "queue.Queue" = queue.Queue()
    w = p2_gui.QueueWriter(q)
    w.write("hello\n")
    w.flush()
    assert not q.empty(), "worker output never reached the log queue"


# ── ScanHistory: the only record of what a scan found ────────────────────────

def test_history_copies_results_so_a_later_mutation_cannot_rewrite_the_past():
    h = p2_gui.ScanHistory()
    results = [{"point": "ROOM TEMP", "value": 72.5}]
    entry = h.add_device_scan("NODE1", "TEC1", 2100, results)
    results[0]["value"] = 999            # caller reuses its list
    assert h.get(entry["id"])["results"][0]["value"] == 72.5


def test_history_ids_are_unique_across_kinds():
    """get() and remove() are keyed on the id, so a collision between a device
    scan and a sweep would silently return the wrong record."""
    h = p2_gui.ScanHistory()
    ids = [
        h.add_device_scan("N", "D", 1, [])["id"],
        h.add_sweep(["P"], 1, [])["id"],
        h.add_walk("N", [])["id"],
    ]
    assert len(set(ids)) == 3
    assert len(h) == 3


def test_history_remove_and_clear():
    h = p2_gui.ScanHistory()
    a = h.add_device_scan("N", "D", 1, [])["id"]
    h.add_sweep(["P"], 1, [])
    assert h.remove(a) is True
    assert h.remove(a) is False, "removing a gone entry reported success"
    assert h.get(a) is None
    assert len(h) == 1
    h.clear()
    assert len(h) == 0 and h.all() == []


def test_history_for_device_filters_to_that_device():
    h = p2_gui.ScanHistory()
    h.add_device_scan("N1", "TEC1", 1, [])
    h.add_device_scan("N1", "TEC2", 1, [])
    h.add_device_scan("N2", "TEC1", 1, [])
    assert len(h.for_device("N1", "TEC1")) == 1


# ── The window itself ────────────────────────────────────────────────────────

@needs_tk
def test_the_main_window_constructs_without_a_config_file(tmp_path, monkeypatch):
    """A first run has no site.json. Construction must survive that, because
    the config dialog is reached *from* the window that would fail to appear.

    Stating a precondition this test discovered: MainWindow requires the
    module-global `p2` to already hold the loaded scanner module. `main()`
    assigns it three lines before constructing the window, so the one real
    caller always satisfies it -- but the constructor does not check, and the
    failure surfaces as `AttributeError: 'NoneType' object has no attribute
    'P2_NETWORK'` from inside _rebuild_tree_from_config, which names neither
    the precondition nor the caller that broke it. Injected here rather than
    guarded in the constructor, because the happy path is fine as it stands.
    """
    import tkinter

    import p2_scanner
    monkeypatch.setattr(p2_gui, "p2", p2_scanner)

    root = tkinter.Tk()
    root.withdraw()
    try:
        win = p2_gui.MainWindow(root, str(tmp_path / "absent.json"))
        assert win.runner is not None
        assert isinstance(win.scan_history, p2_gui.ScanHistory)
        assert win.log_queue is not win.result_queue
    finally:
        root.destroy()
