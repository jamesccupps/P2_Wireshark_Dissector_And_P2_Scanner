"""`SubprocessRunner.stop()` must actually stop the child.

The launcher spawns children for cold-discover scans and manifest builds. Those
talk to panels, and nothing outside the launcher will ever reap them, so a
`stop()` that merely *asks* is not enough: an earlier edition called
`terminate()` and returned, and nothing called `stop()` on window close at all.

These tests need a Tk root because `SubprocessRunner` writes into a Text widget.
They skip rather than fail where no display is available, so a headless CI run
stays green -- but they do run on the Windows box this is developed on, which is
where the orphaned-process failure would actually bite.
"""
from __future__ import annotations

import sys
import time

import pytest

tk = pytest.importorskip("tkinter")


@pytest.fixture()
def tk_root():
    try:
        root = tk.Tk()
    except tk.TclError as e:          # no display
        pytest.skip(f"no Tk display: {e}")
    root.withdraw()
    yield root
    try:
        root.destroy()
    except tk.TclError:
        pass


@pytest.fixture()
def runner(tk_root):
    import p2_bridge_launcher as launcher
    text = tk.Text(tk_root)
    return launcher.SubprocessRunner(text)


def test_stop_reaps_a_child_that_outlives_terminate(runner):
    """A child ignoring SIGTERM must still be gone after stop() returns."""
    # A Python child that installs a SIGTERM handler doing nothing, then sleeps.
    # On Windows terminate() is TerminateProcess and cannot be ignored, so this
    # exercises the plain path there and the escalation path on POSIX. Either
    # way the assertion is the same and is the one that matters.
    code = (
        "import signal, sys, time\n"
        "try:\n"
        "    signal.signal(signal.SIGTERM, lambda *a: None)\n"
        "except Exception:\n"
        "    pass\n"
        "sys.stdout.write('up\\n'); sys.stdout.flush()\n"
        "time.sleep(120)\n"
    )
    runner.run([sys.executable, "-c", code])
    assert runner.running

    deadline = time.time() + 10
    while time.time() < deadline and runner.proc.poll() is not None:
        time.sleep(0.05)

    runner.stop(timeout=3.0)

    assert runner.proc.poll() is not None, "child survived stop()"
    assert not runner.running


def test_stop_is_safe_on_a_child_that_already_exited(runner):
    runner.run([sys.executable, "-c", "pass"])
    runner.proc.wait(timeout=10)
    runner.stop()                      # must not raise
    assert not runner.running


def test_stop_is_safe_when_nothing_was_ever_run(runner):
    runner.stop()                      # must not raise
    assert not runner.running


def test_stop_cancels_the_pending_after_callback(runner):
    """A queued after() firing post-destroy is a TclError in the event loop."""
    runner.run([sys.executable, "-c", "import time; time.sleep(30)"])
    runner._poll_queue()               # schedule one
    runner.stop(timeout=3.0)
    assert runner._poll_after_id is None


def test_window_close_stops_runners_but_not_the_bridge(tk_root):
    """`active_runners()` is what on_close uses; it must find them."""
    import p2_bridge_launcher as launcher
    app = launcher.BridgeLauncherApp(tk_root)
    tk_root.update_idletasks()
    runners = app.active_runners()
    assert runners, "no SubprocessRunner found on the app"
    assert all(isinstance(r, launcher.SubprocessRunner) for r in runners)
