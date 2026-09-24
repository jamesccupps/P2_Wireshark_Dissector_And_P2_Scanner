"""Shutdown must be clean, because this fixture's job is to model behaviour.

`stop()` closes `_server_sock` and sets it to None. `_accept_loop` used to
re-read that attribute for `settimeout()` and again for `accept()`, both
outside any guard, so either could see a closed descriptor (OSError 9) or None
(AttributeError) depending on who won the race. Neither is caught by the loop's
own handlers, so the accept thread died with an unhandled traceback -- 173 of
200 immediate start/stop cycles when measured.

It was visible the whole time as PytestUnhandledThreadExceptionWarning, which
is exactly the shape of thing a suite trains you to ignore. A fixture whose
purpose is to make a client's defects surface should not be leaking its own.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent      # the virtual_pxc/ package
sys.path.insert(0, str(HERE))

import virtual_pxc  # noqa: E402

CYCLES = 60          # 173/200 before the fix, so 60 is ample to catch a regression


@pytest.fixture()
def thread_exceptions():
    """Collect unhandled exceptions from any thread, restoring the hook after."""
    seen: list[str] = []
    lock = threading.Lock()
    previous = threading.excepthook

    def hook(args):
        with lock:
            seen.append(args.exc_type.__name__)

    threading.excepthook = hook
    try:
        yield seen
    finally:
        threading.excepthook = previous


def test_immediate_start_stop_never_kills_the_accept_thread(thread_exceptions):
    """The race is between stop() nulling the socket and _accept_loop reading
    it, so it needs no client and no traffic -- just start, stop, repeat."""
    for _ in range(CYCLES):
        panel = virtual_pxc.VirtualPxc(host="127.0.0.1", port=0)
        panel.start()
        panel.stop()

    time.sleep(0.5)          # let any dying thread surface before asserting
    assert thread_exceptions == [], (
        "accept thread raised %d unhandled exception(s) over %d start/stop "
        "cycles: %s" % (len(thread_exceptions), CYCLES,
                        sorted(set(thread_exceptions)))
    )


def test_stop_is_idempotent(thread_exceptions):
    """stop() runs on the shutdown path of anything embedding the fixture, and
    a second call must not raise or spawn a new failure."""
    panel = virtual_pxc.VirtualPxc(host="127.0.0.1", port=0)
    panel.start()
    panel.stop()
    panel.stop()
    time.sleep(0.3)
    assert thread_exceptions == []
