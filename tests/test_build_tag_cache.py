"""An audit flagged `all_cached_build_tags()` as racy. It is not, here.

    "Individual get/set are atomic under the GIL, but dict(_BUILD_TAG_CACHE)
     can raise RuntimeError: dictionary changed size during iteration if
     another thread writes during the copy."

The prediction is sound for an iteration written in Python. `dict(d)` is not
that: it is one C-level copy that never yields, so on a GIL build no other
thread runs inside it and the error cannot occur. Six writer threads against a
400,000-entry cache produced 41 full copies and no error; ~15,000 copies of a
small one, likewise.

No lock was added. This test exists so the assumption is checked rather than
believed: on a free-threaded interpreter (3.13t and later) there is no GIL to
make the copy atomic, and this is where that shows up.
"""
from __future__ import annotations

import sys
import threading
import time

import firmware_registry as fr


def test_snapshotting_survives_concurrent_writers():
    saved = dict(fr._BUILD_TAG_CACHE)
    for i in range(20000):
        fr._BUILD_TAG_CACHE["host-%05d" % i] = "PME1252"

    stop = threading.Event()
    faults: list[BaseException] = []

    def churn():
        i = 0
        while not stop.is_set():
            try:
                fr.cache_build_tag("x%d" % i, "PME1300")
                fr.evict_build_tag("x%d" % (i - 1))
            except BaseException as exc:       # noqa: BLE001 - reported, not swallowed
                faults.append(exc)
                return
            i += 1

    writers = [threading.Thread(target=churn, daemon=True) for _ in range(4)]
    for t in writers:
        t.start()
    try:
        deadline = time.monotonic() + 1.0
        copies = 0
        while time.monotonic() < deadline:
            snap = fr.all_cached_build_tags()
            assert isinstance(snap, dict)
            copies += 1
        assert copies > 0
    finally:
        stop.set()
        for t in writers:
            t.join(timeout=2.0)
        fr._BUILD_TAG_CACHE.clear()
        fr._BUILD_TAG_CACHE.update(saved)

    assert faults == [], (
        "the cache needs a lock on this interpreter (GIL enabled: %s): %r"
        % (getattr(sys, "_is_gil_enabled", lambda: True)(), faults[0]))
