"""The control panel, driven without a human.

A GUI test that only checks widgets exist proves nothing worth knowing. These
drive the panel the way a person would -- start it, connect a real client to
the port it chose, inject a fault, stop it -- and assert on what the fixture
actually did, not on what the widgets look like.

Skipped where Tk cannot initialise, which is the normal state of a CI runner.
"""
from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent      # the virtual_pxc/ package
sys.path.insert(0, str(HERE))


def _tk_usable() -> bool:
    try:
        import tkinter
        r = tkinter.Tk()
        r.destroy()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _tk_usable(), reason="no usable Tk display")


@pytest.fixture()
def panel_gui():
    """A withdrawn control panel, stopped and destroyed on the way out."""
    import tkinter

    import virtual_pxc_gui

    root = tkinter.Tk()
    root.withdraw()
    cp = virtual_pxc_gui.ControlPanel(root)
    try:
        yield cp
    finally:
        try:
            cp._stop()
        except Exception:
            pass
        root.destroy()


def test_start_binds_a_port_and_stop_releases_it(panel_gui):
    panel_gui._vars["port"].set("0")            # let the OS choose
    panel_gui._start()
    assert panel_gui.panel is not None, "Start did not bring a panel up"
    port = panel_gui.panel.port
    assert port > 0

    # the port is real: a client can reach it
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    sock.close()

    panel_gui._stop()
    assert panel_gui.panel is None
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1).close()


def test_the_controls_follow_the_panel_state(panel_gui):
    """Fault injection against a stopped panel would raise, so the buttons are
    disabled until there is something to break."""
    assert str(panel_gui.start_btn["state"]) == "normal"
    assert all(str(b["state"]) == "disabled" for b in panel_gui.fault_btns)

    panel_gui._vars["port"].set("0")
    panel_gui._start()
    assert str(panel_gui.start_btn["state"]) == "disabled"
    assert str(panel_gui.stop_btn["state"]) == "normal"
    assert all(str(b["state"]) == "normal" for b in panel_gui.fault_btns)

    panel_gui._stop()
    assert str(panel_gui.start_btn["state"]) == "normal"
    assert all(str(b["state"]) == "disabled" for b in panel_gui.fault_btns)


def test_fault_injection_reaches_a_connected_client(panel_gui):
    """The point of the fixture: break the panel on purpose while a client is
    watching, and have the client see it."""
    panel_gui._vars["port"].set("0")
    panel_gui._start()
    sock = socket.create_connection(("127.0.0.1", panel_gui.panel.port), timeout=3)
    time.sleep(0.3)                             # let the panel register the client
    try:
        assert panel_gui.panel.push_dbchange() == 1, "unsolicited push reached nobody"
        assert panel_gui.panel.drop_connections() == 1, "the live connection was not cut"
    finally:
        try:
            sock.close()
        except OSError:
            pass


def test_panel_log_output_reaches_the_pane(panel_gui):
    """Activity arrives from panel threads through a logging handler and a
    queue; the Tk thread drains it. Nothing useful happens if that path is
    broken, and it breaks silently."""
    panel_gui._vars["port"].set("0")
    panel_gui._start()
    panel_gui._poll()                           # one pump, as root.after would
    text = panel_gui.log.get("1.0", "end")
    assert "listening on" in text, "the panel's own log never reached the pane"


def test_a_bad_port_is_reported_and_leaves_no_panel(panel_gui):
    """Typing into the port box is the easiest way to get this wrong."""
    panel_gui._vars["port"].set("not-a-port")
    panel_gui._start()
    assert panel_gui.panel is None
    assert "port must be a number" in panel_gui.log.get("1.0", "end")
    assert str(panel_gui.start_btn["state"]) == "normal"
