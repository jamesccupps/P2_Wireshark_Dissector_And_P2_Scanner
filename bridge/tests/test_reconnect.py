"""The poller's reconnect path, which had never run.

`NodePoller` carries capped exponential backoff, flips every point on the node
to comm-fault when the connection dies, and resets the backoff after a
successful reconnect. None of that had ever executed: the mock accepted a
connection and held it forever, so every test exercised the happy path and
stopped.

A panel is not that polite -- it reboots, it hits its session budget, the
network blips. These tests cut the connection underneath a running poller and
check the three things that have to happen:

  1. points go faulted rather than keeping a stale value that looks live;
  2. the poller reconnects on its own;
  3. values come back.

The third without the first is the dangerous outcome: a bridge that rides
through a panel outage showing the last good reading is worse than one that
goes red, because a supervisor trusts it.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

BRIDGE_ROOT = Path(__file__).resolve().parent.parent
PANEL_DIR = BRIDGE_ROOT.parent / "virtual_pxc"

if not (PANEL_DIR / "virtual_pxc.py").is_file():
    pytest.skip("virtual PXC not present beside the bridge",
                allow_module_level=True)
sys.path.insert(0, str(PANEL_DIR))

import virtual_pxc                                            # noqa: E402
import p2_scanner                                          # noqa: E402

from p2_bridge.config import BridgeConfig, SiteConfig      # noqa: E402
from p2_bridge.manifest import Manifest, PointEntry        # noqa: E402
from p2_bridge.object_factory import build_object          # noqa: E402
from p2_bridge.poller import NodePoller                    # noqa: E402


@pytest.fixture(autouse=True)
def event_loop():
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        yield loop
    finally:
        asyncio.set_event_loop(None)
        loop.close()


@pytest.fixture()
def panel():
    m = virtual_pxc.VirtualPxc.from_fixtures(PANEL_DIR / "fixtures.json")
    m.start()
    try:
        yield m
    finally:
        m.stop()


def _one_point_manifest(panel) -> Manifest:
    man = Manifest()
    man.points.append(PointEntry(
        node=panel.node, host=panel.host, device="CHW.SUPPLY",
        application=0, slot=0, name="CHW.SUPPLY", p2_type="analog_ro",
        bacnet_object_type="analogInput", bacnet_instance=1024,
        object_name=f"{panel.node}.PANEL.CHW.SUPPLY",
        units="DEG F", poll_interval_s=1, point_source="panel"))
    return man


class _Harness:
    def __init__(self, panel, man):
        self.panel, self.man = panel, man
        self.objects = {(e.bacnet_object_type, e.bacnet_instance): build_object(e)
                        for e in man.points}
        site = SiteConfig(p2_network=panel.bln, scanner_name="P2BRIDGE",
                          p2_site=panel.site,
                          known_nodes={panel.node: panel.host})
        cfg = BridgeConfig(panel_enumerate_interval_s=1, inter_read_delay_s=0.0,
                           poll_jitter_s=0.0,
                           reconnect_backoff_initial_s=1.0,
                           reconnect_backoff_max_s=3.0)
        real_ctor = p2_scanner.P2Connection

        def on_port(host, port=None, network=None, scanner_name=None):
            return real_ctor(host, port=panel.port, network=network,
                             scanner_name=scanner_name)

        self.stop = threading.Event()
        self.poller = NodePoller(panel.node, panel.host, site, cfg,
                                 man.points, self.objects, self.stop, p2_scanner)
        self.poller.p2 = type("Shim", (), {"P2Connection": staticmethod(on_port)})()

    @property
    def obj(self):
        e = self.man.points[0]
        return self.objects[(e.bacnet_object_type, e.bacnet_instance)]

    def start(self):
        self.poller.start()

    def stop_now(self):
        self.stop.set()
        self.poller.join(timeout=15)

    def wait(self, pred, seconds, what):
        deadline = time.time() + seconds
        while time.time() < deadline:
            if pred():
                return True
            time.sleep(0.2)
        pytest.fail(f"timed out waiting for {what}")

    def wait_good(self, seconds=25):
        self.wait(lambda: list(self.obj.statusFlags)[1] == 0,
                  seconds, "a good read")

    def wait_faulted(self, seconds=25):
        self.wait(lambda: list(self.obj.statusFlags)[1] == 1,
                  seconds, "the fault flag to set")


def test_a_dropped_connection_faults_the_points_then_recovers(panel):
    h = _Harness(panel, _one_point_manifest(panel))
    h.start()
    try:
        h.wait_good()
        good = h.obj.presentValue
        assert good == pytest.approx(44.2, abs=0.01)

        # A sustained outage, not a blip. Dropping alone is not observable:
        # the poller reconnects inside a second, and the fault window closes
        # before a 0.2s poll can see it -- which is the behaviour we want and
        # makes a bare drop untestable. Refusing the next few connections holds
        # the panel down long enough to assert on.
        panel.refuse_connections(4)
        cut = panel.drop_connections()
        assert cut >= 1, "no live connection to drop"

        # The point must NOT keep reading as live through the outage.
        h.wait_faulted(seconds=40)

        # And the poller must come back by itself once the panel answers again.
        h.wait_good(seconds=60)
        assert h.obj.presentValue == pytest.approx(good, abs=0.01)
    finally:
        h.stop_now()


def test_the_poller_retries_a_panel_that_refuses(panel):
    """Accepting and immediately closing is the nastier failure: TCP succeeds."""
    panel.refuse_connections(3)
    h = _Harness(panel, _one_point_manifest(panel))
    h.start()
    try:
        h.wait_good(seconds=60)
        assert panel.refused_connections == 3
        assert panel.accepted_connections > 3
    finally:
        h.stop_now()


def test_the_value_is_not_silently_stale_during_an_outage(panel):
    """The dangerous outcome, asserted directly.

    A bridge that rides through an outage still serving the last good reading is
    worse than one that goes red: a supervisor believes it. `presentValue` may
    legitimately hold its last value -- BACnet has no null -- but the fault flag
    and reliability must say the value is not current.
    """
    from bacpypes3.basetypes import Reliability
    h = _Harness(panel, _one_point_manifest(panel))
    h.start()
    try:
        h.wait_good()
        panel.refuse_connections(4)      # keep it down long enough to observe
        panel.drop_connections()
        h.wait_faulted(seconds=40)
        assert h.obj.reliability != Reliability.noFaultDetected, (
            "reliability still reads no-fault while the panel is unreachable")
    finally:
        h.stop_now()
