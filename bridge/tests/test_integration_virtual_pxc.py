"""End-to-end: a point on a mock panel becomes a BACnet object with its value.

This is the test the bridge did not have. Everything else in this suite checks a
piece in isolation -- config parsing, object construction, symbol resolution --
and all of it passed while `--show-firmware` was completely non-functional. What
was missing is the one question that matters: **does a value travel from the
panel, through P2, into the BACnet object a supervisor would read?**

It runs against the mock PXC in-process, which is why it can run anywhere. The
mock is strict: it validates `msg_type` as a header length and drops a frame
whose value disagrees with its routing slots, exactly as a panel does. So this
also serves as a regression test for the framing model -- a bridge that went
back to hard-coding 0x33 would fail here rather than in a building.

The BACnet network is deliberately NOT bound. `build_object` and the poller are
the bridge's own code; `Application.from_object_list` is bacpypes3's, and
binding a UDP socket in a unit test buys a flaky port conflict rather than
coverage. `test_bacnet_app_builds` checks the app assembles.
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

import virtual_pxc                                    # noqa: E402
import p2_scanner                                  # noqa: E402

from p2_bridge.config import BridgeConfig, SiteConfig   # noqa: E402
from p2_bridge.manifest import Manifest, PointEntry     # noqa: E402
from p2_bridge.object_factory import build_object       # noqa: E402
from p2_bridge.poller import NodePoller                 # noqa: E402


@pytest.fixture(autouse=True)
def event_loop():
    """bacpypes3 objects need a loop on the thread that constructs them.

    `AnalogInputObject(...)` calls `asyncio.ensure_future(self._post_init())`,
    so even `build_object` -- which has nothing to do with the network -- fails
    outside a loop with "There is no current event loop in thread MainThread".
    `bacnet_app.run_application` documents the same constraint for the
    Application; it applies to every object too.

    The loop is set but not run: scheduling is all the constructor needs, and
    running it would mean driving bacpypes3's whole service stack to read an
    attribute.
    """
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


def _manifest_for(panel) -> Manifest:
    """One PointEntry per panel-internal point the mock serves.

    Panel points rather than FLN points on purpose: they are read through the
    bulk enumerate (0x0981), which is the path that had no mock handler at all
    and so had never been exercised end to end.
    """
    man = Manifest()
    inst = 1024
    for name in sorted(panel.panel_points):
        pp = panel.panel_points[name]
        analog = pp.get("value") is not None
        obj_type = "analogInput" if analog else "binaryInput"
        man.points.append(PointEntry(
            node=panel.node, host=panel.host, device=name,
            application=0, slot=0, name=name,
            p2_type="analog_ro" if analog else "digital_ro",
            bacnet_object_type=obj_type, bacnet_instance=inst,
            object_name=f"{panel.node}.PANEL.{name}",
            description=pp.get("description", ""), units=pp.get("units", ""),
            poll_interval_s=1, point_source="panel",
        ))
        inst += 1
    return man


def _run_one_cycle(panel, man, seconds=25.0):
    """Start a poller, wait for the panel enumerate to land, stop it."""
    site = SiteConfig(p2_network=panel.bln, scanner_name="P2BRIDGE",
                      p2_site=panel.site,
                      known_nodes={panel.node: panel.host})
    cfg = BridgeConfig(panel_enumerate_interval_s=1, inter_read_delay_s=0.0,
                       poll_jitter_s=0.0)
    objects = {(e.bacnet_object_type, e.bacnet_instance): build_object(e)
               for e in man.points}

    # The poller opens its own P2Connection; point it at the mock's port.
    real_ctor = p2_scanner.P2Connection

    def on_port(host, port=None, network=None, scanner_name=None):
        return real_ctor(host, port=panel.port, network=network,
                         scanner_name=scanner_name)

    stop = threading.Event()
    poller = NodePoller(panel.node, panel.host, site, cfg, man.points,
                        objects, stop, p2_scanner)
    poller.p2 = type("ScannerShim", (), {"P2Connection": staticmethod(on_port)})()
    poller.start()
    try:
        deadline = time.time() + seconds
        while time.time() < deadline:
            if poller.successful_reads:
                time.sleep(1.0)          # let the rest of the cycle land
                break
            time.sleep(0.2)
    finally:
        stop.set()
        poller.join(timeout=10)
    return objects, poller


def test_a_panel_value_reaches_its_bacnet_object(panel):
    man = _manifest_for(panel)
    objects, poller = _run_one_cycle(panel, man)

    assert poller.successful_reads, (
        "no point was read; the poller never completed a panel enumerate")

    by_name = {e.name: objects[(e.bacnet_object_type, e.bacnet_instance)]
               for e in man.points}

    # A float carried end to end, not merely "something arrived".
    chw = by_name["CHW.SUPPLY"]
    assert chw.presentValue == pytest.approx(
        panel.panel_points["CHW.SUPPLY"]["value"], abs=0.01)

    oa = by_name["OA.TEMP"]
    assert oa.presentValue == pytest.approx(
        panel.panel_points["OA.TEMP"]["value"], abs=0.01)


def test_a_read_clears_the_startup_fault_flag(panel):
    """Objects start faulted on purpose; a successful read must clear it."""
    man = _manifest_for(panel)
    objects, _ = _run_one_cycle(panel, man)
    entry = next(e for e in man.points if e.name == "CHW.SUPPLY")
    obj = objects[(entry.bacnet_object_type, entry.bacnet_instance)]
    assert list(obj.statusFlags) == [0, 0, 0, 0], (
        "fault flag still set after a good read")


def test_a_point_the_panel_does_not_serve_is_faulted(panel):
    """The other direction: a manifest entry with no panel point stays faulted.

    Without this, a bridge that silently reported stale zeros for every missing
    point would pass the test above.
    """
    man = _manifest_for(panel)
    ghost = PointEntry(
        node=panel.node, host=panel.host, device="NO.SUCH.POINT",
        application=0, slot=0, name="NO.SUCH.POINT", p2_type="analog_ro",
        bacnet_object_type="analogInput", bacnet_instance=9999,
        object_name=f"{panel.node}.PANEL.NO.SUCH.POINT",
        poll_interval_s=1, point_source="panel")
    man.points.append(ghost)

    objects, _ = _run_one_cycle(panel, man)
    obj = objects[("analogInput", 9999)]
    flags = list(obj.statusFlags)
    # statusFlags is [in_alarm, fault, overridden, out_of_service]. Assert the
    # FAULT bit, not the whole array: bacpypes3 derives in_alarm from
    # `eventState != normal`, so a faulted object reads [1, 1, 0, 0] however the
    # bridge writes it. That is BACnet-correct -- IN_ALARM is defined as
    # Event_State != NORMAL -- and `status.py` now says so.
    assert flags[1] == 1, f"missing point was not faulted (statusFlags={flags})"
    assert flags[0] == 1, "in_alarm should follow eventState=fault"


def test_engineering_units_survive_the_trip(panel):
    """`PCT RH` is the unit that exposed the scanner's units allowlist."""
    man = _manifest_for(panel)
    entry = next(e for e in man.points if e.name == "OA.HUMIDITY")
    assert entry.units == "PCT RH"
    obj = build_object(entry)
    from bacpypes3.basetypes import EngineeringUnits
    assert obj.units == EngineeringUnits.percentRelativeHumidity


def test_bacnet_app_builds_from_the_manifest(panel, event_loop):
    """The BACnet side assembles: device object, network port, one per point."""
    from p2_bridge.bacnet_app import build_application
    man = _manifest_for(panel)
    cfg = BridgeConfig(bacnet_address="127.0.0.1/24:47808")

    async def go():
        return build_application(cfg, man)

    app, objects, active = event_loop.run_until_complete(go())
    try:
        assert len(active) == len(man.points)
        assert len(objects) == len(man.points)
    finally:
        app.close()
