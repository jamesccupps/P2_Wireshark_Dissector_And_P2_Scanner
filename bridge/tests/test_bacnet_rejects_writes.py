"""The bridge's BACnet side refuses writes, through the real path.

bacpypes3's Application answers WriteProperty and WritePropertyMultiple for
every property by default. Through bridge 0.5.0 the bridge used it as is, so a
BACnet client could overwrite a bridged presentValue, set outOfService, or
rename a point or the device -- while the README said "writes are rejected".
Found 2026-11-20 by trying it, not by reading the claim.

This builds the bridge's own application on loopback and talks to it with a
real bacpypes3 client, the way a supervisor would: a read must work, every
write must be refused, and the value must be unchanged afterwards.
"""
from __future__ import annotations

import asyncio

import pytest

from bacpypes3.apdu import ErrorRejectAbortNack, RejectPDU
from bacpypes3.app import Application
from bacpypes3.local.device import DeviceObject
from bacpypes3.local.networkport import NetworkPortObject
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import ObjectIdentifier

from p2_bridge.bacnet_app import ReadOnlyApplication, build_application
from p2_bridge.config import BridgeConfig
from p2_bridge.manifest import Manifest, PointEntry

BRIDGE_PORT, CLIENT_PORT = 47941, 47942


def _entry(kind, inst, name):
    return PointEntry(node="NODE1", host="192.0.2.20", device="VAV001",
                      application=2021, slot=inst, name=name,
                      p2_type="analog_rw" if kind.startswith("analog") else "digital_rw",
                      bacnet_object_type=kind, bacnet_instance=inst,
                      object_name="VAV001." + name)


WRITES = [
    ("analogValue:1", "presentValue", 99.0),
    ("analogValue:1", "outOfService", True),
    ("analogValue:1", "objectName", "RENAMED"),
    ("analogValue:1", "description", "rewritten"),
    ("binaryValue:2", "presentValue", "active"),
    ("device:{dev}", "objectName", "RENAMED-DEVICE"),
]


def _run(coro):
    return asyncio.run(asyncio.wait_for(coro, 30))


def test_the_write_services_have_no_handler():
    assert ReadOnlyApplication.do_WritePropertyRequest is None
    assert ReadOnlyApplication.do_WritePropertyMultipleRequest is None


def test_a_client_can_read_but_not_write():
    async def go():
        cfg = BridgeConfig(bacnet_address="127.0.0.1/24:%d" % BRIDGE_PORT)
        man = Manifest(points=[_entry("analogValue", 1, "ROOM TEMP"),
                               _entry("binaryValue", 2, "FAN CMD")])
        app, objects, _ = build_application(cfg, man)
        assert isinstance(app, ReadOnlyApplication)
        objects[("analogValue", 1)].presentValue = 72.5
        client = Application.from_object_list([
            DeviceObject(objectIdentifier=("device", 599), objectName="client",
                         vendorIdentifier=999),
            NetworkPortObject("127.0.0.1/24:%d" % CLIENT_PORT,
                              objectIdentifier=("networkPort", 1), objectName="NP-1"),
        ])
        bridge = Address("127.0.0.1:%d" % BRIDGE_PORT)
        outcomes = []
        try:
            read = await client.read_property(bridge, ObjectIdentifier("analogValue:1"),
                                              "presentValue")
            assert float(read) == pytest.approx(72.5), "the control read failed"
            for oid, prop, value in WRITES:
                oid = oid.format(dev=cfg.bacnet_device_instance)
                before = await client.read_property(bridge, ObjectIdentifier(oid), prop)
                # A refusal comes back as a RejectPDU, which bacpypes3 raises as
                # a BaseException (ErrorRejectAbortNack), not an Exception.
                try:
                    await client.write_property(bridge, ObjectIdentifier(oid), prop, value)
                    refused = False
                except ErrorRejectAbortNack as err:
                    refused = isinstance(err, RejectPDU)
                after = await client.read_property(bridge, ObjectIdentifier(oid), prop)
                outcomes.append((oid, prop, refused, before == after))
        finally:
            client.close()
            app.close()
        return outcomes

    for oid, prop, refused, unchanged in _run(go()):
        assert refused, "%s %s: the write was not rejected" % (oid, prop)
        assert unchanged, "%s %s: the value changed" % (oid, prop)
