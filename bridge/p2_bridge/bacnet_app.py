"""
bacnet_app.py — Build and host the BACnet/IP application from a manifest.

bacpypes3 is asyncio-based: the Application runs inside an event loop and
serves BACnet requests asynchronously. The pollers run in regular threads
(because P2Connection is synchronous). They update bacpypes3 object
attributes directly — for scalar values and small lists this is safe under
CPython's GIL. The cost is that a supervisor's ReadProperty might
occasionally read a value that was being written; the next read picks up
the new value cleanly.

Concurrency note: if you start observing torn reads in production (you
won't, with this object volume), the upgrade path is to push updates
through asyncio.Queue and apply them on the BACnet thread. That work is
intentionally NOT in v0.1.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Tuple

from bacpypes3.app import Application
from bacpypes3.local.device import DeviceObject
from bacpypes3.local.networkport import NetworkPortObject
from bacpypes3.basetypes import ServicesSupported

from .config import BridgeConfig
from .manifest import Manifest, PointEntry
from .object_factory import build_object

log = logging.getLogger(__name__)


def build_application(
    cfg: BridgeConfig,
    manifest: Manifest,
) -> Tuple[Application, Dict[Tuple[str, int], object], List[PointEntry]]:
    """
    Build a bacpypes3 Application with one BACnet object per manifest entry.

    Returns:
        - app: the Application (call await app.start() to begin serving).
        - objects: {(object_type, instance): bacpypes3_object} for fast
          lookup from pollers.
        - active_entries: list of PointEntry that successfully became BACnet
          objects (excludes anything we failed to build, with errors logged).
    """
    device = DeviceObject(
        objectIdentifier=("device", cfg.bacnet_device_instance),
        objectName=cfg.bacnet_device_name,
        description=cfg.bacnet_device_description,
        vendorIdentifier=cfg.bacnet_vendor_identifier,
        vendorName=cfg.bacnet_vendor_name,
        modelName=cfg.bacnet_model_name,
        firmwareRevision=cfg.bacnet_firmware_revision,
        applicationSoftwareVersion=cfg.bacnet_application_software_version,
        # Standard read-only support
        protocolVersion=1,
        protocolRevision=22,
        protocolServicesSupported=_basic_services_supported(),
    )

    network_port = NetworkPortObject(
        cfg.bacnet_address,
        objectName="NP-1",
        objectIdentifier=("networkPort", 1),
    )

    bacnet_objects: List[object] = [device, network_port]
    objects_by_id: Dict[Tuple[str, int], object] = {}
    active_entries: List[PointEntry] = []

    for entry in manifest.points:
        if not entry.enabled:
            continue
        try:
            obj = build_object(entry)
        except Exception as e:
            log.error("Failed to build BACnet object for %s: %s",
                      entry.object_name, e)
            continue
        bacnet_objects.append(obj)
        objects_by_id[(entry.bacnet_object_type, entry.bacnet_instance)] = obj
        active_entries.append(entry)

    log.info("Built BACnet app: device %d (%s) + %d points",
             cfg.bacnet_device_instance, cfg.bacnet_device_name,
             len(active_entries))

    app = Application.from_object_list(bacnet_objects)
    return app, objects_by_id, active_entries


#: The services this bridge actually answers, named rather than numbered.
#:
#: An earlier edition hard-coded `(12, 14, 26, 27, 35, 36)` believing 35 and 36
#: to be who-Is and who-Has. They are **readRange** and
#: **utcTimeSynchronization** -- so the device advertised two services it does
#: not implement, and did not advertise the two it does. who-Has and who-Is are
#: 33 and 34.
#:
#: Taking the numbers from the enum instead of restating them means the next
#: reader cannot get this wrong, and a bacpypes3 that renumbers anything is a
#: build error rather than a silent mis-advertisement.
_SUPPORTED_SERVICES = (
    "readProperty",
    "readPropertyMultiple",
    "iAm",
    "iHave",
    "whoHas",
    "whoIs",
)


def _basic_services_supported() -> ServicesSupported:
    """Advertise exactly the read-only services this bridge answers."""
    flags = [0] * ServicesSupported._bitstring_length
    for name in _SUPPORTED_SERVICES:
        flags[getattr(ServicesSupported, name)] = 1
    return ServicesSupported(flags)


async def run_application(
    app_builder,
    stop_event: asyncio.Event,
    on_started=None,
):
    """
    Build and run the bacpypes3 Application until stop_event is set.

    bacpypes3 binds its UDP socket synchronously inside Application
    construction, and that path calls asyncio.get_running_loop(). So the
    Application MUST be built inside a running event loop. We accept a
    builder callable so the caller can stay synchronous and still get the
    objects/entries back via `on_started`.

    Args:
        app_builder: zero-arg callable returning (app, objects_by_id,
            active_entries). Called once, inside this coroutine.
        stop_event: asyncio Event that, when set, triggers a clean shutdown.
        on_started: optional callback receiving (app, objects_by_id,
            active_entries) once the app is up — caller uses this to start
            its pollers.
    """
    app, objects_by_id, active_entries = app_builder()
    log.info("BACnet/IP service started")
    if on_started is not None:
        on_started(app, objects_by_id, active_entries)
    try:
        await stop_event.wait()
    finally:
        log.info("BACnet/IP service stopping")
        app.close()
