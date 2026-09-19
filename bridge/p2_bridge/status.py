"""
status.py — Translate P2 scanner results to BACnet object state.

This is the heart of the comm-fault propagation. The P2 scanner returns one
of three meaningful states for each read:

  1. result is None
       Network failure, parse failure, or PXC silent.
       → reliability = communicationFailure, fault status flag, hold last value

  2. result['comm_status'] == 'comm_fault'
       PXC returned cached data because the FLN device is offline (Desigo's
       #COM indicator).
       → reliability = noOutput, fault status flag, present cached value
       This matches what Desigo CC shows.

  3. result['comm_status'] in (None, 'online') and value is not None
       Live good read.
       → reliability = noFaultDetected, all status flags clear, update value

The BACnet status_flags array is [in_alarm, fault, overridden, out_of_service]
per the BACnet spec — fault flag is what most supervisors color red.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

from bacpypes3.basetypes import Reliability, EventState

from .manifest import PointEntry

log = logging.getLogger(__name__)


# Reliability is an enum with int backing in bacpypes3. We pass int values
# directly into setters because that's what the wire encoder uses.
RELIABILITY_OK = Reliability.noFaultDetected
RELIABILITY_COMM_FAILURE = Reliability.communicationFailure
RELIABILITY_NO_OUTPUT = Reliability.noOutput

STATUS_FLAGS_OK = [0, 0, 0, 0]
STATUS_FLAGS_FAULT = [0, 1, 0, 0]

# What a supervisor actually reads back from a faulted object is [1, 1, 0, 0],
# not the [0, 1, 0, 0] written above: bacpypes3 derives in_alarm from
# `eventState != normal`, and every path that sets STATUS_FLAGS_FAULT also sets
# eventState = fault. That is BACnet-correct -- IN_ALARM is defined as
# Event_State != NORMAL -- so the library is right and this constant is simply
# not the last word. Noted because a reader comparing the two would otherwise
# assume one of them is a bug.


@dataclass
class ObjectUpdate:
    """A single update to apply to a BACnet object."""
    present_value: Optional[Any]   # None means leave unchanged (hold last good)
    reliability: int
    status_flags: list
    event_state: int = EventState.normal


def update_from_read(entry: PointEntry, result: Optional[Dict]) -> ObjectUpdate:
    """
    Translate one P2 read result into a BACnet object update.

    Args:
        entry: Manifest entry — knows the object type and on/off labels.
        result: Dict from P2Connection.read_point(), or None on read failure.

    Returns:
        ObjectUpdate with the new presentValue (or None to hold), reliability,
        and status flags.
    """
    # Case 1: total read failure
    if result is None:
        return ObjectUpdate(
            present_value=None,
            reliability=RELIABILITY_COMM_FAILURE,
            status_flags=STATUS_FLAGS_FAULT,
            event_state=EventState.fault,
        )

    value = result.get("value")
    comm_status = result.get("comm_status")

    # Case 2: PXC reported comm fault on the FLN device (Desigo #COM)
    if comm_status == "comm_fault":
        # The PXC returned cached data — present it but flag fault so the
        # supervisor knows the value is stale.
        return ObjectUpdate(
            present_value=_translate_value(entry, value),
            reliability=RELIABILITY_NO_OUTPUT,
            status_flags=STATUS_FLAGS_FAULT,
            event_state=EventState.fault,
        )

    # Case 3: PXC parsed the response but value is None (shouldn't normally
    # happen if comm_status is online, but defensive).
    if value is None:
        return ObjectUpdate(
            present_value=None,
            reliability=RELIABILITY_COMM_FAILURE,
            status_flags=STATUS_FLAGS_FAULT,
            event_state=EventState.fault,
        )

    # Case 4: live good read
    return ObjectUpdate(
        present_value=_translate_value(entry, value),
        reliability=RELIABILITY_OK,
        status_flags=STATUS_FLAGS_OK,
        event_state=EventState.normal,
    )


def _translate_value(entry: PointEntry, raw: float):
    """
    Convert a P2 raw float into the right type for the BACnet object.

    Analog: float passes through unchanged.
    Binary: 1 (>= 0.5) → 'active'; 0 → 'inactive'. Matches the Siemens
    convention encoded in render_point_value() in p2_scanner.
    """
    if raw is None:
        return None
    if entry.bacnet_object_type in ("analogInput", "analogValue"):
        return float(raw)
    if entry.bacnet_object_type in ("binaryInput", "binaryValue"):
        return "active" if raw >= 0.5 else "inactive"
    log.warning("Unknown object type for %s: %s", entry.object_name,
                entry.bacnet_object_type)
    return raw


def apply_update(obj, update: ObjectUpdate) -> None:
    """Push an ObjectUpdate into a live bacpypes3 object."""
    if update.present_value is not None:
        try:
            obj.presentValue = update.present_value
        except Exception as e:
            log.warning("Failed to set presentValue on %s: %s",
                        obj.objectName, e)
    try:
        obj.reliability = update.reliability
        obj.statusFlags = update.status_flags
        obj.eventState = update.event_state
    except Exception as e:
        log.warning("Failed to set status fields on %s: %s",
                    obj.objectName, e)
