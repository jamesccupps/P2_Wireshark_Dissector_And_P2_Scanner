"""
manifest.py — Persistent map of P2 points → BACnet objects.

The manifest is the single source of truth for what the bridge exposes. It's
generated once by `tools/build_manifest.py` (which uses the P2 Scanner library
to walk the site), then read by the bridge at startup.

Why persistent: BACnet supervisors bind to objects by instance ID. If the
bridge re-allocated IDs every restart, every supervisor mapping would break.
The manifest is append-only — `merge_discoveries()` keeps existing IDs and
only allocates new ones for newly-discovered points.

Schema (manifest_schema_version=1):
{
  "manifest_schema_version": 1,
  "generated_utc": "2025-...",
  "next_instance_ids": {
    "analogInput": 1024,
    "analogValue": 1024,
    "binaryInput": 1024,
    "binaryValue": 1024
  },
  "points": [
    {
      "node": "NODE3",
      "host": "192.168.1.10",
      "device": "AHU1",
      "application": 2027,
      "slot": 4,
      "name": "ROOM TEMP",
      "p2_type": "analog_ro",
      "bacnet_object_type": "analogInput",
      "bacnet_instance": 1024,
      "object_name": "NODE3.AHU1.ROOM_TEMP",
      "description": "Slot 4, app 2027",
      "units": "DEG F",
      "on_label": null,
      "off_label": null,
      "slope": null,
      "intercept": null,
      "poll_interval_s": 60,
      "enabled": true
    },
    ...
  ]
}
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger(__name__)

MANIFEST_SCHEMA_VERSION = 1

# Map from P2 type string to BACnet object type string.
P2_TYPE_TO_BACNET = {
    "analog_ro": "analogInput",
    "analog_rw": "analogValue",
    "digital_ro": "binaryInput",
    "digital_rw": "binaryValue",
}


@dataclass
class PointEntry:
    node: str
    host: str
    device: str
    application: int
    slot: int
    name: str
    p2_type: str                # 'analog_ro' / 'analog_rw' / 'digital_ro' / 'digital_rw'
    bacnet_object_type: str     # 'analogInput' / 'analogValue' / 'binaryInput' / 'binaryValue'
    bacnet_instance: int
    object_name: str
    description: str = ""
    units: str = ""
    on_label: Optional[str] = None
    off_label: Optional[str] = None
    slope: Optional[float] = None
    intercept: Optional[float] = None
    poll_interval_s: int = 60
    enabled: bool = True
    # Human-readable description of the parent device — populated from the
    # PXC's FLN enumerate response (e.g. "K408 — CONFERENCE", "DIVV1 — DIRIG
    # CONF"). Operators recognize spaces by these names; the BACnet device-name
    # alone (DIVV1) is meaningless to anyone who didn't commission the panel.
    # Default empty for backwards compatibility with manifests built before
    # this field existed.
    device_description: str = ""
    # Where this point lives in the panel's namespace:
    #   "fln"   — point is on a TEC device on the FLN bus (most common)
    #   "panel" — point is panel-internal (PPCL variable, BLN-sourced,
    #             outside-air, system-wide setpoint, etc.). Read by
    #             passing the point name as both the device and point
    #             argument to read_point().
    point_source: str = "fln"

    @property
    def key(self) -> tuple:
        """Stable identity tuple for matching this point across rebuilds."""
        return (self.node, self.device, self.slot, self.name)


@dataclass
class Manifest:
    next_instance_ids: Dict[str, int] = field(default_factory=lambda: {
        "analogInput": 1024,
        "analogValue": 1024,
        "binaryInput": 1024,
        "binaryValue": 1024,
    })
    points: List[PointEntry] = field(default_factory=list)
    generated_utc: str = ""

    def to_dict(self) -> dict:
        return {
            "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
            "generated_utc": self.generated_utc,
            "next_instance_ids": dict(self.next_instance_ids),
            "points": [asdict(p) for p in self.points],
        }

    def save(self, path: Path) -> None:
        self.generated_utc = datetime.now(timezone.utc).isoformat()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        log.info("Wrote manifest with %d points to %s", len(self.points), path)

    @classmethod
    def load(cls, path: Path) -> "Manifest":
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        ver = raw.get("manifest_schema_version", 0)
        if ver != MANIFEST_SCHEMA_VERSION:
            raise ValueError(
                f"Manifest schema version {ver} is incompatible with this "
                f"build (expected {MANIFEST_SCHEMA_VERSION}). Regenerate the "
                f"manifest with tools/build_manifest.py."
            )
        m = cls(
            next_instance_ids=raw.get("next_instance_ids", {}),
            points=[PointEntry(**p) for p in raw.get("points", [])],
            generated_utc=raw.get("generated_utc", ""),
        )
        return m

    @classmethod
    def empty(cls, instance_id_start: int = 1024) -> "Manifest":
        return cls(next_instance_ids={
            "analogInput": instance_id_start,
            "analogValue": instance_id_start,
            "binaryInput": instance_id_start,
            "binaryValue": instance_id_start,
        })

    def existing_keys(self) -> set:
        return {p.key for p in self.points}

    def used_instances(self, object_type: str) -> set:
        return {p.bacnet_instance for p in self.points
                if p.bacnet_object_type == object_type}

    def allocate_instance(self, object_type: str) -> int:
        """Allocate the next free instance ID for a given object type."""
        used = self.used_instances(object_type)
        candidate = self.next_instance_ids.get(object_type, 1024)
        while candidate in used:
            candidate += 1
        self.next_instance_ids[object_type] = candidate + 1
        return candidate


# ─────────────────────────────────────────────────────────────────────────────
# Object-name sanitization
#
# BACnet object names have constraints across the ecosystem:
#   - Must be unique within a device
#   - Most supervisors prefer ASCII, no whitespace, max ~64 chars
#   - Periods are commonly interpreted as hierarchy separators by supervisors
#     (Niagara, some Tridium-flavored stacks). The bridge uses '.' as the
#     join character between NODE/DEVICE/POINT, so periods MUST NOT appear
#     inside any one of those three parts. Otherwise a point named "DAY.NGT"
#     becomes "NODE3.DEVICE.DAY.NGT" which a supervisor reads as a 4-level
#     hierarchy with a phantom DAY folder.
#   - Avoid characters BACnet text frames don't like: control chars
#
# The scheme: NODE.DEVICE.POINT  with whitespace, periods, and other special
# chars inside any part replaced with underscores; runs of underscores are
# collapsed for readability.
# ─────────────────────────────────────────────────────────────────────────────

_OBJ_NAME_BAD_CHARS = re.compile(r"[^A-Za-z0-9_\-]")
_MULTI_UNDERSCORE = re.compile(r"_+")
_MAX_NAME_LEN = 64


def sanitize_part(s: str) -> str:
    """Convert one path component (node / device / point name) to a
    BACnet-safe form. Periods are stripped because make_object_name() uses
    them as the structural separator between parts."""
    s = s.strip().upper().replace(" ", "_")
    s = _OBJ_NAME_BAD_CHARS.sub("_", s)
    s = _MULTI_UNDERSCORE.sub("_", s)
    s = s.strip("_")
    return s


def make_object_name(node: str, device: str, point: str) -> str:
    n = sanitize_part(node)
    d = sanitize_part(device)
    p = sanitize_part(point)
    name = f"{n}.{d}.{p}"
    # If too long, truncate the point name (keep node and device intact for
    # supervisor navigation). BACnet names must remain unique — the manifest
    # builder will detect collisions and append a suffix.
    if len(name) > _MAX_NAME_LEN:
        budget = _MAX_NAME_LEN - len(n) - len(d) - 2  # 2 for the two dots
        budget = max(8, budget)
        p = p[:budget]
        name = f"{n}.{d}.{p}"
    return name


def make_description(entry_kwargs: dict) -> str:
    """Build a useful BACnet `description` for a point.

    Format: "{device_description} · slot N, app NNNN, units · LABEL/LABEL"
    The leading device description is the most useful piece for an
    operator — it tells them WHAT physical space the point is in. The
    bracket of slot / app / units is technical context; the on/off
    labels matter for digital points.
    """
    parts: List[str] = []
    dev_desc = (entry_kwargs.get("device_description") or "").strip()
    if dev_desc:
        parts.append(dev_desc)
    technical = [f"slot {entry_kwargs['slot']}",
                 f"app {entry_kwargs['application']}"]
    if entry_kwargs.get("units"):
        technical.append(entry_kwargs["units"])
    parts.append(", ".join(technical))
    if entry_kwargs.get("on_label") and entry_kwargs.get("off_label"):
        parts.append(f"{entry_kwargs['on_label']}/{entry_kwargs['off_label']}")
    return " · ".join(parts)
