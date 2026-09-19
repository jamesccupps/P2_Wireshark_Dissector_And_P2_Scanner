"""
config.py — Bridge configuration loading and validation.

The bridge takes two config files:
  - site.json       — same format as P2 Scanner: known_nodes, p2_network, etc.
  - bridge_config.json — BACnet device identity + bridge runtime knobs.

Keeping them separate means the bridge can share a site.json with the scanner
(and re-use --cold-discover output) while having its own BACnet config.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, Optional

# Single source of truth for the bridge version. Used as the default for
# bacnet_firmware_revision and bacnet_application_software_version below
# so they don't drift across releases. Callers can still override per-site
# in bridge_config.json.
from p2_bridge import __version__ as _BRIDGE_VERSION

log = logging.getLogger(__name__)


@dataclass
class BridgeConfig:
    # BACnet device identity
    bacnet_device_instance: int = 999999
    bacnet_device_name: str = "P2-Bridge"
    bacnet_device_description: str = "P2-to-BACnet Bridge"
    bacnet_vendor_identifier: int = 999  # Use a real vendor ID in production
    bacnet_vendor_name: str = "P2 Bridge Project"
    bacnet_model_name: str = "p2-bacnet-bridge"
    bacnet_firmware_revision: str = _BRIDGE_VERSION
    bacnet_application_software_version: str = _BRIDGE_VERSION

    # BACnet network binding — "IP/PREFIX:PORT", e.g. "192.168.1.50/24:47808"
    # Subnet mask matters: the bridge will speak BACnet broadcast on the
    # local subnet derived from this. If the bridge runs on the HVAC VLAN,
    # set this to a /24 inside that VLAN.
    bacnet_address: str = "0.0.0.0/24:47808"

    # Object instance ranges. Each P2 point is allocated one instance ID
    # within its object type's range. Numbers below `start` are reserved
    # for the bridge itself (device object, network port, etc.)
    instance_id_start: int = 1024

    # Polling
    default_poll_interval_s: int = 60     # AI/AV analog points
    digital_poll_interval_s: int = 30     # BI/BV digital points
    inter_read_delay_s: float = 0.05      # Match scanner default; be polite to PXCs
    poll_jitter_s: float = 5.0            # Stagger poll cycles to avoid thundering herd

    # Panel-internal points are read in bulk via opcode 0x0981 (enumerate).
    # The Points section of a PXC is a separate namespace from FLN devices —
    # virtual points, PPCL working variables, and panel I/O all live there
    # and respond only to the bulk enumerate, not to per-point read_point().
    # One enumerate covers every panel point on a node in ~10–20 seconds.
    panel_enumerate_interval_s: int = 60

    # Connection management
    reconnect_backoff_initial_s: float = 5.0
    reconnect_backoff_max_s: float = 300.0

    # Logging. Rotation prevents unbounded growth on long-running
    # deployments. Defaults give 10 MB × 5 generations = ~50 MB cap.
    log_level: str = "INFO"
    log_file: Optional[str] = "p2_bacnet_bridge.log"
    log_max_bytes: int = 10 * 1024 * 1024
    log_backup_count: int = 5

    @classmethod
    def from_file(cls, path: Path) -> "BridgeConfig":
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        # Ignore comment keys
        cleaned = {k: v for k, v in raw.items() if not k.startswith("_")}
        return cls(**cleaned)


@dataclass
class SiteConfig:
    """Subset of P2 Scanner's site.json that the bridge needs."""
    p2_network: str
    scanner_name: str
    p2_site: str = "SITE"
    known_nodes: Dict[str, str] = field(default_factory=dict)
    # Firmware build tag per host IP. Populated by the scanner's 0x010C
    # SystemInfo reader (PROTOCOL.md §10.5, CABINET_DISPLAY) and persisted to
    # site.json, so a panel already identified does not need a fresh read to
    # name its firmware. Purely a convenience -- nothing about framing depends
    # on the build tag.
    known_builds: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: Path) -> "SiteConfig":
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        cleaned = {k: v for k, v in raw.items() if not k.startswith("_")}

        if not cleaned.get("p2_network"):
            raise ValueError(
                f"{path}: 'p2_network' is required. Run the P2 scanner with "
                "--cold-discover to populate this file."
            )
        if not cleaned.get("known_nodes"):
            raise ValueError(
                f"{path}: 'known_nodes' is empty. Run the P2 scanner with "
                "--cold-discover or --discover to populate this file."
            )
        # Use only the keys we need; ignore others (forward-compat with scanner)
        return cls(
            p2_network=cleaned["p2_network"],
            scanner_name=cleaned.get("scanner_name", "P2BRIDGE|5034"),
            p2_site=cleaned.get("p2_site", "SITE"),
            known_nodes=cleaned["known_nodes"],
            known_builds=cleaned.get("known_builds", {}),
        )


def setup_logging(cfg: BridgeConfig) -> None:
    """Initialize stdlib logging from bridge config.

    Uses RotatingFileHandler so long-running deployments don't fill the
    disk with an unbounded log. Defaults from BridgeConfig give a ~50 MB
    cap (10 MB × 5 generations); tune via log_max_bytes / log_backup_count
    in bridge_config.json.
    """
    level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if cfg.log_file:
        handlers.append(RotatingFileHandler(
            cfg.log_file,
            maxBytes=cfg.log_max_bytes,
            backupCount=cfg.log_backup_count,
            encoding='utf-8',
        ))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )
