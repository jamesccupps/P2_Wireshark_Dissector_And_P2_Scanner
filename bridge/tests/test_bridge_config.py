"""Tests for BridgeConfig and SiteConfig — load, defaults, and validation."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path


from p2_bridge import __version__ as BRIDGE_VERSION
from p2_bridge.config import BridgeConfig, SiteConfig


def _write_json(data: dict) -> Path:
    tmp = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
    json.dump(data, tmp)
    tmp.close()
    return Path(tmp.name)


# ─────────────────────────────────────────────────────────────────────────────
# BridgeConfig
# ─────────────────────────────────────────────────────────────────────────────


def test_bridge_config_version_derived_from_package():
    cfg = BridgeConfig()
    assert cfg.bacnet_firmware_revision == BRIDGE_VERSION
    assert cfg.bacnet_application_software_version == BRIDGE_VERSION


def test_bridge_config_polling_defaults_match_scanner():
    # H-1: scanner and bridge agree on polling cadence — 60s analog, 30s
    # digital. Drift between these and bridge_config.json.example surfaced
    # as a 4x slowdown bug for users copying from the example.
    cfg = BridgeConfig()
    assert cfg.default_poll_interval_s == 60
    assert cfg.digital_poll_interval_s == 30


def test_bridge_config_log_rotation_defaults():
    cfg = BridgeConfig()
    assert cfg.log_max_bytes == 10 * 1024 * 1024
    assert cfg.log_backup_count == 5


def test_bridge_config_from_file_ignores_comment_keys():
    path = _write_json({
        "_comment": "header explaining the file",
        "bacnet_device_instance": 599001,
        "_comment_polling": "explainer for polling",
        "default_poll_interval_s": 90,
    })
    try:
        cfg = BridgeConfig.from_file(path)
        assert cfg.bacnet_device_instance == 599001
        assert cfg.default_poll_interval_s == 90
    finally:
        path.unlink()


# ─────────────────────────────────────────────────────────────────────────────
# SiteConfig — known_builds round-trip
# ─────────────────────────────────────────────────────────────────────────────


def test_site_config_known_builds_default_empty():
    site = SiteConfig(p2_network="MYBLN", scanner_name="P2SCAN|5034")
    assert site.known_builds == {}


def test_site_config_known_builds_persists():
    path = _write_json({
        "p2_network": "MYBLN",
        "scanner_name": "P2BRIDGE|5034",
        "p2_site": "SITE",
        "known_nodes": {"NODE1": "192.0.2.1"},
        "known_builds": {"192.0.2.1": "PME1300", "192.0.2.2": "PME1252"},
    })
    try:
        site = SiteConfig.from_file(path)
        assert site.known_builds == {
            "192.0.2.1": "PME1300",
            "192.0.2.2": "PME1252",
        }
    finally:
        path.unlink()


def test_site_config_missing_known_builds_is_empty_dict():
    # Backward-compat: site.json without `known_builds` should still load.
    path = _write_json({
        "p2_network": "MYBLN",
        "scanner_name": "P2BRIDGE|5034",
        "known_nodes": {"NODE1": "192.0.2.1"},
    })
    try:
        site = SiteConfig.from_file(path)
        assert site.known_builds == {}
    finally:
        path.unlink()
