"""Tests for the bridge's SIGHUP-triggered config reload helper.

H-20: reload poll cadence / log level live without restarting the bridge
(which would tear down BACnet sessions and pay the reconnect cost
again on every panel reconnect).
"""
from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

from p2_bridge.config import BridgeConfig

import p2_bacnet_bridge as bridge


def _make_temp_cfg(**overrides) -> Path:
    base = {
        "bacnet_device_instance": 599001,
        "bacnet_device_name": "TestBridge",
        "bacnet_vendor_identifier": 999,
        "bacnet_address": "0.0.0.0/24:47808",
        "default_poll_interval_s": 60,
        "digital_poll_interval_s": 30,
        "inter_read_delay_s": 0.05,
        "poll_jitter_s": 5.0,
        "panel_enumerate_interval_s": 60,
        "reconnect_backoff_initial_s": 5.0,
        "reconnect_backoff_max_s": 300.0,
        "log_level": "INFO",
    }
    base.update(overrides)
    tmp = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
    json.dump(base, tmp)
    tmp.close()
    return Path(tmp.name)


def test_reload_updates_polling_intervals(tmp_path):
    initial = _make_temp_cfg()
    cfg = BridgeConfig.from_file(initial)
    log = logging.getLogger("test")

    updated = _make_temp_cfg(default_poll_interval_s=120,
                             digital_poll_interval_s=45,
                             inter_read_delay_s=0.10,
                             poll_jitter_s=8.0)
    bridge._reload_bridge_config(updated, cfg, log)
    try:
        assert cfg.default_poll_interval_s == 120
        assert cfg.digital_poll_interval_s == 45
        assert cfg.inter_read_delay_s == 0.10
        assert cfg.poll_jitter_s == 8.0
    finally:
        initial.unlink()
        updated.unlink()


def test_reload_updates_log_level():
    initial = _make_temp_cfg(log_level="INFO")
    cfg = BridgeConfig.from_file(initial)
    log = logging.getLogger("test")

    updated = _make_temp_cfg(log_level="DEBUG")
    bridge._reload_bridge_config(updated, cfg, log)
    try:
        assert cfg.log_level == "DEBUG"
    finally:
        initial.unlink()
        updated.unlink()


def test_reload_does_not_touch_bacnet_identity():
    # Identity fields are NOT in the reload-safe list — they require a
    # restart because BACnet supervisors bind to them. The reload should
    # leave them as the original cfg had, even if the new file says
    # something different.
    initial = _make_temp_cfg(bacnet_device_instance=599001,
                             bacnet_device_name="Original")
    cfg = BridgeConfig.from_file(initial)
    log = logging.getLogger("test")

    updated = _make_temp_cfg(bacnet_device_instance=600000,
                             bacnet_device_name="Different")
    bridge._reload_bridge_config(updated, cfg, log)
    try:
        # These must NOT change.
        assert cfg.bacnet_device_instance == 599001
        assert cfg.bacnet_device_name == "Original"
    finally:
        initial.unlink()
        updated.unlink()


def test_reload_missing_file_logs_error(caplog):
    cfg = BridgeConfig()
    log = logging.getLogger("test")
    with caplog.at_level(logging.ERROR):
        bridge._reload_bridge_config(Path("/nonexistent/bridge_config.json"),
                                     cfg, log)
    assert any("bridge config not found" in r.message for r in caplog.records)


def test_reload_malformed_file_logs_error(caplog):
    cfg = BridgeConfig()
    tmp = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False)
    tmp.write("not valid json{")
    tmp.close()
    path = Path(tmp.name)
    log = logging.getLogger("test")
    with caplog.at_level(logging.ERROR):
        bridge._reload_bridge_config(path, cfg, log)
    try:
        assert any("failed to parse" in r.message for r in caplog.records)
    finally:
        path.unlink()
