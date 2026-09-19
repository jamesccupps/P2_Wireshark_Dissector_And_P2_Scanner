"""Tests for _validate_bacnet_config — pre-flight BACnet identity validation."""
from __future__ import annotations

import pytest

from p2_bridge.config import BridgeConfig

import p2_bacnet_bridge as bridge


def _good_cfg() -> BridgeConfig:
    cfg = BridgeConfig()
    cfg.bacnet_device_instance = 599001
    cfg.bacnet_device_name = "P2-Bridge"
    cfg.bacnet_vendor_identifier = 999
    cfg.bacnet_address = "192.0.2.10/24:47808"
    return cfg


def test_valid_config_accepts():
    bridge._validate_bacnet_config(_good_cfg())  # no exception = pass


@pytest.mark.parametrize("instance", [-1, 4194303, 99999999])
def test_invalid_device_instance(instance):
    cfg = _good_cfg()
    cfg.bacnet_device_instance = instance
    with pytest.raises(ValueError, match="device_instance"):
        bridge._validate_bacnet_config(cfg)


@pytest.mark.parametrize("vendor", [-1, 65536, 100000])
def test_invalid_vendor(vendor):
    cfg = _good_cfg()
    cfg.bacnet_vendor_identifier = vendor
    with pytest.raises(ValueError, match="vendor"):
        bridge._validate_bacnet_config(cfg)


def test_empty_device_name():
    cfg = _good_cfg()
    cfg.bacnet_device_name = ""
    with pytest.raises(ValueError, match="device_name"):
        bridge._validate_bacnet_config(cfg)


def test_empty_bacnet_address():
    cfg = _good_cfg()
    cfg.bacnet_address = ""
    with pytest.raises(ValueError, match="bacnet_address"):
        bridge._validate_bacnet_config(cfg)


@pytest.mark.parametrize("addr", [
    "192.0.2.10:47808/24",       # transposed prefix and port
    "192.0.2.10/24",             # missing port
    "192.0.2.10",                # missing both
    "not-an-ip/24:47808",
    "192.0.2.999/24:47808",      # out-of-range octet
    "192.0.2.10/33:47808",       # out-of-range prefix
    "192.0.2.10/24:99999",       # out-of-range port
])
def test_malformed_bacnet_address(addr):
    cfg = _good_cfg()
    cfg.bacnet_address = addr
    with pytest.raises(ValueError, match="bacnet_address"):
        bridge._validate_bacnet_config(cfg)
