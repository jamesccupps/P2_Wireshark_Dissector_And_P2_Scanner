"""0x0240 and 0x0241 are point commands, and were named otherwise.

The catalog names them `AP2_POINT_CMD_VALUE` and `AP2_POINT_CMD_PRIORITY`, and
PROTOCOL.md 9.3 flags both DESTRUCTIVE: they command a live point. The scanner
called them `OP_WRITE_QUALITY` and `OP_PROPERTY_ECHO`, and the virtual PXC the
first of them `OP_WRITE_QUALITY`. "PropertyEcho" had no support anywhere: 9.5,
which the old comment cited, lists 0x0241 only as a body shape. A reader was
told one of the two writes was an echo. Same correction as the COV pair in
2.11.0 (test_cov_labels.py).
"""
from __future__ import annotations

import sys
from pathlib import Path

import p2_scanner as ps

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "virtual_pxc"))
import virtual_pxc  # noqa: E402


def test_the_scanner_names_the_point_commands_after_the_catalog():
    assert ps.P2Message.OP_POINT_CMD_VALUE == 0x0240
    assert ps.P2Message.OP_POINT_CMD_PRIORITY == 0x0241
    assert "POINT_CMD_VALUE" in ps.op_label(0x0240)
    assert "POINT_CMD_PRIORITY" in ps.op_label(0x0241)


def test_the_old_names_are_gone():
    for old in ("OP_WRITE_QUALITY", "OP_PROPERTY_ECHO"):
        assert not hasattr(ps.P2Message, old), old
    assert not hasattr(virtual_pxc, "OP_WRITE_QUALITY")


def test_the_virtual_pxc_uses_the_catalog_name():
    assert virtual_pxc.OP_POINT_CMD_VALUE == 0x0240


def test_both_are_refused_by_the_guard():
    for op in (0x0240, 0x0241):
        assert op in ps.REFUSED_OPCODES, hex(op)
