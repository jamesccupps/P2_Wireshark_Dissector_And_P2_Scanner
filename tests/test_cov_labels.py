"""0x0271 and 0x0273 are the COV subscription pair, and were named otherwise.

PROTOCOL.md §9.3 carries a *correction of record*: `AP2_COV_ENABLE` (0x0271)
and `AP2_COV_DISABLE` (0x0273) are the change-of-value subscription
enable/disable pair -- "not ReadExtended/PointExistenceProbe as an earlier
behavioral reading labeled them". The scanner kept both earlier readings as
`OP_READ_EXTENDED` and `OP_WRITE_NOVALUE`, and the virtual PXC kept the first as
`OP_READ_LEGACY`. p2.lua had it right all along.

The names matter beyond tidiness: `read_point()` sends 0x0271, so a reader of
the code was told every point read was a read, when the panel also arms a
subscription (§12.1). This pins the names to the vendor catalog.
"""
from __future__ import annotations

import sys
from pathlib import Path

import p2_scanner as ps

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "virtual_pxc"))
import virtual_pxc  # noqa: E402


def test_the_scanner_names_the_pair_after_the_catalog():
    assert ps.P2Message.OP_COV_ENABLE == 0x0271
    assert ps.P2Message.OP_COV_DISABLE == 0x0273
    assert "COV_ENABLE" in ps.op_label(0x0271)
    assert "COV_DISABLE" in ps.op_label(0x0273)


def test_the_withdrawn_names_are_gone():
    for stale in ("OP_READ_EXTENDED", "OP_WRITE_NOVALUE"):
        assert not hasattr(ps.P2Message, stale), stale
    assert not hasattr(virtual_pxc, "OP_READ_LEGACY")


def test_the_fixture_uses_the_same_name():
    assert virtual_pxc.OP_COV_ENABLE == 0x0271


def test_read_point_documents_that_it_subscribes():
    """read_point sends 0x0271; its docstring must not call that a plain read."""
    doc = ps.P2Connection.read_point.__doc__ or ""
    assert "COV_ENABLE" in doc and "subscription" in doc
