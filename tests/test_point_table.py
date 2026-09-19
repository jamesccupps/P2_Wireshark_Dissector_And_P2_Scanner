"""An unknown TEC application must produce no points, not plausible ones.

`get_point_table()` used to end in an unconditional fallback: whatever the
application number, if the catalog did not know it the function returned
`COMMON_POINTS`. `get_point_table(1)` and `get_point_table(424242)` each
answered with the same 61 points, indistinguishable from real catalog data.

The embedded catalog covers 1,070 applications numbered 20-6797, so any TEC
running something outside that set got a point list belonging to no device --
and the bridge's manifest builder then typed all 61 as analog BACnet objects,
because the rich metadata that would have said otherwise does not exist for an
application the catalog has never heard of.

The hardcoded tables are a catalog-of-last-resort for apps 2020-2027, which is
what the comment above them has always said. These pin both halves.
"""
from __future__ import annotations

import pytest

import p2_scanner


@pytest.fixture()
def catalog_absent():
    """Simulate the one case the hardcoded tables exist for."""
    saved = p2_scanner._TECPNTS_DB
    p2_scanner._TECPNTS_DB = {}
    try:
        yield
    finally:
        p2_scanner._TECPNTS_DB = saved


@pytest.mark.parametrize("app", [1, 19, 9999, 424242])
def test_an_unknown_application_has_no_points(app):
    assert p2_scanner.get_point_table(app) == {}


def test_a_catalogued_application_still_has_its_points():
    """The fix must not empty the normal path."""
    table = p2_scanner.get_point_table(2020)
    assert len(table) > 40
    assert all(len(row) == 4 for row in table.values())


def test_the_hardcoded_tables_serve_only_their_own_applications(catalog_absent):
    """With no catalog, 2020-2027 are answerable and nothing else is."""
    assert len(p2_scanner.get_point_table(2020)) > 40
    assert len(p2_scanner.get_point_table(2027)) > 40
    assert p2_scanner.get_point_table(2019) == {}
    assert p2_scanner.get_point_table(2028) == {}
    assert p2_scanner.get_point_table(9999) == {}


def test_rich_metadata_and_the_point_table_agree_on_membership():
    """A point the table lists should be one get_point_info can describe.

    Not asserted for every point -- the catalog has gaps -- but an application
    the table answers for must be one the rich lookup also answers for, or the
    two halves are describing different things.
    """
    table = p2_scanner.get_point_table(2020)
    named = [row[0] for row in table.values()]
    described = [n for n in named if p2_scanner.get_point_info(2020, n)]
    assert described, "no point in a catalogued application had metadata"
