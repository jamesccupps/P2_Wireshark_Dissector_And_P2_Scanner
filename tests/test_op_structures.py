"""Opcode-to-structure pairings the name-matching rule cannot reach.

`gen_asdu.py` maps an opcode to a structure by matching the opcode's own name
against `AP2_<name>_Request` / `_Response`. Three pairings that rule can never
reach are added by hand on wire evidence, and a regeneration that lost one
would leave a reader unable to decode those bodies at all -- silently, because
`p2_body.decode` returns "no structure is declared" rather than failing.

These are shape assertions on the shipped catalog, not decodes of real bodies:
a `TEC_body` carries names and descriptors, which do not belong in a test.
"""
from __future__ import annotations

import p2_asdu
import p2_body

TEC_RECORD = [["team_response", "Team_response"], ["tec_body", "TEC_body"]]


def test_the_controller_log_request_keeps_its_hand_made_pairing():
    """0x4200 is AP2_CONTROLLER_LOG in the opcode enum and AP2_TEC_Log_* in
    the structure library, so the two names never meet."""
    assert p2_body.structure_for(0x4200, "req") == "AP2_TEC_Log_Request"


def test_the_controller_log_response_is_paired_too():
    """Refused once on a misreading of "truncated".

    `p2_body` calls truncation normal for a short response: it means the body
    ended at a field boundary. Over all 242 response bodies in the corpus every
    byte of every one is consumed, with no error and no leftover, and all 242
    stop at the same field -- the panel sends the TEC record without its
    trailing recharacterization array. That is a short record, not a wrong
    structure, and refusing the pairing left the shipped catalog unable to
    decode the response at all.
    """
    assert p2_body.structure_for(0x4200, "rsp") == "AP2_TEC_Log_Response"
    assert p2_asdu.STRUCTS["AP2_TEC_Log_Response"] == TEC_RECORD


def test_the_disk_log_request_is_a_bare_shared_subtype():
    """0x0050's request is a `User_profile`, not any AP2_*_Request."""
    assert p2_body.structure_for(0x0050, "req") == "User_profile"


def test_the_tec_record_shape_is_declared_by_five_structures():
    """The wire cannot choose between them; the operation does.

    Worth pinning because it is the honest limit of the pairing above: five
    library structures declare this shape field-for-field, so identifying the
    bytes does not identify the name. `AP2_TEC_Log_Response` is the one whose
    name matches the request already paired to this opcode.
    """
    same = {n for n, f in p2_asdu.STRUCTS.items() if f == TEC_RECORD}
    assert same == {
        "AP2_TEC_Log_Response",
        "AP2_TEC_Look_Response",
        "AP2_TEC_Query_Record_Response",
        "AP2_TEC_Definition_Response",
        "AP2_Upl_All_TEC_Response",
    }


def test_the_trailing_fields_the_wire_omits_are_the_last_three():
    """What "short record" means, structurally.

    The walk ends at `nrOfrechar_values` on every body, so the fields the panel
    does not send are that count, the array it governs, and the BACnet flag
    after it. If `TEC_body` ever gains or loses a trailing field this pins
    which one the corpus was measured against.
    """
    tail = [f[0] for f in p2_asdu.STRUCTS["TEC_body"]][-3:]
    assert tail == ["nrOfrechar_values", "rechar_values", "is_bacnet"]
