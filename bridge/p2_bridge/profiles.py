"""
profiles.py — Built-in profiles for filtering which P2 points end up in
the manifest.

A site with many panels and many points per device produces a manifest
that takes minutes to poll completely. For sites that don't need every
calibration constant and PID gain exposed via BACnet, profiles let the
user trim down to what an operator actually monitors.

Each profile is a pair of substring lists:
  - include: a point name must contain at least one of these (empty
             list = include everything)
  - exclude: any match here drops the point even if it matched include

Match is case-insensitive substring against the P2 point name as the
panel reports it (e.g. "ROOM TEMP", "DAY CLG STPT", "CLG P GAIN").
"""
from __future__ import annotations

from typing import Dict, List


# ─────────────────────────────────────────────────────────────────────────────
# Profile definitions
# ─────────────────────────────────────────────────────────────────────────────

ESSENTIAL: Dict[str, List[str]] = {
    "include": [
        # Identity / health
        "APPLICATION",
        "ERROR STATUS",
        "CHK STATUS",
        # Primary sensed value(s)
        "ROOM TEMP",
        "AUX TEMP",
        # Active setpoint and controlled value
        "CTL STPT",
        "CTL TEMP",
        # Primary flow / volume / position — patterns chosen to NOT match
        # FLOW BIAS / FLOW COEFF / FLOW * GAIN
        "AIR VOLUME",
        "FLOW STPT",
        "DMPR POS",
        # Common panel-level outside-air temp variants
        "OATEMP",
        "OAT",
        "OUTSIDE_AIR_TEMP",
    ],
    "exclude": [
        # Defensive: even if a future include matches a config point,
        # never leak PID gains or calibration into the essential profile.
        "P GAIN", "I GAIN", "D GAIN", "BIAS", "COEFF",
        "CAL ", "CTLR ADDRESS",
    ],
}


OPERATIONAL: Dict[str, List[str]] = {
    "include": [
        # Everything in ESSENTIAL
        "APPLICATION", "ERROR STATUS", "CHK STATUS", "CHK OUT",
        "ROOM TEMP", "AUX TEMP", "CTL STPT", "CTL TEMP",
        "AIR VOLUME", "FLOW", "DMPR POS",
        "OATEMP", "OAT", "OUTSIDE_AIR_TEMP",
        # Setpoints and ranges
        "STPT", "SETPOINT",
        # Sensed values
        "TEMP", "PRESS", "HUMID", "ENTH",
        # Actuator commands and feedback
        "DMPR", "VLV", "VALVE",
        "MTR2 ",            # MTR2 COMD, MTR2 POS — both useful
        # Modes / state
        "DAY", "NGT", "OCC", "UNOCC",
        "HEAT", "COOL", "FAN",
        "WALL SWITCH", "STPT DIAL", "OVRD",
        # Loop output
        "LOOPOUT",
        # Generic numbered IO operators look at
        "AI 3", "AI 4", "AO 1",
        "DO 1", "DO 2", "DO 3", "DO 4",
        # Boiler / chiller / lighting common panel patterns
        "BLR", "CHILLER", "CH1", "CH2", "CH3", "CH4",
        "LIGHTING", "LIGHT",
        "EF1", "EF2", "EF3", "EF4", "EF5",
        "ALARM", "ALM",
        "ENABLE", "ENB",
        "STATUS",
    ],
    "exclude": [
        # PID gains / biases / coefficients — configuration, not operational
        "P GAIN", "I GAIN", "D GAIN", "BIAS",
        "COEFF",
        # Calibration / one-time setup
        "CAL ", "DUCT AREA", "LOOP TIME",
        "MTR1", "MTR SETUP",
        "DMPR ROT",         # internal damper-rotation tracking
        "DO DIR",           # DO direction-reversal config
        "TIMING",
        # Internal addressing / metadata that's not interesting at runtime
        "CTLR ADDRESS",
    ],
}


ALL: Dict[str, List[str]] = {"include": [], "exclude": []}


PROFILES: Dict[str, Dict[str, List[str]]] = {
    "essential": ESSENTIAL,
    "operational": OPERATIONAL,
    "all": ALL,
}


# ─────────────────────────────────────────────────────────────────────────────
# Filter API
# ─────────────────────────────────────────────────────────────────────────────

def list_profiles() -> List[str]:
    """Return the list of available profile names."""
    return list(PROFILES.keys())


def match_profile(point_name: str, profile_name: str) -> bool:
    """Return True if `point_name` should be included given the named profile.

    Match logic:
      - Empty include list = include everything
      - Non-empty include = must match at least one substring (case-insensitive)
      - Then exclude takes priority — if any exclude substring matches,
        the point is dropped

    Unknown profile names are treated as 'all' (no filtering).
    """
    p = PROFILES.get(profile_name.lower(), ALL)
    name = point_name.upper()

    include = p.get("include", [])
    if include:
        if not any(s.upper() in name for s in include):
            return False

    exclude = p.get("exclude", [])
    if exclude and any(s.upper() in name for s in exclude):
        return False

    return True


def describe_profile(profile_name: str) -> str:
    """One-line summary suitable for log output."""
    p = PROFILES.get(profile_name.lower(), ALL)
    inc = len(p.get("include", []))
    exc = len(p.get("exclude", []))
    if profile_name.lower() == "all" or (inc == 0 and exc == 0):
        return f"profile={profile_name}: no filtering"
    return (f"profile={profile_name}: include={inc} pattern(s), "
            f"exclude={exc} pattern(s)")
