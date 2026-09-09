"""
firmware_registry.py — panel build-tag cache and platform identification.

A panel reports a firmware build tag in its `0x010C CABINET_DISPLAY` response
(PROTOCOL.md §16.2). This module parses it, caches it per host so a repeat
connection does not have to re-read the identity block, and records what is
known about the handful of builds seen so far.

WHAT THE BUILD TAG IS GOOD FOR, and what it is not.

It identifies the **platform**: which hardware family a panel is, and which
string encoding its firmware uses. PROTOCOL.md §8.4 establishes that the
RAD-50 / ASCII choice is a fixed property of a firmware revision rather than
something negotiated per frame, so knowing the build is genuinely useful before
you decode a name.

It does **not** select a framing "dialect". An earlier version of this module
implemented a legacy/modern dialect lookup keyed on the build tag, on the theory
that `msg_type` 0x33 and 0x34 were class bytes chosen by firmware generation.
That model is withdrawn: `msg_type` is a header length, computed as
`13 + the total bytes of the four routing slots`, and it is not a choice at all
(PROTOCOL.md §6.2, and §6.6 for the withdrawal). The dialect table, the
negotiation function and the `msg_type` map that went with them are gone —
nothing selects framing from a build tag, because framing is arithmetic.

PROTOCOL.md §6.2.5 lists what did survive from that model, and the
string-encoding property above is the part this module still serves.

The registry is non-exhaustive: OEM respins carry identifiers not listed here,
and an unlisted build is not an error. Callers should treat
`classify_unknown_build()` as a hint for logging, never as a decode input.
"""
from __future__ import annotations

from typing import Dict, Optional


# Builds observed or documented so far. `notes` records what is actually known
# about each one; several of these are wire observations that stand on their own
# and were merely bundled into the withdrawn dialect record.
KNOWN_BUILDS = {
    "PME1121": {
        "version": "V2.8.5",
        "build_date": "~2012",
        "notes": "Older P2 build.",
    },
    "PME1252": {
        "version": "V2.8.10",
        "build_date": "Oct 2013",
        "notes": "CONNECT response carries 0x0100 in the 0x2E body; the "
                 "highest build seen in the older group.",
    },
    "PME1300": {
        "version": "V2.8.18",
        "build_date": "Sep 2019",
        "notes": "Final P2 release; adds Adaptive Control (LSM-ADAPT); "
                 "CONNECT response carries the 0x4640 identity block "
                 "(PROTOCOL.md §9.6).",
    },
    "BME1290": {
        "version": "V3.5.2",
        "build_date": "~2019",
        "notes": "BACnet firmware on identical PXC hardware; not addressable "
                 "via this protocol's wire opcodes.",
    },
}


def classify_unknown_build(build_tag: Optional[str]) -> str:
    """Best-effort family/generation hint for a build not in the registry.

    For logging only. Nothing in the decode path may branch on this — the
    protocol does not vary by build in any way this tool relies on.

    Returns one of:
      "older"     — PME with build number <= 1252
      "newer"     — PME with build number >= 1300
      "bacnet"    — BME, the BACnet firmware family; not reachable over P2
      "unknown"   — PME in the 1253-1299 range, or an unrecognized prefix

    The 1253-1299 range is reported as unknown rather than interpolated. No
    build in it has been observed, so placing it on either side would be a
    guess presented as a fact.
    """
    if not build_tag:
        return "unknown"
    tag = build_tag.strip()
    if tag.startswith("PME"):
        suffix = tag[3:]
        try:
            num = int(suffix)
        except ValueError:
            return "unknown"
        if num <= 1252:
            return "older"
        if num >= 1300:
            return "newer"
        return "unknown"          # 1253-1299 — unobserved, do not extrapolate
    if tag.startswith("BME"):
        return "bacnet"
    return "unknown"


def parse_build_tag(model_string: Optional[str]) -> Optional[str]:
    """Extract the PME####/BME#### build tag from a 0x010C response string.

    The 0x010C response carries the build tag in a TLV labeled "panel model"
    that actually holds the firmware-build identifier — e.g. "PME1252 " or
    "PME1300 " (trailing space preserved). Strips whitespace, validates the
    PME/BME prefix, and returns the canonical prefix + digits form, or None.
    """
    if not model_string:
        return None
    tag = model_string.strip()
    if not (tag.startswith("PME") or tag.startswith("BME")):
        return None
    prefix = tag[:3]
    # Walk the digits after the prefix
    i = 3
    while i < len(tag) and tag[i].isdigit():
        i += 1
    if i == 3:
        return None
    return prefix + tag[3:i]


# ─────────────────────────────────────────────────────────────────────────────
# Per-host build-tag cache
#
# Populated by clients when they parse a 0x010C response from a panel, and
# persisted by site.json loaders for cross-process reuse, so a repeat connection
# knows the platform without re-reading the identity block.
# ─────────────────────────────────────────────────────────────────────────────

_BUILD_TAG_CACHE: Dict[str, str] = {}


def get_cached_build_tag(host: str) -> Optional[str]:
    """Return the cached build tag for `host`, or None."""
    return _BUILD_TAG_CACHE.get(host)


def cache_build_tag(host: str, build_tag: str) -> None:
    """Store the build tag for `host`. Idempotent."""
    if build_tag:
        _BUILD_TAG_CACHE[host] = build_tag


def evict_build_tag(host: str) -> None:
    """Remove the cached entry for `host`. Safe when a previously-cached
    tag stops working (firmware upgrade, panel swap)."""
    _BUILD_TAG_CACHE.pop(host, None)


def all_cached_build_tags() -> Dict[str, str]:
    """Snapshot copy of the cache for persistence."""
    return dict(_BUILD_TAG_CACHE)


def load_build_tags(tags: Optional[Dict[str, str]]) -> None:
    """Bulk-update the cache from a saved site.json."""
    if tags:
        _BUILD_TAG_CACHE.update(tags)


def describe_build(build_tag: Optional[str]) -> str:
    """Human-readable one-line description of a build, for log output.

      "PME1300 (V2.8.18, Sep 2019)"
      "PME9999 (not in registry; looks newer)"
      "(no build tag)"
    """
    if not build_tag:
        return "(no build tag)"
    tag = build_tag.strip()
    entry = KNOWN_BUILDS.get(tag)
    if entry:
        return f"{tag} ({entry['version']}, {entry['build_date']})"
    return f"{tag} (not in registry; looks {classify_unknown_build(tag)})"
