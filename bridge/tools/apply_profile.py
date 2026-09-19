#!/usr/bin/env python3
"""
apply_profile.py — Toggle the `enabled` flag on every entry in an existing
manifest based on a built-in profile, in place.

Useful when you've already built a full manifest (every point) but want to
trim what the bridge actually polls and exposes — without rebuilding from
scratch and losing all your BACnet instance ID assignments.

Run with:
  python tools/apply_profile.py manifest.json --profile operational
  python tools/apply_profile.py manifest.json --profile essential --dry-run

Profiles:
  all          — enable every point
  operational  — enable points an operator routinely monitors; disable PID
                 gains, calibration constants, internal config
  essential    — enable only headline operational points (smallest/fastest
                 manifest)

What stays the same:
  - Every BACnet instance ID is preserved
  - Object names and descriptions are preserved
  - device_description is preserved

What changes:
  - The `enabled: true/false` flag on each entry, based on whether the
    point name matches the chosen profile.

The bridge skips disabled entries entirely — they don't appear as BACnet
objects, they don't get polled. To re-enable them, run this tool again
with --profile all.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from p2_bridge.manifest import Manifest
from p2_bridge import profiles


def parse_args():
    p = argparse.ArgumentParser(
        description="Apply a profile filter to an existing manifest "
                    "(toggles enabled flag, preserves instance IDs).",
    )
    p.add_argument("path", help="Path to manifest.json")
    p.add_argument("--profile", default="operational",
                   choices=profiles.list_profiles(),
                   help="Profile to apply")
    p.add_argument("--dry-run", action="store_true",
                   help="Show changes without writing the file")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    path = Path(args.path)
    if not path.exists():
        sys.stderr.write(f"ERROR: manifest not found: {path}\n")
        return 2

    m = Manifest.load(path)
    profile_name = args.profile.lower()

    print(profiles.describe_profile(profile_name))
    print(f"Loaded manifest: {len(m.points)} points")
    print()

    enabled_now = sum(1 for p in m.points if p.enabled)
    print(f"Currently enabled: {enabled_now}")
    print(f"Currently disabled: {len(m.points) - enabled_now}")
    print()

    became_enabled = 0
    became_disabled = 0
    unchanged = 0
    skipped_panel = 0

    for entry in m.points:
        # Panel-internal points are not filtered by profile — their names
        # are PPCL codes that don't match descriptive profile patterns,
        # but the points themselves are operationally curated. Their
        # enabled state is preserved as-is.
        if getattr(entry, "point_source", "fln") == "panel":
            skipped_panel += 1
            continue

        should_enable = profiles.match_profile(entry.name, profile_name)
        if should_enable and not entry.enabled:
            entry.enabled = True
            became_enabled += 1
        elif not should_enable and entry.enabled:
            entry.enabled = False
            became_disabled += 1
        else:
            unchanged += 1

    new_enabled = sum(1 for p in m.points if p.enabled)

    print(f"After profile '{profile_name}':")
    print(f"  Will be enabled:  {new_enabled}")
    print(f"  Will be disabled: {len(m.points) - new_enabled}")
    print()
    print(f"  FLN points newly enabled:    {became_enabled}")
    print(f"  FLN points newly disabled:   {became_disabled}")
    print(f"  FLN points unchanged:        {unchanged}")
    print(f"  Panel points (untouched):    {skipped_panel}")

    if became_enabled == 0 and became_disabled == 0:
        print()
        print("No changes needed — manifest already matches the profile.")
        return 0

    # Show sample of newly disabled points so the user can sanity-check
    if became_disabled > 0:
        print()
        print(f"Sample of {min(15, became_disabled)} points that will be disabled:")
        n = 0
        for entry in m.points:
            if not entry.enabled and n < 15:
                # We just set it; show this one
                print(f"  {entry.object_name:50s}  ({entry.name})")
                n += 1
                if n >= 15:
                    break

    if args.dry_run:
        print()
        print("--dry-run: no changes written.")
        return 0

    m.save(path)
    print()
    print(f"Wrote updated manifest to {path}")
    print(f"All {len(m.points)} bacnet_instance IDs preserved.")
    print()
    print("Restart the bridge to pick up the changes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
