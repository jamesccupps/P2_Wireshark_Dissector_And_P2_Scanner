#!/usr/bin/env python3
"""
rename_objects.py — Re-sanitize the object_name field on every entry in
an existing manifest, in place.

Use this after pulling a manifest.py update that changes the object-name
sanitizer (for example, the v0.1.1 fix that strips periods inside point
names so they don't break BACnet supervisor hierarchy display).

Important:
  - This does NOT contact any PXCs. It's a pure data transformation.
  - All bacnet_instance IDs are preserved. Supervisor bindings to objects
    by instance ID continue to work.
  - The object_name field IS rewritten — supervisors that bound to objects
    by name (uncommon but possible) would need to re-resolve them.

Usage:
  python tools/rename_objects.py manifest.json
  python tools/rename_objects.py manifest.json --dry-run
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from p2_bridge.manifest import Manifest, make_object_name


def parse_args():
    p = argparse.ArgumentParser(
        description="Re-sanitize object names in an existing manifest.",
    )
    p.add_argument("path", help="Path to manifest.json")
    p.add_argument("--dry-run", action="store_true",
                   help="Print proposed changes without writing the file")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    path = Path(args.path)
    if not path.exists():
        sys.stderr.write(f"ERROR: manifest not found: {path}\n")
        return 2

    m = Manifest.load(path)

    # First pass: compute candidate new names
    proposed = []
    for entry in m.points:
        new_name = make_object_name(entry.node, entry.device, entry.name)
        proposed.append((entry, new_name))

    # Second pass: detect collisions among the proposed names and resolve
    # them deterministically by appending the instance ID. Without this,
    # two points whose names sanitize to the same string (e.g. "DO 4" and
    # "DO_4") would produce duplicate object names — a BACnet violation.
    seen = {}
    collisions = 0
    final = []
    for entry, candidate in proposed:
        if candidate in seen:
            disambig = f"{candidate}.{entry.bacnet_instance}"
            collisions += 1
            final.append((entry, disambig))
            seen[disambig] = entry
        else:
            seen[candidate] = entry
            final.append((entry, candidate))

    # Third pass: collect actual changes
    changes = []
    for entry, new_name in final:
        if new_name != entry.object_name:
            changes.append((entry, entry.object_name, new_name))

    if not changes:
        print("No object-name changes needed — manifest is already clean.")
        return 0

    print(f"Object-name changes: {len(changes)}")
    print()
    show = changes[:25]
    for entry, old, new in show:
        print(f"  {old:50s}  ->  {new}")
    if len(changes) > len(show):
        print(f"  ... and {len(changes) - len(show)} more")

    if collisions:
        print()
        print(f"Name collisions resolved with .{{instance_id}} suffix: {collisions}")

    if args.dry_run:
        print()
        print("--dry-run: no changes written.")
        return 0

    # Apply
    for entry, _old, new_name in changes:
        entry.object_name = new_name

    m.save(path)
    print()
    print(f"Wrote updated manifest to {path}")
    print(f"All {len(m.points)} bacnet_instance IDs preserved — "
          "supervisor bindings by instance ID are unaffected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
