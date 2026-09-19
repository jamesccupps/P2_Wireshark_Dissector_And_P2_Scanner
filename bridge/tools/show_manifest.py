#!/usr/bin/env python3
"""
show_manifest.py — Pretty-print and audit a manifest.json.

Usage:
  python tools/show_manifest.py manifest.json
  python tools/show_manifest.py manifest.json --by-node
  python tools/show_manifest.py manifest.json --by-type
  python tools/show_manifest.py manifest.json --node NODE3 --device AHU1
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from p2_bridge.manifest import Manifest


def parse_args():
    p = argparse.ArgumentParser(description="Show / audit a P2-BACnet bridge manifest.")
    p.add_argument("path", help="Path to manifest.json")
    p.add_argument("--by-node", action="store_true",
                   help="Group counts by node")
    p.add_argument("--by-type", action="store_true",
                   help="Group counts by BACnet object type")
    p.add_argument("--node", help="Filter to one node")
    p.add_argument("--device", help="Filter to one device")
    p.add_argument("--list", action="store_true",
                   help="List every point matching the filters")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    m = Manifest.load(Path(args.path))

    points = m.points
    if args.node:
        points = [p for p in points if p.node == args.node]
    if args.device:
        points = [p for p in points if p.device == args.device]

    print(f"Manifest: {args.path}")
    print(f"Generated UTC: {m.generated_utc}")
    print(f"Total points: {len(m.points)}  filtered: {len(points)}")
    print()

    if args.by_node:
        by_node: dict = defaultdict(int)
        for p in points:
            by_node[p.node] += 1
        print("Points per node:")
        for n, c in sorted(by_node.items()):
            print(f"  {n:<20s} {c:>6d}")
        print()

    if args.by_type:
        by_type: dict = defaultdict(int)
        for p in points:
            by_type[p.bacnet_object_type] += 1
        print("Points per BACnet object type:")
        for t, c in sorted(by_type.items()):
            print(f"  {t:<20s} {c:>6d}")
        print()

    print("Next instance IDs:")
    for t, n in sorted(m.next_instance_ids.items()):
        print(f"  {t:<20s} {n}")
    print()

    if args.list or args.node or args.device:
        print(f"{'Node':<10s} {'Device':<14s} {'Slot':>4s}  {'Name':<28s} "
              f"{'Type':<14s} {'Inst':>6s}  ObjectName")
        print("-" * 110)
        for p in points:
            print(f"{p.node:<10s} {p.device:<14s} {p.slot:>4d}  {p.name:<28s} "
                  f"{p.bacnet_object_type:<14s} {p.bacnet_instance:>6d}  {p.object_name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
