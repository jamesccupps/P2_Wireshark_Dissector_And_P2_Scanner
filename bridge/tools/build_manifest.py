#!/usr/bin/env python3
"""
build_manifest.py — Walk a P2 site once and generate manifest.json.

Uses the P2 Scanner library to:
  - Connect to each node listed in site.json
  - Enumerate FLN devices (opcode 0x0986)
  - Read APPLICATION on each device
  - Look up each device's point table from the scanner's embedded TEC catalog
  - Allocate a BACnet instance ID per point
  - Write manifest.json

The manifest is append-only — re-running this script preserves existing
instance IDs and adds new ones for any newly-discovered devices/points.
That stability is critical because BACnet supervisors bind to objects by
instance ID.

You can edit manifest.json by hand to:
  - Set `enabled: false` on points you don't want exposed
  - Override `poll_interval_s` per point
  - Adjust `object_name` if you have your own naming convention
  - Change `units` if you spot a wrong default

Run with:
  python tools/build_manifest.py \\
      --site site.json \\
      --bridge-config bridge_config.json \\
      --out manifest.json
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

# `tools/` sits under the bridge root, so put that on the path first to make
# `p2_bridge` importable, then let scanner_path locate the scanner itself.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from p2_bridge.scanner_path import ensure_scanner_importable

try:
    ensure_scanner_importable()
    import p2_scanner  # type: ignore
except ImportError as e:
    sys.stderr.write(f"ERROR: {e}\n")
    sys.exit(2)

from p2_bridge.config import BridgeConfig, SiteConfig, setup_logging
from p2_bridge.manifest import (
    Manifest,
    PointEntry,
    P2_TYPE_TO_BACNET,
    make_object_name,
    make_description,
)
from p2_bridge import profiles


def parse_args():
    p = argparse.ArgumentParser(description="Build a P2-BACnet bridge manifest by walking the site.")
    p.add_argument("--site", default="site.json")
    p.add_argument("--bridge-config", default="bridge_config.json")
    p.add_argument("--out", default="manifest.json")
    p.add_argument("--node", action="append",
                   help="Only walk these nodes (repeatable). Default: all known.")
    p.add_argument("--rebuild", action="store_true",
                   help="Discard existing manifest entries — start fresh. "
                        "WARNING: invalidates BACnet instance IDs.")
    p.add_argument("--profile", default="all",
                   choices=["all", "operational", "essential"],
                   help="Filter which points to add. 'all' = every point, "
                        "'operational' = exclude PID gains and calibration, "
                        "'essential' = only headline operational points "
                        "(small fast-cycle manifest). Existing manifest "
                        "entries are not affected — use tools/apply_profile.py "
                        "to retroactively trim an existing manifest.")
    p.add_argument("--no-panel-points", action="store_true",
                   help="Skip the panel-wide enumerate step.")
    return p.parse_args()


def configure_p2_scanner(site: SiteConfig) -> None:
    """Set the scanner's module globals. **Only the manifest builder does this.**

    `enumerate_fln_devices` and `get_device_application` read `P2_NETWORK`,
    `SCANNER_NAME` and `P2_SITE` from module state rather than taking them as
    arguments, and this tool is the only caller of either. The bridge daemon
    does not call this and must not start: it uses `P2Connection` directly and
    passes what it needs, so its coupling to the scanner stays visible in the
    call rather than hidden in module state.
    """
    p2_scanner.P2_NETWORK = site.p2_network
    p2_scanner.SCANNER_NAME = site.scanner_name
    p2_scanner.P2_SITE = site.p2_site


def collect_points_for_node(node_name: str, host: str, log: logging.Logger,
                            include_panel_points: bool = True):
    """
    For a given node:
      1. Enumerate FLN devices.
      2. For each device, read APPLICATION.
      3. For each (device, application), look up the point table.
      4. Optionally probe panel-internal point names (PPCL variables,
         BLN-sourced points, outside-air, system-wide setpoints).
      5. Yield dicts describing each point found.

    Falls back gracefully on individual device failures.
    """
    log.info("[%s] Enumerating FLN devices on %s", node_name, host)
    devices = p2_scanner.enumerate_fln_devices(host, node_name.lower())
    if not devices:
        log.warning("[%s] FLN enumerate returned 0 devices", node_name)
    else:
        log.info("[%s] Found %d FLN devices", node_name, len(devices))

    for dev in devices:
        dev_name = dev.get("device")
        dev_desc = (dev.get("description") or "").strip()
        if not dev_name:
            continue
        log.info("  [%s] Reading APPLICATION", dev_name)
        try:
            app_num = p2_scanner.get_device_application(host, node_name.lower(), dev_name)
        except Exception as e:
            log.warning("    [%s] APPLICATION read failed: %s", dev_name, e)
            continue
        if app_num is None:
            log.warning("    [%s] APPLICATION returned None — skipping", dev_name)
            continue

        # F-3: fall back to the v2 catalog `_meta.descr` for devices whose
        # 0x0986 enumerate response carried an empty description string.
        # That happens for FLN devices that were never given a per-instance
        # description in the panel configuration — the catalog description
        # ("VAV Cooling Only", "Fan Coil Unit (4-pipe)", etc.) is at least
        # informative and is constant per application. Wire description
        # always wins when present.
        if not dev_desc:
            try:
                app_meta = p2_scanner.get_app_meta(app_num)
            except AttributeError:
                # Older scanner library without get_app_meta — skip the
                # fallback rather than crash.
                app_meta = None
            if app_meta and isinstance(app_meta.get("descr"), str):
                dev_desc = app_meta["descr"]

        # F-4: skip devices whose application is BACnet/MSTP — those are
        # not reachable via P2 enumerate, the bridge would generate manifest
        # entries for points that can never be read. The catalog flags this
        # via `_meta.transport == 'bacnet_mstp'`.
        try:
            p2_reachable = p2_scanner.app_supports_p2(app_num)
        except AttributeError:
            p2_reachable = None
        if p2_reachable is False:
            log.warning(
                "    [%s] application %d is BACnet/MSTP transport — "
                "not P2-reachable, skipping. Reach this device via "
                "BACnet/IP if the panel acts as a BACnet router.",
                dev_name, app_num,
            )
            continue

        log.info("    [%s] application = %d%s", dev_name, app_num,
                 f" — {dev_desc}" if dev_desc else "")

        pt_table = p2_scanner.get_point_table(app_num)
        if not pt_table:
            log.warning("    [%s] No point table for app %d — skipping",
                        dev_name, app_num)
            continue

        for slot, _info_tuple in sorted(pt_table.items()):
            name = _info_tuple[0]
            meta = p2_scanner.get_point_info(app_num, name) or {}
            yield {
                "point_source": "fln",
                "device": dev_name,
                "device_description": dev_desc,
                "application": app_num,
                "slot": slot,
                "name": name,
                "meta": meta,
            }

    # Build a set of FLN device names already covered by the walk above.
    # Anything from the panel-wide enumerate that lives on one of those
    # devices is already in the manifest; we only want net-new
    # panel-internal points.
    fln_device_names = {d.get("device", "").upper()
                        for d in (devices or []) if d.get("device")}

    # Panel-internal points — the Points section of the PXC. Read in bulk
    # at runtime via opcode 0x0981 (enumerate_all_points), NOT individually
    # via read_point. This is the section's correct read path: virtual
    # points, PPCL working variables, and panel I/O all live here and
    # respond only to the bulk enumerate. The runtime poller refreshes
    # them on its own cadence (panel_enumerate_interval_s).
    #
    # At build time we just discover what's there and add it to the
    # manifest. No read_point validation needed — the runtime never calls
    # read_point on these.
    if include_panel_points:
        log.info("[%s] Enumerating panel-wide points via opcode 0x0981", node_name)
        candidates = []
        try:
            conn = p2_scanner.P2Connection(
                host,
                network=p2_scanner.P2_NETWORK,
                scanner_name=p2_scanner.SCANNER_NAME,
            )
            if not conn.connect(node_name.lower()):
                log.warning("[%s] Could not open connection for panel enumerate",
                            node_name)
            else:
                t0 = time.monotonic()
                all_points = conn.enumerate_all_points(node_name.lower())
                conn.close()
                log.info("[%s] 0x0981 walk: %d entries in %.1fs",
                         node_name, len(all_points), time.monotonic() - t0)

                title_entries = 0
                fln_overlaps = 0
                compound_skipped = 0
                for entry in all_points:
                    dev_name = (entry.get("device") or "").strip()
                    pt_name = (entry.get("point") or "").strip()
                    if entry.get("value") is None:
                        title_entries += 1
                        continue
                    if not pt_name:
                        continue
                    if dev_name.upper() in fln_device_names:
                        fln_overlaps += 1
                        continue
                    if entry.get("subkey"):
                        compound_skipped += 1
                        continue
                    candidates.append(entry)
                log.info("[%s] Panel enumerate filtered: %d kept, "
                         "%d FLN-overlap, %d compound-subkey, %d title-only",
                         node_name, len(candidates), fln_overlaps,
                         compound_skipped, title_entries)
        except Exception as e:
            log.warning("[%s] Panel-point discovery failed: %s", node_name, e)
            candidates = []

        for entry in candidates:
            pt_name = entry["point"]
            yield {
                "point_source": "panel",
                "device": pt_name,
                "device_description": (entry.get("description") or "").strip(),
                "application": 0,
                "slot": 0,
                "name": pt_name,
                "meta": {
                    "type": "analog_ro",
                    "ptype": 3,
                    "units": (entry.get("units") or "").strip(),
                    "rw": False,
                },
            }


def main() -> int:
    args = parse_args()

    bridge_cfg_path = Path(args.bridge_config)
    site_cfg_path = Path(args.site)
    out_path = Path(args.out)

    if not bridge_cfg_path.exists():
        sys.stderr.write(f"ERROR: bridge config not found: {bridge_cfg_path}\n")
        return 2
    if not site_cfg_path.exists():
        sys.stderr.write(f"ERROR: site config not found: {site_cfg_path}\n")
        return 2

    bridge_cfg = BridgeConfig.from_file(bridge_cfg_path)
    site_cfg = SiteConfig.from_file(site_cfg_path)
    setup_logging(bridge_cfg)
    log = logging.getLogger("build_manifest")

    configure_p2_scanner(site_cfg)

    # Load existing manifest if present (preserve instance IDs)
    if out_path.exists() and not args.rebuild:
        manifest = Manifest.load(out_path)
        log.info("Loaded existing manifest with %d points (preserving instance IDs)",
                 len(manifest.points))
    else:
        manifest = Manifest.empty(instance_id_start=bridge_cfg.instance_id_start)
        if args.rebuild:
            log.warning("--rebuild flag set: starting from empty manifest. "
                        "Any BACnet supervisor bindings to existing instance "
                        "IDs will need to be re-mapped.")

    used_object_names = {p.object_name for p in manifest.points}

    # Filter node list
    target_nodes = args.node or list(site_cfg.known_nodes.keys())

    # Profile filtering (only affects NEW entries — existing ones are untouched)
    profile_name = (args.profile or "all").lower()
    log.info(profiles.describe_profile(profile_name))
    if args.no_panel_points:
        log.info("Panel-internal point discovery: DISABLED")

    new_count = 0
    skipped_count = 0
    refreshed_count = 0
    name_collisions = 0
    profile_filtered_count = 0

    # Index existing entries for fast lookup so we can refresh device
    # descriptions on rebuild without re-allocating instance IDs.
    by_key = {p.key: p for p in manifest.points}

    for node_name in target_nodes:
        host = site_cfg.known_nodes.get(node_name)
        if not host:
            log.warning("No host for node %s in site config — skipping", node_name)
            continue

        for found in collect_points_for_node(
                node_name, host, log,
                include_panel_points=not args.no_panel_points):
            point_source = found.get("point_source", "fln")
            dev = found["device"]
            dev_desc = found.get("device_description", "")
            slot = found["slot"]
            name = found["name"]
            app_num = found["application"]
            meta = found["meta"]

            key = (node_name, dev, slot, name)
            existing = by_key.get(key)
            if existing is not None:
                # Don't touch instance IDs or other fields. But DO refresh
                # device_description (and recompute the derived
                # description) — so re-running the build picks up any
                # device descriptions added since the last walk.
                if dev_desc and existing.device_description != dev_desc:
                    existing.device_description = dev_desc
                    existing.description = make_description({
                        "device_description": dev_desc,
                        "slot": existing.slot,
                        "application": existing.application,
                        "units": existing.units,
                        "on_label": existing.on_label,
                        "off_label": existing.off_label,
                    })
                    refreshed_count += 1
                # Backfill point_source on entries that predate the field
                if point_source and not existing.point_source:
                    existing.point_source = point_source
                skipped_count += 1
                continue

            # New point — apply profile filter before allocating anything.
            # Panel-internal points are NEVER filtered by profile: their
            # names are PPCL variable codes (A04SPS, AC04DA) that don't
            # match descriptive profile patterns, but the points themselves
            # are operationally curated (the panel only surfaces what its
            # PPCL programs reference). Filtering them by name would
            # silently drop most of the actually-useful panel data.
            if point_source == "fln" and not profiles.match_profile(name, profile_name):
                profile_filtered_count += 1
                continue

            # Determine BACnet object type from P2 type
            p2_type = meta.get("type")
            if not p2_type:
                # Fallback: infer from ptype (1,4,10 = rw analog/digital;
                # 2,3 = ro). The point table's read_only flag handles this
                # but we want the analog/digital split too.
                ptype = meta.get("ptype", 4)
                is_digital = "on_label" in meta and "off_label" in meta
                rw = ptype not in (2, 3)
                if is_digital:
                    p2_type = "digital_rw" if rw else "digital_ro"
                else:
                    p2_type = "analog_rw" if rw else "analog_ro"

            if p2_type not in P2_TYPE_TO_BACNET:
                log.warning("    Unknown p2_type %r for %s/%s — skipping",
                            p2_type, dev, name)
                skipped_count += 1
                continue

            bacnet_type = P2_TYPE_TO_BACNET[p2_type]
            instance = manifest.allocate_instance(bacnet_type)

            # For panel-internal points, the synthetic device part of the
            # BACnet object name is "PANEL" — gives operators a clean
            # NODE.PANEL.* hierarchy distinct from FLN devices like
            # NODE.K408.* or NODE.DIVV1.*. The on-the-wire device name
            # (in entry.device, used by the poller's read_point() call)
            # stays as the actual point name, which is what the panel
            # protocol expects.
            obj_device_part = "PANEL" if point_source == "panel" else dev
            obj_name = make_object_name(node_name, obj_device_part, name)
            # Object names must be unique within the device. If we hit a
            # collision (long-name truncation, or two TECs with the same
            # device name across nodes — shouldn't happen, defensive),
            # append the instance ID.
            if obj_name in used_object_names:
                obj_name = f"{obj_name}.{instance}"
                name_collisions += 1
            used_object_names.add(obj_name)

            entry_kwargs = {
                "node": node_name,
                "host": host,
                "device": dev,
                "device_description": dev_desc,
                "point_source": point_source,
                "application": app_num,
                "slot": slot,
                "name": name,
                "p2_type": p2_type,
                "bacnet_object_type": bacnet_type,
                "bacnet_instance": instance,
                "object_name": obj_name,
                "units": meta.get("units", ""),
                "on_label": meta.get("on_label"),
                "off_label": meta.get("off_label"),
                "slope": meta.get("slope"),
                "intercept": meta.get("intercept"),
                "poll_interval_s": (
                    bridge_cfg.digital_poll_interval_s
                    if "digital" in p2_type
                    else bridge_cfg.default_poll_interval_s
                ),
                "enabled": True,
            }
            entry_kwargs["description"] = make_description(entry_kwargs)
            new_entry = PointEntry(**entry_kwargs)
            manifest.points.append(new_entry)
            by_key[key] = new_entry
            new_count += 1

    manifest.save(out_path)

    log.info("=" * 60)
    log.info("Manifest build complete:")
    log.info("  Total points in manifest: %d", len(manifest.points))
    log.info("  New points added: %d", new_count)
    log.info("  Already-known points (preserved): %d", skipped_count)
    if refreshed_count:
        log.info("  Device descriptions refreshed on existing points: %d",
                 refreshed_count)
    if profile_filtered_count:
        log.info("  Points filtered out by profile=%s: %d",
                 profile_name, profile_filtered_count)
    if name_collisions:
        log.warning("  Object-name collisions resolved with instance suffix: %d",
                    name_collisions)
    log.info("  Output: %s", out_path.resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
