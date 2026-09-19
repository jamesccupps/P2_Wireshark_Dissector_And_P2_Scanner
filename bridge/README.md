# P2-BACnet Bridge

A read-only bridge from **Siemens APOGEE P2** (the protocol PXC controllers speak) to **BACnet/IP**. Every P2 point becomes a BACnet object, so any BACnet supervisor — Desigo CC, Niagara, EBI, ENTELI-NET, Tridium-anything — can read your APOGEE PXCs as if they were native BACnet devices.

Built on the P2 Scanner library in the root of this repository, which does the actual P2 protocol work and ships a catalog of 1,070 TEC application definitions. The bridge has **no P2 implementation of its own** — the scanner is its protocol stack, and that is deliberate: a second P2 client would drift from [`PROTOCOL.md`](../PROTOCOL.md), which is the document both are built from.

**The bridge is a separate application.** It lives in `bridge/`, has its own entry point, GUI, config and dependencies, and the scanner does not import it. Cloning this repository to use the scanner alone needs nothing installed; `bacpypes3` is the bridge's dependency and is declared in `bridge/requirements.txt`, not at the repository root.

---

## What it does

- Connects to each PXC node listed in your site config over TCP/5033 (P2)
- Maintains one persistent connection per panel (PXCs have an 8–16 peer-session budget — single-flight reads keep things polite)
- Polls every point in the manifest on a configurable interval
- Serves a BACnet/IP device on UDP/47808 with one object per point:
  - `analog_ro` → `analogInput`
  - `analog_rw` → `analogValue`
  - `digital_ro` → `binaryInput`
  - `digital_rw` → `binaryValue`
- Surfaces both **FLN device points** (TEC subpoints) and **panel-internal points** (PPCL variables, BLN-sourced points, outside-air temps, boiler/chiller patterns) — appears as `NODE.DEVICE.*` and `NODE.PANEL.*` respectively
- Profile-based filtering — three built-in profiles (`essential`, `operational`, `all`) let you trim what gets polled at sites where the full manifest cycle takes too long
- Propagates the panel's `#COM` indicator to BACnet `reliability=NO_OUTPUT` + fault status flag, so supervisors light up red the same way Desigo CC does
- Maps APOGEE engineering unit strings (`DEG F`, `CFM`, `INWC`, etc.) to BACnet `EngineeringUnits` enum values
- Maps digital point on/off labels (`NIGHT`/`DAY`, `OCCUPIED`/`UNOCC`, etc.) to BACnet `activeText` / `inactiveText`
- Bakes the device description into each BACnet object's description field (so `NODE1.108.ROOM_TEMP` shows up as `CONFERENCE · slot 4, app 2500, DEG F` — what room it is, then technical context)

---

## What it deliberately doesn't do (yet)

- **No writes.** Mirrors the P2 Scanner's safety stance — the scanner ships read-only, and so does this. RW points appear as AV/BV objects so supervisors get the right type, but writes are rejected. Adding writes is a single method change in `object_factory.py` once you decide to enable it.
- **No COV / push notifications.** v0.1 polls. The 5034-side push channel (`listen_for_push_notifications` in p2_scanner) is the natural follow-up — the cache layer is designed to accept either source.
- **No alarms / events.** No `intrinsicReporting`, no `EventEnrollment` objects. Status flags propagate, but there are no BACnet alarm subscriptions yet.
- **One BACnet device, all PXCs flat.** Simpler navigation. The manifest schema already carries node info, so splitting one BACnet device per PXC is a config switch later.

---

## How it's structured

```
p2-bacnet-bridge/
├── p2_bacnet_bridge.py        ← runtime (entry point)
├── p2_bridge_launcher.py      ← Tkinter configurator GUI
├── launch_gui_windows.bat     ← Windows double-click launcher
├── launch_gui_linux.sh        ← Linux/macOS launcher
├── p2_bridge/
│   ├── config.py               ← bridge_config.json + site.json loaders
│   ├── manifest.py             ← persistent point manifest
│   ├── object_factory.py       ← APOGEE → bacpypes3 object + units map
│   ├── status.py               ← read result → BACnet reliability/statusFlags
│   ├── poller.py               ← one polling worker per PXC node
│   ├── bacnet_app.py           ← assembles the bacpypes3 Application
│   └── profiles.py             ← built-in profile keyword sets
├── tools/
│   ├── build_manifest.py       ← walk the site, generate manifest.json
│   ├── show_manifest.py        ← pretty-print / audit
│   ├── apply_profile.py        ← retroactively trim manifest by profile
│   └── rename_objects.py       ← re-sanitize object names in place
├── bridge_config.json.example
├── site.json.example
├── requirements.txt
├── SECURITY.md                ← reporting path for security issues
└── .gitignore                 ← keeps site.json / manifest.json out of git

Used from the repository root, one directory up — not copied:
    p2_scanner.py + p2_data.py, p2_asdu.py, p2_body.py
    firmware_registry.py
```

**There is no vendoring.** Earlier releases shipped byte-identical copies of the scanner, `firmware_registry.py`, an 8.67 MB `tecpoints.json` and a fork of the protocol spec, kept in step by a sync script, a SHA-256 manifest and a drift-checking CI workflow. All of it is gone: the bridge sits beside the scanner in one repository, so there is one copy and nothing to drift.

The TEC catalog went with it. The scanner embeds its own — 1,070 applications against the 1,024 in the old vendored file, a strict superset — so there is nothing to ship alongside.

`p2_bridge/scanner_path.py` finds the scanner, and it supports three layouts so the bridge still works outside this repository: already on `PYTHONPATH`, one directory up (this repository), or copied next to the bridge's own entry point. The coupling surface is small and deliberate — `P2Connection` and its four methods at runtime, plus the catalog lookups used once when building a manifest — and `tests/test_symbol_resolution.py` fails the build if any of it moves.

---

## Architecture

```
   Desigo CC / Niagara / EBI ──── BACnet/IP ────►  ┌────────────────────────┐
                                                   │  bacpypes3 Application │
                                                   │   (asyncio loop)       │
                                                   │                        │
                                                   │      Object cache      │
                                                   │           ▲            │
                                                   │           │ updates    │
                                                   │   ┌───────┴──────┐     │
                                                   │   │  Pollers     │     │
                                                   │   │  (1/PXC)     │     │
                                                   │   └───────┬──────┘     │
                                                   └───────────┼────────────┘
                                                               │  P2 / TCP 5033
                                                               ▼
                                                       PXC nodes
```

The asyncio loop hosts the BACnet app. Pollers run as regular threads (because `P2Connection` is synchronous) and update bacpypes3 object attributes directly. Under CPython's GIL this is safe for scalar values and small lists; the worst case is a supervisor reading a value during a write, which they'll re-read on the next poll cycle. If torn reads ever become an issue (they won't at this object volume), the upgrade path is to push updates through `asyncio.Queue` and apply them on the BACnet thread.

---

## Quick start

The bridge ships with a Tkinter configurator GUI for first-time setup. You can also run the CLI tools directly if you prefer — the GUI is just a thin wrapper that invokes them.

### The easy path: GUI

**Windows:** double-click `launch_gui_windows.bat`.

**Linux / macOS:** `./launch_gui_linux.sh`.

The GUI has four tabs walking through setup in order:

1. **Site (P2 Config)** — form for `site.json`. Edit the BLN name, scanner identity, and node table. Includes a "Test Connection" button (P2 handshake against one node) and a "Cold Discover" button that runs the P2 Scanner's auto-discovery.
2. **BACnet Config** — form for `bridge_config.json`. Bind interface picker (auto-detects NICs), polling intervals, BACnet device identity. Advanced options collapse out of sight.
3. **Manifest** — builds and inspects `manifest.json`. Shows live output during build, current point-count breakdown after, and a searchable point browser.
4. **Run Bridge** — start/stop the bridge runtime. The bridge launches in a new console window so you see the heartbeat/log output live.

The configurator uses the same JSON files as the CLI, so you can switch back and forth freely.

### The CLI path

```bash
pip install -r requirements.txt
```

Run this from `bridge/`. It installs `bacpypes3` and nothing else; the scanner is already in the repository and needs no install.

If you are running the bridge from outside this repository, copy `p2_scanner.py`, `p2_data.py`, `p2_asdu.py`, `p2_body.py` and `firmware_registry.py` next to `p2_bacnet_bridge.py`, or put their directory on `PYTHONPATH`.

### 2. Configure

```bash
cp site.json.example site.json
cp bridge_config.json.example bridge_config.json
```

Edit `site.json` — same format as the P2 Scanner:

```json
{
  "p2_network": "MYBLN",
  "scanner_name": "P2BRIDGE|5034",
  "known_nodes": {
    "NODE1": "192.168.1.10",
    "NODE2": "192.168.1.11"
  }
}
```

You can populate this automatically by running the P2 Scanner with `--cold-discover --save site.json` first.

Edit `bridge_config.json` for BACnet identity:

```json
{
  "bacnet_device_instance": 599001,
  "bacnet_device_name": "P2-Bridge",
  "bacnet_address": "192.168.1.50/24:47808",
  "default_poll_interval_s": 60,
  "digital_poll_interval_s": 30
}
```

The `bacnet_address` is the local interface the bridge binds to, with the prefix length defining the broadcast subnet. A BACnet device instance number must be unique on your BACnet network — anything in the 0 to 4194302 range works; pick a number outside the ranges your existing supervisor and JACEs use.

### 3. Build the manifest

```bash
python tools/build_manifest.py \
    --site site.json \
    --bridge-config bridge_config.json \
    --out manifest.json
```

This walks every node in `site.json`, enumerates FLN devices via `0x0986`, reads each device's `APPLICATION` value, looks up the point table from the scanner's embedded TEC catalog, and writes `manifest.json` with one entry per point.

The manifest is **append-only** on re-runs: existing BACnet instance IDs are preserved and only new points get fresh IDs. That stability is non-negotiable — supervisors bind to objects by instance ID and re-allocating breaks every existing mapping.

Audit it:

```bash
python tools/show_manifest.py manifest.json --by-node
python tools/show_manifest.py manifest.json --by-type
python tools/show_manifest.py manifest.json --node NODE1 --list
```

### 4. Run the bridge

```bash
python p2_bacnet_bridge.py
```

You should see:

```
2025-... [INFO] bridge: p2-bacnet-bridge starting
2025-... [INFO] bridge:   P2 network: MYBLN
2025-... [INFO] bridge:   P2 nodes: 2
2025-... [INFO] bridge:   manifest points: 786
2025-... [INFO] p2_bridge.bacnet_app: Built BACnet app: device 599001 (P2-Bridge) + 786 points
2025-... [INFO] p2_bridge.bacnet_app: BACnet/IP service started
2025-... [INFO] bridge: Started poller for NODE1 (192.168.1.10) — 393 points
...
2025-... [INFO] poller-NODE1: [NODE1] Connected to 192.168.1.10 — handshake OK
2025-... [INFO] poller-NODE1: [NODE1] Cycle complete: 393 points in 21.4s ...
```

A BACnet `Who-Is` from your supervisor will now find `device 599001`. `Read-Property-Multiple` against any point will return its current value.

### 5. Profiles — trimming what gets polled

A site with many panels and many points per device can produce a manifest where one full poll cycle takes minutes. If you don't need every PID gain and calibration constant exposed via BACnet, profiles let you trim down to what an operator actually monitors.

Three built-in profiles:

| Profile | What it includes | Typical size |
|---|---|---|
| `essential` | Headline operational points only — `ROOM TEMP`, `CTL TEMP/STPT`, `AIR VOLUME`, `DMPR POS`, `ERROR STATUS`, `OATEMP`, plus boiler/chiller enables | ~10–15% of all points |
| `operational` | Setpoints, modes, IO, valves, sensed values. Excludes PID gains, biases, calibration constants. | ~50–60% of all points |
| `all` | Everything (default) | 100% |

**Apply at build time:**

```bash
python tools/build_manifest.py --profile essential
```

**Or trim an existing manifest without rebuilding** (preserves all instance IDs, just toggles the `enabled` flag):

```bash
python tools/apply_profile.py manifest.json --profile operational
python tools/apply_profile.py manifest.json --profile essential --dry-run
```

Disabled points disappear from BACnet entirely — no objects, no polling. Re-enable any time by applying `--profile all`. The GUI exposes both workflows on the Manifest tab.

### 6. Editing the manifest by hand

`manifest.json` is plain JSON. You can:

- Set `"enabled": false` on any point you don't want exposed (it stays in the file but the bridge skips it)
- Override `"poll_interval_s"` per point
- Rename `"object_name"` if your supervisor's import workflow needs a particular convention
- Fix `"units"` if the auto-mapping picked something wrong

The bridge re-reads the manifest at startup, so changes take effect on restart.

---

## Editing per point — what the manifest looks like

```json
{
  "node": "NODE1",
  "host": "192.168.1.10",
  "device": "AHU1",
  "application": 2027,
  "slot": 4,
  "name": "ROOM TEMP",
  "p2_type": "analog_ro",
  "bacnet_object_type": "analogInput",
  "bacnet_instance": 1024,
  "object_name": "NODE1.AHU1.ROOM_TEMP",
  "description": "slot 4, app 2027, DEG F",
  "units": "DEG F",
  "on_label": null,
  "off_label": null,
  "slope": 0.25,
  "intercept": 48.0,
  "poll_interval_s": 60,
  "enabled": true
}
```

`slope` and `intercept` are carried for reference — the PXC already applies them before returning the value, so the bridge passes the post-scaled float through. They're in the manifest so a future "raw mode" can opt out of panel-side scaling if needed.

---

## Comm-fault behavior

The P2 Scanner distinguishes three states; the bridge translates each one:

| P2 read result | BACnet `reliability` | `statusFlags` | `presentValue` |
|---|---|---|---|
| `comm_status="online"`, value present | `NO_FAULT_DETECTED` | `[0,0,0,0]` | live value |
| `comm_status="comm_fault"` (panel returned cached data, FLN device offline — Desigo's #COM) | `NO_OUTPUT` | `[fault,1,0,0]` | cached value preserved |
| `result is None` (PXC silent, parse failure, or connection lost) | `COMMUNICATION_FAILURE` | `[fault,1,0,0]` | last good value held |

Most BACnet supervisors color the point red when `reliability != NO_FAULT_DETECTED`, which matches what an operator already expects to see in Desigo CC.

When the bridge loses its TCP connection to a PXC entirely, every point on that node is flipped to `COMMUNICATION_FAILURE` until the connection comes back. Reconnect uses capped exponential backoff (5s → 10s → 20s → ... → 300s).

---

## Operational notes

**PXC peer-session budget.** PXCs typically allow 8–16 simultaneous peer sessions. The bridge uses one session per PXC, so it consumes one slot per panel. Don't run a second bridge instance against the same site, and don't run a long P2 Scanner walk against a PXC the bridge is actively polling.

**Polling rate.** Default 60s for analog, 30s for digital. With ~50ms per read, a 393-point node completes a full cycle in ~20s. The bridge logs cycle duration so you can tune. If your manifest crosses a thousand points per panel, consider raising `default_poll_interval_s` to give the PXC breathing room.

**Network.** The bridge needs L3 access from its host to TCP/5033 on every PXC, AND BACnet/IP reachability from the supervisor on UDP/47808. If those live on different VLANs, the bridge host needs both NICs (or the BACnet side needs BBMD — not implemented in v0.1, but bacpypes3 supports it natively if you ever need it).

**Vendor identifier.** The default `bacnet_vendor_identifier: 999` is the test/example range. For a deployment you intend to leave running, register a vendor ID with ASHRAE (free) or use one assigned to your organization. Some supervisors silently filter out devices in the test range during discovery scans.

**Logs.** `p2_bacnet_bridge.log` rotates by hand — there's no built-in rotation in v0.1. If you care about log retention, point `log_file` at a path managed by your OS log rotation (logrotate / Windows Event Log forwarder).

---

## Adding a new PXC

1. Add the entry to `site.json` (`"NODE3": "192.168.1.12"`)
2. Re-run `python tools/build_manifest.py` — this only adds new points, existing IDs are preserved
3. Restart the bridge

The new PXC's points appear with fresh BACnet instance IDs. Existing supervisor mappings to other points are unaffected.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| "Manifest references nodes not in site config" | You added points for a node and later removed it from `site.json`. Either restore the node entry or delete those points from `manifest.json`. |
| All points show `COMMUNICATION_FAILURE` immediately at startup | PXC unreachable on TCP/5033, or P2 handshake failing. Run `python p2_scanner.py --config site.json -n NODE1 --info` to confirm direct reachability. |
| All points on one node show fault but others are fine | That PXC is down or unreachable. Bridge will reconnect automatically; check the log for the next reconnect attempt time. |
| Many points show `NO_OUTPUT` (Desigo's #COM) | The FLN bus or specific TEC devices are offline. Cross-check against Desigo CC's System Manager — it will show the same #COM flag. |
| Supervisor doesn't see the bridge in a Who-Is scan | Wrong subnet on `bacnet_address`, or supervisor and bridge aren't on the same broadcast domain. BBMD is the cross-subnet solution and is not in v0.1. |
| BACnet object name truncated | Names cap at 64 chars (BACnet recommendation). Long device + point name combinations get the point portion truncated. Edit `object_name` in the manifest if you want a different shortening. |
| First read on each point right after startup shows fault | Expected. Objects start in `COMMUNICATION_FAILURE` until the first successful read clears them. |

---

## Safety

- Read-only by design. Same posture as the P2 Scanner.
- One TCP session per PXC — won't exhaust peer sessions.
- Polling, not COV — predictable, bounded load.
- No PPCL writes, no schedule edits, no alarm acknowledgements. Those opcodes exist and [`PROTOCOL.md`](../PROTOCOL.md) documents them — point command in §10.3, PPCL in §14, alarming in §13, time-of-day in §15 — but the bridge does not expose any of them.
- The BACnet side advertises exactly the six services it answers: `readProperty`, `readPropertyMultiple`, `i-Am`, `i-Have`, `who-Is`, `who-Has`. `writeProperty` is not among them.

---

## License

MIT, under the repository's [LICENSE](../LICENSE) — the bridge does not carry its own.

The bridge depends on the P2 Scanner library, which has its own license — please respect both when redistributing.

---

## Acknowledgements

This bridge is built on [bacpypes3](https://github.com/JoelBender/BACpypes3)
by Joel Bender — the asyncio BACnet stack that does all the heavy lifting on
the BACnet/IP side. Decades of BACnet protocol work in one package.

---
