# Contributing

Thanks for considering a contribution. The short version: bug reports, real-world deployment notes, and protocol observations are the most valuable thing you can offer. PRs are welcome but please file an issue first to discuss anything non-trivial.

## Filing a bug report

Use the [issue templates](https://github.com/jamesccupps/p2_bacnet_bridge/issues/new/choose). At minimum include:

- The exact bridge version (visible in the GUI title bar or in `p2_bridge/__init__.py`)
- Your Python version and OS (`python --version` + Windows/Linux/macOS)
- The PXC hardware platform (`PXME` / `PXCE` / `PXMR` / `PXCR`) and firmware build tag (`PME####` / `BME####`) if known — both surface in the `0x010C` SystemInfo response. PME and BME are firmware-build identifiers, not hardware models.
- Whatever the log file shows around the failure (`p2_bacnet_bridge.log`)
- The build manifest log if relevant (the GUI captures it; for CLI runs, redirect to a file)

For protocol-level issues, a Wireshark capture of the conversation (filter on TCP/5033 between bridge host and PXC) is the most useful thing in the world.

## Pull requests

- Match the existing code style: hard wraps around 80 chars, type hints where they clarify, docstrings on public functions
- Don't add runtime dependencies without strong justification — the bridge uses only `bacpypes3` and the Python stdlib, plus `p2_scanner` from this repository's root. `bacpypes3` belongs in `bridge/requirements.txt` and must never move to the repository root: cloning this repo for the scanner alone has to stay install-free.
- Keep tools/ scripts standalone and runnable directly with `python tools/whatever.py`
- Test against a real PXC if at all possible — many subtle issues only surface with live panel data. For protocol-level work without a real panel, see the **mock PXC** at `tests/integration/mock_pxc.py` in the scanner repo
- Bump the version string in `p2_bridge/__init__.py` (single source of truth — `p2_bridge_launcher.py` and `p2_bridge/config.py` derive `APP_VERSION`/`bacnet_firmware_revision`/`bacnet_application_software_version` from it)

### Changing the scanner from here

The bridge no longer carries copies of the scanner. It imports `p2_scanner`
from the repository root, one directory up, and earlier releases' four vendored
files, sync scripts, SHA-256 manifest and drift-checking CI workflow are all
gone.

That makes one thing a contributor should be deliberate about: **a change to
`p2_scanner.py` or `firmware_registry.py` is not a bridge change.** Those files
are shared with the scanner, its GUI and `analyze_pcap.py`, and they are built
from [`PROTOCOL.md`](../PROTOCOL.md). Judge such a change against all of their
users, not just the bridge, and if it is a protocol claim rather than a code
fix, the document comes first.

If what the bridge needs is a new capability from the scanner, prefer adding to
its API over reaching into its internals. The coupling surface today is
`P2Connection` plus four methods at runtime, and a handful of catalog lookups
when building a manifest. `tests/test_symbol_resolution.py` states that contract
and fails the build if any of it moves -- including if it moves because the
scanner changed under us.

## Things I'd particularly welcome help on

- Testing against PXC firmware builds other than PME1252 / PME1300 (especially PME11xx and the PME1253–1299 gap range — these would extend `firmware_registry.KNOWN_BUILDS`)
- Multi-FLN walk support. The bridge today calls `enumerate_fln_devices` with the request shape documented in `PROTOCOL.md` for `0x0986 UPL_ALL_TEC` — the panel returns its default FLN's devices (FLN 1). The spec doesn't currently document an FLN-scoped variant of `0x0986`; error code `0x0210` (`invalid_FLN_number`) implies the panel accepts FLN IDs 0-3 somewhere, but the exact request body isn't pinned down. A contribution that captures the wire shape and adds the FLN-scoped variant to `PROTOCOL.md` and `enumerate_fln_devices` would unlock the FLN 2-3 devices on legacy multi-FLN panels.
- BACnet `program` object support for PPCL state monitoring
- BACnet `schedule` object support for those compound-subkey enumerate entries
- COV listener integration (5034 push channel) for sub-second alarm propagation
- Selective writes (analog setpoints, opt-in via manifest field)
- Health HTTP endpoint for monitoring

## Out of scope

- PPCL editing — far too dangerous to expose via BACnet
- Anything that requires modifying the upstream P2 Scanner library (file those upstream)
- Vendor-specific supervisor integrations beyond standard BACnet — keep the bridge protocol-pure
