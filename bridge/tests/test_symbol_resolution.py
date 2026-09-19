"""Every `p2_scanner.X` / `firmware_registry.X` the bridge names must exist.

This test exists because of a specific failure. The bridge's `--show-firmware`
subcommand referenced three symbols that were not there:

  * `firmware_registry.negotiate_dialect`, removed when the dialect model was
    withdrawn from the scanner;
  * `p2_scanner.read_system_info_compact` called at module level, when it has
    only ever been a `P2Connection` method.

Both sites sat inside `except Exception` handlers that printed the resulting
`AttributeError` as a per-node `[FAIL] exception ...` line, so the subcommand
reported every panel as unreachable and read as a network problem. **The rest of
this suite passed the whole time.**

The bridge depends on the scanner as a library across a small, stable API, and
the two evolve in separate files. A static resolve is the cheapest thing that
catches a symbol moving, and it does not need a panel, a network or a mock.

It deliberately checks *attribute access on the imported modules*, which is what
pyflakes cannot see: `import p2_scanner` is valid however wrong the attribute
that follows it is.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import List, Tuple

import firmware_registry
import p2_scanner
import pytest

BRIDGE_ROOT = Path(__file__).resolve().parent.parent

#: Modules whose attribute references get resolved.
WATCHED = {"p2_scanner": p2_scanner, "firmware_registry": firmware_registry}

#: Files that ARE the watched modules, or vendored beside them — skipped so the
#: check never grades the scanner against itself.
SKIP_NAMES = {
    "p2_scanner.py", "firmware_registry.py",
    "p2_data.py", "p2_asdu.py", "p2_body.py", "p2_gui.py",
}


def _bridge_sources() -> List[Path]:
    return [
        p for p in BRIDGE_ROOT.rglob("*.py")
        if p.name not in SKIP_NAMES and "__pycache__" not in p.parts
    ]


def _unresolved(path: Path) -> List[Tuple[int, str, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
    bad = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id in WATCHED
                and not hasattr(WATCHED[node.value.id], node.attr)):
            bad.append((node.lineno, node.value.id, node.attr))
    return bad


def test_sources_were_found():
    """Guard the guard: a path bug here would make the real test vacuous."""
    sources = _bridge_sources()
    assert len(sources) >= 10, f"only found {len(sources)} bridge sources"
    assert any(p.name == "p2_bacnet_bridge.py" for p in sources)


@pytest.mark.parametrize(
    "source", _bridge_sources(), ids=lambda p: p.name)
def test_every_scanner_symbol_resolves(source: Path):
    bad = _unresolved(source)
    assert not bad, "\n".join(
        f"{source.relative_to(BRIDGE_ROOT)}:{ln}  {mod}.{attr} does not exist"
        for ln, mod, attr in bad
    )


def test_the_api_the_bridge_depends_on_is_present():
    """The documented coupling surface, named explicitly.

    The parametrised test above only sees symbols the code currently mentions,
    so a call site deleted by accident would make it pass. This one states the
    contract.
    """
    for name in ("P2Connection", "enumerate_fln_devices", "get_device_application",
                 "get_app_meta", "get_point_table", "get_point_info",
                 "app_supports_p2", "SCANNER_NAME", "__version__"):
        assert hasattr(p2_scanner, name), f"p2_scanner.{name} is missing"

    for name in ("connect", "close", "read_point", "enumerate_all_points",
                 "read_system_info_compact"):
        assert hasattr(p2_scanner.P2Connection, name), \
            f"P2Connection.{name} is missing"

    for name in ("KNOWN_BUILDS", "describe_build", "parse_build_tag",
                 "classify_unknown_build", "get_cached_build_tag",
                 "cache_build_tag", "load_build_tags"):
        assert hasattr(firmware_registry, name), \
            f"firmware_registry.{name} is missing"


def test_the_daemon_does_not_mutate_scanner_globals():
    """Assignment to `p2_scanner.<GLOBAL>` belongs to the manifest builder only.

    `enumerate_fln_devices` and `get_device_application` read `P2_NETWORK`,
    `SCANNER_NAME` and `P2_SITE` from the scanner's module state instead of
    taking them as arguments, and `tools/build_manifest.py` is the only caller
    of either. Everything else -- the poller, the firmware read -- constructs a
    `P2Connection` and passes what it needs.

    Letting the daemon set those globals would make a long-running process
    depend on hidden module state that anything else could change. Keeping the
    rule as a test means it survives the next person who finds it convenient.
    """
    allowed = {"tools/build_manifest.py"}
    offenders = []
    for source in _bridge_sources():
        rel = source.relative_to(BRIDGE_ROOT).as_posix()
        tree = ast.parse(source.read_text(encoding="utf-8"), str(source))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if (isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "p2_scanner"
                        and target.attr.isupper()
                        and rel not in allowed):
                    offenders.append(f"{rel}:{node.lineno}  p2_scanner.{target.attr}")
    assert not offenders, (
        "these assign to scanner module globals outside the manifest builder:\n"
        + "\n".join(offenders))
