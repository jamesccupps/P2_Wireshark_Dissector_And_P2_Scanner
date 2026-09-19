"""scanner_path.py — locate the P2 scanner library, whatever layout we are in.

The bridge has no P2 implementation of its own: the scanner is its protocol
stack. But the bridge is a separate application and has to work in more than one
layout, so where `p2_scanner.py` sits is not fixed:

  1. **Already importable.** Installed, or on `PYTHONPATH`. Nothing to do, and
     this case is checked first so an explicit `PYTHONPATH` always wins.
  2. **Repo layout.** The scanner lives at the repository root and the bridge in
     `bridge/` beside it. This is the layout in
     `P2_Wireshark_Dissector_And_P2_Scanner`.
  3. **Standalone copy.** `p2_scanner.py` sits next to the bridge's own entry
     point — someone copied the two together onto a laptop.

Three call sites used to do this inline with three different answers: the
runtime entry assumed the scanner was in its own directory, `build_manifest.py`
assumed the parent, and `conftest.py` a third thing. After the move into
`bridge/` exactly one of those was right.

The scanner needs `p2_data`, `p2_asdu` and `p2_body` beside it, so this resolves
on `p2_scanner.py` and puts *its* directory on the path rather than guessing
each module separately.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import List, Optional

#: Directory holding this file's package — `bridge/p2_bridge/`.
_PKG_DIR = Path(__file__).resolve().parent

#: `bridge/` — where the bridge's entry points live.
BRIDGE_DIR = _PKG_DIR.parent

#: `bridge/..` — the repository root in the repo layout.
REPO_ROOT = BRIDGE_DIR.parent


def candidate_dirs() -> List[Path]:
    """Directories that might hold `p2_scanner.py`, in search order."""
    return [REPO_ROOT, BRIDGE_DIR]


def ensure_scanner_importable() -> Optional[Path]:
    """Make `import p2_scanner` work. Return the directory added, or None.

    None means the scanner was already importable and nothing was changed --
    not that the search failed. A failed search raises.

    Raises:
        ImportError: with every directory that was tried, so the message is
            actionable rather than just "no module named p2_scanner".
    """
    if importlib.util.find_spec("p2_scanner") is not None:
        return None

    for directory in candidate_dirs():
        if (directory / "p2_scanner.py").is_file():
            path = str(directory)
            if path not in sys.path:
                sys.path.insert(0, path)
            return directory

    tried = "\n".join("    %s" % d for d in candidate_dirs())
    raise ImportError(
        "Cannot find p2_scanner.py. The bridge needs the P2 scanner library "
        "-- it is the bridge's protocol stack.\n"
        "Looked in:\n%s\n"
        "Fix by either putting the bridge in `bridge/` beside the scanner in a "
        "clone of P2_Wireshark_Dissector_And_P2_Scanner, copying "
        "p2_scanner.py (with p2_data.py, p2_asdu.py and p2_body.py) next to "
        "the bridge, or adding the scanner's directory to PYTHONPATH."
        % tried
    )
