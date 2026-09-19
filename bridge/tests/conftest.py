"""Pytest fixtures shared across the bridge test suite.

Adds the bridge root to sys.path so `import p2_scanner`, `import
firmware_registry`, and `from p2_bridge import ...` all resolve when
pytest runs from anywhere.
"""
from __future__ import annotations

import sys
from pathlib import Path

BRIDGE_ROOT = Path(__file__).resolve().parent.parent
if str(BRIDGE_ROOT) not in sys.path:
    sys.path.insert(0, str(BRIDGE_ROOT))

# The scanner sits outside the bridge in the repo layout, so resolve it the
# same way the entry points do rather than assuming a directory here.
from p2_bridge.scanner_path import ensure_scanner_importable  # noqa: E402

ensure_scanner_importable()
