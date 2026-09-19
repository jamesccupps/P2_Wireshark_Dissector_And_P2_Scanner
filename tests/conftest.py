"""Put the repository root on sys.path so `import p2_scanner` resolves.

The scanner lives at the root, not in a package, because it is meant to be
copied to a laptop and run. That makes it awkward to import from a test
directory, which is part of why it went untested for so long.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
