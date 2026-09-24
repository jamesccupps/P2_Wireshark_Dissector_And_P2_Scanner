"""`global` statements that name something the function never assigns.

Two of them sat in p2_scanner: `load_config` declared `global KNOWN_NODES`
while only calling `KNOWN_NODES.update()`, and `auto_learn_network_name`
declared `global P2_SITE` and never touched it. Neither did anything, and
both tell a reader the function rebinds module state when it does not --
which matters in a file where several functions genuinely do.

pyflakes finds these, but CI installs pytest and nothing else, so the check
lives here where it will actually run.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MODULES = ["p2_scanner.py", "firmware_registry.py", "p2_gui.py"]


def _offending_globals(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        declared = {}
        assigned = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Global):
                for name in node.names:
                    declared.setdefault(name, node.lineno)
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    assigned.update(n.id for n in ast.walk(t)
                                    if isinstance(n, ast.Name)
                                    and isinstance(n.ctx, ast.Store))
            elif isinstance(node, (ast.AugAssign, ast.AnnAssign, ast.NamedExpr)):
                if isinstance(node.target, ast.Name):
                    assigned.add(node.target.id)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                assigned.update(n.id for n in ast.walk(node.target)
                                if isinstance(n, ast.Name))
            elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                assigned.update(n.id for n in ast.walk(node.optional_vars)
                                if isinstance(n, ast.Name))
            elif isinstance(node, ast.ExceptHandler) and node.name:
                assigned.add(node.name)
        for name, lineno in declared.items():
            if name not in assigned:
                out.append((path.name, lineno, fn.name, name))
    return out


@pytest.mark.parametrize("module", MODULES)
def test_no_global_declares_a_name_it_never_assigns(module):
    path = ROOT / module
    if not path.is_file():
        pytest.skip("%s not present" % module)
    offenders = _offending_globals(path)
    assert offenders == [], "\n".join(
        "%s:%d  %s() declares `global %s` and never assigns it" % o
        for o in offenders)
