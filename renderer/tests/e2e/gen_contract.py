#!/usr/bin/env python3
"""Emit the portal-surface contract as JSON, derived from server source.

The e2e suite must not hardcode the page list or the auth-gating split —
both live in server code and drift over time. This script AST-parses:

  * server/surfaces.py       -> SURFACE_BUILDERS keys   (every wired page)
  * server/auth_verify.py    -> REQUIRE_AUTH_GET_PATHS  (which pages 401 keyless)

and prints {"pages": [...], "gated": [...]} so the suite always tests
exactly what the server it runs against actually wires.

Usage: python3 renderer/tests/e2e/gen_contract.py [repo_root] > contract.json
"""

import ast
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[3]


def _dict_keys_of(module_path: Path, var_name: str) -> list[str]:
    tree = ast.parse(module_path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id == var_name and node.value is not None:
                    value = node.value
                    if isinstance(value, ast.Dict):
                        return [k.value for k in value.keys if isinstance(k, ast.Constant)]
                    if isinstance(value, (ast.Set, ast.List, ast.Tuple)):
                        return [e.value for e in value.elts if isinstance(e, ast.Constant)]
    raise SystemExit(f"{var_name} not found in {module_path}")


pages = _dict_keys_of(root / "server" / "surfaces.py", "SURFACE_BUILDERS")
auth_paths = _dict_keys_of(root / "server" / "auth_verify.py", "REQUIRE_AUTH_GET_PATHS")
# `/stream` is the SSE form of the SAME page, so it collapses onto the page id
# rather than being treated as a separate surface — otherwise the sanity check
# below sees "directory/stream", finds no such builder, and reports parse drift.
gated = sorted(
    {
        p.removeprefix("/api/surfaces/").removesuffix("/stream")
        for p in auth_paths
        if p.startswith("/api/surfaces/")
    }
)

# Sanity: every gated surface must be a wired page, else the parse drifted.
missing = [g for g in gated if g not in pages]
if missing:
    raise SystemExit(f"gated surfaces not in SURFACE_BUILDERS (parse drift?): {missing}")

json.dump({"pages": pages, "gated": gated}, sys.stdout, indent=2)
print()
