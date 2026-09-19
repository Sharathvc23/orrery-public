"""Reality guard: every server path docs/API.md advertises must map to a
registered route template.

The server-surface audit found docs/API.md listing /api/calls,
/api/nominations, /api/mentors, and /api/agents/{id}/reputation — all 404. A
public API doc that lists non-existent routes breaks the first thing an
integrator tries. This test unions every route template the server registers
(the app + the identity/skills routers it includes at __main__) and asserts
each documented path resolves, guarding the doc from drifting ahead of the code.

Static (no handler execution — several handlers do real network/DB work).

Classification: DOC↔CODE PARITY.
"""

import os
import re
from pathlib import Path

os.environ.setdefault("AGENT_ID", "test-doc-parity")
os.environ.setdefault("AGENT_NAME", "Test Doc Parity")

import chapter_agent
from routes import identity, skills

API_DOC = Path(__file__).resolve().parents[2] / "docs" / "API.md"
_NOT_ROUTES = {"/", "/admin/"}


def _norm(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path.rstrip("/")) or "/"


def _registered() -> set[str]:
    """Union of the app's own routes and the routers it includes at runtime —
    robust to the module-alias split that leaves included routes off
    chapter_agent.app.routes when imported (vs. run as __main__)."""
    reg: set[str] = set()
    holders = [chapter_agent.app, identity.router, skills.router]
    for h in holders:
        for r in getattr(h, "routes", []):
            p = getattr(r, "path", None)
            if p:
                reg.add(_norm(p))
    return reg


def _expand(span: str) -> list[str]:
    m = re.search(r"\{[a-z,\-]+,[a-z,\-]+\}", span)
    if m:
        head, _, tail = span.partition(m.group(0))
        return [head + alt + tail for alt in m.group(0).strip("{}").split(",")]
    return [span]


def _documented_paths() -> list[str]:
    paths: set[str] = set()
    for span in re.findall(r"`(/[^`]*)`", API_DOC.read_text()):
        span = span.strip().rstrip("*").rstrip("/") or "/"
        if span in _NOT_ROUTES or " " in span:
            continue
        paths.update(_expand(span))
    return sorted(paths)


def test_every_documented_path_is_registered():
    reg = _registered()

    def resolves(doc: str) -> bool:
        n = _norm(doc)
        # exact, or a registered route sits directly under a documented family
        return n in reg or any(r == n or r.startswith(n + "/") for r in reg)

    missing = sorted(d for d in _documented_paths() if not resolves(d))
    assert not missing, f"docs/API.md advertises path(s) with no registered route: {missing}"


def test_audit_phantoms_stay_gone():
    doc = API_DOC.read_text()
    for phantom in ("/api/calls", "/api/nominations", "/api/mentors", "/api/agents/{id}/reputation"):
        assert phantom not in doc, f"{phantom} is back in API.md but has no route"
