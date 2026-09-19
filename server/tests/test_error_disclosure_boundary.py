"""The boundary between an error a caller may see and one they may not (M7).

M7 read: "No custom @app.exception_handler — tracebacks could leak in non-prod
profile." The premise is wrong in a way worth recording rather than patching
around. Starlette returns a traceback in the RESPONSE only when the app is built
with ``debug=True``; otherwise an unhandled exception produces a bare
"Internal Server Error" and the traceback goes to the log. Neither app here sets
``debug``, and there is no env wiring that could.

So the fix for M7 is not another handler — adding one would have been redundant
code justified by an unchecked finding. What was missing is a guard, because the
finding describes a state this codebase could drift INTO silently. These tests
are that guard.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

_SERVER = Path(__file__).resolve().parents[1]


def test_starlette_does_not_put_a_traceback_in_the_response_by_default():
    """HAPPY: pins the premise M7 got wrong, by running it rather than reading docs."""
    app = FastAPI()

    @app.get("/boom")
    def boom():  # noqa: ANN202
        raise RuntimeError("internal detail: /secret/path and a database dsn")

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/boom")
    assert resp.status_code == 500
    assert "secret" not in resp.text, "a traceback reached the client — M7's premise would be live"
    assert "dsn" not in resp.text


def test_neither_app_enables_debug_mode():
    """ADVERSARIAL: debug=True is the one switch that makes M7 real.

    If someone adds it — directly or from an env var — tracebacks start reaching
    callers and this test is the thing that says so.
    """
    for rel in ("chapter_agent.py", "../agent/community_member/server.py"):
        src = (_SERVER / rel).read_text(encoding="utf-8")
        # Strip comments so prose about debugging does not trip this.
        code = "\n".join(line.split("#", 1)[0] for line in src.splitlines())
        assert not re.search(r"FastAPI\([^)]*debug\s*=", code, re.S), f"{rel} builds FastAPI with debug="
        assert not re.search(r"\.debug\s*=\s*True", code), f"{rel} sets app.debug = True"


def test_public_routes_never_echo_an_untyped_exception():
    """ADVERSARIAL: on an UNAUTHENTICATED surface, only authored text may be echoed.

    Scoped to routes/skills.py deliberately. That is the public surface M6 fixed,
    and the invariant there is absolute: a bare ``except Exception`` echoing
    str(e) returns text nobody wrote for a caller.

    The same pattern DOES exist elsewhere and is not a violation there —
    /admin/api/audit/* is admin-token gated and the agent dashboard requires a
    local API token, so their audience is the operator, for whom an exception
    message is diagnostic value. The test says where the line is rather than
    pretending the pattern is banned everywhere.
    """
    src = (_SERVER / "routes" / "skills.py").read_text(encoding="utf-8")
    for m in re.finditer(r"except\s+(Exception|BaseException)\s+as\s+(\w+)\s*:", src):
        start = m.end()
        block = src[start : start + 400]
        assert f"str({m.group(2)})" not in block, (
            "a bare Exception handler on the public skills surface echoes str(e) — that is the M6 leak reopening"
        )


def test_operator_surfaces_bound_the_untyped_text_they_echo():
    """EDGE: where a BARE Exception is echoed, it stays bounded.

    The distinction matters and an earlier version of this test missed it. Three
    sites echo str(exc) untruncated — unsupported_a2ui_version,
    listing_entry_unpublishable, grant_refused — and all three catch a TYPED
    domain exception whose message was authored here. Authorship is the bound;
    truncation would add nothing.

    The admin audit handlers catch a bare ``Exception``, where the text could be
    anything a driver or library produced, and those truncate at 200 chars. That
    is the discipline this asserts: untyped echo must be bounded, typed echo need
    not be.
    """
    src = (_SERVER / "chapter_agent.py").read_text(encoding="utf-8")
    lines = src.splitlines()
    unbounded: list[str] = []
    for i, line in enumerate(lines):
        m = re.match(r"\s*except\s+(Exception|BaseException)\s+as\s+(\w+)\s*:", line)
        if not m:
            continue
        name = m.group(2)
        block = "\n".join(lines[i : i + 12])
        for echo in re.finditer(rf"str\({name}\)(\[:\d+\])?", block):
            if not echo.group(1):
                unbounded.append(f"line {i + 1}: except {m.group(1)} as {name}")
    assert not unbounded, "a bare Exception handler echoes unbounded str(): " + "; ".join(unbounded)
