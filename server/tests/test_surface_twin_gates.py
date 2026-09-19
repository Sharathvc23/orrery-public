"""A gated surface's streaming twin inherits its gate — as a RULE, not a list.

Seven gated pages were world-readable over `/stream`: `401` on the page,
`200` on the stream, `RunStarted` then the complete `snapshot`, no credentials.
`/api/surfaces/settings` is a member's private preferences page. Measured by
driving a running instance and reading the bytes, not by reading routes.

**The hole existed because the page's gate and its stream's gate were two
decisions with nothing tying them together.** Seven fixes would close today's
holes and leave the class open: the eighth page gated next year would ship with
an open stream by exactly the same mechanism. So the fix is a rule —
`auth_verify.canonical_surface_path` collapses a twin onto its page before
either `is_open_path` or `requires_auth` decides — and the assertion below is
**derived from the gated set**, so it covers pages that do not exist yet.

⚠️ **The class is genuinely non-uniform and this suite must not assume one
mechanism.** `/api/surfaces/today/stream` answered `403` before this change,
from a check inside the handler rather than from the middleware. So a stream
could be closed by either layer, and a test that only checked
`auth_verify.requires_auth` would have called `today` fixed while the other
seven leaked, and a test that only drove HTTP could not tell a middleware gate
from a handler one. `T1` asserts the rule, `T2` drives the wire.
"""

from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def app_module(monkeypatch):
    monkeypatch.setenv("AGENT_ID", "TEST-twin-org")
    monkeypatch.setenv("AGENT_NAME", "Twin Org")
    sys.modules.pop("chapter_agent", None)
    return importlib.import_module("chapter_agent")


@pytest.fixture
def client(app_module, monkeypatch) -> TestClient:
    """Booted through the lifespan so the surface builders actually render.

    A page whose module was never initialised answers 500, and a suite that
    skipped non-200 responses would then report "no leak" for a page that never
    rendered — the failure this repo has now hit twice.
    """
    import pg_store

    async def _empty_pg(method, table, params=None, body=None):
        return []

    async def _ddl(sql):
        return None

    async def _unreachable():
        return False

    monkeypatch.setattr(app_module, "pg_request", _empty_pg)
    monkeypatch.setattr(pg_store, "execute_ddl", _ddl)
    monkeypatch.setattr(pg_store, "db_reachable", _unreachable)
    app_module._rate_limit_store.clear()
    with TestClient(app_module.app) as c:
        yield c


def _gated_pages() -> list[str]:
    """Every gated A2UI page, derived from the runtime's own gate.

    Not a list of the seven that were found: this is the assertion's whole
    point. A page gated tomorrow joins this set automatically and must bring its
    stream with it.
    """
    import auth_verify
    import surfaces

    return sorted(p for p in surfaces.SURFACE_BUILDERS if auth_verify.requires_auth("GET", f"/api/surfaces/{p}"))


def test_T0_the_derivation_finds_something() -> None:
    """Assert the mechanism before asserting with it. If the derivation returned
    an empty set — a renamed constant, a changed path shape — every assertion
    below would pass by iterating over nothing, which is the vacuous-guard shape
    this repo keeps finding."""
    gated = _gated_pages()

    assert len(gated) >= 8, f"only {len(gated)} gated pages derived — the derivation is broken, not the app"
    for expected in ("settings", "today", "directory", "members"):
        assert expected in gated, f"{expected} is known to be gated but the derivation missed it"


def test_T1_every_gated_page_has_a_gated_stream_by_rule() -> None:
    """The rule, checked at the layer that decides. Derived, so it covers pages
    nobody has written yet."""
    import auth_verify

    ungated = [
        page
        for page in _gated_pages()
        if not auth_verify.requires_auth("GET", f"/api/surfaces/{page}/stream")
    ]

    assert not ungated, (
        "these pages are gated but their AG-UI streams are not — the same document, "
        f"served without credentials: {ungated}"
    )


def test_T1b_an_open_page_keeps_an_open_stream() -> None:
    """Both directions. A rule that gated every stream would satisfy T1 and break
    the portal's live dashboard, which is the feature the streams exist for."""
    import auth_verify
    import surfaces

    open_pages = [p for p in surfaces.SURFACE_BUILDERS if not auth_verify.requires_auth("GET", f"/api/surfaces/{p}")]
    assert open_pages, "no open pages left — the rule over-gated"

    over_gated = [p for p in open_pages if auth_verify.requires_auth("GET", f"/api/surfaces/{p}/stream")]
    assert not over_gated, f"these pages are open but their streams are gated: {over_gated}"


def test_T2_the_stream_is_refused_over_the_wire(client) -> None:
    """Drive it. The rule above is a statement about a function; this is a
    statement about the server, and only the second one is what a stranger meets.

    Asserted as "not 200" rather than "== 401" deliberately: `today/stream` was
    closed by a HANDLER-side check answering 403 while the others were open, so
    the class is non-uniform and pinning one status would assert the mechanism
    rather than the property. What matters is that no unauthenticated caller
    receives the document.
    """
    refused = {}
    for page in _gated_pages():
        with client.stream("GET", f"/api/surfaces/{page}/stream") as r:
            refused[page] = r.status_code

    leaking = {p: s for p, s in refused.items() if s == 200}
    assert not leaking, f"these gated pages still stream their document to a stranger: {leaking}"


def test_T3_the_canonicalisation_only_touches_surface_twins() -> None:
    """A path-rewriting rule in the auth layer is exactly where an over-broad
    match becomes a bypass, so its blast radius is asserted rather than assumed.

    `/api/subscriptions/{id}/stream` is a different `/stream` — it is gated by
    its own prefix and must not be rewritten to `/api/subscriptions/{id}`, and
    a bare `/api/surfaces//stream` must not collapse to the prefix itself.
    """
    import auth_verify as av

    assert av.canonical_surface_path("/api/surfaces/today/stream") == "/api/surfaces/today"
    assert av.canonical_surface_path("/api/surfaces/today") == "/api/surfaces/today"
    for untouched in (
        "/api/subscriptions/abc/stream",
        "/api/members",
        "/stream",
        "/api/surfaces/",
        "/api/surfaces/stream",
    ):
        assert av.canonical_surface_path(untouched) == untouched, f"canonicalisation altered {untouched}"


def test_T4_the_rule_is_applied_in_BOTH_decision_functions() -> None:
    """`is_open_path` short-circuits before `requires_auth` is consulted, so a
    rule applied in only one of them lets the two disagree about a single URL —
    and the fast path is the one that wins. Present-then-exercised: the call has
    to be there, and T1/T2 show it fires."""
    import inspect

    import auth_verify

    for fn in (auth_verify.is_open_path, auth_verify.requires_auth):
        assert "canonical_surface_path(path)" in inspect.getsource(fn), (
            f"{fn.__name__} does not collapse surface twins — the two gate decisions can diverge"
        )
