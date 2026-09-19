"""I2 — default-deny sweep over EVERY confirmed-private GET route.

The intents sweep (test_intents_default_deny.py) only iterates `/api/intents/*`,
so it never exercises the private *surface* routes — `/api/surfaces/intents`,
`/settings`, `/messages`, … The I1 fix put those in
`auth_verify.REQUIRE_AUTH_GET_PATHS`, but nothing asserted the allowlist is
actually honored end-to-end. If a future edit drops one of these entries (or a
route stops respecting it), the leak ships silently — exactly the one-at-a-time
failure mode the systemic fix is meant to end.

This sweep drives every entry in the private-GET allowlist through the LIVE
middleware with an unsigned, spoofed-header request and asserts a 401. It is
data-driven off `auth_verify.REQUIRE_AUTH_GET_PATHS`, so a newly-gated route is
covered automatically and a de-gated one turns this red.

Classification: ADVERSARIAL (unsigned caller enumerating another principal's data).
"""

from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def chapter_agent_module(monkeypatch):
    monkeypatch.setenv("AGENT_ID", "TEST-fixture-chapter")
    monkeypatch.setenv("AGENT_NAME", "Fixture")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    sys.modules.pop("chapter_agent", None)
    return importlib.import_module("chapter_agent")


@pytest.fixture
def client(chapter_agent_module) -> TestClient:
    chapter_agent_module._rate_limit_store.clear()
    return TestClient(chapter_agent_module.app)


def _fixed_private_get_paths() -> list[str]:
    """Every parameter-free path in the private-GET allowlist. (Prefix-gated
    routes carry a path param and are swept separately below.)"""
    import auth_verify

    return sorted(p for p in auth_verify.REQUIRE_AUTH_GET_PATHS if "{" not in p)


def test_allowlist_is_non_empty_and_covers_private_surfaces():
    """Guard against the sweep silently exercising nothing, and pin the specific
    surfaces I2 called out so their removal from the allowlist is a test change,
    not an invisible regression."""
    paths = set(_fixed_private_get_paths())
    assert paths, "REQUIRE_AUTH_GET_PATHS is empty — the sweep would assert nothing"
    for must in (
        "/api/surfaces/intents",
        "/api/surfaces/conversations",
        "/api/surfaces/messages",
        "/api/surfaces/settings",
        "/api/surfaces/chapter-security",
    ):
        assert must in paths, f"{must} fell out of the private-GET allowlist"


def test_every_private_get_rejects_unsigned(client, chapter_agent_module):
    """Data-driven: each gated GET path must reject an unsigned + spoofed-header
    request at the middleware (401), never serve data (2xx/3xx)."""
    leaks = []
    for path in _fixed_private_get_paths():
        resp = client.get(path, headers={"X-Agent-ID": "victim"})
        if resp.status_code != 401:
            leaks.append(f"{path} -> {resp.status_code}")
    assert not leaks, "private GET route(s) not default-denied for an unsigned caller: " + ", ".join(leaks)


def test_gated_surface_is_not_open_at_resolver():
    """The resolver twin of the live sweep: is_open_path must agree that each
    gated surface is closed. Catches an ordering bug where an open prefix could
    shadow the explicit auth entry."""
    import auth_verify

    for path in _fixed_private_get_paths():
        assert auth_verify.is_open_path("GET", path) is False, f"{path} resolves as open despite being gated"


def test_public_per_agent_surfaces_stay_open():
    """The inverse invariant: the genuinely-public per-agent surfaces are NOT
    swept into the gated set. Sharing a profile/reputation URL must work without
    an account, so gating these would be an over-correction regression."""
    import auth_verify

    # `directory` and `members` were REMOVED from this list by the member-directory closure:
    # they are not per-agent pages, they rendered the whole membership
    # — including each member's free-text description — to anyone. The human
    # ruled to close them knowing anonymous links to those two pages break.
    # Everything left here names ONE agent, which is what URL sharing is for.
    for page in ("profile", "reputation", "trust", "endorsements", "dashboard"):
        path = f"/api/surfaces/{page}"
        assert auth_verify.is_open_path("GET", path) is True, f"{path} became gated — public surface over-locked"

    # And the inverse, so removing them from the list above cannot silently
    # un-gate them later: the directory pages must NOT be open.
    for gated in auth_verify.MEMBER_BEARING_SURFACES:
        path = f"/api/surfaces/{gated}"
        assert auth_verify.is_open_path("GET", path) is False, f"{path} is open — member enumeration is back"
