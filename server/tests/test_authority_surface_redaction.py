"""Tests for the /page/authority A2UI surface info-leak fix.

Classification: ADVERSARIAL / EDGE / HAPPY.

Background: ``build_authority_surface`` accepts ``?target=did:key:zX``
and returns the full action-authority scope for that agent — every
action_kind, allowed/denied state, and constraint (rate limits, etc.).
The endpoint is publicly fetchable (the portal sends no credentials on
surface GETs), so any caller could enumerate the authority scope of
any member by guessing or scraping their agent_id. That's an ACL leak:
it tells an attacker exactly what privileges they'd gain by
compromising a specific member.

The fix is **safe-projection**: keep the aggregate counts (allowed /
denied), but redact the per-action_kind list and constraints. Admins
who need the full per-agent scope use the underlying admin-gated REST
endpoints (or pull from the ``chapter_policy``/``authority`` modules
directly with admin access).

Server-gating the surface endpoint is the systemic fix but requires
coordinated portal credential plumbing — same constraint as that change.
Tracked as a follow-up.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-authority-chapter")
os.environ.setdefault("AGENT_NAME", "Test Authority Chapter")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import chapter_agent  # noqa: E402


@pytest.fixture
def client():
    return TestClient(chapter_agent.app)


@pytest.fixture
def stub_authority(monkeypatch):
    """Stub authority.list_scope_for with controllable scope data.

    Sensitive identifiers are deliberately distinctive ("LEAK-CANARY-...")
    so the ADVERSARIAL tests can grep for them in the response. If any
    canary string makes it into the surface, the projection has regressed.
    """
    import authority as authority_mod

    async def fake_list_scope_for(agent_id):
        # Returns a mixed set of allowed + denied rules with constraint
        # detail. Action kinds chosen to be obviously canary-shaped.
        return [
            {
                "action_kind": "LEAK-CANARY-ACTION-POST-CALL",
                "allowed": True,
                "constraints": {"rate_per_hour": 5, "LEAK-CANARY-CONSTRAINT-KEY": "value"},
            },
            {
                "action_kind": "LEAK-CANARY-ACTION-PROPOSE-EVENT",
                "allowed": False,
                "constraints": {"requires_approval": True},
            },
            {
                "action_kind": "LEAK-CANARY-ACTION-INTRO-MEMBER",
                "allowed": True,
                "constraints": {},
            },
        ]

    monkeypatch.setattr(authority_mod, "list_scope_for", fake_list_scope_for)


def _serialize(d):
    import json

    return json.dumps(d, default=str)


# ══════════════════════════════════════════════════════════════════════
# ADVERSARIAL — every LEAK-CANARY must be redacted
# ══════════════════════════════════════════════════════════════════════


def test_ADVERSARIAL_action_kinds_not_leaked_via_target_param(client, stub_authority):
    """Querying ?target=did:key:zVictim MUST NOT return that agent's
    action_kind list. This is the ACL-enumeration leak the fix closes."""
    resp = client.get("/api/surfaces/authority?target=did:key:zVictim")
    assert resp.status_code == 200
    blob = _serialize(resp.json())
    assert "LEAK-CANARY-ACTION-POST-CALL" not in blob
    assert "LEAK-CANARY-ACTION-PROPOSE-EVENT" not in blob
    assert "LEAK-CANARY-ACTION-INTRO-MEMBER" not in blob


def test_ADVERSARIAL_constraints_not_leaked(client, stub_authority):
    """Constraint detail (rate limits, requires_approval flags, etc.)
    is operational metadata. Don't expose it on a public-fetchable
    surface."""
    resp = client.get("/api/surfaces/authority?target=did:key:zVictim")
    blob = _serialize(resp.json())
    assert "LEAK-CANARY-CONSTRAINT-KEY" not in blob
    assert "rate_per_hour" not in blob
    assert "requires_approval" not in blob


def test_ADVERSARIAL_anonymous_caller_cannot_enumerate(client, stub_authority):
    """Same payload regardless of how the caller frames the request —
    no auth, weird headers, target-spoofing all produce the same
    redacted response shape."""
    resp = client.get(
        "/api/surfaces/authority?target=did:key:zSomeoneElse",
        headers={"X-Forwarded-For": "1.2.3.4", "User-Agent": "scraper/1.0"},
    )
    blob = _serialize(resp.json())
    assert "LEAK-CANARY-ACTION-POST-CALL" not in blob


# ══════════════════════════════════════════════════════════════════════
# HAPPY — page still tells the viewer something useful
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_aggregate_counts_still_present(client, stub_authority):
    """The viewer can still see "2 allowed, 1 opt-in" — counts were never
    the leak, and they answer the basic question (how much scope does
    this agent have?) without enumerating the actions themselves."""
    resp = client.get("/api/surfaces/authority?target=did:key:zSelf")
    blob = _serialize(resp.json())
    # Stub: 2 allowed (post_call + intro_member), 1 denied (propose_event)
    assert '"value": "2"' in blob or '"value":"2"' in blob
    assert '"value": "1"' in blob or '"value":"1"' in blob


def test_HAPPY_deep_link_to_admin_endpoint_present(client, stub_authority):
    """The redacted view points the viewer at the admin-gated REST
    endpoint where the full scope is retrievable with proper auth."""
    resp = client.get("/api/surfaces/authority?target=did:key:zSelf")
    blob = _serialize(resp.json())
    # Deep-link references the authority admin path (e.g.
    # /api/authority/{target} or admin/api/authority/{target}).
    assert "/api/authority" in blob or "/admin/api/authority" in blob


def test_HAPPY_title_and_subtitle_preserved(client, stub_authority):
    """Page identity is unchanged — same headings as before the
    redaction, just less content underneath."""
    resp = client.get("/api/surfaces/authority?target=did:key:zSelf")
    blob = _serialize(resp.json())
    assert "Agent Authority" in blob


# ══════════════════════════════════════════════════════════════════════
# EDGE
# ══════════════════════════════════════════════════════════════════════


def test_EDGE_no_target_param_still_shows_help_text(client, stub_authority):
    """Calling without ?target= must still show the existing 'pass
    ?target=' help text — pre-existing UX preserved."""
    resp = client.get("/api/surfaces/authority")
    blob = _serialize(resp.json()).lower()
    assert "target=" in blob or "pass" in blob


def test_EDGE_empty_scope_renders_cleanly(client, monkeypatch):
    """Agent with no authority rules configured — surface still renders
    (no 500, no missing-component error in the A2UI envelope)."""
    import authority as authority_mod

    async def empty(_agent_id):
        return []

    monkeypatch.setattr(authority_mod, "list_scope_for", empty)

    resp = client.get("/api/surfaces/authority?target=did:key:zFreshAgent")
    assert resp.status_code == 200
    body = resp.json()
    # Valid A2UI envelope (createSurface + updateComponents).
    assert "createSurface" in body
    assert "updateComponents" in body
