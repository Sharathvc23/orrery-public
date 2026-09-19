"""Tests for the /page/audit A2UI surface (A3.1).

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.

A3.1 is the leader-facing UI for the audit ledger — fetched via
``GET /api/surfaces/audit`` (or its AG-UI streaming variant
``/api/surfaces/audit/stream``). The surface itself shows **aggregate
stats only**: chain length, last activity, action-type breakdown. Per-
event details (actor identities, target IDs, payload contents, hash
chain values) are NOT embedded — those go through the admin-gated
endpoints under ``/admin/api/audit/*``.

This projection is the security gate: the surface endpoint is
publicly fetchable (matching the convention for other admin surfaces
like ``/api/surfaces/admin``), so we keep the content safe to expose.
The ADVERSARIAL tests below enforce that invariant.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-audit-chapter")
os.environ.setdefault("AGENT_NAME", "Test Audit Chapter")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import chapter_agent  # noqa: E402


@pytest.fixture
def client():
    return TestClient(chapter_agent.app)


@pytest.fixture
def stub_audit_state(monkeypatch):
    """Stub chapter_audit.chain_tip + list_events with controllable data."""
    import chapter_audit

    events_data = [
        {
            "id": "audit-1",
            "occurred_at": "2026-05-23T08:00:00Z",
            "action": "admin.role.change",
            "actor_agent_id": "secret-actor-id",  # MUST NOT leak into surface
            "target_type": "agent",
            "target_id": "secret-target-id",  # MUST NOT leak
            "outcome": "ok",
            "detail": {"secret_payload": "must-not-appear-in-surface"},
            "prev_hash": "sha256:should-not-leak",
            "hash": "sha256:should-not-leak",
        },
        {
            "id": "audit-2",
            "occurred_at": "2026-05-23T09:00:00Z",
            "action": "admin.role.change",
            "actor_agent_id": "secret-actor-id",
            "outcome": "ok",
            "detail": {"role_after": "leader"},
        },
        {
            "id": "audit-3",
            "occurred_at": "2026-05-23T09:30:00Z",
            "action": "admin.dsar.delete",
            "actor_agent_id": "secret-actor-id",
            "outcome": "ok",
        },
    ]
    tip_data = {
        "tip_sha256": "abc123" + "0" * 58,  # MUST NOT leak
        "length": len(events_data),
        "first_occurred_at": events_data[0]["occurred_at"],
        "last_occurred_at": events_data[-1]["occurred_at"],
    }

    async def fake_list_events(**_kwargs):
        return list(events_data)

    async def fake_chain_tip(_chapter_id):
        return dict(tip_data)

    monkeypatch.setattr(chapter_audit, "list_events", fake_list_events)
    monkeypatch.setattr(chapter_audit, "chain_tip", fake_chain_tip)
    return {"events": events_data, "tip": tip_data}


def _serialize(d):
    import json

    return json.dumps(d, default=str)


# ══════════════════════════════════════════════════════════════════════
# ADVERSARIAL — safe-projection invariants come FIRST
# ══════════════════════════════════════════════════════════════════════


def test_ADVERSARIAL_surface_does_not_leak_actor_ids(client, stub_audit_state):
    """The audit surface MUST NOT embed actor_agent_id values from events.
    A leader's identity in a privileged action is the operator-sensitive
    bit; admin-gated /admin/api/audit is the only path that should
    expose it."""
    resp = client.get("/api/surfaces/audit")
    assert resp.status_code == 200
    blob = _serialize(resp.json())
    assert "secret-actor-id" not in blob


def test_ADVERSARIAL_surface_does_not_leak_target_ids(client, stub_audit_state):
    """target_id can be a member did or other PII-adjacent identifier."""
    resp = client.get("/api/surfaces/audit")
    blob = _serialize(resp.json())
    assert "secret-target-id" not in blob


def test_ADVERSARIAL_surface_does_not_leak_detail_payload(client, stub_audit_state):
    """detail can carry ComplianceCredentials, role transitions, full
    payload contents from PR. None of it belongs in the public
    surface."""
    resp = client.get("/api/surfaces/audit")
    blob = _serialize(resp.json())
    assert "secret_payload" not in blob
    assert "must-not-appear-in-surface" not in blob


def test_ADVERSARIAL_surface_does_not_leak_chain_hashes(client, stub_audit_state):
    """Chain hashes are part of the integrity proof — exposing them via
    a public surface lets an adversary correlate snapshots without
    auth. /admin/api/audit/verify is the proper gated path."""
    resp = client.get("/api/surfaces/audit")
    blob = _serialize(resp.json())
    assert "should-not-leak" not in blob
    # The tip_sha256 specifically — full hex digest must not appear
    assert "abc123" + "0" * 58 not in blob


# ══════════════════════════════════════════════════════════════════════
# FAILURE
# ══════════════════════════════════════════════════════════════════════


def test_FAILURE_chain_tip_raises_returns_unavailable_surface(client, monkeypatch):
    """If chain_tip raises, the builder returns the 'unavailable' fallback
    surface — same pattern as build_approvals_surface when governance is
    missing. We never let an exception escape into a 500 from a surface
    endpoint."""
    import chapter_audit

    async def boom(*_args, **_kwargs):
        raise RuntimeError("supabase down")

    monkeypatch.setattr(chapter_audit, "chain_tip", boom)

    resp = client.get("/api/surfaces/audit")
    assert resp.status_code == 200
    blob = _serialize(resp.json())
    # The fallback surface advertises unavailability without leaking the
    # raw exception message.
    assert "unavailable" in blob.lower() or "temporarily" in blob.lower()
    assert "supabase down" not in blob  # exception text MUST NOT leak


# ══════════════════════════════════════════════════════════════════════
# EDGE
# ══════════════════════════════════════════════════════════════════════


def test_EDGE_empty_chain_renders_empty_state(client, monkeypatch):
    """Empty chain = a fresh chapter that hasn't emitted audit events yet.
    Surface still renders cleanly with a 'no events yet' message."""
    import chapter_audit

    async def empty_tip(_chapter_id):
        return {"tip_sha256": "", "length": 0, "first_occurred_at": None, "last_occurred_at": None}

    async def empty_events(**_kwargs):
        return []

    monkeypatch.setattr(chapter_audit, "chain_tip", empty_tip)
    monkeypatch.setattr(chapter_audit, "list_events", empty_events)

    resp = client.get("/api/surfaces/audit")
    assert resp.status_code == 200
    blob = _serialize(resp.json()).lower()
    assert "no audit events" in blob or "ledger will populate" in blob or "no events" in blob


# ══════════════════════════════════════════════════════════════════════
# HAPPY
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_surface_endpoint_returns_a2ui_envelope(client, stub_audit_state):
    """Sanity: response is a v0.9 A2UI envelope (createSurface +
    updateComponents)."""
    resp = client.get("/api/surfaces/audit")
    assert resp.status_code == 200
    body = resp.json()
    assert "createSurface" in body
    assert "updateComponents" in body
    assert body["updateComponents"]["root"] in {c.get("id") for c in body["updateComponents"]["components"]}


def test_HAPPY_surface_has_title_and_chain_length_metric(client, stub_audit_state):
    """The leader-readable summary needs at least: a title and the chain
    length so a leader can tell at-a-glance how much activity exists."""
    resp = client.get("/api/surfaces/audit")
    blob = _serialize(resp.json())
    assert "Audit Log" in blob
    # Chain length from the stub = 3 events
    assert '"value": "3"' in blob or '"value":"3"' in blob


def test_HAPPY_surface_shows_action_type_breakdown(client, stub_audit_state):
    """When events exist, the surface should aggregate them by action
    type so leaders see what KIND of activity has been happening,
    without exposing per-event specifics."""
    resp = client.get("/api/surfaces/audit")
    blob = _serialize(resp.json())
    assert "admin.role.change" in blob
    assert "admin.dsar.delete" in blob


def test_HAPPY_surface_has_deep_links_to_admin_endpoints(client, stub_audit_state):
    """The surface points at the admin-gated endpoints rather than
    embedding their data — separation of UI scaffolding from data
    access."""
    resp = client.get("/api/surfaces/audit")
    blob = _serialize(resp.json())
    assert "/admin/api/audit/verify" in blob
    assert "/admin/api/audit/export" in blob
    assert "/admin/api/audit/attest" in blob


def test_HAPPY_audit_registered_in_surface_builders():
    """The page is reachable via the canonical SURFACE_BUILDERS dict."""
    import surfaces

    assert "audit" in surfaces.SURFACE_BUILDERS
    assert callable(surfaces.SURFACE_BUILDERS["audit"])


def test_HAPPY_admin_nav_includes_audit_link():
    """Leaders find the audit page from the admin console nav row.
    Without this, the audit surface is reachable only by direct URL —
    invisible to anyone who doesn't know it exists.

    Checked via source inspection rather than via /api/surfaces/admin
    because build_admin_surface has runtime dependencies (federation,
    knowledge cache, intents) that aren't reliably initialized in test
    isolation. The nav-row addition is a static change to the function
    body — source inspection is a precise check for what we added."""
    import inspect

    import surfaces

    src = inspect.getsource(surfaces.build_admin_surface)
    assert "/page/audit" in src
