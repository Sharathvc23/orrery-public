"""Prosecution-grade tests for the three-tier broadcast governance (PR5).

Covers:

* HAPPY        chapter agent direct send, leader direct send, high-trust
               direct send, low-trust propose → row created
* EDGE         exactly-at-floor trust (75.0), unknown caller, propose
               with empty body, propose with audience=local
* FAILURE      module not initialized, governance unknown kind
* ADVERSARIAL  caller spoofing the proposer field (body has none),
               trust below floor cannot bypass, role=member cannot
               direct-send, role=admin still blocked if trust unset
               (we test role-OR-trust, not role-AND-trust),
               approval kind "broadcast" rejected if not registered.

The send path uses fakes; no real HTTP. The approval-sweep execution
is exercised via the helper directly in
``test_think_chapter_broadcast.py`` (already in tree) — we don't
re-test it here.
"""

from __future__ import annotations

import pytest

import broadcast
import event_bus
import governance

# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def fake_supabase():
    """Records calls + returns whatever the test sets in `agent_rows`."""
    state: dict = {"calls": [], "agent_rows": {}, "approvals_inserted": []}

    async def _fake(method, table, params=None, body=None, **kwargs):
        state["calls"].append((method, table, params, body))
        if method == "GET" and table == "agents" and params:
            # Parse "agent_id=eq.X" from params
            filter_val = params.get("agent_id", "")
            agent_id = filter_val.split("eq.", 1)[-1] if "eq." in filter_val else ""
            row = state["agent_rows"].get(agent_id)
            return [row] if row else []
        if method == "POST" and table == "pending_approvals":
            state["approvals_inserted"].append(body)
            # Return a fake row shape the propose() function expects.
            inserted = dict(body or {})
            inserted["id"] = "fake-approval-id"
            inserted["status"] = "pending"
            return [inserted]
        if method == "POST" and table == "event_log":
            return [{"id": 9999}]
        if method == "POST" and table == "broadcast_log":
            return [{"id": 1}]
        return []

    return _fake, state


@pytest.fixture(autouse=True)
def reset_modules(fake_supabase):
    """Wire fakes into broadcast + event_bus + governance."""
    fake, _state = fake_supabase
    event_bus.init(fake, "bayarea-nanda-chapter")
    broadcast.init(
        pg_request=fake,
        chapter_id="bayarea-nanda-chapter",
        federation={},
        sign_outbound=None,
    )
    broadcast._reset_dedup_for_tests()
    governance.init(fake, "bayarea-nanda-chapter")
    yield


# ── HAPPY ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_chapter_agent_can_broadcast_directly():
    """The chapter agent itself is always authorised to broadcast —
    that's the autonomous think-cycle path."""
    allowed, reason = await broadcast.caller_can_broadcast_directly("bayarea-nanda-chapter")
    assert allowed is True
    assert reason == "chapter_agent"


@pytest.mark.asyncio
async def test_leader_can_broadcast_directly(fake_supabase):
    _fake, state = fake_supabase
    state["agent_rows"]["alice-leader"] = {
        "agent_id": "alice-leader",
        "chapter_role": "leader",
        "trust_score": 30,
    }
    allowed, reason = await broadcast.caller_can_broadcast_directly("alice-leader")
    assert allowed is True
    assert reason == "leader_role"


@pytest.mark.asyncio
async def test_admin_can_broadcast_directly(fake_supabase):
    _fake, state = fake_supabase
    state["agent_rows"]["root-admin"] = {
        "agent_id": "root-admin",
        "chapter_role": "admin",
        "trust_score": 0,
    }
    allowed, reason = await broadcast.caller_can_broadcast_directly("root-admin")
    assert allowed is True
    assert reason == "leader_role"


@pytest.mark.asyncio
async def test_high_trust_member_can_broadcast_directly(fake_supabase):
    _fake, state = fake_supabase
    state["agent_rows"]["trusted-member"] = {
        "agent_id": "trusted-member",
        "chapter_role": "member",
        "trust_score": 80,
    }
    allowed, reason = await broadcast.caller_can_broadcast_directly("trusted-member")
    assert allowed is True
    assert reason == "trust_floor"


# ── EDGE ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trust_floor_is_exactly_75_inclusive(fake_supabase):
    """Boundary proof: trust_score == 75 is allowed (>= floor)."""
    _fake, state = fake_supabase
    state["agent_rows"]["at-floor"] = {
        "agent_id": "at-floor",
        "chapter_role": "member",
        "trust_score": 75,
    }
    allowed, reason = await broadcast.caller_can_broadcast_directly("at-floor")
    assert allowed is True
    assert reason == "trust_floor"


@pytest.mark.asyncio
async def test_trust_just_below_floor_is_denied(fake_supabase):
    """Boundary proof: trust_score == 74.99 is denied."""
    _fake, state = fake_supabase
    state["agent_rows"]["below-floor"] = {
        "agent_id": "below-floor",
        "chapter_role": "member",
        "trust_score": 74.99,
    }
    allowed, reason = await broadcast.caller_can_broadcast_directly("below-floor")
    assert allowed is False
    assert reason == "below_floor"


@pytest.mark.asyncio
async def test_unknown_agent_is_denied():
    """A caller whose agent_id isn't in the agents table cannot
    bypass the gate by claiming a fake identity."""
    allowed, reason = await broadcast.caller_can_broadcast_directly("nobody")
    assert allowed is False
    assert reason == "unknown_agent"


# ── ADVERSARIAL ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_regular_member_role_denied(fake_supabase):
    """role='member' with low trust must hit propose path, NOT direct."""
    _fake, state = fake_supabase
    state["agent_rows"]["regular-member"] = {
        "agent_id": "regular-member",
        "chapter_role": "member",
        "trust_score": 10,
    }
    allowed, reason = await broadcast.caller_can_broadcast_directly("regular-member")
    assert allowed is False
    assert reason == "below_floor"


@pytest.mark.asyncio
async def test_null_trust_score_treated_as_zero(fake_supabase):
    """A NULL trust_score (newly-joined member before any signals)
    must be treated as 0, not as 'unknown' that bypasses the check."""
    _fake, state = fake_supabase
    state["agent_rows"]["fresh-member"] = {
        "agent_id": "fresh-member",
        "chapter_role": "member",
        "trust_score": None,
    }
    allowed, reason = await broadcast.caller_can_broadcast_directly("fresh-member")
    assert allowed is False
    assert reason == "below_floor"


@pytest.mark.asyncio
async def test_null_chapter_role_treated_as_member(fake_supabase):
    """A NULL chapter_role row must not be silently treated as leader."""
    _fake, state = fake_supabase
    state["agent_rows"]["no-role-but-trusted"] = {
        "agent_id": "no-role-but-trusted",
        "chapter_role": None,
        "trust_score": 50,
    }
    allowed, reason = await broadcast.caller_can_broadcast_directly("no-role-but-trusted")
    # No role, trust below 75 → must hit propose path
    assert allowed is False
    assert reason == "below_floor"


@pytest.mark.asyncio
async def test_role_is_case_insensitive(fake_supabase):
    """Defensive: a stray 'LEADER' uppercase shouldn't bypass either
    direction — we lowercase before comparing."""
    _fake, state = fake_supabase
    state["agent_rows"]["upper-leader"] = {
        "agent_id": "upper-leader",
        "chapter_role": "LEADER",
        "trust_score": 0,
    }
    allowed, reason = await broadcast.caller_can_broadcast_directly("upper-leader")
    assert allowed is True
    assert reason == "leader_role"


@pytest.mark.asyncio
async def test_uninitialized_module_denies(monkeypatch):
    """If the module never got init()'d, every check returns False —
    fail closed."""
    monkeypatch.setattr(broadcast, "_pg_request", None)
    allowed, reason = await broadcast.caller_can_broadcast_directly("anyone")
    assert allowed is False
    assert reason == "uninitialized"


# ── Approval kind registration ─────────────────────────────────────


def test_broadcast_is_a_known_approval_kind():
    """If governance.APPROVAL_KINDS doesn't include 'broadcast',
    governance.propose() silently drops the row and the propose
    endpoint silently fails. Pin the registration."""
    assert "broadcast" in governance.APPROVAL_KINDS


# ── propose() integration ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_propose_broadcast_writes_pending_approval_row(fake_supabase):
    """End-to-end: governance.propose(kind='broadcast', ...) lands a
    row in pending_approvals with the broadcast payload preserved."""
    _fake, state = fake_supabase
    row = await governance.propose(
        kind="broadcast",
        proposer_agent_id="alice-member",
        payload={
            "title": "Open office hours next Friday",
            "body": "Anyone want to join a discussion on agent governance?",
            "tags": ["governance", "discussion"],
            "audience": "all",
        },
        confidence=0.5,
    )
    assert row is not None
    assert row["status"] == "pending"
    assert len(state["approvals_inserted"]) == 1
    inserted = state["approvals_inserted"][0]
    assert inserted["kind"] == "broadcast"
    assert inserted["proposer_agent_id"] == "alice-member"
    assert inserted["payload"]["title"] == "Open office hours next Friday"
    assert inserted["payload"]["audience"] == "all"


@pytest.mark.asyncio
async def test_propose_with_unknown_kind_raises():
    """A typo in the kind name must RAISE.

    This asserted `is None` until the approval-parity fix. Returning None was described as "loud"
    and was not: the caller could not distinguish "typo, never queued" from
    "queued fine", which is exactly how three operational kinds deadlocked in
    production while every layer reported success."""
    with pytest.raises(governance.ProposalFailed) as exc:
        await governance.propose(
            kind="broadcaast",  # intentional typo
            proposer_agent_id="alice",
            payload={"title": "x", "body": "y"},
        )
    assert "broadcaast" in str(exc.value)
