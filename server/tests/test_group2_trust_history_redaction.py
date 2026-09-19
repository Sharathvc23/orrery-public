"""Group 2 item 9: GET /api/agents/{agent_id}/trust HISTORY field is a
REDACTION, not a closure -- the score stays open (its only external
consumer, agent/community_member/identity_trust.py, reads only `score`),
but each history row used to carry source_agent_id, source_event_id and
free-text reason verbatim, despite the handler's own docstring claiming
they were already redacted to endorser_role-grain.

Both endorsements.py call sites that mint a trust event put the endorser's
raw agent_id directly into `reason` (e.g. f"endorsed by {endorser_agent_id}")
and into source_event_id (f"endorsement:{endorser}:{endorsee}") -- so
redacting only source_agent_id, as the stale docstring claimed, would not
have closed this. chapter_agent._redact_trust_history drops all three and
replaces them with a single endorser_role field (the source agent's
chapter_role, or None for system-generated events like tenure milestones).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import reset_chapter_agent_module

TARGET = "group2-trust-target"
ENDORSER = "group2-trust-endorser"

RAW_HISTORY = [
    {
        "event_type": "endorsement_received",
        "delta": "0.5",
        "source_agent_id": ENDORSER,
        "source_event_id": f"endorsement:{ENDORSER}:{TARGET}",
        "reason": f"endorsed by {ENDORSER}",
        "occurred_at": "2026-01-01T00:00:00Z",
    },
    {
        "event_type": "inactive_decay",
        "delta": "-1.0",
        "source_agent_id": None,
        "source_event_id": None,
        "reason": "no qualifying activity in 60+ days",
        "occurred_at": "2026-02-01T00:00:00Z",
    },
]


@pytest.mark.asyncio
async def test_redact_trust_history_unit(monkeypatch):
    import chapter_agent
    import governance

    async def fake_get_chapter_role(agent_id):
        assert agent_id == ENDORSER
        return "leader"

    monkeypatch.setattr(governance, "get_chapter_role", fake_get_chapter_role)

    out = await chapter_agent._redact_trust_history([dict(r) for r in RAW_HISTORY])

    assert out[0] == {
        "event_type": "endorsement_received",
        "delta": "0.5",
        "occurred_at": "2026-01-01T00:00:00Z",
        "endorser_role": "leader",
    }
    assert out[1] == {
        "event_type": "inactive_decay",
        "delta": "-1.0",
        "occurred_at": "2026-02-01T00:00:00Z",
        "endorser_role": None,
    }
    for row in out:
        assert "source_agent_id" not in row
        assert "source_event_id" not in row
        assert "reason" not in row


@pytest.fixture
def client(monkeypatch):
    mod = reset_chapter_agent_module(monkeypatch)

    async def fake_pg_request(method, table, params=None, body=None, on_conflict=None, merge_jsonb=None):
        if table == "agents":
            return [{"trust_score": 42.0}]
        return []

    async def fake_list_history(agent_id, *, limit=20):
        return [dict(r) for r in RAW_HISTORY]

    async def fake_projection_30d(agent_id, *, now=None):
        return {"recent_30d_delta": 0.0, "projected_30d": 0.0}

    async def fake_get_chapter_role(agent_id):
        return "leader" if agent_id == ENDORSER else "member"

    import governance
    import trust_events

    monkeypatch.setattr(mod, "pg_request", fake_pg_request)
    monkeypatch.setattr(trust_events, "list_history", fake_list_history)
    monkeypatch.setattr(trust_events, "projection_30d", fake_projection_30d)
    monkeypatch.setattr(governance, "get_chapter_role", fake_get_chapter_role)
    return TestClient(mod.app)


def test_trust_endpoint_is_open_for_a_member_who_opted_in(client, monkeypatch):
    """The score is open — no signature required — for a member who consented
    to be listed, exactly as the profile route serves them. A member who did
    not opt in answers 404 to a stranger, byte-identical to an unknown id
    (asserted in test_anonymous_member_disclosure.py)."""
    import chapter_agent

    chapter_agent.members[TARGET] = {
        "name": "Target",
        "listing": {"listed": True, "agent_url": "https://target.example"},
    }
    resp = client.get(f"/api/agents/{TARGET}/trust")
    assert resp.status_code == 200, resp.text


def test_trust_history_redacted_over_the_wire(client, monkeypatch):
    """THE GUARD: no raw agent_id or free text survives to the wire."""
    import chapter_agent

    chapter_agent.members[TARGET] = {
        "name": "Target",
        "listing": {"listed": True, "agent_url": "https://target.example"},
    }
    resp = client.get(f"/api/agents/{TARGET}/trust")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["score"] == 42.0
    history = body["history"]
    assert len(history) == 2
    for row in history:
        assert "source_agent_id" not in row
        assert "source_event_id" not in row
        assert "reason" not in row
    assert history[0]["endorser_role"] == "leader"
    assert history[1]["endorser_role"] is None
    assert ENDORSER not in resp.text
    assert "endorsed by" not in resp.text
