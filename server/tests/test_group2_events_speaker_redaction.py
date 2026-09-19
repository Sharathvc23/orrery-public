"""Group 2 (redaction, not closure): GET /api/events and its A2UI twin
GET /api/surfaces/events keep serving anonymously -- both are CORS-declared
keyless-public by design (chapter_agent._PUBLIC_CORS_PATHS,
tests/test_cors_public_read.py) -- but each event row's suggested_speakers
field is a real member display name the event-proposal LLM was prompted
with (think_cycle.propose_event builds a "Some members: ..." prompt and
asks the LLM to name specific ones), persisted verbatim into agent_events
and served to anyone.

Closed by dropping that one field at read time, independently, in both
list_events (chapter_agent.py) and build_events_surface (surfaces.py) --
thought_redaction.redact_suggested_speakers -- leaving the rest of the row
(title, description, event_type, status) untouched: the public board still
works, it just stops naming members.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import reset_chapter_agent_module

RAW_EVENT = {
    "id": "ev1",
    "title": "ML meetup",
    "description": "A talk on transformers",
    "event_type": "meetup",
    "proposed_reason": "members want more ML content",
    "suggested_speakers": ["Jane Doe", "John Smith"],
    "status": "proposed",
}


@pytest.fixture
def stack(monkeypatch):
    """A client whose surface builders can actually render — booted the real
    way (lifespan entered, not each module's init() hand-called), same
    pattern as tests/test_member_enumeration_closed.py's ``client`` fixture:
    a page whose module was never initialised answers 500, which would make
    this test pass for the wrong reason (no error != no leak)."""
    mod = reset_chapter_agent_module(monkeypatch)

    async def fake_pg_request(method, table, params=None, body=None, on_conflict=None, merge_jsonb=None):
        if table == "agent_events":
            return [dict(RAW_EVENT)]
        return []

    async def _ddl(sql):
        return None

    async def _reachable():
        return False

    import pg_store

    monkeypatch.setattr(mod, "pg_request", fake_pg_request)
    monkeypatch.setattr(pg_store, "pg_request", fake_pg_request, raising=False)
    monkeypatch.setattr(pg_store, "execute_ddl", _ddl)
    monkeypatch.setattr(pg_store, "db_reachable", _reachable)
    mod._rate_limit_store.clear()
    with TestClient(mod.app) as client:
        yield mod, client


def test_redact_suggested_speakers_unit():
    import thought_redaction

    out = thought_redaction.redact_suggested_speakers([dict(RAW_EVENT)])
    assert "suggested_speakers" not in out[0]
    # everything else survives untouched
    assert out[0]["title"] == RAW_EVENT["title"]
    assert out[0]["proposed_reason"] == RAW_EVENT["proposed_reason"]


def test_api_events_stays_public_but_drops_speaker_names(stack):
    """THE GUARD for the raw API: still anonymously readable (CORS-declared
    keyless-public), but suggested_speakers is gone."""
    _mod, client = stack
    resp = client.get("/api/events")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["events"], "fixture event should be returned"
    for ev in body["events"]:
        assert "suggested_speakers" not in ev
    assert "Jane Doe" not in resp.text
    assert "John Smith" not in resp.text


def test_surfaces_events_drops_speaker_names(stack):
    """THE GUARD for the A2UI twin: same underlying leak, same fix, proven
    independently -- build_events_surface runs its own separate query, not
    a call through list_events."""
    _mod, client = stack
    resp = client.get("/api/surfaces/events")
    assert resp.status_code == 200, resp.text
    assert "Jane Doe" not in resp.text
    assert "John Smith" not in resp.text
