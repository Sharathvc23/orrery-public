"""M-O1 — GET /api/intents unauth PII disclosure + intents-surface default-deny sweep.

The 3rd unauthenticated hole found on /api/intents/* (after that change). GET
/api/intents (list_intents) had NO auth guard and was in no auth_verify list, so
it was default-open: an unsigned GET /api/intents?agent_id=<victim> returned up
to 20 of the victim's active/matched intents — requester_agent_id + raw
intent_text + match_details — bulk-enumerable (agent_ids are public via the open
GET /api/members).

Beyond the one-line fix, this locks a DEFAULT-DENY INVARIANT: no /api/intents/*
GET route may be reachable unauthenticated. The sweep test iterates the live
route table so a FUTURE intents GET route can't silently ship default-open.

Classification: ADVERSARIAL.
"""

from __future__ import annotations

import importlib
import json
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


def _status(resp) -> int:
    return getattr(resp, "status_code", 200)


def _body(resp) -> dict:
    if isinstance(resp, dict):
        return resp
    b = resp.body
    return json.loads(b.decode() if isinstance(b, bytes) else b)


# ── the specific leak ────────────────────────────────────────────────


def test_list_intents_unauth_rejected(client: TestClient):
    """Unsigned GET /api/intents?agent_id=<victim> must NOT return the victim's
    intents — it must 401."""
    resp = client.get("/api/intents", headers={"X-Agent-ID": "victim"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_intents_scoped_to_verified_caller(chapter_agent_module, monkeypatch):
    """The list is scoped to the caller's OWN intents — the ?agent_id query is
    ignored in favor of the verified caller."""
    seen = {}

    async def fake_active(agent_id=None):
        seen["agent_id"] = agent_id
        return [{"id": "i1", "requester_agent_id": agent_id}]

    monkeypatch.setattr(chapter_agent_module.intents, "get_active_intents", fake_active)

    class _State:
        agent_id = "alice"

    class _Req:
        state = _State()
        headers = {"X-Agent-ID": "victim"}

    await chapter_agent_module.list_intents(_Req())
    assert seen["agent_id"] == "alice", "list_intents did not scope to the verified caller"


# ── default-deny invariant sweep ─────────────────────────────────────


def _intents_get_paths(app) -> list[str]:
    """Concrete URLs for every GET route under /api/intents/* (path params
    filled with a dummy)."""
    # Both sources. Routes mounted with include_router sit behind an
    # _IncludedRouter wrapper in app.routes, so a walk that reads the app alone
    # sees the wrapper and none of its children. For a default-deny sweep that
    # is the dangerous direction: an intents route added to a router module
    # would be skipped and the sweep would report clean over a route it never
    # requested.
    from tests.test_mutating_routes_bind_the_actor import _router_module_routes

    paths = []
    for route in list(app.routes) + _router_module_routes():
        methods = getattr(route, "methods", None) or set()
        path = getattr(route, "path", "")
        if "GET" in methods and path.startswith("/api/intents"):
            concrete = path
            for part in path.split("/"):
                if part.startswith("{") and part.endswith("}"):
                    concrete = concrete.replace(part, "x")
            paths.append(concrete)
    return paths


@pytest.mark.asyncio
async def test_submit_intent_uses_verified_caller_not_body(chapter_agent_module, monkeypatch):
    """POST /api/intents must attribute the intent to the VERIFIED caller, not a
    body-supplied requester_agent_id (write-IDOR — submitting as a victim)."""
    seen = {}

    async def fake_create(requester, text, tags):
        seen["requester"] = requester
        return "i1"

    async def noop(*a, **k):
        return None

    monkeypatch.setattr(chapter_agent_module.intents, "create_intent", fake_create)
    monkeypatch.setattr(chapter_agent_module.intents, "match_intent", noop)
    monkeypatch.setattr(chapter_agent_module.intents, "match_intent_federation", noop)
    monkeypatch.setattr(chapter_agent_module.activity_tracker, "track", noop)
    monkeypatch.setattr(chapter_agent_module.event_bus, "safe_publish", noop)

    class _State:
        agent_id = "alice"

    class _Req:
        state = _State()
        headers = {"X-Agent-ID": "victim"}

    req = chapter_agent_module.IntentSubmission(
        requester_agent_id="victim", intent_text="hi", intent_tags=[]
    )
    await chapter_agent_module.submit_intent(req, _Req())
    assert seen["requester"] == "alice", "intent attributed to the body id, not the verified caller"


@pytest.mark.asyncio
async def test_submit_intent_unauth_rejected(chapter_agent_module):
    class _State:
        agent_id = ""

    class _Req:
        state = _State()
        headers = {"X-Agent-ID": "victim"}

    req = chapter_agent_module.IntentSubmission(
        requester_agent_id="victim", intent_text="hi", intent_tags=[]
    )
    resp = await chapter_agent_module.submit_intent(req, _Req())
    assert _status(resp) == 401


@pytest.mark.asyncio
async def test_open_surface_action_consent_respond_never_reveals_pii(chapter_agent_module, monkeypatch):
    """POST /api/surfaces/action is OPEN. Its consent_respond action must NOT
    record an unauthenticated consent or reach the PII boundary
    (check_mutual_consent) — the surface-action twin of that change (sweep)."""
    called = {"reveal": False, "respond": False}

    async def fake_reveal(*a, **k):
        called["reveal"] = True
        return {"requester": {"name": "SECRET", "profile_type": "m", "skills": []}}

    async def fake_respond(*a, **k):
        called["respond"] = True
        return {"mutual_consent": True}

    monkeypatch.setattr(chapter_agent_module.consent_gate, "check_mutual_consent", fake_reveal)
    monkeypatch.setattr(chapter_agent_module.consent_gate, "respond_to_intent", fake_respond)

    req = chapter_agent_module.SurfaceAction(
        surface_id="s",
        component_id="c",
        action="consent_respond",
        values={"intent_id": "i1", "responder_agent_id": "victim", "response": "accept"},
    )
    class _State:
        agent_id = ""

    class _Req:
        state = _State()
        headers = {"X-Agent-ID": "victim"}

    out = await chapter_agent_module.handle_surface_action(req, _Req())
    assert called["reveal"] is False, "open surface action reached the PII boundary (check_mutual_consent)"
    assert called["respond"] is False, "open surface action recorded an unauthenticated consent"
    assert "SECRET" not in json.dumps(out)


@pytest.mark.asyncio
async def test_open_surface_action_submit_intent_not_forgeable(chapter_agent_module, monkeypatch):
    """POST /api/surfaces/action submit_intent is OPEN. Authorship MUST derive
    from the verified caller, never the body-supplied requester_agent_id —
    else anyone can plant an intent attributed to a victim, polluting their
    activity/receipts. Anonymous (unsigned) submission is allowed, but
    it can never name a specific agent as the author."""
    seen = {}

    async def fake_create(requester, text, tags):
        seen["requester"] = requester
        return "i1"

    async def fake_match(*a, **k):
        return {}

    async def noop(*a, **k):
        return None

    monkeypatch.setattr(chapter_agent_module.intents, "create_intent", fake_create)
    monkeypatch.setattr(chapter_agent_module.intents, "match_intent", fake_match)
    monkeypatch.setattr(chapter_agent_module.intents, "match_intent_federation", fake_match)
    monkeypatch.setattr(chapter_agent_module.activity_tracker, "track", noop)
    monkeypatch.setattr(
        chapter_agent_module.projections, "match_intent_against_projections", lambda *a, **k: []
    )
    monkeypatch.setattr(chapter_agent_module.projections, "get_projections", lambda *a, **k: [])

    def _req(agent_id):
        class _State:
            pass

        st = _State()
        st.agent_id = agent_id

        class _Req:
            state = st
            headers = {"X-Agent-ID": "victim"}

        return _Req()

    payload = chapter_agent_module.SurfaceAction(
        surface_id="s",
        component_id="c",
        action="submit_intent",
        values={"dash-intent-input": "hi", "requester_agent_id": "victim", "dash-intent-tags": "x"},
    )

    # Unsigned caller forging requester_agent_id=victim → attributed to "anonymous", not victim.
    await chapter_agent_module.handle_surface_action(payload, _req(""))
    assert seen["requester"] != "victim", "open surface forged authorship as the victim"
    assert seen["requester"] == "anonymous"

    # Signed caller alice; body still claims victim → attributed to the verified caller.
    seen.clear()
    await chapter_agent_module.handle_surface_action(payload, _req("alice"))
    assert seen["requester"] == "alice", "authorship not derived from the verified caller"


def test_no_intents_get_route_is_default_open(client, chapter_agent_module):
    """Every /api/intents/* GET route must reject an unsigned request — none may
    be default-open. Iterates the live route table so a new route can't slip
    through unauthenticated. (Goal: stop finding these one at a time.)"""
    get_paths = _intents_get_paths(chapter_agent_module.app)
    assert get_paths, "no /api/intents GET routes discovered — test is not exercising anything"
    leaks = []
    for path in get_paths:
        resp = client.get(path, headers={"X-Agent-ID": "victim"})
        # Unsigned + spoofed header must NOT yield a 2xx data response.
        if resp.status_code < 400:
            leaks.append(f"{path} -> {resp.status_code}")
    assert not leaks, "intents GET route(s) reachable unauthenticated (default-open): " + ", ".join(leaks)
