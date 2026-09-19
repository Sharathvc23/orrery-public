"""``POST /api/digest/build`` requires a credential (audit M11).

WHAT WAS MEASURED, and why this file asserts over HTTP with the real digest
builder rather than a stub of it.

The route was open. The middleware exempted it because the handler's docstring
said "the digest is public-tier" and the 5/min ceiling capped LLM burn — a
cost argument offered as a content argument. Measured on a local org (one
member registered, one intent submitted, then an unauthenticated POST): the
response carried the intent's text verbatim in ``top_intents[0].text`` and
again in ``summary_markdown`` (the deterministic fallback quotes the first
three intents), the joiner's ``agent_id``, display name and skills in
``new_members[0]``, and with the default ``publish: true`` it appended a
``chapter.digest.weekly`` row to event_log attributed to the org.

The rows the digest reads are delivered over SSE only to a SIGNED member
(``MIN_TRUST_TO_SUBSCRIBE`` is 0.0 for member.joined and intent.published, but
the stream 401s without a caller). The route now sits at that tier: a signed
member or the operator bearer. It is refused at the middleware AND in the
handler, so re-adding one string to the open set in ``auth_verify`` does not
reopen it.

WHAT IS ASSERTED

1. An anonymous POST is refused, with ``publish`` true and false, and the
   refusal carries none of the member-authored text sitting in event_log.
2. An anonymous POST publishes nothing: event_log gains no row.
3. A signed member receives the digest — the same content they would receive
   over SSE — and the operator bearer does too.
4. The handler refuses on its own: with the middleware classifier planted
   open, an anonymous POST is still refused.
5. The gate runs on the DEFAULT configuration. No fixture here sets an
   environment variable to switch it on; there is none to set.

The event_log is in memory and the LLM client is absent, so ``build_digest``
takes the keyless deterministic path — which is the path that quoted the
intent text in ``summary_markdown`` in the measurement. Nothing between the
TestClient and the fake ``pg_request`` is replaced.
"""

from __future__ import annotations

import importlib
import json
import sys

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import initialize_admin_token, register_test_regular_member

ROUTE = "/api/digest/build"

#: What a member actually writes into an intent: prose with contact details.
INTENT_TEXT = "Looking for a co-founder; call me at +1-555-0142 or write to mallory.private@example.com before Friday"
JOINER_ID = "mallory-m11"
JOINER_NAME = "Mallory Q (private person)"
JOINER_SKILLS = ["python", "grief-counselling"]

#: Every string an anonymous caller must not see. Checked against the raw
#: response text so a leak under ANY key — a renamed field, the fallback
#: summary, an error detail — fails the test.
MEMBER_AUTHORED = (
    INTENT_TEXT,
    "+1-555-0142",
    "mallory.private@example.com",
    JOINER_ID,
    JOINER_NAME,
    "grief-counselling",
)


def _now_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()


@pytest.fixture
def mod(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_ID", "TEST-digest-gate-org")
    monkeypatch.setenv("AGENT_NAME", "Digest Gate Org")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    for name in ("admin", "auth_verify", "governance", "chapter_agent"):
        sys.modules.pop(name, None)
    return importlib.import_module("chapter_agent")


@pytest.fixture
def event_log() -> list[dict]:
    """The rows a real org would hold after one join and one intent — the same
    two producers the measurement drove over HTTP."""
    ts = _now_iso()
    return [
        {
            "id": 1,
            "event_type": "member.joined",
            "publisher_agent_id": "TEST-digest-gate-org",
            "payload": {
                "agent_id": JOINER_ID,
                "name": JOINER_NAME,
                "origin": "sovereign",
                "skills": JOINER_SKILLS,
                "did_key": "did:key:z6Mk" + "m" * 40,
                "trust_score": 0.0,
            },
            "created_at": ts,
        },
        {
            "id": 2,
            "event_type": "intent.published",
            "publisher_agent_id": "TEST-digest-gate-org",
            "payload": {
                "intent_id": "0103cf9a-b14f-48ba-b95a-2d72a6faaa26",
                "submitter_agent_id": JOINER_ID,
                "text": INTENT_TEXT,
                "tags": [],
                "submitter_trust_score": 0.0,
            },
            "created_at": ts,
        },
    ]


@pytest.fixture
def client(mod, monkeypatch, event_log) -> TestClient:
    import digest as digest_mod
    import event_bus

    async def _pg(method: str, table: str, params=None, body=None):
        if table == "event_log" and method == "GET":
            return [dict(r) for r in event_log]
        if table == "event_log" and method == "POST":
            row = {"id": len(event_log) + 1, **(body or {}), "created_at": _now_iso()}
            event_log.append(row)
            return [row]
        return []

    monkeypatch.setattr(mod, "pg_request", _pg)
    digest_mod.init(_pg, "TEST-digest-gate-org", "Digest Gate Org", llm=None)
    event_bus.init(_pg, "TEST-digest-gate-org")
    mod._rate_limit_store.clear()
    mod.members.clear()
    initialize_admin_token(monkeypatch)
    return TestClient(mod.app)


def _post(client: TestClient, body: dict, headers: dict | None = None):
    raw = json.dumps(body)
    return client.post(ROUTE, content=raw, headers={"content-type": "application/json", **(headers or {})})


def _signed_member(mod):
    member = register_test_regular_member(mod, agent_id=JOINER_ID, name=JOINER_NAME)

    def headers(body: dict) -> dict:
        raw = json.dumps(body)
        return member["signer"](method="POST", url_path=ROUTE, body=raw)

    return member, headers


# ── the tier the digest actually sits at ──────────────────────────────


def test_HAPPY_signed_member_receives_the_digest(client, mod):
    """A tier-0 subscriber would receive these rows over SSE; the build
    endpoint gives the same member the same content."""
    _member, headers = _signed_member(mod)
    body = {"window_days": 7, "publish": False}
    r = _post(client, body, headers(body))
    assert r.status_code == 200, r.text
    payload = r.json()["payload"]
    assert payload["top_intents"][0]["text"] == INTENT_TEXT
    assert payload["new_members"][0]["agent_id"] == JOINER_ID
    assert INTENT_TEXT[:100] in payload["summary_markdown"]


def test_HAPPY_operator_bearer_can_trigger_a_build(client):
    body = {"window_days": 7, "publish": False}
    r = _post(client, body, {"X-Admin-Token": "f" * 64})
    assert r.status_code == 200, r.text
    assert r.json()["payload"]["intent_published_count"] == 1


def test_HAPPY_signed_member_can_publish_and_the_row_lands(client, mod, event_log):
    _member, headers = _signed_member(mod)
    body = {"window_days": 7, "publish": True}
    r = _post(client, body, headers(body))
    assert r.status_code == 200, r.text
    assert r.json()["published"] is True
    assert event_log[-1]["event_type"] == "chapter.digest.weekly"


# ── the leak, closed ─────────────────────────────────────────────────


@pytest.mark.parametrize("publish", [False, True])
def test_ADVERSARIAL_anonymous_build_is_refused_and_leaks_no_member_text(client, publish):
    r = _post(client, {"window_days": 7, "publish": publish})
    assert r.status_code == 401, r.text
    for needle in MEMBER_AUTHORED:
        assert needle not in r.text, f"member-authored text {needle!r} reached an unauthenticated caller"


def test_ADVERSARIAL_anonymous_build_publishes_nothing(client, event_log):
    before = len(event_log)
    _post(client, {"window_days": 7, "publish": True})
    assert len(event_log) == before, "an unauthenticated caller appended a chapter-attributed row to event_log"


def test_ADVERSARIAL_handler_refuses_even_when_the_middleware_classifier_is_open(client, monkeypatch):
    """The plant that reopened this route once: one string added to the open
    set in auth_verify. The handler's own check must hold without it."""
    import auth_verify

    real = auth_verify.is_open_path
    monkeypatch.setattr(auth_verify, "is_open_path", lambda m, p: True if (m, p) == ("POST", ROUTE) else real(m, p))
    r = _post(client, {"window_days": 7, "publish": False})
    assert r.status_code == 401, r.text
    for needle in MEMBER_AUTHORED:
        assert needle not in r.text


def test_ADVERSARIAL_spoofed_agent_id_header_is_not_a_credential(client):
    """X-Agent-ID without a signature is what _resolve_caller exists to ignore."""
    r = _post(client, {"window_days": 7, "publish": False}, {"X-Agent-ID": JOINER_ID})
    assert r.status_code == 401, r.text
    assert INTENT_TEXT not in r.text


def test_ADVERSARIAL_wrong_bearer_is_refused(client):
    r = _post(client, {"window_days": 7, "publish": False}, {"X-Admin-Token": "0" * 64})
    assert r.status_code == 401, r.text
    assert INTENT_TEXT not in r.text


# ── the gate is the default, not a mode ──────────────────────────────


def test_ADVERSARIAL_gate_holds_with_no_flag_set(client, monkeypatch):
    """No environment variable turns this gate on. Every ORRERY_* and
    FEDERATION_* variable is cleared for the request; a gate that needed one
    of them would let the anonymous build through here."""
    import os

    for name in [k for k in os.environ if k.startswith(("ORRERY_", "FEDERATION_", "LLM_"))]:
        monkeypatch.delenv(name, raising=False)
    r = _post(client, {"window_days": 7, "publish": False})
    assert r.status_code == 401, r.text
    assert INTENT_TEXT not in r.text
