"""Auth-scoping for GET /api/conversations/{agent_id}.

Used to answer for ANY agent_id with no participation check at all, while the
write path on the same table (agent_conversations.send_message) has always
enforced ``from_agent_id in (thread.from_agent_id, thread.to_agent_id)``. A
thread's ``messages`` field is the verbatim conversation body between two
agents — this route served it to anyone who supplied either party's id.

The middleware now requires a valid signature (GET via the
``/api/conversations/`` prefix, same idiom as ``/api/settings/``) and the
handler binds the target id to the verified caller via ``_require_agent_owner``
— same shared primitive ``/api/settings/*`` uses, so a signed member can only
read their OWN threads, never another agent's by passing a different id.

Classification: HAPPY / ADVERSARIAL.
"""

import asyncio
from unittest.mock import MagicMock

import pytest

import agent_conversations
import auth_verify
import chapter_agent


def _req(caller: str, *, headers: dict | None = None):
    req = MagicMock()
    req.state.agent_id = caller
    req.headers = headers or {}
    return req


class _FakePg:
    def __init__(self, rows: list[dict] | None = None):
        self.rows = rows or []

    async def __call__(self, method, table, params=None, body=None):
        return self.rows


@pytest.fixture(autouse=True)
def _init_agent_conversations():
    prev = agent_conversations._pg_request
    agent_conversations.init(_FakePg(), "TEST-conversations-chapter")
    yield
    agent_conversations._pg_request = prev


# ── the GET is auth-gated at the middleware layer ──────────────────────


def test_conversations_get_prefix_requires_auth():
    prefixes = auth_verify.REQUIRE_AUTH_GET_PREFIXES
    assert "/api/conversations/" in prefixes
    assert any("/api/conversations/alice".startswith(p) for p in prefixes)


def test_conversations_get_is_not_open_path():
    assert auth_verify.is_open_path("GET", "/api/conversations/alice") is False


def test_conversations_get_requires_auth_directly():
    assert auth_verify.requires_auth("GET", "/api/conversations/alice") is True


# ── ADVERSARIAL: a signed caller cannot read another agent's threads ───


def test_conversations_get_rejects_cross_agent():
    with pytest.raises(chapter_agent.HTTPException) as e:
        asyncio.run(chapter_agent.get_conversations("alice", _req("bob")))
    assert e.value.status_code == 403


def test_conversations_get_rejects_unauthenticated():
    """No verified caller (empty request.state.agent_id) → 403, even though the
    path names a specific agent_id."""
    with pytest.raises(chapter_agent.HTTPException) as e:
        asyncio.run(chapter_agent.get_conversations("alice", _req("")))
    assert e.value.status_code == 403


# ── HAPPY: the agent (or an admin) reaches its own threads ─────────────


def test_conversations_get_allows_self():
    agent_conversations._pg_request = _FakePg(
        [{"id": "t1", "from_agent_id": "alice", "to_agent_id": "bob", "messages": [{"text": "hi"}]}]
    )
    out = asyncio.run(chapter_agent.get_conversations("alice", _req("alice")))
    assert out["total"] >= 1
    assert out["threads"][0]["id"] == "t1"


def test_conversations_get_allows_admin(monkeypatch):
    monkeypatch.setattr(auth_verify, "check_admin_token_header", lambda h: True)
    out = asyncio.run(chapter_agent.get_conversations("alice", _req("bob")))
    assert out["total"] == 0
