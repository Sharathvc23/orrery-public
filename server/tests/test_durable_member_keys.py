"""Durable agent_id→did:key identity across restarts.

The auth key store (auth_verify._agent_keys) is in-memory and empty on every
boot. Before this fix, a member's Ed25519 key lived ONLY there, so after a chapter
redeploy did_key_for_member() returned "" — silently emptying the reputation/
standing surfaces and breaking signed-request verification until the member
happened to re-register.

The durable home is the EXISTING agent_facts jsonb column (provider.did) — no
schema migration, works on every deployment. Three parts, each covered here:
  1. registration persists the did:key in agent_facts.provider.did (_persist_member_to_db)
  2. startup rehydrates the key store from that column (reload_member_keys → store_did_key)
  3. resolution falls back to the persisted did when the store misses (arp.resolve_member_did)

Classification: HAPPY / EDGE / FAILURE.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import pytest  # noqa: E402

import arp as arp_mod  # noqa: E402
import auth_verify  # noqa: E402
import chapter_agent  # noqa: E402
import sovereign_identity  # noqa: E402

_ED = "A" * 43 + "="  # 44-char, '='-padded → ed25519-shaped (decodes to 32 bytes)
_DID = sovereign_identity.build_did_key_from_ed25519(_ED)  # the did:key for _ED


class _Postgres:
    """Records POST bodies; returns a configurable list for GET."""

    def __init__(self, get_return=None):
        self.posts: list[tuple[str, dict]] = []
        self.get_return = get_return or []

    async def __call__(self, method, table, params=None, body=None, **kw):
        if method == "POST":
            self.posts.append((table, body))
            return [{"id": "x"}]
        if method == "GET":
            return self.get_return
        return None


# ══════════════════════════════════════════════════════════════════════
# 1. Registration persists the did:key into agent_facts
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_persist_writes_did_in_agent_facts(monkeypatch):  # HAPPY
    sb = _Postgres()
    monkeypatch.setattr(chapter_agent, "pg_request", sb)
    await chapter_agent._persist_member_to_db("alice", {"name": "Alice", "public_key": _ED}, "sovereign")
    assert sb.posts, "expected an agents upsert"
    _, body = sb.posts[0]
    assert body["agent_facts"]["provider"]["did"].startswith("did:key:")


@pytest.mark.asyncio
async def test_persist_omits_facts_when_no_key(monkeypatch):  # EDGE
    sb = _Postgres()
    monkeypatch.setattr(chapter_agent, "pg_request", sb)
    await chapter_agent._persist_member_to_db("alice", {"name": "Alice"}, "sovereign")
    _, body = sb.posts[0]
    assert "agent_facts" not in body  # nothing to persist → don't clobber with empty facts


@pytest.mark.asyncio
async def test_persist_omits_facts_for_non_ed25519_key(monkeypatch):  # EDGE — legacy HMAC pubkey isn't did:key material
    sb = _Postgres()
    monkeypatch.setattr(chapter_agent, "pg_request", sb)
    await chapter_agent._persist_member_to_db("alice", {"name": "Alice", "public_key": "shorthmac"}, "sovereign")
    _, body = sb.posts[0]
    assert "agent_facts" not in body


# ══════════════════════════════════════════════════════════════════════
# 2. Startup rehydrates the key store from agent_facts
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_reload_restores_key_from_agent_facts(monkeypatch):  # HAPPY
    sb = _Postgres(
        get_return=[
            {"agent_id": "alice", "agent_facts": {"provider": {"did": _DID}}},
            {"agent_id": "bob", "agent_facts": None},  # skipped — no facts
            {"agent_id": "carol", "agent_facts": {"provider": {}}},  # skipped — no did
            {"agent_id": "", "agent_facts": {"provider": {"did": _DID}}},  # skipped — no agent_id
        ]
    )
    monkeypatch.setattr(chapter_agent, "pg_request", sb)
    monkeypatch.setattr(auth_verify, "_agent_keys", {})

    await chapter_agent.reload_member_keys()

    # store_did_key parsed the pubkey out of the did and filed it in the ed25519 slot,
    # roundtripping back to the original key.
    assert auth_verify._agent_keys["alice"]["ed25519_pubkey"] == _ED
    assert "bob" not in auth_verify._agent_keys
    assert "carol" not in auth_verify._agent_keys
    assert "" not in auth_verify._agent_keys


@pytest.mark.asyncio
async def test_reload_best_effort_on_supabase_error(monkeypatch):  # FAILURE — must not wedge startup
    async def _boom(*_a, **_k):
        raise RuntimeError("supabase down")

    monkeypatch.setattr(chapter_agent, "pg_request", _boom)
    monkeypatch.setattr(auth_verify, "_agent_keys", {})
    await chapter_agent.reload_member_keys()  # must NOT raise
    assert auth_verify._agent_keys == {}


@pytest.mark.asyncio
async def test_reload_noop_without_supabase(monkeypatch):  # EDGE
    monkeypatch.setattr(chapter_agent, "pg_request", None)
    monkeypatch.setattr(auth_verify, "_agent_keys", {})
    await chapter_agent.reload_member_keys()  # must NOT raise
    assert auth_verify._agent_keys == {}


# ══════════════════════════════════════════════════════════════════════
# 3. Durable resolver — fast path + DB fallback
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_resolve_fast_path_uses_in_memory(monkeypatch):  # HAPPY
    monkeypatch.setattr(arp_mod, "did_key_for_member", lambda _aid: "did:key:zFAST")
    monkeypatch.setattr(arp_mod, "_pg_request", None)  # must not touch the DB
    assert await arp_mod.resolve_member_did("alice") == "did:key:zFAST"


@pytest.mark.asyncio
async def test_resolve_falls_back_to_agent_facts(monkeypatch):  # HAPPY
    monkeypatch.setattr(arp_mod, "did_key_for_member", lambda _aid: "")  # store miss

    async def _get(method, table, params=None, body=None):
        return [{"agent_facts": {"provider": {"did": "did:key:zDB"}}}]

    monkeypatch.setattr(arp_mod, "_pg_request", _get)
    assert await arp_mod.resolve_member_did("alice") == "did:key:zDB"


@pytest.mark.asyncio
async def test_resolve_empty_when_no_facts(monkeypatch):  # EDGE
    monkeypatch.setattr(arp_mod, "did_key_for_member", lambda _aid: "")

    async def _get(method, table, params=None, body=None):
        return []  # no row

    monkeypatch.setattr(arp_mod, "_pg_request", _get)
    assert await arp_mod.resolve_member_did("ghost") == ""


@pytest.mark.asyncio
async def test_resolve_empty_when_facts_have_no_did(monkeypatch):  # EDGE
    monkeypatch.setattr(arp_mod, "did_key_for_member", lambda _aid: "")

    async def _get(method, table, params=None, body=None):
        return [{"agent_facts": {"provider": {}}}]  # facts but no did

    monkeypatch.setattr(arp_mod, "_pg_request", _get)
    assert await arp_mod.resolve_member_did("alice") == ""


@pytest.mark.asyncio
async def test_resolve_best_effort_on_db_error(monkeypatch):  # FAILURE
    monkeypatch.setattr(arp_mod, "did_key_for_member", lambda _aid: "")

    async def _boom(*_a, **_k):
        raise RuntimeError("db down")

    monkeypatch.setattr(arp_mod, "_pg_request", _boom)
    assert await arp_mod.resolve_member_did("alice") == ""  # swallowed, not raised
