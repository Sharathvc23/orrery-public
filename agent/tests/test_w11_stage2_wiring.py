"""W11 stage 2 wiring: outbound sanitization + chapter TOFU.

- Every user-controlled field that leaves the machine through the chapter
  client is sanitized first (defense in depth); identity fields are untouched.
- The chapter's identity is TOFU-pinned on connect: first contact is "new",
  an unchanged identity is "trusted", a changed key/id is "warning".
"""

from __future__ import annotations

import pytest

from community_member import trust
from community_member.a2a_client import A2AClient

# ── sanitize at the outbound boundary ──


def test_join_chapter_sanitizes_content():
    client = A2AClient("http://c.example", agent_id="alice")
    seen = {}
    client._post_open = lambda path, payload: seen.update(payload=payload) or {"ok": True}

    client.join_chapter(
        "alice",
        name="<script>evil</script>Bob",
        description="hello <img src=x onerror=alert(1)>",
        skills=["python", "<script>bad</script>"],
    )
    p = seen["payload"]
    assert "<script>" not in p["name"]
    assert "onerror" not in p["description"] and "<img" not in p["description"]
    assert all("<script>" not in s for s in p["skills"])
    # identity fields are NOT rewritten — they must match the signed request
    assert p["agent_id"] == "alice"


def test_join_chapter_preserves_clean_content():
    client = A2AClient("http://c.example", agent_id="alice")
    seen = {}
    client._post_open = lambda path, payload: seen.update(payload=payload) or {"ok": True}

    client.join_chapter("alice", name="Alice", description="an agent", skills=["python", "ml"])
    p = seen["payload"]
    assert p["name"] == "Alice"
    assert p["description"] == "an agent"
    assert p["skills"] == ["python", "ml"]


def test_submit_intent_sanitizes_text():
    client = A2AClient("http://c.example", agent_id="alice")
    seen = {}
    client._post = lambda path, payload, **kw: seen.update(payload=payload) or {"ok": True}

    client.submit_intent("alice", "need help <script>steal()</script>", tags=["ai"])
    assert "<script>" not in seen["payload"]["intent_text"]
    assert seen["payload"]["intent_tags"] == ["ai"]


def test_update_projection_sanitizes_skills():
    client = A2AClient("http://c.example", agent_id="alice")
    seen = {}
    client._post = lambda path, payload, **kw: seen.update(payload=payload) or {"ok": True}

    client.update_projection("alice", skills=["<script>x</script>", "rust"], interests=["<b>ai</b>"])
    assert all("<script>" not in s for s in seen["payload"]["skills"])
    assert all("<b>" not in i for i in seen["payload"]["interests"])


# ── chapter TOFU ──


@pytest.fixture
def _isolated_trust(monkeypatch, tmp_path):
    monkeypatch.setattr(trust, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(trust, "TRUST_FILE", tmp_path / "trusted_chapters.json")


def _card(did: str) -> dict:
    return {"id": "chapter-1", "agent_name": "Chapter One", "provider": {"did": did}}


def test_tofu_new_then_trusted(_isolated_trust):
    client = A2AClient("http://c.example")
    client._get_open = lambda path: _card("did:key:zAAA")
    assert client.tofu_verify_chapter()[0] == "new"
    assert client.tofu_verify_chapter()[0] == "trusted"


def test_tofu_warns_on_key_change(_isolated_trust):
    client = A2AClient("http://c.example")
    client._get_open = lambda path: _card("did:key:zAAA")
    assert client.tofu_verify_chapter()[0] == "new"
    # the chapter now presents a DIFFERENT key at the same URL — MITM / rotation
    client._get_open = lambda path: _card("did:key:zEVIL")
    assert client.tofu_verify_chapter()[0] == "warning"


def test_tofu_unknown_on_fetch_failure(_isolated_trust):
    client = A2AClient("http://c.example")

    def _boom(path):
        raise RuntimeError("network down")

    client._get_open = _boom
    status, _ = client.tofu_verify_chapter()
    assert status == "unknown"


def test_tofu_unknown_without_chapter(_isolated_trust):
    client = A2AClient("")
    assert client.tofu_verify_chapter()[0] == "unknown"
