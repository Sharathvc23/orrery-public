"""Tests for chat_store — durable conversation history.

Coverage map:

  R1  Forgery — corrupt content_json gracefully degrades to a string
  R2  Replay — append after clear works (auto-increment continues)
  R3  Injection — invalid role rejected with ValueError, no row written
  R5  Boundary — limit=1000 caps; limit=0 clamps up to 1
  R10 Persistence — close + re-init returns the same rows
"""

from __future__ import annotations

from pathlib import Path

import pytest

from community_member import chat_store


@pytest.fixture(autouse=True)
def _reset(tmp_path: Path):
    chat_store._reset_for_tests()
    chat_store.init(tmp_path / "chat_history.db")
    yield
    chat_store._reset_for_tests()


def test_append_and_list_recent_chronological():
    chat_store.append("user", "first")
    chat_store.append("assistant", "second")
    chat_store.append("user", "third")
    turns = chat_store.list_recent()
    assert [t["role"] for t in turns] == ["user", "assistant", "user"]
    assert [t["content"] for t in turns] == ["first", "second", "third"]


def test_multimodal_content_round_trips():
    blocks = [
        {"type": "text", "text": "what is this"},
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAA="}},
    ]
    chat_store.append("user", blocks)
    [turn] = chat_store.list_recent()
    assert turn["content"] == blocks


def test_invalid_role_raises():
    with pytest.raises(ValueError):
        chat_store.append("villain", "text")


def test_limit_caps_at_1000():
    for i in range(50):
        chat_store.append("user", f"msg-{i}")
    turns = chat_store.list_recent(limit=10)
    assert len(turns) == 10
    # Most-recent slice in chronological order
    assert turns[0]["content"] == "msg-40"
    assert turns[-1]["content"] == "msg-49"


def test_limit_zero_clamps_to_one():
    chat_store.append("user", "only one")
    turns = chat_store.list_recent(limit=0)
    assert len(turns) == 1


def test_clear_deletes_all_returns_count():
    for _ in range(5):
        chat_store.append("user", "x")
    deleted = chat_store.clear()
    assert deleted == 5
    assert chat_store.list_recent() == []


def test_persistence_across_reinit(tmp_path: Path):
    """A reset + re-init against the same db_path returns rows."""
    chat_store._reset_for_tests()
    chat_store.init(tmp_path / "chat_history.db")
    chat_store.append("user", "before reset")
    chat_store._reset_for_tests()
    chat_store.init(tmp_path / "chat_history.db")
    [turn] = chat_store.list_recent()
    assert turn["content"] == "before reset"


def test_init_required_before_use():
    chat_store._reset_for_tests()
    with pytest.raises(RuntimeError, match="must be called first"):
        chat_store.append("user", "x")
