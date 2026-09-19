"""
Prosecution-grade tests for community_member.settings_sync.

The thesis: chapter is source of truth; local cache is a mirror;
last-write-wins by chapter-side timestamps; never crash on chapter
outage or corrupt cache.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import pytest

from community_member import settings_sync as ss

# ─── Test doubles ─────────────────────────────────────


class FakeClient:
    """Minimal stand-in for A2AClient with only the settings methods."""

    def __init__(self):
        self.stored: dict[str, dict] = {}
        self.should_fail = False
        self.call_log: list[tuple] = []

    def get_settings(self, agent_id: str) -> dict:
        self.call_log.append(("GET", agent_id))
        if self.should_fail:
            raise ConnectionError("chapter offline")
        return {"agent_id": agent_id, "settings": self.stored.get(agent_id, {})}

    def update_settings(self, agent_id: str, patch: dict) -> dict:
        self.call_log.append(("POST", agent_id, patch))
        if self.should_fail:
            raise ConnectionError("chapter offline")
        # Chapter-side merge is deep; mimic that here.
        merged = ss._deep_merge(self.stored.get(agent_id, {}), patch)
        self.stored[agent_id] = merged
        return {"agent_id": agent_id, "settings": merged}


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    cache = tmp_path / ".nanda" / "settings.json"
    monkeypatch.setattr(ss, "SETTINGS_CACHE", cache)
    return cache


@pytest.fixture
def client():
    return FakeClient()


# ═══════════════════════════════════════════════════════
# _deep_merge — pure recursion
# ═══════════════════════════════════════════════════════


def test_deep_merge_leaf_overwrite():
    assert ss._deep_merge({"a": 1}, {"a": 2}) == {"a": 2}


def test_deep_merge_recurses_into_dicts():
    base = {"llm": {"provider": "anthropic", "model": "claude"}}
    patch = {"llm": {"model": "opus-4"}}
    assert ss._deep_merge(base, patch) == {"llm": {"provider": "anthropic", "model": "opus-4"}}


def test_deep_merge_replaces_dict_with_scalar():
    """EDGE: patch value type differs from base → patch wins entirely."""
    base = {"llm": {"provider": "anthropic"}}
    patch = {"llm": "disabled"}
    assert ss._deep_merge(base, patch) == {"llm": "disabled"}


def test_deep_merge_preserves_untouched_keys():
    base = {"a": 1, "b": {"x": 1}}
    patch = {"b": {"y": 2}}
    assert ss._deep_merge(base, patch) == {"a": 1, "b": {"x": 1, "y": 2}}


def test_deep_merge_empty_patch_is_noop():
    base = {"a": {"b": 1}}
    assert ss._deep_merge(base, {}) == {"a": {"b": 1}}
    assert ss._deep_merge({}, base) == {"a": {"b": 1}}


# ═══════════════════════════════════════════════════════
# validate_patch
# ═══════════════════════════════════════════════════════


def test_validate_happy():
    ok, _ = ss.validate_patch({"llm": {"provider": "openai"}})
    assert ok


def test_validate_empty_patch_ok():
    ok, _ = ss.validate_patch({})
    assert ok


def test_validate_rejects_unknown_top_level_key():
    """ADVERSARIAL: caller sets a top-level key that isn't allowed."""
    ok, reason = ss.validate_patch({"hackers_in": "the_wires"})
    assert not ok
    assert "unknown top-level key" in reason


def test_validate_rejects_non_dict():
    ok, reason = ss.validate_patch("not a dict")  # type: ignore[arg-type]
    assert not ok
    assert "must be a dict" in reason


def test_validate_rejects_oversized_payload():
    """ADVERSARIAL: 128 KiB patch rejected."""
    huge = {"llm": {"prompt": "x" * (128 * 1024)}}
    ok, reason = ss.validate_patch(huge)
    assert not ok
    assert "too large" in reason


def test_validate_accepts_every_known_top_level_key():
    for key in ss.KNOWN_TOP_LEVEL_KEYS:
        ok, _ = ss.validate_patch({key: {}})
        assert ok, f"rejected {key!r}"


def test_validate_matches_chapter_side_keys():
    """The local set must match the chapter's DEFAULTS top-level keys exactly
    so a push that passes here never gets rejected server-side."""
    assert set(ss.DEFAULTS.keys()) == ss.KNOWN_TOP_LEVEL_KEYS


# ═══════════════════════════════════════════════════════
# Local cache I/O
# ═══════════════════════════════════════════════════════


def test_read_local_missing_returns_empty(tmp_cache):
    assert ss.read_local() == {}


def test_write_and_read_local_roundtrip(tmp_cache):
    ss.write_local({"llm": {"provider": "xai"}})
    cached = ss.read_local()
    assert cached["llm"] == {"provider": "xai"}
    assert "_cached_at" in cached


def test_write_local_sets_0600_permissions(tmp_cache):
    """ADVERSARIAL: cache contains no secrets but must still be owner-only —
    the settings bag can contain IDs that a cohabitant user shouldn't read."""
    ss.write_local({"llm": {"provider": "openai"}})
    mode = tmp_cache.stat().st_mode & 0o777
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


def test_read_local_survives_corrupt_json(tmp_cache):
    """EDGE: cache file gets truncated mid-write — return empty, not crash."""
    tmp_cache.parent.mkdir(parents=True, exist_ok=True)
    tmp_cache.write_text("{not valid json")
    assert ss.read_local() == {}


def test_read_local_survives_binary_garbage(tmp_cache):
    """ADVERSARIAL: another process wrote random bytes — still no crash."""
    tmp_cache.parent.mkdir(parents=True, exist_ok=True)
    tmp_cache.write_bytes(b"\xff\xfe\x00\x00random")
    assert ss.read_local() == {}


def test_strip_meta_removes_underscored_keys():
    assert ss._strip_meta({"llm": {}, "_cached_at": "x", "privacy": {}}) == {"llm": {}, "privacy": {}}


# ═══════════════════════════════════════════════════════
# pull_from_chapter
# ═══════════════════════════════════════════════════════


def test_pull_merges_chapter_over_defaults(tmp_cache, client):
    client.stored["alice"] = {"llm": {"provider": "openai"}}
    result = ss.pull_from_chapter("alice", client)
    # Chapter value wins
    assert result["llm"]["provider"] == "openai"
    # Default value survives for keys the chapter didn't touch
    assert result["voice"]["always_on"] is False


def test_pull_persists_chapter_snapshot_to_cache(tmp_cache, client):
    client.stored["alice"] = {"llm": {"provider": "groq"}}
    ss.pull_from_chapter("alice", client)
    cached = ss.read_local()
    # Cache contains the chapter's view (minus our metadata)
    assert cached["llm"] == {"provider": "groq"}
    assert "_cached_at" in cached


def test_pull_falls_back_to_cache_when_chapter_down(tmp_cache, client):
    """EDGE: chapter is offline. Agent must keep working."""
    ss.write_local({"llm": {"provider": "ollama_local"}})
    client.should_fail = True
    result = ss.pull_from_chapter("alice", client)
    assert result["llm"]["provider"] == "ollama_local"


def test_pull_returns_defaults_when_no_cache_and_chapter_down(tmp_cache, client):
    """FAILURE mode: nothing local, chapter unreachable. Return defaults."""
    client.should_fail = True
    result = ss.pull_from_chapter("alice", client)
    assert result["llm"]["provider"] == ss.DEFAULTS["llm"]["provider"]


def test_pull_empty_chapter_returns_defaults(tmp_cache, client):
    """EDGE: chapter has no row for this agent yet — effective settings are defaults."""
    result = ss.pull_from_chapter("alice", client)
    assert result == ss._deep_merge(ss.DEFAULTS, {})


# ═══════════════════════════════════════════════════════
# push_to_chapter
# ═══════════════════════════════════════════════════════


def test_push_happy(tmp_cache, client):
    result = ss.push_to_chapter("alice", {"llm": {"provider": "xai"}}, client)
    assert result["llm"]["provider"] == "xai"
    # Chapter stored the patch
    assert client.stored["alice"]["llm"]["provider"] == "xai"
    # Local cache updated
    cached = ss.read_local()
    assert cached["llm"]["provider"] == "xai"


def test_push_rejects_invalid_patch_before_network(tmp_cache, client):
    """HAPPY (defensive): validation happens before the round-trip,
    so a bad patch doesn't waste a chapter call."""
    with pytest.raises(ValueError, match="unknown top-level key"):
        ss.push_to_chapter("alice", {"not_a_real_key": 1}, client)
    assert client.call_log == []  # no network call


def test_push_rejects_oversized_patch_before_network(tmp_cache, client):
    huge = {"llm": {"dump": "x" * (80 * 1024)}}
    with pytest.raises(ValueError, match="too large"):
        ss.push_to_chapter("alice", huge, client)
    assert client.call_log == []


def test_push_merges_incrementally(tmp_cache, client):
    """HAPPY: two sequential pushes — each adds to the cache without erasing prior keys."""
    ss.push_to_chapter("alice", {"llm": {"provider": "openai"}}, client)
    ss.push_to_chapter("alice", {"voice": {"tts_provider": "piper_local"}}, client)
    cached = ss.read_local()
    assert cached["llm"]["provider"] == "openai"
    assert cached["voice"]["tts_provider"] == "piper_local"


# ═══════════════════════════════════════════════════════
# sync_on_startup + effective_settings
# ═══════════════════════════════════════════════════════


def test_sync_on_startup_is_idempotent(tmp_cache, client):
    client.stored["alice"] = {"llm": {"provider": "groq"}}
    r1 = ss.sync_on_startup("alice", client)
    r2 = ss.sync_on_startup("alice", client)
    assert r1 == r2


def test_sync_on_startup_picks_up_chapter_changes(tmp_cache, client):
    """HAPPY: portal edits settings while agent is offline; startup pulls
    the new state."""
    # Cache is stale
    ss.write_local({"llm": {"provider": "old-value"}})
    client.stored["alice"] = {"llm": {"provider": "new-value"}}

    merged = ss.sync_on_startup("alice", client)
    assert merged["llm"]["provider"] == "new-value"
    cached = ss.read_local()
    assert cached["llm"] == {"provider": "new-value"}


def test_effective_settings_survives_chapter_outage(tmp_cache, client):
    client.should_fail = True
    ss.write_local({"llm": {"provider": "ollama_local"}})
    result = ss.effective_settings("alice", client)
    assert result["llm"]["provider"] == "ollama_local"


def test_effective_settings_survives_everything_missing(tmp_cache, client):
    """ADVERSARIAL: chapter offline AND no cache. Must return defaults, not crash."""
    client.should_fail = True
    result = ss.effective_settings("alice", client)
    assert result == dict(ss.DEFAULTS)


def test_pull_empty_response_handled(tmp_cache):
    """ADVERSARIAL: chapter returns {} instead of the expected shape — don't crash."""

    class EmptyClient:
        def get_settings(self, agent_id):
            return {}

    result = ss.pull_from_chapter("alice", EmptyClient())
    assert result == ss._deep_merge(ss.DEFAULTS, {})


def test_push_returns_persists_chapter_merged_shape(tmp_cache, client):
    """HAPPY: chapter's response (the post-patch merged state) is what
    becomes the new cache, not the raw patch."""
    client.stored["alice"] = {"llm": {"provider": "old"}, "voice": {"always_on": True}}
    result = ss.push_to_chapter("alice", {"llm": {"provider": "new"}}, client)
    # Chapter-side merge preserved voice.always_on
    assert result["voice"]["always_on"] is True
    assert result["llm"]["provider"] == "new"
    # Cache reflects the chapter's post-merge view. We assert on the
    # payload (strip our `_cached_at` marker, which is always present).
    cached = ss._strip_meta(ss.read_local())
    assert cached == {"llm": {"provider": "new"}, "voice": {"always_on": True}}
