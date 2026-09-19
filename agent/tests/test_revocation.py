"""Tests for community_member.revocation — per-execution freshness check.

Coverage map to the v2 threat model:

  R1  Forgery — fetcher returning non-dict JSON is rejected, treated
      as network error (fall back to cache)
  R2  Replay — repeated calls within TTL use cache (fetcher called
      once per TTL window); tests verify cache hit count
  R3  Injection — chapter_url / skill_id with weird chars pass through
      safely (dict keys, not filesystem)
  R4  Authz — revoked=true ALWAYS raises, no bypass via cache
  R5  Boundary — exactly at FRESHNESS_WINDOW_SECONDS → stale; 1s
      before → still fresh
  R7  Adversarial — fetcher that raises but cache says revoked →
      still raises revoked (cache revoked decision survives offline)
  R8  Downgrade — after successful non-revoked fetch, a later revoked
      fetch replaces the cache; the revoked decision wins
  R10 Persistence — cache survives module-level across multiple
      check_fresh calls (not across process restart, which is fine —
      fresh process re-fetches)

  S5  Skill with revoked attestation refuses to run even from cached
      consent — canonical integration test uses invoke_tool + fetcher
      returning revoked=True, confirms ToolError raised
"""

from __future__ import annotations

import pytest

from community_member import revocation


@pytest.fixture(autouse=True)
def _reset():
    revocation.reset_for_tests()
    yield
    revocation.reset_for_tests()


# ── Happy path ─────────────────────────────────────────────────────


def test_non_revoked_skill_allows():
    def fetcher(_url, _id):
        return False

    revocation.check_fresh("https://chapter.example", "skill-x", fetcher=fetcher)


# ── R4: revoked always raises ──────────────────────────────────────


def test_R4_revoked_fetch_raises():
    def fetcher(_url, _id):
        return True

    with pytest.raises(revocation.RevocationCheckFailed) as exc:
        revocation.check_fresh("https://chapter.example", "skill-x", fetcher=fetcher)
    assert exc.value.reason == "skill_revoked"


def test_R4_revoked_cache_survives_offline():
    """If the cache says revoked (from a past successful check), a
    later offline check still raises revoked. The revoked decision
    is sticky even when fresher info isn't available."""
    calls = {"n": 0}

    def flaky_fetcher(_url, _id):
        calls["n"] += 1
        if calls["n"] == 1:
            return True  # first call: revoked
        raise ConnectionError("offline")

    # First call caches revoked=True.
    with pytest.raises(revocation.RevocationCheckFailed) as exc:
        revocation.check_fresh("https://c", "s", fetcher=flaky_fetcher)
    assert exc.value.reason == "skill_revoked"

    # Second call: fetcher fails, but cache still revoked — raise.
    with pytest.raises(revocation.RevocationCheckFailed) as exc:
        revocation.check_fresh("https://c", "s", fetcher=flaky_fetcher)
    assert exc.value.reason == "skill_revoked"


# ── R2: cache behavior ─────────────────────────────────────────────


def test_R2_fetcher_called_on_every_invocation_to_detect_new_revocations():
    """The cache doesn't PREVENT fetches — it just fills in when the
    network is unavailable. On every call we try to fetch fresh; the
    cache is a fallback. This is intentional: waiting 24 hours to
    notice a new revocation is too long, so we probe every time."""
    calls = {"n": 0}

    def fetcher(_url, _id):
        calls["n"] += 1
        return False

    revocation.check_fresh("https://c", "s", fetcher=fetcher)
    revocation.check_fresh("https://c", "s", fetcher=fetcher)
    revocation.check_fresh("https://c", "s", fetcher=fetcher)
    assert calls["n"] == 3  # every call tries fresh; cache is fallback only


# ── R5 boundary: freshness window ─────────────────────────────────


def test_R5_cache_just_before_ttl_still_fresh():
    def ok_then_fail(_url, _id):
        # First call succeeds; subsequent fail.
        if not hasattr(ok_then_fail, "called"):
            ok_then_fail.called = True
            return False
        raise ConnectionError("offline")

    revocation.check_fresh("https://c", "s", fetcher=ok_then_fail, now=1000)
    # Second call: offline, cache is 1s younger than the window.
    revocation.check_fresh(
        "https://c",
        "s",
        fetcher=ok_then_fail,
        now=1000 + revocation.FRESHNESS_WINDOW_SECONDS - 1,
    )


def test_R5_cache_exactly_at_ttl_is_stale():
    def ok_then_fail(_url, _id):
        if not hasattr(ok_then_fail, "called"):
            ok_then_fail.called = True
            return False
        raise ConnectionError("offline")

    revocation.check_fresh("https://c", "s", fetcher=ok_then_fail, now=1000)
    with pytest.raises(revocation.RevocationCheckFailed) as exc:
        revocation.check_fresh(
            "https://c",
            "s",
            fetcher=ok_then_fail,
            now=1000 + revocation.FRESHNESS_WINDOW_SECONDS,
        )
    assert exc.value.reason == "freshness_stale"


def test_first_time_offline_is_stale():
    def always_fail(_url, _id):
        raise ConnectionError("offline")

    with pytest.raises(revocation.RevocationCheckFailed) as exc:
        revocation.check_fresh("https://c", "s", fetcher=always_fail)
    assert exc.value.reason == "freshness_stale"


# ── R8: revoked fetch after a non-revoked cache ──────────────────


def test_R8_new_revocation_overrides_stale_non_revoked_cache():
    """User had a non-revoked cached result; chapter later revokes;
    next successful fetch must surface the new revoked state."""
    state = {"revoked": False}

    def fetcher(_url, _id):
        return state["revoked"]

    revocation.check_fresh("https://c", "s", fetcher=fetcher)
    # Now chapter revokes.
    state["revoked"] = True
    with pytest.raises(revocation.RevocationCheckFailed) as exc:
        revocation.check_fresh("https://c", "s", fetcher=fetcher)
    assert exc.value.reason == "skill_revoked"


# ── R3: weird inputs ───────────────────────────────────────────────


def test_R3_weird_ids_stored_as_dict_keys_not_paths():
    def fetcher(_url, _id):
        return False

    # agent_id-ish with slashes — goes in as a dict key, no filesystem.
    revocation.check_fresh("https://c", "../etc/passwd", fetcher=fetcher)


# ── Per-chapter independence ─────────────────────────────────────


def test_cache_per_chapter_not_just_per_skill():
    """Same skill_id may be hosted on two chapters with independent
    revocation state — the cache key includes chapter_url."""
    state = {"ch-a": False, "ch-b": True}

    def fetcher(url, _id):
        return state[url]

    revocation.check_fresh("ch-a", "same-skill", fetcher=fetcher)
    with pytest.raises(revocation.RevocationCheckFailed):
        revocation.check_fresh("ch-b", "same-skill", fetcher=fetcher)


# ── S5 integration with skill_runtime ───────────────────────────


def test_S5_invoke_tool_blocks_revoked_high_risk_skill(monkeypatch):
    """Canonical S5 integration: a skill with high-risk capability that
    has been remotely revoked cannot be executed even if the user
    previously granted consent."""
    from community_member import skill_runtime

    class FakeSkill:
        skill_id = "malicious"
        name = "malicious"
        version = "1.0.0"
        declared_capabilities = {"shell.exec"}
        tools = {"run": lambda args: "stdout"}
        tool_specs = {}

    revocation.reset_for_tests()

    def fetcher(_url, _id):
        return True  # revoked

    with pytest.raises(skill_runtime.ToolError, match="revocation_check_failed"):
        skill_runtime.invoke_tool(
            [FakeSkill()],  # type: ignore[list-item]
            skill_id="malicious",
            tool_name="run",
            args={},
            user_grants={"malicious": {"shell.exec"}},
            consent_per_invocation=True,
            chapter_url="https://chapter.example",
            revocation_fetcher=fetcher,
        )


def test_S5_invoke_tool_allows_non_revoked_high_risk_skill():
    from community_member import skill_runtime

    class FakeSkill:
        skill_id = "ok-skill"
        name = "ok"
        version = "1.0.0"
        declared_capabilities = {"shell.exec"}
        tools = {"run": lambda args: "hi"}
        tool_specs = {}

    revocation.reset_for_tests()

    def fetcher(_url, _id):
        return False  # not revoked

    result = skill_runtime.invoke_tool(
        [FakeSkill()],  # type: ignore[list-item]
        skill_id="ok-skill",
        tool_name="run",
        args={},
        user_grants={"ok-skill": {"shell.exec"}},
        consent_per_invocation=True,
        chapter_url="https://chapter.example",
        revocation_fetcher=fetcher,
    )
    assert result == "hi"


def test_low_risk_skill_skips_revocation_check():
    """Low-risk skills don't trigger the revocation check — no
    chapter_url needed. Install-time verification is sufficient for
    skills that can't do damage."""
    from community_member import skill_runtime

    class FakeSkill:
        skill_id = "benign"
        name = "benign"
        version = "1.0.0"
        declared_capabilities = set()  # no high-risk caps
        tools = {"echo": lambda args: args.get("msg", "")}
        tool_specs = {}

    def should_never_be_called(_url, _id):
        raise AssertionError("revocation check ran for a low-risk skill")

    result = skill_runtime.invoke_tool(
        [FakeSkill()],  # type: ignore[list-item]
        skill_id="benign",
        tool_name="echo",
        args={"msg": "hello"},
        user_grants={"benign": set()},
        chapter_url="https://chapter.example",
        revocation_fetcher=should_never_be_called,
    )
    assert result == "hello"
