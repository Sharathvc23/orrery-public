"""
Prosecution-grade tests for surface_cache.py — TTL memoization + telemetry.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import asyncio
import time

import pytest

import surface_cache as sc


@pytest.fixture(autouse=True)
def reset_cache():
    sc.reset()
    yield
    sc.reset()


# ═══════════════════════════════════════════════════════════════
# get / set / TTL
# ═══════════════════════════════════════════════════════════════


def test_get_missing_returns_none():
    assert sc.get("never-set") is None


def test_set_and_get_within_ttl():
    sc.set("k", {"v": 1}, ttl=5.0)
    assert sc.get("k") == {"v": 1}


def test_expired_entry_is_evicted():
    """EDGE: a zero-TTL entry (clamped to 0.1s) expires after a short sleep."""
    sc.set("k", "v", ttl=0.01)
    time.sleep(0.2)
    assert sc.get("k") is None


def test_ttl_clamped_to_min_floor():
    """ADVERSARIAL: ttl=-5 or 0 clamped to 0.1s — never infinite negative cache."""
    sc.set("k", "v", ttl=-5)
    # entry does expire after its clamped floor.
    time.sleep(0.2)
    assert sc.get("k") is None


def test_set_overwrites_previous_value():
    sc.set("k", "v1")
    sc.set("k", "v2")
    assert sc.get("k") == "v2"


# ═══════════════════════════════════════════════════════════════
# invalidate
# ═══════════════════════════════════════════════════════════════


def test_invalidate_drops_matching_prefix():
    sc.set("skills:alice", 1)
    sc.set("skills:bob", 2)
    sc.set("mesh:alice", 3)
    n = sc.invalidate("skills:")
    assert n == 2
    assert sc.get("skills:alice") is None
    assert sc.get("mesh:alice") == 3


def test_invalidate_zero_matches():
    assert sc.invalidate("nothing:") == 0


def test_invalidate_empty_prefix_drops_all():
    sc.set("a", 1)
    sc.set("b", 2)
    n = sc.invalidate("")
    assert n == 2


# ═══════════════════════════════════════════════════════════════
# cached_builder — async wrapping
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_cached_builder_memoizes_within_ttl():
    calls = {"n": 0}

    async def slow(target=None):
        calls["n"] += 1
        return {"result": target or "default"}

    wrapped = sc.cached_builder("test-surface", slow, ttl=5.0)
    r1 = await wrapped("alice")
    r2 = await wrapped("alice")

    assert r1 == r2
    assert calls["n"] == 1  # only built once
    stats = sc.stats()["test-surface"]
    assert stats["builds"] == 1
    assert stats["hits"] == 1


@pytest.mark.asyncio
async def test_cached_builder_misses_on_different_target():
    calls = {"n": 0}

    async def fn(target=None):
        calls["n"] += 1
        return {"target": target}

    wrapped = sc.cached_builder("s", fn, ttl=5.0)
    await wrapped("alice")
    await wrapped("bob")

    assert calls["n"] == 2
    # No cache hit for a brand-new target.
    assert sc.stats()["s"]["builds"] == 2
    assert sc.stats()["s"]["hits"] == 0


@pytest.mark.asyncio
async def test_cached_builder_rebuilds_after_ttl_expiry():
    calls = {"n": 0}

    async def fn(target=None):
        calls["n"] += 1
        return calls["n"]

    wrapped = sc.cached_builder("s", fn, ttl=0.01)
    r1 = await wrapped()
    time.sleep(0.2)
    r2 = await wrapped()

    assert r1 != r2
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_cached_builder_timing_recorded():
    async def slow(target=None):
        await asyncio.sleep(0.05)
        return "ok"

    wrapped = sc.cached_builder("timed", slow, ttl=5.0)
    await wrapped()
    s = sc.stats()["timed"]
    assert s["avg_ms"] >= 40  # 50ms sleep minus wiggle


@pytest.mark.asyncio
async def test_cached_builder_shares_key_for_none_and_empty_target():
    """EDGE: target=None and target='' share the same cache key.

    This guards against accidental cache-key divergence when callers don't
    normalize target=None before passing through. The cache returns None on
    miss, so builders that return None ARE rebuilt — but surface builders
    always return a dict, so this is not a real-world concern.
    """
    calls = {"n": 0}

    async def fn(target=None):
        calls["n"] += 1
        return {"target": target or "default"}  # never returns None

    wrapped = sc.cached_builder("s", fn)
    await wrapped(None)
    await wrapped("")

    assert calls["n"] == 1


# ═══════════════════════════════════════════════════════════════
# stats shape
# ═══════════════════════════════════════════════════════════════


def test_stats_empty_when_nothing_built():
    assert sc.stats() == {}


@pytest.mark.asyncio
async def test_stats_shape_has_required_keys():
    async def fn(target=None):
        return "x"

    await sc.cached_builder("s", fn)()
    s = sc.stats()["s"]
    for key in ("hits", "misses", "builds", "avg_ms", "last_built_at"):
        assert key in s


# ═══════════════════════════════════════════════════════════════
# reset — test-helper invariant
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_reset_clears_cache_and_stats():
    async def fn(target=None):
        return "x"

    await sc.cached_builder("s", fn)()
    assert sc.stats() != {}
    sc.reset()
    assert sc.stats() == {}
    assert sc.get("s:") is None


# ═══════════════════════════════════════════════════════════════
# /page/docs surface
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_docs_surface_lists_every_registered_surface():
    class FakeSB:
        async def __call__(self, *a, **kw):
            return []

    import surfaces

    surfaces.init(
        pg_request_fn=FakeSB(),
        members_dict={},
        federation_dict={},
        knowledge_cache={},
        agent_id="x",
        agent_name="X",
        get_think_count=lambda: 0,
    )
    result = await surfaces.build_docs_surface()
    components = result["updateComponents"]["components"]
    tables = [c for c in components if c.get("component") == "Table"]
    assert len(tables) >= 3  # surfaces / endpoints / modules

    surface_table = next(t for t in tables if "Surface" in t.get("headers", []))
    # Every registered surface appears as a row.
    registered_count = len(surfaces.SURFACE_BUILDERS)
    assert len(surface_table["rows"]) == registered_count


@pytest.mark.asyncio
async def test_docs_surface_emits_v09():
    class FakeSB:
        async def __call__(self, *a, **kw):
            return []

    import surfaces

    surfaces.init(
        pg_request_fn=FakeSB(),
        members_dict={},
        federation_dict={},
        knowledge_cache={},
        agent_id="x",
        agent_name="X",
        get_think_count=lambda: 0,
    )
    result = await surfaces.build_docs_surface()
    assert result.get("version") == "0.10"
    assert "updateComponents" in result


@pytest.mark.asyncio
async def test_docs_surface_shows_cache_stats_when_present():
    """HAPPY: after building a cached surface, /page/docs reflects it."""

    async def fn(target=None):
        return "x"

    await sc.cached_builder("skills", fn)()

    class FakeSB:
        async def __call__(self, *a, **kw):
            return []

    import surfaces

    surfaces.init(
        pg_request_fn=FakeSB(),
        members_dict={},
        federation_dict={},
        knowledge_cache={},
        agent_id="x",
        agent_name="X",
        get_think_count=lambda: 0,
    )
    result = await surfaces.build_docs_surface()
    components = result["updateComponents"]["components"]
    surface_table = next(t for t in components if t.get("component") == "Table" and "Surface" in t.get("headers", []))
    # Every row is [surface, summary, hits, builds, avg]. The 'skills' row
    # should show builds >= 1 after our test call.
    skills_row = next(r for r in surface_table["rows"] if r[0] == "/page/skills")
    assert skills_row[3] == "1"  # builds
