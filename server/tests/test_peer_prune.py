"""dead federation peers can be forgotten — explicitly (leader forget)
and automatically (heartbeat prune) — so a zombie peer stops haunting
/health federation_state forever.

Classification: HAPPY / EDGE / ADVERSARIAL.
"""

from datetime import UTC, datetime, timedelta

import pytest

import federation_policy as fp

NOW = datetime.now(UTC)
STALE = (NOW - timedelta(days=5)).isoformat()   # acme's real situation
FRESH = (NOW - timedelta(hours=1)).isoformat()
PRUNE_AFTER_S = 72 * 3600


class _FakePostgres:
    """GET/POST/PATCH/DELETE over in-memory tables, params-filter aware."""

    def __init__(self):
        self.tables: dict[str, list[dict]] = {
            "federation_policy": [],
            "federation_policy_history": [],
        }

    async def __call__(self, method, table, params=None, body=None):
        rows = self.tables.setdefault(table, [])
        if method == "GET":
            return [r for r in rows if self._match(r, params)]
        if method == "POST":
            body = dict(body or {})
            body.setdefault("created_at", NOW.isoformat())
            rows.append(body)
            return [body]
        if method == "PATCH":
            hit = [r for r in rows if self._match(r, params)]
            for r in hit:
                r.update(body or {})
            return hit
        if method == "DELETE":
            keep = [r for r in rows if not self._match(r, params)]
            deleted = len(rows) - len(keep)
            self.tables[table] = keep
            return [{"deleted": deleted}]
        raise AssertionError(f"unexpected method {method}")

    @staticmethod
    def _match(row, params):
        for k, v in (params or {}).items():
            if k in ("order", "select", "limit"):
                continue
            want = v[3:] if isinstance(v, str) and v.startswith("eq.") else v
            if str(row.get(k)) != str(want):
                return False
        return True


@pytest.fixture
def env():
    sb = _FakePostgres()
    fp.init(pg_request=sb, agent_id="test-chapter")
    return sb


def _seed(env, peer, *, state="degraded", last_success=STALE, endpoint=""):
    env.tables["federation_policy"].append(
        {
            "chapter_id": "test-chapter",
            "peer_chapter_id": peer,
            "peer_endpoint": endpoint or f"https://{peer}.example",
            "state": state,
            "consecutive_failures": 2,
            "backoff_seconds": 1440,
            "blocked_by": "leader-1" if state == "blocked" else None,
            "last_success_at": last_success,
            "updated_at": last_success,
        }
    )


# ── forget_peer (the leader action) ──────────────────────────────────────


@pytest.mark.asyncio
async def test_forget_deletes_the_row_and_logs_history(env):
    _seed(env, "acme")
    result = await fp.forget_peer("acme", "leader-1", reason="dead legacy peer")
    assert result["ok"] and result["previous_state"] == "degraded"
    assert env.tables["federation_policy"] == []  # gone from every surface
    hist = env.tables["federation_policy_history"]
    assert any(h.get("event") == "forget" for h in hist), hist  # audit stays


@pytest.mark.asyncio
async def test_forget_unknown_peer_is_not_found(env):
    assert (await fp.forget_peer("ghost", "leader-1"))["error"] == "not_found"


@pytest.mark.asyncio
async def test_forgotten_peer_disappears_from_list_policies(env):
    """The /health federation_state source: list_policies must not carry it."""
    _seed(env, "acme")
    _seed(env, "regentix", state="online", last_success=FRESH)
    await fp.forget_peer("acme", "leader-1")
    peers = [p["peer_chapter_id"] for p in await fp.list_policies()]
    assert peers == ["regentix"]


# ── prune_stale_peers (the heartbeat sweep) ──────────────────────────────


@pytest.mark.asyncio
async def test_stale_unanchored_dead_peer_is_pruned(env):
    """HAPPY (the acme case): degraded 5 days, not in KNOWN_CHAPTER_ENDPOINTS,
    not live → pruned."""
    _seed(env, "acme")
    pruned = await fp.prune_stale_peers([], set(), PRUNE_AFTER_S)
    assert pruned == ["acme"]
    assert env.tables["federation_policy"] == []


@pytest.mark.asyncio
async def test_anchored_peer_never_auto_pruned(env):
    """EDGE: the operator anchor is authoritative — even a long-dead anchored
    peer stays (the operator removes it from the env, not the sweeper)."""
    _seed(env, "acme", endpoint="https://acme.example")
    pruned = await fp.prune_stale_peers(["https://acme.example/"], set(), PRUNE_AFTER_S)
    assert pruned == []
    assert len(env.tables["federation_policy"]) == 1


@pytest.mark.asyncio
async def test_live_peer_never_pruned_even_if_row_looks_stale(env):
    _seed(env, "regentix")
    assert await fp.prune_stale_peers([], {"regentix"}, PRUNE_AFTER_S) == []


@pytest.mark.asyncio
async def test_blocked_peer_kept_as_deliberate_tombstone(env):
    """EDGE: block is a leader decision — the sweeper never undoes it."""
    _seed(env, "evil-peer", state="blocked")
    assert await fp.prune_stale_peers([], set(), PRUNE_AFTER_S) == []
    assert env.tables["federation_policy"][0]["state"] == "blocked"


@pytest.mark.asyncio
async def test_recently_failing_peer_not_pruned(env):
    """EDGE: a peer that succeeded an hour ago is failing, not dead."""
    _seed(env, "flaky", last_success=FRESH)
    assert await fp.prune_stale_peers([], set(), PRUNE_AFTER_S) == []


@pytest.mark.asyncio
async def test_zero_threshold_disables_pruning(env):
    _seed(env, "acme")
    assert await fp.prune_stale_peers([], set(), 0) == []
    assert len(env.tables["federation_policy"]) == 1


@pytest.mark.asyncio
async def test_undatable_row_left_for_explicit_forget(env):
    """ADVERSARIAL: a row with no parseable timestamps is never auto-deleted —
    silent data loss is worse than a lingering row the leader can forget."""
    env.tables["federation_policy"].append(
        {"chapter_id": "test-chapter", "peer_chapter_id": "mystery", "state": "degraded"}
    )
    assert await fp.prune_stale_peers([], set(), PRUNE_AFTER_S) == []
    assert len(env.tables["federation_policy"]) == 1


# ── the route (leader gate) + /health end-to-end ─────────────────────────
# Handler-level tests (the established idiom here — the signed-transport
# middleware has its own suite; these prove THIS handler's gate + effect).


class _FakeRequest:
    headers: dict = {}
    state = type("S", (), {})()


@pytest.fixture
def ca(env):
    import os
    import sys

    os.environ.setdefault("AGENT_ID", "test-chapter")
    return sys.modules.get("chapter_agent") or __import__("chapter_agent")


def _gate(monkeypatch, ca, caller="leader-1", is_leader=True):
    import governance

    monkeypatch.setattr(ca, "_resolve_caller", lambda request: caller)

    async def _can(actor):
        return is_leader

    monkeypatch.setattr(governance, "can_approve", _can)


@pytest.mark.asyncio
async def test_forget_route_unauthenticated_401(ca, monkeypatch):
    from fastapi import HTTPException

    monkeypatch.setattr(ca, "_resolve_caller", lambda request: "")
    with pytest.raises(HTTPException) as e:
        await ca.forget_peer_endpoint("acme", ca.PeerBlock(actor_agent_id="ignored", reason="x"), _FakeRequest())
    assert e.value.status_code == 401


@pytest.mark.asyncio
async def test_forget_route_non_leader_403(ca, monkeypatch, env):
    from fastapi import HTTPException

    _seed(env, "acme")
    _gate(monkeypatch, ca, caller="rando", is_leader=False)
    with pytest.raises(HTTPException) as e:
        await ca.forget_peer_endpoint("acme", ca.PeerBlock(actor_agent_id="ignored", reason="x"), _FakeRequest())
    assert e.value.status_code == 403
    assert len(env.tables["federation_policy"]) == 1  # untouched


@pytest.mark.asyncio
async def test_forget_route_leader_removes_peer_from_health(ca, monkeypatch, env):
    """THE THAT CHANGE done-when: after a leader forget, /health federation_state no
    longer carries the peer."""
    from fastapi.testclient import TestClient

    c = TestClient(ca.app)
    _seed(env, "acme")
    _seed(env, "regentix", state="online", last_success=FRESH)
    before = [p["peer"] for p in c.get("/health").json()["federation_state"]]
    assert "acme" in before
    _gate(monkeypatch, ca)
    result = await ca.forget_peer_endpoint("acme", ca.PeerBlock(actor_agent_id="ignored", reason="dead legacy peer"), _FakeRequest())
    assert result["forgotten"]
    after = [p["peer"] for p in c.get("/health").json()["federation_state"]]
    assert "acme" not in after and "regentix" in after


@pytest.mark.asyncio
async def test_forget_route_unknown_peer_404(ca, monkeypatch):
    from fastapi import HTTPException

    _gate(monkeypatch, ca)
    with pytest.raises(HTTPException) as e:
        await ca.forget_peer_endpoint("ghost", ca.PeerBlock(actor_agent_id="ignored", reason="x"), _FakeRequest())
    assert e.value.status_code == 404
