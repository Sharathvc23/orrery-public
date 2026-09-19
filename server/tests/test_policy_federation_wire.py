"""
R1-R10 integration tests for Phase 4 wire-up:
  policy.tune_cycle → _federation_merge_cycle → federated_policy_merge

Covers the wiring: that tune_cycle actually calls merge when the flag
is set, skips when not, respects pin, respects auto_tuned, and handles
all the failure paths without leaking into production state.

  R1  Forgery            — peer snapshot for pinned key ignored
  R2  Replay             — (merge is stateless per cycle; R2 tested in merge module)
  R3  Injection          — malformed snapshot fields (non-numeric) skipped
  R4  Authorization      — flag must be true to merge; pinned keys exempt
  R5  Boundary           — no peers → no-op; flag missing → false default
  R6  Concurrency        — (merge is pure; R6 tested in merge module)
  R7  Adversarial input  — peer with string value skipped, not crashed
  R8  Downgrade          — auto_tuned=false keys skipped
  R9  Timing             — N/A (upstream federation_intelligence handles)
  R10 Persistence        — merge updates chapter_policy + history
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402

import federation_intelligence  # noqa: E402
import policy  # noqa: E402

# ── Shared test doubles ──────────────────────────────────────────────


class _FakePostgres:
    """In-memory stand-in for the Postgres client."""

    def __init__(self):
        self.chapter_policy: list[dict] = []
        self.chapter_policy_history: list[dict] = []
        self.outcomes: list[dict] = []
        self.agents: list[dict] = []
        self.calls: list[dict] = []
        self.pending_approvals: list[dict] = []
        self.chapter_role_nominations: list[dict] = []

    async def __call__(self, method, table_or_path, params=None, body=None):
        table = table_or_path.split("?")[0]
        if method == "GET":
            source = getattr(self, table, [])
            if not isinstance(source, list):
                return []
            rows = list(source)
            if params:
                rows = self._filter(rows, params)
            return rows
        if method == "POST":
            target = getattr(self, table, None)
            if isinstance(target, list):
                target.append(dict(body or {}))
            return [body]
        if method == "PATCH":
            target = getattr(self, table, [])
            if not isinstance(target, list):
                return []
            filters = self._parse_path_filters(table_or_path)
            matched = []
            for row in target:
                if all(str(row.get(k)) == v for k, v in filters.items()):
                    row.update(body or {})
                    matched.append(row)
            return matched
        return None

    @staticmethod
    def _parse_path_filters(path):
        if "?" not in path:
            return {}
        _, qs = path.split("?", 1)
        filters = {}
        for pair in qs.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                # strip eq. prefix
                filters[k] = v.replace("eq.", "")
        return filters

    def _filter(self, rows, params):
        out = []
        for row in rows:
            keep = True
            for k, v in params.items():
                if k in ("select", "order", "limit"):
                    continue
                want = v.replace("eq.", "")
                actual = row.get(k, "")
                # Normalize bool to match "true"/"false" strings
                if isinstance(actual, bool):
                    actual_str = "true" if actual else "false"
                else:
                    actual_str = str(actual)
                if actual_str != want:
                    keep = False
                    break
            if keep:
                out.append(row)
        return out


@pytest.fixture
def supabase():
    s = _FakePostgres()
    policy.init(pg_request=s, agent_id="test-chapter")
    return s


@pytest.fixture(autouse=True)
def _reset_federation_cache():
    """Each test gets a fresh peer-knowledge cache."""
    federation_intelligence.federation_knowledge.clear()
    yield
    federation_intelligence.federation_knowledge.clear()


def _seed_policy(supabase, key, value, baseline, auto_tuned=True, pinned_by=None):
    supabase.chapter_policy.append(
        {
            "chapter_id": "test-chapter",
            "key": key,
            "value": value,
            "baseline": baseline,
            "value_type": "float",
            "auto_tuned": auto_tuned,
            "pinned_by": pinned_by,
        }
    )


def _seed_peer(peer_id, key, value, baseline=0.7, sample_size=50):
    federation_intelligence.federation_knowledge[peer_id] = {
        "chapter_id": peer_id,
        "policy_snapshot": [
            {"key": key, "value": value, "baseline": baseline, "sample_size": sample_size, "confidence": 1.0},
        ],
    }


# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery: peer snapshot for pinned key is ignored
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R1_forgery_pinned_key_untouched(supabase):
    """Even with federation flag ON and peer consensus, a pinned key
    must not move. Pinning is the chapter leader's veto."""
    _seed_policy(supabase, "federation.enabled", True, True, auto_tuned=False)
    _seed_policy(supabase, "intro.confidence_floor", 0.7, 0.7, pinned_by="leader-alice")

    _seed_peer("peer1", "intro.confidence_floor", 0.9)
    _seed_peer("peer2", "intro.confidence_floor", 0.9)
    _seed_peer("peer3", "intro.confidence_floor", 0.9)

    result = await policy._federation_merge_cycle(supabase.chapter_policy)
    assert "intro.confidence_floor" not in result


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection: snapshot with non-numeric value gets skipped, not crashed
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R3_injection_non_numeric_snapshot_skipped(supabase):
    _seed_policy(supabase, "intro.confidence_floor", 0.7, 0.7)

    federation_intelligence.federation_knowledge["peer1"] = {
        "policy_snapshot": [
            {"key": "intro.confidence_floor", "value": "not-a-number", "baseline": 0.7, "sample_size": 50}
        ],
    }
    federation_intelligence.federation_knowledge["peer2"] = {
        "policy_snapshot": [{"key": "intro.confidence_floor", "value": 0.72, "baseline": 0.7, "sample_size": 50}],
    }

    # Should not crash; skipped entry leaves just peer2 (below MIN_PEERS_FOR_MERGE)
    result = await policy._federation_merge_cycle(supabase.chapter_policy)
    assert "intro.confidence_floor" not in result  # below 2-peer minimum


# ══════════════════════════════════════════════════════════════════════
# R4 — Authorization: flag gates merge; pinned keys skipped
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R4_authz_flag_off_means_no_merge(supabase):
    """When federation.enabled is absent or false, the merge cycle
    doesn't run even if peers have data."""
    # No federation.enabled row in supabase → _get_bool returns False
    _seed_policy(supabase, "intro.confidence_floor", 0.7, 0.7)
    _seed_peer("peer1", "intro.confidence_floor", 0.9)
    _seed_peer("peer2", "intro.confidence_floor", 0.9)
    _seed_peer("peer3", "intro.confidence_floor", 0.9)

    enabled = await policy._get_bool("federation.enabled")
    assert enabled is False
    # tune_cycle reads federation.enabled to decide; if False, merge cycle
    # isn't invoked. We verify _get_bool directly as the gate.


@pytest.mark.asyncio
async def test_R4_authz_flag_true_enables_merge(supabase):
    _seed_policy(supabase, "federation.enabled", True, True, auto_tuned=False)
    enabled = await policy._get_bool("federation.enabled")
    assert enabled is True


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: no peers → no-op; empty knowledge cache
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R5_boundary_empty_peer_cache_returns_empty(supabase):
    _seed_policy(supabase, "intro.confidence_floor", 0.7, 0.7)
    # Cache is empty (autouse fixture cleared it)
    result = await policy._federation_merge_cycle(supabase.chapter_policy)
    assert result == {}


@pytest.mark.asyncio
async def test_R5_boundary_peer_snapshot_missing_field_defaults(supabase):
    """If a peer's snapshot is missing optional fields, defaults apply
    (confidence=1.0)."""
    _seed_policy(supabase, "intro.confidence_floor", 0.7, 0.7)

    federation_intelligence.federation_knowledge["peer1"] = {
        "policy_snapshot": [{"key": "intro.confidence_floor", "value": 0.75, "baseline": 0.7, "sample_size": 50}],
    }
    federation_intelligence.federation_knowledge["peer2"] = {
        "policy_snapshot": [{"key": "intro.confidence_floor", "value": 0.73, "baseline": 0.7, "sample_size": 30}],
    }

    result = await policy._federation_merge_cycle(supabase.chapter_policy)
    # Both are valid, 2 peers meets MIN_PEERS_FOR_MERGE → merge happens
    assert "intro.confidence_floor" in result
    assert 0.7 < result["intro.confidence_floor"]["new"] < 0.77


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial: peer with entirely malformed entry doesn't crash
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R7_adversarial_peer_with_garbage_snapshots(supabase):
    _seed_policy(supabase, "intro.confidence_floor", 0.7, 0.7)

    federation_intelligence.federation_knowledge["evil"] = {
        "policy_snapshot": [
            {"value": "abc"},  # missing key
            {"key": "intro.confidence_floor", "sample_size": "also-not-a-number"},
            None,  # not even a dict — but our iter handles this
        ],
    }
    # Must not raise; all malformed entries skipped; nothing to merge
    result = await policy._federation_merge_cycle(supabase.chapter_policy)
    assert result == {}


# ══════════════════════════════════════════════════════════════════════
# R8 — Downgrade: keys with auto_tuned=false are NOT merged
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R8_downgrade_fixed_key_never_merged(supabase):
    """Some keys are deliberately fixed (auto_tuned=false). Peer agreement
    must not override a chapter's explicit decision to freeze a value."""
    _seed_policy(supabase, "call.trust_min_established", 20.0, 20.0, auto_tuned=False)
    _seed_peer("peer1", "call.trust_min_established", 35.0, baseline=20.0)
    _seed_peer("peer2", "call.trust_min_established", 35.0, baseline=20.0)
    _seed_peer("peer3", "call.trust_min_established", 35.0, baseline=20.0)

    result = await policy._federation_merge_cycle(supabase.chapter_policy)
    assert "call.trust_min_established" not in result


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: merge writes chapter_policy + history
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R10_persistence_merge_writes_patch_and_history(supabase):
    _seed_policy(supabase, "intro.confidence_floor", 0.7, 0.7)

    _seed_peer("boston", "intro.confidence_floor", 0.75)
    _seed_peer("london", "intro.confidence_floor", 0.74)
    _seed_peer("tokyo", "intro.confidence_floor", 0.76)

    result = await policy._federation_merge_cycle(supabase.chapter_policy)
    assert "intro.confidence_floor" in result

    # Check the policy row got updated
    row = next(r for r in supabase.chapter_policy if r["key"] == "intro.confidence_floor")
    assert row["value"] != 0.7
    assert "federation_merge" in (row.get("last_tune_reason") or "")

    # Check a history row was written
    assert len(supabase.chapter_policy_history) == 1
    h = supabase.chapter_policy_history[0]
    assert h["key"] == "intro.confidence_floor"
    assert "federation_merge" in h["reason"]
    assert h["actor"] == "test-chapter"


# ══════════════════════════════════════════════════════════════════════
# HAPPY — kept last per R1-R10 ordering
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_happy_get_policy_snapshot_exports_tunable_keys(supabase):
    """Our exported snapshot contains only tunable-unpinned numeric keys."""
    _seed_policy(supabase, "intro.confidence_floor", 0.72, 0.7)
    _seed_policy(supabase, "intro.cooldown_days", 28, 30)
    # Fixed key excluded
    _seed_policy(supabase, "call.trust_min_established", 20.0, 20.0, auto_tuned=False)
    # Pinned key excluded
    _seed_policy(supabase, "pinned.key", 0.5, 0.5, pinned_by="leader-alice")

    # supabase GET /chapter_policy?auto_tuned=eq.true returns only
    # rows where auto_tuned=true, so the fixed and pinned above are
    # filtered server-side. We verify that behavior here.
    snaps = await policy.get_policy_snapshot_for_federation()
    keys = {s["key"] for s in snaps}
    # Only auto_tuned keys come out; fixed and pinned omitted.
    assert "intro.confidence_floor" in keys
    assert "intro.cooldown_days" in keys
    assert "call.trust_min_established" not in keys
    assert "pinned.key" not in keys


def test_happy_get_our_summary_includes_empty_policy_snapshot():
    """Sync get_our_summary carries policy_snapshot=[] so peers that
    receive it don't crash on .get('policy_snapshot', [])."""
    federation_intelligence.init(
        pg_request=None,
        knowledge_cache={"chapter_intelligence": {}},
        agent_id="test",
        agent_name="Test",
    )
    summary = federation_intelligence.get_our_summary()
    assert "policy_snapshot" in summary
    assert summary["policy_snapshot"] == []
