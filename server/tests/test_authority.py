"""
Tests for authority.py — agent authority scope + rate limits + constraints.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

import authority


class _FakePostgres:
    def __init__(self):
        self.tables: dict[str, list[dict]] = {
            "agent_authority_scope": [],
            "agent_authority_usage": [],
        }

    async def __call__(self, method, table_or_path, params=None, body=None):
        table = table_or_path.split("?")[0]
        if method == "GET":
            rows = list(self.tables.get(table, []))
            if params:
                rows = self._filter(rows, params)
            return rows
        if method == "POST":
            body = dict(body or {})
            body.setdefault("id", f"id-{len(self.tables[table]) + 1}")
            body.setdefault("created_at", datetime.now(UTC).isoformat())
            self.tables.setdefault(table, []).append(body)
            return [body]
        if method == "PATCH":
            filters = self._parse_path_filters(table_or_path)
            matched = []
            for row in self.tables.get(table, []):
                if all(self._match(row, k, v) for k, v in filters.items()):
                    row.update(body or {})
                    matched.append(row)
            return matched
        return None

    @staticmethod
    def _parse_path_filters(path):
        if "?" not in path:
            return {}
        _, qs = path.split("?", 1)
        return dict(pair.split("=", 1) for pair in qs.split("&"))

    def _filter(self, rows, params):
        out = list(rows)
        for k, v in (params or {}).items():
            if k in ("select", "order", "limit"):
                continue
            out = [r for r in out if self._match(r, k, v)]
        return out

    @staticmethod
    def _match(row, key, predicate):
        if "." not in predicate:
            return row.get(key) == predicate
        op, val = predicate.split(".", 1)
        rv = row.get(key)
        if op == "eq":
            if val == "true":
                return rv is True
            if val == "false":
                return rv is False
            return str(rv) == val
        return True


@pytest.fixture
def env():
    sb = _FakePostgres()
    authority.init(pg_request=sb, agent_id="test-chapter")
    return sb


def _seed_scope(env, agent_id, action_kind, allowed=True, constraints=None):
    env.tables["agent_authority_scope"].append(
        {
            "agent_id": agent_id,
            "action_kind": action_kind,
            "allowed": allowed,
            "constraints": constraints or {},
        }
    )


def _seed_usage(env, agent_id, action_kind, window_kind, count, window_start=None):
    ws = window_start or authority._window_start(window_kind).isoformat()
    env.tables["agent_authority_usage"].append(
        {
            "id": f"u-{len(env.tables['agent_authority_usage']) + 1}",
            "agent_id": agent_id,
            "action_kind": action_kind,
            "window_kind": window_kind,
            "window_start": ws,
            "count": count,
        }
    )


# ═══════════════════════════════════════════════
# PURE CONSTRAINT EVAL
# ═══════════════════════════════════════════════


def test_check_constraints_empty_constraints_always_allows():
    ok, reason = authority.check_constraints("submit_intent", {}, {}, {})
    assert ok
    assert reason == "ok"


def test_check_constraints_under_rate_limit_allowed():
    ok, _ = authority.check_constraints("submit_intent", {"max_per_week": 3}, {}, {"per_week": 2})
    assert ok


def test_check_constraints_at_rate_limit_denied():
    """C5 boundary: used=cap already denies."""
    ok, reason = authority.check_constraints("submit_intent", {"max_per_week": 3}, {}, {"per_week": 3})
    assert not ok
    assert "rate_limit" in reason


def test_check_constraints_daily_rate_limit():
    ok, reason = authority.check_constraints("submit_call", {"max_per_day": 2}, {}, {"per_day": 2})
    assert not ok
    assert "per day" in reason


def test_check_rsvp_type_constraint_allows_configured():
    ok, _ = authority.check_constraints(
        "rsvp_event",
        {"types": ["virtual", "in_person"]},
        {"type": "virtual"},
    )
    assert ok


def test_check_rsvp_type_denies_unlisted():
    """ADVERSARIAL: trying to RSVP a type not in allowlist."""
    ok, reason = authority.check_constraints(
        "rsvp_event",
        {"types": ["virtual"]},
        {"type": "in_person"},
    )
    assert not ok
    assert "in_person" in reason


def test_check_meeting_duration_constraint():
    ok, _ = authority.check_constraints(
        "accept_meeting",
        {"duration_max_min": 30},
        {"duration_min": 20},
    )
    assert ok


def test_check_meeting_duration_denies_overlong():
    ok, reason = authority.check_constraints(
        "accept_meeting",
        {"duration_max_min": 30},
        {"duration_min": 60},
    )
    assert not ok
    assert "duration" in reason


def test_check_meeting_hours_constraint_allows_inside():
    ok, _ = authority.check_constraints(
        "accept_meeting",
        {"hours": "09:00-18:00"},
        {"hour": 14},
    )
    assert ok


def test_check_meeting_hours_denies_outside():
    ok, reason = authority.check_constraints(
        "accept_meeting",
        {"hours": "09:00-18:00"},
        {"hour": 22},
    )
    assert not ok
    assert "outside" in reason


def test_check_meeting_hours_boundary_exact_start_allowed():
    """C5 boundary: hour == start_hour → allowed."""
    ok, _ = authority.check_constraints(
        "accept_meeting",
        {"hours": "09:00-18:00"},
        {"hour": 9},
    )
    assert ok


def test_check_meeting_hours_boundary_exact_end_denied():
    """C5 boundary: hour == end_hour → denied (exclusive)."""
    ok, reason = authority.check_constraints(
        "accept_meeting",
        {"hours": "09:00-18:00"},
        {"hour": 18},
    )
    assert not ok


def test_check_meeting_malformed_hours_ignored():
    """EDGE: malformed constraint doesn't crash, just skips that check."""
    ok, _ = authority.check_constraints(
        "accept_meeting",
        {"hours": "gibberish"},
        {"hour": 14},
    )
    assert ok


# ═══════════════════════════════════════════════
# WINDOW START MATH
# ═══════════════════════════════════════════════


def test_window_start_day_zeros_time():
    now = datetime(2026, 4, 18, 13, 45, 30, tzinfo=UTC)
    ws = authority._window_start("day", now=now)
    assert ws.year == 2026 and ws.month == 4 and ws.day == 18
    assert ws.hour == 0 and ws.minute == 0


def test_window_start_week_uses_monday():
    """HAPPY: Friday Apr 18, 2025 → Monday Apr 14."""
    fri = datetime(2025, 4, 18, 15, 0, tzinfo=UTC)
    ws = authority._window_start("week", now=fri)
    assert ws.day == 14
    assert ws.weekday() == 0  # Monday


def test_window_start_week_from_monday_same_day():
    """EDGE: called on Monday → returns same Monday at midnight."""
    mon = datetime(2026, 4, 20, 10, 0, tzinfo=UTC)  # Monday
    ws = authority._window_start("week", now=mon)
    assert ws.day == 20
    assert ws.hour == 0


# ═══════════════════════════════════════════════
# TOOL MAP
# ═══════════════════════════════════════════════


def test_tool_action_map_covers_core_tools():
    """Every action_kind declared in the schema has a tool entry or a
    direct test in VALID_ACTIONS (server-only, not exposed to tool layer)."""
    declared = {
        "submit_intent",
        "respond_to_intent",
        "submit_call",
        "respond_to_call",
        "update_projection",
        "save_private_note",
        "start_conversation",
        "rsvp_event",
        "accept_meeting",
    }
    assert declared.issubset(set(authority.TOOL_ACTION_MAP.values()))


def test_save_note_aliases_to_save_private_note():
    """EDGE: community-member uses 'save_note' locally; it maps to save_private_note."""
    assert authority.TOOL_ACTION_MAP["save_note"] == "save_private_note"


# ═══════════════════════════════════════════════
# INTEGRATED CHECK_AUTHORITY
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_check_authority_unknown_action(env):
    """ADVERSARIAL: unknown action_kind rejected without DB round-trip."""
    result = await authority.check_authority("alice", "delete_chapter")
    assert not result["allowed"]
    assert result["reason"] == "unknown_action"


@pytest.mark.asyncio
async def test_check_authority_no_scope_denies(env):
    """HAPPY default: agent with no scope row → deny (safety default)."""
    result = await authority.check_authority("stranger", "submit_intent")
    assert not result["allowed"]
    assert result["reason"] == "no_scope_configured"


@pytest.mark.asyncio
async def test_check_authority_allowed_no_constraints(env):
    _seed_scope(env, "alice", "update_projection", allowed=True)
    result = await authority.check_authority("alice", "update_projection")
    assert result["allowed"]


@pytest.mark.asyncio
async def test_check_authority_opt_in_action_denies(env):
    _seed_scope(env, "alice", "cross_chapter_message", allowed=False)
    result = await authority.check_authority("alice", "cross_chapter_message")
    assert not result["allowed"]
    assert result["reason"] == "action_not_allowed"
    assert result["opt_in_required"] is True


@pytest.mark.asyncio
async def test_check_authority_under_weekly_limit(env):
    _seed_scope(env, "alice", "submit_intent", allowed=True, constraints={"max_per_week": 3})
    _seed_usage(env, "alice", "submit_intent", "week", 1)
    result = await authority.check_authority("alice", "submit_intent")
    assert result["allowed"]
    assert result["quota"]["per_week"]["used"] == 1
    assert result["quota"]["per_week"]["cap"] == 3


@pytest.mark.asyncio
async def test_check_authority_at_weekly_limit_denied(env):
    _seed_scope(env, "alice", "submit_intent", allowed=True, constraints={"max_per_week": 3})
    _seed_usage(env, "alice", "submit_intent", "week", 3)
    result = await authority.check_authority("alice", "submit_intent")
    assert not result["allowed"]
    assert "rate_limit" in result["reason"]


# ═══════════════════════════════════════════════
# That change — usage lookup fails CLOSED (no quota bypass on a DB error)
# ═══════════════════════════════════════════════


class _UsageReadFailsPostgres(_FakePostgres):
    """Reads of agent_authority_scope succeed; reads of agent_authority_usage raise
    (a transient DB error on that table) — the exact split that produced the quota bypass: primary gate passes, usage read fails."""

    async def __call__(self, method, table_or_path, params=None, body=None):
        if method == "GET" and table_or_path.split("?")[0] == "agent_authority_usage":
            raise RuntimeError("simulated DB error reading usage")
        return await super().__call__(method, table_or_path, params, body)


@pytest.mark.asyncio
async def test_usage_count_raises_on_db_error():
    sb = _UsageReadFailsPostgres()
    authority.init(pg_request=sb, agent_id="test-chapter")
    with pytest.raises(authority.UsageLookupError):
        await authority._usage_count("alice", "submit_intent", "week")


@pytest.mark.asyncio
async def test_usage_count_raises_when_no_db():
    authority.init(pg_request=None, agent_id="test-chapter")
    with pytest.raises(authority.UsageLookupError):
        await authority._usage_count("alice", "submit_intent", "week")


@pytest.mark.asyncio
async def test_usage_count_zero_on_empty_window(env):
    """A SUCCESSFUL query with no row is a real 0 (window genuinely unused) — the
    fail-closed change must not turn a legit empty window into a deny."""
    assert await authority._usage_count("alice", "submit_intent", "week") == 0


@pytest.mark.asyncio
async def test_check_authority_fails_closed_when_usage_unreadable():
    """The regression: a rate-capped, ALLOWED action must be DENIED when the usage
    count can't be read — never allowed via a silent used=0 (quota bypass)."""
    sb = _UsageReadFailsPostgres()
    authority.init(pg_request=sb, agent_id="test-chapter")
    _seed_scope(sb, "alice", "submit_intent", allowed=True, constraints={"max_per_week": 3})

    result = await authority.check_authority("alice", "submit_intent")

    assert result["allowed"] is False, "usage-read failure must fail CLOSED, not allow"
    assert result["reason"] == "quota_check_failed"


@pytest.mark.asyncio
async def test_check_authority_rsvp_type_filtered(env):
    _seed_scope(
        env,
        "alice",
        "rsvp_event",
        allowed=True,
        constraints={"types": ["virtual"]},
    )
    denied = await authority.check_authority(
        "alice",
        "rsvp_event",
        context={"type": "in_person"},
    )
    assert not denied["allowed"]
    allowed = await authority.check_authority(
        "alice",
        "rsvp_event",
        context={"type": "virtual"},
    )
    assert allowed["allowed"]


# ═══════════════════════════════════════════════
# USAGE RECORDING
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_record_usage_creates_row(env):
    _seed_scope(env, "alice", "submit_call", allowed=True, constraints={"max_per_day": 2})
    await authority.record_usage("alice", "submit_call")
    rows = env.tables["agent_authority_usage"]
    assert len(rows) == 1
    assert rows[0]["count"] == 1


@pytest.mark.asyncio
async def test_record_usage_increments_existing(env):
    _seed_scope(env, "alice", "submit_call", allowed=True, constraints={"max_per_day": 2})
    await authority.record_usage("alice", "submit_call")
    await authority.record_usage("alice", "submit_call")
    rows = env.tables["agent_authority_usage"]
    # Single row, count = 2 (same window)
    assert len(rows) == 1
    assert rows[0]["count"] == 2


@pytest.mark.asyncio
async def test_record_usage_skips_unconstrained_action(env):
    """EDGE: action with no rate constraints → no usage rows written."""
    _seed_scope(env, "alice", "update_projection", allowed=True, constraints={})
    await authority.record_usage("alice", "update_projection")
    assert env.tables["agent_authority_usage"] == []


@pytest.mark.asyncio
async def test_end_to_end_rate_enforcement(env):
    """C5 lifecycle: allow → use → use → now denied."""
    _seed_scope(env, "alice", "submit_call", allowed=True, constraints={"max_per_day": 2})

    r1 = await authority.check_authority("alice", "submit_call")
    assert r1["allowed"]
    await authority.record_usage("alice", "submit_call")

    r2 = await authority.check_authority("alice", "submit_call")
    assert r2["allowed"]  # used=1 < cap=2
    await authority.record_usage("alice", "submit_call")

    r3 = await authority.check_authority("alice", "submit_call")
    assert not r3["allowed"]  # used=2, cap=2 → blocked
    assert "rate_limit" in r3["reason"]


# ═══════════════════════════════════════════════
# SET SCOPE (self-serve + admin)
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_set_scope_new_row(env):
    result = await authority.set_scope(
        "alice",
        "publish_public_note",
        allowed=True,
        updated_by="self",
    )
    assert result["ok"]


@pytest.mark.asyncio
async def test_set_scope_updates_existing(env):
    _seed_scope(env, "alice", "submit_call", allowed=True, constraints={"max_per_day": 2})
    result = await authority.set_scope(
        "alice",
        "submit_call",
        allowed=True,
        constraints={"max_per_day": 10},
        updated_by="admin-1",
    )
    assert result["ok"]
    assert env.tables["agent_authority_scope"][0]["constraints"]["max_per_day"] == 10


@pytest.mark.asyncio
async def test_set_scope_unknown_action_rejected(env):
    result = await authority.set_scope("alice", "delete_chapter", allowed=True)
    assert result["error"] == "unknown_action"


@pytest.mark.asyncio
async def test_list_scope_for_returns_all_actions(env):
    _seed_scope(env, "alice", "submit_intent", allowed=True)
    _seed_scope(env, "alice", "submit_call", allowed=True)
    rows = await authority.list_scope_for("alice")
    assert len(rows) == 2
