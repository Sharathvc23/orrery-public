"""Durable per-agent memory for unattended service agents (PR8).

The properties worth pinning are the ones that make this safe to hand four
unattended agents: an agent cannot reach a sibling's memory, memory cannot grow
without bound, and a cursor does not silently expire.

Backed by a fake `pg_request` — an in-memory table with the same filter
semantics the real one uses. That keeps the suite deterministic and, since the segfault investigation,
opens no real database connection.

Classification: HAPPY (round-trip) + ADVERSARIAL (scoping, bounds, expiry).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

import agent_memory_store as ams


class FakePg:
    """Minimal PostgREST-shaped store: eq./lt. filters, POST/PATCH/DELETE."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def _match(self, row: dict, params: dict) -> bool:
        for col, expr in (params or {}).items():
            if col in ("select", "order"):
                continue
            if expr.startswith("eq."):
                if str(row.get(col)) != expr[3:]:
                    return False
            elif expr.startswith("lt."):
                got = row.get(col)
                if not got or str(got) >= expr[3:]:
                    return False
        return True

    async def __call__(self, method, table, params=None, body=None):
        assert table == ams.TABLE
        if method == "GET":
            return [dict(r) for r in self.rows if self._match(r, params or {})]
        if method == "POST":
            self.rows.append(dict(body))
            return [dict(body)]
        if method == "PATCH":
            hit = [r for r in self.rows if self._match(r, params or {})]
            for r in hit:
                r.update(body or {})
            return hit
        if method == "DELETE":
            keep = [r for r in self.rows if not self._match(r, params or {})]
            removed = len(self.rows) - len(keep)
            self.rows = keep
            return [{"deleted": removed}]
        raise AssertionError(f"unexpected method {method}")


@pytest.fixture
def pg() -> FakePg:
    fake = FakePg()
    ams.init(fake, "spikeorg")
    return fake


class TestRoundTrip:
    @pytest.mark.asyncio
    async def test_remember_then_recall(self, pg: FakePg) -> None:
        await ams.remember("crm", "cursor", "inbox", {"last_id": 41})
        assert await ams.recall("crm", "cursor", "inbox") == {"last_id": 41}

    @pytest.mark.asyncio
    async def test_recall_missing_is_none_not_an_error(self, pg: FakePg) -> None:
        assert await ams.recall("crm", "cursor", "never-written") is None

    @pytest.mark.asyncio
    async def test_remembering_twice_updates_rather_than_duplicating(self, pg: FakePg) -> None:
        """An agent that accumulates duplicate cursors has no cursor."""
        await ams.remember("crm", "cursor", "inbox", {"last_id": 1})
        await ams.remember("crm", "cursor", "inbox", {"last_id": 99})
        assert await ams.recall("crm", "cursor", "inbox") == {"last_id": 99}
        assert len(pg.rows) == 1, f"upsert created {len(pg.rows)} rows"

    @pytest.mark.asyncio
    async def test_forget_is_idempotent(self, pg: FakePg) -> None:
        await ams.remember("crm", "note", "n", "x")
        await ams.forget("crm", "note", "n")
        await ams.forget("crm", "note", "n")  # must not raise
        assert await ams.recall("crm", "note", "n") is None


class TestAgentsCannotReachEachOther:
    """The structural half of 'memory is data, never instructions': an agent
    that can write a sibling's memory can steer it, because memory is replayed
    into future context."""

    @pytest.mark.asyncio
    async def test_same_key_under_two_agents_is_two_entries(self, pg: FakePg) -> None:
        await ams.remember("crm", "cursor", "inbox", {"who": "crm"})
        await ams.remember("comms", "cursor", "inbox", {"who": "comms"})
        assert await ams.recall("crm", "cursor", "inbox") == {"who": "crm"}
        assert await ams.recall("comms", "cursor", "inbox") == {"who": "comms"}

    @pytest.mark.asyncio
    async def test_recall_all_never_returns_a_siblings_rows(self, pg: FakePg) -> None:
        await ams.remember("crm", "note", "a", 1)
        await ams.remember("comms", "note", "b", 2)
        await ams.remember("research", "note", "c", 3)
        got = await ams.recall_all("crm")
        assert [r["memory_key"] for r in got] == ["a"]

    @pytest.mark.asyncio
    async def test_forget_agent_leaves_siblings_intact(self, pg: FakePg) -> None:
        await ams.remember("crm", "note", "a", 1)
        await ams.remember("comms", "note", "b", 2)
        await ams.forget_agent("crm")
        assert await ams.recall("crm", "note", "a") is None
        assert await ams.recall("comms", "note", "b") == 2

    @pytest.mark.asyncio
    async def test_an_empty_agent_id_is_refused_not_treated_as_shared(self, pg: FakePg) -> None:
        """A blank scope must not silently become a global one."""
        for call in (
            ams.remember("", "note", "k", 1),
            ams.recall("", "note", "k"),
            ams.recall_all(""),
            ams.forget("", "note", "k"),
            ams.forget_agent(""),
        ):
            with pytest.raises(ams.MemoryError_) as e:
                await call
            assert e.value.reason == "agent_id_required"


class TestExpiry:
    @pytest.mark.asyncio
    async def test_a_cursor_never_expires_by_default(self, pg: FakePg) -> None:
        """The considered departure from the chapter-side shape, which defaults
        to 7 days. A cursor that silently expires makes an agent reprocess or
        skip a window with no error anywhere."""
        await ams.remember("crm", "cursor", "inbox", {"last_id": 7})
        assert pg.rows[0]["expires_at"] is None
        assert await ams.recall("crm", "cursor", "inbox") == {"last_id": 7}

    @pytest.mark.asyncio
    async def test_a_dedup_key_expires_by_default(self, pg: FakePg) -> None:
        await ams.remember("crm", "dedup", "sent:42", True)
        assert pg.rows[0]["expires_at"] is not None

    @pytest.mark.asyncio
    async def test_an_expired_entry_reads_as_absent(self, pg: FakePg) -> None:
        await ams.remember("crm", "dedup", "old", True, ttl=timedelta(seconds=-1))
        assert await ams.recall("crm", "dedup", "old") is None
        assert await ams.recall("crm", "dedup", "old", include_expired=True) is True

    @pytest.mark.asyncio
    async def test_reading_an_expired_entry_does_not_delete_it(self, pg: FakePg) -> None:
        """A read path that mutates makes replica lag look like data loss."""
        await ams.remember("crm", "dedup", "old", True, ttl=timedelta(seconds=-1))
        await ams.recall("crm", "dedup", "old")
        assert len(pg.rows) == 1, "recall deleted a row"

    @pytest.mark.asyncio
    async def test_purge_is_the_only_thing_that_deletes_on_age(self, pg: FakePg) -> None:
        await ams.remember("crm", "dedup", "old", True, ttl=timedelta(seconds=-1))
        await ams.remember("crm", "cursor", "keep", 1)
        await ams.purge_expired()
        assert [r["memory_key"] for r in pg.rows] == ["keep"]

    @pytest.mark.asyncio
    async def test_recall_all_omits_expired(self, pg: FakePg) -> None:
        await ams.remember("crm", "cursor", "live", 1)
        await ams.remember("crm", "dedup", "dead", 1, ttl=timedelta(seconds=-1))
        assert [r["memory_key"] for r in await ams.recall_all("crm")] == ["live"]

    def test_an_unparseable_expiry_is_not_treated_as_expired(self) -> None:
        """Otherwise a driver changing its timestamp format silently deletes
        every cursor in the org."""
        assert ams._is_expired("not-a-timestamp") is False
        assert ams._is_expired(None) is False
        assert ams._is_expired("") is False

    def test_a_naive_timestamp_is_read_as_utc(self) -> None:
        past = (datetime.now(UTC) - timedelta(days=1)).replace(tzinfo=None).isoformat()
        assert ams._is_expired(past) is True


class TestBoundsAreEnforced:
    """Unbounded memory is a slow outage, not a feature."""

    @pytest.mark.asyncio
    async def test_oversized_value_is_refused(self, pg: FakePg) -> None:
        with pytest.raises(ams.MemoryError_) as e:
            await ams.remember("crm", "note", "big", "x" * (ams.MAX_VALUE_BYTES + 1))
        assert e.value.reason == "value_too_large"

    @pytest.mark.asyncio
    async def test_overlong_key_is_refused(self, pg: FakePg) -> None:
        with pytest.raises(ams.MemoryError_) as e:
            await ams.remember("crm", "note", "k" * (ams.MAX_KEY_CHARS + 1), 1)
        assert e.value.reason == "key_too_long"

    @pytest.mark.asyncio
    async def test_unserialisable_value_is_refused_before_the_database(self, pg: FakePg) -> None:
        with pytest.raises(ams.MemoryError_) as e:
            await ams.remember("crm", "note", "k", {1, 2, 3})  # a set is not JSON
        assert e.value.reason == "value_not_serialisable"
        assert pg.rows == [], "a rejected value still reached the store"

    @pytest.mark.asyncio
    async def test_unknown_memory_type_is_refused(self, pg: FakePg) -> None:
        with pytest.raises(ams.MemoryError_) as e:
            await ams.remember("crm", "embedding", "k", 1)
        assert e.value.reason == "unknown_memory_type"

    @pytest.mark.asyncio
    async def test_quota_stops_unbounded_growth(self, pg: FakePg, monkeypatch) -> None:
        monkeypatch.setattr(ams, "MAX_ENTRIES_PER_AGENT", 3)
        for i in range(3):
            await ams.remember("crm", "dedup", f"k{i}", True)
        with pytest.raises(ams.MemoryError_) as e:
            await ams.remember("crm", "dedup", "k3", True)
        assert e.value.reason == "quota_exceeded"

    @pytest.mark.asyncio
    async def test_quota_does_not_block_updating_an_existing_key(
        self, pg: FakePg, monkeypatch
    ) -> None:
        """At quota an agent must still be able to advance its cursor, or it
        wedges the moment it fills up."""
        monkeypatch.setattr(ams, "MAX_ENTRIES_PER_AGENT", 2)
        await ams.remember("crm", "cursor", "inbox", 1)
        await ams.remember("crm", "note", "n", 1)
        await ams.remember("crm", "cursor", "inbox", 2)  # must not raise
        assert await ams.recall("crm", "cursor", "inbox") == 2


class TestDeterminism:
    def test_no_llm_anywhere_in_this_module(self) -> None:
        """Memory is storage, not inference — asserted, not just asserted-in-prose."""
        import inspect

        src = inspect.getsource(ams)
        for banned in ("openai", "OpenAI", "llm", "chat.completions", "planner"):
            assert banned.lower() not in src.lower().replace("llm in any path", ""), (
                f"{banned!r} appears in a module that must stay deterministic"
            )

    @pytest.mark.asyncio
    async def test_uninitialised_store_fails_loudly(self) -> None:
        ams._pg_request = None
        with pytest.raises(RuntimeError, match="init"):
            await ams.recall("crm", "cursor", "k")
