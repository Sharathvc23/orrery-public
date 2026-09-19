"""detect_score_drift — batched replay (RPC + keyset fallback).

The old detector ran one SUM(delta) query per agent (N+1, timed out on real
chapters). The new one computes all agents' replay in a single aggregate via the
replay_scores_all RPC, falling back to a keyset-paginated sum over the ledger PK.

The non-negotiable property: a *failed* read must RAISE, never return an empty
replay — otherwise every agent would be falsely flagged as drifted. These tests
pin that, plus that the batched sums match what a per-agent SUM(delta) would give.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.
"""

from decimal import Decimal

import pytest

import trust_events


class _DriftFake:
    """Tailored PostgREST stub for the drift detector's three reads:
    POST rpc/replay_scores_all, GET agents, GET trust_events (keyset). A
    (method, table) in ``fail_on`` returns None to simulate a backend failure."""

    def __init__(self, *, agents, events=None, rpc=None, fail_on=None, max_rows=None):
        self.agents = agents
        self.events = events or []
        self.rpc = rpc  # list -> RPC present; None -> RPC unavailable (fallback)
        self.fail_on = fail_on or set()
        self.max_rows = max_rows  # PostgREST-style server cap on rows-per-response

    async def __call__(self, method, table, params=None, body=None):
        if (method, table) in self.fail_on:
            return None
        if method == "POST" and table == "rpc/replay_scores_all":
            return self.rpc
        if method == "GET" and table == "agents":
            return list(self.agents)
        if method == "GET" and table == "trust_events":
            rows = list(self.events)
            idf = (params or {}).get("id", "")
            if isinstance(idf, str) and idf.startswith("gt."):
                gt = int(idf[3:])
                rows = [r for r in rows if int(r["id"]) > gt]
            rows.sort(key=lambda r: int(r["id"]))
            cap = int((params or {}).get("limit", 5000))
            if self.max_rows is not None:  # server may return fewer than requested
                cap = min(cap, self.max_rows)
            return rows[:cap]
        return None


def _init(fake):
    trust_events.init(fake, "test-chapter")


async def test_rpc_clean_reports_no_drift():  # HAPPY
    _init(
        _DriftFake(
            agents=[{"agent_id": "a", "trust_score": 5.0}, {"agent_id": "b", "trust_score": 0.0}],
            rpc=[{"agent_id": "a", "replayed": 5.0}],
        )
    )
    assert await trust_events.detect_score_drift() == []


async def test_rpc_detects_drift():  # HAPPY — the whole point
    _init(_DriftFake(agents=[{"agent_id": "a", "trust_score": 7.0}], rpc=[{"agent_id": "a", "replayed": 5.0}]))
    drifts = await trust_events.detect_score_drift()
    assert len(drifts) == 1
    assert drifts[0]["agent_id"] == "a"
    assert Decimal(drifts[0]["drift"]) == Decimal("2")


async def test_score_without_any_events_is_drift():  # EDGE — stored>0, replays to 0
    _init(_DriftFake(agents=[{"agent_id": "c", "trust_score": 3.0}], rpc=[]))
    drifts = await trust_events.detect_score_drift()
    assert len(drifts) == 1 and Decimal(drifts[0]["replayed"]) == Decimal("0")


async def test_keyset_fallback_sums_match_per_agent(monkeypatch):  # HAPPY — RPC absent
    events = [
        {"id": 1, "agent_id": "a", "delta": 2.0},
        {"id": 2, "agent_id": "a", "delta": 3.0},
        {"id": 3, "agent_id": "b", "delta": 1.0},
    ]
    _init(
        _DriftFake(
            agents=[{"agent_id": "a", "trust_score": 5.0}, {"agent_id": "b", "trust_score": 1.0}],
            events=events,
            rpc=None,
        )
    )
    # a: 2+3 == 5 stored; b: 1 == 1 stored → no drift, summed exactly once each.
    assert await trust_events.detect_score_drift() == []


async def test_keyset_fallback_detects_drift():  # HAPPY — RPC absent
    _init(
        _DriftFake(
            agents=[{"agent_id": "a", "trust_score": 9.0}], events=[{"id": 1, "agent_id": "a", "delta": 2.0}], rpc=None
        )
    )
    drifts = await trust_events.detect_score_drift()
    assert len(drifts) == 1 and Decimal(drifts[0]["replayed"]) == Decimal("2")


async def test_keyset_paginates_past_server_rowcap():  # ADVERSARIAL — the bug guard
    """PostgREST caps rows-per-response below our requested limit. Pagination must
    continue to an EMPTY page, not stop at the cap — else it silently skips events
    and mis-sums the ledger. 5 events, server cap of 2 per page → must sum all 5."""
    events = [{"id": i, "agent_id": "a", "delta": 1.0} for i in range(1, 6)]  # sum = 5
    _init(_DriftFake(agents=[{"agent_id": "a", "trust_score": 5.0}], events=events, rpc=None, max_rows=2))
    assert await trust_events.detect_score_drift() == []  # all 5 summed → 5 == 5, no drift
    # A stored score equal to only the FIRST capped page (sum 2) MUST be flagged —
    # proving we didn't stop at the cap.
    _init(_DriftFake(agents=[{"agent_id": "a", "trust_score": 2.0}], events=events, rpc=None, max_rows=2))
    assert len(await trust_events.detect_score_drift()) == 1


async def test_trust_events_read_failure_raises_not_false_drift():  # FAILURE/ADVERSARIAL
    """A partial ledger read must RAISE — never be summed to 0 and reported as
    "every agent drifted"."""
    _init(_DriftFake(agents=[{"agent_id": "a", "trust_score": 5.0}], rpc=None, fail_on={("GET", "trust_events")}))
    with pytest.raises(RuntimeError, match="partial ledger"):
        await trust_events.detect_score_drift()


async def test_agents_read_failure_raises():  # FAILURE
    _init(_DriftFake(agents=[], rpc=[], fail_on={("GET", "agents")}))
    with pytest.raises(RuntimeError, match="partial read"):
        await trust_events.detect_score_drift()
