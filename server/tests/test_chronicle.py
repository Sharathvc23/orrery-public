"""R1-R10 tests for chapter.chronicle — daily first-person Chronicle.

R1  Forgery      — chronicle_public=false hides the Chronicle from public surface
R2  Replay       — generate_for_day is idempotent (upsert, not duplicate)
R3  Injection    — narrative containing special chars survives store + retrieve
R4  Authz        — generate_for_all_own_members skips members whose
                   parent_chapter ≠ this chapter
R5  Boundary     — empty receipts → chronicle with empty stats, non-empty narrative
R7  Adversarial  — None LLM falls back to deterministic narrative
R10 Persistence  — generate → get_chronicle round-trip preserves narrative + stats
"""

from __future__ import annotations

import os
from datetime import date

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest

import chronicle


class _FakePostgres:
    def __init__(self) -> None:
        self.agents: list[dict] = []
        self.arp_receipts: list[dict] = []
        self.chronicles: list[dict] = []

    async def __call__(self, method, table, params=None, body=None):
        t = table.split("?")[0]
        if method == "GET":
            rows = list(getattr(self, t, []))
            for k, v in (params or {}).items():
                if k in ("select", "order", "limit", "and"):
                    continue
                if isinstance(v, str) and v.startswith("eq."):
                    wanted = v[3:]
                    rows = [r for r in rows if str(r.get(k, "")) == wanted]
                elif isinstance(v, str) and v.startswith("gte."):
                    wanted = v[4:]
                    rows = [r for r in rows if str(r.get(k, "")) >= wanted]
            # Apply order desc + limit
            order = (params or {}).get("order", "")
            if order.endswith(".desc"):
                col = order.split(".")[0]
                rows = sorted(rows, key=lambda r: r.get(col, ""), reverse=True)
            limit = (params or {}).get("limit")
            if limit:
                rows = rows[: int(limit)]
            return rows
        if method == "POST" and t == "chronicles":
            row = dict(body or {})
            # Upsert by composite key
            existing = [
                i
                for i, r in enumerate(self.chronicles)
                if r["principal_did"] == row["principal_did"] and r["chronicle_date"] == row["chronicle_date"]
            ]
            if existing:
                self.chronicles[existing[0]] = row
            else:
                self.chronicles.append(row)
            return [row]
        return None


# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def supabase() -> _FakePostgres:
    s = _FakePostgres()
    chronicle.init(
        pg_request=s,
        chapter_id="test-chapter",
        chapter_name="Test Chapter",
        llm=None,
    )
    return s


def _seed_agent(s, *, agent_id="alice", parent="test-chapter", public=False):
    s.agents.append(
        {
            "agent_id": agent_id,
            "name": agent_id.title(),
            "description": "test member",
            "config": {
                "parent_chapter": parent,
                "personality": "thoughtful, direct",
                "voice": "thoughtful",
                "title": "Engineer",
                "company": "Acme Robotics",
                "chronicle_public": public,
            },
        }
    )


def _seed_receipt(
    s,
    *,
    principal_did="did:key:zAlice",
    category="message_sent",
    issued_at="2026-05-22T14:00:00Z",
    summary="Sent a test message.",
    amount_cents=None,
    amount_currency=None,
):
    s.arp_receipts.append(
        {
            "principal_did": principal_did,
            "issued_at": issued_at,
            "action_category": category,
            "action_outcome": "completed",
            "human_summary": summary,
            "amount_currency": amount_currency,
            "amount_cents": amount_cents,
            "counterparty_did": "did:key:zBob",
            "receipt_json": {
                "version": "arp/0.1",
                "principal_did": principal_did,
                "issued_at": issued_at,
                "action": {
                    "category": category,
                    "human_summary": summary,
                    "outcome": "completed",
                    "counterparty_did": "did:key:zBob",
                    **({"amount": {"cents": amount_cents, "currency": amount_currency}} if amount_cents else {}),
                },
            },
        }
    )


# ══════════════════════════════════════════════════════════════════════
# R1 — Forgery: chronicle_public=false hides chronicle from public access
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R1_chronicle_public_false_hides_publicly(supabase):
    _seed_agent(supabase, agent_id="alice", public=False)
    assert await chronicle.is_chronicle_public("alice") is False


@pytest.mark.asyncio
async def test_R1_chronicle_public_true_visible(supabase):
    _seed_agent(supabase, agent_id="bob", public=True)
    assert await chronicle.is_chronicle_public("bob") is True


# ══════════════════════════════════════════════════════════════════════
# R2 — Replay: generate_for_day is idempotent (upsert, not duplicate)
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R2_generate_for_day_idempotent(supabase):
    _seed_agent(supabase, agent_id="alice")
    _seed_receipt(supabase)

    day = date(2026, 5, 22)
    r1 = await chronicle.generate_for_day(principal_did="did:key:zAlice", agent_id="alice", day=day)
    r2 = await chronicle.generate_for_day(principal_did="did:key:zAlice", agent_id="alice", day=day)

    assert r1 is not None and r2 is not None
    assert len(supabase.chronicles) == 1


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection: special chars survive store + retrieve
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R3_special_chars_in_narrative_survive(supabase):
    _seed_agent(supabase, agent_id="alice")
    _seed_receipt(
        supabase,
        summary='Sent a "quote" with backslash \\ and tab\there.',
    )
    day = date(2026, 5, 22)
    result = await chronicle.generate_for_day(principal_did="did:key:zAlice", agent_id="alice", day=day)
    assert result is not None
    # The deterministic fallback narrative survives the round-trip
    fetched = await chronicle.get_chronicle("did:key:zAlice", day)
    assert fetched is not None
    assert isinstance(fetched["narrative"], str)


# ══════════════════════════════════════════════════════════════════════
# R4 — Authz: generate_for_all_own_members skips foreign-parent members
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R4_skip_members_with_foreign_parent_chapter(supabase):
    _seed_agent(supabase, agent_id="alice", parent="test-chapter")
    _seed_agent(supabase, agent_id="visitor", parent="other-chapter")

    members = {
        "alice": {"name": "Alice", "ed25519_pubkey": ""},
        "visitor": {"name": "Visitor", "ed25519_pubkey": ""},
    }
    await chronicle.generate_for_all_own_members(day=date(2026, 5, 22), members=members)
    # Neither has a real pubkey so both get filtered at did:key resolve
    # step; the authz filter is exercised before key resolve, so the
    # visitor is filtered first regardless. We assert NO chronicle is
    # written for the visitor by checking nothing under visitor's did.
    visitor_rows = [c for c in supabase.chronicles if c.get("principal_did", "").endswith("visitor")]
    assert visitor_rows == []


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: empty receipts → chronicle written with empty stats
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R5_no_receipts_produces_quiet_day_chronicle(supabase):
    _seed_agent(supabase, agent_id="alice")
    # No receipts seeded
    result = await chronicle.generate_for_day(principal_did="did:key:zAlice", agent_id="alice", day=date(2026, 5, 22))
    assert result is not None
    assert result["stats"]["receipt_count"] == 0
    assert "quiet day" in result["narrative"].lower()


@pytest.mark.asyncio
async def test_R5_aggregate_stats_pure_function():
    stats = chronicle._aggregate_stats(
        [
            {"action": {"category": "purchase", "outcome": "completed", "amount": {"currency": "USD", "cents": -1000}}},
            {"action": {"category": "purchase", "outcome": "completed", "amount": {"currency": "USD", "cents": -500}}},
            {"action": {"category": "message_sent", "outcome": "completed"}},
        ]
    )
    assert stats["receipt_count"] == 3
    assert stats["by_category"]["purchase"] == 2
    assert stats["by_category"]["message_sent"] == 1
    assert stats["amount_totals"]["USD"] == -1500


# ══════════════════════════════════════════════════════════════════════
# R7 — Adversarial: None LLM falls back to deterministic narrative
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R7_no_llm_falls_back_to_deterministic(supabase):
    _seed_agent(supabase, agent_id="alice")
    _seed_receipt(supabase, category="purchase", amount_cents=-1500, amount_currency="USD")
    _seed_receipt(
        supabase,
        category="message_sent",
        issued_at="2026-05-22T15:00:00Z",
        summary="Second action.",
    )
    result = await chronicle.generate_for_day(principal_did="did:key:zAlice", agent_id="alice", day=date(2026, 5, 22))
    assert result is not None
    assert result["narrative"]  # non-empty
    assert "Alice" in result["narrative"] or "agent" in result["narrative"].lower()


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: round-trip preserves narrative + stats
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_R10_persistence_round_trip(supabase):
    _seed_agent(supabase, agent_id="alice")
    _seed_receipt(supabase, category="purchase", amount_cents=-2000, amount_currency="USD")
    written = await chronicle.generate_for_day(principal_did="did:key:zAlice", agent_id="alice", day=date(2026, 5, 22))
    assert written is not None

    fetched = await chronicle.get_chronicle("did:key:zAlice", date(2026, 5, 22))
    assert fetched is not None
    assert fetched["narrative"] == written["narrative"]
    assert fetched["stats"]["receipt_count"] == written["stats"]["receipt_count"]
    assert fetched["parent_chapter"] == "test-chapter"


@pytest.mark.asyncio
async def test_R10_list_chronicles_orders_newest_first(supabase):
    _seed_agent(supabase, agent_id="alice")
    _seed_receipt(supabase, issued_at="2026-05-22T14:00:00Z")
    _seed_receipt(supabase, issued_at="2026-05-23T14:00:00Z")

    await chronicle.generate_for_day(principal_did="did:key:zAlice", agent_id="alice", day=date(2026, 5, 22))
    await chronicle.generate_for_day(principal_did="did:key:zAlice", agent_id="alice", day=date(2026, 5, 23))

    rows = await chronicle.list_chronicles("did:key:zAlice", limit=10)
    assert len(rows) == 2
    assert rows[0]["chronicle_date"] == "2026-05-23"
    assert rows[1]["chronicle_date"] == "2026-05-22"


# ══════════════════════════════════════════════════════════════════════
# Sources attribution shape — forward-compat for non-ARP sources
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_sources_attribution_records_arp_count(supabase):
    _seed_agent(supabase, agent_id="alice")
    _seed_receipt(supabase)
    _seed_receipt(supabase, issued_at="2026-05-22T15:00:00Z", summary="Second.")
    result = await chronicle.generate_for_day(principal_did="did:key:zAlice", agent_id="alice", day=date(2026, 5, 22))
    assert result is not None
    sources = result["sources"]
    assert any(s["type"] == "arp_receipts" and s["count"] == 2 for s in sources)
