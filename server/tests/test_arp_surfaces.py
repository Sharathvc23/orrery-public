"""Tests for /page/today and /page/chronicle A2UI surface builders.

The surface builders read directly from pg_request (module global).
Tests inject a fake.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest

import surfaces


class _FakePostgres:
    def __init__(self) -> None:
        self.agents: list[dict] = []
        self.arp_receipts: list[dict] = []
        self.chronicles: list[dict] = []

    async def __call__(self, method, table, params=None, body=None):
        t = table.split("?")[0]
        if method != "GET":
            return None
        rows = list(getattr(self, t, []))
        for k, v in (params or {}).items():
            if k in ("select", "order", "limit", "and"):
                continue
            if isinstance(v, str) and v.startswith("eq."):
                rows = [r for r in rows if str(r.get(k, "")) == v[3:]]
            elif isinstance(v, str) and v.startswith("gte."):
                rows = [r for r in rows if str(r.get(k, "")) >= v[4:]]
        order = (params or {}).get("order", "")
        if order.endswith(".desc"):
            col = order.split(".")[0]
            rows = sorted(rows, key=lambda r: r.get(col, ""), reverse=True)
        limit = (params or {}).get("limit")
        if limit:
            rows = rows[: int(limit)]
        return rows


@pytest.fixture
def sb():
    s = _FakePostgres()
    # surfaces.py reads the module-global ``pg_request``
    surfaces.pg_request = s
    # chronicle.py keeps its own injected handle; wire the same fake so
    # the visibility-gate check inside build_chronicle_surface works.
    import chronicle

    chronicle.init(
        pg_request=s,
        chapter_id="test-chapter",
        chapter_name="Test Chapter",
        llm=None,
    )
    yield s
    surfaces.pg_request = None


def _component_texts(surface_dict: dict) -> list[str]:
    """Flatten every text-bearing component into a list of strings."""
    out: list[str] = []
    for c in (surface_dict.get("updateComponents") or {}).get("components", []):
        for k in ("text", "markdown", "label", "title"):
            v = c.get(k)
            if isinstance(v, str):
                out.append(v)
    return out


# ══════════════════════════════════════════════════════════════════════
# /page/today
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_today_with_no_target_returns_unauth_surface(sb):
    result = await surfaces.build_today_surface(target=None)
    texts = " | ".join(_component_texts(result))
    assert "Sign in" in texts or "signed in" in texts.lower()


@pytest.mark.asyncio
async def test_today_with_target_no_receipts_returns_quiet_day(sb):
    result = await surfaces.build_today_surface(target="did:key:zAlice")
    texts = " ".join(_component_texts(result))
    assert "quiet" in texts.lower() or "no recorded" in texts.lower()


@pytest.mark.asyncio
async def test_today_renders_receipts_grouped_by_category(sb):
    from datetime import UTC, datetime

    today = datetime.now(UTC).strftime("%Y-%m-%dT14:00:00Z")
    sb.arp_receipts.extend(
        [
            {
                "principal_did": "did:key:zAlice",
                "issued_at": today,
                "action_category": "purchase",
                "action_outcome": "completed",
                "human_summary": "Bought coffee at Pavement.",
                "amount_currency": "USD",
                "amount_cents": -425,
                "counterparty_did": "did:key:zPavement",
            },
            {
                "principal_did": "did:key:zAlice",
                "issued_at": today,
                "action_category": "message_sent",
                "action_outcome": "completed",
                "human_summary": "Replied to Maria.",
                "amount_currency": None,
                "amount_cents": None,
                "counterparty_did": "did:key:zMaria",
            },
        ]
    )
    result = await surfaces.build_today_surface(target="did:key:zAlice")
    texts = " ".join(_component_texts(result))
    # Both categories surface
    assert "Purchases" in texts
    assert "Messages sent" in texts
    # Specific summaries surface
    assert "Bought coffee at Pavement." in texts
    assert "Replied to Maria." in texts
    # Amount label is rendered for the purchase
    assert "USD" in texts
    # Aggregate header
    assert "2 recorded actions" in texts


# ══════════════════════════════════════════════════════════════════════
# /page/chronicle?target=
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_chronicle_missing_target_shows_help_surface(sb):
    result = await surfaces.build_chronicle_surface(target=None)
    texts = " ".join(_component_texts(result))
    assert "target" in texts.lower()


@pytest.mark.asyncio
async def test_chronicle_private_by_default_returns_private_surface(sb):
    sb.agents.append(
        {
            "agent_id": "alice",
            "name": "Alice",
            "config": {"chronicle_public": False},
        }
    )
    result = await surfaces.build_chronicle_surface(target="alice")
    texts = " ".join(_component_texts(result))
    assert "private" in texts.lower()


@pytest.mark.asyncio
async def test_chronicle_public_with_no_entries_shows_empty_state(sb):
    sb.agents.append(
        {
            "agent_id": "alice",
            "name": "Alice",
            "config": {"chronicle_public": True},
        }
    )
    result = await surfaces.build_chronicle_surface(target="alice")
    texts = " ".join(_component_texts(result))
    # The empty-state copy mentions that entries publish at end of day
    assert "no chronicle entries" in texts.lower() or "publish" in texts.lower()


@pytest.mark.asyncio
async def test_chronicle_public_with_entries_renders_them(sb, monkeypatch):
    # The chronicle surface resolves the target's did:key via
    # auth_verify._agent_keys; stub the lookup.
    import auth_verify
    import sovereign_identity as si

    monkeypatch.setattr(auth_verify, "_agent_keys", {"alice": {"ed25519_pubkey": "AAAA"}}, raising=False)
    monkeypatch.setattr(
        si,
        "build_did_key_from_ed25519",
        lambda pk: "did:key:zAlice" if pk == "AAAA" else "",
    )

    sb.agents.append(
        {
            "agent_id": "alice",
            "name": "Alice Patel",
            "config": {"chronicle_public": True},
        }
    )
    sb.chronicles.append(
        {
            "principal_did": "did:key:zAlice",
            "chronicle_date": "2026-05-22",
            "parent_chapter": "test-chapter",
            "narrative": "Today I focused on AI infrastructure work.",
            "stats": {"by_category": {"message_sent": 3, "decision_made": 1}, "receipt_count": 4},
            "sources": [],
            "updated_at": "2026-05-22T23:50:00Z",
        }
    )
    result = await surfaces.build_chronicle_surface(target="alice")
    texts = " ".join(_component_texts(result))
    assert "Alice Patel's Chronicle" in texts
    assert "Today I focused on AI infrastructure work." in texts
    assert "2026-05-22" in texts
    # Category breakdown shown
    assert "Messages sent: 3" in texts
