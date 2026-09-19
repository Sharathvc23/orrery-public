"""Tests for community_member.arp_surfaces — local /api/agency-log/today.

R3   Injection    — special chars in human_summary survive serialization
R5   Boundary     — empty log → quiet-day surface; UTC-day filter is correct
R10  Persistence  — today's receipts render in the surface; older receipts excluded
"""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime, timedelta

os.environ.setdefault(
    "COMMUNITY_MEMBER_HOME",
    os.path.join(tempfile.gettempdir(), "cm-arp-surfaces-tests"),
)

import pytest

from community_member.arp import (
    AgencyLog,
    build_receipt,
    did_from_private_key,
    sign_receipt,
)
from community_member.arp_surfaces import build_today_surface_from_log

SK = b"member-sdk-surfaces-tests-32by!a"
assert len(SK) == 32


@pytest.fixture
def log(tmp_path):
    return AgencyLog(home=tmp_path / "agency")


def _texts(surface: dict) -> str:
    return " | ".join(
        c.get("text", "")
        for c in (surface.get("updateComponents") or {}).get("components", [])
        if isinstance(c, dict) and c.get("text")
    )


def _add(
    log: AgencyLog,
    *,
    category: str = "message_sent",
    summary: str = "test",
    issued_at: str | None = None,
    receipt_id: str | None = None,
    amount_cents: int | None = None,
    amount_currency: str | None = None,
):
    did = did_from_private_key(SK)
    extras: dict = {}
    if issued_at:
        extras["issued_at"] = issued_at
    if receipt_id:
        extras["receipt_id"] = receipt_id
    action = {
        "category": category,
        "human_summary": summary,
        "outcome": "completed",
    }
    if amount_cents is not None:
        action["amount"] = {"currency": amount_currency or "USD", "cents": amount_cents}
    r = build_receipt(action=action, issuer_did=did, principal_did=did, **extras)
    sign_receipt(r, SK)
    log.append(r)
    return r


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: empty log → quiet-day surface
# ══════════════════════════════════════════════════════════════════════


def test_R5_empty_log_renders_quiet_day(log):
    surface = build_today_surface_from_log(log)
    text = _texts(surface)
    assert surface["createSurface"]["surfaceId"] == "today-local"
    assert "quiet" in text.lower()


# ══════════════════════════════════════════════════════════════════════
# R5 — Boundary: yesterday's receipt is NOT included in today's surface
# ══════════════════════════════════════════════════════════════════════


def test_R5_yesterday_receipt_excluded_from_today(log):
    yesterday = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT14:00:00Z")
    _add(log, summary="From yesterday", issued_at=yesterday, receipt_id="11111111-1111-4111-8111-111111111111")
    surface = build_today_surface_from_log(log)
    text = _texts(surface)
    assert "From yesterday" not in text
    assert "quiet" in text.lower()


# ══════════════════════════════════════════════════════════════════════
# R10 — Persistence: today's receipts render in the right sections
# ══════════════════════════════════════════════════════════════════════


def test_R10_today_receipts_grouped_by_category_with_summaries(log):
    today_iso = datetime.now(UTC).strftime("%Y-%m-%dT14:00:00Z")
    _add(
        log,
        category="purchase",
        summary="Bought coffee at Pavement.",
        amount_cents=-425,
        amount_currency="USD",
        issued_at=today_iso,
        receipt_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    )
    _add(
        log,
        category="message_sent",
        summary="Replied to Maria.",
        issued_at=today_iso,
        receipt_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    )
    surface = build_today_surface_from_log(log)
    text = _texts(surface)

    assert "Purchases" in text
    assert "Messages sent" in text
    assert "Bought coffee at Pavement." in text
    assert "Replied to Maria." in text
    # Amount label for the purchase
    assert "USD" in text
    # Aggregate header
    assert "2 recorded actions" in text or "2 recorded" in text


# ══════════════════════════════════════════════════════════════════════
# R3 — Injection: special chars in summary survive surface rendering
# ══════════════════════════════════════════════════════════════════════


def test_R3_special_chars_in_summary_survive(log):
    today_iso = datetime.now(UTC).strftime("%Y-%m-%dT14:00:00Z")
    weird = 'He said "hi" — tab\there and backslash\\.'
    _add(
        log,
        summary=weird,
        issued_at=today_iso,
        receipt_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    )
    surface = build_today_surface_from_log(log)
    text = _texts(surface)
    assert weird in text


# ══════════════════════════════════════════════════════════════════════
# UTC-day boundary precision
# ══════════════════════════════════════════════════════════════════════


def test_receipts_at_midnight_utc_count_as_today(log):
    today_midnight = datetime.now(UTC).strftime("%Y-%m-%dT00:00:00Z")
    _add(
        log,
        summary="Midnight UTC action",
        issued_at=today_midnight,
        receipt_id="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    )
    surface = build_today_surface_from_log(log)
    text = _texts(surface)
    assert "Midnight UTC action" in text


# ══════════════════════════════════════════════════════════════════════
# A2UI shape sanity
# ══════════════════════════════════════════════════════════════════════


def test_surface_carries_a2ui_v09_envelope(log):
    surface = build_today_surface_from_log(log)
    assert surface.get("version") == "0.9"
    upd = surface.get("updateComponents") or {}
    assert "surfaceId" in upd
    assert "root" in upd
    assert isinstance(upd.get("components"), list)
    # Required top-level fields
    assert "createSurface" in surface
