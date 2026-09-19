"""Tests for the /page/approvals A2UI surface info-leak fix.

Classification: ADVERSARIAL / EDGE / HAPPY.

Background: ``build_approvals_surface`` was publicly fetchable via
``GET /api/surfaces/approvals`` and embedded member names, proposal
payload contents, nominator identities, and reason strings. The
docstring said *"AgentPage.tsx should hide the sidebar link for non-
privileged users"* — defense in name only. Action execution is gated by
``governance.approve(actor)`` server-side, so the leak was display-only,
but it included real names + private payload content.

The fix is **safe-projection**: redact the sensitive bits in the surface
while keeping the actionable scaffolding (kind, timestamp, item_id,
buttons). The buttons continue to work because the action handler at
``/api/approvals/{id}/approve|reject`` already checks the actor's role.

Server-gating the surface endpoint itself is a separate concern that
requires coordinated portal-side credentials (the portal currently
fetches surfaces with no auth). Documented as a follow-up; not in this
PR.

ADVERSARIAL tests below are the security gate — they enforce that the
projection does not regress.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-approvals-chapter")
os.environ.setdefault("AGENT_NAME", "Test Approvals Chapter")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import chapter_agent  # noqa: E402


@pytest.fixture
def client():
    return TestClient(chapter_agent.app)


@pytest.fixture
def stub_governance(monkeypatch):
    """Stub governance.get_dashboard, list_pending.

    Sensitive identifiers in fixture data are deliberately distinctive
    ("LEAK-CANARY-..." strings) so the ADVERSARIAL tests below can
    grep for them in the response. If any LEAK-CANARY string makes it
    into the surface, the projection has regressed.
    """
    import governance

    async def fake_get_dashboard():
        return {
            "pending_count": 3,
            "expiring_soon_count": 1,
            "approved_last_24h": 7,
            "rejected_last_24h": 2,
        }

    async def fake_list_pending(*, kind=None, limit=50):
        return [
            {
                "id": "appr-uuid-001",
                "kind": "introduction",
                "confidence": 0.87,
                "created_at": "2026-05-23T08:00:00Z",
                "payload": {
                    "member_a": {"name": "LEAK-CANARY-MEMBER-A-NAME"},
                    "member_b": {"name": "LEAK-CANARY-MEMBER-B-NAME"},
                    "pair": ["LEAK-CANARY-PAIR-DID-A", "LEAK-CANARY-PAIR-DID-B"],
                    "reason": "LEAK-CANARY-REASON-TEXT",
                },
            },
            {
                "id": "appr-uuid-002",
                "kind": "cross_chapter_intent",
                "confidence": 0.65,
                "created_at": "2026-05-23T08:30:00Z",
                "peer_chapter_id": "boston-chapter",  # peer IDs are publicly known
                "payload": {"intent_text": "LEAK-CANARY-INTENT-TEXT"},
            },
            {
                "id": "appr-uuid-003",
                "kind": "event_proposal",
                "confidence": 0.42,
                "created_at": "2026-05-23T09:00:00Z",
                "payload": {
                    "title": "LEAK-CANARY-EVENT-TITLE",
                    "description": "LEAK-CANARY-EVENT-DESCRIPTION",
                },
            },
            {
                "id": "appr-uuid-004",
                "kind": "member_admission",
                "confidence": 0.7,
                "created_at": "2026-05-23T09:30:00Z",
                "payload": {
                    "nominee_name": "LEAK-CANARY-NOMINEE-NAME",
                    "nominee_agent_id": "LEAK-CANARY-NOMINEE-AGENT-ID",
                    "note": "LEAK-CANARY-ADMISSION-NOTE",
                },
            },
            {
                "id": "appr-uuid-005",
                "kind": "role_promotion",
                "confidence": 0.55,
                "created_at": "2026-05-23T10:00:00Z",
                "payload": {
                    "nominee_agent_id": "LEAK-CANARY-PROMO-NOMINEE",
                    "target_role": "leader",
                    "reason": "LEAK-CANARY-PROMO-REASON",
                },
            },
        ]

    monkeypatch.setattr(governance, "get_dashboard", fake_get_dashboard)
    monkeypatch.setattr(governance, "list_pending", fake_list_pending)


def _serialize(d):
    import json

    return json.dumps(d, default=str)


# ══════════════════════════════════════════════════════════════════════
# ADVERSARIAL — every LEAK-CANARY must be redacted
# ══════════════════════════════════════════════════════════════════════


def test_ADVERSARIAL_no_member_names_in_introduction_card(client, stub_governance):
    """Introduction proposal cards used to show ``f"Introduce {a} × {b}"``
    where a and b were real member names. Names MUST NOT appear."""
    resp = client.get("/api/surfaces/approvals")
    blob = _serialize(resp.json())
    assert "LEAK-CANARY-MEMBER-A-NAME" not in blob
    assert "LEAK-CANARY-MEMBER-B-NAME" not in blob
    assert "LEAK-CANARY-PAIR-DID-A" not in blob
    assert "LEAK-CANARY-PAIR-DID-B" not in blob


def test_ADVERSARIAL_no_reason_text_in_proposals(client, stub_governance):
    """Operator-written reason strings can contain PII or strategic info.
    Must not leak via the public surface."""
    resp = client.get("/api/surfaces/approvals")
    blob = _serialize(resp.json())
    assert "LEAK-CANARY-REASON-TEXT" not in blob
    assert "LEAK-CANARY-PROMO-REASON" not in blob
    assert "LEAK-CANARY-ADMISSION-NOTE" not in blob


def test_ADVERSARIAL_no_intent_text_in_cross_chapter_card(client, stub_governance):
    """Cross-chapter intent text can describe member needs or business
    intent. Treat as private."""
    resp = client.get("/api/surfaces/approvals")
    blob = _serialize(resp.json())
    assert "LEAK-CANARY-INTENT-TEXT" not in blob


def test_ADVERSARIAL_no_event_title_or_description(client, stub_governance):
    """Event proposals may be confidential before they're announced."""
    resp = client.get("/api/surfaces/approvals")
    blob = _serialize(resp.json())
    assert "LEAK-CANARY-EVENT-TITLE" not in blob
    assert "LEAK-CANARY-EVENT-DESCRIPTION" not in blob


def test_ADVERSARIAL_no_nominee_or_nominator_identities(client, stub_governance):
    """Member admission + role promotion cards used to show nominee names
    and target roles. All identity fields must be redacted in the
    surface; admins fetch details from the admin-gated REST endpoints
    when they need to make a decision."""
    resp = client.get("/api/surfaces/approvals")
    blob = _serialize(resp.json())
    assert "LEAK-CANARY-NOMINEE-NAME" not in blob
    assert "LEAK-CANARY-NOMINEE-AGENT-ID" not in blob
    assert "LEAK-CANARY-PROMO-NOMINEE" not in blob


# ══════════════════════════════════════════════════════════════════════
# HAPPY — surface still functions as an actionable queue
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_aggregate_stats_still_present(client, stub_governance):
    """Counts are safe to display — they were never the leak."""
    resp = client.get("/api/surfaces/approvals")
    blob = _serialize(resp.json())
    assert '"value": "3"' in blob or '"value":"3"' in blob  # pending_count


def test_HAPPY_action_buttons_remain_for_each_proposal(client, stub_governance):
    """Approve / reject buttons must keep working — that's the page's
    primary purpose. governance.approve() guards the action; the buttons
    are display scaffolding only."""
    resp = client.get("/api/surfaces/approvals")
    blob = _serialize(resp.json())
    # All five fixture proposals should still have their item IDs
    # threaded through to the buttons.
    for item_id in ["appr-uuid-001", "appr-uuid-002", "appr-uuid-003", "appr-uuid-004", "appr-uuid-005"]:
        assert item_id in blob


def test_HAPPY_kind_still_visible_so_admin_can_categorize(client, stub_governance):
    """Admins need to know WHAT kind of proposal each card is — a queue
    of unlabeled items is unusable. Kind itself is not sensitive."""
    resp = client.get("/api/surfaces/approvals")
    blob = _serialize(resp.json())
    assert "introduction" in blob.lower()
    assert "event" in blob.lower()
    assert "admission" in blob.lower() or "member" in blob.lower()


# ══════════════════════════════════════════════════════════════════════
# EDGE — empty + governance unavailable
# ══════════════════════════════════════════════════════════════════════


def test_EDGE_empty_queue_renders_caught_up_message(client, monkeypatch):
    """Empty queue = "chapter is caught up" — pre-existing message must
    still appear after the redaction refactor."""
    import governance

    async def empty_dashboard():
        return {"pending_count": 0, "expiring_soon_count": 0, "approved_last_24h": 0, "rejected_last_24h": 0}

    async def empty_list(**_kwargs):
        return []

    monkeypatch.setattr(governance, "get_dashboard", empty_dashboard)
    monkeypatch.setattr(governance, "list_pending", empty_list)

    resp = client.get("/api/surfaces/approvals")
    blob = _serialize(resp.json()).lower()
    assert "caught up" in blob or "no pending" in blob
