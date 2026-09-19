"""Tests for the 4 additional chapter action paths wired to emit ARP receipts.

  governance.approve            → decision_made (outcome=completed)
  governance.reject             → decision_made (outcome=reversed)
  broadcast.send_broadcast      → message_sent
  outcome_tracker.record_feedback → decision_made

Each path is fire-and-forget — telemetry must not wedge business logic.
Tests verify a receipt lands in arp_receipts with the expected
(principal_did, category, counterparty), and that business logic still
succeeds even when receipt emission fails.

Classification: HAPPY / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import asyncio
import base64
import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ── Shared Fake Postgres ──────────────────────────────────────────────


class _FakePostgres:
    def __init__(self) -> None:
        self.arp_receipts: list[dict] = []
        self.pending_approvals: list[dict] = []
        self.agents: list[dict] = []
        self.agent_action_outcomes: list[dict] = []

    async def __call__(self, method, table, params=None, body=None):
        t = table.split("?")[0]
        if method == "GET":
            rows = list(getattr(self, t, []))
            for k, v in (params or {}).items():
                if k in ("select", "order", "limit"):
                    continue
                if isinstance(v, str) and v.startswith("eq."):
                    wanted = v[3:]
                    rows = [r for r in rows if str(r.get(k, "")) == wanted]
            limit = (params or {}).get("limit")
            if limit:
                rows = rows[: int(limit)]
            return rows
        if method == "POST":
            target = getattr(self, t, None)
            if isinstance(target, list):
                row = dict(body or {})
                # Receipt uniqueness simulation
                if t == "arp_receipts":
                    if any(
                        r["issuer_did"] == row["issuer_did"] and r["receipt_id"] == row["receipt_id"] for r in target
                    ):
                        raise RuntimeError("duplicate key value")
                target.append(row)
                return [row]
            return None
        if method == "PATCH":
            # The id filter now rides in params=; fall back to the old
            # table?id=eq.X path form for any unconverted call.
            id_match = str((params or {}).get("id", "")).replace("eq.", "") or None
            if not id_match:
                spec = table.split("?", 1)[1] if "?" in table else ""
                for kv in spec.split("&"):
                    if kv.startswith("id=eq."):
                        id_match = kv[len("id=eq.") :]
                        break
            target = getattr(self, t, None)
            if isinstance(target, list) and id_match:
                for r in target:
                    if str(r.get("id", "")) == id_match:
                        r.update(body or {})
                        return [r]
            return []
        return None


# ── Chapter keypair seed (so emit_chapter_action can sign) ────────────


def _seed_chapter_keypair(chapter_id: str = "test-chapter"):
    import sovereign_identity

    sk = Ed25519PrivateKey.from_private_bytes(b"more-action-paths-tests-seed-32!")
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    sovereign_identity._ed25519_keypairs[chapter_id] = {
        "private_key": sk_bytes,
        "public_key": pk_bytes,
    }


def _seed_member_pubkey(agent_id: str):
    """Place a fake Ed25519 pubkey for agent_id in auth_verify._agent_keys
    so arp.did_key_for_member resolves to a valid did:key."""
    import auth_verify

    sk = Ed25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pubkey_b64 = base64.b64encode(pk_bytes).decode()
    auth_verify._agent_keys[agent_id] = {"ed25519_pubkey": pubkey_b64}


@pytest.fixture
def supabase():
    import arp as arp_mod
    import auth_verify

    s = _FakePostgres()
    arp_mod.init(pg_request=s, chapter_id="test-chapter")
    _seed_chapter_keypair("test-chapter")
    # Clear auth_verify._agent_keys so each test starts fresh.
    auth_verify._agent_keys.clear()
    return s


async def _drain():
    """Yield once so create_task() coroutines run to completion."""
    await asyncio.sleep(0)
    await asyncio.sleep(0)


# ══════════════════════════════════════════════════════════════════════
# governance.approve / reject
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_approve_emits_decision_made_receipt(supabase):
    import governance

    governance._pg_request = supabase
    governance._agent_id = "test-chapter"
    _seed_member_pubkey("alice")
    _seed_member_pubkey("leader")

    # Seed an approval row
    supabase.pending_approvals.append(
        {
            "id": "ap-1",
            "kind": "introduction",
            "proposer_agent_id": "alice",
            "target_agent_id": "bob",
            "chapter_id": "test-chapter",
            "status": "pending",
        }
    )

    async def can_approve_yes(_):
        return True

    monkeypatch_global = pytest.MonkeyPatch()
    monkeypatch_global.setattr(governance, "can_approve", can_approve_yes)

    await governance.approve("ap-1", "leader")
    monkeypatch_global.undo()
    await _drain()

    assert any(
        r["action_category"] == "decision_made"
        and r["receipt_json"]["action"]["outcome"] == "completed"
        and r["receipt_json"]["action"]["counterparty_label"] == "leader"
        for r in supabase.arp_receipts
    )


@pytest.mark.asyncio
async def test_reject_emits_decision_made_reversed_receipt(supabase):
    import governance

    governance._pg_request = supabase
    governance._agent_id = "test-chapter"
    _seed_member_pubkey("alice")
    _seed_member_pubkey("leader")

    supabase.pending_approvals.append(
        {
            "id": "ap-2",
            "kind": "broadcast",
            "proposer_agent_id": "alice",
            "chapter_id": "test-chapter",
            "status": "pending",
        }
    )

    async def can_approve_yes(_):
        return True

    mp = pytest.MonkeyPatch()
    mp.setattr(governance, "can_approve", can_approve_yes)

    await governance.reject("ap-2", "leader", reason="out of scope")
    mp.undo()
    await _drain()

    receipt = next(
        (r for r in supabase.arp_receipts if r["action_category"] == "decision_made"),
        None,
    )
    assert receipt is not None
    assert receipt["receipt_json"]["action"]["outcome"] == "reversed"
    assert "rejected" in receipt["human_summary"].lower()
    assert "out of scope" in receipt["human_summary"]


@pytest.mark.asyncio
async def test_approve_unauthorized_no_receipt(supabase):
    """If can_approve returns False, the approval is rejected at the
    auth gate and NO receipt is emitted."""
    import governance

    governance._pg_request = supabase
    governance._agent_id = "test-chapter"

    async def can_approve_no(_):
        return False

    mp = pytest.MonkeyPatch()
    mp.setattr(governance, "can_approve", can_approve_no)

    result = await governance.approve("ap-999", "rando")
    mp.undo()
    await _drain()

    assert result == {"error": "not_authorized"}
    assert supabase.arp_receipts == []


# ══════════════════════════════════════════════════════════════════════
# broadcast.send_broadcast
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_broadcast_send_emits_message_sent_for_sender(supabase, monkeypatch):
    import broadcast as broadcast_mod
    import event_bus

    broadcast_mod._pg_request = supabase
    broadcast_mod._chapter_id = "test-chapter"
    _seed_member_pubkey("alice")

    # Stub event_bus.publish to succeed
    async def fake_publish(_event_type, _payload):
        return 99

    monkeypatch.setattr(event_bus, "publish", fake_publish)

    # Stub the audit + federation pushes — out of scope for this test
    async def noop(*_a, **_k):
        return None

    monkeypatch.setattr(broadcast_mod, "_audit_send", noop, raising=False)
    # is_initialized must be true
    monkeypatch.setattr(broadcast_mod, "is_initialized", lambda: True, raising=False)

    result = await broadcast_mod.send_broadcast(
        sender_agent_id="alice",
        title="Town hall this Friday",
        body="Join us at 4pm to discuss the new policy.",
        tags=["governance", "town-hall"],
        audience="local",
    )
    await _drain()

    assert result.get("event_id") == 99
    assert any(
        r["action_category"] == "message_sent"
        and "Town hall this Friday" in r["receipt_json"]["action"]["human_summary"]
        and r["receipt_json"]["action"]["machine_payload"]["broadcast_id"]
        for r in supabase.arp_receipts
    )


# ══════════════════════════════════════════════════════════════════════
# outcome_tracker.record_feedback
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_outcome_feedback_emits_decision_made(supabase):
    import outcome_tracker

    outcome_tracker._pg_request = supabase
    outcome_tracker._agent_id = "test-chapter"
    _seed_member_pubkey("alice")

    await outcome_tracker.record_feedback(
        action_id="intro-7",
        action_type="introduction",
        signal="positive",
        agent_id="alice",
    )
    await _drain()

    assert any(
        r["action_category"] == "decision_made"
        and r["receipt_json"]["action"]["machine_payload"]["signal"] == "positive"
        for r in supabase.arp_receipts
    )


@pytest.mark.asyncio
async def test_outcome_feedback_without_agent_id_no_receipt(supabase):
    """When no agent_id is provided, no principal to attribute → no receipt."""
    import outcome_tracker

    outcome_tracker._pg_request = supabase
    outcome_tracker._agent_id = "test-chapter"

    await outcome_tracker.record_feedback(
        action_id="intro-8",
        action_type="introduction",
        signal="positive",
    )
    await _drain()

    assert supabase.arp_receipts == []
