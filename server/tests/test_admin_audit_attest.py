"""Tests for POST /admin/api/audit/attest (A3.3).

Classification: HAPPY / EDGE / FAILURE / AUTHZ / ADVERSARIAL.

A3.3 ships a signed chain-snapshot attestation: the admin asks the
chapter to commit to its current audit-chain state — tip sha256, length,
window — and receives a chapter-signed ARP receipt back. The admin can
publish that receipt anywhere (peer chapters, a public archive, a
compliance officer's inbox). Anyone with the chapter's public key can
verify the signature, and the receipt's content claims the chain state
at the snapshot moment.

Architecturally:
  - chapter_audit.chain_tip()       reads {tip, length, last_occurred_at}
  - arp.emit_audit_chain_snapshot()  signs+persists, returns receipt
  - POST /admin/api/audit/attest    admin-gated wrapper

This is a Signed Tree Head pattern (CT-style), built on the chapter's
existing ARP primitive rather than minting a new VC type. The
ComplianceCredential machinery is reserved for "did this action
satisfy regulation X?" — a different question than chain-integrity.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-audit-chapter")
os.environ.setdefault("AGENT_NAME", "Test Audit Chapter")
os.environ.setdefault("XAI_API_KEY", "test-xai-key")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import chapter_agent  # noqa: E402


@pytest.fixture
def client():
    return TestClient(chapter_agent.app)


@pytest.fixture
def admin_token(monkeypatch):
    monkeypatch.setenv("CHAPTER_ADMIN_TOKEN", "test-token-abc123")
    import admin as admin_mod

    admin_mod._admin_token = "test-token-abc123"  # noqa: S105 — test stub, not a real secret
    return "test-token-abc123"


@pytest.fixture
def stub_chain_state(monkeypatch):
    """Replace chapter_audit.chain_tip with a controllable stub."""
    import chapter_audit

    state = {
        "tip_sha256": "abc123def456" + "0" * 52,  # 64 hex chars
        "length": 42,
        "last_occurred_at": "2026-05-23T09:00:00Z",
        "first_occurred_at": "2026-05-01T00:00:00Z",
    }

    async def fake_chain_tip(chapter_id):
        return dict(state)

    monkeypatch.setattr(chapter_audit, "chain_tip", fake_chain_tip)
    return state


@pytest.fixture
def stub_arp_emit(monkeypatch, stub_chain_state):
    """Replace arp.emit_audit_chain_snapshot with a controllable stub
    that returns a plausibly-shaped signed ARP receipt."""
    import arp

    captured: dict[str, dict] = {"last_call": {}}

    async def fake_emit(**kwargs):
        captured["last_call"] = kwargs
        return {
            "version": "arp/0.1",
            "receipt_id": "test-receipt-uuid-001",
            "issuer_did": "did:key:zTestChapter",
            "principal_did": "did:key:zTestChapter",  # self-attestation
            "issued_at": "2026-05-23T10:00:00Z",
            "action": {
                "category": "audit.chain.snapshot",
                "human_summary": "Audit chain snapshot — 42 events, tip abc123…",
                "outcome": "completed",
                "machine_payload": {
                    "tip_sha256": kwargs.get("tip_sha256"),
                    "chain_length": kwargs.get("chain_length"),
                    "snapshot_at": kwargs.get("snapshot_at"),
                    "first_occurred_at": kwargs.get("first_occurred_at"),
                    "last_occurred_at": kwargs.get("last_occurred_at"),
                },
            },
            "signature": "base64-ed25519-signature-here",
        }

    monkeypatch.setattr(arp, "emit_audit_chain_snapshot", fake_emit)
    return captured


# ══════════════════════════════════════════════════════════════════════
# AUTHZ + FAILURE + ADVERSARIAL come first
# ══════════════════════════════════════════════════════════════════════


def test_AUTHZ_attest_requires_admin(client, stub_arp_emit):
    """Unauthenticated → 401. Without the admin gate, anyone could spam
    chain attestations and pollute the chapter's ARP log."""
    resp = client.post("/admin/api/audit/attest")
    assert resp.status_code == 401


def test_AUTHZ_attest_rejects_wrong_token(client, admin_token, stub_arp_emit):
    resp = client.post(
        "/admin/api/audit/attest",
        headers={"X-Admin-Token": "wrong-token"},
    )
    assert resp.status_code == 401


def test_FAILURE_chain_tip_supabase_error_returns_503(client, admin_token, monkeypatch):
    """If chain_tip raises (Postgres down), return 503 — same shape as
    the other audit endpoints under /admin/api/."""
    import chapter_audit

    async def boom(chapter_id):
        raise RuntimeError("supabase timeout")

    monkeypatch.setattr(chapter_audit, "chain_tip", boom)

    resp = client.post(
        "/admin/api/audit/attest",
        headers={"X-Admin-Token": admin_token},
    )
    assert resp.status_code == 503
    assert "supabase timeout" in resp.json()["detail"]


def test_FAILURE_keypair_unavailable_returns_503(client, admin_token, stub_chain_state, monkeypatch):
    """If the chapter has no Ed25519 keypair loaded (boot ordering, test
    isolation), arp.emit_audit_chain_snapshot returns None. The endpoint
    must surface that as 503, not silently return an unsigned blob."""
    import arp

    async def no_keypair(**_kwargs):
        return None

    monkeypatch.setattr(arp, "emit_audit_chain_snapshot", no_keypair)

    resp = client.post(
        "/admin/api/audit/attest",
        headers={"X-Admin-Token": admin_token},
    )
    assert resp.status_code == 503
    assert "keypair" in resp.json()["error"].lower() or "sign" in resp.json()["error"].lower()


def test_ADVERSARIAL_no_unsigned_receipts_in_response(client, admin_token, stub_chain_state, monkeypatch):
    """If arp ever returns a receipt without a signature (bug, partial
    init, etc.), the endpoint must refuse to return it — auditors trust
    the signature, not the response."""
    import arp

    async def unsigned(**_kwargs):
        return {
            "version": "arp/0.1",
            "receipt_id": "fake",
            "action": {"category": "audit.chain.snapshot"},
            # Intentionally NO signature field
        }

    monkeypatch.setattr(arp, "emit_audit_chain_snapshot", unsigned)

    resp = client.post(
        "/admin/api/audit/attest",
        headers={"X-Admin-Token": admin_token},
    )
    # Must NOT return 200 with an unsigned receipt.
    assert resp.status_code == 503


# ══════════════════════════════════════════════════════════════════════
# EDGE
# ══════════════════════════════════════════════════════════════════════


def test_EDGE_empty_chain_still_attests_length_zero(client, admin_token, monkeypatch):
    """An empty audit chain is a legitimate state to attest — 'as of
    snapshot time, this chapter has emitted zero audit events'. Useful
    for fresh chapters that want a baseline commit."""
    import arp
    import chapter_audit

    async def empty_tip(chapter_id):
        return {"tip_sha256": "", "length": 0, "last_occurred_at": None, "first_occurred_at": None}

    captured = {}

    async def fake_emit(**kwargs):
        captured.update(kwargs)
        return {
            "version": "arp/0.1",
            "receipt_id": "empty-chain-receipt",
            "issuer_did": "did:key:zTestChapter",
            "principal_did": "did:key:zTestChapter",
            "issued_at": "2026-05-23T10:00:00Z",
            "action": {
                "category": "audit.chain.snapshot",
                "human_summary": "Audit chain snapshot — 0 events (empty chain)",
                "outcome": "completed",
                "machine_payload": {
                    "tip_sha256": "",
                    "chain_length": 0,
                    "snapshot_at": kwargs.get("snapshot_at"),
                },
            },
            "signature": "base64-sig",
        }

    monkeypatch.setattr(chapter_audit, "chain_tip", empty_tip)
    monkeypatch.setattr(arp, "emit_audit_chain_snapshot", fake_emit)

    resp = client.post(
        "/admin/api/audit/attest",
        headers={"X-Admin-Token": admin_token},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["action"]["machine_payload"]["chain_length"] == 0
    assert captured["chain_length"] == 0


# ══════════════════════════════════════════════════════════════════════
# HAPPY
# ══════════════════════════════════════════════════════════════════════


def test_HAPPY_attest_returns_signed_receipt(client, admin_token, stub_arp_emit):
    resp = client.post(
        "/admin/api/audit/attest",
        headers={"X-Admin-Token": admin_token},
    )
    assert resp.status_code == 200
    receipt = resp.json()
    assert receipt["version"] == "arp/0.1"
    assert receipt["action"]["category"] == "audit.chain.snapshot"
    assert receipt["signature"]  # non-empty


def test_HAPPY_machine_payload_carries_chain_state(client, admin_token, stub_arp_emit, stub_chain_state):
    """The receipt's machine_payload is the externally-verifiable claim:
    'as of snapshot_at, this chain has length=N and tip=H'."""
    resp = client.post(
        "/admin/api/audit/attest",
        headers={"X-Admin-Token": admin_token},
    )
    payload = resp.json()["action"]["machine_payload"]
    assert payload["tip_sha256"] == stub_chain_state["tip_sha256"]
    assert payload["chain_length"] == stub_chain_state["length"]
    assert payload["last_occurred_at"] == stub_chain_state["last_occurred_at"]
    assert "snapshot_at" in payload  # endpoint-set; we don't assert exact value


def test_HAPPY_self_attestation_invariant_issuer_equals_principal(client, admin_token, stub_arp_emit):
    """In a chain-snapshot attestation, the chapter is both issuer
    (signer) and principal (subject of the claim). This is the Signed
    Tree Head pattern — the entity attests to its own log state.
    Verifiers know to read this as self-commitment, not third-party
    evidence."""
    resp = client.post(
        "/admin/api/audit/attest",
        headers={"X-Admin-Token": admin_token},
    )
    receipt = resp.json()
    assert receipt["issuer_did"] == receipt["principal_did"]


def test_HAPPY_emit_called_with_chain_tip_values(client, admin_token, stub_arp_emit, stub_chain_state):
    """The endpoint passes the chain state through to arp unchanged.
    Any reshaping happens in arp (which knows the ARP receipt schema),
    not in the endpoint."""
    resp = client.post(
        "/admin/api/audit/attest",
        headers={"X-Admin-Token": admin_token},
    )
    assert resp.status_code == 200
    call = stub_arp_emit["last_call"]
    assert call["tip_sha256"] == stub_chain_state["tip_sha256"]
    assert call["chain_length"] == stub_chain_state["length"]
    assert call["last_occurred_at"] == stub_chain_state["last_occurred_at"]
