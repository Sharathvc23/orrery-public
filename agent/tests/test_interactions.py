"""Phase 2 — auto-emit ARP receipts on agent↔service interactions.

HAPPY    record_interaction writes a signed receipt naming the counterparty
WIRING   send_task_recorded auto-emits on a successful A2A call
FAILURE  a failed A2A call records NOTHING (a receipt attests a real action)
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from community_member.arp import AgencyLog, did_from_private_key, verify_receipt_signature
from community_member.interactions import record_interaction


def _key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes_raw()


def _cp_did() -> str:
    return did_from_private_key(_key())


def test_record_interaction_emits_signed_receipt_with_counterparty(tmp_path):
    sk = _key()
    log = AgencyLog(home=tmp_path / "agency")
    cp = _cp_did()

    r = record_interaction(
        sk_bytes=sk,
        agency_log=log,
        counterparty_did=cp,
        counterparty_label="arxiv-rag-attention",
        summary="Queried the Attention RAG agent about scaling laws.",
        category="data_shared",
    )

    assert r["action"]["counterparty_did"] == cp
    assert r["action"]["counterparty_label"] == "arxiv-rag-attention"
    assert r["action"]["category"] == "data_shared"
    assert verify_receipt_signature(r)  # signed and verifies
    assert any(x["receipt_id"] == r["receipt_id"] for x in log.list_recent(limit=10))


async def test_send_task_recorded_emits_on_success(tmp_path, monkeypatch):
    from community_member.a2a_client_v2 import AsyncGoogleA2AClient

    sk = _key()
    log = AgencyLog(home=tmp_path / "agency")
    cp = _cp_did()
    client = AsyncGoogleA2AClient("http://svc.test", agent_id="me")

    async def fake_send_task(tool, args, **_kw):
        return {"result": "ok"}

    monkeypatch.setattr(client, "send_task", fake_send_task)

    result = await client.send_task_recorded(
        "query",
        {"q": "scaling laws"},
        counterparty_did=cp,
        counterparty_label="arxiv-rag-bert",
        sk_bytes=sk,
        agency_log=log,
        category="data_shared",
    )
    await client.aclose()

    assert result == {"result": "ok"}
    rows = log.list_recent(limit=10)
    assert len(rows) == 1
    assert rows[0]["action"]["counterparty_did"] == cp
    assert rows[0]["action"]["category"] == "data_shared"


async def test_send_task_recorded_records_nothing_on_failure(tmp_path, monkeypatch):
    from community_member.a2a_client_v2 import AsyncGoogleA2AClient

    sk = _key()
    log = AgencyLog(home=tmp_path / "agency")
    client = AsyncGoogleA2AClient("http://svc.test", agent_id="me")

    async def boom(tool, args, **_kw):
        raise RuntimeError("service unreachable")

    monkeypatch.setattr(client, "send_task", boom)

    with pytest.raises(RuntimeError):
        await client.send_task_recorded(
            "query",
            {},
            counterparty_did=_cp_did(),
            counterparty_label="down-service",
            sk_bytes=sk,
            agency_log=log,
        )
    await client.aclose()

    assert log.list_recent(limit=10) == []  # no receipt for a call that didn't happen


def test_send_task_recorded_sync_emits_on_success(tmp_path, monkeypatch):
    """Parity: the sync client records exactly like the async one. The class
    promises "Same surface as GoogleA2AClient", so send_task_recorded must
    exist and behave identically on both."""
    from community_member.a2a_client_v2 import GoogleA2AClient

    sk = _key()
    log = AgencyLog(home=tmp_path / "agency")
    cp = _cp_did()
    client = GoogleA2AClient("http://svc.test", agent_id="me")

    def fake_send_task(tool, args, **_kw):
        return {"result": "ok"}

    monkeypatch.setattr(client, "send_task", fake_send_task)

    result = client.send_task_recorded(
        "query",
        {"q": "scaling laws"},
        counterparty_did=cp,
        counterparty_label="arxiv-rag-bert",
        sk_bytes=sk,
        agency_log=log,
        category="data_shared",
    )
    client.close()

    assert result == {"result": "ok"}
    rows = log.list_recent(limit=10)
    assert len(rows) == 1
    assert rows[0]["action"]["counterparty_did"] == cp
    assert rows[0]["action"]["category"] == "data_shared"


def test_send_task_recorded_sync_records_nothing_on_failure(tmp_path, monkeypatch):
    from community_member.a2a_client_v2 import GoogleA2AClient

    sk = _key()
    log = AgencyLog(home=tmp_path / "agency")
    client = GoogleA2AClient("http://svc.test", agent_id="me")

    def boom(tool, args, **_kw):
        raise RuntimeError("service unreachable")

    monkeypatch.setattr(client, "send_task", boom)

    with pytest.raises(RuntimeError):
        client.send_task_recorded(
            "query",
            {},
            counterparty_did=_cp_did(),
            counterparty_label="down-service",
            sk_bytes=sk,
            agency_log=log,
        )
    client.close()

    assert log.list_recent(limit=10) == []  # no receipt for a call that didn't happen
