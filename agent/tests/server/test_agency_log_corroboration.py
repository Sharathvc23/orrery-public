"""/api/agency-log/receipts must classify each receipt's corroboration for the UI.

The endpoint returns a ``corroboration`` map (receipt_id -> bool) computed by the
authoritative vendored verifier, so the web's "corroborated" badge can never drift
from what actually scores under nanda-rep/0.2. Receipts themselves stay pristine.

Classification: HAPPY / EDGE.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from community_member import config as config_mod
from community_member import keystore
from community_member.arp import AgencyLog, build_receipt, did_from_private_key, sign_receipt
from community_member.config import Config
from community_member.cosign import make_witness
from community_member.server import create_app

_A = os.urandom(32)  # issuer
_B = os.urandom(32)  # counterparty


def _receipt(n: int, *, corroborated: bool) -> dict:
    issuer = did_from_private_key(_A)
    action = {
        "category": "message_sent",
        "human_summary": f"r{n}",
        "outcome": "completed",
        "counterparty_did": did_from_private_key(_B),
        "counterparty_label": "B",
    }
    r = build_receipt(
        action=action, issuer_did=issuer, principal_did=issuer, receipt_id=f"{n:08d}-1111-4111-8111-111111111111"
    )
    if corroborated:  # witness inserted BEFORE the issuer signs (cosign-companion §1)
        r["evidence"] = {"witness_signatures": [make_witness(r, sk_bytes=_B)]}
    sign_receipt(r, _A)
    return r


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    keystore.reset_for_tests(dir_override=tmp_path)
    log = AgencyLog(home=tmp_path)
    log.append(_receipt(1, corroborated=True))
    log.append(_receipt(2, corroborated=False))
    cfg = Config()
    cfg.agent_id = "alice"
    cfg.chapter_url = "https://chapter.example/"
    cfg.private_key = "dummy-priv"
    cfg.public_key = "dummy-pub"
    try:
        yield TestClient(create_app(cfg))
    finally:
        keystore.reset_for_tests()


def test_corroboration_map_classifies_each_receipt(client):  # HAPPY
    resp = client.get("/api/agency-log/receipts")
    assert resp.status_code == 200
    body = resp.json()
    corr = body["corroboration"]
    assert corr["00000001-1111-4111-8111-111111111111"] is True  # co-signed
    assert corr["00000002-1111-4111-8111-111111111111"] is False  # named CP, not co-signed
    # Receipts are returned pristine — corroboration is a sibling, not an envelope field.
    for r in body["receipts"]:
        assert "corroborated" not in r and "_corroborated" not in r


def test_empty_log_has_empty_corroboration(client, tmp_path, monkeypatch):  # EDGE
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path / "empty")
    resp = client.get("/api/agency-log/receipts")
    assert resp.status_code == 200
    assert resp.json()["corroboration"] == {}
