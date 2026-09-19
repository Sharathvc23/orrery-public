"""/api/reputation-ledger — the member's OWN corroborated standing, computed
LOCALLY from the Agency Log (sovereignty: never asks the chapter).

Returns the AgentFacts ``verifiable_receipts`` facet for the requested scoring
method, computed by the published ``sm_arp.vrp`` math over the local receipts —
the same number a chapter or resolver would derive. nanda-rep/0.2 (corroborated)
by default; nanda-rep/0.1 (self-attested) on request.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from community_member import config as config_mod
from community_member import keystore
from community_member.arp import AgencyLog, build_receipt, did_from_private_key, sign_receipt
from community_member.config import Config
from community_member.cosign import make_witness
from community_member.server import create_app

_A = os.urandom(32)  # the member (issuer + principal)
_B = os.urandom(32)  # counterparty / witness
_PUB_A = base64.b64encode(
    Ed25519PrivateKey.from_private_bytes(_A).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
).decode()


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
def make_client(tmp_path: Path, monkeypatch):
    """Factory: build a dashboard TestClient over a fresh Agency Log seeded with
    ``receipts``, with the given ``public_key`` (defaults to the real pubkey of
    _A, so the derived subject did:key matches the seeded receipts' principal)."""

    def _make(*, public_key: str = _PUB_A, receipts=(), subdir: str = "m") -> TestClient:
        home = tmp_path / subdir
        home.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(config_mod, "CONFIG_DIR", home)
        keystore.reset_for_tests(dir_override=home)
        log = AgencyLog(home=home)
        for r in receipts:
            log.append(r)
        cfg = Config()
        cfg.agent_id = "alice"
        cfg.chapter_url = "https://chapter.example/"
        cfg.private_key = "dummy-priv"
        cfg.public_key = public_key
        return TestClient(create_app(cfg))

    yield _make
    keystore.reset_for_tests()


# ── HAPPY ─────────────────────────────────────────────────────


def test_corroborated_standing_computed_locally(make_client):  # HAPPY
    c = make_client(receipts=[_receipt(1, corroborated=True), _receipt(2, corroborated=False)])
    body = c.get("/api/reputation-ledger").json()
    assert "error" not in body
    assert body["method"] == "nanda-rep/0.2"
    assert body["subject_did"] == did_from_private_key(_A)
    facet = body["facet"]
    assert facet["behavioral_merkle_root"]
    assert facet["receipt_count"] == 2
    assert facet["corroboration_rate"] == 0.5  # 1 of 2 co-signed
    assert facet["reputation_score"] > 0  # the corroborated receipt scores


# ── EDGE ──────────────────────────────────────────────────────


def test_self_attested_method_scores_uncorroborated(make_client):  # EDGE
    # nanda-rep/0.1 ignores corroboration → even un-co-signed receipts score.
    c = make_client(receipts=[_receipt(1, corroborated=False), _receipt(2, corroborated=False)])
    body = c.get("/api/reputation-ledger?method=nanda-rep/0.1").json()
    assert body["method"] == "nanda-rep/0.1"
    assert body["facet"]["reputation_score"] > 0


def test_corroborated_method_is_zero_without_cosign(make_client):  # EDGE
    # nanda-rep/0.2: an uncorroborated receipt earns zero (VRP 0.3 §C).
    c = make_client(receipts=[_receipt(1, corroborated=False)])
    facet = c.get("/api/reputation-ledger?method=nanda-rep/0.2").json()["facet"]
    assert facet["reputation_score"] == 0
    assert facet["corroboration_rate"] == 0


def test_empty_log_has_no_standing(make_client):  # EDGE
    facet = make_client(receipts=[]).get("/api/reputation-ledger").json()["facet"]
    assert not facet.get("behavioral_merkle_root")  # nothing to show → UI renders empty state


# ── FAILURE ───────────────────────────────────────────────────


def test_unsupported_method_rejected(make_client):  # FAILURE
    c = make_client(receipts=[_receipt(1, corroborated=True)])
    body = c.get("/api/reputation-ledger?method=nanda-rep/9.9").json()
    assert "error" in body and "facet" not in body


def test_missing_identity_reported(make_client):  # FAILURE
    body = make_client(public_key="", receipts=[_receipt(1, corroborated=True)]).get("/api/reputation-ledger").json()
    assert "error" in body and "identity" in body["error"].lower()


# ── ADVERSARIAL ──────────────────────────────────────────────


def test_unparseable_public_key_reported_not_500(make_client):  # ADVERSARIAL
    c = make_client(public_key="!!!not-base64!!!", receipts=[_receipt(1, corroborated=True)])
    resp = c.get("/api/reputation-ledger")
    assert resp.status_code == 200  # graceful — a bad key must not crash the dashboard
    assert "error" in resp.json()
