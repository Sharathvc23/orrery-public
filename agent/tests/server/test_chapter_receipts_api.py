"""Tests for /api/chapter/receipts — the chapter-side view of your receipts.

The endpoint proxies a signed, principal-scoped read of the home chapter's
``GET /api/receipts`` (spec/arp/0.1 §10.1). Its contract is that it must NEVER
conflate "could not ask the chapter" with "the chapter has nothing for you" —
a silent failure there would tell the user "no receipts" when the truth is the
request failed.

Coverage map:

  R1  HAPPY      — chapter returns receipts → returned with `source`, no error
  R2  EDGE       — chapter returns a genuinely empty list → empty, NO error
                   (honest empty must stay honest; no over-eager erroring)
  R3  FAILURE    — chapter is unreachable (`_get` raises) → `error` is surfaced
                   and receipts is empty (regression guard against `except: pass`)
  R4  ADVERSARIAL— chapter declines with an error body (`{"detail": ...}`) →
                   the chapter's reason is surfaced, not masqueraded as empty

R3 and R4 fail against the previous `except Exception: pass` implementation,
which is exactly the bug they pin.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from community_member import keystore, server
from community_member.config import Config
from community_member.server import create_app


@pytest.fixture
def tmp_env(tmp_path: Path, monkeypatch):
    from community_member import config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    keystore.reset_for_tests(dir_override=tmp_path)
    yield tmp_path
    keystore.reset_for_tests()


@pytest.fixture
def cfg(tmp_env) -> Config:
    c = Config()
    c.agent_id = "alice"
    c.chapter_url = "https://chapter.example/"
    c.private_key = "dummy-priv"
    c.public_key = "dummy-pub"
    return c


@pytest.fixture
def client(cfg) -> TestClient:
    return TestClient(create_app(cfg, agent=None))


class _StubClient:
    """Stands in for the A2AClient; `_get` does whatever the test needs."""

    def __init__(self, behavior):
        self._behavior = behavior

    def _get(self, path: str, timeout: float = 10.0):
        return self._behavior(path)


def _install_client(monkeypatch, behavior) -> None:
    monkeypatch.setattr(server, "_client", _StubClient(behavior))


_RECEIPT = {
    "receipt_id": "r-1",
    "version": "arp/0.1",
    "issued_at": "2026-06-05T00:00:00Z",
    "issuer_did": "did:key:zAlice",
    "principal_did": "did:key:zAlice",
    "signature": "sig",
    "action": {"category": "message_sent"},
}


# R1 — HAPPY ─────────────────────────────────────────────────────────────────
def test_receipts_returned_with_source(client, monkeypatch):
    _install_client(monkeypatch, lambda path: {"receipts": [_RECEIPT]})
    resp = client.get("/api/chapter/receipts")
    assert resp.status_code == 200
    data = resp.json()
    assert [r["receipt_id"] for r in data["receipts"]] == ["r-1"]
    # trailing slash on chapter_url is normalised
    assert data["source"] == "https://chapter.example"
    assert not data.get("error")


# R2 — EDGE: honest empty stays honest ───────────────────────────────────────
def test_genuinely_empty_has_no_error(client, monkeypatch):
    _install_client(monkeypatch, lambda path: {"receipts": []})
    data = client.get("/api/chapter/receipts").json()
    assert data["receipts"] == []
    assert not data.get("error"), "an enrolled-but-empty result must not show an error"


# R5 — HAPPY: corroboration classified the same as the local Agency Log ────────
def test_corroboration_map_classifies_chapter_receipts(client, monkeypatch):
    import os

    from community_member.arp import build_receipt, did_from_private_key, sign_receipt
    from community_member.cosign import make_witness

    a, b = os.urandom(32), os.urandom(32)

    def _r(rid: str, corroborated: bool) -> dict:
        issuer = did_from_private_key(a)
        action = {
            "category": "message_sent",
            "outcome": "completed",
            "counterparty_did": did_from_private_key(b),
            "counterparty_label": "B",
        }
        r = build_receipt(action=action, issuer_did=issuer, principal_did=issuer, receipt_id=rid)
        if corroborated:  # witness inserted before the issuer signs (cosign-companion §1)
            r["evidence"] = {"witness_signatures": [make_witness(r, sk_bytes=b)]}
        sign_receipt(r, a)
        return r

    _install_client(monkeypatch, lambda path: {"receipts": [_r("rc", True), _r("ru", False)]})
    data = client.get("/api/chapter/receipts").json()
    assert data["corroboration"] == {"rc": True, "ru": False}


# R3 — FAILURE: unreachable must surface, not fake-empty ──────────────────────
def test_unreachable_chapter_surfaces_error_not_empty(client, monkeypatch):
    def _boom(path):
        raise ConnectionError("connection refused")

    _install_client(monkeypatch, _boom)
    data = client.get("/api/chapter/receipts").json()
    assert data["receipts"] == []
    assert data.get("error"), "unreachable chapter must be reported, not shown as empty"
    assert "connection refused" in data["error"]


# R4 — ADVERSARIAL: a declined request must surface the chapter's reason ──────
def test_declined_request_surfaces_chapter_reason(client, monkeypatch):
    _install_client(monkeypatch, lambda path: {"detail": "not enrolled at this chapter"})
    data = client.get("/api/chapter/receipts").json()
    assert data["receipts"] == []
    assert data.get("error"), "an error body must not be silently dropped to empty"
    assert "not enrolled" in data["error"]
