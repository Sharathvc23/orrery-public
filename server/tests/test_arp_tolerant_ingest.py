"""Tolerant chain ingest for foreign issuers (spec/arp/0.2 §0.6).

A chapter's Issuer Log is only a partial replica of a member's per-issuer hash
chain, so it cannot be the authority on that chain's completeness. The chapter
therefore:

  * strict-verifies chain continuity for its OWN receipts (it holds the full
    chain) and for any receipt whose prior it already holds; but
  * ACCEPTS a foreign (member-issued) receipt whose ``previous_receipt_hash``
    points at a prior the chapter doesn't hold — rather than rejecting a
    perfectly legitimate sovereign receipt.

Schema + signature are always strict regardless of issuer.

This avoids importing ``conformance.arp`` (an unrelated env may shadow it); it
drives the chapter's own ``arp.emit`` ingest path.
"""

from __future__ import annotations

import base64
import hashlib
import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import base58
import jcs
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class _FakePostgres:
    """Minimal Postgres stand-in: GET filters arp_receipts, POST appends."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def __call__(self, method, table, params=None, body=None):
        t = table.split("?")[0]
        if method == "GET" and t == "arp_receipts":
            out = list(self.rows)
            for k, v in (params or {}).items():
                if k in ("select", "order", "limit"):
                    continue
                out = [r for r in out if str(r.get(k, "")) == v.replace("eq.", "")]
            return out
        if method == "POST" and t == "arp_receipts":
            self.rows.append(dict(body))
            return [body]
        return None


def _did(pk_bytes: bytes) -> str:
    return "did:key:z" + base58.b58encode(b"\xed\x01" + pk_bytes).decode()


def _sign(receipt: dict, sk: Ed25519PrivateKey) -> dict:
    body = {k: v for k, v in receipt.items() if k != "signature"}
    receipt["signature"] = base64.b64encode(sk.sign(jcs.canonicalize(body))).decode()
    return receipt


def _receipt(sk: Ed25519PrivateKey, *, receipt_id: str, prev: str | None = None) -> dict:
    pk = sk.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    did = _did(pk)
    r: dict = {
        "version": "arp/0.1",
        "receipt_id": receipt_id,
        "issuer_did": did,
        "principal_did": did,
        "issued_at": "2026-06-07T00:00:00Z",
        "action": {"category": "message_sent", "human_summary": "hi", "outcome": "completed"},
    }
    if prev is not None:
        r["previous_receipt_hash"] = prev
    return _sign(r, sk)


@pytest.fixture
def chapter(tmp_path):
    import arp as arp_mod
    import sovereign_identity

    # Seed a deterministic chapter keypair so arp._chapter_keypair_bytes() resolves.
    sk = Ed25519PrivateKey.from_private_bytes(b"tolerant-ingest-chapter-seed-32!")
    pk_b = sk.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    sovereign_identity._ed25519_keypairs["test-chapter"] = {
        "private_key": sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        "public_key": pk_b,
    }
    fake = _FakePostgres()
    arp_mod.init(fake, "test-chapter", offline=False)
    chapter_did = arp_mod._chapter_keypair_bytes()[1]
    return arp_mod, sk, chapter_did


_BOGUS_PREV = "sha256:" + "00" * 32


async def test_foreign_receipt_with_unknown_prior_is_accepted(chapter) -> None:
    arp_mod, _chapter_sk, _chapter_did = chapter
    member_sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"sovereign-member").digest())
    r = _receipt(member_sk, receipt_id="11111111-1111-4111-8111-111111111111", prev=_BOGUS_PREV)
    res = await arp_mod.emit(r)
    assert res.ok, f"foreign receipt with unknown prior should be tolerated, got {res.stage}: {res.detail}"


async def test_own_receipt_with_unknown_prior_is_rejected(chapter) -> None:
    arp_mod, chapter_sk, _chapter_did = chapter
    r = _receipt(chapter_sk, receipt_id="22222222-2222-4222-8222-222222222222", prev=_BOGUS_PREV)
    res = await arp_mod.emit(r)
    assert not res.ok and res.stage == "hash_chain", f"own chain must be strict, got {res.stage}"


async def test_foreign_receipt_bad_signature_still_rejected(chapter) -> None:
    arp_mod, _chapter_sk, _chapter_did = chapter
    member_sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"sovereign-member").digest())
    r = _receipt(member_sk, receipt_id="33333333-3333-4333-8333-333333333333", prev=_BOGUS_PREV)
    r["action"]["human_summary"] = "tampered after signing"  # break signature
    res = await arp_mod.emit(r)
    assert not res.ok and res.stage == "signature", "signature is always strict, even for foreign issuers"
