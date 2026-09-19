"""Phase 2 — the member verifies the chapter's Merkle checkpoint + inclusion proof.

The reverse-audit seam, landing on the party it protects. The chapter signs a
checkpoint committing to its Issuer Log by RFC 6962 Merkle root and serves an
inclusion proof per receipt. With this, a sovereign member can prove its OWN
receipt is committed under that signed root — offline — and DETECT a chapter that
drops or omits it (the proof won't verify, or the chapter can't produce one).

Classification:
  HAPPY        — the member's receipt is included under the signed root → accepted
  EDGE         — single-leaf tree (empty proof) verifies
  ADVERSARIAL  — tampered checkpoint signature → checkpoint_signature
  ADVERSARIAL  — proof root != the signed checkpoint root → root_mismatch
  ADVERSARIAL  — a receipt that isn't in the tree → not_included
"""

from __future__ import annotations

import base64
import hashlib
import os
import tempfile

os.environ.setdefault(
    "COMMUNITY_MEMBER_HOME",
    os.path.join(tempfile.gettempdir(), "cm-checkpoint-tests-do-not-use"),
)

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from community_member._merkle import inclusion_proof, merkle_root
from community_member.arp import build_receipt, did_from_private_key, sign_receipt
from community_member.checkpoint import verify_checkpoint_signature, verify_membership

MEMBER_SK = hashlib.sha256(b"checkpoint-member").digest()
CHAPTER_SK = hashlib.sha256(b"checkpoint-chapter").digest()
CHAPTER_DID = did_from_private_key(CHAPTER_SK)


def _receipt(n: int) -> dict:
    did = did_from_private_key(MEMBER_SK)
    r = build_receipt(
        action={"category": "message_sent", "human_summary": f"msg {n}", "outcome": "completed"},
        issuer_did=did,
        principal_did=did,
        issued_at=f"2026-06-07T00:00:0{n}Z",
    )
    return sign_receipt(r, MEMBER_SK)


def _chapter_checkpoint(receipts: list[dict]) -> dict:
    """Mimic chapter/arp.build_checkpoint: sign the RFC 6962 root over the
    JCS-canonical full receipts."""
    leaves = [jcs.canonicalize(r) for r in receipts]
    root = merkle_root(leaves)
    payload = {
        "version": "aae-checkpoint/0.1",
        "type": "checkpoint",
        "signer_did": CHAPTER_DID,
        "created_at": "2026-06-07T00:00:10Z",
        "tree_size": len(receipts),
        "merkle_root": "sha256:" + root.hex(),
        "receipt_ids": [r["receipt_id"] for r in receipts],
    }
    sig = Ed25519PrivateKey.from_private_bytes(CHAPTER_SK).sign(jcs.canonicalize(payload))
    return {"payload": payload, "signer_did": CHAPTER_DID, "signature": base64.b64encode(sig).decode()}


def _proof_for(receipts: list[dict], idx: int) -> dict:
    leaves = [jcs.canonicalize(r) for r in receipts]
    return {
        "receipt_id": receipts[idx]["receipt_id"],
        "leaf_index": idx,
        "tree_size": len(receipts),
        "merkle_root": "sha256:" + merkle_root(leaves).hex(),
        "proof": [p.hex() for p in inclusion_proof(leaves, idx)],
    }


def test_member_receipt_committed_verifies() -> None:
    receipts = [_receipt(i) for i in range(5)]
    cp = _chapter_checkpoint(receipts)
    res = verify_membership(receipts[2], checkpoint=cp, proof=_proof_for(receipts, 2))
    assert res.ok and res.stage == "accepted"


def test_single_leaf_tree_verifies() -> None:
    receipts = [_receipt(0)]
    cp = _chapter_checkpoint(receipts)
    res = verify_membership(receipts[0], checkpoint=cp, proof=_proof_for(receipts, 0))
    assert res.ok and res.stage == "accepted"


def test_valid_checkpoint_signature() -> None:
    receipts = [_receipt(i) for i in range(3)]
    assert verify_checkpoint_signature(_chapter_checkpoint(receipts)) is True


def test_tampered_checkpoint_signature_rejected() -> None:
    receipts = [_receipt(i) for i in range(3)]
    cp = _chapter_checkpoint(receipts)
    cp["payload"]["tree_size"] = 99  # mutate signed payload
    res = verify_membership(receipts[0], checkpoint=cp, proof=_proof_for(receipts, 0))
    assert not res.ok and res.stage == "checkpoint_signature"


def test_proof_root_not_matching_checkpoint_rejected() -> None:
    receipts = [_receipt(i) for i in range(4)]
    cp = _chapter_checkpoint(receipts)
    proof = _proof_for(receipts, 1)
    proof["merkle_root"] = "sha256:" + "0" * 64  # proof claims a different root
    res = verify_membership(receipts[1], checkpoint=cp, proof=proof)
    assert not res.ok and res.stage == "root_mismatch"


def test_receipt_not_in_tree_rejected() -> None:
    receipts = [_receipt(i) for i in range(4)]
    cp = _chapter_checkpoint(receipts)
    outsider = _receipt(99)  # never committed
    # present it with a (valid-shaped) proof slot — inclusion must fail
    res = verify_membership(outsider, checkpoint=cp, proof=_proof_for(receipts, 0))
    assert not res.ok and res.stage == "not_included"
