"""Member-side verification of a chapter's Merkle checkpoint + inclusion proof.

ARP's forward tamper-evidence (the per-issuer hash chain) lets a verifier detect
*mutation* of a known log. This is the reverse seam: a member proves its OWN
receipt is committed under its chapter's signed checkpoint — offline — and so can
DETECT a chapter that silently drops or omits it. The audit runs in the direction
that protects the principal: the member auditing the chapter, not the other way.

Inputs match exactly what the chapter serves:
* ``/api/checkpoint`` → ``{"payload": {... "merkle_root": "sha256:<hex>",
  "tree_size": N ...}, "signer_did": <chapter did:key>, "signature": <b64>}``
* ``/api/checkpoint/proof/{receipt_id}`` → ``{"leaf_index", "tree_size",
  "merkle_root": "sha256:<hex>", "proof": [<hex>, ...]}``

The Merkle leaf is the JCS-canonical bytes of the full receipt (including its
signature) — identical to the chapter's ``checkpoint_leaves``. Inclusion is
checked with the vendored canonical RFC 6962 verifier (``_merkle``).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._merkle import verify_inclusion

_DID_PREFIX = b"\xed\x01"


def _pubkey_from_did(did_key: str) -> Ed25519PublicKey:
    import base58

    if not did_key.startswith("did:key:z"):
        raise ValueError(f"unsupported DID method: {did_key!r}")
    decoded = base58.b58decode(did_key[len("did:key:z") :])
    if len(decoded) != 34 or decoded[:2] != _DID_PREFIX:
        raise ValueError("not a did:key Ed25519 record")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def _root_bytes(root: str) -> bytes:
    """Decode a ``sha256:<hex>`` (or bare hex) root to raw bytes."""
    return bytes.fromhex(root[len("sha256:") :] if root.startswith("sha256:") else root)


def receipt_leaf(receipt: dict[str, Any]) -> bytes:
    """The Merkle leaf for a receipt: JCS-canonical bytes of the FULL receipt
    (including its signature) — matches the chapter's ``checkpoint_leaves``."""
    return jcs.canonicalize(receipt)


def verify_checkpoint_signature(checkpoint: dict[str, Any]) -> bool:
    """True iff the checkpoint's Ed25519 signature verifies under its signer DID
    over the JCS-canonical payload."""
    payload = checkpoint.get("payload")
    signer = checkpoint.get("signer_did") or (payload or {}).get("signer_did")
    sig_b64 = checkpoint.get("signature")
    if not isinstance(payload, dict) or not signer or not sig_b64:
        return False
    try:
        _pubkey_from_did(signer).verify(base64.b64decode(sig_b64), jcs.canonicalize(payload))
    except Exception:
        return False
    return True


@dataclass
class MembershipResult:
    ok: bool
    stage: str  # checkpoint_signature | root_mismatch | not_included | accepted
    detail: str

    @classmethod
    def accepted(cls) -> MembershipResult:
        return cls(True, "accepted", "receipt is committed by the chapter's signed checkpoint")


def verify_membership(
    receipt: dict[str, Any],
    *,
    checkpoint: dict[str, Any],
    proof: dict[str, Any],
) -> MembershipResult:
    """Prove ``receipt`` is committed under the chapter's signed checkpoint.

    Three gates, in order: the checkpoint signature must verify; the inclusion
    proof must commit to the SAME root the chapter signed (else a valid proof
    could be paired with an unsigned root); and the receipt's leaf must be
    included under that root. A failure at any gate names the stage, so a member
    can tell "the chapter's commitment is forged" from "my receipt was omitted".
    """
    if not verify_checkpoint_signature(checkpoint):
        return MembershipResult(False, "checkpoint_signature", "checkpoint signature does not verify")

    signed_root = checkpoint.get("payload", {}).get("merkle_root")
    if not signed_root or proof.get("merkle_root") != signed_root:
        return MembershipResult(
            False, "root_mismatch", "inclusion proof's root does not match the signed checkpoint root"
        )

    included = verify_inclusion(
        leaf=receipt_leaf(receipt),
        leaf_index=int(proof["leaf_index"]),
        tree_size=int(proof["tree_size"]),
        proof=[bytes.fromhex(p) for p in proof.get("proof", [])],
        root=_root_bytes(signed_root),
    )
    if not included:
        return MembershipResult(False, "not_included", "receipt is not committed under the signed root")
    return MembershipResult.accepted()


__all__ = [
    "MembershipResult",
    "receipt_leaf",
    "verify_checkpoint_signature",
    "verify_membership",
]
