"""RFC 6962 Merkle tree — reverse-audit proofs over the ARP Issuer Log.

ARP gives *forward* tamper-evidence
via the per-issuer hash chain; this adds the *reverse* seam: "prove this receipt
is included under a signed commitment, without handing over the whole log." A
notary/auditor (here, the chapter) signs a checkpoint anchoring an RFC 6962
Merkle tree over the receipts; any holder of a receipt + its inclusion proof +
the signed root verifies membership offline. Consistency proofs additionally
show the log is append-only (an old root is a prefix of a new one).

Pure functions over raw leaf bytes; domain-separated leaf/node hashes per
RFC 6962 §2.1. The checkpoint *envelope* (signing) lives with the chapter keypair.
"""

from __future__ import annotations

import hashlib


def _leaf_hash(data: bytes) -> bytes:
    # RFC 6962 §2.1: MTH of a single leaf is SHA-256(0x00 || data).
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    # RFC 6962 §2.1: interior node is SHA-256(0x01 || left || right).
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_pow2_lt(n: int) -> int:
    """Largest power of two strictly less than n (n > 1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over raw leaf data."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return _leaf_hash(leaves[0])
    k = _largest_pow2_lt(n)
    return _node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves: list[bytes], m: int) -> list[bytes]:
    """RFC 6962 audit path for leaf index ``m`` in the tree over ``leaves``."""
    n = len(leaves)
    if not 0 <= m < n:
        raise IndexError(f"leaf index {m} out of range for size {n}")
    if n == 1:
        return []
    k = _largest_pow2_lt(n)
    if m < k:
        return inclusion_proof(leaves[:k], m) + [merkle_root(leaves[k:])]
    return inclusion_proof(leaves[k:], m - k) + [merkle_root(leaves[:k])]


def verify_inclusion(*, leaf: bytes, leaf_index: int, tree_size: int, proof: list[bytes], root: bytes) -> bool:
    """RFC 6962 inclusion-proof verification (the Trillian reference algorithm)."""
    if leaf_index >= tree_size:
        return False
    fn, sn = leaf_index, tree_size - 1
    r = _leaf_hash(leaf)
    for p in proof:
        if fn == sn or (fn & 1):
            r = _node_hash(p, r)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def _subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if b else [merkle_root(leaves)]
    k = _largest_pow2_lt(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [merkle_root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [merkle_root(leaves[:k])]


def consistency_proof(leaves: list[bytes], m: int) -> list[bytes]:
    """Prove the size-``m`` tree is a prefix of the size-``len(leaves)`` tree."""
    n = len(leaves)
    if not 0 < m <= n:
        raise ValueError(f"need 0 < m <= n; got m={m}, n={n}")
    if m == n:
        return []
    return _subproof(m, leaves, True)


def verify_consistency(*, old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]) -> bool:
    """RFC 6962 consistency-proof verification: old tree is a prefix of new."""
    if old_size > new_size:
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0:
        return not proof

    nodes = list(proof)
    if old_size & (old_size - 1) == 0:  # old_size is a power of two
        nodes = [old_root] + nodes
    if not nodes:
        return False

    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = sr = nodes[0]
    for c in nodes[1:]:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            fr = _node_hash(c, fr)
            sr = _node_hash(c, sr)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = _node_hash(sr, c)
        fn >>= 1
        sn >>= 1

    return fr == old_root and sr == new_root and sn == 0
