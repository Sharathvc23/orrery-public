"""RFC 6962 Merkle proofs — inclusion + consistency.

INCLUSION    every leaf in trees of size 1..17 has a proof that verifies
TAMPER       a tampered leaf / wrong index does not verify
CONSISTENCY  every prefix m of an n-tree has a consistency proof that verifies
NON-PREFIX   a forged old-root is rejected (append-only is enforced)
"""

from __future__ import annotations

import hashlib

from merkle import (
    consistency_proof,
    inclusion_proof,
    merkle_root,
    verify_consistency,
    verify_inclusion,
)


def _leaves(n: int) -> list[bytes]:
    return [f"leaf-{i}".encode() for i in range(n)]


def test_inclusion_proofs_verify_all_sizes():
    for n in range(1, 18):
        leaves = _leaves(n)
        root = merkle_root(leaves)
        for m in range(n):
            proof = inclusion_proof(leaves, m)
            assert verify_inclusion(leaf=leaves[m], leaf_index=m, tree_size=n, proof=proof, root=root), (
                f"size={n} index={m}"
            )


def test_tampered_leaf_fails():
    leaves = _leaves(7)
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, 3)
    assert not verify_inclusion(leaf=b"tampered", leaf_index=3, tree_size=7, proof=proof, root=root)


def test_wrong_index_fails():
    leaves = _leaves(7)
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, 3)
    assert not verify_inclusion(leaf=leaves[4], leaf_index=4, tree_size=7, proof=proof, root=root)


def test_consistency_proofs_verify_all():
    for n in range(2, 18):
        leaves = _leaves(n)
        new_root = merkle_root(leaves)
        for m in range(1, n + 1):
            old_root = merkle_root(leaves[:m])
            proof = consistency_proof(leaves, m)
            assert verify_consistency(old_size=m, new_size=n, old_root=old_root, new_root=new_root, proof=proof), (
                f"n={n} m={m}"
            )


def test_consistency_rejects_non_prefix():
    leaves = _leaves(8)
    new_root = merkle_root(leaves)
    forged = _leaves(8)
    forged[0] = b"rewritten-history"
    bad_old_root = merkle_root(forged[:4])
    proof = consistency_proof(leaves, 4)
    assert not verify_consistency(old_size=4, new_size=8, old_root=bad_old_root, new_root=new_root, proof=proof)


def test_empty_and_single():
    assert merkle_root([]) == hashlib.sha256(b"").digest()
    leaves = _leaves(1)
    root = merkle_root(leaves)
    assert verify_inclusion(leaf=leaves[0], leaf_index=0, tree_size=1, proof=[], root=root)
