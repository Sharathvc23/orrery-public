"""Phase 2 — the member can VERIFY delegated authority (DATs), not just emit receipts.

A DAT records what an agent was *allowed* to do, signed by the grantor (operator →
chapter → member), never self-claimed. Before this, the member had no way to check
"is this counterparty actually authorized by its principal to do this?" — it could
only trust its chapter. ``community_member.dat`` gives the member the canonical DAT
verifier (vendored from ``conformance/dat``) plus a local store to hold and present
the DAT its principal granted it.

Classification:
  HAPPY        — a valid single DAT verifies (grantee, in-scope category, in window)
  EDGE         — a 2-hop chain (operator → chapter → member) verifies at the leaf
  ADVERSARIAL  — forged signature / expired window / out-of-scope / scope-widening / revoked
  HAPPY        — DatStore holds the member's granted DAT and presents it back
"""

from __future__ import annotations

import hashlib
import os
import tempfile

os.environ.setdefault(
    "COMMUNITY_MEMBER_HOME",
    os.path.join(tempfile.gettempdir(), "cm-dat-tests-do-not-use"),
)

from community_member.arp import did_from_private_key
from community_member.dat import (
    DatStore,
    build_dat,
    verify_counterparty_dat,
)

OP_SK = hashlib.sha256(b"operator").digest()
CH_SK = hashlib.sha256(b"chapter").digest()
ME_SK = hashlib.sha256(b"member").digest()
OP_DID = did_from_private_key(OP_SK)
CH_DID = did_from_private_key(CH_SK)
ME_DID = did_from_private_key(ME_SK)

PAST = "2020-01-01T00:00:00Z"
FUTURE = "2099-01-01T00:00:00Z"
NOW = "2026-06-07T00:00:00Z"


def _grant(grantor_sk, grantor_did, grantee_did, cats, *, not_after=FUTURE, not_before=PAST, granted_by=None):
    return build_dat(
        grantor_sk_bytes=grantor_sk,
        grantor_did=grantor_did,
        grantee_did=grantee_did,
        action_categories=cats,
        not_after=not_after,
        not_before=not_before,
        granted_by=granted_by,
    )


def test_valid_single_dat_verifies() -> None:
    dat = _grant(OP_SK, OP_DID, ME_DID, ["payment_sent"])
    res = verify_counterparty_dat(dat, now=NOW, category="payment_sent")
    assert res.ok and res.stage == "accepted"


def test_out_of_scope_category_rejected() -> None:
    dat = _grant(OP_SK, OP_DID, ME_DID, ["message_sent"])
    res = verify_counterparty_dat(dat, now=NOW, category="payment_sent")
    assert not res.ok and res.stage == "scope"


def test_expired_dat_rejected() -> None:
    dat = _grant(OP_SK, OP_DID, ME_DID, ["payment_sent"], not_after="2021-01-01T00:00:00Z")
    res = verify_counterparty_dat(dat, now=NOW, category="payment_sent")
    assert not res.ok and res.stage == "window"


def test_forged_signature_rejected() -> None:
    dat = _grant(OP_SK, OP_DID, ME_DID, ["payment_sent"])
    dat["scope"]["action_categories"].append("purchase")  # tamper after signing
    res = verify_counterparty_dat(dat, now=NOW, category="purchase")
    assert not res.ok and res.stage == "signature"


def test_two_hop_chain_verifies_at_leaf() -> None:
    # operator grants chapter; chapter sub-delegates to member.
    root = _grant(OP_SK, OP_DID, CH_DID, ["payment_sent", "message_sent"])
    leaf = _grant(CH_SK, CH_DID, ME_DID, ["payment_sent"], granted_by=root["grant_id"])
    pool = {root["grant_id"]: root, leaf["grant_id"]: leaf}
    res = verify_counterparty_dat(leaf, now=NOW, category="payment_sent", dats_by_id=pool)
    assert res.ok and res.stage == "accepted"


def _chain_of(n: int, cats=("message_sent",)):
    """Build a chain of exactly ``n`` DATs (root → … → leaf), continuity intact."""
    sks = [hashlib.sha256(f"p{i}".encode()).digest() for i in range(n + 1)]
    dids = [did_from_private_key(sk) for sk in sks]
    pool: dict = {}
    parent_id = None
    leaf = None
    for i in range(n):
        d = _grant(sks[i], dids[i], dids[i + 1], list(cats), granted_by=parent_id)
        pool[d["grant_id"]] = d
        parent_id = d["grant_id"]
        leaf = d
    return pool, leaf


def test_chain_at_max_depth_accepted() -> None:
    """A chain of exactly MAX_CHAIN_DEPTH (5) links verifies."""
    pool, leaf = _chain_of(5)
    res = verify_counterparty_dat(leaf, now=NOW, category="message_sent", dats_by_id=pool)
    assert res.ok, res


def test_chain_exceeding_max_depth_rejected() -> None:
    """A 6-link chain is REJECTED — MAX_CHAIN_DEPTH=5 means 5, not 6
    off-by-one: > vs >=)."""
    pool, leaf = _chain_of(6)
    res = verify_counterparty_dat(leaf, now=NOW, category="message_sent", dats_by_id=pool)
    assert not res.ok and res.stage == "depth", res


def test_sub_delegation_cannot_widen_scope() -> None:
    root = _grant(OP_SK, OP_DID, CH_DID, ["message_sent"])
    leaf = _grant(CH_SK, CH_DID, ME_DID, ["payment_sent"], granted_by=root["grant_id"])
    pool = {root["grant_id"]: root, leaf["grant_id"]: leaf}
    res = verify_counterparty_dat(leaf, now=NOW, category="payment_sent", dats_by_id=pool)
    assert not res.ok and res.stage == "scope"


def test_revoked_dat_rejected() -> None:
    dat = _grant(OP_SK, OP_DID, ME_DID, ["payment_sent"])
    res = verify_counterparty_dat(dat, now=NOW, category="payment_sent", revocations={dat["grant_id"]})
    assert not res.ok and res.stage == "revoked"


def test_dat_store_holds_and_presents(tmp_path) -> None:
    store = DatStore(tmp_path / "dats")
    granted = _grant(OP_SK, OP_DID, ME_DID, ["payment_sent"])
    store.add(granted)
    assert store.get(granted["grant_id"]) == granted
    assert granted in store.list_for_grantee(ME_DID)
    # presenting a held DAT round-trips and still verifies
    presented = store.get(granted["grant_id"])
    assert verify_counterparty_dat(presented, now=NOW, category="payment_sent").ok
