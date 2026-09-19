"""DAT — Delegated Authority Token chains.

CHAIN        operator → chapter → member verifies end-to-end
SCOPE-LEAF   a category outside the leaf grant is rejected
SCOPE-WIDEN  a sub-delegation cannot widen scope beyond its parent
CONTINUITY   a child's grantor must be the parent's grantee
REVOKED      a revoked grant in the chain is rejected
WINDOW       an expired DAT is rejected
SIGNATURE    a tampered DAT does not verify
CONSTRAINTS  amount caps + counterparty allowlist + jurisdiction
"""

from __future__ import annotations

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dat import build_dat, evaluate_constraints, verify_dat_chain

# PAST/NOW/FUTURE bracket a fixed window so the validity-window check is
# independent of the wall clock (build_dat would otherwise default not_before to
# the real current time, making the test fail whenever it runs after NOW).
PAST = "2026-01-01T00:00:00Z"
NOW = "2026-06-04T12:00:00Z"
FUTURE = "2027-01-01T00:00:00Z"


def mk(label: str) -> tuple[bytes, str]:
    seed = label.encode().ljust(32, b"!")[:32]
    pk = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return seed, "did:key:z" + base58.b58encode(b"\xed\x01" + pk).decode()


def _chain(leaf_cats=("message_sent",), root_cats=("message_sent", "data_shared", "intent_submitted")):
    op_sk, op = mk("operator")
    ch_sk, ch = mk("chapter")
    mem_sk, mem = mk("member")
    root = build_dat(
        grantor_sk_bytes=op_sk,
        grantor_did=op,
        grantee_did=ch,
        action_categories=list(root_cats),
        not_after=FUTURE,
        not_before=PAST,
    )
    leaf = build_dat(
        grantor_sk_bytes=ch_sk,
        grantor_did=ch,
        grantee_did=mem,
        action_categories=list(leaf_cats),
        not_after=FUTURE,
        not_before=PAST,
        granted_by=root["grant_id"],
    )
    return {root["grant_id"]: root, leaf["grant_id"]: leaf}, root, leaf


def test_valid_chain_verifies():
    dats, root, leaf = _chain()
    r = verify_dat_chain(leaf["grant_id"], dats_by_id=dats, now=NOW, category="message_sent")
    assert r.ok, r


def _chain_of(n: int, cats=("message_sent",)):
    """Build a chain of exactly ``n`` DATs (root → … → leaf). Continuity holds:
    each hop's grantor is the previous hop's grantee."""
    parties = [mk(f"p{i}") for i in range(n + 1)]  # n+1 dids
    dats: dict = {}
    parent_id = None
    leaf = None
    for i in range(n):
        grantor_sk, grantor_did = parties[i]
        _, grantee_did = parties[i + 1]
        d = build_dat(
            grantor_sk_bytes=grantor_sk,
            grantor_did=grantor_did,
            grantee_did=grantee_did,
            action_categories=list(cats),
            not_after=FUTURE,
            not_before=PAST,
            granted_by=parent_id,
        )
        dats[d["grant_id"]] = d
        parent_id = d["grant_id"]
        leaf = d
    return dats, leaf


def test_chain_at_max_depth_accepted():
    """A chain of exactly MAX_CHAIN_DEPTH (5) links verifies."""
    dats, leaf = _chain_of(5)
    r = verify_dat_chain(leaf["grant_id"], dats_by_id=dats, now=NOW)
    assert r.ok, r


def test_chain_exceeding_max_depth_rejected():
    """A 6-link chain must be REJECTED — MAX_CHAIN_DEPTH=5 means 5, not 6
    off-by-one: the depth check used > instead of >=)."""
    dats, leaf = _chain_of(6)
    r = verify_dat_chain(leaf["grant_id"], dats_by_id=dats, now=NOW)
    assert not r.ok and r.stage == "depth", r


def test_category_outside_leaf_scope_rejected():
    dats, root, leaf = _chain()
    r = verify_dat_chain(leaf["grant_id"], dats_by_id=dats, now=NOW, category="data_shared")
    assert not r.ok and r.stage == "scope"


def test_subdelegation_widening_rejected():
    # leaf grants a category the parent (root) does not hold.
    dats, root, leaf = _chain(leaf_cats=("message_sent", "purchase"), root_cats=("message_sent",))
    r = verify_dat_chain(leaf["grant_id"], dats_by_id=dats, now=NOW)
    assert not r.ok and r.stage == "scope"


def test_continuity_break_rejected():
    op_sk, op = mk("operator")
    ch_sk, ch = mk("chapter")
    other_sk, other = mk("someone-else")
    mem_sk, mem = mk("member")
    # root grants to `other`, but the leaf's grantor is `ch` ≠ `other`.
    root = build_dat(
        grantor_sk_bytes=op_sk,
        grantor_did=op,
        grantee_did=other,
        action_categories=["message_sent"],
        not_after=FUTURE,
        not_before=PAST,
    )
    leaf = build_dat(
        grantor_sk_bytes=ch_sk,
        grantor_did=ch,
        grantee_did=mem,
        action_categories=["message_sent"],
        not_after=FUTURE,
        not_before=PAST,
        granted_by=root["grant_id"],
    )
    dats = {root["grant_id"]: root, leaf["grant_id"]: leaf}
    r = verify_dat_chain(leaf["grant_id"], dats_by_id=dats, now=NOW)
    assert not r.ok and r.stage == "delegation"


def test_revocation_rejected():
    dats, root, leaf = _chain()
    r = verify_dat_chain(leaf["grant_id"], dats_by_id=dats, now=NOW, revocations={root["grant_id"]})
    assert not r.ok and r.stage == "revoked"


def test_expired_window_rejected():
    dats, root, leaf = _chain()
    r = verify_dat_chain(leaf["grant_id"], dats_by_id=dats, now="2030-01-01T00:00:00Z")
    assert not r.ok and r.stage == "window"


def test_tampered_dat_rejected():
    dats, root, leaf = _chain()
    leaf["grantee_did"] = "did:key:z6MkTamperedGranteeDidValue"  # after signing
    r = verify_dat_chain(leaf["grant_id"], dats_by_id=dats, now=NOW)
    assert not r.ok and r.stage == "signature"


def test_constraints_amount_and_allowlist_and_jurisdiction():
    c = {
        "amount_cents_per_action_max": 1000,
        "amount_currency": "USD",
        "counterparty_allowlist": ["label:Bob"],
        "jurisdictions": ["US-MA"],
    }

    def rcpt(cents, label, locus="US-MA"):
        return {
            "action": {
                "category": "purchase",
                "amount": {"cents": cents, "currency": "USD"},
                "counterparty_did": "did:key:zX",
                "counterparty_label": label,
            },
            "jurisdiction": {"action_locus": locus},
        }

    assert evaluate_constraints(c, rcpt(500, "Bob")).ok
    assert evaluate_constraints(c, rcpt(5000, "Bob")).stage == "amount_action"
    assert evaluate_constraints(c, rcpt(500, "Eve")).stage == "counterparty"
    assert evaluate_constraints(c, rcpt(500, "Bob", locus="US-CA")).stage == "jurisdiction"
