"""The auditor walks the chain; the verifier decides it. Both, and their disagreement.

⚠️ WHAT THESE PIN. Three things, in order of how badly each would fail silently:

1. **The walk reaches the root and reports every hop**, not just the first
   problem. An operator asking "why can my agent no longer act?" is answered by
   "the chapter's grant expired two hops up", never by "something is wrong".
2. **Revocation severs the chain at the hop that was withdrawn** — including an
   ancestor, since otherwise sub-delegation outlives the authority it came from.
3. **The verdict is the verifier's.** The audit adds visibility, not a second
   opinion. `test_control_a_divergence_between_the_two_is_reported_not_resolved`
   is the load-bearing one: if the auditor ever silently defers to the gate, it
   stops being able to catch the drift it exists for.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from community_member._dat import build_dat
from community_member.arp import did_from_private_key
from community_member.authority_audit import walk_authority

CATEGORY = "a2a.tasks/send#save_note"


def _iso(delta_hours: int) -> str:
    return (datetime.now(UTC) + timedelta(hours=delta_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Party:
    def __init__(self) -> None:
        self.seed = Ed25519PrivateKey.generate().private_bytes_raw()
        self.did = did_from_private_key(self.seed)

    def grants(self, grantee: _Party, *, categories=None, granted_by=None, not_after=None, not_before=None) -> dict:
        return build_dat(
            grantor_sk_bytes=self.seed,
            grantor_did=self.did,
            grantee_did=grantee.did,
            action_categories=categories or [CATEGORY],
            not_after=not_after or _iso(24),
            not_before=not_before,
            granted_by=granted_by,
        )


def _chain(**kw):
    """operator → chapter → agent, the topology Phase 3b describes."""
    operator, chapter, agent = _Party(), _Party(), _Party()
    root = operator.grants(chapter, not_after=kw.get("root_not_after"))
    leaf = chapter.grants(agent, granted_by=root["grant_id"], categories=kw.get("leaf_categories"))
    return root, leaf, {root["grant_id"]: root, leaf["grant_id"]: leaf}


# ── the walk reaches the root ───────────────────────────────────────────────


def test_a_sound_chain_walks_to_its_root_and_is_intact():
    root, leaf, pool = _chain()

    walk = walk_authority(leaf["grant_id"], dats_by_id=pool)

    assert walk.verdict == "intact", walk.reason
    assert walk.ok
    assert walk.root_grant_id == root["grant_id"]
    assert [h.grant_id for h in walk.hops] == [leaf["grant_id"], root["grant_id"]], "leaf first, then its parent"
    assert all(h.ok for h in walk.hops)
    assert walk.severed_at is None


def test_every_hop_is_reported_not_only_the_broken_one():
    """The difference between this and the verifier. An operator needs to see
    that their own grant is fine and the one above it is not."""
    _root, leaf, pool = _chain(root_not_after=_iso(-1))

    walk = walk_authority(leaf["grant_id"], dats_by_id=pool)

    assert len(walk.hops) == 2, "the walk stopped at the first problem instead of reporting the chain"
    assert walk.hops[0].ok, "the agent's own grant is sound and was reported as broken"
    assert not walk.hops[1].ok
    assert "expired at" in walk.hops[1].problem


def test_a_single_unchained_grant_is_its_own_root():
    operator, agent = _Party(), _Party()
    dat = operator.grants(agent)

    walk = walk_authority(dat["grant_id"], dats_by_id={dat["grant_id"]: dat})

    assert walk.verdict == "intact"
    assert walk.root_grant_id == dat["grant_id"]
    assert walk.hops[0].continuous_with_child is None, "a leaf has nothing below it"
    assert walk.hops[0].within_parent_scope is None, "a root was given its scope by nobody here"


# ── revocation severs it ────────────────────────────────────────────────────


def test_revoking_the_leaf_severs_the_chain_at_the_leaf():
    _root, leaf, pool = _chain()

    walk = walk_authority(leaf["grant_id"], dats_by_id=pool, revocations={leaf["grant_id"]})

    assert walk.verdict == "severed"
    assert walk.severed_at == leaf["grant_id"]
    assert walk.hops[0].revoked and walk.hops[0].problem == "revoked"


def test_revoking_the_ancestor_severs_the_chain_and_names_the_ancestor():
    """Phase 3b's gate, in one assertion: after revoke, the same walk marks it
    severed — and says which hop, so the operator is not left guessing."""
    root, leaf, pool = _chain()

    walk = walk_authority(leaf["grant_id"], dats_by_id=pool, revocations={root["grant_id"]})

    assert walk.verdict == "severed"
    assert walk.severed_at == root["grant_id"], "the leaf was blamed for its ancestor's withdrawal"
    assert walk.hops[0].ok, "the agent's own grant is untouched and was reported as the problem"
    assert walk.hops[1].revoked


def test_control_the_same_chain_unrevoked_is_intact():
    """Pairs with the two above. Without it, a walk that reports `severed` for
    any reason at all would look like revocation working."""
    _root, leaf, pool = _chain()

    assert walk_authority(leaf["grant_id"], dats_by_id=pool).verdict == "intact"


def test_revocation_is_named_before_expiry():
    """A grant withdrawn and then left to lapse must not be reported as expired
    — that sends the operator to renew something nobody intends to honour."""
    root, leaf, pool = _chain(root_not_after=_iso(-1))

    walk = walk_authority(leaf["grant_id"], dats_by_id=pool, revocations={root["grant_id"]})

    assert walk.hops[1].problem == "revoked"


# ── what it cannot walk, it says so about ───────────────────────────────────


def test_a_parent_named_but_not_supplied_is_unresolvable_not_severed():
    """A chain that cannot be walked is not a chain that was withdrawn, and
    saying "severed" here would be a guess dressed as a finding."""
    _root, leaf, pool = _chain()
    pool = {leaf["grant_id"]: leaf}  # the ancestor withheld

    walk = walk_authority(leaf["grant_id"], dats_by_id=pool)

    assert walk.verdict == "unresolvable"
    assert "not supplied" in walk.reason
    assert walk.root_grant_id is None, "a root was claimed for a chain that was never walked to one"


def test_a_cycle_is_refused_rather_than_walked_forever():
    a, b = _Party(), _Party()
    one = build_dat(
        grantor_sk_bytes=a.seed,
        grantor_did=a.did,
        grantee_did=b.did,
        action_categories=[CATEGORY],
        not_after=_iso(24),
        granted_by="two",
    )
    two = build_dat(
        grantor_sk_bytes=b.seed,
        grantor_did=b.did,
        grantee_did=a.did,
        action_categories=[CATEGORY],
        not_after=_iso(24),
        granted_by=one["grant_id"],
    )
    walk = walk_authority(one["grant_id"], dats_by_id={one["grant_id"]: one, "two": two})

    assert walk.verdict == "unresolvable"
    assert "cycle" in walk.reason


# ── the verdict is the verifier's ───────────────────────────────────────────


def test_a_sub_delegation_that_widens_scope_is_severed_and_the_two_agree():
    """The rule most likely to make a hand-rolled auditor disagree with the
    gate, which is why it is here rather than left to the verifier's tests."""
    operator, chapter, agent = _Party(), _Party(), _Party()
    root = operator.grants(chapter, categories=[CATEGORY])
    leaf = chapter.grants(agent, categories=[CATEGORY, "a2a.tasks/send#install_skill"], granted_by=root["grant_id"])

    walk = walk_authority(leaf["grant_id"], dats_by_id={root["grant_id"]: root, leaf["grant_id"]: leaf})

    assert walk.verdict == "severed", f"expected severed, got {walk.verdict}: {walk.reason}"
    assert walk.hops[0].within_parent_scope is False
    assert "widens the scope" in walk.hops[0].problem


def test_control_a_divergence_between_the_two_is_reported_not_resolved(monkeypatch):
    """The load-bearing test.

    An auditor that quietly deferred to the gate would hide exactly the drift it
    exists to catch; one that overruled it would be a second verifier by another
    name. Forcing the gate to accept a chain the audit found broken must produce
    `disputed`, naming both sides.
    """
    from community_member import authority_audit
    from community_member._dat import DatResult

    _root, leaf, pool = _chain()
    monkeypatch.setattr(authority_audit, "verify_dat_chain", lambda *a, **k: DatResult(True, "accepted", "ok"))

    walk = walk_authority(leaf["grant_id"], dats_by_id=pool, revocations={leaf["grant_id"]})

    assert walk.verdict == "disputed", "the auditor deferred to the gate and swallowed the divergence"
    assert "divergence" in walk.reason
    assert walk.severed_at == leaf["grant_id"]


def test_control_the_other_direction_of_divergence_is_also_reported(monkeypatch):
    from community_member import authority_audit
    from community_member._dat import DatResult

    _root, leaf, pool = _chain()
    monkeypatch.setattr(authority_audit, "verify_dat_chain", lambda *a, **k: DatResult(False, "scope", "nope"))

    walk = walk_authority(leaf["grant_id"], dats_by_id=pool)

    assert walk.verdict == "disputed"
    assert "every hop audits clean" in walk.reason


# ── the report says what it does not establish ──────────────────────────────


def test_a_walk_states_its_limits():
    _root, leaf, pool = _chain()

    walk = walk_authority(leaf["grant_id"], dats_by_id=pool)

    assert walk.not_established, "an intact verdict with no stated limits reads as proof of authority"
    assert any("real principal" in n for n in walk.not_established)
    assert any("ARP receipt chain" in n for n in walk.not_established), (
        "the two revocation mechanisms must not be conflated"
    )
    assert any("published elsewhere is invisible" in n for n in walk.not_established)


def test_the_report_serialises_whole():
    _root, leaf, pool = _chain()

    d = walk_authority(leaf["grant_id"], dats_by_id=pool).as_dict()

    assert d["verdict"] == "intact" and d["depth"] == 2
    assert [h["grant_id"] for h in d["hops"]] == [leaf["grant_id"], _root_id(pool, leaf)]
    assert d["not_established"]


def _root_id(pool: dict, leaf: dict) -> str:
    return leaf["granted_by"]
