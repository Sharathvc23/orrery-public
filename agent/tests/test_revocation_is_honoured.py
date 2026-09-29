"""Revoking a grant must actually stop it authorising calls.

⚠️ THE GAP THIS CLOSES. Every piece of revocation already existed and none of
them touched. ``verify_dat_chain`` has always honoured a revocation set,
``check_authority`` has always been able to return the ``revoked`` stage, and
``DatStore`` has always held the grants — but ``check_authority`` called the
verifier without a revocation set, and the store had nowhere to record one. So
the set was empty on every call and **no grant was ever treated as withdrawn**.

That is the dangerous shape. Read from either end the feature looks present;
only the wiring between them was missing, and nothing failed loudly to say so.

The load-bearing test is
``test_control_without_the_revocation_set_a_revoked_grant_still_passes``: it
pins the pre-fix behaviour, so if the wiring is ever dropped again the tests
above it cannot quietly start passing for the wrong reason.

Real keys, real signatures, real chains. A DAT with a made-up signature is
refused at the signature stage, which would let a revocation test pass without
revocation having been consulted at all.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from community_member._dat import build_dat
from community_member.arp import did_from_private_key
from community_member.dat import DatStore
from community_member.delegated_call import action_name, check_authority

TOOL = "save_note"
CATEGORY = action_name(TOOL)
TOMORROW = (datetime.now(UTC) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Party:
    """One key, and the did:key it publishes."""

    def __init__(self) -> None:
        self.seed = Ed25519PrivateKey.generate().private_bytes_raw()
        self.did = did_from_private_key(self.seed)

    def grants(
        self,
        grantee: _Party,
        *,
        categories: list[str] | None = None,
        granted_by: str | None = None,
    ) -> dict:
        return build_dat(
            grantor_sk_bytes=self.seed,
            grantor_did=self.did,
            grantee_did=grantee.did,
            action_categories=categories or [CATEGORY],
            not_after=TOMORROW,
            granted_by=granted_by,
        )


# ── the fix ─────────────────────────────────────────────────────────────────


def test_a_live_grant_authorises():
    """The baseline. Without it, every refusal below could be a refusal for some
    unrelated reason — a bad signature, a missed scope — rather than revocation."""
    owner, agent = _Party(), _Party()

    verdict = check_authority(owner.grants(agent), self_did=agent.did, tool=TOOL)

    assert verdict.ok, verdict.detail
    assert verdict.stage == "accepted"


def test_a_revoked_grant_is_refused():
    """The whole point of the change."""
    owner, agent = _Party(), _Party()
    dat = owner.grants(agent)

    verdict = check_authority(dat, self_did=agent.did, tool=TOOL, revocations={dat["grant_id"]})

    assert not verdict.ok, "a withdrawn grant still authorised the call"
    assert verdict.stage == "revoked"
    assert dat["grant_id"] in verdict.detail


def test_control_without_the_revocation_set_a_revoked_grant_still_passes():
    """Pins the behaviour that made this a gap.

    This exact call — a grant the operator has withdrawn, checked without the
    set — is what every caller made before the wiring existed. Keeping it green
    is what stops the test above from passing vacuously if ``revocations`` is
    ever dropped again on the way to the verifier.
    """
    owner, agent = _Party(), _Party()

    verdict = check_authority(owner.grants(agent), self_did=agent.did, tool=TOOL)

    assert verdict.ok, "the pre-fix behaviour changed; this control describes nothing now"


def test_an_unrelated_revocation_does_not_refuse_this_grant():
    """Revocation must be keyed to the grant, not act as a blanket flag."""
    owner, agent = _Party(), _Party()

    verdict = check_authority(owner.grants(agent), self_did=agent.did, tool=TOOL, revocations={"some-other-grant"})

    assert verdict.ok, verdict.detail


# ── the store ───────────────────────────────────────────────────────────────


def test_the_store_records_a_revocation_without_losing_the_grant(tmp_path: Path):
    """A grant that is gone and a grant that was withdrawn are different facts.

    Receipts issued while it was live still name it, so answering "was this
    authorised when it happened?" needs both the grant and the fact of its
    revocation. Deleting the row would instead answer "there was never any
    authority" — a different, and false, claim.
    """
    owner, agent = _Party(), _Party()
    dat = owner.grants(agent)
    store = DatStore(home=tmp_path / "member")
    store.add(dat)

    store.revoke(dat["grant_id"], reason="key rotated")

    assert store.is_revoked(dat["grant_id"])
    assert store.revoked() == {dat["grant_id"]}
    assert store.get(dat["grant_id"]) == dat, "revoking erased the grant's own history"


def test_revoking_twice_is_idempotent(tmp_path: Path):
    owner, agent = _Party(), _Party()
    dat = owner.grants(agent)
    store = DatStore(home=tmp_path / "member")
    store.add(dat)

    store.revoke(dat["grant_id"], reason="first")
    store.revoke(dat["grant_id"], reason="second")

    assert store.revoked() == {dat["grant_id"]}


def test_a_grant_never_revoked_is_not_reported_as_revoked(tmp_path: Path):
    owner, agent = _Party(), _Party()
    dat = owner.grants(agent)
    store = DatStore(home=tmp_path / "member")
    store.add(dat)

    assert store.revoked() == set()
    assert not store.is_revoked(dat["grant_id"])


def test_a_revocation_survives_reopening_the_store(tmp_path: Path):
    """Revocation held only in memory is revocation until the next restart."""
    owner, agent = _Party(), _Party()
    dat = owner.grants(agent)
    DatStore(home=tmp_path / "member").revoke(dat["grant_id"])

    assert DatStore(home=tmp_path / "member").revoked() == {dat["grant_id"]}


def test_the_store_feeds_the_check_directly(tmp_path: Path):
    """``DatStore.revoked()`` is exactly the shape ``check_authority`` consumes.

    If these two ever disagree, the fix is wired only inside the tests.
    """
    owner, agent = _Party(), _Party()
    dat = owner.grants(agent)
    store = DatStore(home=tmp_path / "member")
    store.add(dat)
    store.revoke(dat["grant_id"])

    verdict = check_authority(dat, self_did=agent.did, tool=TOOL, revocations=store.revoked())

    assert not verdict.ok
    assert verdict.stage == "revoked"


# ── the chain ───────────────────────────────────────────────────────────────


def test_a_sub_delegated_grant_authorises_while_its_ancestor_stands():
    """The baseline for the test below: the chain itself is sound."""
    root, middle, agent = _Party(), _Party(), _Party()
    parent = root.grants(middle)
    leaf = middle.grants(agent, granted_by=parent["grant_id"])

    verdict = check_authority(
        leaf,
        self_did=agent.did,
        tool=TOOL,
        dats_by_id={parent["grant_id"]: parent, leaf["grant_id"]: leaf},
    )

    assert verdict.ok, verdict.detail


def test_revoking_an_ancestor_withdraws_what_was_delegated_beneath_it():
    """Otherwise revocation only ever reaches the leaf, and sub-delegation
    becomes a way for authority to outlive the grant it came from: withdraw the
    operator's grant to the chapter, and the chapter's agents keep transacting."""
    root, middle, agent = _Party(), _Party(), _Party()
    parent = root.grants(middle)
    leaf = middle.grants(agent, granted_by=parent["grant_id"])

    verdict = check_authority(
        leaf,
        self_did=agent.did,
        tool=TOOL,
        revocations={parent["grant_id"]},
        dats_by_id={parent["grant_id"]: parent, leaf["grant_id"]: leaf},
    )

    assert not verdict.ok, "an ancestor was withdrawn and the grant beneath it survived"
    assert verdict.stage == "revoked"
    assert parent["grant_id"] in verdict.detail


def test_control_an_ancestor_revoked_but_never_supplied_is_invisible():
    """Honest about the limit. Without ``dats_by_id`` the chain cannot be walked
    past the leaf, so an upstream revocation cannot be consulted — the presenter
    has to supply its ancestors. Recorded here so the boundary is a stated
    property rather than a surprise: the refusal comes from the missing parent,
    not from the revocation.
    """
    root, middle, agent = _Party(), _Party(), _Party()
    parent = root.grants(middle)
    leaf = middle.grants(agent, granted_by=parent["grant_id"])

    verdict = check_authority(leaf, self_did=agent.did, tool=TOOL, revocations={parent["grant_id"]})

    assert not verdict.ok, "a chained grant verified with no ancestors to walk"
    assert verdict.stage == "delegation", f"expected the missing parent to be the complaint, got {verdict.stage}"


# ── unrelated refusals still stand ──────────────────────────────────────────


def test_a_self_granted_dat_is_still_refused():
    """Not about revocation, and worth not regressing while the authority path
    is being edited: an agent cannot authorise itself."""
    agent = _Party()

    verdict = check_authority(agent.grants(agent), self_did=agent.did, tool=TOOL)

    assert not verdict.ok
    assert verdict.stage == "grantor"
