"""Lifecycle as a RESOLVABLE state, not presence-or-absence.

⚠️ THE DEFECT THIS REMOVES. A listing used to be consent-gated, which is presence
or ABSENCE — so a caller could not tell "this business no longer has an agent"
from "resolution failed". That is the same failure shape as an unrecognised
``?schema=`` selector returning a plausible wrong answer instead of a 400,
one layer up: an ambiguous answer is worse than an honest error,
because a stale endpoint produces a plausible transaction with a party that no
longer exists.

The load-bearing assertions here are the ones that keep FOUR answers apart —
``active`` / ``suspended`` / ``revoked`` / ``not_established``. Any two of them
collapsing is the bug coming back.

⚠️ And the tempting shortcut is tested AGAINST: deleting the binding on
withdrawal makes revocation indistinguishable from never-existed, so
``revoke_listing`` must leave a record and ``delete_binding`` must not be on any
withdrawal path.
"""

import base64
import json

import pytest

from community_member import owner, registry
from community_member.config import Config
from community_member.crypto import build_did_key

AGENT_DID = build_did_key(base64.b64encode(b"\x01" * 32).decode())


@pytest.fixture
def home(tmp_path):
    return tmp_path


@pytest.fixture
def owner_identity():
    return owner.mint_owner_identity()


def _establish(home, owner_identity, *, subject="moonbakery.com"):
    """A real, active binding — the starting point for every transition test."""
    nonce = owner.owner_nonce(owner_identity.did, "randomness")
    anchor = {"method": "oidc", "issuer": "https://accounts.google.com", "id": "sub-1"}
    owner.save_binding(
        home,
        owner_did=owner_identity.did,
        subject=subject,
        anchor=anchor,
        evidence=owner.build_owner_evidence(
            owner=owner_identity, subject=subject, anchor=anchor, id_token="h.p.s", nonce=nonce
        ),
        grant=owner.build_listing_grant(owner=owner_identity, agent_did=AGENT_DID),
    )
    return owner.load_binding(home)


# ── ⚠️ the four answers, kept apart ──────────────────────────────────────────


def test_no_binding_resolves_to_not_established_not_to_an_error(home):
    """ "Never existed" is an ANSWER, with its own name.

    If this returned None, or raised, or reported "revoked", the caller would be
    back to guessing — which is the whole defect.
    """
    answer = owner.resolve_lifecycle(owner.load_binding(home))
    assert answer.state == owner.LIFECYCLE_NOT_ESTABLISHED
    assert answer.resolvable is False
    assert answer.terminal is False


def test_the_four_states_are_all_distinct(home, owner_identity):
    """The single assertion that most directly encodes the owner-attested rework."""
    seen = {owner.resolve_lifecycle(None).state}
    _establish(home, owner_identity)
    seen.add(owner.resolve_lifecycle(owner.load_binding(home)).state)
    owner.suspend_listing(home)
    seen.add(owner.resolve_lifecycle(owner.load_binding(home)).state)
    owner.revoke_listing(home)
    seen.add(owner.resolve_lifecycle(owner.load_binding(home)).state)
    assert seen == {
        owner.LIFECYCLE_NOT_ESTABLISHED,
        owner.LIFECYCLE_ACTIVE,
        owner.LIFECYCLE_SUSPENDED,
        owner.LIFECYCLE_REVOKED,
    }


def test_a_fresh_binding_is_active(home, owner_identity):
    _establish(home, owner_identity)
    answer = owner.resolve_lifecycle(owner.load_binding(home))
    assert answer.state == owner.LIFECYCLE_ACTIVE
    assert answer.resolvable is True


def test_a_binding_written_before_lifecycle_existed_reads_as_active(home, owner_identity):
    """Back-compat that matters: an older binding was consented to and never
    withdrawn, so inferring anything but active would revoke listings nobody
    withdrew."""
    _establish(home, owner_identity)
    binding = owner.load_binding(home)
    binding.pop("lifecycle", None)
    owner.binding_path(home).write_text(json.dumps(binding))
    assert owner.resolve_lifecycle(owner.load_binding(home)).state == owner.LIFECYCLE_ACTIVE


# ── revocation is recorded, not deleted ──────────────────────────────────────


def test_the_OLD_withdrawal_shape_IS_ambiguous_so_the_next_test_is_not_vacuous(home, owner_identity):
    """⚠️ The differential that makes "revocation is observable" mean something.

    Asserting only that our revocation is distinguishable from not-found is
    consistent with a system where everything is distinguishable from everything.
    This performs the withdrawal the way it was performed before the owner-attested rework — delete
    the binding — and shows the resulting answer is BYTE-IDENTICAL to a subject
    that never existed. That is the ambiguity, reproduced rather than described:
    at this point no caller can tell "closed the shop" from "lookup failed".
    """
    _establish(home, owner_identity)
    never_existed = owner.resolve_lifecycle(None).to_public_dict()

    owner.delete_binding(home)  # the earlier withdrawal
    after_old_style_withdrawal = owner.resolve_lifecycle(owner.load_binding(home)).to_public_dict()

    assert after_old_style_withdrawal == never_existed, (
        "expected the OLD withdrawal to be indistinguishable from never-existed — if this fails, "
        "deletion is no longer ambiguous and the recorded-revocation design may be redundant"
    )

    # The same withdrawal, done the supported way, is distinguishable.
    _establish(home, owner_identity)
    owner.revoke_listing(home)
    assert owner.resolve_lifecycle(owner.load_binding(home)).to_public_dict() != never_existed


def test_revocation_leaves_a_record_rather_than_deleting_the_binding(home, owner_identity):
    """⚠️ THE TEMPTING SHORTCUT, asserted against.

    Deleting would make this indistinguishable from ``not_established``. The file
    must still be there and the answer must still say revoked.
    """
    _establish(home, owner_identity)
    owner.revoke_listing(home, reason="closed the shop")

    assert owner.binding_path(home).exists(), "withdrawal deleted the record — revocation is now unobservable"
    answer = owner.resolve_lifecycle(owner.load_binding(home))
    assert answer.state == owner.LIFECYCLE_REVOKED
    assert answer.state != owner.resolve_lifecycle(None).state


def test_revocation_carries_the_revoking_authority_and_the_time(home, owner_identity):
    _establish(home, owner_identity)
    answer = owner.revoke_listing(home, reason="closed the shop")
    assert answer.by == owner_identity.did
    assert answer.since and answer.since.endswith("Z")
    assert answer.reason == "closed the shop"


def test_delete_binding_is_not_the_withdrawal_path(home, owner_identity):
    """It still exists for genuine local cleanup, and it still destroys the
    distinction — which is exactly why no withdrawal flow may call it."""
    _establish(home, owner_identity)
    owner.delete_binding(home)
    assert owner.resolve_lifecycle(owner.load_binding(home)).state == owner.LIFECYCLE_NOT_ESTABLISHED


def test_no_withdrawal_flow_calls_delete_binding():
    """Structural, because a comment saying "do not call this" is not a guard."""
    import inspect

    from community_member import wizard

    source = inspect.getsource(wizard.withdraw_listing)
    assert "delete_binding" not in source
    assert "set_lifecycle" in source or "revoke_listing" in source


# ── transitions ──────────────────────────────────────────────────────────────


def test_suspension_is_reversible(home, owner_identity):
    _establish(home, owner_identity)
    assert owner.suspend_listing(home).state == owner.LIFECYCLE_SUSPENDED
    assert owner.resume_listing(home).state == owner.LIFECYCLE_ACTIVE


def test_revocation_is_terminal(home, owner_identity):
    """⚠️ A resolver that saw "revoked" and cached it must not be made wrong.

    Re-listing after a withdrawal requires a NEW binding — i.e. fresh consent,
    which is the thing that actually changed.
    """
    _establish(home, owner_identity)
    owner.revoke_listing(home)
    with pytest.raises(owner.LifecycleError, match="terminal"):
        owner.resume_listing(home)
    with pytest.raises(owner.LifecycleError, match="terminal"):
        owner.suspend_listing(home)


def test_a_new_binding_after_revocation_is_active_again(home, owner_identity):
    """The supported way back: consent again, which writes a fresh binding."""
    _establish(home, owner_identity)
    owner.revoke_listing(home)
    fresh = owner.mint_owner_identity()
    _establish(home, fresh)
    assert owner.resolve_lifecycle(owner.load_binding(home)).state == owner.LIFECYCLE_ACTIVE


def test_transitioning_to_the_current_state_is_a_no_op_not_an_error(home, owner_identity):
    _establish(home, owner_identity)
    owner.suspend_listing(home)
    first = owner.resolve_lifecycle(owner.load_binding(home)).since
    assert owner.suspend_listing(home).since == first, "a redundant transition rewrote the timestamp"


def test_an_unknown_state_is_refused(home, owner_identity):
    _establish(home, owner_identity)
    with pytest.raises(owner.LifecycleError, match="state must be one of"):
        owner.set_lifecycle(home, "deleted")


def test_transitioning_with_no_binding_is_refused(home):
    with pytest.raises(owner.LifecycleError, match="no owner binding"):
        owner.revoke_listing(home)


def test_a_corrupt_lifecycle_block_reads_as_active_not_as_revoked(home, owner_identity):
    """Fail-open here on purpose, and it is the opposite of the consent gate.

    Reading garbage as "revoked" would let a corrupted file silently retract a
    listing nobody withdrew — inventing a retraction is worse than missing one,
    because the retraction is the claim a caller acts on.
    """
    _establish(home, owner_identity)
    binding = owner.load_binding(home)
    binding["lifecycle"] = {"state": "banana"}
    owner.binding_path(home).write_text(json.dumps(binding))
    assert owner.resolve_lifecycle(owner.load_binding(home)).state == owner.LIFECYCLE_ACTIVE


# ── attestation: signed vs merely recorded ───────────────────────────────────


def test_an_unsigned_revocation_is_recorded_but_not_attested(home, owner_identity):
    """Withdrawal must not require the owner phrase — the key is never persisted,
    and locking someone out of revoking their own listing is a worse failure than
    an unattested record."""
    _establish(home, owner_identity)
    answer = owner.revoke_listing(home)
    assert answer.state == owner.LIFECYCLE_REVOKED
    assert answer.attested is False
    assert answer.to_public_dict()["owner_attested"] is False


def test_a_signed_revocation_is_attested_and_verifies(home, owner_identity):
    _establish(home, owner_identity)
    answer = owner.revoke_listing(home, reason="sold the business", owner=owner_identity)
    assert answer.attested is True
    assert owner.resolve_lifecycle(owner.load_binding(home)).attested is True


def test_a_forged_signature_is_reported_as_unattested_not_as_attested(home, owner_identity):
    """⚠️ The plausible-wrong-answer check, one level down.

    An unverifiable attestation claim must degrade to "not attested", never be
    reported as owner-signed.
    """
    _establish(home, owner_identity)
    owner.revoke_listing(home, owner=owner_identity)
    binding = owner.load_binding(home)
    binding["lifecycle"]["signature"] = base64.b64encode(b"\x00" * 64).decode()
    owner.binding_path(home).write_text(json.dumps(binding))
    answer = owner.resolve_lifecycle(owner.load_binding(home))
    assert answer.state == owner.LIFECYCLE_REVOKED, "a bad signature must not undo the revocation"
    assert answer.attested is False


def test_a_signature_cannot_be_replayed_onto_a_different_state(home, owner_identity):
    """The statement binds subject + owner + state + time, so a "suspended"
    signature cannot be presented as a "revoked" one."""
    _establish(home, owner_identity)
    owner.suspend_listing(home, owner=owner_identity)
    binding = owner.load_binding(home)
    stolen = binding["lifecycle"]["signature"]
    binding["lifecycle"] = {
        "state": owner.LIFECYCLE_REVOKED,
        "since": binding["lifecycle"]["since"],
        "by": owner_identity.did,
        "reason": None,
        "signature": stolen,
    }
    owner.binding_path(home).write_text(json.dumps(binding))
    assert owner.resolve_lifecycle(owner.load_binding(home)).attested is False


def test_a_signature_cannot_be_replayed_with_a_fresh_timestamp(home, owner_identity):
    _establish(home, owner_identity)
    owner.revoke_listing(home, owner=owner_identity)
    binding = owner.load_binding(home)
    binding["lifecycle"]["since"] = "2099-01-01T00:00:00Z"
    owner.binding_path(home).write_text(json.dumps(binding))
    assert owner.resolve_lifecycle(owner.load_binding(home)).attested is False


def test_signing_with_the_wrong_owner_key_is_refused(home, owner_identity):
    _establish(home, owner_identity)
    with pytest.raises(owner.LifecycleError, match="did not authorise this listing"):
        owner.revoke_listing(home, owner=owner.mint_owner_identity())


def test_an_active_listing_is_never_reported_as_attested(home, owner_identity):
    """``owner_attested`` is about a transition. There is no transition into the
    initial active state, so claiming attestation there would be meaningless."""
    _establish(home, owner_identity)
    assert owner.resolve_lifecycle(owner.load_binding(home)).attested is False


# ── the gate distinguishes them too ──────────────────────────────────────────


def test_the_gate_reports_revoked_rather_than_no_consent(home, owner_identity):
    """A caller reading the gate must be able to tell a withdrawal from an
    absence, not only a caller reading the resolution endpoint."""
    _establish(home, owner_identity)
    owner.revoke_listing(home)
    verdict = owner.listing_grant_verdict(owner.load_binding(home), AGENT_DID)
    assert verdict.ok is False
    assert verdict.reason == "revoked"


def test_the_gate_reports_suspended_distinctly(home, owner_identity):
    _establish(home, owner_identity)
    owner.suspend_listing(home)
    assert owner.listing_grant_verdict(owner.load_binding(home), AGENT_DID).reason == "suspended"


def test_the_gate_reports_no_owner_consent_when_nothing_was_established():
    assert owner.listing_grant_verdict(None, AGENT_DID).reason == "no_owner_consent"


def test_revocation_outranks_an_expired_grant(home, owner_identity):
    """The withdrawal is the operative fact and the more specific answer. A
    revoked listing that also expired must not report "expired" — that reads as
    "renew it" when the truth is "it was withdrawn"."""
    _establish(home, owner_identity)
    owner.revoke_listing(home)
    binding = owner.load_binding(home)
    assert owner.listing_grant_verdict(binding, AGENT_DID, now="2099-01-01T00:00:00Z").reason == "revoked"


@pytest.mark.parametrize(
    "transition,expected",
    [
        (None, True),
        (owner.LIFECYCLE_SUSPENDED, False),
        (owner.LIFECYCLE_REVOKED, False),
    ],
)
def test_announce_follows_the_lifecycle(home, owner_identity, monkeypatch, transition, expected):
    from community_member import config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", home)
    monkeypatch.delenv("COMMUNITY_MEMBER_NO_REGISTRY", raising=False)
    cfg = Config()
    cfg.agent_id, cfg.api_key = "alice-agent", "sk-test"
    cfg.public_key = base64.b64encode(b"\x01" * 32).decode()
    _establish(home, owner_identity)
    if transition:
        owner.set_lifecycle(home, transition)
    assert registry.should_announce(cfg) is expected


# ── the resolvable document ──────────────────────────────────────────────────


def test_the_public_document_always_carries_every_field(home, owner_identity):
    """An omitted key makes a consumer's ``.get()`` return None for both "not
    revoked" and "revoked but the details are missing" — the ambiguity again,
    one level down. So every field is always present."""
    keys = {"version", "state", "subject", "since", "revoking_authority", "reason", "owner_attested"}
    assert set(owner.resolve_lifecycle(None).to_public_dict()) == keys
    _establish(home, owner_identity)
    assert set(owner.resolve_lifecycle(owner.load_binding(home)).to_public_dict()) == keys
    owner.revoke_listing(home, reason="why")
    assert set(owner.resolve_lifecycle(owner.load_binding(home)).to_public_dict()) == keys


def test_the_public_document_never_leaks_the_grant_or_evidence(home, owner_identity):
    _establish(home, owner_identity)
    owner.revoke_listing(home, owner=owner_identity)
    blob = json.dumps(owner.resolve_lifecycle(owner.load_binding(home)).to_public_dict())
    assert "evidence" not in blob
    assert "grant" not in blob
    assert owner_identity.private_key_b64 not in blob
