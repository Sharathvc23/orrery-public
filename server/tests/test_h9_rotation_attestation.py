"""H9 — a peer may rotate its key ONLY by proving continuity with the old one.

Today `check_and_pin_did` returns ("mismatch", old) and KEEPS the pin, so a peer
that legitimately rotates is isolated from the federation until an operator runs
`clear_did_pin`. Fail-closed, permanently, with no automated recovery.

⚠️ THE REFUSAL CASES ARE THE POINT, AND THEY ARE WRITTEN FIRST ON PURPOSE.
An automated "accept the new key" path is a TAKEOVER PRIMITIVE unless the
attestation is genuinely bound to the OLD key. Anything weaker — a grace window,
a TOFU re-pin, accepting an attestation signed by the NEW key, accepting a
replay of an old rotation — converts a fail-closed isolation into a silent
hijack, which is strictly worse than the breakage it fixes. So: unsigned,
wrong-key, self-signed, wrong-subject and replayed rotations must ALL be refused,
and those tests come before the happy path.

Scope note carried from the design position: this makes rotation routine for
peers that IMPLEMENT it. The five umbrella chapters are a separate codebase and
would need the same verifier before an orrery key rotation is safe mesh-wide.
"""

from __future__ import annotations

import base64
import time

import nacl.signing
import pytest

import federation_policy as fp


def _identity():
    sk = nacl.signing.SigningKey.generate()
    pk_b64 = base64.b64encode(bytes(sk.verify_key)).decode()
    import sovereign_identity

    return sk, sovereign_identity.build_did_key_from_ed25519(pk_b64)


def _attest(sk, *, peer_id: str, old_did: str, new_did: str, issued_at: float | None = None) -> dict:
    """A rotation attestation signed by `sk`."""
    att = {
        "type": "chapter.key.rotation",
        "peer_chapter_id": peer_id,
        "old_did": old_did,
        "new_did": new_did,
        "issued_at": int(issued_at if issued_at is not None else time.time()),
    }
    att["signature"] = base64.b64encode(
        sk.sign(fp.rotation_signing_material(att)).signature
    ).decode()
    return att


@pytest.fixture
def peer():
    old_sk, old_did = _identity()
    new_sk, new_did = _identity()
    return {"id": "peer-a", "old_sk": old_sk, "old_did": old_did, "new_sk": new_sk, "new_did": new_did}


# ── REFUSALS FIRST ───────────────────────────────────────────────────────────


def test_REFUSE_unsigned_rotation(peer):
    att = _attest(peer["old_sk"], peer_id=peer["id"], old_did=peer["old_did"], new_did=peer["new_did"])
    att.pop("signature")
    ok, why = fp.verify_rotation_attestation(att, peer_id=peer["id"], pinned_did=peer["old_did"])
    assert not ok and "signature" in why


def test_REFUSE_rotation_signed_by_the_NEW_key(peer):
    """The takeover case. An attacker holds only the key they are installing."""
    att = _attest(peer["new_sk"], peer_id=peer["id"], old_did=peer["old_did"], new_did=peer["new_did"])
    ok, why = fp.verify_rotation_attestation(att, peer_id=peer["id"], pinned_did=peer["old_did"])
    assert not ok, "a rotation signed by the incoming key was accepted — that is a hijack"


def test_REFUSE_rotation_signed_by_an_unrelated_key(peer):
    other_sk, _ = _identity()
    att = _attest(other_sk, peer_id=peer["id"], old_did=peer["old_did"], new_did=peer["new_did"])
    ok, _ = fp.verify_rotation_attestation(att, peer_id=peer["id"], pinned_did=peer["old_did"])
    assert not ok


def test_REFUSE_when_old_did_does_not_match_the_pin(peer):
    """The attestation must name the key we actually hold, not any old key."""
    _, unrelated_did = _identity()
    att = _attest(peer["old_sk"], peer_id=peer["id"], old_did=unrelated_did, new_did=peer["new_did"])
    ok, why = fp.verify_rotation_attestation(att, peer_id=peer["id"], pinned_did=peer["old_did"])
    assert not ok and "old_did" in why


def test_REFUSE_rotation_bound_to_a_different_peer(peer):
    """A valid rotation for peer B must not rotate peer A."""
    att = _attest(peer["old_sk"], peer_id="peer-b", old_did=peer["old_did"], new_did=peer["new_did"])
    ok, why = fp.verify_rotation_attestation(att, peer_id=peer["id"], pinned_did=peer["old_did"])
    assert not ok and "peer" in why


def test_REFUSE_replayed_stale_rotation(peer):
    """Replay: a genuine old rotation must not re-install a superseded key."""
    att = _attest(
        peer["old_sk"],
        peer_id=peer["id"],
        old_did=peer["old_did"],
        new_did=peer["new_did"],
        issued_at=time.time() - (fp.ROTATION_MAX_AGE_S + 60),
    )
    ok, why = fp.verify_rotation_attestation(att, peer_id=peer["id"], pinned_did=peer["old_did"])
    assert not ok and "stale" in why


def test_REFUSE_future_dated_rotation(peer):
    att = _attest(
        peer["old_sk"],
        peer_id=peer["id"],
        old_did=peer["old_did"],
        new_did=peer["new_did"],
        issued_at=time.time() + (fp.ROTATION_MAX_AGE_S + 60),
    )
    ok, _ = fp.verify_rotation_attestation(att, peer_id=peer["id"], pinned_did=peer["old_did"])
    assert not ok


def test_REFUSE_tampered_new_did(peer):
    """Signature covers new_did, so swapping it must break verification."""
    att = _attest(peer["old_sk"], peer_id=peer["id"], old_did=peer["old_did"], new_did=peer["new_did"])
    _, attacker_did = _identity()
    att["new_did"] = attacker_did
    ok, _ = fp.verify_rotation_attestation(att, peer_id=peer["id"], pinned_did=peer["old_did"])
    assert not ok


def test_REFUSE_when_there_is_no_pin_to_prove_continuity_from(peer):
    """With no existing pin there is no OLD key, so nothing can be proven.

    That case is TOFU (first sighting), not rotation, and must not route here.
    """
    att = _attest(peer["old_sk"], peer_id=peer["id"], old_did=peer["old_did"], new_did=peer["new_did"])
    ok, _ = fp.verify_rotation_attestation(att, peer_id=peer["id"], pinned_did=None)
    assert not ok


# ── Only then, the happy path ────────────────────────────────────────────────


def test_ACCEPT_a_rotation_signed_by_the_old_key(peer):
    att = _attest(peer["old_sk"], peer_id=peer["id"], old_did=peer["old_did"], new_did=peer["new_did"])
    ok, why = fp.verify_rotation_attestation(att, peer_id=peer["id"], pinned_did=peer["old_did"])
    assert ok, why


def test_the_signing_material_binds_every_field_that_matters(peer):
    """If a field is outside the signed material, an attacker can edit it freely."""
    base = {
        "type": "chapter.key.rotation",
        "peer_chapter_id": peer["id"],
        "old_did": peer["old_did"],
        "new_did": peer["new_did"],
        "issued_at": 1000,
    }
    material = fp.rotation_signing_material(base)
    for field, value in (
        ("peer_chapter_id", "other"),
        ("old_did", "did:key:zOther"),
        ("new_did", "did:key:zOther"),
        ("issued_at", 2000),
    ):
        assert fp.rotation_signing_material({**base, field: value}) != material, (
            f"{field} is not covered by the signature"
        )


# ═══════════════════════════════════════════════════════════════════════════
# spec/0.6 §8.5 CONFORMANCE — driven from the SHIPPED umbrella vectors.
#
# The tests above were written before §8.5 existed and verify this module
# against its own understanding. These verify it against the SPEC's corpus, and
# that difference is the whole point: two runtimes that each pass the same
# published vectors agree by conformance. Two that agree because one copied the
# other, or because each wrote fixtures matching its own behaviour, have drift
# that simply has not surfaced.
# ═══════════════════════════════════════════════════════════════════════════

import hashlib  # noqa: E402
import json  # noqa: E402
from pathlib import Path  # noqa: E402

VECTORS = Path(__file__).resolve().parents[2] / "vectors" / "rotation" / "v06" / "peer-rotation-cases.json"
# Pinned to the umbrella corpus at `60cc22d`. If the umbrella corpus changes, this
# fails until someone re-syncs deliberately — rather than Orrery silently
# continuing to attest against a corpus the spec no longer blesses.
CANONICAL_SHA256 = "2b71d9e35364dede15efcd2047399dad92239f7a37646c54fd8451975a4de272"
DOC = json.loads(VECTORS.read_text())


def test_vector_corpus_is_the_unmodified_canonical_one():
    """ADVERSARIAL: a locally-edited corpus would let Orrery 'conform' to
    vectors it had adjusted to suit itself, which is exactly the drift §8.5 was
    specified ahead of implementation to prevent."""
    actual = hashlib.sha256(VECTORS.read_bytes()).hexdigest()
    assert actual == CANONICAL_SHA256, (
        f"vectors/rotation/v06 has drifted from the umbrella corpus.\n"
        f"  expected {CANONICAL_SHA256}\n  actual   {actual}\n"
        f"Re-copy from the umbrella at vectors/rotation/v06/ and update "
        f"CANONICAL_SHA256 in the same commit — see vectors/rotation/v06/PROVENANCE.md."
    )


@pytest.mark.parametrize("case", DOC["cases"], ids=[c["id"] for c in DOC["cases"]])
def test_spec_vector_case(case):
    """Every single-attestation case in the shipped corpus."""
    ok, why = fp.verify_rotation_attestation(
        case["attestation"],
        peer_id=case["peer_chapter_id"],
        pinned_did=case["pinned_did"],
        now=case["now"],
    )
    if case["expect"] == "accept":
        assert ok, f'{case["id"]} must be ACCEPTED; refused as {why!r} — {case["why"]}'
    else:
        assert not ok, (
            f'{case["id"]} was ACCEPTED. {case["why"]} An accept path that is right '
            f"with one refusal wrong is a silent takeover primitive, not a partial "
            f"implementation of §8.5."
        )
        assert why == case["refusal"], (
            f'{case["id"]}: refused as {why!r}, §8.5.4 names {case["refusal"]!r}. '
            f"Refusals must be individually diagnosable — one nobody can read gets "
            f"'fixed' by an operator running clear_did_pin, re-creating the hazard."
        )


@pytest.mark.parametrize("case", DOC["chain_cases"], ids=[c["id"] for c in DOC["chain_cases"]])
def test_spec_chain_case(case):
    """§8.5.2 chain walking — the capability this module did NOT have before."""
    ok, why, final = fp.walk_rotation_chain(
        case["rotations"],
        peer_id=case["peer_chapter_id"],
        pinned_did=case["pinned_did"],
        now=case["now"],
    )
    if case["expect"] == "accept":
        assert ok, f'{case["id"]} must be accepted; refused as {why!r}'
        assert final == case["final_did"], "chain walk landed on the wrong final key"
    else:
        assert not ok, f'{case["id"]} was accepted — {case["why"]}'
        assert why == case["refusal"], f"refused as {why!r}, spec names {case['refusal']!r}"
        assert final == case["pinned_did"], (
            "a refused chain MUST leave the ORIGINAL pin — advancing to a valid "
            "prefix leaves the pin on a key no complete chain authorised (§8.5.3)"
        )


def test_every_normative_refusal_is_exercised_against_this_module():
    """The mapping check: §8.5.4's nine refusals, each reached in THIS code.

    The nine hand-written tests above predate the normative list, so their
    coverage was assumed rather than shown. This asserts it.
    """
    reached = set()
    for case in DOC["cases"]:
        if case["expect"] != "refuse":
            continue
        ok, why = fp.verify_rotation_attestation(
            case["attestation"], peer_id=case["peer_chapter_id"],
            pinned_did=case["pinned_did"], now=case["now"],
        )
        assert not ok
        reached.add(why)
    for case in DOC["chain_cases"]:
        if case["expect"] != "refuse":
            continue
        ok, why, _ = fp.walk_rotation_chain(
            case["rotations"], peer_id=case["peer_chapter_id"],
            pinned_did=case["pinned_did"], now=case["now"],
        )
        assert not ok
        reached.add(why)
    required = {
        "no_signature", "signature_not_by_pinned_key", "old_did_not_pinned",
        "peer_mismatch", "stale", "future_dated", "new_did_invalid",
        "wrong_type", "no_pin", "chain_break",
    }
    assert required <= reached, f"§8.5.4 refusals never reached: {sorted(required - reached)}"
