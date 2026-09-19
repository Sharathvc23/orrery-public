"""provider.did migrates from the legacy internal ``did:key:{raw-b64}``
carrier to the proper W3C ``did:key:z…`` derivation.

Contract under test (permanent dual-read within 0.x, writes converge):

* READERS accept BOTH formats — a pre-migration row keeps authenticating
  after a restart (the security round-trip, both directions).
* WRITERS emit only the W3C form; non-Ed25519 material (legacy HMAC keys
  that used to masquerade in the field) gets NO DID at all.
* Frozen wire ids untouched — this is the internal provider.did convention.

Classification: HAPPY / EDGE / ADVERSARIAL.
"""

import time

import pytest

import auth_verify
import sovereign_identity

pytestmark = pytest.mark.usefixtures("clean_keys")


@pytest.fixture
def clean_keys():
    auth_verify._agent_keys.clear()
    yield
    auth_verify._agent_keys.clear()


def _ed25519_member():
    kp = sovereign_identity.generate_ed25519_keypair("mig-tmp")
    sovereign_identity._ed25519_keypairs.pop("mig-tmp", None)
    return kp  # {"private_key": b64, "public_key": b64}


# ── pubkey_from_provider_did: the dual-format reader ────────────────────


def test_reads_w3c_form():
    kp = _ed25519_member()
    did = sovereign_identity.build_did_key_from_ed25519(kp["public_key"])
    assert sovereign_identity.pubkey_from_provider_did(did) == kp["public_key"]


def test_reads_legacy_ed25519_carrier():
    """HAPPY: the legacy internal form still yields the key."""
    kp = _ed25519_member()
    legacy = f"did:key:{kp['public_key']}"
    assert sovereign_identity.pubkey_from_provider_did(legacy) == kp["public_key"]


def test_legacy_hmac_carrier_yields_nothing():
    """ADVERSARIAL: a legacy HMAC pubkey riding in the field is NOT Ed25519
    material — it must never come back as a verifiable key."""
    assert sovereign_identity.pubkey_from_provider_did("did:key:hmac-public-key-string") == ""


@pytest.mark.parametrize("junk", ["", "did:web:example.com", "did:key:", "did:key:%%%%", "not-a-did"])
def test_junk_yields_nothing(junk):
    assert sovereign_identity.pubkey_from_provider_did(junk) == ""


# ── writers emit the W3C form only ───────────────────────────────────────


def test_build_nanda_facts_emits_w3c_did_for_ed25519_key():
    kp = _ed25519_member()
    facts = sovereign_identity.build_nanda_facts("mig-agent", {"name": "Mig"}, kp["public_key"])
    did = facts["provider"]["did"]
    assert did.startswith("did:key:z6Mk")
    # round-trips through the strict W3C extractor — the legacy form never did
    assert sovereign_identity.extract_ed25519_pubkey_from_did_key(did) == kp["public_key"]


def test_build_nanda_facts_emits_no_did_for_non_ed25519_key():
    """EDGE: an HMAC-era public key gets NO DID — it never was one. (HMAC
    verification reads signing_secret, never this field.)"""
    facts = sovereign_identity.build_nanda_facts("mig-agent", {"name": "Mig"}, "hmac-public-key-string")
    assert facts["provider"].get("did") is None


# ── the security round-trip: persisted row → restart → signed request ────


def _roundtrip_verifies(did: str, kp: dict) -> tuple[bool, str]:
    """Simulate restart rehydration from a persisted row carrying ``did``,
    then verify a REAL signed request from that member."""
    auth_verify.load_keys_from_members(
        {"mig-agent": {"name": "Mig", "agent_facts": {"provider": {"did": did}}}}
    )
    ts = str(int(time.time()))
    message = f"{{}}:mig-agent:{ts}"
    sig = sovereign_identity.ed25519_sign(message, kp["private_key"])
    valid, _, reason = auth_verify.verify_request(
        "{}",
        {
            "X-Agent-ID": "mig-agent",
            "X-Agent-Signature": sig,
            "X-Agent-Timestamp": ts,
            "X-Agent-Sig-Scheme": "ed25519",
        },
    )
    return valid, reason


def test_legacy_row_still_authenticates_after_restart():
    """THE THAT CHANGE guarantee: a live-org row persisted BEFORE the migration
    (legacy did format) rehydrates on restart and its signatures verify."""
    kp = _ed25519_member()
    valid, reason = _roundtrip_verifies(f"did:key:{kp['public_key']}", kp)
    assert valid, f"legacy-format row failed to authenticate: {reason}"


def test_w3c_row_authenticates_after_restart():
    """HAPPY: the post-migration format round-trips identically."""
    kp = _ed25519_member()
    did = sovereign_identity.build_did_key_from_ed25519(kp["public_key"])
    valid, reason = _roundtrip_verifies(did, kp)
    assert valid, f"W3C-format row failed to authenticate: {reason}"


def test_full_write_read_roundtrip_through_new_facts():
    """HAPPY: facts written by the NEW writer rehydrate through the reader —
    the converged end-state round-trip."""
    kp = _ed25519_member()
    facts = sovereign_identity.build_nanda_facts("mig-agent", {"name": "Mig"}, kp["public_key"])
    valid, reason = _roundtrip_verifies(facts["provider"]["did"], kp)
    assert valid, reason
