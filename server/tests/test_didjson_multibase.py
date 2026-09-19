"""did.json verificationMethod speaks standard W3C —
Ed25519VerificationKey2020 requires publicKeyMultibase (z-base58btc over the
0xed01 multicodec), not the nonstandard publicKeyBase64 it carried.

Transition contract: BOTH fields served one window (live federation peers
still read the legacy field from each other); readers prefer multibase.
The key itself never changes — round-trip against the org signer is asserted.

Classification: HAPPY / EDGE / ADVERSARIAL.
"""

import base64
import os
import sys

os.environ.setdefault("AGENT_ID", "test-didjson-chapter")
os.environ.setdefault("AGENT_NAME", "Test DidJson Chapter")

import base58
import pytest
from fastapi.testclient import TestClient

import chapter_agent  # noqa: F401 — ensures sys.modules['chapter_agent'] exists when this module runs alone
import federation_signing
import sovereign_identity


@pytest.fixture
def vm():
    # Give the org a signing key, as startup's ensure_chapter_keypair does.
    # did.json READS the key and 503s when absent — it no longer mints one on
    # demand, because an anonymous read must not be able to invent (and,
    # via the _ed25519_keypairs cache, then block) this org's identity.
    # Resolve the id through sys.modules, exactly as routes/identity.py's `ca`
    # proxy does: other modules re-import chapter_agent, so a module-level
    # reference captured at import time can be a stale object whose AGENT_ID is
    # not the one the handler reads.
    live = sys.modules["chapter_agent"]
    sovereign_identity.generate_ed25519_keypair(live.AGENT_ID)
    client = TestClient(live.app)
    doc = client.get("/.well-known/did.json").json()
    assert "verificationMethod" in doc, f"did.json did not serve a document: {doc}"
    return doc["verificationMethod"][0]


def test_multibase_field_present_and_z_prefixed(vm):
    assert vm["type"] == "Ed25519VerificationKey2020"
    assert vm["publicKeyMultibase"].startswith("z")


def test_standard_resolver_extracts_the_key(vm):
    """HAPPY (the done-when): a by-the-book multibase/multicodec decode —
    base58btc, 0xed01 prefix, 32 key bytes — recovers the org key."""
    raw = base58.b58decode(vm["publicKeyMultibase"][1:])
    assert raw[:2] == b"\xed\x01"
    assert len(raw) == 34
    assert raw[2:] == base64.b64decode(vm["publicKeyBase64"])


def test_round_trips_with_the_attestation_signer_key():
    """HAPPY: same identity as the badge/attestation signer — the multibase
    equals the org's did:key derivation for its LIVE keypair (no key change).

    Resolves chapter_agent through sys.modules exactly like the route's ``ca``
    proxy does (another suite module re-imports chapter_agent, so the
    module-level import here can go stale), and seeds the keypair so the test
    owns its state."""
    import sys

    ca = sys.modules["chapter_agent"]
    sovereign_identity.generate_ed25519_keypair(ca.AGENT_ID)
    kp = sovereign_identity._ed25519_keypairs[ca.AGENT_ID]
    pk_b64 = base64.b64encode(kp["public_key"]).decode()
    served = TestClient(ca.app).get("/.well-known/did.json").json()["verificationMethod"][0]
    expected = sovereign_identity.build_did_key_from_ed25519(pk_b64).removeprefix("did:key:")
    assert served["publicKeyMultibase"] == expected
    assert served["publicKeyBase64"] == pk_b64


def test_legacy_field_still_served_one_transition_window(vm):
    """EDGE: un-upgraded live peers read publicKeyBase64 — it stays until 1.0."""
    assert vm["publicKeyBase64"]


# ── the federation reader prefers multibase, tolerates everything else ────


def _vm_doc(**fields):
    return {"verificationMethod": [dict(fields)]}


@pytest.mark.asyncio
async def test_reader_prefers_multibase(monkeypatch):
    kp = sovereign_identity.generate_ed25519_keypair("didjson-tmp")
    sovereign_identity._ed25519_keypairs.pop("didjson-tmp", None)
    mb = sovereign_identity.build_did_key_from_ed25519(kp["public_key"]).removeprefix("did:key:")

    async def fake_get(url):
        return _vm_doc(publicKeyMultibase=mb, publicKeyBase64="legacy-should-not-win")

    got = await federation_signing.fetch_peer_pubkey("https://peer.example", http_get=fake_get)
    assert got == kp["public_key"]


@pytest.mark.asyncio
async def test_reader_falls_back_to_legacy_field():
    async def fake_get(url):
        return _vm_doc(publicKeyBase64="legacy-b64-key")

    got = await federation_signing.fetch_peer_pubkey("https://peer.example", http_get=fake_get)
    assert got == "legacy-b64-key"


@pytest.mark.asyncio
async def test_reader_rejects_junk_multibase_then_uses_legacy():
    """ADVERSARIAL: a malformed multibase (bad multicodec) never yields a key;
    the legacy field still rescues the doc."""
    async def fake_get(url):
        return _vm_doc(publicKeyMultibase="zNotARealMultibaseKey", publicKeyBase64="legacy-b64-key")

    got = await federation_signing.fetch_peer_pubkey("https://peer.example", http_get=fake_get)
    assert got == "legacy-b64-key"
