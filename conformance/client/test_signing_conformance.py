"""Client signing-conformance suite.

Runs the committed ``vectors/signing/`` corpus through the selected ``--adapter``
and asserts byte-for-byte agreement with the spec. A runtime that derives a
different did:key, builds a different canonical string, or produces a different
Ed25519 signature fails here — the executable contract behind the
"trust by cryptography, not vendor" thesis.

Coverage: did:key derivation (+ an adversarial drift case), the v0.2 canonical
string, a real Ed25519 sign roundtrip (deterministic per RFC 8032, so the
signature must match exactly), and the v0.3 canonical string.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def test_did_key_derivation(adapter, signing_vectors):
    vectors = signing_vectors("did-key-derivations.json")
    for case in vectors["cases"]:
        pubkey = bytes.fromhex(case["input"]["pubkey32_hex"])
        assert adapter.derive_did_key(pubkey) == case["expected"]["did_key"], case["id"]


def test_did_key_adversarial_drift_rejected(adapter, signing_vectors):
    """The conforming did:key must NOT equal the base64url-encoded variant — a
    runtime that used the wrong multibase would collide with this and fail."""
    vectors = signing_vectors("did-key-derivations.json")
    for case in vectors.get("adversarial_cases", []):
        pubkey = bytes.fromhex(case["input"]["pubkey32_hex"])
        got = adapter.derive_did_key(pubkey)
        assert got == case["expected"]["conforming_did_key"], case["id"]
        assert got != case["expected"]["must_not_equal"], case["id"]


def test_canonical_string_v02(adapter, signing_vectors):
    vectors = signing_vectors("ed25519-canonical-strings.json")
    for case in vectors["cases"]:
        i = case["input"]
        got = adapter.canonical_string(i["body"], i["agent_id"], i["timestamp"])
        assert got == case["expected"]["canonical_string"], case["id"]


def test_sign_roundtrip_v02(adapter, signing_vectors):
    """Ed25519 is deterministic (RFC 8032): a conformant signer produces the
    exact signature in the vector, and it verifies against the public key."""
    vectors = signing_vectors("ed25519-canonical-strings.json")
    seed = bytes.fromhex(vectors["signing_key"]["private_key32_hex"])
    pub = bytes.fromhex(vectors["signing_key"]["public_key32_hex"])
    verifier = Ed25519PublicKey.from_public_bytes(pub)
    for case in vectors["cases"]:
        i = case["input"]
        canonical = adapter.canonical_string(i["body"], i["agent_id"], i["timestamp"])
        sig_b64 = adapter.sign(seed, canonical)
        assert sig_b64 == case["expected"]["signature_b64"], f"{case['id']}: signature differs from spec"
        # And it actually verifies — the signature is real, not just matching.
        verifier.verify(base64.b64decode(sig_b64), canonical.encode())


def test_canonical_string_v03(adapter, signing_vectors):
    vectors = signing_vectors("canonical-strings-v03.json")
    for case in vectors["cases"]:
        i = case["input"]
        got = adapter.canonical_string_v03(
            i["method"], i["url_path"], i["body"], i["agent_id"], i["timestamp"], i["nonce"]
        )
        assert got == case["expected"]["canonical_string"], case["id"]
