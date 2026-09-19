"""Stage-2 smoke tests for the Orrery OpenClaw skill bundle.

Exercises the real crypto surface (did:key derivation, Ed25519 sign/verify, the
v0.3 signed-header set) and proves every helper module imports cleanly. No network,
no filesystem identity — the pure functions are tested directly.
"""

import base64

import pytest
import sign_request as sr
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _raw_pub(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def test_did_key_format():
    did = sr._build_did_key(_raw_pub(Ed25519PrivateKey.generate()))
    assert did.startswith("did:key:z")


def test_did_key_rejects_wrong_length():
    with pytest.raises(ValueError):
        sr._build_did_key(b"too-short")


def test_sign_verify_roundtrip_v03():
    priv = Ed25519PrivateKey.generate()
    canonical = sr.canonical_string_v03("POST", "/api/feedback", "{}", "agent-1", "1700000000", "nonce")
    sig_b64 = sr.ed25519_sign(priv, canonical)
    # raises InvalidSignature if the signature doesn't verify
    priv.public_key().verify(base64.b64decode(sig_b64), canonical.encode())


def test_signed_headers_v03_shape():
    priv = Ed25519PrivateKey.generate()
    did = sr._build_did_key(_raw_pub(priv))
    h = sr._signed_headers(priv, did, "agent-1", "{}", scheme="ed25519+nonce", method="POST", url_path="/api/x")
    assert h["X-Agent-Sig-Scheme"] == "ed25519+nonce"
    assert h["X-Agent-DID-Key"] == did
    assert "X-Agent-Nonce" in h and "X-Agent-Signature" in h


def test_unsupported_scheme_rejected():
    priv = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError):
        sr._signed_headers(priv, "did:key:z", "a", "{}", scheme="hmac")


def test_all_helpers_import():
    import _cache_signing  # noqa: F401
    import _sanitize  # noqa: F401
    import discover_org  # noqa: F401
    import stream_events  # noqa: F401
