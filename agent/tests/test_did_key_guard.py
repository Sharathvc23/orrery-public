"""P1 — refuse to mint a publishable did:key without real Ed25519.

On a minimal install (no PyNaCl), config falls back to ``generate_keypair()``,
whose ``public_key`` is ``sha256(private_key)`` — a 32-byte HASH, not an Ed25519
verify-key. ``build_did_key`` only checked ``len == 32``, so it happily encoded
the hash into a ``did:key`` that AgentFacts / NEST / A2A then advertised — an
identity nothing could verify a signature against.

``build_did_key`` now refuses unless Ed25519 is actually available, so the agent
never publishes a did:key it cannot back. The AgentFacts surface falls back to
``did:web`` instead.
"""

import base64

import pytest

import community_member.crypto as crypto


def _b64_32() -> str:
    return base64.b64encode(b"\x01" * 32).decode()


def test_build_did_key_refuses_without_ed25519(monkeypatch):
    monkeypatch.setattr(crypto, "ed25519_available", lambda: False)
    with pytest.raises(ValueError):
        crypto.build_did_key(_b64_32())


def test_build_did_key_works_with_ed25519():
    """When Ed25519 IS available (the normal case), a real verify-key still
    mints a did:key."""
    if not crypto.ed25519_available():
        pytest.skip("Ed25519 not available in this environment")
    kp = crypto.generate_ed25519_keypair()
    did = crypto.build_did_key(kp["public_key"])
    assert did.startswith("did:key:z")


def test_agentfacts_falls_back_to_did_web_without_ed25519(monkeypatch):
    """The published AgentFacts DID degrades to did:web rather than advertising
    a meaningless did:key from the HMAC-fallback hash."""
    from community_member.sm_bridge_adapter import _agent_did

    monkeypatch.setattr(crypto, "ed25519_available", lambda: False)

    class _Cfg:
        public_key = _b64_32()
        agent_id = "alice"

    did = _agent_did(_Cfg(), "https://example.com/agent")
    assert did.startswith("did:web:"), f"published a non-did:web identity without Ed25519: {did}"
