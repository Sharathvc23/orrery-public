"""Real-path proof that sign_request_body routes through the extracted canonical.

The conformance suite verifies `canonical_string_v0{2,3}` / `compose_signed_headers_*`
against the spec vectors. That only proves the helper functions are correct — not
that the production signer actually uses them. These tests close that gap: they call
the real `sign_request_body`, then confirm the emitted `X-Agent-Signature` verifies
over the canonical recomputed (from the *same* helper) using the echoed timestamp +
nonce. If the monolith ever stopped routing through the helper, the signature would
no longer verify over the helper's canonical and these fail.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from community_member import auth, crypto


def _verifies(pubkey_b64: str, canonical: str, signature_b64: str) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64))
    try:
        pub.verify(base64.b64decode(signature_b64), canonical.encode())
        return True
    except Exception:
        return False


def test_v03_signature_verifies_over_extracted_canonical() -> None:
    kp = crypto.generate_ed25519_keypair()
    auth.init_keys(kp["private_key"], kp["public_key"], "ed25519")

    headers = auth.sign_request_body("BODY-X", "agent-7", method="post", url_path="/api/members")
    assert headers["X-Agent-Sig-Scheme"] == "ed25519+nonce"

    canonical = auth.canonical_string_v03(
        "post",
        "/api/members",
        "BODY-X",
        "agent-7",
        headers["X-Agent-Timestamp"],
        headers["X-Agent-Nonce"],
    )
    assert _verifies(kp["public_key"], canonical, headers["X-Agent-Signature"])

    # A different method over the same echoed fields must NOT verify — proves the
    # signature actually binds the canonical's components, not just any string.
    wrong = auth.canonical_string_v03(
        "get",
        "/api/members",
        "BODY-X",
        "agent-7",
        headers["X-Agent-Timestamp"],
        headers["X-Agent-Nonce"],
    )
    assert not _verifies(kp["public_key"], wrong, headers["X-Agent-Signature"])


def test_v02_signature_verifies_over_extracted_canonical() -> None:
    kp = crypto.generate_ed25519_keypair()
    auth.init_keys(kp["private_key"], kp["public_key"], "ed25519")

    headers = auth.sign_request_body("BODY-Y", "agent-2")  # no method/url_path → v0.2
    assert headers["X-Agent-Sig-Scheme"] == "ed25519"

    canonical = auth.canonical_string_v02("BODY-Y", "agent-2", headers["X-Agent-Timestamp"])
    assert _verifies(kp["public_key"], canonical, headers["X-Agent-Signature"])
