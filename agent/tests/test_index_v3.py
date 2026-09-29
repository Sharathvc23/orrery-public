"""Claiming a name on Index v3 — one key, three views.

⚠️ THE PROPERTY THIS PROTECTS. The index name ``urn:ai:key:<subject_key>``, the
``did:key`` on this agent's card, and the issuer on every ARP receipt it signs
must be **the same key in three encodings** — not three assertions that happen
to agree today. If they can drift, a resolver reaching the agent through the
index, a peer verifying one of its receipts, and anyone reading its card are
each trusting a different identity while believing they are trusting one.

The load-bearing assertion is ``test_index_name_and_arp_did_are_the_same_key``.

The cross-implementation checks need a ``nanda-index-v3`` checkout and skip
without one. They are worth having anyway: a signing format reimplemented from a
spec and never compared against the implementation that verifies it is a guess.
"""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import pytest

from community_member.index_v3 import (
    AGENT_CARD_MEDIA_TYPE,
    INTENT_CONTEXT,
    INTENT_FIELDS,
    IndexV3Error,
    ensure_registered,
    key_urn,
    register,
    sign_intent,
    subject_key_of,
)

INDEX_SRC = Path(os.environ.get("NANDA_INDEX_V3", Path.home() / "nanda-index-v3")) / "src"
_HAVE_INDEX = (INDEX_SRC / "api" / "app.py").exists()
needs_index = pytest.mark.skipif(
    not _HAVE_INDEX, reason=f"no nanda-index-v3 checkout at {INDEX_SRC} (set NANDA_INDEX_V3)"
)
if _HAVE_INDEX and str(INDEX_SRC) not in sys.path:
    sys.path.insert(0, str(INDEX_SRC))


def _key_b64() -> str:
    """A private key in the encoding ``config.private_key`` uses: b64 of the seed."""
    from nacl.signing import SigningKey

    return base64.b64encode(bytes(SigningKey.generate())).decode()


# ── the property ────────────────────────────────────────────────────────────


def test_index_name_and_arp_did_are_the_same_key():
    """The whole point. Drift here splits one identity into several."""
    from community_member.arp import did_from_private_key

    private_b64 = _key_b64()
    seed = base64.b64decode(private_b64)

    # What the index will call this agent.
    subject_key = subject_key_of(private_b64)
    # What its receipts are signed by.
    did = did_from_private_key(seed)

    # Different encodings, same 32 bytes of public key underneath.
    import base58

    from_index = base64.urlsafe_b64decode(subject_key[1:] + "=" * (-len(subject_key[1:]) % 4))
    from_did = base58.b58decode(did.removeprefix("did:key:z"))[2:]  # strip the 0xed01 prefix

    assert from_index == from_did, (
        "the index name and the receipt issuer are different keys; a peer "
        "verifying a receipt is not verifying the agent discovery returned"
    )


def test_a_name_is_derived_from_the_key_not_chosen():
    a, b = _key_b64(), _key_b64()
    assert key_urn(subject_key_of(a), "agent") != key_urn(subject_key_of(b), "agent")
    assert subject_key_of(a) == subject_key_of(a)


def test_absent_intent_fields_are_omitted_not_nulled():
    """Under JCS an absent key and a null one are different bytes."""
    private_b64 = _key_b64()
    challenge = {
        "challenge_id": "c1", "id": "urn:ai:key:uAAA/agent", "subject_key": "uAAA",
        "next_hop": "https://agent.example", "media_type": AGENT_CARD_MEDIA_TYPE, "nonce": "n",
    }
    padded = dict(challenge, audience=None, not_after=None, prev=None)

    assert sign_intent(private_b64, challenge) != sign_intent(private_b64, padded)


# ── against the index itself ────────────────────────────────────────────────


@needs_index
def test_signing_constants_and_encoding_match_the_index():
    from core.envelope import public_key_to_multibase  # type: ignore[import-not-found]
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from provers.base import INTENT_CONTEXT as THEIRS_CTX  # type: ignore[import-not-found]
    from provers.base import INTENT_FIELDS as THEIRS_FIELDS  # type: ignore[import-not-found]

    assert INTENT_CONTEXT == THEIRS_CTX
    assert INTENT_FIELDS == tuple(THEIRS_FIELDS)

    private_b64 = _key_b64()
    theirs = public_key_to_multibase(
        Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64)).public_key()
    )
    assert subject_key_of(private_b64) == theirs


@needs_index
def test_a_real_index_accepts_what_this_signs(tmp_path, monkeypatch):
    """End to end against the actual server, which verifies the signature itself."""
    from fastapi.testclient import TestClient

    monkeypatch.chdir(tmp_path)
    from api.app import build  # type: ignore[import-not-found]

    client = TestClient(build())
    private_b64 = _key_b64()
    next_hop = "https://agent.example/.well-known/agent-card.json"

    record = register(
        index_url="http://testserver", private_key_b64=private_b64,
        next_hop=next_hop, http=client,
    )["record"]

    assert record["id"] == key_urn(subject_key_of(private_b64), "agent")
    assert record["next_hop"] == next_hop

    resolved = client.get("/v1/resolve", params={"id": record["id"]})
    assert resolved.status_code == 200
    assert resolved.json()["record"]["next_hop"] == next_hop


@needs_index
def test_the_index_refuses_a_signature_over_a_next_hop_it_never_issued(tmp_path, monkeypatch):
    """Negative control. Without this, "the subject asked for this destination"
    is an empty claim."""
    from fastapi.testclient import TestClient

    monkeypatch.chdir(tmp_path)
    from api.app import build  # type: ignore[import-not-found]

    client = TestClient(build())
    private_b64 = _key_b64()
    subject_key = subject_key_of(private_b64)

    started = client.post("/v1/register", json={
        "id": key_urn(subject_key, "agent"), "subject_key": subject_key,
        "next_hop": "https://agent.example/card.json",
        "media_type": AGENT_CARD_MEDIA_TYPE, "anchor_type": "key",
    })
    challenge = started.json()["challenge"]

    forged = dict(challenge, next_hop="https://attacker.example/card.json")
    proved = client.post("/v1/prove", json={
        "challenge_id": challenge["challenge_id"],
        "response": {"subject_sig": sign_intent(private_b64, forged)},
    })

    assert proved.status_code >= 400


# ── renewal ─────────────────────────────────────────────────────────────────


@needs_index
def test_a_restart_does_not_append_to_an_append_only_log(tmp_path, monkeypatch):
    """Registering on every start is right; registering unconditionally is not."""
    from fastapi.testclient import TestClient

    monkeypatch.chdir(tmp_path)
    from api.app import build  # type: ignore[import-not-found]

    client = TestClient(build())
    args = dict(index_url="http://testserver", private_key_b64=_key_b64(),
                next_hop="https://agent.example/card.json", http=client)

    assert ensure_registered(**args)["action"] == "registered"
    size = client.get("/health").json()["tree_size"]

    for _ in range(3):
        assert ensure_registered(**args)["action"] == "current"

    assert client.get("/health").json()["tree_size"] == size


@needs_index
def test_a_record_near_expiry_is_renewed(tmp_path, monkeypatch):
    """Renewal must happen before expiry, or discovery goes dark first."""
    from datetime import datetime, timedelta

    from fastapi.testclient import TestClient

    monkeypatch.chdir(tmp_path)
    from api.app import build  # type: ignore[import-not-found]

    client = TestClient(build())
    args = dict(index_url="http://testserver", private_key_b64=_key_b64(),
                next_hop="https://agent.example/card.json", http=client)

    first = ensure_registered(**args)
    expires = datetime.fromisoformat(first["expires_at"].replace("Z", "+00:00"))

    renewed = ensure_registered(**args, now=lambda: expires - timedelta(minutes=5))
    assert renewed["action"] == "renewed"
    assert renewed["seq"] == first["seq"] + 1


def test_an_unreachable_index_is_reported_not_raised():
    """Someone else's outage must not become ours."""

    class _Down:
        def get(self, *_a, **_k):
            raise ConnectionError("index is down")

    result = ensure_registered(
        index_url="http://index.test", private_key_b64=_key_b64(),
        next_hop="https://agent.example", http=_Down(),
    )
    assert result["action"] == "unreachable"


def test_a_refusal_is_reported_not_raised():
    class _Refusing:
        def get(self, *_a, **_k):
            return _Resp(404, "{}")

        def post(self, *_a, **_k):
            return _Resp(400, '{"error":"proof_rejected"}')

    class _Resp:
        def __init__(self, status_code, text):
            self.status_code, self.text = status_code, text

        def json(self):
            import json

            return json.loads(self.text)

    result = ensure_registered(
        index_url="http://index.test", private_key_b64=_key_b64(),
        next_hop="https://agent.example", http=_Refusing(),
    )
    assert result["action"] == "failed"
    assert "proof_rejected" in result["detail"]
