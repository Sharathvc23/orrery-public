"""H4/H7 — the emit path fails closed, and cross-org A2A proves who is asking.

H4: sign_outbound()/sign_request() returned {} when the chapter had no keypair,
and callers sent the request anyway. A fail-OPEN on the emit path, and invisible
from our side: our logs looked clean and the failure surfaced as a rejection on
the PEER's box, if the peer enforced at all.

H7: query_chapter() POSTed to a peer's /a2a with no identity proof at all.

⚠️ Why outbound fails CLOSED while H9 (inbound rotation) must not: they are
opposite sides of the trust boundary. Refusing to EMIT costs us nothing — an
unsigned federation message is worthless to us anyway, since the receiver's
enforcement is the only thing that would have given it weight. Refusing to
ACCEPT a rotated peer key costs a legitimate peer its whole membership. Same
word, different decision.
"""

from __future__ import annotations

import pytest

import federation_signing
import sovereign_identity

CHAPTER = "TEST-h4-chapter"


@pytest.fixture
def no_keypair(monkeypatch):
    monkeypatch.setattr(sovereign_identity, "_ed25519_keypairs", {})


@pytest.fixture
def with_keypair(monkeypatch):
    monkeypatch.setattr(sovereign_identity, "_ed25519_keypairs", {})
    sovereign_identity.generate_ed25519_keypair(CHAPTER)
    return CHAPTER


def test_H4_sign_outbound_refuses_instead_of_returning_empty(no_keypair):
    """The finding itself: {} let the caller send unsigned."""
    with pytest.raises(federation_signing.OutboundUnsigned, match="refusing to emit unsigned"):
        federation_signing.sign_outbound(CHAPTER, {"a": 1})


def test_H4_sign_request_refuses_instead_of_returning_empty(no_keypair):
    with pytest.raises(federation_signing.OutboundUnsigned):
        federation_signing.sign_request(CHAPTER, "GET", "/api/members")


def test_H4_no_signing_path_returns_an_empty_dict(no_keypair):
    """Pinned by name, per the done-when: NO code path may return {} where a
    signature was expected. An empty dict is indistinguishable from 'signed' to
    a caller that only checks truthiness of individual headers."""
    for fn in (
        lambda: federation_signing.sign_outbound(CHAPTER, {"a": 1}),
        lambda: federation_signing.sign_request(CHAPTER, "GET", "/x"),
    ):
        with pytest.raises(federation_signing.OutboundUnsigned):
            result = fn()
            assert result != {}, "returned {} instead of refusing"


def test_H4_the_error_names_the_cause_and_the_fix(no_keypair):
    """A refusal nobody can act on is only marginally better than silence."""
    with pytest.raises(federation_signing.OutboundUnsigned) as e:
        federation_signing.sign_outbound(CHAPTER, {})
    msg = str(e.value)
    assert CHAPTER in msg
    assert "ensure_chapter_keypair" in msg


def test_H4_signing_still_works_when_a_keypair_exists(with_keypair):
    headers = federation_signing.sign_outbound(with_keypair, {"a": 1})
    assert headers[federation_signing.CHAPTER_SIG_HEADER]
    assert headers[federation_signing.CHAPTER_DID_HEADER].startswith("did:key:")


def test_H7_sign_request_binds_method_and_path(with_keypair):
    """H7 reuses this scheme rather than inventing one, so the binding it gets
    is the same one member-directory reads already rely on: a captured
    signature cannot be moved to another route or method."""
    a = federation_signing.request_descriptor("POST", "/a2a", with_keypair)
    b = federation_signing.request_descriptor("GET", "/a2a", with_keypair)
    c = federation_signing.request_descriptor("POST", "/api/members", with_keypair)
    assert a != b and a != c


async def test_H7_a2a_query_signs_with_the_existing_scheme(with_keypair, monkeypatch):
    """The cross-org A2A POST must carry S2S identity headers."""
    import federation_discovery as fd

    monkeypatch.setattr(fd, "_agent_id", with_keypair)
    monkeypatch.setattr(fd, "_federation", {"peer": {"endpoint": "https://peer.example"}})

    seen: dict = {}

    class _Resp:
        status_code = 200

        def json(self):
            return {"content": {"text": "hi"}}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, headers=None, json=None, timeout=None):
            seen["headers"] = headers or {}
            return _Resp()

    monkeypatch.setattr(fd.httpx, "AsyncClient", lambda *a, **k: _Client())

    await fd.query_chapter("peer", "q")

    assert federation_signing.CHAPTER_SIG_HEADER in seen["headers"], "A2A query went unsigned"
    assert seen["headers"][federation_signing.CHAPTER_ORIGIN_HEADER] == with_keypair


async def test_H7_a2a_query_refuses_rather_than_asking_unsigned(no_keypair, monkeypatch):
    """H4 applies here too: no key means no query, not an anonymous one."""
    import federation_discovery as fd

    monkeypatch.setattr(fd, "_agent_id", CHAPTER)
    monkeypatch.setattr(fd, "_federation", {"peer": {"endpoint": "https://peer.example"}})

    def _boom(*a, **k):
        raise AssertionError("sent a request despite having no keypair")

    monkeypatch.setattr(fd.httpx, "AsyncClient", _boom)

    assert await fd.query_chapter("peer", "q") is None
