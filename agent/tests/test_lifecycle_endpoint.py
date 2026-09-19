"""The lifecycle answer over real HTTP — it must never 404.

A state that is not served anywhere is not resolvable; it is a local variable.
These drive the real FastAPI app so the claim "a caller can tell revoked from
not-found" is exercised the way a caller would exercise it.

⚠️ The single most important assertion here is that the endpoint returns **200
with an explicit state in every case, including "never established"**. A 404
would recreate the exact ambiguity the unit removes — the caller is back to
guessing whether the subject was withdrawn or the lookup failed.
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from community_member import owner

LIFECYCLE_URL = "/.well-known/agent-lifecycle.json"


@pytest.fixture
def client(tmp_path, monkeypatch):
    from community_member import config as config_mod
    from community_member.config import Config
    from community_member.crypto import generate_keypair
    from community_member.server import create_app

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    cfg = Config()
    cfg.agent_id = "moonbakery"
    cfg.name = "Moon Bakery"
    cfg.description = "A bakery"
    cfg.api_key = "x" * 32
    kp = generate_keypair()
    cfg.private_key = kp["private_key"]
    cfg.public_key = kp["public_key"]

    class FakeAgent:
        AGENT_TOOLS = [{"type": "function", "function": {"name": "search_chapter", "description": "d"}}]

        async def execute_tool(self, name, args):
            return json.dumps({"ok": True})

    return TestClient(create_app(cfg, agent=FakeAgent())), tmp_path


def _establish(home, identity, subject="moonbakery.com"):
    nonce = owner.owner_nonce(identity.did, "r")
    anchor = {"method": "oidc", "issuer": "https://accounts.google.com", "id": "sub-1"}
    from community_member.crypto import build_did_key

    owner.save_binding(
        home,
        owner_did=identity.did,
        subject=subject,
        anchor=anchor,
        evidence=owner.build_owner_evidence(
            owner=identity, subject=subject, anchor=anchor, id_token="h.p.s", nonce=nonce
        ),
        grant=owner.build_listing_grant(
            owner=identity, agent_did=build_did_key(base64.b64encode(b"\x01" * 32).decode())
        ),
    )


# ── ⚠️ never 404 ─────────────────────────────────────────────────────────────


def test_never_established_answers_200_with_an_explicit_state(client):
    """⚠️ A 404 here would be the whole defect. "Nothing found" is exactly the
    answer a caller cannot act on."""
    tc, _ = client
    resp = tc.get(LIFECYCLE_URL)
    assert resp.status_code == 200
    assert resp.json()["state"] == owner.LIFECYCLE_NOT_ESTABLISHED


@pytest.mark.parametrize(
    "transition,expected",
    [
        (None, owner.LIFECYCLE_ACTIVE),
        (owner.LIFECYCLE_SUSPENDED, owner.LIFECYCLE_SUSPENDED),
        (owner.LIFECYCLE_REVOKED, owner.LIFECYCLE_REVOKED),
    ],
)
def test_every_state_answers_200(client, transition, expected):
    tc, home = client
    _establish(home, owner.mint_owner_identity())
    if transition:
        owner.set_lifecycle(home, transition)
    resp = tc.get(LIFECYCLE_URL)
    assert resp.status_code == 200
    assert resp.json()["state"] == expected


def test_revoked_is_distinguishable_from_never_established_over_http(client):
    """The assertion the owner-attested rework is actually about, driven end to end."""
    tc, home = client
    before = tc.get(LIFECYCLE_URL).json()
    _establish(home, owner.mint_owner_identity())
    owner.revoke_listing(home, reason="closed")
    after = tc.get(LIFECYCLE_URL).json()

    assert before["state"] == owner.LIFECYCLE_NOT_ESTABLISHED
    assert after["state"] == owner.LIFECYCLE_REVOKED
    assert before["state"] != after["state"]
    # And the same HTTP status for both, so the status code is not doing the
    # discriminating — the body is, which is what a caller can rely on.
    assert tc.get(LIFECYCLE_URL).status_code == 200


def test_the_revoked_answer_carries_the_authority_and_the_time(client):
    tc, home = client
    identity = owner.mint_owner_identity()
    _establish(home, identity)
    owner.revoke_listing(home, reason="sold the business")
    body = tc.get(LIFECYCLE_URL).json()
    assert body["revoking_authority"] == identity.did
    assert body["since"]
    assert body["reason"] == "sold the business"
    assert body["subject"] == "moonbakery.com"


def test_an_unsigned_revocation_is_not_reported_as_owner_attested(client):
    tc, home = client
    _establish(home, owner.mint_owner_identity())
    owner.revoke_listing(home)
    assert tc.get(LIFECYCLE_URL).json()["owner_attested"] is False


def test_a_signed_revocation_is_reported_as_owner_attested(client):
    tc, home = client
    identity = owner.mint_owner_identity()
    _establish(home, identity)
    owner.revoke_listing(home, owner=identity)
    assert tc.get(LIFECYCLE_URL).json()["owner_attested"] is True


def test_the_endpoint_needs_no_auth(client):
    """A resolver deciding whether to transact has no credentials with this
    agent — requiring auth would make the answer unreachable by the only
    audience that needs it."""
    tc, home = client
    _establish(home, owner.mint_owner_identity())
    owner.revoke_listing(home)
    assert tc.get(LIFECYCLE_URL).status_code == 200


def test_the_endpoint_leaks_no_grant_or_evidence(client):
    tc, home = client
    identity = owner.mint_owner_identity()
    _establish(home, identity)
    owner.revoke_listing(home, owner=identity)
    blob = tc.get(LIFECYCLE_URL).text
    assert "evidence" not in blob
    assert "grant" not in blob
    assert identity.private_key_b64 not in blob


# ── the agent card carries it too ────────────────────────────────────────────


def test_the_agent_card_carries_the_lifecycle(client):
    """A resolver that only fetches the card must still learn.

    Without this, the card of a business that withdrew reads exactly like the
    card of an active one — the ambiguity, on the surface most clients use.
    """
    tc, home = client
    _establish(home, owner.mint_owner_identity())
    owner.revoke_listing(home)
    ext = tc.get("/.well-known/agent.json").json()["x-nanda"]
    assert ext["lifecycle"]["state"] == owner.LIFECYCLE_REVOKED
    assert ext["lifecycle_url"].endswith(LIFECYCLE_URL)


def test_the_card_lifecycle_is_a_sibling_of_profile_not_inside_it(client):
    """``profile`` is signed canonical JSON. A key added inside it would change
    the bytes the signature covers and break verification for every consumer."""
    tc, home = client
    _establish(home, owner.mint_owner_identity())
    ext = tc.get("/.well-known/agent.json").json()["x-nanda"]
    assert "lifecycle" in ext
    assert "lifecycle" not in (ext.get("profile") or {})


def test_the_card_still_serves_when_no_binding_exists(client):
    """An agent that never consented is not broken — it is not_established."""
    tc, _ = client
    resp = tc.get("/.well-known/agent.json")
    assert resp.status_code == 200
    assert resp.json()["x-nanda"]["lifecycle"]["state"] == owner.LIFECYCLE_NOT_ESTABLISHED
