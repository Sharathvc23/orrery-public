"""The uninstall webhook over real HTTP.

⚠️ The endpoint is open by ROUTE and closed by SIGNATURE — a platform has no
agent credentials, so it cannot sit behind agent auth. With no secret configured
every request is refused, so the surface is inert until deliberately enabled.
These drive the real FastAPI app because "the module refuses" and "the endpoint
refuses" are different claims, and only the second one is what an attacker meets.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from community_member import owner, platform_events

SECRET = "a-real-shared-secret"
PLATFORM = "square"
URL = f"/webhooks/platform/{PLATFORM}/uninstall"
LIFECYCLE_URL = "/.well-known/agent-lifecycle.json"


@pytest.fixture
def client(tmp_path, monkeypatch):
    from community_member import config as config_mod
    from community_member.config import Config
    from community_member.crypto import generate_keypair
    from community_member.server import create_app

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setenv(f"ORRERY_PLATFORM_WEBHOOK_SECRET_{PLATFORM.upper()}", SECRET)
    cfg = Config()
    cfg.agent_id = "moonbakery"
    cfg.name = "Moon Bakery"
    cfg.api_key = "x" * 32
    kp = generate_keypair()
    cfg.private_key = kp["private_key"]
    cfg.public_key = kp["public_key"]

    class FakeAgent:
        AGENT_TOOLS = [{"type": "function", "function": {"name": "search_chapter", "description": "d"}}]

        async def execute_tool(self, name, args):
            return json.dumps({"ok": True})

    return TestClient(create_app(cfg, agent=FakeAgent())), tmp_path


def _establish(home):
    identity = owner.mint_owner_identity()
    from community_member.crypto import build_did_key

    nonce = owner.owner_nonce(identity.did, "r")
    anchor = {"method": "oidc", "issuer": "https://accounts.google.com", "id": "sub-1"}
    owner.save_binding(
        home,
        owner_did=identity.did,
        subject="moonbakery.com",
        anchor=anchor,
        evidence=owner.build_owner_evidence(
            owner=identity, subject="moonbakery.com", anchor=anchor, id_token="h.p.s", nonce=nonce
        ),
        grant=owner.build_listing_grant(
            owner=identity, agent_did=build_did_key(base64.b64encode(b"\x01" * 32).decode())
        ),
    )
    return identity


def _body(event_id="evt-1"):
    return json.dumps(
        {
            "event_id": event_id,
            "occurred_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "subject": "moonbakery.com",
        }
    ).encode()


def _sign(raw, secret=SECRET):
    return hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()


def test_a_verified_uninstall_suspends_over_http(client):
    tc, home = client
    _establish(home)
    raw = _body()
    resp = tc.post(URL, content=raw, headers={"X-Orrery-Signature": _sign(raw)})

    assert resp.status_code == 202
    assert resp.json()["outcome"] == platform_events.APPLIED
    assert tc.get(LIFECYCLE_URL).json()["state"] == owner.LIFECYCLE_SUSPENDED


def test_the_resolution_surface_names_the_platform_as_the_authority(client):
    """The whole point: a caller resolving this business learns it is suspended,
    by whom, and that the owner did not attest it."""
    tc, home = client
    _establish(home)
    raw = _body()
    tc.post(URL, content=raw, headers={"X-Orrery-Signature": _sign(raw)})

    body = tc.get(LIFECYCLE_URL).json()
    assert body["state"] == owner.LIFECYCLE_SUSPENDED
    assert body["revoking_authority"] == f"platform:{PLATFORM}"
    assert body["owner_attested"] is False


def test_an_unsigned_post_is_401_and_changes_nothing(client):
    """⚠️ The denial-of-listing primitive this exists to prevent."""
    tc, home = client
    _establish(home)
    resp = tc.post(URL, content=_body())

    assert resp.status_code == 401
    assert resp.json()["outcome"] == platform_events.REFUSED
    assert resp.json()["state_changed"] is False
    assert tc.get(LIFECYCLE_URL).json()["state"] == owner.LIFECYCLE_ACTIVE


def test_a_wrongly_signed_post_is_401_and_changes_nothing(client):
    tc, home = client
    _establish(home)
    raw = _body()
    resp = tc.post(URL, content=raw, headers={"X-Orrery-Signature": _sign(raw, "wrong")})
    assert resp.status_code == 401
    assert tc.get(LIFECYCLE_URL).json()["state"] == owner.LIFECYCLE_ACTIVE


def test_with_no_secret_configured_every_request_is_refused(client, monkeypatch):
    """The endpoint is inert until someone deliberately turns it on."""
    tc, home = client
    monkeypatch.delenv(f"ORRERY_PLATFORM_WEBHOOK_SECRET_{PLATFORM.upper()}", raising=False)
    _establish(home)
    raw = _body()
    resp = tc.post(URL, content=raw, headers={"X-Orrery-Signature": _sign(raw)})
    assert resp.status_code == 401
    assert resp.json()["reason"].startswith("not_configured")
    assert tc.get(LIFECYCLE_URL).json()["state"] == owner.LIFECYCLE_ACTIVE


def test_an_unknown_platform_is_refused_rather_than_falling_back(client):
    """A platform with no configured secret must not borrow another's."""
    tc, home = client
    _establish(home)
    raw = _body()
    resp = tc.post("/webhooks/platform/wix/uninstall", content=raw, headers={"X-Orrery-Signature": _sign(raw)})
    assert resp.status_code == 401
    assert tc.get(LIFECYCLE_URL).json()["state"] == owner.LIFECYCLE_ACTIVE


def test_a_duplicate_delivery_is_accepted_not_failed(client):
    """Platforms retry on non-success; failing a duplicate causes a retry storm."""
    tc, home = client
    _establish(home)
    raw = _body()
    tc.post(URL, content=raw, headers={"X-Orrery-Signature": _sign(raw)})
    second = tc.post(URL, content=raw, headers={"X-Orrery-Signature": _sign(raw)})

    assert second.status_code == 202
    assert second.json()["outcome"] == platform_events.ALREADY_APPLIED
    assert second.json()["state_changed"] is False


def test_the_signature_covers_the_bytes_sent_not_a_reserialisation(client):
    """The handler reads the raw body. If it re-parsed and re-encoded the JSON
    before verifying, a signature over the original bytes would stop matching."""
    tc, home = client
    _establish(home)
    raw = b'{"event_id":"evt-x",  "occurred_at":"%s",   "subject":"moonbakery.com"}' % (
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ").encode()
    )
    resp = tc.post(URL, content=raw, headers={"X-Orrery-Signature": _sign(raw)})
    assert resp.status_code == 202, resp.json()


def test_the_webhook_does_not_touch_the_agent_card(client):
    """Additive: the card is the index-ban assertion's surface and this must not reshape it."""
    tc, home = client
    _establish(home)
    before = tc.get("/.well-known/agent.json").json()
    raw = _body()
    tc.post(URL, content=raw, headers={"X-Orrery-Signature": _sign(raw)})
    after = tc.get("/.well-known/agent.json").json()

    # Only the lifecycle block may differ — everything else byte-identical.
    before["x-nanda"].pop("lifecycle", None)
    after["x-nanda"].pop("lifecycle", None)
    assert before == after
