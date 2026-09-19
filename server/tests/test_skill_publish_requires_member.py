"""Publishing a skill into the org's registry is a member's act.

``POST /api/skills/publish`` and ``/publish/package`` verify the PUBLISHER's
Ed25519 signature over the content, which proves the skill is authentic and
nothing about who is listing it in THIS org's registry. Both were open at the
middleware, so any keypair on the internet could put a package in an org's
registry — the supply-chain shape a public deploy meets on day one. The
package route even honoured an ``author_agent_id`` query parameter verbatim.

Publication now takes a registered member's request signature (the same
eligibility the directory gates use), the registration is attributed to that
member, and the package signature is still verified fail-closed.
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from tests._admin_fixtures import register_test_regular_member, reset_chapter_agent_module

ORG = "TEST-skill-publish-org"


class _Pg:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def __call__(self, method, table, params=None, body=None, **_kw):
        if table != "chapter_skills":
            return []
        if method == "GET":
            return list(self.rows)
        if method == "POST":
            b = dict(body or {})
            b.setdefault("revoked_at", None)
            b.setdefault("chapter_id", ORG)
            self.rows.append(b)
            return [b]
        return None


@pytest.fixture
def stack(monkeypatch):
    import skill_registry as sr

    mod = reset_chapter_agent_module(monkeypatch, agent_id=ORG)
    mod.members.clear()
    pg = _Pg()
    sr.init(pg, ORG)
    member = register_test_regular_member(mod, agent_id="skill-author", name="Skill Author")
    return mod, member, pg, TestClient(mod.app)


def _signed_manifest() -> dict:
    import skill_registry as sr
    from sovereign_identity import build_did_key_from_ed25519

    sk = SigningKey.generate()
    did = build_did_key_from_ed25519(base64.b64encode(sk.verify_key.encode()).decode())
    manifest = {"name": "hello", "version": "0.1.0", "description": "greets", "capabilities": ["text.generate"]}
    content = sr.canonical_content_bytes(manifest)
    sha = sr.compute_sha256(content)
    sig = base64.b64encode(sk.sign(sha.encode("utf-8")).signature).decode()
    return {"manifest": manifest, "signature": sig, "signing_key_did": did, "content_sha256": sha}


def _post(client, headers_for, path, payload):
    body = json.dumps(payload, separators=(",", ":"))
    headers = headers_for(method="POST", url_path=path, body=body) if headers_for else {}
    headers["Content-Type"] = "application/json"
    return client.post(path, content=body, headers=headers)


def test_an_anonymous_caller_cannot_publish(stack):
    _mod, _member, pg, client = stack
    resp = _post(client, None, "/api/skills/publish", _signed_manifest())
    assert resp.status_code == 401, resp.text
    assert pg.rows == [], "a valid package signature alone put a skill in the registry"


def test_a_stranger_with_a_keypair_cannot_publish(stack):
    """The publisher key signs the manifest; a second fresh key signs the
    request. Neither belongs to a member."""
    _mod, _member, pg, client = stack
    import os
    import time

    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("stranger")

    def signer(*, method: str, url_path: str, body: str) -> dict:
        ts, nonce = str(int(time.time())), base64.b64encode(os.urandom(32)).decode()
        msg = f"{method}:{url_path}:{body}:stranger-with-keys:{ts}:{nonce}"
        return {
            "X-Agent-ID": "stranger-with-keys",
            "X-Agent-Signature": sovereign_identity.ed25519_sign(msg, kp["private_key"]),
            "X-Agent-Timestamp": ts,
            "X-Agent-Nonce": nonce,
            "X-Agent-Sig-Scheme": "ed25519+nonce",
            "X-Agent-DID-Key": sovereign_identity.build_did_key_from_ed25519(kp["public_key"]),
        }

    resp = _post(client, signer, "/api/skills/publish", _signed_manifest())
    assert resp.status_code == 401, resp.text
    assert pg.rows == []


def test_a_registered_member_publishes_and_is_the_recorded_author(stack):
    _mod, member, pg, client = stack
    resp = _post(client, member["signer"], "/api/skills/publish", _signed_manifest())
    assert resp.status_code == 200, resp.text
    assert len(pg.rows) == 1
    assert pg.rows[0].get("author_agent_id") == member["agent_id"]


def test_the_package_route_is_gated_the_same_way(stack):
    _mod, _member, pg, client = stack
    resp = client.post(
        "/api/skills/publish/package?author_agent_id=someone-else",
        content=b"PK\x03\x04",
        headers={"Content-Type": "application/zip"},
    )
    assert resp.status_code == 401, resp.text
    assert pg.rows == []


def test_the_handlers_refuse_on_their_own_without_a_verified_caller(stack):
    """Two layers: the middleware is asserted over the wire above; this calls
    the handlers as a request with no verified identity would reach them."""
    import asyncio
    from unittest.mock import MagicMock

    from fastapi import HTTPException

    from routes import skills as skills_routes

    req = MagicMock()
    req.state.agent_id = ""
    req.headers = {}
    req.query_params = {"author_agent_id": "someone-else"}

    async def _body():
        return b"PK\x03\x04"

    req.body = _body
    with pytest.raises(HTTPException) as exc:
        asyncio.run(skills_routes.skill_publish_package(req))
    assert exc.value.status_code == 401

    payload = skills_routes.SkillPublishRequest(**_signed_manifest())
    with pytest.raises(HTTPException) as exc:
        asyncio.run(skills_routes.skill_publish(payload, req))
    assert exc.value.status_code == 401
