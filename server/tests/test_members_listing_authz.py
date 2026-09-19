"""The enumeration closure — ``GET /api/members`` is not a public bulk-enumeration surface.

Before this module the member directory was in ``OPEN_PATHS``: any anonymous
caller got every member's agent_id, name, description, skills, interests,
availability, reputation, github_url and linkedin_url in one request. A
discovery system should answer "does THIS subject have an agent?" for a caller
who already knows the subject — the exact-match ``GET /api/agents/{id}/profile``
(its near-duplicate, ``GET /api/member/{id}/profile``, was retired) — not
"who are all your members?".

What is locked here:

  * anonymous ``GET /api/members`` (and the trailing-slash twin) → 401;
  * ``POST /api/members`` — first-time TOFU registration, which the OpenClaw
    skill depends on — stays OPEN. This is the regression that would silently
    break every new member if a future refactor closed the path by method-blind
    edit, so it is pinned explicitly;
  * a signed member, an operator bearer token, and a signature-verified
    federation peer can all still read the list;
  * the ``/api/federation/{peer}/members`` proxy is gated too — otherwise an
    anonymous caller launders a peer's directory through our federation key;
  * cross-org discovery still works end-to-end, proven by driving the REAL
    ``federation_discovery.query_chapter_members`` against a REAL second org's
    app over the REAL signing path (only the transport is injected);
  * a peer query that fails is LOUD — never a silent ``[]``.

Classification: ADVERSARIAL (bulk enumeration + peer-signature forgery).
"""

from __future__ import annotations

import importlib
import sys
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from ._admin_fixtures import initialize_admin_token, make_signer, register_test_regular_member

ORG_A = "TEST-org-a"
ORG_A_ENDPOINT = "http://org-a.test"
ORG_B_ENDPOINT = "http://org-b.test"


async def _noop_pg(*args, **kwargs):
    return []


@pytest.fixture
def org_b(monkeypatch: pytest.MonkeyPatch):
    """The org under test — the one whose directory is being read."""
    monkeypatch.setenv("AGENT_ID", "TEST-org-b")
    monkeypatch.setenv("AGENT_NAME", "Org B")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.delenv("CHAPTER_SLUG", raising=False)
    for mod in ("admin", "auth_verify", "chapter_agent"):
        sys.modules.pop(mod, None)
    mod = importlib.import_module("chapter_agent")
    monkeypatch.setattr(mod, "pg_request", _noop_pg)
    monkeypatch.setattr(mod, "PUBLIC_URL", "")
    mod.members.clear()
    mod.members.update(
        {
            "alice": {"name": "Alice", "description": "Real member", "skills": ["python"]},
            "bob": {"name": "Bob", "description": "Real member", "skills": ["rust"]},
        }
    )
    mod.federation.clear()
    return mod


@pytest.fixture
def client(org_b) -> TestClient:
    org_b._rate_limit_store.clear()
    return TestClient(org_b.app)


def _peer_did(agent_id: str) -> str:
    """Mint a real Ed25519 keypair for ``agent_id`` (cached in
    ``sovereign_identity._ed25519_keypairs``, which is what the federation
    signer reads) and return its did:key."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair(agent_id)
    return sovereign_identity.build_did_key_from_ed25519(kp["public_key"])


# ---------------------------------------------------------------------------
# Classification — the source of truth
# ---------------------------------------------------------------------------


def test_get_members_requires_auth() -> None:
    import auth_verify

    assert auth_verify.requires_auth("GET", "/api/members") is True
    assert auth_verify.requires_auth("GET", "/api/members/") is True
    assert auth_verify.is_open_path("GET", "/api/members") is False


def test_post_members_registration_is_still_open() -> None:
    """The TOFU-register path is method-scoped and MUST stay open — the org has
    no recorded key on first contact, and the OpenClaw skill registers here."""
    import auth_verify

    assert auth_verify.is_open_path("POST", "/api/members") is True
    assert auth_verify.is_open_path("POST", "/api/members/") is True
    assert auth_verify.is_open_path("POST", "/api/members/rotate") is True


def test_federation_members_proxy_requires_auth() -> None:
    """``/api/federation/{peer}/members`` returns a PEER's directory. Open, it
    would launder exactly the enumeration this issue closes."""
    import auth_verify

    assert auth_verify.requires_auth("GET", "/api/federation/TEST-org-a/members") is True
    # The federation summary itself stays public (bootstrap document).
    assert auth_verify.requires_auth("GET", "/api/federation") is False


# ---------------------------------------------------------------------------
# Live middleware — the enumeration itself
# ---------------------------------------------------------------------------


def test_anonymous_enumeration_is_rejected(client: TestClient) -> None:
    """THE BUG: this returned 200 + every member's PII before the fix."""
    for path in ("/api/members", "/api/members/", "/api/members?skill=python"):
        resp = client.get(path)
        assert resp.status_code == 401, f"{path} enumerable anonymously: {resp.text[:300]}"
        assert "alice" not in resp.text


def test_anonymous_federation_proxy_is_rejected(client: TestClient, org_b) -> None:
    org_b.federation[ORG_A] = {"endpoint": ORG_A_ENDPOINT, "name": "Org A"}
    resp = client.get(f"/api/federation/{ORG_A}/members")
    assert resp.status_code == 401


def test_registration_still_succeeds_unauthenticated(client: TestClient, org_b) -> None:
    """Regression pin: closing the GET must not close the POST."""
    resp = client.post("/api/members", json={"agent_id": "newcomer", "name": "Newcomer"})
    assert resp.status_code == 200, resp.text[:300]
    assert "newcomer" in org_b.members


def test_signed_member_can_list(client: TestClient, org_b) -> None:
    member = register_test_regular_member(org_b, agent_id="carol", name="Carol")
    sign = make_signer(member["agent_id"], member["private_key"])

    resp = client.get("/api/members", headers=sign(method="GET", url_path="/api/members"))
    assert resp.status_code == 200, resp.text[:300]
    assert {m["agent_id"] for m in resp.json()["members"]} >= {"alice", "bob"}


def test_operator_bearer_can_list(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    token, _admin = initialize_admin_token(monkeypatch)

    resp = client.get("/api/members", headers={"X-Admin-Token": token})
    assert resp.status_code == 200, resp.text[:300]

    bad = client.get("/api/members", headers={"X-Admin-Token": "0" * 64})
    assert bad.status_code == 401


# ---------------------------------------------------------------------------
# The federation leg — two real orgs, real signatures
# ---------------------------------------------------------------------------


@pytest.fixture
def org_a_signing(org_b):
    """Give org A a real keypair and register it as a pinned peer of org B."""
    did = _peer_did(ORG_A)
    org_b.federation[ORG_A] = {"endpoint": ORG_A_ENDPOINT, "name": "Org A", "did": did}
    return did


@pytest.fixture
def org_a_discovery(org_a_signing, org_b, monkeypatch: pytest.MonkeyPatch):
    """Org A's federation_discovery, pointed at org B. This is the real
    production module — nothing about the signing path is stubbed."""
    import federation_discovery

    fed_a: dict = {"TEST-org-b": {"endpoint": ORG_B_ENDPOINT, "name": "Org B"}}
    failures: dict = {}
    monkeypatch.setattr(federation_discovery, "_agent_id", ORG_A)
    monkeypatch.setattr(federation_discovery, "_federation", fed_a)
    monkeypatch.setattr(federation_discovery, "_federation_failures", failures)
    return federation_discovery


def _asgi_client(app) -> httpx.AsyncClient:
    """An httpx client whose transport is org B's ASGI app. Only the wire is
    faked — org B's middleware, signature verification and handler all run."""
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app))


@pytest.mark.asyncio
async def test_cross_org_discovery_still_returns_members(org_a_discovery, org_b) -> None:
    """END TO END: org A's real discovery code signs the GET, org B's real
    middleware verifies it, and A gets B's directory back."""
    async with _asgi_client(org_b.app) as http:
        members = await org_a_discovery.query_chapter_members("TEST-org-b", client=http)

    assert {m["agent_id"] for m in members} == {"alice", "bob"}


@pytest.mark.asyncio
async def test_unsigned_peer_read_is_rejected(org_a_discovery, org_b, capsys) -> None:
    """A peer that is allowlisted but does NOT sign gets nothing — an endpoint
    in the registry is not authorization."""
    import sovereign_identity

    sovereign_identity._ed25519_keypairs.pop(ORG_A, None)  # A has no key → cannot sign

    async with _asgi_client(org_b.app) as http:
        members = await org_a_discovery.query_chapter_members("TEST-org-b", client=http)

    assert members == []
    out = capsys.readouterr().out
    # H4 CHANGED WHERE THIS IS ENFORCED, and the new property is stronger.
    # This test used to prove the PEER rejected our unsigned read (HTTP 401) —
    # protection that lived on someone else's box and was invisible from here.
    # The emit path now refuses before the request is made, so an unsigned peer
    # read is never sent at all. Same observable result for the caller (empty
    # list, loud log); the failure moved from the receiver to us, which is the
    # point of H4.
    assert "refusing to emit unsigned" in out


@pytest.mark.asyncio
async def test_peer_signature_from_the_wrong_key_is_rejected(org_a_discovery, org_b, capsys) -> None:
    """Forgery: the claimed origin is a real peer, the signature is valid — but
    it is not the key org B has pinned for that peer."""
    org_b.federation[ORG_A]["did"] = _peer_did("TEST-org-a-impostor")  # pin someone else's key

    async with _asgi_client(org_b.app) as http:
        members = await org_a_discovery.query_chapter_members("TEST-org-b", client=http)

    assert members == []
    assert "invalid_signature" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_unknown_peer_cannot_read(org_a_discovery, org_b, capsys) -> None:
    """A correctly-signed request from an org that is NOT in our federation
    registry is still refused — the allowlist remains the trust anchor."""
    org_b.federation.clear()

    async with _asgi_client(org_b.app) as http:
        members = await org_a_discovery.query_chapter_members("TEST-org-b", client=http)

    assert members == []
    assert "unknown_peer" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_captured_peer_signature_goes_stale(org_a_signing, org_b) -> None:
    """Replay bound: the peer's signature covers a timestamp, and a captured
    read stops working once the freshness window passes."""
    import federation_signing

    headers = federation_signing.sign_request(ORG_A, "GET", "/api/members")
    assert headers, "org A must have a signing key for this test to mean anything"

    async with _asgi_client(org_b.app) as http:
        fresh = await http.get(f"{ORG_B_ENDPOINT}/api/members", headers=headers)
        assert fresh.status_code == 200

        stale = dict(headers)
        stale[federation_signing.CHAPTER_TS_HEADER] = str(int(time.time()) - 4000)
        replayed = await http.get(f"{ORG_B_ENDPOINT}/api/members", headers=stale)

    assert replayed.status_code == 401


@pytest.mark.asyncio
async def test_peer_read_authorization_does_not_extend_to_the_proxy(org_a_signing, org_b) -> None:
    """A peer may read OUR directory; it may not use us to relay a third org's."""
    import federation_signing

    path = f"/api/federation/{ORG_A}/members"
    headers = federation_signing.sign_request(ORG_A, "GET", path)

    async with _asgi_client(org_b.app) as http:
        resp = await http.get(f"{ORG_B_ENDPOINT}{path}", headers=headers)

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_peer_signature_is_bound_to_the_route(org_a_signing, org_b) -> None:
    """A signature minted for another route does not move to the directory."""
    import federation_signing

    headers = federation_signing.sign_request(ORG_A, "GET", "/api/knowledge/summary")

    async with _asgi_client(org_b.app) as http:
        resp = await http.get(f"{ORG_B_ENDPOINT}/api/members", headers=headers)

    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# No silent failures
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unreachable_peer_query_is_loud(org_a_discovery, capsys) -> None:
    """The old handler was ``except Exception: pass`` → ``[]``. A peer we
    cannot reach is an operational fault, not an org with no members."""

    class _Boom:
        async def get(self, *args, **kwargs):
            raise httpx.ConnectError("connection refused")

    members = await org_a_discovery.query_chapter_members("TEST-org-b", client=_Boom())

    assert members == []
    out = capsys.readouterr().out
    assert "FAILED" in out and "ConnectError" in out


@pytest.mark.asyncio
async def test_peer_without_endpoint_is_loud(org_a_discovery, capsys) -> None:
    org_a_discovery._federation["TEST-org-b"] = {"name": "Org B"}  # no endpoint

    members = await org_a_discovery.query_chapter_members("TEST-org-b")

    assert members == []
    assert "SKIPPED" in capsys.readouterr().out
