"""A signature is not membership, and a member who did not opt in is not disclosed.

Two findings, measured over the wire before this file existed, both on the
GET side of an org whose member directory is "closed":

1. **TOFU verified anyone.** A caller who had never registered could mint a
   keypair, choose any agent_id, sign a GET, and be ``tofu_accepted`` — which
   set ``request.state.verified`` and passed every signed-only gate. The
   directory the gate exists to close came back, descriptions included. Trust
   on first use is spec/0.2 §3.1's bootstrap for a REGISTERED member whose key
   is not yet on file; treating possession of some key as membership made it
   a registration path with no registration.

2. **Four per-member routes disclosed members who never opted in, and two of
   them republished the member's free-text description.** The profile route
   was consent-gated for exactly this; ``/agents/{id}``, the AgentFacts
   document, ``/api/agents/{id}/trust`` and ``/api/agents/{id}/aae-events``
   were not, and ``/sm-bridge/index`` enumerated every member of a deployed
   org — twenty-three, names and descriptions — to an anonymous GET.

The assertions here are of two kinds. The first drives a never-registered
signer at the gated routes and requires a refusal. The second drives every
per-member route twice — once for a registered member who did not opt in, once
for an id that does not exist — and requires the two answers to be BYTE
IDENTICAL, because a gate that answers differently closes a disclosure and
opens a membership oracle in its place.
"""

from __future__ import annotations

import base64
import importlib
import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

_PUBLIC_URL = "https://disclosure-org.example"
MEMBER = "napa-canary"
STRANGER_ID = "no-such-member-zz"
DESCRIPTION_CANARY = "owner@napa-canary.example"


@pytest.fixture
def mod(monkeypatch):
    monkeypatch.setenv("AGENT_ID", "TEST-disclosure-org")
    monkeypatch.setenv("AGENT_NAME", "Disclosure Org")
    sys.modules.pop("chapter_agent", None)
    m = importlib.import_module("chapter_agent")
    monkeypatch.setattr(m, "PUBLIC_URL", _PUBLIC_URL)
    return m


@pytest.fixture
def member(mod):
    """A registered member who has NOT opted in, holding a canary in the
    description field — the field an audit found carrying contact details."""
    import auth_verify
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("disclosure-member")
    mod.members[MEMBER] = {
        "name": "Napa Canary Winery",
        "description": f"Winery. Contact: {DESCRIPTION_CANARY}",
        "skills": ["viticulture", "wine"],
        "endpoint": "https://napa-canary.example",
        "public_key": kp["public_key"],
        "profile_type": "member",
        "availability": "active",
        "interests": [],
        "virtual": True,
    }
    auth_verify.store_agent_key(MEMBER, kp["public_key"], ed25519_pubkey=kp["public_key"])
    yield {"agent_id": MEMBER, "priv": kp["private_key"], "pub": kp["public_key"]}
    mod.members.pop(MEMBER, None)
    auth_verify._agent_keys.pop(MEMBER, None)


@pytest.fixture
def client(mod, monkeypatch) -> TestClient:
    import pg_store

    async def _pg(method, table, params=None, body=None, **_kw):
        params = params or {}
        # The trust route reads the agents row; give the member one so the
        # only thing standing between a stranger and a 200 is the gate.
        if method == "GET" and table == "agents" and params.get("agent_id") == f"eq.{MEMBER}":
            return [{"agent_id": MEMBER, "trust_score": 42.0, "config": {}}]
        return []

    async def _ddl(sql):
        return None

    async def _unreachable():
        return False

    monkeypatch.setattr(mod, "pg_request", _pg)
    monkeypatch.setattr(pg_store, "pg_request", _pg, raising=False)
    monkeypatch.setattr(pg_store, "execute_ddl", _ddl)
    monkeypatch.setattr(pg_store, "db_reachable", _unreachable)
    mod._rate_limit_store.clear()
    with TestClient(mod.app) as c:
        yield c


def _signed(agent_id: str, priv: str, pub: str, path: str, method: str = "GET") -> dict:
    import sovereign_identity

    ts = str(int(time.time()))
    nonce = base64.b64encode(os.urandom(32)).decode()
    msg = f"{method}:{path}::{agent_id}:{ts}:{nonce}"
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": sovereign_identity.ed25519_sign(msg, priv),
        "X-Agent-Timestamp": ts,
        "X-Agent-Nonce": nonce,
        "X-Agent-Sig-Scheme": "ed25519+nonce",
        "X-Agent-DID-Key": sovereign_identity.build_did_key_from_ed25519(pub),
    }


def _stranger():
    """A never-registered identity with a perfectly good keypair."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("stranger")
    return "stranger-" + os.urandom(3).hex(), kp["private_key"], kp["public_key"]


# ── 1. a signature is not membership ─────────────────────────────────

GATED_READS = (
    "/api/members",
    "/api/surfaces/directory",
    "/api/surfaces/members",
    f"/api/agents/{MEMBER}/endorsements",
    "/api/policy",
    "/api/federation/peers",
    "/api/receipts",
)


@pytest.mark.parametrize("path", GATED_READS)
def test_a_never_registered_signer_is_refused_at_every_signed_only_read(client, member, path):
    sid, priv, pub = _stranger()
    resp = client.get(path, headers=_signed(sid, priv, pub, path))
    assert resp.status_code == 401, f"{path}: a stranger with a fresh keypair got {resp.status_code}: {resp.text[:200]}"
    assert resp.json().get("detail") == "no_stored_key"
    assert MEMBER not in resp.text and DESCRIPTION_CANARY not in resp.text


def test_a_refused_stranger_leaves_no_key_behind(client, member):
    """Refused BEFORE the key is filed: a second attempt must not find a
    stored key and verify against it."""
    import auth_verify

    sid, priv, pub = _stranger()
    client.get("/api/members", headers=_signed(sid, priv, pub, "/api/members"))
    assert auth_verify.get_agent_key(sid) is None
    resp = client.get("/api/members", headers=_signed(sid, priv, pub, "/api/members"))
    assert resp.status_code == 401


def test_a_stored_key_without_membership_is_still_not_a_member(client, member):
    """The bind is at authorization, not only at TOFU: an id whose key IS on
    file (pinned on the interop surfaces, or a member since removed) does not
    pass the gates by signing."""
    import auth_verify

    sid, priv, pub = _stranger()
    auth_verify.store_agent_key(sid, pub, ed25519_pubkey=pub)
    try:
        resp = client.get("/api/members", headers=_signed(sid, priv, pub, "/api/members"))
        assert resp.status_code == 401
        assert resp.json().get("detail") == "no_stored_key"
    finally:
        auth_verify._agent_keys.pop(sid, None)


def test_a_stranger_is_not_a_verified_caller_on_the_identity_aware_catalog(client, member):
    """The catalog lists members only to a verified caller. A stranger who signs
    must get the anonymous projection, not the member list."""
    import auth_verify

    sid, priv, pub = _stranger()
    auth_verify.store_agent_key(sid, pub, ed25519_pubkey=pub)
    try:
        path = "/.well-known/ai-catalog.json"
        resp = client.get(path, headers=_signed(sid, priv, pub, path))
        assert resp.status_code == 200, "the document itself stays public"
        assert MEMBER not in resp.text
        assert resp.json()["withheldMembers"] >= 1
    finally:
        auth_verify._agent_keys.pop(sid, None)


def test_a_registered_member_still_passes(client, member):
    """The fix must not lock the door on the people it is for."""
    resp = client.get(
        "/api/members", headers=_signed(member["agent_id"], member["priv"], member["pub"], "/api/members")
    )
    assert resp.status_code == 200, resp.text


def test_the_a2a_interop_surfaces_still_take_a_self_authenticating_stranger(client, member, monkeypatch):
    """/run is invoked by callers who never joined; the signature is accountability."""

    async def _echo(text, task_id):
        return f"echo:{text}", None

    monkeypatch.setattr(sys.modules["chapter_agent"], "agent_logic", _echo)
    sid, priv, pub = _stranger()
    body = '{"message":{"role":"user","parts":[{"text":"hi"}]}}'
    headers = _signed(sid, priv, pub, "/run", method="POST")
    # v0.3 canonical binds the body; rebuild the signature over it.
    import sovereign_identity

    ts, nonce = headers["X-Agent-Timestamp"], headers["X-Agent-Nonce"]
    headers["X-Agent-Signature"] = sovereign_identity.ed25519_sign(f"POST:/run:{body}:{sid}:{ts}:{nonce}", priv)
    headers["Content-Type"] = "application/json"
    resp = client.post("/run", content=body, headers=headers)
    assert resp.status_code == 200, resp.text


# ── 2. a member who did not opt in is indistinguishable from nobody ──

PER_MEMBER_ROUTES = (
    "/api/agents/{id}/trust",
    "/api/agents/{id}/aae-events",
    "/api/agents/{id}/profile",
)


@pytest.mark.parametrize("route", PER_MEMBER_ROUTES)
def test_a_silent_member_answers_a_stranger_exactly_like_an_unknown_id(client, member, route):
    real = client.get(route.format(id=MEMBER))
    fake = client.get(route.format(id=STRANGER_ID))
    assert real.status_code == fake.status_code, (route, real.status_code, fake.status_code, real.text[:200])
    assert real.text.replace(MEMBER, "{id}") == fake.text.replace(STRANGER_ID, "{id}"), (
        f"{route}: the two answers differ, so the id can be probed:\n  real={real.text[:200]}\n  fake={fake.text[:200]}"
    )


def test_a_member_who_opted_in_has_an_open_trust_score(client, member, mod):
    mod.members[MEMBER]["listing"] = {"listed": True, "agent_url": "https://napa-canary.example"}
    resp = client.get(f"/api/agents/{MEMBER}/trust")
    assert resp.status_code == 200, resp.text
    assert resp.json()["score"] == 42.0


def test_a_signed_member_may_read_another_members_trust_score(client, member, mod):
    """Members see each other's transparent reputation; the oracle is only
    closed to strangers."""
    import auth_verify
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("peer")
    mod.members["peer-member"] = {"name": "Peer", "public_key": kp["public_key"]}
    auth_verify.store_agent_key("peer-member", kp["public_key"], ed25519_pubkey=kp["public_key"])
    try:
        path = f"/api/agents/{MEMBER}/trust"
        resp = client.get(path, headers=_signed("peer-member", kp["private_key"], kp["public_key"], path))
        assert resp.status_code == 200, resp.text
    finally:
        mod.members.pop("peer-member", None)
        auth_verify._agent_keys.pop("peer-member", None)


# ── 3. the public documents carry no member-authored prose ───────────


@pytest.mark.parametrize(
    "path",
    [f"/agents/{MEMBER}", f"/.well-known/agentfacts/{MEMBER}.json", f"/agentfacts/{MEMBER}.json"],
)
def test_the_public_member_documents_do_not_republish_the_description(client, member, path):
    resp = client.get(path)
    assert resp.status_code == 200, resp.text
    assert DESCRIPTION_CANARY not in resp.text, f"{path} republishes the member's free-text description"
    assert "Winery. Contact" not in resp.text


# ── 4. the sm-bridge index enumerates only members who opted in ──────


def test_the_sm_bridge_index_withholds_a_member_who_did_not_opt_in(client, member):
    resp = client.get("/sm-bridge/index")
    assert resp.status_code == 200, resp.text
    assert MEMBER not in resp.text, "a member who never opted in is enumerated to an anonymous GET"
    assert DESCRIPTION_CANARY not in resp.text


def test_the_sm_bridge_index_lists_a_member_who_opted_in_without_their_prose(client, member, mod):
    mod.members[MEMBER]["listing"] = {"listed": True, "agent_url": "https://napa-canary.example"}
    resp = client.get("/sm-bridge/index")
    assert resp.status_code == 200, resp.text
    assert MEMBER in resp.text
    assert DESCRIPTION_CANARY not in resp.text


def test_the_sm_bridge_delta_feed_withholds_a_member_who_did_not_opt_in(client, member, mod):
    """The feed is the index in another shape: replaying it from seq 0 rebuilds
    the index. It used to re-seed every member at boot and upsert on every
    registration, so closing the index alone would have left the same
    enumeration one path over."""
    import sm_bridge_adapter as smb

    smb.record_member_delta("upsert", MEMBER, mod.members[MEMBER])  # what registration does
    resp = client.get("/sm-bridge/deltas", params={"since": "0"})
    assert resp.status_code == 200, resp.text
    assert MEMBER not in resp.text and DESCRIPTION_CANARY not in resp.text


def test_opting_in_publishes_to_the_delta_feed_and_opting_out_retracts(client, member, mod):
    """The consent endpoint is the lifecycle event the feed carries."""
    import json as _json

    path = "/api/me/listing"
    body = _json.dumps({"listed": True})
    headers = _signed(member["agent_id"], member["priv"], member["pub"], path, method="POST")
    import sovereign_identity

    ts, nonce = headers["X-Agent-Timestamp"], headers["X-Agent-Nonce"]
    headers["X-Agent-Signature"] = sovereign_identity.ed25519_sign(
        f"POST:{path}:{body}:{member['agent_id']}:{ts}:{nonce}", member["priv"]
    )
    headers["Content-Type"] = "application/json"
    assert client.post(path, content=body, headers=headers).status_code == 200
    deltas = client.get("/sm-bridge/deltas", params={"since": "0"}).json().get("deltas") or []
    mine = [d for d in deltas if MEMBER in _json.dumps(d)]
    assert mine and mine[-1]["action"] == "upsert", deltas
    assert DESCRIPTION_CANARY not in _json.dumps(mine)

    body = _json.dumps({"listed": False})
    headers = _signed(member["agent_id"], member["priv"], member["pub"], path, method="POST")
    ts, nonce = headers["X-Agent-Timestamp"], headers["X-Agent-Nonce"]
    headers["X-Agent-Signature"] = sovereign_identity.ed25519_sign(
        f"POST:{path}:{body}:{member['agent_id']}:{ts}:{nonce}", member["priv"]
    )
    headers["Content-Type"] = "application/json"
    assert client.post(path, content=body, headers=headers).status_code == 200
    deltas = client.get("/sm-bridge/deltas", params={"since": "0"}).json().get("deltas") or []
    mine = [d for d in deltas if MEMBER in _json.dumps(d)]
    assert mine[-1]["action"] == "delete", deltas
