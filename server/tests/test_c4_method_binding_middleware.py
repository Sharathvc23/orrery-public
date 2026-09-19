"""C4 middleware integration — a method-unbound signature can't drive a mutation.

Unit coverage of the rule lives in test_auth_verify.py; this drives it through
the LIVE middleware so the enforcement + the fail-closed reason handling are
exercised together. Before the fix, `method_binding_required` was an unhandled
reason that fell through the middleware's deny-list and let the request proceed
(fail-open) — this pins the 401.

Classification: ADVERSARIAL (cross-method / method-unbound replay).
"""

from __future__ import annotations

import importlib
import sys
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def chapter_agent_module(monkeypatch):
    monkeypatch.setenv("AGENT_ID", "TEST-fixture-chapter")
    monkeypatch.setenv("AGENT_NAME", "Fixture")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    sys.modules.pop("chapter_agent", None)
    return importlib.import_module("chapter_agent")


@pytest.fixture
def client(chapter_agent_module) -> TestClient:
    chapter_agent_module._rate_limit_store.clear()
    return TestClient(chapter_agent_module.app)


def _v02_headers(body: str, agent_id: str, priv_b64: str, pub_b64: str) -> dict:
    import sovereign_identity

    ts = str(int(time.time()))
    sig = sovereign_identity.ed25519_sign(f"{body}:{agent_id}:{ts}", priv_b64)
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": sig,
        "X-Agent-Timestamp": ts,
        "X-Agent-Sig-Scheme": "ed25519",
        "X-Agent-DID-Key": sovereign_identity.build_did_key_from_ed25519(pub_b64),
        "Content-Type": "application/json",
    }


def test_v02_post_to_internal_api_is_rejected(client):
    """A validly-signed v0.2 POST to an internal mutating endpoint is refused at
    the middleware with method_binding_required (not silently allowed through)."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("TEST-c4-alice")
    body = '{"intent_text":"hi","requester_agent_id":"TEST-c4-alice","intent_tags":[]}'
    headers = _v02_headers(body, "TEST-c4-alice", kp["private_key"], kp["public_key"])

    resp = client.post("/api/intents", content=body, headers=headers)
    assert resp.status_code == 401
    assert resp.json().get("detail") == "method_binding_required"


def test_a2a_interop_post_still_accepts_v02(client, chapter_agent_module, monkeypatch):
    """The A2A interop exemption holds for the surface the SPEC carves out:
    a v0.2 POST /a2a is NOT rejected for method binding.

    spec/0.5/signing.md §"What mutating means" names exactly `POST /a2a`,
    `POST /a2a/` and `POST /a2a/@{handle}` — third-party traffic from
    implementations that track the A2A protocol rather than this one, which
    cannot be held to a NANDA major-version window."""

    async def fake_logic(message, conversation_id):
        return ("ok", None)

    monkeypatch.setattr(chapter_agent_module, "agent_logic", fake_logic)

    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("TEST-c4-bob")
    # The legacy /a2a envelope (role + content + conversation_id), not /run's
    # message-parts shape — this test is about the AUTH decision, so the body
    # has to be one the route accepts or a 422 would mask the result.
    body = '{"role":"user","content":{"type":"text","text":"hi"},"conversation_id":"c4-test"}'
    headers = _v02_headers(body, "TEST-c4-bob", kp["private_key"], kp["public_key"])

    resp = client.post("/a2a", content=body, headers=headers)
    # Whatever the handler does, it must NOT be the C4 binding rejection.
    if resp.status_code == 401:
        assert resp.json().get("detail") != "method_binding_required"
    else:
        assert resp.status_code == 200


def test_run_takes_v02_again_now_that_the_spec_names_it(client, chapter_agent_module, monkeypatch):
    """`/run` has its v0.2 exemption BACK, and this test is the same test as
    before with its expectation inverted — deliberately not deleted.

    The round trip: the advertised-version correction dropped `/run` from the exemption because spec/0.5 as
    first published enumerated only the `/a2a` family, and a chapter must not
    attest a version it bends. That was the correct reading AND the trigger to
    fix the spec instead of the runtime — umbrella / PR established the
    omission was accidental (`/run` is the standard A2A invoke, reached by the
    same third parties from the agent card; `chapter/`, the runtime v0.5 was
    drafted against, has no `/run` at all). spec/0.5/signing.md now names
    `POST /run` and `POST /run/`, so the exemption returns.

    Kept as an inverted assertion rather than removed because a deleted test is
    an untested claim: whichever way the spec points, the behaviour on this
    route is pinned, and the flip is visible in history.

    Classification: HAPPY (the interop surface accepts the legacy scheme the
    spec requires it to accept).
    """

    async def fake_logic(message, conversation_id):
        return ("ok", None)

    monkeypatch.setattr(chapter_agent_module, "agent_logic", fake_logic)

    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("TEST-c4-run")
    body = '{"message":{"role":"user","parts":[{"text":"hi"}]}}'
    headers = _v02_headers(body, "TEST-c4-run", kp["private_key"], kp["public_key"])

    resp = client.post("/run", content=body, headers=headers)

    assert resp.status_code != 401, f"v0.2 must be accepted on /run per spec/0.5: {resp.text[:200]}"
    assert (resp.json() or {}).get("detail") != "method_binding_required"


def test_run_trailing_slash_also_takes_v02(client, chapter_agent_module, monkeypatch):
    """The spec names `POST /run/` alongside `POST /run`. A caller that follows
    the agent card's URL with a trailing slash must not get a different answer
    — that asymmetry is how a carve-out quietly half-applies."""

    async def fake_logic(message, conversation_id):
        return ("ok", None)

    monkeypatch.setattr(chapter_agent_module, "agent_logic", fake_logic)

    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("TEST-c4-run-slash")
    body = '{"message":{"role":"user","parts":[{"text":"hi"}]}}'
    headers = _v02_headers(body, "TEST-c4-run-slash", kp["private_key"], kp["public_key"])

    resp = client.post("/run/", content=body, headers=headers)

    assert resp.status_code != 401, f"v0.2 must be accepted on /run/ too: {resp.text[:200]}"
    assert (resp.json() or {}).get("detail") != "method_binding_required"


def test_run_still_accepts_the_replacement_scheme(client, chapter_agent_module, monkeypatch):
    """The interop surface is not closed — it moved to v0.3. A method-bound
    signature on /run still works, so the cost of the line above is "clients
    must sign v0.3 here", not "this route is gone"."""

    async def fake_logic(message, conversation_id):
        return ("ok", None)

    monkeypatch.setattr(chapter_agent_module, "agent_logic", fake_logic)

    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("TEST-c4-run-v03")
    body = '{"message":{"role":"user","parts":[{"text":"hi"}]}}'
    headers = _v03_headers("POST", "/run", body, "TEST-c4-run-v03", kp["private_key"], kp["public_key"])

    resp = client.post("/run", content=body, headers=headers)

    assert resp.status_code != 401, resp.text[:200]


def _v03_headers(method, url_path, body, agent_id, priv_b64, pub_b64):
    """Reconstruct EXACTLY what community_member.auth.sign_request_body emits for
    v0.3 (canonical_string_v03: METHOD:url_path:body:agent_id:ts:nonce), so this
    server-side test exercises the real client↔server contract without importing
    the agent package."""
    import base64
    import os

    import sovereign_identity

    ts = str(int(time.time()))
    nonce = base64.b64encode(os.urandom(32)).decode()
    canonical = f"{method.upper()}:{url_path}:{body}:{agent_id}:{ts}:{nonce}"
    sig = sovereign_identity.ed25519_sign(canonical, priv_b64)
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": sig,
        "X-Agent-Timestamp": ts,
        "X-Agent-Nonce": nonce,
        "X-Agent-Sig-Scheme": "ed25519+nonce",
        "X-Agent-DID-Key": sovereign_identity.build_did_key_from_ed25519(pub_b64),
        "Content-Type": "application/json",
    }


def test_v03_client_signature_is_accepted_end_to_end(client):
    """A correctly-signed v0.3 POST (real client canonical) passes the middleware
    — auth is NOT rejected. Locks the client↔server contract for a mutation."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("TEST-c4-e2e")
    # TOFU pins a key only for a registered member; register the signer first.
    client.app  # noqa: B018 — the fixture module is the one the app reads
    import chapter_agent as _ca

    _ca.members["TEST-c4-e2e"] = {"name": "C4 e2e", "public_key": kp["public_key"]}
    body = '{"agent_id":"TEST-c4-e2e","availability":"always"}'
    headers = _v03_headers("POST", "/api/projection/update", body, "TEST-c4-e2e", kp["private_key"], kp["public_key"])
    resp = client.post("/api/projection/update", content=body, headers=headers)
    assert resp.status_code != 401, f"correctly-signed v0.3 mutation was auth-rejected: {resp.text}"


def test_v03_authed_get_with_query_string_round_trips(client):
    """Making the client always-v0.3 means authed GETs now sign url_path, which
    the server builds as path+'?'+query. A v0.3 GET whose signed url_path
    INCLUDES the query must be accepted; one that OMITS it must be rejected —
    proving the query is bound into the canonical on both sides."""
    import auth_verify
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("TEST-c4-get")
    auth_verify.store_agent_key("TEST-c4-get", "", "", ed25519_pubkey=kp["public_key"])
    import chapter_agent as _ca

    _ca.members["TEST-c4-get"] = {"name": "C4 get", "public_key": kp["public_key"]}

    path = "/api/receipts"
    query = "principal_did=did:key:zABC"
    full = f"{path}?{query}"

    # (1) signed WITH the query in url_path → matches server's raw_path → not 401.
    ok = _v03_headers("GET", full, "", "TEST-c4-get", kp["private_key"], kp["public_key"])
    r_ok = client.get(full, headers=ok)
    assert r_ok.status_code != 401, f"v0.3 GET with query in canonical was auth-rejected: {r_ok.text}"

    # (2) signed WITHOUT the query (url_path=path only) but requested WITH query →
    #     canonical mismatch → 401. Proves the query is genuinely part of binding.
    bad = _v03_headers("GET", path, "", "TEST-c4-get", kp["private_key"], kp["public_key"])
    r_bad = client.get(full, headers=bad)
    assert r_bad.status_code == 401, "server ignored the query string in url_path — binding is incomplete"
