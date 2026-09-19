"""The ``X-Auth-Status`` response header says verified or not, and nothing else.

Audit M20 is about the specific reasons a signed-request failure returns
(``key_mismatch``, ``no_stored_key``, ``invalid_signature``). On the wire BODY
those reasons are mandated by the spec — ``spec/0.5/signing.md`` names the
closed set and the umbrella's R1 conformance asserts ``key_mismatch`` — so the
body keeps them and M20 is recorded as residual. Response headers are not in
that mandate, and this one used to carry the reason too:
``X-Auth-Status: unverified:<reason>``.

That mattered on every default-open GET — ``/api/digest``, ``/api/events``,
``/api/thoughts``, ``/version``, the ``/``-suffixed twins of ``/api/sessions``
and ``/api/runtimes``, thirty paths measured — which answer the same 200 body
to everyone, so the body says nothing about the caller; the header then said
``unverified:no_stored_key`` for an agent_id this org has never seen and
``unverified:invalid_signature`` for one it has a key for. An unauthenticated
caller could learn which ids are members from a surface whose body is
deliberately the same for all of them. (The identity-aware open paths stamp
``open`` on their own branch and never carried it.)

Asserted here, the L1 pair-shape: the two responses are identical in status,
body and every header. ``test_cors_on_auth_rejection.py`` keeps asserting the
stamp exists; this file asserts what it may not say.
"""

from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import build_v03_signed_headers

KNOWN = "TEST-known-member"
UNKNOWN = "TEST-never-registered"
REASONS = (
    "key_mismatch",
    "no_stored_key",
    "invalid_signature",
    "expired_timestamp",
    "nonce_replay",
    "missing_signature",
    "missing_agent_id",
    "method_binding_required",
    "invalid_did_key",
    "unknown_sig_scheme",
)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AGENT_ID", "TEST-header-org")
    monkeypatch.setenv("AGENT_NAME", "Header Org")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    for name in ("auth_verify", "chapter_agent"):
        sys.modules.pop(name, None)
    mod = importlib.import_module("chapter_agent")

    async def _no_db(*_a, **_k):
        return []

    monkeypatch.setattr(mod, "pg_request", _no_db)
    mod.members.clear()
    import auth_verify
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair(KNOWN)
    auth_verify.store_agent_key(KNOWN, "", "", ed25519_pubkey=kp["public_key"])
    return TestClient(mod.app)


def _bad_signature_for(agent_id: str, path: str) -> dict[str, str]:
    """A well-formed v0.3 signature made with a key the org has never seen —
    without a DID header, so the middleware verifies rather than bootstraps."""
    import sovereign_identity

    wrong = sovereign_identity.generate_ed25519_keypair(agent_id)
    return build_v03_signed_headers(body="", agent_id=agent_id, private_key_b64=wrong["private_key"], url_path=path)


@pytest.mark.parametrize("path", ["/api/digest", "/api/events", "/api/thoughts", "/version", "/api/sessions/"])
def test_ADVERSARIAL_known_and_unknown_ids_get_identical_responses_on_an_open_path(client, path):
    known = client.get(path, headers=_bad_signature_for(KNOWN, path))
    unknown = client.get(path, headers=_bad_signature_for(UNKNOWN, path))
    assert known.status_code == unknown.status_code == 200, (known.text, unknown.text)
    assert known.content == unknown.content
    assert dict(known.headers) == dict(unknown.headers), "a header distinguishes a member's id from a stranger's"
    assert known.headers["x-auth-status"] == "unverified"


@pytest.mark.parametrize("path", ["/api/digest", "/api/sessions", "/api/members", "/api/intents", "/api/invites"])
def test_ADVERSARIAL_no_response_header_carries_a_failure_reason(client, path):
    for agent_id in (KNOWN, UNKNOWN):
        r = client.get(path, headers=_bad_signature_for(agent_id, path))
        for name, value in r.headers.items():
            for reason in REASONS:
                assert reason not in value, f"{name}: {value!r} carries the failure reason on {path}"


def test_HAPPY_a_verified_caller_is_still_stamped_verified(client):
    """A stored key alone is not membership any more; the caller must be one."""
    import auth_verify
    import chapter_agent
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("TEST-alice-ok")
    auth_verify.store_agent_key("TEST-alice-ok", "", "", ed25519_pubkey=kp["public_key"])
    chapter_agent.members["TEST-alice-ok"] = {
        "agent_id": "TEST-alice-ok",
        "name": "Alice",
        "skills": [],
        "origin": "sovereign",
    }
    h = build_v03_signed_headers(
        body="", agent_id="TEST-alice-ok", private_key_b64=kp["private_key"], url_path="/api/members"
    )
    r = client.get("/api/members", headers=h)
    assert r.status_code == 200 and r.headers["x-auth-status"] == "verified"
