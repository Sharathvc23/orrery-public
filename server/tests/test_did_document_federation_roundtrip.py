"""The public-discovery rule — a peer fetches this org's key from did.json and verifies what it signed.

The done-when for the public-discovery rule says code identity is not sufficient: prove the round
trip. So this does not assert that `fetch_peer_pubkey` *would* work — it runs the
real thing end to end:

  1. this org signs a federation broadcast with its REAL signing key, through
     `federation_signing.sign_outbound`;
  2. a "peer" resolves our public key by fetching `/.well-known/did.json`
     ANONYMOUSLY through the live ASGI app — no credentials, exactly as
     `federation_signing.fetch_peer_pubkey` does over the wire;
  3. the peer verifies the signature with `federation_signing.verify_inbound`.

Every step is production code. Only the transport is in-process.

This is the assertion that would have caught the reported defect if it had been
real: had did.json required auth, step 2 returns nothing and step 3 fails with
`peer_key_unavailable` — the org would be unverifiable to the entire mesh while
`/health` still said `ok`.

Classification: HAPPY (R1 — the round trip), ADVERSARIAL (R2-R3 — the failure
modes that make the round trip meaningful).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import federation_signing
import sovereign_identity


@pytest.fixture
def chapter_agent_module():
    """Resolved through sys.modules, exactly as routes/identity.py's `ca` proxy
    does. Other modules re-import chapter_agent, so a reference captured at
    import time can be a stale object whose AGENT_ID is not the one the handler
    reads — which shows up as a mystifying "no signing key" 503."""
    import importlib
    import sys

    return sys.modules.get("chapter_agent") or importlib.import_module("chapter_agent")


@pytest.fixture
def client(chapter_agent_module) -> TestClient:
    chapter_agent_module._rate_limit_store.clear()
    return TestClient(chapter_agent_module.app)


@pytest.fixture
def org_key(chapter_agent_module):
    kp = sovereign_identity.generate_ed25519_keypair(chapter_agent_module.AGENT_ID)
    yield kp
    sovereign_identity._ed25519_keypairs.pop(chapter_agent_module.AGENT_ID, None)


def _peer_fetcher(client: TestClient):
    """A peer's `http_get`: an ANONYMOUS fetch of a URL, same as
    `federation_signing._default_get` performs over real HTTP."""

    async def _get(url: str) -> dict | None:
        path = url.split("localhost", 1)[-1] if "localhost" in url else url
        for prefix in ("http://", "https://"):
            if path.startswith(prefix):
                path = "/" + path[len(prefix) :].split("/", 1)[1]
        resp = client.get(path)  # no auth headers, deliberately
        return resp.json() if resp.status_code == 200 else None

    return _get


async def test_R1_peer_resolves_our_key_from_did_json_and_verifies_our_signature(
    client: TestClient, chapter_agent_module, org_key
) -> None:
    body = {"broadcast_id": "roundtrip-1", "origin_chapter_id": chapter_agent_module.AGENT_ID, "note": "hello"}
    headers = federation_signing.sign_outbound(chapter_agent_module.AGENT_ID, body)
    assert headers, "the org must have a signing key for this test to mean anything"

    # The peer knows only our endpoint. It resolves the key itself.
    pubkey = await federation_signing.fetch_peer_pubkey("http://localhost", _peer_fetcher(client))
    assert pubkey == org_key["public_key"], "the peer must resolve OUR actual signing key from did.json"

    valid, reason = await federation_signing.verify_inbound(body, headers, "http://localhost", _peer_fetcher(client))

    assert valid is True, f"a peer could not verify a signature we produced: {reason}"
    assert reason in ("ok", "ok_legacy")


async def test_R2_an_unreadable_did_json_makes_us_unverifiable(
    client: TestClient, chapter_agent_module, org_key
) -> None:
    """Why R1 matters, stated as its own assertion: if that document cannot be
    read anonymously, the peer has no key and the signature — a perfectly valid
    one — cannot be checked. This is the failure the reported 401 would have
    caused, reproduced by simulating an unreadable document."""
    body = {"broadcast_id": "roundtrip-2", "origin_chapter_id": chapter_agent_module.AGENT_ID}
    headers = federation_signing.sign_outbound(chapter_agent_module.AGENT_ID, body)

    async def _gated(url: str) -> dict | None:
        return None  # what a 401 looks like to fetch_peer_pubkey

    valid, reason = await federation_signing.verify_inbound(body, headers, "http://localhost", _gated)

    assert valid is False
    assert reason == "peer_key_unavailable"


async def test_R3_a_tampered_body_still_fails_with_a_resolvable_key(
    client: TestClient, chapter_agent_module, org_key
) -> None:
    """The round trip must not be trivially green: with the key resolvable, a
    modified body must still be rejected. Otherwise R1 proves only that two
    functions ran."""
    body = {"broadcast_id": "roundtrip-3", "origin_chapter_id": chapter_agent_module.AGENT_ID, "note": "original"}
    headers = federation_signing.sign_outbound(chapter_agent_module.AGENT_ID, body)

    tampered = {**body, "note": "tampered in flight"}
    valid, reason = await federation_signing.verify_inbound(
        tampered, headers, "http://localhost", _peer_fetcher(client)
    )

    assert valid is False
    assert reason == "invalid_signature"
