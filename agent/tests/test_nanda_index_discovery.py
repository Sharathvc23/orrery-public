"""Discovery: a URN in, a callable agent out — and every refusal named.

The defect this guards is not "resolve fails". It is resolve SUCCEEDING onto
something you cannot call: a record that is listed but not active, a card whose
``url`` is null, or a hop shape guessed wrong because the resolver assumed one
``media_type``. All three return a plausible answer, which is why each has a
test that pins the specific refusal rather than just "not ok".
"""

from __future__ import annotations

import httpx
import pytest

from community_member import nanda_index

INDEX = "https://index.example"
CARD_URL = "https://smb.example/t/bobs/.well-known/agent.json"
DID = "did:key:z6MkrFpAWXdELWtJLpfD4YXgjqe7PTGgrHy3e3y2Ja84Gdcb"


def _record(**overrides):
    record = {
        "org_id": "bobs",
        "display_name": "Bob's Barbers",
        "status": "active",
        "registry_url": CARD_URL,
        "media_type": nanda_index.MEDIA_A2A_CARD,
        "identifier": "urn:ai:domain:example.com:agent:bobs",
        "trust_manifest": {"identity": DID, "identityType": "did"},
    }
    record.update(overrides)
    return record


def _card(**overrides):
    card = {
        "name": "Bob's Barbers",
        "description": "Sovereign SMB agent",
        "url": "https://smb.example/t/bobs",
        "version": "0.8.0",
        "authentication": {"schemes": ["ed25519", "did-auth"], "credentials": DID},
    }
    card.update(overrides)
    return card


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), timeout=5)


def _routes(record=None, card=None, *, resolve_status=200, card_status=200, extra=None):
    """A mock index + card host. Any unrouted URL is a test bug, not a 404."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/api/v1/resolve" in url:
            if resolve_status != 200:
                return httpx.Response(resolve_status, json={"error": "nope"})
            return httpx.Response(
                200,
                json={
                    "locator": request.url.params.get("locator"),
                    "identifier": (record or {}).get("identifier", ""),
                    "index_record": record,
                },
            )
        for route_url, payload in (extra or {}).items():
            if url == route_url:
                return httpx.Response(200, json=payload)
        if url == CARD_URL:
            return httpx.Response(card_status, json=card if card_status == 200 else {})
        raise AssertionError(f"unrouted request in test: {url}")

    return handler


# ── the happy path, and the join to the existing signed caller ───────────────


def test_an_a2a_card_record_resolves_in_two_hops_to_a_callable_endpoint():
    with _client(_routes(_record(), _card())) as http:
        found = nanda_index.discover("urn:ai:domain:example.com:agent:bobs", index=INDEX, client=http)
    assert found.ok, found.reason
    assert found.endpoint == "https://smb.example/t/bobs"
    assert found.did == DID


def test_the_cards_did_is_checked_against_the_did_the_index_vouches_for():
    """Two independent statements of one identity, published through different
    channels. A card that quietly changed its key must not read as agreement."""
    with _client(_routes(_record(), _card())) as http:
        agrees = nanda_index.discover("urn:x", index=INDEX, client=http)
    assert nanda_index.did_matches_record(agrees) is True

    other = "did:key:z6MkuGKW5dt7RcBkTecvP4xL75kQErV6r5P4s14CzWH7jbcB"
    with _client(_routes(_record(), _card(authentication={"schemes": [], "credentials": other}))) as http:
        differs = nanda_index.discover("urn:x", index=INDEX, client=http)
    assert differs.ok, "the disagreement is a separate question from resolvability"
    assert nanda_index.did_matches_record(differs) is False


def test_client_for_returns_the_existing_signed_a2a_client_not_a_new_one():
    """Discovery's only job is learning the endpoint. Calling and signing stay
    in ``a2a_client_v2``; a second implementation would be the thing to avoid."""
    from community_member.a2a_client_v2 import GoogleA2AClient

    with _client(_routes(_record(), _card())) as http:
        found = nanda_index.discover("urn:x", index=INDEX, client=http)
    peer = nanda_index.client_for(found, agent_id="me", private_key="sk", public_key="pk")
    try:
        assert isinstance(peer, GoogleA2AClient)
        assert peer.base_url == "https://smb.example/t/bobs"
        assert peer.agent_id == "me"
    finally:
        peer.close()


def test_client_for_refuses_an_unresolved_agent():
    with _client(_routes(_record(), _card(url=""))) as http:
        found = nanda_index.discover("urn:x", index=INDEX, client=http)
    with pytest.raises(ValueError, match="card_names_no_runtime"):
        nanda_index.client_for(found)


# ── the failures that would otherwise look like successes ────────────────────


def test_a_card_naming_no_runtime_is_a_refusal_not_a_success():
    """The live personal record has exactly this shape: the chain resolves end
    to end and lands on a card whose ``url`` is null. Reporting that as a
    successful resolve is what makes it hard to notice."""
    with _client(_routes(_record(), _card(url=""))) as http:
        found = nanda_index.discover("urn:x", index=INDEX, client=http)
    assert not found.ok
    assert found.reason == "card_names_no_runtime"
    assert found.card, "the card is still reported — the caller may want to see what resolved"


def test_a_non_active_record_is_refused_by_that_name():
    with _client(_routes(_record(status="pending"), _card())) as http:
        found = nanda_index.discover("urn:x", index=INDEX, client=http)
    assert found.reason == "not_active"


def test_a_record_with_no_registry_url_names_nothing_to_fetch():
    with _client(_routes(_record(registry_url=None), _card())) as http:
        found = nanda_index.discover("urn:x", index=INDEX, client=http)
    assert found.reason == "no_registry_url"


def test_an_unfetchable_card_is_distinguished_from_an_unresolvable_urn():
    """Four failures, four responses. 'could not resolve' would collapse them."""
    with _client(_routes(_record(), None, card_status=404)) as http:
        unfetchable = nanda_index.discover("urn:x", index=INDEX, client=http)
    with _client(_routes(None, None, resolve_status=404)) as http:
        unresolvable = nanda_index.discover("urn:x", index=INDEX, client=http)
    assert unfetchable.reason == "card_unfetchable"
    assert unresolvable.reason == "not_resolvable"
    assert unfetchable.reason != unresolvable.reason


# ── the hop shape is chosen, never guessed ──────────────────────────────────


def test_a_catalog_record_is_walked_as_a_registry_not_read_as_a_card():
    """``ai-catalog+json`` means ``registry_url`` is a registry to walk. The one
    pre-existing resolve in the tree assumed this shape for everything."""
    registry = "https://registry.example"
    identifier = "urn:ai:domain:example.com:agent:bobs"
    extra = {
        f"{registry}/agents/{identifier}": {"url": CARD_URL},
    }
    record = _record(media_type=nanda_index.MEDIA_AI_CATALOG, registry_url=registry)
    with _client(_routes(record, _card(), extra=extra)) as http:
        found = nanda_index.discover(identifier, index=INDEX, client=http)
    assert found.ok, found.reason
    assert found.endpoint == "https://smb.example/t/bobs"


def test_an_unknown_media_type_is_refused_rather_than_tried_as_a_card():
    """FAILURE-MODE GUARD. Falling back to "try it as a card" would return a
    wrong answer for an MCP server card or a skill zip, and the wrongness would
    only surface at call time."""
    record = _record(media_type="application/mcp-server-card+json")

    def handler(request: httpx.Request) -> httpx.Response:
        if "/api/v1/resolve" in str(request.url):
            return httpx.Response(200, json={"locator": "u", "identifier": "i", "index_record": record})
        raise AssertionError(f"the resolver fetched {request.url} for a media_type it does not know")

    with _client(handler) as http:
        found = nanda_index.discover("urn:x", index=INDEX, client=http)
    assert found.reason == "unsupported_media_type"


def test_discovery_never_reads_the_bulk_listing():
    """A live record is ``active`` in ``GET /api/v1/index`` and unresolvable at
    ``resolve``. The listing is not evidence, so nothing here may consult it."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/index" or path.startswith("/api/v1/index/"):
            raise AssertionError("discovery consulted the bulk listing, which does not agree with resolve")
        if path == "/api/v1/resolve":
            return httpx.Response(200, json={"locator": "u", "identifier": "i", "index_record": _record()})
        if str(request.url) == CARD_URL:
            return httpx.Response(200, json=_card())
        raise AssertionError(f"unrouted: {request.url}")

    with _client(handler) as http:
        assert nanda_index.discover("urn:x", index=INDEX, client=http).ok
