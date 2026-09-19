"""
Tests for registry_divergence — the cross-registry omission/equivocation alarm.

The property under test: with ≥2 registries, any disagreement about the watch
set (omission, endpoint claim, attested DID) becomes a finding + a one-shot
federation.registry.divergence event — while an UNREACHABLE registry is never
mistaken for one that claims an org is absent.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import registry_attestation
import registry_divergence as rd
import sovereign_identity

NEST = "https://nest.example"
INDEX = "https://index.example"


@pytest.fixture(autouse=True)
def fresh_dedupe():
    rd._emitted.clear()
    yield
    rd._emitted.clear()


@pytest.fixture
def org_keypair():
    sovereign_identity.generate_ed25519_keypair("acme")
    yield
    sovereign_identity._ed25519_keypairs.pop("acme", None)


# ── diff_views: pure diff logic ──────────────────────────────


def test_consistent_views_no_findings():
    """HAPPY: registries agree — nothing to report."""
    v = {"endpoint": "https://acme.example.com"}
    assert rd.diff_views({NEST: {"acme": v}, INDEX: {"acme": dict(v)}}, {"acme"}) == []


def test_diff_views_unconfirmed_when_sibling_serves_and_peer_errored():
    """F4 (pure): present on one registry + errored on another → `unconfirmed`."""
    v = {"endpoint": "https://acme.example.com"}
    findings = rd.diff_views({NEST: {"acme": v}, INDEX: {}}, {"acme"}, errored={INDEX: {"acme"}})
    assert [f["kind"] for f in findings] == ["unconfirmed"]
    assert findings[0]["unconfirmed_on"] == [INDEX]


def test_diff_views_no_unconfirmed_when_no_sibling_serves():
    """An errored id that NO registry serves is not `unconfirmed` — there is no
    corroborating claim to contradict, so it stays silence (avoids noise when
    every registry is simply down)."""
    findings = rd.diff_views({NEST: {}, INDEX: {}}, {"acme"}, errored={NEST: {"acme"}, INDEX: {"acme"}})
    assert findings == []


def test_endpoint_divergence_detected():
    """ADVERSARIAL: registries claim different endpoints for the same org."""
    views = {
        NEST: {"acme": {"endpoint": "https://real.example.com"}},
        INDEX: {"acme": {"endpoint": "https://attacker.example.com"}},
    }
    findings = rd.diff_views(views, {"acme"})
    assert [f["kind"] for f in findings] == ["endpoint"]
    assert findings[0]["endpoints"] == {
        NEST: "https://real.example.com",
        INDEX: "https://attacker.example.com",
    }


def test_omission_detected():
    """ADVERSARIAL: one registry serves the org, another confirms it absent."""
    views = {NEST: {"acme": {"endpoint": "https://acme.example.com"}}, INDEX: {"acme": None}}
    findings = rd.diff_views(views, {"acme"})
    assert [f["kind"] for f in findings] == ["omission"]
    assert findings[0]["present_on"] == [NEST]
    assert findings[0]["missing_from"] == [INDEX]


def test_did_divergence_detected():
    """ADVERSARIAL: registries serve different valid attested DIDs — identity
    equivocation."""
    views = {
        NEST: {"acme": {"endpoint": "https://acme.example.com", "did": "did:key:zAAA"}},
        INDEX: {"acme": {"endpoint": "https://acme.example.com", "did": "did:key:zBBB"}},
    }
    findings = rd.diff_views(views, {"acme"})
    assert [f["kind"] for f in findings] == ["did"]


def test_unreachable_registry_is_not_omission():
    """EDGE: a registry that made NO claim (id missing from its view — it was
    unreachable) must not be reported as claiming absence."""
    views = {NEST: {"acme": {"endpoint": "https://acme.example.com"}}, INDEX: {}}
    assert rd.diff_views(views, {"acme"}) == []


def test_missing_endpoint_on_one_side_no_false_positive():
    """EDGE: a registry whose record lacks an endpoint value doesn't create a
    fake endpoint divergence."""
    views = {
        NEST: {"acme": {"endpoint": "https://acme.example.com"}},
        INDEX: {"acme": {"endpoint": ""}},
    }
    assert rd.diff_views(views, {"acme"}) == []


def test_ids_outside_watch_set_ignored():
    """EDGE: only the watch set is compared."""
    views = {
        NEST: {"stranger": {"endpoint": "https://a.example"}},
        INDEX: {"stranger": None},
    }
    assert rd.diff_views(views, {"acme"}) == []


# ── check(): fetch + emit ────────────────────────────────────


def _client_for(responses):
    """responses: url-substring → (status_code, json_body)"""

    async def _get(url, **kw):
        for frag, (code, body) in responses.items():
            if frag in url:
                resp = MagicMock(status_code=code)
                resp.json = MagicMock(return_value=body)
                return resp
        raise ConnectionError(f"unmatched {url}")

    client = MagicMock()
    client.get = AsyncMock(side_effect=_get)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


def _capture_events(monkeypatch):
    import event_bus

    events = []

    async def _publish(ev_type, payload):
        events.append((ev_type, payload))

    monkeypatch.setattr(event_bus, "safe_publish", _publish)
    return events


@pytest.mark.asyncio
async def test_single_registry_is_noop():
    """EDGE: nothing to corroborate against — no fetch, no findings."""
    client = _client_for({})
    with patch("registry_divergence.httpx.AsyncClient", return_value=client):
        assert await rd.check([NEST], {"acme"}) == []
    client.get.assert_not_called()


@pytest.mark.asyncio
async def test_endpoint_divergence_emits_event_once(monkeypatch):
    """HAPPY+EDGE: a divergence emits federation.registry.divergence exactly
    once per process even when check() runs every heartbeat."""
    events = _capture_events(monkeypatch)
    client = _client_for(
        {
            f"{NEST}/api/agents/acme": (200, {"agent_id": "acme", "endpoint": "https://real.example.com"}),
            f"{INDEX}/api/agents/acme": (200, {"agent_id": "acme", "endpoint": "https://attacker.example.com"}),
        }
    )
    with patch("registry_divergence.httpx.AsyncClient", return_value=client):
        first = await rd.check([NEST, INDEX], {"acme"})
        second = await rd.check([NEST, INDEX], {"acme"})

    assert [f["kind"] for f in first] == ["endpoint"]
    assert [f["kind"] for f in second] == ["endpoint"]  # still reported
    assert len([e for e in events if e[0] == "federation.registry.divergence"]) == 1  # emitted once


@pytest.mark.asyncio
async def test_soft_404_counts_as_absence(monkeypatch):
    """HAPPY: NEST's 200-with-error body ("Agent not found") is a positive
    claim of absence → omission finding."""
    events = _capture_events(monkeypatch)
    client = _client_for(
        {
            f"{NEST}/api/agents/acme": (200, {"agent_id": "acme", "endpoint": "https://acme.example.com"}),
            f"{INDEX}/api/agents/acme": (200, {"success": False, "error": "Agent not found"}),
        }
    )
    with patch("registry_divergence.httpx.AsyncClient", return_value=client):
        findings = await rd.check([NEST, INDEX], {"acme"})

    assert [f["kind"] for f in findings] == ["omission"]
    assert events and events[0][1]["missing_from"] == [INDEX]


@pytest.mark.asyncio
async def test_http_500_is_unconfirmed_not_silence(monkeypatch):
    """F4: a registry answering 500 for an id a SIBLING serves is not a
    confirmed omission (the record isn't proven absent), but it is not silence
    either — a cheating registry could hide an omission behind a 500. It surfaces
    as an `unconfirmed` finding, and never a crash."""
    _capture_events(monkeypatch)
    client = _client_for(
        {
            f"{NEST}/api/agents/acme": (200, {"agent_id": "acme", "endpoint": "https://acme.example.com"}),
            f"{INDEX}/api/agents/acme": (500, {"error": "boom"}),
        }
    )
    with patch("registry_divergence.httpx.AsyncClient", return_value=client):
        findings = await rd.check([NEST, INDEX], {"acme"})
    assert [f["kind"] for f in findings] == ["unconfirmed"]
    assert findings[0]["present_on"] == [NEST]
    assert findings[0]["unconfirmed_on"] == [INDEX]


@pytest.mark.asyncio
async def test_valid_attestations_feed_did_comparison(monkeypatch, org_keypair):
    """ADVERSARIAL: two registries serving different VALID attestations for
    the same org (one signed by an attacker key) → did divergence."""
    events = _capture_events(monkeypatch)
    real = registry_attestation.build("acme", "https://acme.example.com", "acme")
    sovereign_identity.generate_ed25519_keypair("attacker")
    forged = registry_attestation.build("acme", "https://acme.example.com", "attacker")
    sovereign_identity._ed25519_keypairs.pop("attacker", None)

    client = _client_for(
        {
            f"{NEST}/api/agents/acme": (
                200,
                {"agent_id": "acme", "endpoint": "https://acme.example.com", "attestation": real},
            ),
            f"{INDEX}/api/agents/acme": (
                200,
                {"agent_id": "acme", "endpoint": "https://acme.example.com", "attestation": forged},
            ),
        }
    )
    with patch("registry_divergence.httpx.AsyncClient", return_value=client):
        findings = await rd.check([NEST, INDEX], {"acme"})

    assert [f["kind"] for f in findings] == ["did"]
    assert events[0][1]["kind"] == "did"


@pytest.mark.asyncio
async def test_invalid_attestation_does_not_feed_did_comparison(monkeypatch, org_keypair):
    """EDGE: an invalid attestation contributes no DID — one valid + one
    invalid is not a did divergence."""
    _capture_events(monkeypatch)
    real = registry_attestation.build("acme", "https://acme.example.com", "acme")
    tampered = {"record": dict(real["record"]), "sig": real["sig"]}
    tampered["record"]["endpoint"] = "https://elsewhere.example.com"

    client = _client_for(
        {
            f"{NEST}/api/agents/acme": (
                200,
                {"agent_id": "acme", "endpoint": "https://acme.example.com", "attestation": real},
            ),
            f"{INDEX}/api/agents/acme": (
                200,
                {"agent_id": "acme", "endpoint": "https://acme.example.com", "attestation": tampered},
            ),
        }
    )
    with patch("registry_divergence.httpx.AsyncClient", return_value=client):
        assert await rd.check([NEST, INDEX], {"acme"}) == []
