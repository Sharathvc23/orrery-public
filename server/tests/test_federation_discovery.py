"""Federation discovery — peers qualify structurally, not by name.

Regression guards for the org-rename era: two orgs named e.g. ``astrocity``
and ``acme`` must federate. The old gate required "chapter"/"nanda" in the
peer's agent_id, which silently rejected every org not named like the
original chapter deployments. Also guards: explicit KNOWN_CHAPTER_ENDPOINTS
peers must survive a NEST outage, and an org must never federate with
itself even when reached via an alias URL.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import federation_discovery as fd
import registry_attestation
import sovereign_identity


def _mock_response(status_code=200, payload=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json = MagicMock(return_value=payload if payload is not None else {})
    return resp


def _mock_client(get_side_effect):
    client = MagicMock()
    client.get = AsyncMock(side_effect=get_side_effect)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


ORG_HEALTH = {"status": "ok", "agent_id": "acme", "display_name": "ACME Collective", "members": 3}


# ── _check_chapter_endpoint: structural gate ─────────────────────────────


@pytest.mark.asyncio
async def test_org_named_peer_accepted_without_chapter_or_nanda_in_id():
    """HAPPY: a peer named 'acme' (no chapter/nanda substring) qualifies."""
    client = _mock_client(lambda url, **kw: _mock_response(200, ORG_HEALTH))
    result = await fd._check_chapter_endpoint(client, "https://acme.example.com")
    assert result is not None
    chapter_id, info = result
    assert chapter_id == "acme"
    assert info["status"] == "online"
    assert info["members"] == 3
    assert info["name"] == "ACME Collective"  # display_name preferred


@pytest.mark.asyncio
async def test_non_org_health_surface_rejected():
    """EDGE: a reachable /health that isn't an org server (no agent_id/members) is not a peer."""
    client = _mock_client(lambda url, **kw: _mock_response(200, {"status": "ok"}))
    assert await fd._check_chapter_endpoint(client, "https://something.example.com") is None


@pytest.mark.asyncio
async def test_self_via_alias_url_rejected(monkeypatch):
    """EDGE: an org reached at a URL != PUBLIC_URL but with our own agent_id is self, not a peer."""
    monkeypatch.setattr(fd, "_agent_id", "acme")
    client = _mock_client(lambda url, **kw: _mock_response(200, ORG_HEALTH))
    assert await fd._check_chapter_endpoint(client, "https://alias.example.com") is None


@pytest.mark.asyncio
async def test_unreachable_endpoint_returns_none():
    """EDGE: a connection error yields None, never raises."""

    async def _boom(url, **kw):
        raise RuntimeError("connect timeout")

    client = _mock_client(_boom)
    assert await fd._check_chapter_endpoint(client, "https://down.example.com") is None


# ── discover(): known endpoints survive a NEST outage ────────────────────


@pytest.mark.asyncio
async def test_known_endpoints_probed_when_nest_is_down(monkeypatch):
    """HAPPY: NEST unreachable + explicit allowlist → the peer is still discovered."""
    federation: dict = {}
    failures: dict = {}
    fd.init("https://nest.down.example", "my-org", "https://me.example.com", federation, failures)
    monkeypatch.setenv("KNOWN_CHAPTER_ENDPOINTS", "https://acme.example.com")

    async def _get(url, **kw):
        if "nest.down.example" in url:
            raise RuntimeError("registry down")
        return _mock_response(200, ORG_HEALTH)

    client = _mock_client(_get)
    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    assert "acme" in federation
    assert federation["acme"]["status"] == "online"


@pytest.mark.asyncio
async def test_nest_records_still_prefiltered_by_name(monkeypatch):
    """EDGE: unsolicited NEST records keep the probe-volume bound — a plain
    member agent record is not health-probed; an explicit allowlist peer is."""
    federation: dict = {}
    failures: dict = {}
    fd.init("https://nest.example", "my-org", "https://me.example.com", federation, failures)
    monkeypatch.setenv("KNOWN_CHAPTER_ENDPOINTS", "")

    nest_payload = {
        "agents": [
            {"agent_id": "random-member-bot", "endpoint": "https://member.example.com"},
        ]
    }
    probed: list[str] = []

    async def _get(url, **kw):
        if "nest.example" in url:
            return _mock_response(200, nest_payload)
        probed.append(url)
        return _mock_response(200, ORG_HEALTH)

    client = _mock_client(_get)
    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    assert probed == []  # member record never probed
    assert federation == {}


# ── discover(): self-certifying registry records ─────────────────────────


@pytest.fixture
def acme_attestation():
    """A valid signed endpoint attestation from 'acme-org' for its real endpoint."""
    sovereign_identity.generate_ed25519_keypair("acme-org")
    att = registry_attestation.build("acme-org", "https://acme.example.com", "acme-org")
    yield att
    sovereign_identity._ed25519_keypairs.pop("acme-org", None)


def _discover_setup(monkeypatch, nest_agents, enforce=False):
    federation: dict = {}
    fd.init("https://nest.example", "my-org", "https://me.example.com", federation, {})
    monkeypatch.setenv("KNOWN_CHAPTER_ENDPOINTS", "")
    # Warn mode must be requested with an explicit falsey value, not "". Since C9
    # an empty value means "nobody decided" and reads as ENFORCING — the same
    # coercion the production flag now uses. Setting "" here used to select warn
    # mode, so this helper quietly encoded the fail-open convention the audit
    # filed against.
    monkeypatch.setenv("FEDERATION_REQUIRE_SIGNED_RECORDS", "true" if enforce else "false")

    probed: list[str] = []

    async def _get(url, **kw):
        if "nest.example" in url:
            return _mock_response(200, {"agents": nest_agents})
        probed.append(url)
        return _mock_response(200, ORG_HEALTH)

    return federation, probed, _mock_client(_get)


@pytest.mark.asyncio
async def test_attested_record_discovered_with_did(monkeypatch, acme_attestation):
    """HAPPY: a valid attestation → peer discovered and the signer DID is
    carried onto the federation entry for downstream key verification."""
    record = {"agent_id": "acme-org", "endpoint": "https://acme.example.com", "attestation": acme_attestation}
    federation, probed, client = _discover_setup(monkeypatch, [record])

    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    assert "acme" in federation
    assert federation["acme"]["did"] == acme_attestation["record"]["did"]


@pytest.mark.asyncio
async def test_cheating_registry_endpoint_overridden_by_attestation(monkeypatch, acme_attestation):
    """ADVERSARIAL: the cheating-registry attack — the registry serves an
    attacker endpoint on an otherwise-valid record. The signed endpoint wins;
    the attacker endpoint is never probed."""
    record = {"agent_id": "acme-org", "endpoint": "https://attacker.example.com", "attestation": acme_attestation}
    federation, probed, client = _discover_setup(monkeypatch, [record])

    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    assert probed == ["https://acme.example.com/health"]
    assert federation["acme"]["endpoint"] == "https://acme.example.com"


@pytest.mark.asyncio
async def test_tampered_attestation_warn_mode_falls_back_unverified(monkeypatch, acme_attestation):
    """EDGE: invalid attestation under warn mode — the record is still probed at
    the registry endpoint (cutover-compatible), but no DID is attached: the peer
    is reachable, not verified.

    Warn mode is now an explicit opt-in (C9 flipped the default to enforcing),
    so this sets the flag rather than relying on the default.
    """
    tampered = {"record": dict(acme_attestation["record"]), "sig": acme_attestation["sig"]}
    tampered["record"]["endpoint"] = "https://elsewhere.example.com"
    record = {"agent_id": "acme-org", "endpoint": "https://acme.example.com", "attestation": tampered}
    federation, probed, client = _discover_setup(monkeypatch, [record])

    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    assert probed == ["https://acme.example.com/health"]
    assert "did" not in federation["acme"]


@pytest.mark.asyncio
async def test_unattested_record_skipped_under_enforcement(monkeypatch):
    """ADVERSARIAL: FEDERATION_REQUIRE_SIGNED_RECORDS=on — a legacy/unattested
    registry record is not probed at all."""
    record = {"agent_id": "legacy-org", "endpoint": "https://legacy.example.com"}
    federation, probed, client = _discover_setup(monkeypatch, [record], enforce=True)

    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    assert probed == []
    assert federation == {}


@pytest.mark.asyncio
async def test_enforcement_keeps_attested_and_allowlist_peers(monkeypatch, acme_attestation):
    """HAPPY: under enforcement, attested records and explicit allowlist peers
    both still federate — only unverifiable registry records are dropped."""
    records = [
        {"agent_id": "acme-org", "endpoint": "https://acme.example.com", "attestation": acme_attestation},
        {"agent_id": "legacy-org", "endpoint": "https://legacy.example.com"},
    ]
    federation, probed, client = _discover_setup(monkeypatch, records, enforce=True)
    monkeypatch.setenv("KNOWN_CHAPTER_ENDPOINTS", "https://trusted.example.com")

    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    assert "https://trusted.example.com/health" in probed
    assert "https://acme.example.com/health" in probed
    assert "https://legacy.example.com/health" not in probed


# ── discover(): attestations reach ALLOWLISTED peers (live-mesh wiring) ──


@pytest.mark.asyncio
async def test_allowlisted_peer_record_still_pins_did(monkeypatch, acme_attestation):
    """HAPPY: the live-mesh case — a peer wired via KNOWN_CHAPTER_ENDPOINTS
    whose id ('acme-corp', like astrocity/regentix/rocketbrain) never matches
    the chapter/nanda/org substring filter, and whose endpoint the allowlist
    already dedups. Its attestation must STILL be verified so the DID pin
    lands on the federation entry."""
    att = registry_attestation.build("acme-corp", "https://acme.example.com", "acme-org")
    record = {"agent_id": "acme-corp", "endpoint": "https://acme.example.com", "attestation": att}
    federation, probed, client = _discover_setup(monkeypatch, [record])
    monkeypatch.setenv("KNOWN_CHAPTER_ENDPOINTS", "https://acme.example.com")

    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    # Probed exactly once (allowlist), not twice — dedup intact.
    assert probed == ["https://acme.example.com/health"]
    assert federation["acme"]["did"] == att["record"]["did"]


@pytest.mark.asyncio
async def test_member_record_supplies_host_did_for_allowlisted_org(monkeypatch, acme_attestation):
    """HAPPY: a host-certified MEMBER record (subject=member, endpoint=org's)
    also carries the org DID onto an allowlisted peer."""
    member_att = registry_attestation.build("alice", "https://acme.example.com", "acme-org")
    record = {"agent_id": "alice", "endpoint": "https://acme.example.com", "attestation": member_att}
    federation, probed, client = _discover_setup(monkeypatch, [record])
    monkeypatch.setenv("KNOWN_CHAPTER_ENDPOINTS", "https://acme.example.com")

    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    assert federation["acme"]["did"] == member_att["record"]["did"]


@pytest.mark.asyncio
async def test_attested_unsolicited_record_still_not_probed(monkeypatch, acme_attestation):
    """ADVERSARIAL: probe-volume bound holds — an attested record that is
    neither org-shaped nor allowlisted is NOT probed (signatures are
    self-minted; anyone can flood the registry with validly-signed records)."""
    att = registry_attestation.build("random-agent", "https://flood.example.com", "acme-org")
    record = {"agent_id": "random-agent", "endpoint": "https://flood.example.com", "attestation": att}
    federation, probed, client = _discover_setup(monkeypatch, [record])

    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    assert probed == []
    assert federation == {}


# ── discover(): by-id attestation fetch (NEST strips it from the list) ───


def _nest_projection_setup(monkeypatch, by_id_doc, by_id_status=200):
    """NEST-realistic mock: the LIST endpoint serves a trimmed camelCase
    projection with NO attestation; the by-id endpoint serves the raw doc."""
    federation: dict = {}
    fd.init("https://nest.example", "my-org", "https://me.example.com", federation, {})
    monkeypatch.setenv("KNOWN_CHAPTER_ENDPOINTS", "https://acme.example.com")
    monkeypatch.setenv("FEDERATION_REQUIRE_SIGNED_RECORDS", "")

    trimmed = {"id": "skill-acme", "name": "ACME", "endpoint": "https://acme.example.com", "status": "running"}
    by_id_calls: list[str] = []

    async def _get(url, **kw):
        if url.endswith("/api/agents"):
            return _mock_response(200, {"agents": [trimmed], "pagination": {}})
        if "/api/agents/" in url:
            by_id_calls.append(url)
            return _mock_response(by_id_status, by_id_doc)
        return _mock_response(200, ORG_HEALTH)

    return federation, by_id_calls, _mock_client(_get)


@pytest.mark.asyncio
async def test_by_id_fetch_supplies_did_when_list_is_trimmed(monkeypatch, acme_attestation):
    """HAPPY: the live-NEST case — list projection has no attestation, the
    raw by-id record does. The DID still lands on the federation entry."""
    att = registry_attestation.build("acme", "https://acme.example.com", "acme-org")
    federation, by_id_calls, client = _nest_projection_setup(
        monkeypatch, {"agent_id": "acme", "attestation": att}
    )

    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    assert by_id_calls == ["https://nest.example/api/agents/acme"]
    assert federation["acme"]["did"] == att["record"]["did"]


@pytest.mark.asyncio
async def test_by_id_fetch_happens_once_then_did_carries_forward(monkeypatch, acme_attestation):
    """EDGE: the by-id fetch is one-shot per peer — later cycles reuse the
    DID already carried on the federation entry."""
    att = registry_attestation.build("acme", "https://acme.example.com", "acme-org")
    federation, by_id_calls, client = _nest_projection_setup(
        monkeypatch, {"agent_id": "acme", "attestation": att}
    )

    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()
        await fd.discover()

    assert len(by_id_calls) == 1
    assert federation["acme"]["did"] == att["record"]["did"]


@pytest.mark.asyncio
async def test_by_id_attestation_for_other_endpoint_not_pinned(monkeypatch, acme_attestation):
    """ADVERSARIAL: the raw record's attestation attests a DIFFERENT endpoint
    than the one we're connected to — surfaced, not pinned."""
    att = registry_attestation.build("acme", "https://elsewhere.example.com", "acme-org")
    federation, by_id_calls, client = _nest_projection_setup(
        monkeypatch, {"agent_id": "acme", "attestation": att}
    )

    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    assert "did" not in federation["acme"]


@pytest.mark.asyncio
async def test_by_id_fetch_absent_or_failing_is_harmless(monkeypatch, acme_attestation):
    """EDGE: by-id 404 (or no attestation on the doc) — peer still federates
    unpinned, nothing raises."""
    federation, by_id_calls, client = _nest_projection_setup(monkeypatch, {"error": "not found"}, by_id_status=404)

    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    assert federation["acme"]["status"] == "online"
    assert "did" not in federation["acme"]


# ── discover(): DID pinning wire-up ──────────────────────────────────────


def _capture_events(monkeypatch):
    import event_bus

    events: list[tuple[str, dict]] = []

    async def _publish(ev_type, payload):
        events.append((ev_type, payload))

    monkeypatch.setattr(event_bus, "safe_publish", _publish)
    return events


@pytest.mark.asyncio
async def test_attested_did_is_pinned_on_discovery(monkeypatch, acme_attestation):
    """HAPPY: a verified attested DID is handed to federation_policy for TOFU
    pinning, keyed by the peer's /health identity."""
    import federation_policy

    record = {"agent_id": "acme-org", "endpoint": "https://acme.example.com", "attestation": acme_attestation}
    federation, probed, client = _discover_setup(monkeypatch, [record])

    pinned_calls: list[tuple] = []

    async def _pin(peer_id, did, endpoint=None):
        pinned_calls.append((peer_id, did, endpoint))
        return "pinned", did

    monkeypatch.setattr(federation_policy, "check_and_pin_did", _pin)
    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    assert pinned_calls == [("acme", acme_attestation["record"]["did"], "https://acme.example.com")]
    assert federation["acme"]["did"] == acme_attestation["record"]["did"]


@pytest.mark.asyncio
async def test_did_mismatch_warn_mode_trusts_pin_and_emits_event(monkeypatch, acme_attestation):
    """ADVERSARIAL: registry re-keys a known peer. Warn mode keeps the peer
    reachable but downstream verification gets the PINNED DID, and a
    did_mismatch event fires for the audit trail.

    Warn mode is an explicit opt-in since C9 flipped the default to enforcing.
    """
    import asyncio

    import federation_policy

    record = {"agent_id": "acme-org", "endpoint": "https://acme.example.com", "attestation": acme_attestation}
    federation, probed, client = _discover_setup(monkeypatch, [record])
    events = _capture_events(monkeypatch)

    async def _pin(peer_id, did, endpoint=None):
        return "mismatch", "did:key:zORIGINALPIN"

    monkeypatch.setattr(federation_policy, "check_and_pin_did", _pin)
    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()
    await asyncio.sleep(0)

    assert federation["acme"]["did"] == "did:key:zORIGINALPIN"
    mismatch = [p for t, p in events if t == "federation.peer.did_mismatch"]
    assert mismatch and mismatch[0]["attested_did"] == acme_attestation["record"]["did"]
    assert mismatch[0]["pinned_did"] == "did:key:zORIGINALPIN"


@pytest.mark.asyncio
async def test_did_mismatch_under_enforcement_drops_peer(monkeypatch, acme_attestation):
    """ADVERSARIAL: FEDERATION_REQUIRE_SIGNED_RECORDS=on + identity swap →
    the peer is not admitted at all this cycle (event still fires)."""
    import asyncio

    import federation_policy

    record = {"agent_id": "acme-org", "endpoint": "https://acme.example.com", "attestation": acme_attestation}
    federation, probed, client = _discover_setup(monkeypatch, [record], enforce=True)
    events = _capture_events(monkeypatch)

    async def _pin(peer_id, did, endpoint=None):
        return "mismatch", "did:key:zORIGINALPIN"

    monkeypatch.setattr(federation_policy, "check_and_pin_did", _pin)
    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()
    await asyncio.sleep(0)

    assert "acme" not in federation
    assert any(t == "federation.peer.did_mismatch" for t, _ in events)


@pytest.mark.asyncio
async def test_attestation_subject_must_match_record(monkeypatch, acme_attestation):
    """ADVERSARIAL: a registry can't dress record B in org A's valid
    attestation — subject mismatch is treated as unverified (skipped under
    enforcement)."""
    record = {"agent_id": "other-org", "endpoint": "https://other.example.com", "attestation": acme_attestation}
    federation, probed, client = _discover_setup(monkeypatch, [record], enforce=True)

    with patch("federation_discovery.httpx.AsyncClient", return_value=client):
        await fd.discover()

    assert probed == []
    assert federation == {}
