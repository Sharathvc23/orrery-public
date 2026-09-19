"""Federation directory — peers discoverable without manual endpoints.

The directory is an additional, curated peer source (FEDERATION_DIRECTORY_URLS)
whose records are only ever admitted with a VALID self-certifying attestation
(the that change–that change scheme, verbatim — no new trust primitive). Enforcement posture
elsewhere is unchanged: KNOWN_CHAPTER_ENDPOINTS stays the anchor, the NEST path
keeps its FEDERATION_REQUIRE_SIGNED_RECORDS warn-then-enforce semantics, and
discover() still only runs under the FEDERATION_AUTODISCOVER gate.

Includes the two-org local drill (real Ed25519 attestations, real verify path,
mutual discovery with NO manual endpoints) and the directory-as-divergence-leg
proof.

Classification: HAPPY / EDGE / ADVERSARIAL.
"""

from __future__ import annotations

import copy
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import federation_discovery as fd
import registry_attestation
import registry_divergence
import sovereign_identity

DIRECTORY = "https://directory.example"

ORG_A = "astro-org"
ORG_B = "acme-org"
EP_A = "https://astro.example.com"
EP_B = "https://acme.example.com"


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


def _health(org_id: str, name: str) -> dict:
    return {"status": "ok", "agent_id": org_id, "display_name": name, "members": 2}


@pytest.fixture
def two_orgs(monkeypatch):
    """Two orgs with REAL Ed25519 keypairs and REAL signed directory records —
    published to a directory, with NO manual endpoints configured anywhere."""
    monkeypatch.delenv("KNOWN_CHAPTER_ENDPOINTS", raising=False)
    monkeypatch.delenv("FEDERATION_REQUIRE_SIGNED_RECORDS", raising=False)
    monkeypatch.setenv("FEDERATION_DIRECTORY_URLS", DIRECTORY)
    for org in (ORG_A, ORG_B):
        sovereign_identity._ed25519_keypairs.pop(org, None)
        sovereign_identity.generate_ed25519_keypair(org)
    records = [
        {"agent_id": ORG_A, "endpoint": EP_A, "attestation": registry_attestation.build(ORG_A, EP_A, ORG_A)},
        {"agent_id": ORG_B, "endpoint": EP_B, "attestation": registry_attestation.build(ORG_B, EP_B, ORG_B)},
    ]
    yield records
    for org in (ORG_A, ORG_B):
        sovereign_identity._ed25519_keypairs.pop(org, None)


def _directory_transport(records):
    """A mocked httpx transport: the directory serves the records; each org's
    endpoint serves an org-shaped /health; NEST is not configured at all."""

    async def _get(url, **kw):
        if url.startswith(f"{DIRECTORY}/api/agents"):
            return _mock_response(200, {"agents": copy.deepcopy(records)})
        if url.startswith(f"{EP_A}/health"):
            return _mock_response(200, _health(ORG_A, "Astro Org"))
        if url.startswith(f"{EP_B}/health"):
            return _mock_response(200, _health(ORG_B, "Acme Org"))
        raise RuntimeError(f"unexpected fetch: {url}")

    return _mock_client(_get)


async def _discover_as(org_id: str, public_url: str, records) -> dict:
    federation: dict = {}
    fd.init("", org_id, public_url, federation, {})
    with patch("federation_discovery.httpx.AsyncClient", return_value=_directory_transport(records)):
        await fd.discover()
    return federation


# ── the local drill: mutual discovery with no manual endpoints ──────────


@pytest.mark.asyncio
async def test_two_orgs_find_each_other_via_directory_only(two_orgs):
    """HAPPY (the drill): no KNOWN_CHAPTER_ENDPOINTS, no NEST — each org
    discovers the other from the directory alone, attested + DID carried."""
    fed_a = await _discover_as(ORG_A, EP_A, two_orgs)
    assert ORG_B in fed_a and fed_a[ORG_B]["endpoint"] == EP_B
    assert fed_a[ORG_B]["did"] == two_orgs[1]["attestation"]["record"]["did"]
    assert ORG_A not in fed_a  # never self, even though the directory lists us

    fed_b = await _discover_as(ORG_B, EP_B, two_orgs)
    assert ORG_A in fed_b and fed_b[ORG_A]["endpoint"] == EP_A
    assert fed_b[ORG_A]["did"] == two_orgs[0]["attestation"]["record"]["did"]


@pytest.mark.asyncio
async def test_directory_probes_the_signed_endpoint_not_the_served_copy(two_orgs):
    """ADVERSARIAL: a cheating directory rewrites the top-level endpoint —
    discovery must probe the endpoint the org SIGNED, not the served copy."""
    two_orgs[1]["endpoint"] = "https://evil.example.com"  # attestation still says EP_B
    fed_a = await _discover_as(ORG_A, EP_A, two_orgs)
    assert fed_a[ORG_B]["endpoint"] == EP_B


# ── forged / unattested records are rejected ─────────────────────────────


@pytest.mark.asyncio
async def test_forged_directory_record_rejected(two_orgs):
    """ADVERSARIAL (issue checklist): a tampered signature never admits a peer."""
    two_orgs[1]["attestation"]["record"]["endpoint"] = "https://evil.example.com"  # sig now invalid
    fed_a = await _discover_as(ORG_A, EP_A, two_orgs)
    assert ORG_B not in fed_a


@pytest.mark.asyncio
async def test_redressed_attestation_rejected(two_orgs):
    """ADVERSARIAL: record B dressed in org A's valid attestation → rejected
    (subject mismatch), no peer admitted."""
    two_orgs[1]["attestation"] = copy.deepcopy(two_orgs[0]["attestation"])
    fed_a = await _discover_as(ORG_A, EP_A, two_orgs)
    assert ORG_B not in fed_a


@pytest.mark.asyncio
async def test_unattested_directory_record_rejected_even_without_enforcement(two_orgs, capsys):
    """ADVERSARIAL: the directory surface is born fail-closed — an unattested
    record is rejected even with FEDERATION_REQUIRE_SIGNED_RECORDS off (the
    flag keeps governing only the legacy NEST path)."""
    del two_orgs[1]["attestation"]
    fed_a = await _discover_as(ORG_A, EP_A, two_orgs)
    assert ORG_B not in fed_a
    assert "1 rejected (attestation required on this surface)" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_expired_attestation_rejected(two_orgs):
    """EDGE: a stale directory record (expired attestation window) is rejected."""
    expired = registry_attestation.build(ORG_B, EP_B, ORG_B, now=1000.0, ttl_s=60.0)
    two_orgs[1]["attestation"] = expired
    fed_a = await _discover_as(ORG_A, EP_A, two_orgs)
    assert ORG_B not in fed_a


# ── bounds + config plumbing ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_directory_probe_cap_logged_not_silent(two_orgs, monkeypatch, capsys):
    """EDGE: a bloated directory is clipped at the probe cap and says so."""
    org_c, ep_c = "zeta-org", "https://zeta.example.com"
    sovereign_identity.generate_ed25519_keypair(org_c)
    try:
        two_orgs.append(
            {"agent_id": org_c, "endpoint": ep_c, "attestation": registry_attestation.build(org_c, ep_c, org_c)}
        )
        monkeypatch.setattr(fd, "_DIRECTORY_PROBE_CAP", 1)
        fed_a = await _discover_as(ORG_A, EP_A, two_orgs)
    finally:
        sovereign_identity._ed25519_keypairs.pop(org_c, None)
    out = capsys.readouterr().out
    assert "directory probe cap (1) reached" in out
    assert len(fed_a) == 1  # exactly one admitted this cycle, the clip was loud


def test_directory_urls_parse_and_default_empty(monkeypatch):
    monkeypatch.delenv("FEDERATION_DIRECTORY_URLS", raising=False)
    assert fd.directory_urls() == []
    monkeypatch.setenv("FEDERATION_DIRECTORY_URLS", " https://a.example/ , https://b.example , https://a.example ")
    assert fd.directory_urls() == ["https://a.example", "https://b.example"]


@pytest.mark.asyncio
async def test_no_directory_configured_is_inert(two_orgs, monkeypatch):
    """EDGE: FEDERATION_DIRECTORY_URLS unset → feature fully inert (and with
    no NEST/allowlist either, nothing is discovered)."""
    monkeypatch.delenv("FEDERATION_DIRECTORY_URLS", raising=False)
    fed_a = await _discover_as(ORG_A, EP_A, two_orgs)
    assert fed_a == {}


# ── directory as a divergence-detector leg ──────────────────────────────


@pytest.mark.asyncio
async def test_directory_is_a_divergence_leg(two_orgs, monkeypatch):
    """HAPPY (issue checklist): a directory that re-points an org's endpoint
    diverges from the sibling registry and the detector says so."""
    registry_divergence._alerted.clear() if hasattr(registry_divergence, "_alerted") else None
    nest = "https://nest.example"
    honest = {"agent_id": ORG_B, "endpoint": EP_B, "attestation": two_orgs[1]["attestation"]}
    lying = copy.deepcopy(honest)
    lying["endpoint"] = "https://evil.example.com"

    async def _get(url, **kw):
        if url.startswith(f"{nest}/api/agents/{ORG_B}"):
            return _mock_response(200, honest)
        if url.startswith(f"{DIRECTORY}/api/agents/{ORG_B}"):
            return _mock_response(200, lying)
        return _mock_response(404, {})

    client = _mock_client(_get)
    with patch("registry_divergence.httpx.AsyncClient", return_value=client):
        findings = await registry_divergence.check([nest, DIRECTORY], {ORG_B})
    kinds = {f["kind"] for f in findings}
    assert any("endpoint" in k for k in kinds), findings
