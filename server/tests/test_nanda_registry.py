"""
Tests for NANDA Registry — dual registration on NEST + NANDA Index.

Validates backward compatibility with NEST and new Index registration.
Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import nanda_registry
import registry_attestation
import sovereign_identity


@pytest.fixture(autouse=True)
def setup():
    nanda_registry.registered_on_nest.clear()
    nanda_registry.registered_on_index.clear()
    nanda_registry.init(
        registry_url="https://nest.test.org",
        agent_id="test-chapter",
        agent_name="Test Chapter",
        agent_description="Test",
        agent_focus="testing",
        members={"alice": {"name": "Alice", "skills": ["python"]}, "bob": {"name": "Bob", "skills": []}},
        public_url="https://test.example.com",
    )


SAMPLE_FACTS = {
    "id": "did:web:test.example.com:agents:test-chapter",
    "agent_name": "test-chapter",
    "endpoints": {"agentfacts_url": "https://test.example.com/agentfacts.json"},
}


# ── HAPPY: NEST backward compatibility ──────────────────────


@pytest.mark.asyncio
async def test_nest_registration_sends_payload():
    """HAPPY: NEST registration sends correct payload format."""
    mock_resp = MagicMock(status_code=201)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("nanda_registry.httpx.AsyncClient", return_value=mock_client):
        result = await nanda_registry._register_on_nest(
            "test-chapter",
            {
                "agent_id": "test-chapter",
                "name": "Test",
                "endpoint": "https://test.example.com",
            },
        )

    assert result is True
    mock_client.post.assert_called_once()
    call_url = mock_client.post.call_args[0][0]
    assert "nest.test.org/api/agents" in call_url


@pytest.mark.asyncio
async def test_dual_registration_calls_both():
    """HAPPY: register_chapter calls both NEST and Index."""
    nest_resp = MagicMock(status_code=201)
    index_resp = MagicMock(status_code=201)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=nest_resp)
    mock_client.put = AsyncMock(return_value=index_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    nanda_registry._index_urls = ["https://index.nanda.org"]

    with patch("nanda_registry.httpx.AsyncClient", return_value=mock_client):
        await nanda_registry.register_chapter("https://test.example.com", facts=SAMPLE_FACTS)

    # Should have called post at least twice (NEST + Index)
    assert mock_client.post.call_count >= 2


# ── HAPPY: Index registration ───────────────────────────────


@pytest.mark.asyncio
async def test_index_registration_sends_full_facts():
    """HAPPY: Index registration includes full AgentFacts payload."""
    nanda_registry._index_urls = ["https://index.nanda.org"]
    mock_resp = MagicMock(status_code=201)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("nanda_registry.httpx.AsyncClient", return_value=mock_client):
        result = await nanda_registry.register_on_index("alice", SAMPLE_FACTS)

    assert result is True
    call_kwargs = mock_client.post.call_args
    payload = call_kwargs[1]["json"]
    assert payload["facts"] == SAMPLE_FACTS
    assert payload["agent_id"] == "alice"
    # Top-level endpoint claim — the cross-registry divergence detector
    # compares this field across registries.
    assert payload["endpoint"] == "https://test.example.com"


@pytest.mark.asyncio
async def test_member_registration_on_both():
    """HAPPY: Member registration hits both NEST and Index when facts provided."""
    nanda_registry._index_urls = ["https://index.nanda.org"]
    mock_resp = MagicMock(status_code=201)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("nanda_registry.httpx.AsyncClient", return_value=mock_client):
        await nanda_registry.register_member(
            "alice", {"name": "Alice", "skills": ["python"]}, "https://test.example.com", facts=SAMPLE_FACTS
        )

    assert mock_client.post.call_count >= 2


# ── EDGE: Fault isolation ───────────────────────────────────


@pytest.mark.asyncio
async def test_index_failure_does_not_block_nest():
    """EDGE: If Index is down, NEST registration still succeeds."""
    nanda_registry._index_urls = ["https://index.nanda.org"]
    nest_resp = MagicMock(status_code=201)

    call_count = 0

    async def mock_post(url, **kwargs):
        nonlocal call_count
        call_count += 1
        if "index.nanda.org" in url:
            raise ConnectionError("Index unreachable")
        return nest_resp

    mock_client = AsyncMock()
    mock_client.post = mock_post
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("nanda_registry.httpx.AsyncClient", return_value=mock_client):
        await nanda_registry.register_chapter("https://test.example.com", facts=SAMPLE_FACTS)

    # Should have attempted both
    assert call_count >= 2


@pytest.mark.asyncio
async def test_no_index_url_skips_index():
    """EDGE: Empty NANDA_INDEX_URL skips Index registration entirely."""
    nanda_registry._index_urls = []
    result = await nanda_registry.register_on_index("test", SAMPLE_FACTS)
    assert result is False


# ── Multi-registry parsing + fanout ─────────────────────────


def test_parse_index_urls_empty():
    """EDGE: empty string produces empty list."""
    assert nanda_registry._parse_index_urls("") == []


def test_parse_index_urls_single():
    """HAPPY: single URL parsed, trailing slash stripped."""
    assert nanda_registry._parse_index_urls("https://idx.example.com/") == ["https://idx.example.com"]


def test_parse_index_urls_comma_separated():
    """HAPPY: comma-separated list parses to multiple URLs."""
    parsed = nanda_registry._parse_index_urls("https://a.com, https://b.com ,https://c.com/")
    assert parsed == ["https://a.com", "https://b.com", "https://c.com"]


def test_parse_index_urls_skips_blank_segments():
    """EDGE: double commas and whitespace-only segments skipped."""
    parsed = nanda_registry._parse_index_urls("https://a.com,,  ,https://b.com")
    assert parsed == ["https://a.com", "https://b.com"]


@pytest.mark.asyncio
async def test_index_fanout_parallel():
    """HAPPY: register_on_index fans out to every configured index in parallel."""
    nanda_registry._index_urls = ["https://idx-a.com", "https://idx-b.com"]
    posted_urls: list[str] = []

    async def fake_post(url, **kw):
        posted_urls.append(url)
        return MagicMock(status_code=201)

    mock_client = AsyncMock()
    mock_client.post = fake_post
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("nanda_registry.httpx.AsyncClient", return_value=mock_client):
        ok = await nanda_registry.register_on_index("alice", SAMPLE_FACTS)

    assert ok is True
    assert any("idx-a.com" in u for u in posted_urls)
    assert any("idx-b.com" in u for u in posted_urls)


@pytest.mark.asyncio
async def test_index_fanout_one_down_other_succeeds():
    """EDGE: one index down, other succeeds — returns True."""
    nanda_registry._index_urls = ["https://idx-down.com", "https://idx-ok.com"]

    async def fake_post(url, **kw):
        if "idx-down" in url:
            raise ConnectionError("unreachable")
        return MagicMock(status_code=201)

    mock_client = AsyncMock()
    mock_client.post = fake_post
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("nanda_registry.httpx.AsyncClient", return_value=mock_client):
        ok = await nanda_registry.register_on_index("alice", SAMPLE_FACTS)

    assert ok is True
    assert "alice" in nanda_registry.registered_on_index


@pytest.mark.asyncio
async def test_index_fanout_all_down_returns_false():
    """FAILURE: all indexes unreachable, returns False, doesn't raise."""
    nanda_registry._index_urls = ["https://a.com", "https://b.com"]

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=ConnectionError("down"))
    mock_client.put = AsyncMock(side_effect=ConnectionError("down"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("nanda_registry.httpx.AsyncClient", return_value=mock_client):
        ok = await nanda_registry.register_on_index("alice", SAMPLE_FACTS)

    assert ok is False
    assert "alice" not in nanda_registry.registered_on_index


@pytest.mark.asyncio
async def test_probe_indexes_returns_reachability():
    """HAPPY: probe_indexes returns per-URL reachability info."""
    nanda_registry._index_urls = ["https://idx-up.com", "https://idx-dn.com"]

    async def fake_get(url, **kw):
        if "idx-up" in url:
            return MagicMock(status_code=200)
        raise ConnectionError("down")

    mock_client = AsyncMock()
    mock_client.get = fake_get
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("nanda_registry.httpx.AsyncClient", return_value=mock_client):
        results = await nanda_registry.probe_indexes()

    assert len(results) == 2
    by_url = {r["url"]: r for r in results}
    assert by_url["https://idx-up.com"]["reachable"] is True
    assert by_url["https://idx-dn.com"]["reachable"] is False


def test_get_registry_status_exposes_config():
    """HAPPY: get_registry_status reports configured registries for /health."""
    nanda_registry._index_urls = ["https://idx.example.com"]
    status = nanda_registry.get_registry_status()

    assert status["nest"]["configured"] is True
    assert status["nest"]["url"] == "https://nest.test.org"
    assert len(status["indexes"]) == 1
    assert status["indexes"][0]["url"] == "https://idx.example.com"


def test_init_parses_env_var():
    """HAPPY: init() reads NANDA_INDEX_URL env var as comma-separated list."""
    import os as _os

    _os.environ["NANDA_INDEX_URL"] = "https://one.com,https://two.com"
    try:
        nanda_registry.init(
            registry_url="https://nest",
            agent_id="a",
            agent_name="A",
            agent_description="d",
            agent_focus="x",
            members={},
            public_url="https://pub",
        )
        assert nanda_registry._index_urls == ["https://one.com", "https://two.com"]
    finally:
        _os.environ.pop("NANDA_INDEX_URL", None)


@pytest.mark.asyncio
async def test_unregister_from_index():
    """HAPPY: Unregister removes agent from Index."""
    nanda_registry._index_urls = ["https://index.nanda.org"]
    mock_resp = MagicMock(status_code=200)
    mock_client = AsyncMock()
    mock_client.delete = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("nanda_registry.httpx.AsyncClient", return_value=mock_client):
        result = await nanda_registry.unregister_from_index("alice")

    assert result is True
    mock_client.delete.assert_called_once()


# ── FAILURE: Both registries down ───────────────────────────


@pytest.mark.asyncio
async def test_both_registries_down_no_crash():
    """FAILURE: Both NEST and Index unreachable — agent doesn't crash."""
    nanda_registry._index_urls = ["https://index.nanda.org"]

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=ConnectionError("Network down"))
    mock_client.put = AsyncMock(side_effect=ConnectionError("Network down"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("nanda_registry.httpx.AsyncClient", return_value=mock_client):
        # Should not raise
        await nanda_registry.register_chapter("https://test.example.com", facts=SAMPLE_FACTS)


# ── ADVERSARIAL: TEST- prefix gating (NEST sandbox pollution) ─


@pytest.mark.asyncio
async def test_test_prefixed_member_not_published_to_nest():
    """ADVERSARIAL: TEST- prefix gates members out of NEST publication.

    Conformance probes (and any other deliberately-ephemeral agent)
    register on the chapter so tests can verify chapter behavior, but
    MUST NOT publish to NEST where they pollute discovery. The gate is
    in nanda_registry.register_member.
    """
    nanda_registry._index_urls = ["https://index.nanda.org"]

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=MagicMock(status_code=201))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("nanda_registry.httpx.AsyncClient", return_value=mock_client):
        await nanda_registry.register_member(
            "TEST-conformance-abc123",
            {"name": "TEST conformance", "skills": []},
            "https://test.example.com",
            facts=SAMPLE_FACTS,
        )

    # Zero outbound HTTP — no NEST POST, no Index POST.
    assert mock_client.post.call_count == 0, "TEST-prefixed member must not publish to NEST or NANDA Index"
    # Recorded so the periodic re-publish loop does not retry.
    assert "TEST-conformance-abc123" in nanda_registry.registered_on_nest


@pytest.mark.asyncio
async def test_test_prefix_gate_is_case_sensitive():
    """EDGE: gate matches the documented `TEST-` prefix exactly.

    Lowercase `test-` and other variants are real agent IDs and MUST
    publish normally. Only the documented uppercase TEST- convention
    triggers the gate.
    """
    nanda_registry._index_urls = []

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=MagicMock(status_code=201))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("nanda_registry.httpx.AsyncClient", return_value=mock_client):
        await nanda_registry.register_member(
            "test-lowercase",
            {"name": "Real agent", "skills": []},
            "https://test.example.com",
        )

    assert mock_client.post.call_count == 1, "lowercase test- is a real agent_id, must publish"


@pytest.mark.asyncio
async def test_non_test_member_publishes_normally():
    """HAPPY: regression guard — the gate doesn't break normal member registration."""
    nanda_registry._index_urls = []

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=MagicMock(status_code=201))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("nanda_registry.httpx.AsyncClient", return_value=mock_client):
        await nanda_registry.register_member(
            "alice", {"name": "Alice", "skills": ["python"]}, "https://test.example.com"
        )

    assert mock_client.post.call_count == 1


# ── Signed endpoint attestations (self-certifying records) ───


def _mock_client(status_code=201):
    client = AsyncMock()
    client.post = AsyncMock(return_value=MagicMock(status_code=status_code))
    client.put = AsyncMock(return_value=MagicMock(status_code=status_code))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


@pytest.fixture
def org_keypair():
    sovereign_identity.generate_ed25519_keypair("test-chapter")
    yield
    sovereign_identity._ed25519_keypairs.pop("test-chapter", None)


@pytest.mark.asyncio
async def test_chapter_registration_carries_verifiable_attestation(org_keypair):
    """HAPPY: the NEST payload carries a signed endpoint attestation that
    verifies offline and binds the org's id + endpoint."""
    client = _mock_client()
    with patch("nanda_registry.httpx.AsyncClient", return_value=client):
        await nanda_registry.register_chapter("https://test.example.com")

    payload = client.post.call_args[1]["json"]
    att = payload["attestation"]
    ok, reason = registry_attestation.verify(att)
    assert (ok, reason) == (True, "ok")
    assert att["record"]["agent_id"] == "test-chapter"
    assert att["record"]["endpoint"] == "https://test.example.com"


@pytest.mark.asyncio
async def test_member_registration_attested_by_org_key(org_keypair):
    """HAPPY: member records are host-certified — subject is the member, the
    signing DID is the org's (members are served at the org's endpoint)."""
    client = _mock_client()
    with patch("nanda_registry.httpx.AsyncClient", return_value=client):
        await nanda_registry.register_member(
            "alice", {"name": "Alice", "skills": ["python"]}, "https://test.example.com"
        )

    att = client.post.call_args[1]["json"]["attestation"]
    ok, _ = registry_attestation.verify(att)
    assert ok is True
    assert att["record"]["agent_id"] == "alice"
    chapter_att = registry_attestation.build("test-chapter", "https://x.com", "test-chapter")
    assert att["record"]["did"] == chapter_att["record"]["did"]


@pytest.mark.asyncio
async def test_index_registration_carries_attestation(org_keypair):
    """HAPPY: the Index payload carries the attestation too."""
    nanda_registry._index_urls = ["https://index.nanda.org"]
    client = _mock_client()
    with patch("nanda_registry.httpx.AsyncClient", return_value=client):
        await nanda_registry.register_on_index("test-chapter", SAMPLE_FACTS)

    att = client.post.call_args[1]["json"]["attestation"]
    ok, reason = registry_attestation.verify(att)
    assert (ok, reason) == (True, "ok")


@pytest.mark.asyncio
async def test_nest_update_fallback_carries_attestation(org_keypair):
    """EDGE: when the create POST 409s and registration falls back to PUT, the
    attestation rides along — a re-register must not strip the signed record."""
    client = _mock_client()
    client.post = AsyncMock(return_value=MagicMock(status_code=409))
    with patch("nanda_registry.httpx.AsyncClient", return_value=client):
        await nanda_registry.register_chapter("https://test.example.com")

    update_body = client.put.call_args[1]["json"]
    ok, _ = registry_attestation.verify(update_body["attestation"])
    assert ok is True


@pytest.mark.asyncio
async def test_registration_without_keypair_is_unattested_but_succeeds():
    """EDGE: no org keypair yet (first boot registers before
    ensure_chapter_keypair) — registration proceeds without the field."""
    sovereign_identity._ed25519_keypairs.pop("test-chapter", None)
    client = _mock_client()
    with patch("nanda_registry.httpx.AsyncClient", return_value=client):
        await nanda_registry.register_chapter("https://test.example.com")

    payload = client.post.call_args[1]["json"]
    assert "attestation" not in payload
