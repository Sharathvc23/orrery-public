"""
Tests for NANDA Index AgentFacts schema compliance.

Validates that build_nanda_facts() and the /agentfacts.json endpoints
produce output conforming to the full NANDA AgentFacts specification:
https://github.com/projnanda/agentfacts-format

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

import json

import pytest

import sovereign_identity
from nanda_models import NandaAgentFacts


@pytest.fixture(autouse=True)
def setup():
    sovereign_identity._agent_id = "test-chapter"


SAMPLE_MEMBER = {
    "name": "Alice Chen",
    "description": "Full-stack engineer in distributed systems",
    "skills": ["python", "rust", "kubernetes", "distributed-systems"],
}

PUBLIC_URL = "https://test-chapter.example.com"


# ══════════════════════════════════════════════════════════════
# HAPPY: Core schema compliance
# ══════════════════════════════════════════════════════════════


def test_all_required_fields_present():
    """HAPPY: AgentFacts contains every required top-level field."""
    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)

    required = ["id", "agent_name", "description", "version", "provider", "endpoints", "capabilities", "skills"]
    for field in required:
        assert field in facts, f"Missing required field: {field}"


def test_round_trip_validation():
    """HAPPY: Output validates against the NandaAgentFacts Pydantic model."""
    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_key="abc123", public_url=PUBLIC_URL)

    # This must not raise — proves the dict conforms to the model
    validated = NandaAgentFacts(**facts)
    assert validated.id == facts["id"]
    assert validated.agent_name == "alice"


def test_did_web_format():
    """HAPPY: DID uses W3C did:web format when public_url has a real domain."""
    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url="https://my-agent.example.com")

    assert facts["id"].startswith("did:web:")
    assert "my-agent.example.com" in facts["id"]
    assert "alice" in facts["id"]


def test_handle_format():
    """HAPPY: Handle follows @agent_id@domain pattern."""
    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url="https://chapter.example.com")

    assert facts["handle"] == "@alice@chapter.example.com"


def test_endpoints_constructed_from_url():
    """HAPPY: Endpoints are dynamically built from public_url, not hardcoded."""
    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url="https://my.server.com")

    assert facts["endpoints"]["a2a"] == "https://my.server.com/a2a"
    assert facts["endpoints"]["agentfacts_url"] == "https://my.server.com/agentfacts/alice.json"
    assert "https://my.server.com/a2a" in facts["endpoints"]["static"]


def test_skills_have_urn_format():
    """HAPPY: Skills use urn:nanda:skill: identifier format."""
    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)

    for skill in facts["skills"]:
        assert skill["id"].startswith("urn:nanda:skill:"), f"Bad skill ID: {skill['id']}"
        assert skill["description"]
        assert "inputModes" in skill
        assert "outputModes" in skill


def test_certification_present():
    """HAPPY: Certification section is populated with issuer and level."""
    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)

    assert facts["certification"]["level"] == "self-declared"
    assert facts["certification"]["issuer"]
    assert facts["certification"]["issuanceDate"]


def test_authentication_methods_declared():
    """HAPPY: Capabilities.authentication declares the ACTUAL auth methods.

    The org signs with Ed25519 (did:key), so AgentFacts must advertise
    ed25519/did-auth — not the stale bespoke hmac-sha256 (the org-side
    twin of the agent's that change)."""
    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)

    methods = facts["capabilities"]["authentication"]["methods"]
    assert "ed25519" in methods
    assert "did-auth" in methods
    assert "hmac-sha256" not in methods


def test_version_is_not_stale_placeholder():
    """The AgentFacts version must be the real server version, not the old
    hardcoded 1.0.0."""
    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)
    assert facts["version"] == sovereign_identity.SERVER_VERSION
    assert facts["version"] != "1.0.0"


def test_evaluations_populated_when_provided():
    """HAPPY: Evaluations section appears when data is passed."""
    evals = {"performanceScore": 4.2, "totalInteractions": 150, "avgResponseTimeMs": 85.5}
    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL, evaluations=evals)

    assert facts["evaluations"]["performanceScore"] == 4.2
    assert facts["evaluations"]["totalInteractions"] == 150


def test_telemetry_populated_when_provided():
    """HAPPY: Telemetry section appears when data is passed."""
    telem = {"latency_p50_ms": 45.0, "latency_p99_ms": 200.0, "error_rate_pct": 0.5}
    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL, telemetry=telem)

    assert facts["telemetry"]["latency_p50_ms"] == 45.0
    assert facts["telemetry"]["error_rate_pct"] == 0.5


# ══════════════════════════════════════════════════════════════
# EDGE: Boundary conditions
# ══════════════════════════════════════════════════════════════


def test_empty_member_produces_valid_facts():
    """EDGE: Member with no skills, no description still produces valid AgentFacts."""
    facts = sovereign_identity.build_nanda_facts("ghost", {}, public_url=PUBLIC_URL)

    validated = NandaAgentFacts(**facts)
    assert validated.agent_name == "ghost"
    assert validated.skills == []
    assert "NANDA agent" in validated.description


def test_skill_truncation_at_limit():
    """EDGE: Members with many skills get truncated to 20 max."""
    member = {"name": "Poly", "skills": [f"skill-{i}" for i in range(100)]}
    facts = sovereign_identity.build_nanda_facts("poly", member, public_url=PUBLIC_URL)

    assert len(facts["skills"]) == 20
    assert len(facts["capabilities"]["skills"]) == 20


def test_no_public_url_graceful():
    """EDGE: Missing public_url produces valid facts with localhost DID."""
    facts = sovereign_identity.build_nanda_facts("local", SAMPLE_MEMBER)

    # Should fall back to did:nanda: format
    assert facts["id"].startswith("did:nanda:")
    # Endpoints should be empty but valid
    validated = NandaAgentFacts(**facts)
    assert validated.endpoints.static == []


def test_updated_at_is_recent():
    """EDGE: updated_at timestamp is set to a recent time."""
    from datetime import UTC, datetime, timedelta

    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)

    updated = datetime.fromisoformat(facts["updated_at"])
    assert (datetime.now(UTC) - updated) < timedelta(seconds=5)


# ══════════════════════════════════════════════════════════════
# ADVERSARIAL: Security and correctness
# ══════════════════════════════════════════════════════════════


def test_no_hardcoded_urls():
    """ADVERSARIAL: Output must not contain any hardcoded deployment URLs."""
    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url="https://custom.example.com")
    serialized = json.dumps(facts)

    # PUBLIC_URL is this module's own fixture host, and the call above passed a
    # DIFFERENT one — so if it appears in the output, a module-level default
    # leaked past the argument. That is the property this test has always been
    # about; it previously spelled it as a literal deployment URL, which named
    # the hosting platform in a public tree to assert a string was absent.
    forbidden = ["org.example.com", PUBLIC_URL]
    for url in forbidden:
        assert url not in serialized, f"Hardcoded URL found: {url}"


def test_special_chars_in_agent_id():
    """ADVERSARIAL: SQL injection in agent_id doesn't break DID/handle."""
    facts = sovereign_identity.build_nanda_facts(
        "'; DROP TABLE agents;--",
        {"name": "Evil", "skills": ["<script>"]},
        public_url=PUBLIC_URL,
    )

    assert facts["id"].startswith("did:")
    validated = NandaAgentFacts(**facts)
    assert validated.agent_name == "'; DROP TABLE agents;--"


def test_xss_in_member_name():
    """ADVERSARIAL: XSS in member name appears in label but doesn't break model."""
    facts = sovereign_identity.build_nanda_facts(
        "test",
        {"name": "<img onerror=alert(1)>", "description": "<script>evil()</script>"},
        public_url=PUBLIC_URL,
    )

    validated = NandaAgentFacts(**facts)
    assert validated.label == "<img onerror=alert(1)>"  # Stored as-is (rendering escapes)


def test_very_long_description():
    """ADVERSARIAL: Extremely long description doesn't crash."""
    facts = sovereign_identity.build_nanda_facts(
        "long",
        {"name": "Long", "description": "x" * 100_000, "skills": ["a"]},
        public_url=PUBLIC_URL,
    )

    validated = NandaAgentFacts(**facts)
    assert len(validated.description) == 100_000


# ══════════════════════════════════════════════════════════════
# FAILURE: Graceful degradation
# ══════════════════════════════════════════════════════════════


def test_none_evaluations_omitted():
    """FAILURE: None evaluations/telemetry are excluded from output (exclude_none)."""
    facts = sovereign_identity.build_nanda_facts("alice", SAMPLE_MEMBER, public_url=PUBLIC_URL)

    # evaluations and telemetry should not be in output when not provided
    assert "evaluations" not in facts or facts.get("evaluations") is None
    assert "telemetry" not in facts or facts.get("telemetry") is None


def test_invalid_url_doesnt_crash():
    """FAILURE: Malformed public_url doesn't crash, produces some DID."""
    facts = sovereign_identity.build_nanda_facts("test", SAMPLE_MEMBER, public_url="not-a-url")

    assert facts["id"].startswith("did:")
    NandaAgentFacts(**facts)
