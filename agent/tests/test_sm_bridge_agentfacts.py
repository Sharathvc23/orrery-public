"""Phase 1: the sovereign agent emits canonical NANDA AgentFacts via sm-bridge.

Proves projectnanda-compatibility of the agent's identity surface: the
AgentFacts is the upstream ``SmAgentFacts`` shape (not the old bespoke
``did:nanda``/``hmac`` document), and the agent exposes sm-bridge's
``/sm-bridge/{index,resolve}`` registry routers.
"""

import base64

from fastapi.testclient import TestClient

from community_member import sm_bridge_adapter
from community_member.config import Config
from community_member.server import create_app


def _cfg(agent_id="alice-agent") -> Config:
    c = Config()
    c.agent_id = agent_id
    c.name = "Alice"
    c.description = "A human"
    c.skills = ["calendar", "email"]
    c.api_key = "x"
    c.public_key = base64.b64encode(b"\x02" * 32).decode()
    return c


def test_build_self_agentfacts_is_canonical_smagentfacts():
    from sm_bridge import SmAgentFacts

    facts = sm_bridge_adapter.build_self_agentfacts(_cfg(), "https://me.example.com")
    assert isinstance(facts, SmAgentFacts)
    assert facts.id.startswith("did:key:z")  # did:key from the Ed25519 pubkey
    assert facts.agent_name == "alice-agent"
    # AgentFacts version is sourced from the SDK __version__ (matches the A2A card).
    from community_member import __version__

    assert facts.version == __version__
    assert facts.endpoints.static == ["https://me.example.com/"]
    assert [s.id for s in facts.skills] == ["urn:nanda:skill:calendar", "urn:nanda:skill:email"]


def test_auth_is_ed25519_not_hmac():
    """The old bespoke facts wrongly advertised hmac-sha256; the agent signs
    with Ed25519. This is the compatibility bug Phase 1 fixes."""
    facts = sm_bridge_adapter.build_self_agentfacts(_cfg(), "https://me.example.com")
    methods = facts.capabilities.authentication.methods
    assert "ed25519" in methods
    assert "hmac-sha256" not in methods


def test_agentfacts_endpoint_serves_nanda_shape():
    client = TestClient(create_app(_cfg()))
    r = client.get("/agentfacts.json")
    assert r.status_code == 200
    j = r.json()
    assert j["id"].startswith("did:key:z")
    assert j["agent_name"] == "alice-agent"
    assert "ed25519" in j["capabilities"]["authentication"]["methods"]


def test_sm_bridge_index_lists_self():
    client = TestClient(create_app(_cfg()))
    r = client.get("/sm-bridge/index")
    assert r.status_code == 200
    j = r.json()
    assert j["total_count"] == 1
    assert j["agents"][0]["agent_name"] == "alice-agent"


def test_sm_bridge_resolve_self():
    client = TestClient(create_app(_cfg()))
    r = client.get("/sm-bridge/resolve", params={"agent": "alice-agent"})
    assert r.status_code == 200
    assert r.json()["agent_name"] == "alice-agent"


def test_test_prefixed_agent_excluded_from_registry():
    conv = sm_bridge_adapter.make_self_converter(_cfg("TEST-probe"), "https://x")
    assert list(conv.list_agents(100, 0)) == []
    assert conv.get_agent("TEST-probe") is None


# ── provider: who OPERATES the endpoint, not who is being hosted ─────────────


def test_the_default_provider_is_the_agent_itself():
    """The member runtime IS its own provider — the person whose agent it is
    runs the process and holds the key — so the default must not move. Asserted
    because the override added for ``smb_host`` changes this function for every
    caller, and a silent default flip would rewrite the member runtime's own
    identity document."""
    facts = sm_bridge_adapter.build_self_agentfacts(_cfg(), "https://me.example.com")
    assert facts.provider.name == "Alice"
    assert facts.provider.url == "https://me.example.com"
    # Its own provider, so its own did:key genuinely identifies the provider.
    assert facts.provider.did == facts.id


def test_a_provider_override_names_the_operator_and_drops_the_agents_did():
    """A host that runs OTHER people's agents supplies its own operator
    identity. ``provider.did`` is documented as the PROVIDER's DID and the only
    did available here is the AGENT's, so naming a third-party operator beside
    the agent's key would assert the operator's key is the agent's key. We say
    nothing rather than something false."""
    facts = sm_bridge_adapter.build_self_agentfacts(
        _cfg(),
        "https://host.example/t/alice-agent",
        provider_organization="host.example",
        provider_url="https://host.example",
    )
    assert facts.provider.name == "host.example"
    assert facts.provider.url == "https://host.example"
    assert facts.provider.did is None
    # The agent is still identified where the agent belongs.
    assert facts.id.startswith("did:key:z")
    assert facts.label == "Alice"
    # and the dropped field really is absent from the served JSON, not null
    assert "did" not in facts.model_dump(mode="json", exclude_none=True)["provider"]
