"""
Adversarial tests for sovereign_identity.py — prosecution-grade.

Following the Behavioral Testing Constitution:
- P2: Cryptographic anchor proofs (signing, verification, forgery)
- P3: Security invariant proofs (DID integrity, attestation tiers)
- C2: Every happy path gets a hostile path
- C5: Boundary proofs mandatory
- C7: Cryptographic forgery mandatory
"""

import pytest

import sovereign_identity


class FakePostgresRequest:
    def __init__(self):
        self.calls = []

    async def __call__(self, method, table, params=None, body=None):
        self.calls.append((method, table, params, body))
        if method == "GET" and table == "agents":
            return [{"agent_facts": {"certification": {"attestations": []}}}]
        return None


@pytest.fixture
def identity_env():
    fake_sb = FakePostgresRequest()
    sovereign_identity.init(pg_request=fake_sb, agent_id="test-chapter")
    return fake_sb


# ═══════════════════════════════════════════════
# P3: SECURITY INVARIANT PROOFS — NANDA FACTS
# ═══════════════════════════════════════════════


# HAPPY: Build facts produces valid NandaAgentFacts
def test_build_nanda_facts_valid(identity_env):
    kp = sovereign_identity.generate_ed25519_keypair("facts-tmp")
    sovereign_identity._ed25519_keypairs.pop("facts-tmp", None)
    facts = sovereign_identity.build_nanda_facts(
        "alice", {"name": "Alice", "skills": ["python", "ml"], "description": "Engineer"}, kp["public_key"]
    )
    assert facts["id"] == "did:nanda:alice"
    # provider.did is the proper W3C derivation now (the old assertion
    # codified the legacy did:key:{raw} carrier).
    assert facts["provider"]["did"] == sovereign_identity.build_did_key_from_ed25519(kp["public_key"])
    assert facts["certification"]["level"] == "self-declared"
    assert len(facts["skills"]) == 2


# EDGE: Empty skills produces valid facts
def test_build_facts_empty_skills(identity_env):
    facts = sovereign_identity.build_nanda_facts("bob", {"name": "Bob", "skills": []}, "")
    assert facts["skills"] == []
    assert facts["provider"].get("did") is None  # No public key (excluded_none)


# EDGE: Missing fields don't crash
def test_build_facts_missing_fields(identity_env):
    facts = sovereign_identity.build_nanda_facts("ghost", {}, "")
    assert facts["agent_name"] == "ghost"
    assert facts["description"] == "NANDA agent @ghost"


# ADVERSARIAL: Skills exceeding limit get truncated
def test_build_facts_skill_overflow(identity_env):
    facts = sovereign_identity.build_nanda_facts(
        "overflow", {"name": "O", "skills": [f"skill-{i}" for i in range(100)]}, ""
    )
    assert len(facts["skills"]) <= 20


# ADVERSARIAL: Special chars in agent_id
def test_build_facts_special_chars(identity_env):
    facts = sovereign_identity.build_nanda_facts(
        "'; DROP TABLE--", {"name": "<script>alert(1)</script>", "skills": ["<img onerror=evil>"]}, ""
    )
    assert facts["id"].startswith("did:")


# ═══════════════════════════════════════════════
# ATTESTATION TIER PROOFS
# ═══════════════════════════════════════════════


# HAPPY: Attest skill at valid tier
@pytest.mark.asyncio
async def test_attest_skill_valid(identity_env):
    result = await sovereign_identity.attest_skill("alice", "python", "github-verified")
    assert result["trust_level"] == "github-verified"
    assert "python:github-verified" in result["attestations"]


# FAILURE: Invalid trust level rejected
@pytest.mark.asyncio
async def test_attest_invalid_tier(identity_env):
    result = await sovereign_identity.attest_skill("alice", "python", "god-mode")
    assert "error" in result


# EDGE: Trust levels have correct numeric ordering
def test_trust_level_ordering():
    levels = sovereign_identity.TRUST_LEVELS
    assert levels["self-declared"] < levels["github-verified"]
    assert levels["github-verified"] < levels["peer-attested"]
    assert levels["peer-attested"] < levels["chapter-confirmed"]


# EDGE: Get trust for non-attested skill returns self-declared
@pytest.mark.asyncio
async def test_get_trust_unattested(identity_env):
    result = await sovereign_identity.get_skill_trust("alice", "nonexistent-skill")
    assert result["trust_level"] == "self-declared"
    assert result["score"] == 1


# ═══════════════════════════════════════════════
# CRDT-LITE FACTS VERSION PERSISTENCE
# ═══════════════════════════════════════════════


class _FakePostgresVersioned:
    """Fake Postgres that returns a fixed set of agents with facts_version."""

    def __init__(self, rows):
        self._rows = rows

    async def __call__(self, method, table, params=None, body=None):
        if method == "GET" and table == "agents":
            return self._rows
        return None


@pytest.mark.asyncio
async def test_load_facts_versions_hydrates_counter():
    """HAPPY: load_facts_versions populates the in-memory counter from Postgres."""
    sovereign_identity._facts_versions.clear()
    fake = _FakePostgresVersioned(
        [
            {"agent_id": "alice", "agent_facts": {"facts_version": 7}},
            {"agent_id": "bob", "agent_facts": {"facts_version": 3}},
        ]
    )
    sovereign_identity.init(pg_request=fake, agent_id="chapter")

    loaded = await sovereign_identity.load_facts_versions()

    assert loaded == 2
    assert sovereign_identity._facts_versions["alice"] == 7
    assert sovereign_identity._facts_versions["bob"] == 3


@pytest.mark.asyncio
async def test_restart_preserves_monotonicity():
    """C7 invariant: simulated restart — next get_facts_version exceeds persisted value."""
    sovereign_identity._facts_versions.clear()
    fake = _FakePostgresVersioned(
        [
            {"agent_id": "alice", "agent_facts": {"facts_version": 42}},
        ]
    )
    sovereign_identity.init(pg_request=fake, agent_id="chapter")

    # Before hydration, get_facts_version would return 1 — violating monotonicity
    # After hydration, it must return 43+
    await sovereign_identity.load_facts_versions()
    next_version = sovereign_identity.get_facts_version("alice")
    assert next_version == 43


@pytest.mark.asyncio
async def test_load_facts_versions_handles_missing_field():
    """EDGE: rows without facts_version are skipped, no crash."""
    sovereign_identity._facts_versions.clear()
    fake = _FakePostgresVersioned(
        [
            {"agent_id": "alice", "agent_facts": {}},
            {"agent_id": "bob", "agent_facts": None},
            {"agent_id": "charlie"},  # no agent_facts at all
        ]
    )
    sovereign_identity.init(pg_request=fake, agent_id="chapter")

    loaded = await sovereign_identity.load_facts_versions()
    assert loaded == 0
    # No spurious entries inserted
    assert sovereign_identity._facts_versions == {}


@pytest.mark.asyncio
async def test_load_facts_versions_never_decreases():
    """ADVERSARIAL: a lower persisted value must not overwrite a higher in-memory counter."""
    sovereign_identity._facts_versions.clear()
    # Simulate a counter already at 100 (e.g. from a later build)
    sovereign_identity._facts_versions["alice"] = 100

    fake = _FakePostgresVersioned(
        [
            {"agent_id": "alice", "agent_facts": {"facts_version": 5}},
        ]
    )
    sovereign_identity.init(pg_request=fake, agent_id="chapter")
    await sovereign_identity.load_facts_versions()

    # Must keep the higher value — a rogue Postgres rollback can't force us backwards
    assert sovereign_identity._facts_versions["alice"] == 100


@pytest.mark.asyncio
async def test_load_facts_versions_handles_supabase_error():
    """EDGE: Postgres failure during hydration doesn't crash startup."""

    class Boom:
        async def __call__(self, *args, **kw):
            raise RuntimeError("supabase down")

    sovereign_identity._facts_versions.clear()
    sovereign_identity.init(pg_request=Boom(), agent_id="chapter")

    # Must not raise
    loaded = await sovereign_identity.load_facts_versions()
    assert loaded == 0


@pytest.mark.asyncio
async def test_load_facts_versions_rejects_non_int_versions():
    """ADVERSARIAL: non-integer facts_version (injected bad data) is ignored."""
    sovereign_identity._facts_versions.clear()
    fake = _FakePostgresVersioned(
        [
            {"agent_id": "alice", "agent_facts": {"facts_version": "SEVEN"}},
            {"agent_id": "bob", "agent_facts": {"facts_version": -5}},
            {"agent_id": "charlie", "agent_facts": {"facts_version": 9}},
        ]
    )
    sovereign_identity.init(pg_request=fake, agent_id="chapter")
    loaded = await sovereign_identity.load_facts_versions()

    assert loaded == 1  # only charlie
    assert "alice" not in sovereign_identity._facts_versions
    assert "bob" not in sovereign_identity._facts_versions
    assert sovereign_identity._facts_versions["charlie"] == 9


@pytest.mark.asyncio
async def test_load_facts_versions_no_supabase_init():
    """EDGE: calling before init() doesn't crash."""
    sovereign_identity._pg_request = None
    sovereign_identity._facts_versions.clear()
    loaded = await sovereign_identity.load_facts_versions()
    assert loaded == 0


@pytest.mark.asyncio
async def test_build_nanda_facts_uses_hydrated_counter():
    """HAPPY end-to-end: after hydration, build_nanda_facts embeds incremented version."""
    sovereign_identity._facts_versions.clear()
    fake = _FakePostgresVersioned(
        [
            {"agent_id": "alice", "agent_facts": {"facts_version": 10}},
        ]
    )
    sovereign_identity.init(pg_request=fake, agent_id="chapter")
    await sovereign_identity.load_facts_versions()

    facts = sovereign_identity.build_nanda_facts("alice", {"name": "Alice", "skills": ["py"]}, "pk")
    assert facts["facts_version"] == 11
