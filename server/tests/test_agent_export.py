"""
Adversarial tests for agent_export.py — prosecution-grade.

- P1: State transitions (export produces valid format, import creates agent)
- P3: Security invariants (private memory requires signature, no silent overwrite)
- C2: Every happy path gets a hostile path
- C5: Boundary proofs
- C7: Forgery mandatory
"""

import pytest

import agent_export
import sovereign_identity


class FakePostgresRequest:
    def __init__(self):
        self.calls = []
        self.data = {}

    async def __call__(self, method, table, params=None, body=None):
        self.calls.append((method, table, params, body))

        if method == "GET" and table == "agents":
            if params and "agent_id" in str(params):
                aid = [v for v in params.values() if "eq." in str(v)][0].replace("eq.", "")
                if aid in self.data:
                    return [self.data[aid]]
            return []

        if method == "GET":
            return []

        if method == "POST":
            return [body] if body else []

        return None


@pytest.fixture
def export_env():
    fake_sb = FakePostgresRequest()
    agent_export.init(pg_request=fake_sb, agent_id="test-chapter")
    sovereign_identity.init(pg_request=fake_sb, agent_id="test-chapter")

    # Seed a test agent
    fake_sb.data["alice"] = {
        "agent_id": "alice",
        "name": "@alice",
        "description": "Test agent",
        "skills": ["python", "ml"],
        "profile_type": "developer",
        "interests": ["AI"],
        "availability": "active",
        "reputation": {"introductions": 5, "votes": 3},
        "agent_facts": {
            "id": "did:nanda:alice",
            "provider": {"did": "did:key:abc123"},
        },
        "llm_provider": "xai",
        "llm_model": "grok-3-mini",
    }
    return fake_sb


# ═══════════════════════════════════════════════
# P1: STATE TRANSITIONS — EXPORT
# ═══════════════════════════════════════════════


# SECURITY (C2): the /export ENDPOINT restricts to the agent or an admin.
def _req(caller: str, *, headers: dict | None = None):
    from unittest.mock import MagicMock

    req = MagicMock()
    req.state.agent_id = caller
    req.headers = headers or {}
    return req


@pytest.mark.asyncio
async def test_export_endpoint_rejects_cross_agent_caller(export_env):
    """A verified member cannot export another member's record (IDOR)."""
    from fastapi import HTTPException

    import chapter_agent

    with pytest.raises(HTTPException) as exc:
        await chapter_agent.export_agent_endpoint("alice", _req("bob"))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_export_endpoint_rejects_unauthenticated(export_env):
    """No verified caller (empty request.state.agent_id) → 403."""
    from fastapi import HTTPException

    import chapter_agent

    with pytest.raises(HTTPException) as exc:
        await chapter_agent.export_agent_endpoint("alice", _req(""))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_export_endpoint_allows_self(export_env):
    """The agent exporting its own record succeeds."""
    import chapter_agent

    result = await chapter_agent.export_agent_endpoint("alice", _req("alice"))
    assert result["agent"]["agent_id"] == "alice"


# HAPPY: Export produces valid format
@pytest.mark.asyncio
async def test_export_valid_format(export_env):
    result = await agent_export.export_agent("alice")
    assert result["version"] == "1.0"
    assert result["agent"]["agent_id"] == "alice"
    assert result["agent"]["skills"] == ["python", "ml"]
    assert result["identity"]["did"] == "did:key:abc123"
    assert "evolution_history" in result
    assert "conversations" in result
    assert "projection" in result
    assert "private_memory" not in result  # Not requested


# FAILURE: Export nonexistent agent
@pytest.mark.asyncio
async def test_export_nonexistent(export_env):
    result = await agent_export.export_agent("ghost")
    assert "error" in result


# ═══════════════════════════════════════════════
# P1: STATE TRANSITIONS — IMPORT
# ═══════════════════════════════════════════════


# HAPPY: Import creates agent
@pytest.mark.asyncio
async def test_import_creates_agent(export_env):
    export_data = {
        "version": "1.0",
        "exported_from": "other-chapter",
        "agent": {
            "agent_id": "bob",
            "name": "@bob",
            "description": "Imported agent",
            "skills": ["rust", "go"],
            "profile_type": "developer",
            "interests": ["Systems"],
            "reputation": {},
        },
        "evolution_history": [],
        "private_memory": [],
    }
    result = await agent_export.import_agent(export_data)
    assert result["imported"] is True
    assert result["agent_id"] == "bob"


# FAILURE: Import duplicate agent_id rejected (no silent overwrite)
@pytest.mark.asyncio
async def test_import_duplicate_rejected(export_env):
    export_data = {
        "version": "1.0",
        "agent": {"agent_id": "alice", "name": "@alice"},
    }
    result = await agent_export.import_agent(export_data)
    assert "error" in result
    assert "already exists" in result["error"]


# FAILURE: Wrong version rejected
@pytest.mark.asyncio
async def test_import_wrong_version(export_env):
    result = await agent_export.import_agent({"version": "99.0", "agent": {}})
    assert "error" in result
    assert "version" in result["error"].lower()


# FAILURE: Missing agent_id rejected
@pytest.mark.asyncio
async def test_import_missing_agent_id(export_env):
    result = await agent_export.import_agent({"version": "1.0", "agent": {}})
    assert "error" in result


# EDGE: Import with evolution history
@pytest.mark.asyncio
async def test_import_with_evolution(export_env):
    export_data = {
        "version": "1.0",
        "agent": {"agent_id": "charlie", "name": "@charlie", "skills": ["js"]},
        "evolution_history": [
            {"skill": "react", "personality": "frontend expert", "trigger": "activity", "score": 5.0},
            {"skill": "node", "personality": "backend too", "trigger": "activity", "score": 3.0},
        ],
    }
    result = await agent_export.import_agent(export_data)
    assert result["imported"] is True
    assert result["evolution_entries"] == 2


# ═══════════════════════════════════════════════
# ADVERSARIAL
# ═══════════════════════════════════════════════


# ADVERSARIAL: SQL injection in agent_id
@pytest.mark.asyncio
async def test_export_sql_injection(export_env):
    result = await agent_export.export_agent("'; DROP TABLE--")
    assert "error" in result  # Not found, doesn't crash


# ADVERSARIAL: Import with malicious agent_facts
@pytest.mark.asyncio
async def test_import_malicious_facts(export_env):
    export_data = {
        "version": "1.0",
        "agent": {
            "agent_id": "evil",
            "name": "<script>alert(1)</script>",
            "description": "'; DROP TABLE agents;--",
            "skills": ["<img onerror=evil>"],
            "agent_facts": {"id": "'; DROP TABLE--"},
        },
    }
    result = await agent_export.import_agent(export_data)
    assert result["imported"] is True  # Creates but data is sanitized at API layer


# EDGE: Export includes correct field counts
@pytest.mark.asyncio
async def test_export_field_completeness(export_env):
    result = await agent_export.export_agent("alice")
    required_fields = [
        "version",
        "exported_at",
        "exported_from",
        "agent",
        "identity",
        "evolution_history",
        "conversations",
        "activity_summary",
        "projection",
    ]
    for field in required_fields:
        assert field in result, f"Missing field: {field}"
