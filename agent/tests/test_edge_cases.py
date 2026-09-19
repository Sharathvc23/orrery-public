"""
Edge case tests — EDGE-01 through EDGE-10.

These test boundary conditions, missing data, and graceful failures.
"""

import pytest

from community_member.config import Config
from community_member.sanitize import sanitize_agent_id, sanitize_skills

# ═══════════════════════════════════════════════
# EDGE-01: Empty skills list accepted
# ═══════════════════════════════════════════════


def test_empty_skills_accepted():
    assert sanitize_skills([]) == []


# ═══════════════════════════════════════════════
# EDGE-02: 20 skills accepted, 21 rejected
# ═══════════════════════════════════════════════


def test_max_skills_accepted():
    skills = [f"skill-{i}" for i in range(20)]
    result = sanitize_skills(skills)
    assert len(result) == 20


def test_over_max_skills_truncated():
    skills = [f"skill-{i}" for i in range(21)]
    result = sanitize_skills(skills)
    assert len(result) == 20


# ═══════════════════════════════════════════════
# EDGE-03: Agent ID with only hyphens rejected
# ═══════════════════════════════════════════════


def test_hyphens_only_rejected():
    assert sanitize_agent_id("---") == ""


def test_single_hyphen_rejected():
    assert sanitize_agent_id("-") == ""


# ═══════════════════════════════════════════════
# EDGE-04: Zero-length passphrase rejected
# ═══════════════════════════════════════════════


def test_empty_passphrase_rejected():
    from community_member.crypto import derive_key

    with pytest.raises(ValueError, match="empty"):
        derive_key("")


def test_empty_passphrase_encrypt_rejected():
    from community_member.crypto import encrypt_value

    # Empty passphrase should fail at derive_key level
    with pytest.raises(ValueError):
        encrypt_value("secret", "")


# ═══════════════════════════════════════════════
# EDGE-05: Config file missing → defaults
# ═══════════════════════════════════════════════


def test_missing_config_returns_defaults(tmp_path, monkeypatch):
    import community_member.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    config = Config.load()
    assert config.agent_id == ""
    assert not config.is_configured()


# ═══════════════════════════════════════════════
# EDGE-06: Config file corrupted → defaults (no crash)
# ═══════════════════════════════════════════════


def test_corrupted_config_no_crash(tmp_path, monkeypatch):
    import community_member.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    (tmp_path / "config.json").write_text("NOT VALID JSON {{{")
    config = Config.load()
    assert config.agent_id == ""  # Defaults, no crash


def test_corrupted_agent_state_no_crash(tmp_path, monkeypatch):
    import community_member.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    (tmp_path / "agent.json").write_text("CORRUPTED")
    config = Config()
    state = config.load_agent_state()
    assert state == {}  # Empty dict, no crash


def test_corrupted_memory_no_crash(tmp_path, monkeypatch):
    import community_member.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    (tmp_path / "memory.json").write_text("CORRUPTED")
    config = Config()
    memory = config.load_private_memory()
    assert memory == []  # Empty list, no crash


# ═══════════════════════════════════════════════
# EDGE-07: Chapter offline → graceful error
# ═══════════════════════════════════════════════


def test_chapter_offline_graceful():
    import httpx

    from community_member.a2a_client import A2AClient

    client = A2AClient("https://nonexistent-chapter.invalid")
    with pytest.raises((httpx.ConnectError, httpx.ConnectTimeout, OSError)):
        client.health()


# ═══════════════════════════════════════════════
# EDGE-08: Invalid LLM key → agent reports error, no crash
# ═══════════════════════════════════════════════


@pytest.mark.asyncio
async def test_invalid_llm_key_no_crash():
    from community_member.agent import LocalAgent

    config = Config()
    config.agent_id = "test"
    config.chapter_url = "https://nonexistent.invalid"
    config.api_key = "invalid-key"
    config.provider = "xai"
    config.model = "grok-3-mini"
    config.skills = ["test"]

    agent = LocalAgent(config)
    # Think should fail gracefully, not crash
    result = await agent.think()
    assert result is None  # Failed but didn't crash


# ═══════════════════════════════════════════════
# EDGE-09: Config save/load roundtrip
# ═══════════════════════════════════════════════


def test_config_roundtrip(tmp_path, monkeypatch):
    import community_member.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)

    config = Config()
    config.agent_id = "test-agent"
    config.name = "Test"
    config.skills = ["python", "rust"]
    config.chapter_url = "https://test.com"
    config.provider = "xai"
    config.api_key = "key123"
    config.model = "grok-3-mini"
    config.ensure_keypair()  # a real configured agent has an identity
    config.save()

    loaded = Config.load()
    assert loaded.agent_id == "test-agent"
    assert loaded.skills == ["python", "rust"]
    assert loaded.api_key == "key123"
    assert loaded.is_configured()


# ═══════════════════════════════════════════════
# EDGE-10: Multiple memory saves accumulate
# ═══════════════════════════════════════════════


def test_memory_accumulates(tmp_path, monkeypatch):
    import community_member.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)

    config = Config()
    config.save_private_memory("note1", "first")
    config.save_private_memory("note2", "second")
    config.save_private_memory("note3", "third")

    memory = config.load_private_memory()
    assert len(memory) == 3
    assert memory[0]["key"] == "note1"
    assert memory[2]["key"] == "note3"
