"""
Privacy tests — SC-7: Memory Privacy Audit.

SEC-20: No private memory in any HTTP request body
SEC-21: Export without passphrase excludes private memory
"""

import json

from community_member.config import Config

# ═══════════════════════════════════════════════
# SEC-20: No private memory in HTTP requests
# ═══════════════════════════════════════════════


def test_a2a_client_never_sends_memory():
    """ADVERSARIAL: audit that A2AClient never includes memory.json content."""
    import inspect

    from community_member import a2a_client

    source = inspect.getsource(a2a_client)
    # memory.json, load_private_memory, save_private_memory should NEVER appear
    assert "memory.json" not in source, "A2A client references memory.json"
    assert "load_private_memory" not in source, "A2A client references private memory loader"
    assert "private_memory" not in source.replace("include_private", ""), "A2A client references private_memory"


def test_agent_never_sends_memory_to_http():
    """ADVERSARIAL: audit that agent.py never sends private notes via HTTP."""
    import inspect

    from community_member import agent

    source = inspect.getsource(agent)
    # The agent's save_note tool should write to config, not HTTP
    assert "memory.json" not in source.replace("~/.community-member/memory.json", ""), (
        "Agent references memory.json in non-comment context"
    )


def test_wizard_never_sends_memory():
    """ADVERSARIAL: audit wizard.py never transmits private data."""
    import inspect

    from community_member import wizard

    source = inspect.getsource(wizard)
    assert "load_private_memory" not in source, "Wizard loads private memory"


# ═══════════════════════════════════════════════
# SEC-21: Export without passphrase excludes memory
# ═══════════════════════════════════════════════


def test_config_save_private_memory_is_local(tmp_path):
    """HAPPY: private memory saves to local file only."""
    config = Config()
    # Monkey-patch config dir
    import community_member.config as config_mod

    original = config_mod.CONFIG_DIR
    config_mod.CONFIG_DIR = tmp_path

    config.save_private_memory("goal", "Become CEO", "goal")
    memory = config.load_private_memory()

    config_mod.CONFIG_DIR = original

    assert len(memory) == 1
    assert memory[0]["key"] == "goal"
    assert memory[0]["value"] == "Become CEO"
    # Verify it's on disk, not in any HTTP-accessible location
    assert (tmp_path / "memory.json").exists()


def test_agent_state_excludes_private_memory(tmp_path):
    """FAILURE: agent state export does not include private memory."""
    import community_member.config as config_mod

    original = config_mod.CONFIG_DIR
    config_mod.CONFIG_DIR = tmp_path

    config = Config()
    config.save_private_memory("secret", "my-password", "note")
    config.save_agent_state({"agent_id": "test", "skills": ["python"]})

    agent_state = config.load_agent_state()
    state_str = json.dumps(agent_state)

    config_mod.CONFIG_DIR = original

    # Agent state must NOT contain private memory
    assert "my-password" not in state_str
    assert "secret" not in state_str
