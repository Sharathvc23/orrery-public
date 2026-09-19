"""W11 wiring: the ``update_settings`` agent tool routes through
``settings_sync.push_to_chapter`` (client-side validation + local cache +
offline outbox), not the raw ``client.update_settings`` call.

Proof of wiring:
- a valid patch reaches the client AND is mirrored into the local cache
  (only settings_sync writes the cache);
- an invalid patch is rejected client-side BEFORE any network call
  (a guarantee the raw client path never had).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from community_member import config as cm_config
from community_member import settings_sync


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setattr(cm_config, "CONFIG_DIR", tmp_path / "cm-home")
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "cm-home"))
    monkeypatch.setattr(settings_sync, "SETTINGS_CACHE", tmp_path / "settings.json")

    from community_member.agent import LocalAgent
    from community_member.config import Config

    cfg = Config()
    cfg.provider = "ollama"
    cfg.model = "test-model"
    cfg.agent_id = "alice"
    return LocalAgent(cfg)


def test_update_settings_tool_routes_through_settings_sync(agent):
    calls: list[tuple] = []
    agent.client = SimpleNamespace(
        update_settings=lambda aid, patch: (calls.append((aid, patch)), {"settings": dict(patch)})[1],
    )

    out = asyncio.run(agent.execute_tool("update_settings", {"patch": {"privacy": {"share": False}}}))

    # reached the chapter client on the happy path …
    assert calls == [("alice", {"privacy": {"share": False}})]
    # … and settings_sync mirrored it into the local cache (raw client never does)
    assert settings_sync.read_local().get("privacy") == {"share": False}
    assert "error" not in out


def test_update_settings_tool_validates_client_side(agent):
    calls: list[tuple] = []
    agent.client = SimpleNamespace(
        update_settings=lambda aid, patch: (calls.append((aid, patch)), {"settings": {}})[1],
    )

    out = asyncio.run(agent.execute_tool("update_settings", {"patch": {"bogus_key": 1}}))

    # rejected before any network call — a guard only push_to_chapter adds
    assert "invalid settings patch" in out
    assert calls == []
