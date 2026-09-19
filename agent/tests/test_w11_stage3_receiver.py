"""W11 stage 3 wiring: inbound channel receiver.

- channel_secrets: agent-local per-connection secret store + resolver, with the
  kind-only fallback Discord needs.
- connect_channel: stores the verification secret LOCALLY and never sends it to
  the chapter.
- _drain_inbound: the run loop consumes verified inbox events.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from community_member import channel_secrets
from community_member import config as cm_config
from community_member.channel_receiver import Inbox, InboxItem


@pytest.fixture(autouse=True)
def _isolate_secrets(monkeypatch, tmp_path):
    monkeypatch.setattr(channel_secrets, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(channel_secrets, "SECRETS_FILE", tmp_path / "channel_secrets.json")


# ── the secret store + resolver ──


def test_set_and_get_secret_exact():
    channel_secrets.set_secret("slack", "T123", "shhh")
    assert channel_secrets.get_secret("slack", "T123") == "shhh"


def test_get_secret_unknown_is_empty():
    assert channel_secrets.get_secret("slack", "nope") == ""


def test_discord_kind_only_fallback():
    # Discord verifies before it can parse remote_id → resolver is called with "".
    channel_secrets.set_secret("discord", "guild-9", "pubkeyhex")
    assert channel_secrets.get_secret("discord", "") == "pubkeyhex"


def test_has_any_reflects_state():
    assert channel_secrets.has_any() is False
    channel_secrets.set_secret("webhook", "wh-1", "s")
    assert channel_secrets.has_any() is True


def test_secret_file_is_owner_only():
    channel_secrets.set_secret("slack", "T1", "s")
    mode = (channel_secrets.SECRETS_FILE.stat().st_mode) & 0o777
    assert mode == 0o600


# ── connect_channel stores the secret locally, not to the chapter ──


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setattr(cm_config, "CONFIG_DIR", tmp_path / "cm-home")
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path / "cm-home"))
    from community_member.agent import LocalAgent
    from community_member.config import Config

    cfg = Config()
    cfg.provider = "ollama"
    cfg.model = "test-model"
    cfg.agent_id = "alice"
    return LocalAgent(cfg)


def test_connect_channel_stores_secret_locally_not_to_chapter(agent):
    import asyncio

    sent = {}
    agent.client = SimpleNamespace(
        connect_channel=lambda **kw: sent.update(kw) or {"ok": True},
    )
    asyncio.run(
        agent.execute_tool(
            "connect_channel",
            {"kind": "slack", "remote_id": "T999", "signing_secret": "top-secret"},
        )
    )
    # secret is on disk locally …
    assert channel_secrets.get_secret("slack", "T999") == "top-secret"
    # … and was NOT included in the chapter POST
    assert "signing_secret" not in sent
    assert "top-secret" not in str(sent)


# ── the run loop drains the inbox ──


def test_drain_inbound_consumes_items(agent):
    inbox = Inbox()
    inbox.put_nowait(
        InboxItem(
            kind="slack",
            remote_id="T1",
            sender="slack:U1",
            body={"text": "hi"},
            session_scope="agent:channel:slack:dm:U1",
            event_sha256="abc",
        )
    )
    agent.inbox = inbox
    drained = agent._drain_inbound()
    assert drained == 1
    assert inbox.size == 0


def test_drain_inbound_noop_without_inbox(agent):
    agent.inbox = None
    assert agent._drain_inbound() == 0
