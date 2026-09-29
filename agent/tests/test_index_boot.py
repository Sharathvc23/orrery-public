"""Boot-time index registration — off by default, and honest when it declines.

⚠️ THE DEFAULT THIS PROTECTS. An agent must not publish itself to a third party
because it happened to start. Registration is opt-in via an env var, and every
refusal says which precondition was missing rather than failing silently — a
quiet no-op and a successful registration look identical from the outside, and
that is the failure mode worth preventing.
"""

from __future__ import annotations

import base64
from types import SimpleNamespace

from community_member.index_boot import announce_to_index


def _config():
    from nacl.signing import SigningKey

    return SimpleNamespace(private_key=base64.b64encode(bytes(SigningKey.generate())).decode())


def test_off_unless_an_index_is_named(monkeypatch):
    monkeypatch.delenv("NANDA_INDEX_V3_URL", raising=False)
    assert announce_to_index(_config()) is None


def test_refuses_to_publish_a_pointer_it_cannot_be_reached_at(monkeypatch):
    """A next_hop guessed from a local bind address sends resolvers nowhere."""
    monkeypatch.setenv("NANDA_INDEX_V3_URL", "http://index.test")
    monkeypatch.delenv("AGENT_PUBLIC_URL", raising=False)

    result = announce_to_index(_config())

    assert result["action"] == "skipped"
    assert "AGENT_PUBLIC_URL" in result["detail"]


def test_without_a_key_there_is_no_name_to_claim(monkeypatch):
    """The identifier IS the key, so a keyless agent has nothing to register."""
    monkeypatch.setenv("NANDA_INDEX_V3_URL", "http://index.test")
    monkeypatch.setenv("AGENT_PUBLIC_URL", "https://agent.example")

    result = announce_to_index(SimpleNamespace(private_key=""))

    assert result["action"] == "skipped"
    assert "signing key" in result["detail"]


def test_an_unreachable_index_does_not_stop_the_agent(monkeypatch):
    """Someone else's outage must not become ours."""
    import community_member.index_v3 as index_v3

    monkeypatch.setenv("NANDA_INDEX_V3_URL", "http://index.test")
    monkeypatch.setenv("AGENT_PUBLIC_URL", "https://agent.example")

    def _down(**_kwargs):
        return {"action": "unreachable", "id": "urn:ai:key:u…/agent", "detail": "refused"}

    monkeypatch.setattr(index_v3, "ensure_registered", _down)
    assert announce_to_index(_config())["action"] == "unreachable"


def test_the_pointer_is_the_agent_card(monkeypatch):
    """Whatever registers must point at the card, not the bare host."""
    import community_member.index_v3 as index_v3

    monkeypatch.setenv("NANDA_INDEX_V3_URL", "http://index.test")
    monkeypatch.setenv("AGENT_PUBLIC_URL", "https://agent.example/")
    seen: dict = {}

    def _capture(**kwargs):
        seen.update(kwargs)
        return {"action": "registered", "id": "x", "seq": 1, "expires_at": "z"}

    monkeypatch.setattr(index_v3, "ensure_registered", _capture)
    announce_to_index(_config())

    assert seen["next_hop"] == "https://agent.example/.well-known/agent-card.json"
    assert seen["path"] == "agent"
