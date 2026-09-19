"""An agent can run standalone — no org required.

The wizard lets you skip the org step ("run on my own"); is_configured() must
treat that as valid so the dashboard serves. You join an org later (wizard or
Settings).
"""

from __future__ import annotations

from community_member.config import Config


def _identity(c: Config) -> Config:
    c.agent_id = "ada"
    c.private_key = "priv"
    c.public_key = "pub"
    return c


def test_standalone_agent_is_configured():
    c = _identity(Config())
    c.chapter_url = ""  # no org
    c.provider = "ollama"
    c.api_key = "local"  # local LLM sentinel
    assert c.is_configured()


def test_org_is_not_required():
    with_org = _identity(Config())
    with_org.chapter_url = "https://org.example"
    with_org.api_key = "k"
    without_org = _identity(Config())
    without_org.chapter_url = ""
    without_org.api_key = "k"
    assert with_org.is_configured() and without_org.is_configured()


def test_identity_required_brain_optional():
    # No identity → not configured, even with an LLM key.
    no_identity = Config()
    no_identity.api_key = "k"
    assert not no_identity.is_configured()  # no agent_id

    # Identity but NO brain → STILL configured: keyless is a complete setup
    # (the agent runs + serves + joins; a key only lights up the LLM extras).
    keyless = _identity(Config())
    keyless.api_key = ""  # no LLM at all (not even a local sentinel)
    assert keyless.is_configured()
