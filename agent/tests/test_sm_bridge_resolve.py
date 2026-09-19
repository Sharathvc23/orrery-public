"""P2 — /sm-bridge/resolve must round-trip the canonical id the index advertises.

/sm-bridge/index advertises ``id = did:key…``, but resolve only matched the bare
``agent_id`` — so a NANDA/NEST consumer that reads the index id and resolves by it
got a 404. SelfConverter.get_agent now also matches the did:key and the @handle.

Classification: HAPPY / EDGE (gating).
"""

from __future__ import annotations

import base64

import pytest

from community_member import sm_bridge_adapter
from community_member.config import Config


def _cfg(agent_id: str = "priya-agent") -> Config:
    c = Config()
    c.agent_id = agent_id
    c.name = "Priya"
    c.description = "A sovereign agent"
    c.skills = ["calendar"]
    c.api_key = "x"
    c.public_key = base64.b64encode(b"\x02" * 32).decode()
    return c


def test_resolve_round_trips_index_id():
    cfg = _cfg("priya-agent")
    conv = sm_bridge_adapter.make_self_converter(cfg, "https://me.example.com")
    if conv is None:
        pytest.skip("sm-bridge not installed")

    did = sm_bridge_adapter._agent_did(cfg, "https://me.example.com")  # what /index advertises
    rec = {"agent_id": "priya-agent"}

    assert conv.get_agent(did) == rec, "resolve by the index id (did) failed — the break"
    assert conv.get_agent("priya-agent") == rec
    assert conv.get_agent("@priya-agent") == rec
    assert conv.get_agent("did:key:zSomeoneElse") is None
    assert conv.get_agent("not-a-real-agent") is None


def test_resolve_still_gated_for_test_prefix():
    """TEST- agents stay unlisted + unresolvable by any form (publication gate)."""
    cfg = _cfg("TEST-bot")
    conv = sm_bridge_adapter.make_self_converter(cfg, "https://me.example.com")
    if conv is None:
        pytest.skip("sm-bridge not installed")

    did = sm_bridge_adapter._agent_did(cfg, "https://me.example.com")
    assert conv.get_agent("TEST-bot") is None
    assert conv.get_agent(did) is None
    assert conv.get_agent("@TEST-bot") is None
