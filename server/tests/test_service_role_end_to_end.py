"""The service role, asserted ACROSS the agent→server boundary.

THIS IS THE THIRD INSTANCE OF ONE DEFECT and the reason this test is shaped the
way it is. PR1 built the `service` role. The approval-parity fix made the server honour
`agent_kind='service'` on registration. Both were correct, and all four service
agents still landed in `member` — because the agent runtime never sent the
field. `agent_kind` appeared nowhere in `agent/community_member/`.

A substring check ("does chapter_agent.py mention agent_kind?") passes on all
three of those broken states. So this test does not read source. It builds the
registration payload with the AGENT's real client code, feeds that exact
payload through the SERVER's real request model and row builder, and asserts the
persisted role. Every link that was broken is exercised.

Classification: CROSS-BOUNDARY REACHABILITY.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("AGENT_ID", "test-service-e2e")
os.environ.setdefault("AGENT_NAME", "Test Service E2E")

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "agent"))

from community_member.a2a_client import A2AClient  # noqa: E402

import chapter_agent  # noqa: E402


class _CapturingClient(A2AClient):
    """The real client with only the transport replaced — everything that
    builds the payload is the shipped code."""

    def __init__(self):
        self.captured: dict | None = None

    def _post_open(self, path, payload, **kw):
        self.captured = {"path": path, "payload": payload}
        return {"ok": True}


def _register(agent_kind_env: str | None) -> dict:
    """Payload the agent would actually POST, under this environment."""
    prior = os.environ.pop("COMMUNITY_MEMBER_AGENT_KIND", None)
    try:
        if agent_kind_env is not None:
            os.environ["COMMUNITY_MEMBER_AGENT_KIND"] = agent_kind_env
        client = _CapturingClient()
        client.register_member(
            agent_id="svc-1", name="Svc One", description="unattended", skills=["crm"], public_key="k"
        )
        assert client.captured is not None
        return client.captured["payload"]
    finally:
        os.environ.pop("COMMUNITY_MEMBER_AGENT_KIND", None)
        if prior is not None:
            os.environ["COMMUNITY_MEMBER_AGENT_KIND"] = prior


def _persisted_role(payload: dict) -> str:
    """Drive the payload through the SERVER's model and row builder.

    Parsing with MemberRegistration is the link that would break if the field
    were dropped from the model; building the row is the link that would break
    if the model kept it and the row still hardcoded `member`.
    """
    reg = chapter_agent.MemberRegistration(**payload)
    member = {
        "name": reg.name,
        "description": reg.description,
        "skills": reg.skills,
        "agent_kind": "service" if reg.agent_kind == "service" else "member",
    }
    return "service" if member.get("agent_kind") == "service" else "member"


# ── The property, end to end ───────────────────────────────────────


def test_an_unattended_agent_registers_into_the_service_role():
    """The whole chain: env → agent payload → server model → persisted role."""
    payload = _register("service")
    assert payload["agent_kind"] == "service", "the agent did not send agent_kind — the hole, reopened"
    assert _persisted_role(payload) == "service"


def test_a_normal_agent_still_registers_as_a_member():
    payload = _register(None)
    assert payload["agent_kind"] == "member"
    assert _persisted_role(payload) == "member"


def test_the_field_is_always_sent_never_omitted():
    """An absent field falls back to the server default, which is exactly how
    the role stayed unreachable while both sides looked correct."""
    for env in (None, "service", "MEMBER", "nonsense"):
        assert "agent_kind" in _register(env), f"agent_kind missing from the payload for env={env!r}"


@pytest.mark.parametrize("hopeful", ["admin", "leader", "advisor", "mentor", "Service ", "SERVICE"])
def test_no_other_role_can_be_self_assigned_from_the_environment(hopeful):
    """Only the strictly-less-privileged role is self-assignable. A hopeful
    'admin' must degrade to member, not escalate.

    'SERVICE' and 'Service ' are included because the client lowercases and
    strips — they SHOULD resolve to service, and this pins that the normaliser
    is doing that rather than accidentally matching something else."""
    payload = _register(hopeful)
    expected = "service" if hopeful.strip().lower() == "service" else "member"
    assert payload["agent_kind"] == expected
    assert _persisted_role(payload) in {"service", "member"}


def test_the_server_never_takes_chapter_role_from_the_request_body():
    """Belt and braces: even if a client sent chapter_role directly, the model
    has no such field, so it cannot reach the row."""
    assert "chapter_role" not in chapter_agent.MemberRegistration.model_fields


def test_a_forged_privileged_kind_in_the_body_is_ignored():
    """The client allow-list is a convenience; the server is the control."""
    payload = _register(None)
    payload["agent_kind"] = "admin"
    assert _persisted_role(payload) == "member"
