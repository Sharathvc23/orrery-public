"""Tests that register_member emits member.joined on the event bus (EB-2).

The whole point of EB-2 is the chapter starting to publish observable
state changes. member.joined is the proof case. If this test breaks,
subscribers (OpenClaw, podcast-as-agent, mentor-matcher, etc.) won't
see new members and the launch demo loses its keystone signal.

Coverage:
  * happy path — new registration emits exactly one member.joined
  * payload contents — agent_id, name, skills, origin, did_key all map
    correctly from the registration request
  * re-registration does NOT emit (existing branch — only first join)
  * did_key derivation: present when public_key set, empty when not
  * emission is fire-and-forget — a Postgres failure must NOT 5xx the
    registration response
"""

from __future__ import annotations

import asyncio
import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402

import chapter_agent  # noqa: E402
import event_bus  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_state(monkeypatch):
    """Fresh members dict + recording event bus per test."""
    monkeypatch.setattr(chapter_agent, "members", {})
    monkeypatch.setattr(chapter_agent, "PUBLIC_URL", "")

    calls: list[tuple[str, dict, dict]] = []

    async def _record(event_type, payload, *, publisher_agent_id=None, trace=None):
        calls.append(
            (
                event_type,
                dict(payload) if isinstance(payload, dict) else payload.model_dump(),
                {"publisher_agent_id": publisher_agent_id, "trace": trace},
            )
        )

    monkeypatch.setattr(event_bus, "safe_publish", _record)
    yield calls


async def _drain():
    """Yield the loop so fire-and-forget asyncio.create_task() runs."""
    # Two yields cover the case where the scheduled coro itself awaits.
    await asyncio.sleep(0)
    await asyncio.sleep(0)


def _make_reg(agent_id="alice", **kwargs):
    return chapter_agent.MemberRegistration(
        agent_id=agent_id,
        name=kwargs.pop("name", "Alice"),
        **kwargs,
    )


# ── Happy path ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_new_registration_emits_member_joined(_isolate_state):
    calls = _isolate_state
    result = await chapter_agent.register_member(_make_reg(skills=["python", "rust"]))
    await _drain()

    assert result.get("registered") is True
    assert len(calls) == 1
    event_type, payload, _ = calls[0]
    assert event_type == "member.joined"
    assert payload["agent_id"] == "alice"
    assert payload["name"] == "Alice"
    assert payload["skills"] == ["python", "rust"]
    assert payload["origin"] == "sovereign"
    assert payload["did_key"] == ""  # no public_key supplied


@pytest.mark.asyncio
async def test_did_key_derived_when_public_key_present(_isolate_state):
    """When the member supplies an Ed25519 pubkey, did_key must be derived."""
    import base64

    # 32 bytes → valid Ed25519 pubkey shape
    pubkey_b64 = base64.b64encode(b"\x01" * 32).decode()

    calls = _isolate_state
    await chapter_agent.register_member(_make_reg(public_key=pubkey_b64))
    await _drain()

    assert len(calls) == 1
    payload = calls[0][1]
    assert payload["did_key"].startswith("did:key:z")  # W3C did:key shape


@pytest.mark.asyncio
async def test_openclaw_origin_emits_with_origin_field(_isolate_state):
    calls = _isolate_state
    await chapter_agent.register_member(_make_reg(origin="openclaw"))
    await _drain()

    assert len(calls) == 1
    assert calls[0][1]["origin"] == "openclaw"


# ── Re-registration suppression ──────────────────────────────────────


@pytest.mark.asyncio
async def test_reregistration_does_not_re_emit_member_joined(_isolate_state):
    calls = _isolate_state

    await chapter_agent.register_member(_make_reg(agent_id="bob"))
    await _drain()
    assert len(calls) == 1

    # Same agent, second call — must NOT emit a second member.joined.
    # Re-registration is usually a key-rotation / metadata-update path,
    # not a new join.
    await chapter_agent.register_member(_make_reg(agent_id="bob", name="Bob v2"))
    await _drain()

    assert len(calls) == 1, "re-registration must not re-emit member.joined"


# ── Fire-and-forget invariant (CLAUDE.md outcome rule) ───────────────


@pytest.mark.asyncio
async def test_event_bus_failure_does_not_break_registration(monkeypatch):
    """If the event bus blows up, register_member must still 200."""
    monkeypatch.setattr(chapter_agent, "members", {})
    monkeypatch.setattr(chapter_agent, "PUBLIC_URL", "")

    async def _boom(*args, **kwargs):
        raise RuntimeError("supabase exploded")

    monkeypatch.setattr(event_bus, "safe_publish", _boom)

    # Wrap in create_task path used by chapter_agent — the response should
    # still be the success shape, even though the background task raises.
    result = await chapter_agent.register_member(_make_reg(agent_id="carol"))
    await _drain()

    assert result.get("registered") is True
    assert "error" not in result
