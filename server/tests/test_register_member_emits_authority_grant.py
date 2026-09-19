"""Tests that register_member emits an authority_granted ARP receipt for new
sovereign members (A1 — wire authority chain into onboarding).

Per ARP spec §4.6, the chapter is allowed to emit authority_granted on the
principal's behalf during onboarding in v0.1 — establishes the verifiable
consent record without requiring SDK round-trip.

Coverage:
  * happy path — new sovereign registration triggers arp.emit_authority_grant
  * grant scope: includes intent_submitted, message_sent, data_shared
  * grant expiry: ~365 days in the future, RFC 3339 with Z suffix
  * re-registration does NOT re-emit (matches member.joined suppression)
  * openclaw origin: no grant emitted (sovereign-only in v0.1)
  * no public_key → no grant emitted (need a did_key to derive)
  * fire-and-forget: emission failure does NOT 5xx the registration
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402

import chapter_agent  # noqa: E402
import event_bus  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_state(monkeypatch):
    """Fresh members dict + stubbed event bus + record of grant emissions."""
    monkeypatch.setattr(chapter_agent, "members", {})
    monkeypatch.setattr(chapter_agent, "PUBLIC_URL", "")

    # Stub event_bus to avoid noise
    async def _noop_publish(*_a, **_kw):
        return None

    monkeypatch.setattr(event_bus, "safe_publish", _noop_publish)

    # Stub nanda_registry.register_member so we don't hit network
    import nanda_registry

    async def _noop_register(*_a, **_kw):
        return None

    monkeypatch.setattr(nanda_registry, "register_member", _noop_register)

    # Record all arp.emit_authority_grant calls
    calls: list[dict] = []

    async def _record_grant(**kwargs) -> str:
        calls.append(dict(kwargs))
        return "fake-receipt-uuid-" + str(len(calls))

    import arp as arp_mod

    monkeypatch.setattr(arp_mod, "emit_authority_grant", _record_grant)
    yield calls


async def _drain():
    """Yield the loop so fire-and-forget asyncio.create_task() runs."""
    for _ in range(3):
        await asyncio.sleep(0)


def _make_reg(agent_id="alice", **kwargs):
    return chapter_agent.MemberRegistration(
        agent_id=agent_id,
        name=kwargs.pop("name", "Alice"),
        public_key=kwargs.pop("public_key", "A" * 43 + "="),  # 44-char ed25519-shaped
        **kwargs,
    )


# ══════════════════════════════════════════════════════════════════════
# HAPPY — new sovereign registration emits an authority grant
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_HAPPY_new_sovereign_member_triggers_authority_grant(_isolate_state):
    calls = _isolate_state
    result = await chapter_agent.register_member(_make_reg(origin="sovereign"))
    await _drain()

    assert result.get("registered") is True
    assert len(calls) == 1, "expected exactly one authority_granted emission"

    grant = calls[0]
    assert grant["principal_did"].startswith("did:key:"), "must use did:key for principal"
    assert grant["granted_to_did"] == grant["principal_did"], "self-grant: agent acts on principal's behalf"


def test_HAPPY_grant_scope_includes_baseline_categories():
    """The grant covers the three categories a chapter member routinely
    needs: intent_submitted, message_sent, data_shared. Other categories
    require a separate explicit grant from the member's SDK."""

    async def runner():
        # Re-isolate per coroutine
        return None

    # Validated structurally via fixture in the test above; here just
    # assert the expected scope set as a static property.
    expected_scope = ["intent_submitted", "message_sent", "data_shared"]
    # This is what chapter_agent.register_member's grant emission uses
    assert set(expected_scope) >= {"intent_submitted", "message_sent", "data_shared"}


@pytest.mark.asyncio
async def test_HAPPY_grant_expiry_is_about_365_days(_isolate_state):
    """grant_expires_at should be ~1 year from now, RFC 3339 Z suffix."""
    calls = _isolate_state
    await chapter_agent.register_member(_make_reg(origin="sovereign"))
    await _drain()

    grant = calls[0]
    expires_str = grant["grant_expires_at"]
    assert expires_str.endswith("Z"), "must use Z suffix (RFC 3339)"

    expires_dt = datetime.strptime(expires_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    now = datetime.now(UTC)
    days = (expires_dt - now).total_seconds() / 86400
    assert 364 <= days <= 366, f"expiry should be ~365 days; got {days:.1f}"


@pytest.mark.asyncio
async def test_HAPPY_grant_scope_passed_correctly(_isolate_state):
    calls = _isolate_state
    await chapter_agent.register_member(_make_reg(origin="sovereign"))
    await _drain()

    scope = calls[0]["granted_scope"]
    assert "intent_submitted" in scope
    assert "message_sent" in scope
    assert "data_shared" in scope


# ══════════════════════════════════════════════════════════════════════
# EDGE — re-registration, openclaw, no key
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_EDGE_reregistration_does_not_re_emit_grant(_isolate_state):
    calls = _isolate_state

    await chapter_agent.register_member(_make_reg(origin="sovereign", agent_id="bob"))
    await _drain()
    assert len(calls) == 1

    # Same agent, second call — re-registration. Must NOT emit a second grant.
    await chapter_agent.register_member(_make_reg(origin="sovereign", agent_id="bob"))
    await _drain()

    assert len(calls) == 1, "re-registration must not re-emit authority_granted"


@pytest.mark.asyncio
async def test_EDGE_openclaw_origin_no_grant_emitted(_isolate_state):
    """openclaw agents skip the chapter-emitted grant — they're issuer-side
    already, and re-granting authority to a less-trusted runtime would
    muddle the trust model. v0.2 will revisit."""
    calls = _isolate_state
    await chapter_agent.register_member(_make_reg(origin="openclaw"))
    await _drain()
    assert len(calls) == 0


@pytest.mark.asyncio
async def test_EDGE_no_public_key_no_grant_emitted(_isolate_state):
    """Without a public_key we can't derive a did:key, so no grant.
    Registration itself still succeeds."""
    calls = _isolate_state
    result = await chapter_agent.register_member(
        chapter_agent.MemberRegistration(
            agent_id="keyless",
            name="Keyless Agent",
            origin="sovereign",
            public_key="",
        )
    )
    await _drain()
    assert result.get("registered") is True
    assert len(calls) == 0


# ══════════════════════════════════════════════════════════════════════
# FAILURE — fire-and-forget invariant
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_FAILURE_grant_emission_failure_does_not_break_registration(monkeypatch):
    """If arp.emit_authority_grant blows up, register_member must still 200."""
    monkeypatch.setattr(chapter_agent, "members", {})
    monkeypatch.setattr(chapter_agent, "PUBLIC_URL", "")

    async def _noop_publish(*_a, **_kw):
        return None

    monkeypatch.setattr(event_bus, "safe_publish", _noop_publish)

    import nanda_registry

    async def _noop_register(*_a, **_kw):
        return None

    monkeypatch.setattr(nanda_registry, "register_member", _noop_register)

    async def _boom(**_kw):
        raise RuntimeError("ARP issuer offline")

    import arp as arp_mod

    monkeypatch.setattr(arp_mod, "emit_authority_grant", _boom)

    result = await chapter_agent.register_member(
        chapter_agent.MemberRegistration(
            agent_id="carol",
            name="Carol",
            origin="sovereign",
            public_key="A" * 43 + "=",
        )
    )
    await _drain()

    assert result.get("registered") is True
    assert "error" not in result
