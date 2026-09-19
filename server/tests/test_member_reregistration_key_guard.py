"""P0 — account-takeover guard on /api/members re-registration.

`/api/members` is open-pathed (the registration handler does its own TOFU),
so the auth middleware does NOT run for it. That means re-registration is the
ONE place a caller can change a stored agent's identity. Before this guard,
register_member called `replace_agent_key` unconditionally whenever a 44-char
key was supplied — so an unauthenticated POST with someone else's agent_id and
the attacker's own pubkey hard-overwrote the victim's Ed25519 key, and the
attacker could then sign as the victim everywhere. Full account takeover.

Contract locked here:
  * changing the key of an EXISTING agent via plain re-registration is
    rejected (403) — a key change is a ROTATION, which must be self-signed by
    the old key via POST /api/members/rotate;
  * same-key re-registration (idempotent profile update) is allowed;
  * re-registration that omits a key (profile-only update) is allowed and
    keeps the stored key;
  * first registration of a brand-new agent is unaffected.

**AND THE GUARD MUST SURVIVE A RESTART.** Every test above registers the victim
in the SAME process that then attacks them, so `members["victim"]["public_key"]`
is always populated and the guard always has something to compare against. On a
real org it does not: `members[]` is rebuilt on every boot by
`load_persisted_members`, which did not carry `public_key` — so `existing_key`
was `""`, the guard's `if existing_key and ...` never fired, and the takeover
this file exists to refuse was open again after every redeploy. This suite was
green throughout. The two restart-shaped cases at the bottom close that: they
rebuild the victim through the REAL loader from a REAL-shaped Postgres row
before attacking, which is the only in-process approximation of a boot. The
over-the-wire proof against an actual two-process restart is
`scripts/restart_durability_probe.py`.

Classification: ADVERSARIAL (attacker re-registers a victim with their key).
"""

from __future__ import annotations

import base64
import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402

import auth_verify  # noqa: E402
import chapter_agent  # noqa: E402
import sovereign_identity  # noqa: E402

_K1 = base64.b64encode(b"\x01" * 32).decode()  # victim's key
_K2 = base64.b64encode(b"\x02" * 32).decode()  # attacker's key


def _status(resp) -> int:
    return getattr(resp, "status_code", 200)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(chapter_agent, "members", {})
    monkeypatch.setattr(chapter_agent, "PUBLIC_URL", "")
    auth_verify._agent_keys.clear()
    yield
    auth_verify._agent_keys.clear()


@pytest.mark.asyncio
async def test_reregistration_with_different_key_is_rejected():
    """The takeover vector: re-register an existing agent with a DIFFERENT
    key and no rotation proof → 403, and the stored key is unchanged."""
    await chapter_agent.register_member(
        chapter_agent.MemberRegistration(agent_id="victim", name="Victim", public_key=_K1)
    )
    assert auth_verify._agent_keys["victim"]["ed25519_pubkey"] == _K1

    resp = await chapter_agent.register_member(
        chapter_agent.MemberRegistration(agent_id="victim", name="Victim", public_key=_K2)
    )

    assert _status(resp) == 403
    # The victim's stored key MUST be untouched — no takeover.
    assert auth_verify._agent_keys["victim"]["ed25519_pubkey"] == _K1
    assert chapter_agent.members["victim"]["public_key"] == _K1


@pytest.mark.asyncio
async def test_reregistration_with_same_key_is_allowed():
    """Idempotent profile update (same key) still works — 200, key intact."""
    await chapter_agent.register_member(
        chapter_agent.MemberRegistration(agent_id="victim", name="Victim", public_key=_K1)
    )
    resp = await chapter_agent.register_member(
        chapter_agent.MemberRegistration(
            agent_id="victim", name="Victim Renamed", public_key=_K1
        )
    )
    assert _status(resp) == 200
    assert auth_verify._agent_keys["victim"]["ed25519_pubkey"] == _K1
    assert chapter_agent.members["victim"]["name"] == "Victim Renamed"


@pytest.mark.asyncio
async def test_reregistration_without_key_keeps_stored_key():
    """A profile-only update that omits the key is allowed and preserves the
    stored key (not a key change)."""
    await chapter_agent.register_member(
        chapter_agent.MemberRegistration(agent_id="victim", name="Victim", public_key=_K1)
    )
    resp = await chapter_agent.register_member(
        chapter_agent.MemberRegistration(agent_id="victim", name="Victim Again")
    )
    assert _status(resp) == 200
    assert auth_verify._agent_keys["victim"]["ed25519_pubkey"] == _K1
    assert chapter_agent.members["victim"]["public_key"] == _K1


@pytest.mark.asyncio
async def test_first_registration_is_unaffected():
    """A brand-new agent registers normally — the guard only protects an
    already-stored key."""
    resp = await chapter_agent.register_member(
        chapter_agent.MemberRegistration(agent_id="newbie", name="Newbie", public_key=_K1)
    )
    assert _status(resp) == 200
    assert auth_verify._agent_keys["newbie"]["ed25519_pubkey"] == _K1


# ══════════════════════════════════════════════════════════════════════
# The guard across a restart — the case the four above cannot reach
# ══════════════════════════════════════════════════════════════════════

_DID_K1 = sovereign_identity.build_did_key_from_ed25519(_K1)


def _persisted_victim_row() -> dict:
    """The victim's row as `_persist_member_to_db` actually writes it: the key
    lives in `agent_facts.provider.did`, the origin in its own column."""
    return {
        "agent_id": "victim",
        "name": "Victim",
        "description": "",
        "skills": [],
        "profile_type": "member",
        "origin": "sovereign",
        "agent_facts": {"provider": {"did": _DID_K1}},
        "config": {"parent_chapter": chapter_agent.AGENT_ID, "virtual": False, "endpoint": ""},
    }


async def _reboot_from_postgres(monkeypatch) -> None:
    """Rebuild `members[]` the way a boot does — nothing in memory, everything
    from the row. Asserts the victim actually came back, because a loader that
    dropped the row would leave the attack below asserting nothing."""
    monkeypatch.setattr(chapter_agent, "members", {})
    auth_verify._agent_keys.clear()

    async def _pg(method, table, params=None, body=None):
        return [_persisted_victim_row()] if method == "GET" else None

    monkeypatch.setattr(chapter_agent, "pg_request", _pg)
    await chapter_agent.load_persisted_members()
    assert "victim" in chapter_agent.members, "loader dropped the victim — the attack below proves nothing"


@pytest.mark.asyncio
async def test_key_change_guard_survives_a_reboot(monkeypatch):
    """THE REGRESSION. Rebuild the victim from Postgres exactly as a boot does,
    then run the takeover. Before `public_key` was hydrated this returned 200
    and swapped the key; measured over a real two-process restart, the
    attacker's key then signed as the victim and the legitimate key got
    `key_mismatch`."""
    await _reboot_from_postgres(monkeypatch)

    resp = await chapter_agent.register_member(
        chapter_agent.MemberRegistration(agent_id="victim", name="Victim", public_key=_K2)
    )

    assert _status(resp) == 403
    assert chapter_agent.members["victim"]["public_key"] == _K1


@pytest.mark.asyncio
async def test_reboot_does_not_lock_the_legitimate_member_out(monkeypatch):
    """The other half, and the one a too-eager fix would break: the REAL owner
    re-registering with their own key still gets 200. A guard that refused
    everything after a reboot would pass the test above and be worse than the
    bug."""
    await _reboot_from_postgres(monkeypatch)

    resp = await chapter_agent.register_member(
        chapter_agent.MemberRegistration(agent_id="victim", name="Victim Renamed", public_key=_K1)
    )

    assert _status(resp) == 200
    assert chapter_agent.members["victim"]["name"] == "Victim Renamed"


@pytest.mark.asyncio
async def test_origin_immutability_survives_a_reboot(monkeypatch):
    """Same class, same loader: the origin guard reads `existing["origin"]`, so
    without hydration an unauthenticated POST could flip a member's trust origin
    after every redeploy."""
    await _reboot_from_postgres(monkeypatch)

    resp = await chapter_agent.register_member(
        chapter_agent.MemberRegistration(agent_id="victim", name="Victim", origin="openclaw", public_key=_K1)
    )

    assert _status(resp) == 200
    assert resp.get("error", "").startswith("origin mismatch"), resp
    assert chapter_agent.members["victim"]["origin"] == "sovereign"
