"""The credential an operator types during onboarding: where it goes, and where
it must never appear.

Onboarding is the one place a human hands this service a provider API key. Two
properties matter about what happens next, and neither was asserted:

* it must not come back out of any surface this service serves, and
* it must not sit in the clear in a database that seals every other secret.

The second was false. The value was written as ``{"value": "<key>"}`` into the
same table that holds the chapter's signing key and members' provider keys —
both of which are sealed under ``secret_sealing`` because a dump or a backup is
enough to read a plaintext row.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import chapter_agent
import onboarding
import secret_sealing
import settings as settings_mod

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_settings_onboarding import _FakePostgres  # noqa: E402  (needs the tests dir above)

#: Distinctive so a sweep can prove it is looking at the right string.
CANARY = "sk-canary-must-never-surface-0000"


def _resolved_provider(pg) -> str:
    """The provider a member would actually run with, by the loader's rules.

    Mirrors ``sovereign_runtime.load_sessions`` precedence rather than calling
    it, because that function also builds live clients. The precedence itself is
    asserted against the real function in ``test_provider_precedence.py``.
    """
    import os

    import llm_config

    explicit = os.environ.get("LLM_PROVIDER", "").strip().lower()
    if explicit:
        return explicit
    rows = pg.tables.get("agent_api_keys", [])
    if rows and rows[0].get("provider"):
        return str(rows[0]["provider"])
    agent = pg.tables["agents"][0]
    return str(agent.get("llm_provider") or llm_config.PROVIDER)


@pytest.fixture
def wired(monkeypatch):
    """A chapter with a key-encryption secret configured, as a running one has."""
    monkeypatch.setenv(secret_sealing.KEY_SECRET_ENV, "test-key-encryption-secret-not-a-real-one")
    pg = _FakePostgres()
    pg.tables["agents"].append({"agent_id": "alice", "onboarding_step": 1, "profile_id": "p-alice"})
    settings_mod.init(pg)
    onboarding.init(pg)
    return pg


async def _onboard(pg, *, provider: str = "openai", api_key: str = CANARY):
    """Run the wizard's LLM step through the REAL sealing write path."""
    written: list[tuple[str, str, str]] = []

    async def store_secret(agent_id: str, key_name: str, value: str) -> None:
        # ⚠️ THE REAL WRITE PATH, not a copy of it. An earlier draft of this file
        # sealed the value here, in the test's own helper — so restoring the
        # plaintext write in the product changed nothing and every assertion
        # below still passed. The guard was aimed one layer off the claim.
        written.append((agent_id, key_name, value))
        await chapter_agent.store_onboarding_secret(pg, agent_id, key_name, value)

    await onboarding.advance(
        "alice",
        step=1,
        values={"provider": provider, "api_key": api_key},
        store_secret=store_secret,
        settings_module=settings_mod,
    )
    return written


# ── the secret does not sit in the clear ─────────────────────────────────────


@pytest.mark.asyncio
async def test_the_stored_credential_is_sealed_at_rest(wired):
    """The property that was false. Same database, same mechanism, same reason
    as the chapter signing key beside it."""
    await _onboard(wired)
    row = wired.tables["agent_private_memory"][0]
    stored = row["memory_value"]["value"]
    assert secret_sealing.is_sealed(stored), f"the credential is at rest in the clear: {stored[:24]!r}"
    assert CANARY not in stored, "the plaintext key survives inside the stored value"


@pytest.mark.asyncio
async def test_the_sealed_value_is_the_key_and_not_something_that_merely_looks_sealed(wired):
    """A guard that only checks the prefix would pass on a constant. Unsealing
    has to give the key back, or the row is sealed and useless."""
    await _onboard(wired)
    stored = wired.tables["agent_private_memory"][0]["memory_value"]["value"]
    assert secret_sealing.unseal(stored) == CANARY


@pytest.mark.asyncio
async def test_two_operators_secrets_do_not_seal_to_the_same_bytes(wired):
    """Identical plaintext under one secret must not produce one ciphertext —
    that would leak that two operators configured the same provider key."""
    await _onboard(wired)
    # Rewind through the SUPPORTED path. Winding the integer back on its own no
    # longer re-opens the wizard: `get_step` reads completion from the recorded
    # timestamp, not from the ordinal, so a member who finished stays finished
    # however the column is edited. That is the property that stops an operator
    # mid-wizard being renumbered into "done" — see onboarding.get_step.
    await onboarding.reset("alice")
    wired.tables["agent_settings"][0]["onboarding_completed_at"] = None
    wired.tables["agents"][0]["onboarding_step"] = 1
    await _onboard(wired)
    stored = [r["memory_value"]["value"] for r in wired.tables["agent_private_memory"]]
    assert len(stored) == 2
    assert stored[0] != stored[1], "the same key sealed twice produced identical bytes"


# ── the secret never comes back out ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_credential_reaches_no_response_this_service_produces(wired):
    """It does not today, and nothing said so. The sweep is validated first:
    a detector that cannot find the canary anywhere would report every surface
    clean while checking nothing."""
    await _onboard(wired)

    at_rest = json.dumps(wired.tables["agent_private_memory"], default=str)
    assert secret_sealing.is_sealed(wired.tables["agent_private_memory"][0]["memory_value"]["value"]), (
        "precondition: the row must be sealed"
    )

    surfaces = {
        "get_settings": await settings_mod.get_settings("alice"),
        "get_setting(llm.provider)": await settings_mod.get_setting("alice", "llm.provider"),
        "update_settings": await settings_mod.update_settings("alice", {"llm": {"provider": "groq"}}),
        "reset_settings": await settings_mod.reset_settings("alice"),
    }
    for name, body in surfaces.items():
        text = json.dumps(body, default=str)
        assert CANARY not in text, f"{name} returned the operator's API key"
        assert at_rest not in text, f"{name} returned the raw at-rest row"


@pytest.mark.asyncio
async def test_the_sweep_can_actually_find_the_canary(wired):
    """The positive control for the test above. If this ever fails, that one is
    asserting nothing."""
    await _onboard(wired)
    haystack = json.dumps(
        [{"leaked": secret_sealing.unseal(wired.tables["agent_private_memory"][0]["memory_value"]["value"])}]
    )
    assert CANARY in haystack


# ── what the operator chose is still not what runs ───────────────────────────


@pytest.mark.asyncio
async def test_the_chosen_provider_is_what_executes(wired, monkeypatch):
    """INVERTED, and deliberately not deleted.

    This used to assert the defect: onboarding recorded the operator's provider
    into ``agent_settings`` while the path that runs a member read
    ``agent_api_keys`` and ``agents.llm_provider``, so the choice was stored,
    displayed nowhere as authoritative, and executed by nothing.

    Onboarding now writes both stores the runtime actually reads. The assertion
    is the same fact turned the right way up: what the operator chose is what a
    member would run with.
    """
    import llm_config

    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.setattr(llm_config, "PROVIDER", "anthropic")
    monkeypatch.setattr(llm_config, "DEFAULT_MODEL", "claude-sonnet-4-6")
    await _onboard(wired, provider="openai")

    # Recorded where the runtime reads it, not only in the settings document.
    assert wired.tables["agents"][0]["llm_provider"] == "openai"
    key_rows = wired.tables.get("agent_api_keys", [])
    assert [r["provider"] for r in key_rows] == ["openai"]

    # And it is what resolution yields for that member.
    assert _resolved_provider(wired) == "openai"
    assert _resolved_provider(wired) != llm_config.PROVIDER, (
        "the choice only matches because it equals the environment default — this test would pass without the wiring"
    )


# ── a stored choice cannot claim to be what runs ─────────────────────────────


@pytest.mark.asyncio
async def test_a_stored_provider_cannot_override_what_the_surface_reports(wired, monkeypatch):
    """⚠️ THE HALF THE EARLIER FIX LEFT OPEN.

    Making the resolved pair the DEFAULT fixed the common case — an operator
    with nothing stored. It did not fix this one: onboarding stores a provider,
    the stored value won the merge, and the surface went back to reporting a
    choice the runtime does not consult. The fix is only complete if a stored
    value cannot outrank the observation.
    """
    import llm_config

    monkeypatch.setattr(llm_config, "PROVIDER", "anthropic")
    monkeypatch.setattr(llm_config, "DEFAULT_MODEL", "claude-sonnet-4-6")
    await _onboard(wired, provider="openai")

    effective = await settings_mod.get_settings("alice")
    assert effective["llm"] == {"provider": "anthropic", "model": "claude-sonnet-4-6"}


@pytest.mark.asyncio
async def test_a_direct_patch_cannot_override_it_either(wired, monkeypatch):
    """The write path returns an effective view too, and it must agree with the
    read path — otherwise the value is honest until someone changes it."""
    import llm_config

    monkeypatch.setattr(llm_config, "PROVIDER", "anthropic")
    monkeypatch.setattr(llm_config, "DEFAULT_MODEL", "claude-sonnet-4-6")
    result = await settings_mod.update_settings("alice", {"llm": {"provider": "groq", "model": "made-up"}})
    assert result["llm"] == {"provider": "anthropic", "model": "claude-sonnet-4-6"}


@pytest.mark.asyncio
async def test_every_other_section_still_takes_the_operators_preference(wired):
    """The narrowness matters. Only ``llm`` is an observation; pinning the whole
    document would make the settings surface read-only, which is not the fix."""
    result = await settings_mod.update_settings("alice", {"voice": {"wake_word": True}})
    assert result["voice"]["wake_word"] is True


@pytest.mark.asyncio
async def test_the_choice_is_still_recorded_even_though_it_is_not_reported(wired):
    """Not-authoritative is not the same as discarded. Whatever eventually
    consumes the operator's choice needs it to still be there."""
    await _onboard(wired, provider="openai")
    assert wired.tables["agent_settings"][0]["settings"]["llm"]["provider"] == "openai"
