"""Which provider runs a member, and whose credential goes with it.

Driven against ``sovereign_runtime.load_sessions`` itself, not a re-statement of
its rules — a test that mirrors the precedence would agree with a wrong
implementation as readily as a right one.

⚠️ THE PROVIDER AND THE KEY TRAVEL TOGETHER. The failure this guards is not
"the wrong provider ran". It is a credential for one provider arriving in a
request addressed to another, which is the defect the shared registry exists to
make unrepresentable and which a precedence rule applied to the name alone would
reintroduce.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import api_key_store
import secret_sealing
import sovereign_runtime

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_settings_onboarding import _FakePostgres  # noqa: E402  (needs the tests dir above)

MEMBER_KEY = "sk-member-byok-key"


@pytest.fixture
def wired(monkeypatch):
    monkeypatch.setenv(secret_sealing.KEY_SECRET_ENV, "test-key-encryption-secret-not-a-real-one")
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    for var in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "XAI_API_KEY", "GROQ_API_KEY"):
        monkeypatch.setenv(var, f"env-key-for-{var.split('_')[0].lower()}")
    pg = _FakePostgres()
    pg.tables["agents"] = [
        {"agent_id": "m1", "profile_id": "p1", "llm_provider": "groq", "llm_model": "x", "status": "active"}
    ]
    pg.tables["agent_api_keys"] = []
    monkeypatch.setattr(sovereign_runtime, "_pg", lambda: pg)
    # Cleared on the way IN and on the way OUT. ``sessions`` is a module-level
    # registry, so a session built here would otherwise be visible to every
    # later test in the run — which is how this file made an unrelated
    # read-surface test fail while passing on its own.
    sovereign_runtime.sessions.clear()
    yield pg
    sovereign_runtime.sessions.clear()


async def _seed_key(pg, provider: str, key: str = MEMBER_KEY):
    await api_key_store.save_api_key(pg, profile_id="p1", provider=provider, api_key=key)


async def _load(pg) -> sovereign_runtime.SovereignSession | None:
    await sovereign_runtime.load_sessions({"m1": {"name": "M", "skills": []}})
    return sovereign_runtime.sessions.get("m1")


def _key_on(session) -> str:
    """The credential the built client will actually send."""
    return str(getattr(session.llm, "api_key", ""))


def _offered_providers() -> set[str]:
    """The wizard's provider option list, found by the field's KEY.

    Indexed by position (``STEP_SPEC[2]["fields"][0]``) until removing an
    earlier step renumbered the wizard and this raised IndexError. The step a
    question lives on is presentation; the question is identified by its key.
    """
    import onboarding as onb

    for spec in onb.STEP_SPEC.values():
        for field in spec["fields"]:
            if field["key"] == "provider":
                return {onb.normalise_provider_choice(o["value"]) for o in field["options"]}
    raise AssertionError("the wizard no longer asks for a provider — this guard went blind")


# ── the member's own key runs the member's own provider ──────────────────────


@pytest.mark.asyncio
async def test_a_stored_key_runs_its_own_provider_with_its_own_credential(wired):
    """DETECTOR VALIDATION and the ordinary case in one: a session must be built
    at all, or every assertion below passes vacuously."""
    await _seed_key(wired, "openai")
    session = await _load(wired)
    assert session is not None, "no session was built — the rest of this file would prove nothing"
    assert session.provider == "openai"
    assert _key_on(session) == MEMBER_KEY


@pytest.mark.asyncio
async def test_the_agents_recorded_provider_runs_when_there_is_no_key_row(wired):
    """A local endpoint needs no credential, so the choice recorded on the agent
    is enough to run it. Before this, that column was selected and ignored."""
    wired.tables["agents"][0]["llm_provider"] = "ollama"
    await _seed_key(wired, "openai")
    wired.tables["agent_api_keys"].clear()
    session = await _load(wired)
    assert session is not None
    assert session.provider == "ollama"


# ── an explicit environment variable outranks the persisted choice ───────────


@pytest.mark.asyncio
async def test_an_explicit_env_provider_outranks_a_stored_one(wired, monkeypatch):
    """An operator who sets the variable deliberately is not overridden by an
    onboarding choice made months earlier."""
    await _seed_key(wired, "openai")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    session = await _load(wired)
    assert session is not None
    assert session.provider == "anthropic"


@pytest.mark.asyncio
async def test_the_env_override_does_not_carry_the_stored_key_to_another_provider(wired, monkeypatch):
    """⚠️ THE ONE THAT MATTERS. Overriding the NAME while keeping the stored
    credential would address a request to Anthropic carrying an OpenAI key —
    exactly the shape that put a live third-party key in the wrong
    Authorization header."""
    await _seed_key(wired, "openai")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    session = await _load(wired)
    assert session is not None
    assert _key_on(session) != MEMBER_KEY, "the member's OpenAI key was sent to Anthropic"
    assert _key_on(session) == "env-key-for-anthropic"


@pytest.mark.asyncio
async def test_the_auto_detected_default_does_not_outrank_a_members_key(wired, monkeypatch):
    """``llm_config.PROVIDER`` is never empty because it auto-detects. Treating
    that as an operator decision would make it outrank every member's real key,
    which is bring-your-own-key stopping working with no one changing anything."""
    import llm_config

    monkeypatch.setattr(llm_config, "PROVIDER", "anthropic")
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    await _seed_key(wired, "openai")
    session = await _load(wired)
    assert session is not None
    assert session.provider == "openai"
    assert _key_on(session) == MEMBER_KEY


# ── the credential does not surface ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_reading_the_key_for_execution_does_not_print_it(wired, capsys):
    """It has to be unsealed to be used. Unsealing it into a log is how a sealed
    secret becomes a plaintext one somewhere else."""
    await _seed_key(wired, "openai")
    capsys.readouterr()
    session = await _load(wired)
    assert session is not None and _key_on(session) == MEMBER_KEY
    out = capsys.readouterr()
    assert MEMBER_KEY not in out.out + out.err, "the member's key was printed while being loaded"


@pytest.mark.asyncio
async def test_a_key_that_cannot_be_unsealed_drops_that_member_only(wired, capsys):
    """One unreadable row must not stop every other member's runtime, and the
    log line must name the member rather than the value.

    ⚠️ WHICH GUARD THIS ACTUALLY EXERCISES. The fixture records a REMOTE
    provider, so the member is refused by the keyless check further down, not
    by the ``unreadable`` skip — removing that skip leaves this test passing.
    The unreadable path itself is held by
    ``test_an_unreadable_key_does_not_fall_through_to_a_local_provider``.
    """
    await _seed_key(wired, "openai")
    wired.tables["agent_api_keys"][0]["api_key_encrypted"] = secret_sealing.ENC_PREFIX + "not-decryptable"
    capsys.readouterr()
    session = await _load(wired)
    out = capsys.readouterr()
    assert session is None
    assert MEMBER_KEY not in out.out + out.err


@pytest.mark.asyncio
async def test_an_unreadable_key_does_not_fall_through_to_a_local_provider(wired):
    """⚠️ A MEMBER WHOSE OWN KEY CANNOT BE READ MUST NOT RUN ON SOMEONE ELSE'S.

    The member stored a key for a remote provider and their agent row records a
    LOCAL one. If the unreadable row is merely skipped rather than
    disqualifying, the member falls past the stored-key branch into the local
    branch and starts — on an endpoint they never chose, with the operator's
    resources, because their own credential broke. The keyless check below
    cannot catch it: a local provider bills nobody and is allowed to start
    without a key, which is exactly why the skip has to come first.

    Distinct from ``test_a_key_that_cannot_be_unsealed_drops_that_member_only``,
    where the recorded provider is remote and that later check does the work.
    """
    await _seed_key(wired, "openai")
    wired.tables["agent_api_keys"][0]["api_key_encrypted"] = secret_sealing.ENC_PREFIX + "not-decryptable"
    wired.tables["agents"][0]["llm_provider"] = "ollama"

    session = await _load(wired)

    assert session is None, (
        "a member whose own key could not be unsealed started anyway, on "
        f"{getattr(session, 'provider', None)!r} — the unreadable row fell through "
        "to the local-provider branch"
    )


# ── the three vocabularies agree ─────────────────────────────────────────────


def test_every_provider_onboarding_offers_is_one_the_resolver_knows():
    """Onboarding's option list, the resolver registry and the table's CHECK
    constraint were three different answers to one question — the list offered
    ``ollama_local``, which neither of the other two accepts, so choosing it
    stored a provider nothing could run."""
    import llm_runtime

    offered = _offered_providers()
    unknown = sorted(offered - set(llm_runtime.PROVIDERS))
    assert not unknown, f"onboarding offers provider(s) the resolver cannot resolve: {unknown}"


def test_a_remote_provider_onboarding_offers_can_be_stored_for_execution():
    """A provider the key table rejects cannot carry a credential, so choosing
    it would silently produce a member that never runs."""
    import llm_runtime

    offered = _offered_providers()
    remote = {p for p in offered if p in llm_runtime.PROVIDERS and p not in llm_runtime.LOCAL_PROVIDERS}
    unstorable = sorted(p for p in remote if not api_key_store.writable(p))
    assert not unstorable, f"onboarding offers remote provider(s) whose key cannot be stored: {unstorable}"


@pytest.mark.asyncio
async def test_a_remote_provider_recorded_without_a_key_does_not_start_the_member(wired):
    """⚠️ THE DEPLOYED-ORG GUARD. ``agents.llm_provider`` has a column default
    of a REMOTE provider, so a member who never chose anything looks by value
    exactly like one who did. Starting on that would put members who have never
    run onto the org's own credential — a spend increase nobody asked for,
    across every deployed org at once. Only a local endpoint, which costs
    nothing and needs no key, starts without one."""
    wired.tables["agents"][0]["llm_provider"] = "xai"  # the column default
    wired.tables["agent_api_keys"].clear()
    assert await _load(wired) is None


@pytest.mark.asyncio
async def test_a_local_provider_recorded_without_a_key_does_start(wired):
    """The other half — the guard above must not simply refuse everything."""
    wired.tables["agents"][0]["llm_provider"] = "ollama"
    wired.tables["agent_api_keys"].clear()
    session = await _load(wired)
    assert session is not None and session.provider == "ollama"


# ── the writer refuses rather than sending a doomed INSERT ───────────────────


@pytest.mark.asyncio
async def test_a_provider_the_table_rejects_is_refused_before_the_write(wired, capsys):
    """The CHECK constraint accepts five names; the registry knows seven.
    Sending an INSERT the database will reject surfaces as a generic write
    error and reads like an outage rather than a vocabulary mismatch — so the
    refusal happens here, and says which names are allowed."""
    capsys.readouterr()
    saved = await api_key_store.save_api_key(wired, profile_id="p1", provider="ollama", api_key=MEMBER_KEY)
    out = capsys.readouterr().out
    assert saved is False
    assert wired.tables["agent_api_keys"] == [], "a row was written for a provider the table rejects"
    assert "ollama" in out and "NOT saved" in out
    assert MEMBER_KEY not in out, "the refusal logged the credential"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs",
    [
        {"profile_id": "", "provider": "openai", "api_key": MEMBER_KEY},
        {"profile_id": "p1", "provider": "", "api_key": MEMBER_KEY},
        {"profile_id": "p1", "provider": "openai", "api_key": ""},
    ],
    ids=["no-profile", "no-provider", "no-key"],
)
async def test_an_incomplete_write_stores_nothing(wired, kwargs):
    """Each of the three is a different missing half of the same fact. None of
    them may leave a partial row behind."""
    assert await api_key_store.save_api_key(wired, **kwargs) is False
    assert wired.tables["agent_api_keys"] == []


@pytest.mark.asyncio
async def test_saving_twice_updates_the_row_rather_than_adding_a_second(wired):
    """Re-running onboarding must not leave two keys for one profile and
    provider, where which one the runtime picks is arbitrary."""
    await _seed_key(wired, "openai", "first-key")
    await _seed_key(wired, "openai", "second-key")
    rows = wired.tables["agent_api_keys"]
    assert len(rows) == 1
    assert secret_sealing.unseal(rows[0]["api_key_encrypted"]) == "second-key"


# ── the first write this table has ever had, tested directly ────────────────
#
# The seal-then-write path was covered only incidentally, by tests that used it
# to set up something else. A path exercised as a side effect is one whose
# failure gets attributed to whatever was actually being asserted, so the two
# branches and the no-logging claim are driven here on their own terms.


@pytest.mark.asyncio
async def test_a_fresh_profile_and_provider_are_inserted_sealed(wired):
    """The POST branch. What lands in the column is ciphertext, and unsealing it
    returns the key — a value that is merely prefixed would satisfy the first
    assertion and be useless for the second."""
    assert wired.tables["agent_api_keys"] == []

    saved = await api_key_store.save_api_key(wired, profile_id="p1", provider="openai", api_key=MEMBER_KEY)
    assert saved is True

    rows = wired.tables["agent_api_keys"]
    assert len(rows) == 1, "a fresh profile+provider did not take the insert branch"
    stored = rows[0]["api_key_encrypted"]
    assert secret_sealing.is_sealed(stored), f"the key was written unsealed: {stored[:24]!r}"
    assert MEMBER_KEY not in stored, "the plaintext key survives inside the stored value"
    assert secret_sealing.unseal(stored) == MEMBER_KEY, "the sealed value is not the key"
    assert rows[0]["provider"] == "openai"
    assert rows[0]["profile_id"] == "p1"


@pytest.mark.asyncio
async def test_the_same_profile_and_provider_are_updated_not_duplicated(wired):
    """The PATCH branch. Two rows for one profile and provider would leave which
    key the runtime picks up to row order."""
    await api_key_store.save_api_key(wired, profile_id="p1", provider="openai", api_key="first-key")
    await api_key_store.save_api_key(wired, profile_id="p1", provider="openai", api_key="second-key")

    rows = wired.tables["agent_api_keys"]
    assert len(rows) == 1, "re-saving inserted a second row instead of updating"
    assert secret_sealing.unseal(rows[0]["api_key_encrypted"]) == "second-key"


@pytest.mark.asyncio
async def test_a_second_provider_for_one_profile_is_its_own_row(wired):
    """The update must key on the PAIR. Matching on profile alone would make a
    member's second provider overwrite their first."""
    await api_key_store.save_api_key(wired, profile_id="p1", provider="openai", api_key="openai-key")
    await api_key_store.save_api_key(wired, profile_id="p1", provider="anthropic", api_key="anthropic-key")

    by_provider = {r["provider"]: r["api_key_encrypted"] for r in wired.tables["agent_api_keys"]}
    assert set(by_provider) == {"openai", "anthropic"}
    assert secret_sealing.unseal(by_provider["openai"]) == "openai-key"


@pytest.mark.asyncio
@pytest.mark.parametrize("branch", ["insert", "update"])
async def test_neither_write_path_puts_the_credential_in_a_log_line(wired, capsys, branch):
    """The docstring says the value is never logged. That was a claim about the
    code rather than a property anything checked — and it is the claim that
    matters most, because a sealed row whose plaintext is in the log is not
    sealed in any useful sense."""
    if branch == "update":
        await api_key_store.save_api_key(wired, profile_id="p1", provider="openai", api_key="earlier-key")
    capsys.readouterr()

    await api_key_store.save_api_key(wired, profile_id="p1", provider="openai", api_key=MEMBER_KEY)

    out = capsys.readouterr()
    assert MEMBER_KEY not in out.out + out.err, f"the {branch} path logged the credential"


@pytest.mark.asyncio
async def test_the_log_check_can_actually_catch_a_leak(wired, capsys):
    """Positive control for the pair above. If printing the key does not trip
    this, those tests are asserting that nothing was printed at all."""
    capsys.readouterr()
    print(f"pretend a future edit logged {MEMBER_KEY}")
    out = capsys.readouterr()
    assert MEMBER_KEY in out.out
