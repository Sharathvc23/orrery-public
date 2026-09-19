"""What is left behind when a step fails half way.

Making the failure loud did not make the sequence whole. A step performs several
independent writes across `agents`, `agent_settings`, `agent_api_keys` and
`agent_private_memory`; `pg_store` runs each statement on its own pooled
connection, so they cannot share a transaction, and a refusal on write N leaves
1..N-1 applied.

⚠️ EVERY ASSERTION HERE IS ON THE RESULTING STATE, NOT ON THE EXCEPTION. That an
error was raised is already held by `test_onboarding_strict_writes`. The claim
this file makes is a different one — that the state a partial failure leaves is
one worth defending, and that what the operator is told about it is true.

Two properties:

* THE PARTIAL IS SAFE. The member's credential is written before the provider
  recorded on their agent row, because `load_sessions` reads a stored key row as
  its own provider-and-key PAIR. "Key landed, agent row did not" is a member who
  RUNS on the provider they chose; the reverse is a member correctly refused a
  session. Both honest, the first strictly closer to done.
* THE REPORT IS TRUE. The wizard used to answer a mid-sequence refusal with
  "Nothing was recorded", which is false the moment anything landed — the same
  defect as reporting a success that did not happen, mirrored.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import onboarding
import settings as settings_mod

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_settings_onboarding import _FakePostgres  # noqa: E402  (needs the tests dir above)

AID = "partial-writes-member"
PROFILE = "p-partial"
KEY = "sk-operator-key"


class _RefusingPostgres(_FakePostgres):
    """Refuses one named write the way a configured database does — by
    returning None, which is what `pg_store.pg_request` does on failure."""

    def __init__(self, refuse=None, refuse_body_key=None):
        super().__init__()
        self.refuse = refuse
        self.refuse_body_key = refuse_body_key
        self.refused: list[tuple] = []

    async def __call__(self, method, table_or_path, params=None, body=None):
        table = table_or_path.split("?")[0]
        if self.refuse == (method, table) and (self.refuse_body_key is None or self.refuse_body_key in (body or {})):
            self.refused.append((method, table, body))
            return None
        return await super().__call__(method, table_or_path, params=params, body=body)


@pytest.fixture
def store(monkeypatch):
    import secret_sealing

    monkeypatch.setenv(secret_sealing.KEY_SECRET_ENV, "test-key-encryption-secret-not-a-real-one")

    def _make(refuse=None, refuse_body_key=None):
        pg = _RefusingPostgres(refuse=refuse, refuse_body_key=refuse_body_key)
        pg.tables["agents"] = [{"agent_id": AID, "profile_id": PROFILE, "name": "before", "onboarding_step": 1}]
        pg.tables["agent_api_keys"] = []
        pg.tables["agent_settings"] = []
        onboarding.init(pg_request_fn=pg)
        settings_mod.init(pg_request_fn=pg)
        return pg

    return _make


def _agent(pg) -> dict:
    return pg.tables["agents"][0]


def _keys(pg) -> list[dict]:
    return pg.tables["agent_api_keys"]


async def _submit(pg):
    return await onboarding.advance(AID, 1, {"provider": "anthropic", "api_key": KEY}, settings_module=settings_mod)


# ── detector validation ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_clean_step_lands_everything(store):
    """The reference state. Without it, every assertion below could pass on a
    step that writes nothing at all."""
    pg = store()
    result = await _submit(pg)
    assert result == {"next_step": 2, "completed": True}
    assert _agent(pg)["llm_provider"] == "anthropic"
    assert len(_keys(pg)) == 1
    assert _agent(pg)["onboarding_step"] == 2


# ── the partial is safe ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_refusal_after_the_credential_leaves_a_member_who_can_still_run(store):
    """⚠️ THE ORDERING GUARANTEE, ASSERTED ON STATE. The provider PATCH is
    refused. The credential must ALREADY be stored, because a stored key row
    carries its own provider and is enough for `load_sessions` to run the member
    on the provider they chose. Written the other way round, this same failure
    leaves a member recorded as using a provider they have no key for."""
    pg = store(refuse=("PATCH", "agents"), refuse_body_key="llm_provider")

    with pytest.raises(onboarding.StepPartiallyApplied):
        await _submit(pg)

    rows = _keys(pg)
    assert len(rows) == 1, "the credential was not stored before the provider write was attempted"
    assert rows[0]["provider"] == "anthropic"
    assert rows[0]["profile_id"] == PROFILE


@pytest.mark.asyncio
async def test_a_mid_sequence_refusal_never_advances_the_wizard(store):
    """The step increment is last of all, so a member whose step did not finish
    is still ON that step and is asked again rather than carried past it."""
    for refuse_key in ("llm_provider",):
        pg = store(refuse=("PATCH", "agents"), refuse_body_key=refuse_key)
        with pytest.raises(onboarding.StepPartiallyApplied):
            await _submit(pg)
        assert _agent(pg)["onboarding_step"] == 1, "the wizard advanced past a step that did not finish"


# ── the report is true ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_step_whose_completion_flag_is_refused_asks_the_question_again(store):
    """The LAST write, and the one partial state a stored integer alone cannot
    describe. The increment lands and `mark_onboarding_complete` is refused, so
    the row says step 2 while nothing records that onboarding finished.

    Asserted through `get_step`, because that is what decides what the operator
    is shown: completion is read from where it is recorded, so this member is
    sent back to the last answerable step rather than being told they are done.
    """
    pg = store(refuse=("PATCH", "agent_settings"), refuse_body_key="onboarding_completed_at")

    with pytest.raises(onboarding.StepPartiallyApplied):
        await _submit(pg)

    assert _agent(pg)["onboarding_step"] == 2, "the increment should have landed before this write"
    assert await onboarding.get_step(AID) != onboarding.STEPS - 1, (
        "a member whose completion was never recorded is being reported as done"
    )
    assert await onboarding.get_step(AID) == onboarding.STEPS - 2


@pytest.mark.asyncio
async def test_what_the_failure_claims_was_saved_really_is_in_the_store(store):
    """Asserted against the store, not against the message. A report that names
    writes which did not land is the same lie as "nothing was recorded", one
    step along."""
    pg = store(refuse=("PATCH", "agents"), refuse_body_key="llm_provider")

    with pytest.raises(onboarding.StepPartiallyApplied) as exc:
        await _submit(pg)

    saved = exc.value.saved
    assert saved, "a step that had already written twice reported saving nothing"
    assert exc.value.failed not in saved, (
        f"the write that was REFUSED ({exc.value.failed!r}) is listed among the ones that saved"
    )
    assert _agent(pg).get("llm_provider") is None, (
        "the refused provider write reached the store — the fake is not refusing what it claims to"
    )

    if any("provider key" in s for s in saved):
        assert _keys(pg), "the report claims the provider key was saved and it is not in the store"
    if any("preference" in s for s in saved):
        assert pg.tables["agent_settings"], "the report claims a settings write landed and it did not"
    assert not any("progress" in s for s in saved), "the report claims the step advanced, and it did not"
    assert KEY not in str(exc.value), "the operator's credential came back in the failure detail"


@pytest.mark.asyncio
async def test_the_failure_does_not_claim_writes_that_never_ran(store):
    """The first write of the step is refused, so nothing can have landed and
    the report must say so rather than naming later writes optimistically."""
    pg = store(refuse=("POST", "agent_settings"))

    with pytest.raises(onboarding.StepPartiallyApplied) as exc:
        await _submit(pg)

    assert exc.value.saved == [], f"nothing had landed, but the report named {exc.value.saved}"
    assert not _keys(pg)
    assert _agent(pg)["onboarding_step"] == 1


# ── resubmitting converges ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_resubmitting_after_a_partial_failure_reaches_the_clean_state(store):
    """The operator's actual next move, asserted on state. Every write in a step
    is idempotent, so the resubmit re-applies what landed and retries what did
    not — it must not duplicate the credential row or double-advance the step."""
    pg = store(refuse=("PATCH", "agents"), refuse_body_key="llm_provider")
    with pytest.raises(onboarding.StepPartiallyApplied):
        await _submit(pg)

    pg.refuse = None  # the database recovers
    result = await _submit(pg)

    assert result == {"next_step": 2, "completed": True}
    assert _agent(pg)["llm_provider"] == "anthropic"
    assert _agent(pg)["onboarding_step"] == 2
    assert len(_keys(pg)) == 1, f"the resubmit duplicated the credential row: {len(_keys(pg))} rows"
    assert len(pg.tables["agent_settings"]) == 1, "the resubmit duplicated the settings row"


@pytest.mark.asyncio
async def test_the_private_memory_copy_cannot_strand_the_writes_that_matter(store):
    """The one best-effort write, pinned as best-effort. It is a second copy of
    the credential that nothing reads — and against the real schema it does not
    even land, because `agent_private_memory.owner_id` is `uuid NOT NULL` and
    the caller supplies the member's text handle.

    So it goes LAST and its failure is swallowed. The property that matters is
    that it cannot take the credential, the provider or the step with it.
    """
    pg = store()

    async def failing_store_secret(agent_id: str, key_name: str, value: str) -> None:
        raise RuntimeError(f'invalid input syntax for type uuid: "{agent_id}"')

    result = await onboarding.advance(
        AID,
        1,
        {"provider": "anthropic", "api_key": KEY},
        store_secret=failing_store_secret,
        settings_module=settings_mod,
    )

    assert result == {"next_step": 2, "completed": True}
    assert len(_keys(pg)) == 1, "a failed private-memory copy took the real credential with it"
    assert _agent(pg)["llm_provider"] == "anthropic"
    assert _agent(pg)["onboarding_step"] == 2
