"""One question, four places that answer it.

Which providers exist is stated by ``llm_runtime.PROVIDERS``, by the wizard's
option list, by ``agents_llm_provider_check`` and by
``agent_api_keys_provider_check``. They have already disagreed twice: the wizard
offered ``ollama_local``, which neither the registry nor either constraint
accepts, and the constraints named five providers while the registry knew seven
— so choosing "Local (Ollama)" wrote a provider the database refused and the
member silently ran the column DEFAULT instead.

The wizard-vs-registry half is already held by
``test_provider_precedence.test_every_provider_onboarding_offers_is_one_the_resolver_knows``.
This file closes the other half: REGISTRY vs CONSTRAINT.

⚠️ BOTH SIDES ARE DERIVED. A list of provider names written out here would be a
fifth vocabulary, and it would agree with the schema only until someone edits
one of them — which is the exact failure these tests exist to catch. The
constraint is parsed out of ``infra/init.sql``, the registry is imported.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import api_key_store
import llm_runtime

_INIT_SQL = Path(__file__).resolve().parents[2] / "infra" / "init.sql"
_MIGRATIONS = Path(__file__).resolve().parents[2] / "infra" / "migrations"


def _check_values(constraint: str, sql: str) -> set[str]:
    """The value set a named CHECK constraint admits, read out of the DDL."""
    m = re.search(constraint + r"[^(]*CHECK \(\(?\w+ = ANY \(ARRAY\[(.*?)\]\)\)", sql, re.S)
    assert m, f"{constraint} not found — the schema moved and this guard went blind"
    return set(re.findall(r"'([^']+)'::text", m.group(1)))


def _agents_check() -> set[str]:
    return _check_values("agents_llm_provider_check", _INIT_SQL.read_text())


# ── the registry and the constraint agree ────────────────────────────────────


def test_every_provider_the_resolver_knows_can_be_stored_on_an_agent():
    """The defect this file is named for. A provider the resolver can run but
    the column refuses is one the wizard can offer, the operator can pick, and
    nothing can record — which is how "Local (Ollama)" became a member running
    xai."""
    unstorable = sorted(set(llm_runtime.PROVIDERS) - _agents_check())
    assert not unstorable, (
        f"agents_llm_provider_check refuses provider(s) llm_runtime can resolve: {unstorable}. "
        "Widen the constraint (see infra/migrations/0007) rather than narrowing the resolver."
    )


def test_the_constraint_admits_nothing_the_resolver_cannot_run_except_declared_legacy():
    """The other direction, which is the one that rots quietly. A value accepted
    at rest and refused at run time produces a member who cannot start and a row
    that looks fine. ``custom`` is exactly that and is declared, so it is
    subtracted by name from the CODE, never from a copy in this test — anything
    else is drift."""
    unrunnable = sorted(_agents_check() - set(llm_runtime.PROVIDERS) - llm_runtime.LEGACY_PROVIDER_VALUES)
    assert not unrunnable, (
        f"agents_llm_provider_check admits provider(s) llm_runtime cannot resolve: {unrunnable}. "
        "Either add them to the registry or declare them in llm_runtime.LEGACY_PROVIDER_VALUES "
        "with the reason they are still accepted."
    )


def test_the_legacy_exemption_covers_nothing_it_does_not_need_to():
    """The exemption is a subtraction, so it is the one part of this file that
    can be widened to silence it. A value declared legacy that no constraint
    actually admits is not documenting a gap — it is pre-authorising one, and
    the next name added to the constraint would inherit the exemption without
    anyone deciding to grant it.

    Caught by planting: adding two plausible providers to LEGACY_PROVIDER_VALUES
    left every other test in this file green.
    """
    stale = sorted(llm_runtime.LEGACY_PROVIDER_VALUES - _agents_check())
    assert not stale, (
        f"llm_runtime.LEGACY_PROVIDER_VALUES exempts {stale}, which agents_llm_provider_check "
        "does not admit. Remove them: an exemption with nothing to exempt only weakens the guard."
    )


def test_the_declared_legacy_values_really_are_unresolvable():
    """DETECTOR VALIDATION for the subtraction above. If a legacy value became
    resolvable, the exemption would be silently hiding a provider that no longer
    needs one."""
    for name in llm_runtime.LEGACY_PROVIDER_VALUES:
        with pytest.raises(llm_runtime.LLMNotConfigured):
            llm_runtime.resolve(name)


# ── the key table is deliberately narrower, and stays that way ───────────────


def test_the_key_table_refuses_local_providers_on_purpose():
    """``agent_api_keys`` holds a CREDENTIAL and a local provider takes none, so
    it is NOT widened with the agents constraint. The reason is not tidiness:
    ``sovereign_runtime.load_sessions`` reads the presence of a stored key row
    as branch 2 of its precedence chain, so a local row would start claiming to
    be a bring-your-own-key member."""
    keys_check = _check_values("agent_api_keys_provider_check", _INIT_SQL.read_text())
    admitted_local = sorted(keys_check & llm_runtime.LOCAL_PROVIDERS)
    assert not admitted_local, f"agent_api_keys accepts local provider(s) {admitted_local}, which take no credential"
    unstorable_remote = sorted((set(llm_runtime.PROVIDERS) - llm_runtime.LOCAL_PROVIDERS) - keys_check)
    assert not unstorable_remote, (
        f"a REMOTE provider the resolver knows cannot have its key stored: {unstorable_remote}"
    )


def test_the_modules_writable_set_matches_the_key_tables_constraint():
    """``api_key_store.WRITABLE_PROVIDERS`` is a Python copy of that constraint
    and refuses writes on its own. Two copies of one list is how the wizard and
    the schema drifted in the first place; here they are at least held equal."""
    assert api_key_store.WRITABLE_PROVIDERS == _check_values("agent_api_keys_provider_check", _INIT_SQL.read_text())


# ── init.sql and the migration say the same thing ────────────────────────────


def test_the_migration_and_init_sql_agree_on_the_widened_constraint():
    """A fresh install reads init.sql and an existing one reads the migration.
    When they disagree the difference shows up only on whichever kind of install
    you did not test — the divergence 0003's comment already names."""
    migration = next(_MIGRATIONS.glob("0007_*.sql")).read_text()
    assert _check_values("agents_llm_provider_check", migration) == _agents_check()


def test_the_migration_and_init_sql_agree_that_agents_has_an_avatar():
    migration = next(_MIGRATIONS.glob("0007_*.sql")).read_text()
    assert re.search(r"ALTER TABLE public\.agents\s+ADD COLUMN IF NOT EXISTS avatar_url", migration)
    agents_ddl = re.search(r"CREATE TABLE public\.agents \((.*?)\n\);", _INIT_SQL.read_text(), re.S)
    assert agents_ddl and re.search(r"^\s*avatar_url text,", agents_ddl.group(1), re.M), (
        "init.sql's agents table has no avatar_url — a fresh install would not get the column"
    )
