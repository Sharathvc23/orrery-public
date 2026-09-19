"""think_event is community-shaped, so it is gated on WHO the members are.

Orrery is an SMB + individuals product. ``think_event`` proposes community
events — workshops, meetups, hackathons — which is a peer-directory behaviour.
Applied to business listings it composes events out of service catalogues ("a
haircut meetup"), so the fix is a gate on ``profile_type`` rather than a reworded
prompt: rewording would leave the same wrong output with better copy.

⚠️ The gate is an EXCLUSION set, and it was an inclusion allowlist first. That
allowlist covered one of the seven values the database actually permits, so six
ordinary individual roles read as businesses and think_event silently proposed
nothing. The guard that would have caught it — deriving the legal values from
``infra/init.sql`` and asserting none of them is excluded — is now the centre of
this file, because the original test suite pinned the WRONG behaviour and would
have defended the bug against a fix.

Also pins the accurate scope of the old docstring's claim. It said the cycle
worked from "member skills and interests"; it only ever read ``skills`` —
``interests`` appeared in the prose and never in the code. Recorded here so the
next reader does not go looking for a use that was never there.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import think_cycle

_INIT_SQL = Path(__file__).resolve().parents[2] / "infra" / "init.sql"


def _profile_types_the_database_permits() -> frozenset[str]:
    """The legal values of ``agents.profile_type``, READ FROM THE SCHEMA.

    Derived, not hand-copied. The first version of this gate hand-picked a set of
    "individual" types and got six of seven legal values wrong; a hand-copied
    list here would be the same mistake one file over, and nothing would compare
    the two sides. Parsing the CHECK constraint means the schema is the source of
    truth and a widening shows up here as a failure.
    """
    sql = _INIT_SQL.read_text()
    match = re.search(
        r"CONSTRAINT\s+agents_profile_type_check\s+CHECK\s*\(\(profile_type\s*=\s*ANY\s*\(ARRAY\[(.*?)\]\)\)\)",
        sql,
        re.DOTALL,
    )
    assert match, "agents_profile_type_check not found in infra/init.sql — did the schema move?"
    return frozenset(re.findall(r"'([^']+)'::text", match.group(1)))


@pytest.fixture(autouse=True)
def _isolate_members(monkeypatch):
    monkeypatch.setattr(think_cycle, "AGENT_ID", "test-chapter", raising=False)
    monkeypatch.setattr(think_cycle, "members", {}, raising=False)


def _member(profile_type=None, name="Ada"):
    m = {"name": name, "skills": ["python"], "description": ""}
    if profile_type is not None:
        m["profile_type"] = profile_type
    return m


# ── the classifier ───────────────────────────────────────────────────────────


def test_missing_profile_type_reads_as_individual():
    """The historical default. Every other reader of this column assumes
    ``member`` when it is absent (consent_gate, surfaces, agent_export), so
    nothing that worked before this change stops working."""
    assert think_cycle._is_individual(_member()) is True
    assert think_cycle._is_individual({}) is True


def test_none_profile_type_reads_as_individual():
    assert think_cycle._is_individual({"profile_type": None}) is True


# ── the guard that would have caught the original bug ────────────────────────


def test_the_schema_permits_exactly_the_seven_values_this_gate_reasons_about():
    """Pins the parse itself, so a silent regex failure cannot make the guard
    below vacuous by matching an empty set."""
    assert _profile_types_the_database_permits() == {
        "member",
        "founder",
        "developer",
        "investor",
        "mentor",
        "researcher",
        "leader",
    }


@pytest.mark.parametrize("profile_type", sorted(_profile_types_the_database_permits()))
def test_every_profile_type_the_database_permits_is_an_individual(profile_type):
    """⚠️ THE REGRESSION GUARD.

    All seven legal values are ordinary individual roles. The first version of
    this gate was an inclusion allowlist that covered exactly one of them, so
    founder / developer / investor / mentor / researcher / leader all read as
    "not an individual" and think_event quietly proposed nothing for any org not
    typed literally "member". This is the assertion that fails on that code.
    """
    assert think_cycle._is_individual(_member(profile_type)) is True


def test_no_database_legal_value_is_excluded_as_a_business():
    """The same invariant stated against the set rather than the function.

    If someone widens the CHECK constraint to add a business-shaped type, or adds
    a type here that the database already permits for people, this fails and says
    which value — instead of a member type silently losing its community
    behaviour, which is how this went wrong the first time.
    """
    overlap = _profile_types_the_database_permits() & think_cycle.BUSINESS_PROFILE_TYPES
    assert overlap == frozenset(), f"these are legal member types being excluded as businesses: {sorted(overlap)}"


def test_business_is_not_an_individual():
    """Intent, kept even though the column cannot currently carry this value.

    Reachable today only via a hand-authored org config (``seed_members`` passes
    profile_type through unchecked). It is the behaviour we want the moment the
    discriminator can travel — see the module note on why it cannot yet.
    """
    assert think_cycle._is_individual(_member("business")) is False


def test_unknown_profile_type_falls_open_to_individual():
    """⚠️ THIS ASSERTION WAS REVERSED, DELIBERATELY.

    It previously read ``is False`` — "fail closed on an unrecognised type" — and
    that framing is what produced the bug: the gate refused everything it had not
    enumerated, and the things it had not enumerated were six of the seven legal
    ways to be a person.

    Fail-closed is right for authorization (see
    ``community_member/owner.listing_grant_verdict``, which refuses everything it
    cannot positively verify). This is not authorization; it decides whether to
    ask an LLM for a workshop idea. Closed, real people silently lose a feature.
    Open, a business might appear in an event prompt. The guard above is what
    keeps the open direction honest.
    """
    assert think_cycle._is_individual(_member("franchise")) is True


# ── the gate ─────────────────────────────────────────────────────────────────


async def test_think_event_returns_early_for_an_all_business_org(monkeypatch):
    """An org of businesses is a service directory, not a community. It must
    propose nothing — and must not even query for pending events, because the
    decision does not depend on them."""
    calls: list[tuple] = []

    async def _pg(*args, **kwargs):
        calls.append((args, kwargs))
        return []

    monkeypatch.setattr(think_cycle, "pg_request", _pg, raising=False)
    monkeypatch.setattr(think_cycle, "members", {"barber": _member("business", "Bob's Barbers")}, raising=False)

    assert await think_cycle.think_event() is None
    assert calls == [], "an all-business org must not even reach the event query"


async def test_think_event_returns_early_for_an_empty_org(monkeypatch):
    async def _pg(*args, **kwargs):
        raise AssertionError("must not be reached")

    monkeypatch.setattr(think_cycle, "pg_request", _pg, raising=False)
    monkeypatch.setattr(think_cycle, "members", {}, raising=False)
    assert await think_cycle.think_event() is None


async def test_think_event_proceeds_with_at_least_one_individual(monkeypatch):
    """A mixed org still has a community. The gate is "any individual", not
    "no businesses" — a barber joining a chapter must not silence its events."""
    queried: list[str] = []

    async def _pg(method, table, **kwargs):
        queried.append(table)
        # Report 5 pending events so the cycle stops right after the gate,
        # without needing an LLM. Reaching this proves the gate let it through.
        return [{"id": i} for i in range(5)]

    monkeypatch.setattr(think_cycle, "pg_request", _pg, raising=False)
    monkeypatch.setattr(
        think_cycle,
        "members",
        {"barber": _member("business", "Bob's Barbers"), "ada": _member("member", "Ada")},
        raising=False,
    )
    await think_cycle.think_event()
    assert queried == ["agent_events"], "the gate should have allowed the cycle to query pending events"


async def test_business_offerings_do_not_feed_the_event_prompt(monkeypatch):
    """The substantive assertion: a business's skills must not reach the LLM as
    community-event material. Without the per-member filter this passes the
    barber's offerings straight into the prompt."""
    prompts: list[str] = []

    async def _pg(method, table, **kwargs):
        return []  # no pending events -> the cycle proceeds to build the prompt

    class _Response:
        def __init__(self):
            self.choices = [type("C", (), {"message": type("M", (), {"content": "not json"})()})()]

    class _Completions:
        def create(self, **kwargs):
            prompts.append(str(kwargs["messages"]))
            return _Response()

    class _LLM:
        chat = type("Chat", (), {"completions": _Completions()})()

    async def _recent(*_a, **_k):
        return []

    async def _remember(*_a, **_k):
        return None

    monkeypatch.setattr(think_cycle, "pg_request", _pg, raising=False)
    monkeypatch.setattr(think_cycle, "llm", _LLM(), raising=False)
    monkeypatch.setattr(think_cycle, "recent_memories", _recent, raising=False)
    monkeypatch.setattr(think_cycle, "remember", _remember, raising=False)
    monkeypatch.setattr(think_cycle, "get_intelligence_context", lambda: "", raising=False)
    monkeypatch.setattr(
        think_cycle,
        "members",
        {
            "barber": {"name": "Bob's Barbers", "skills": ["beard-trim"], "profile_type": "business"},
            "ada": {"name": "Ada", "skills": ["python"], "profile_type": "member"},
        },
        raising=False,
    )

    await think_cycle.think_event()

    assert prompts, "the cycle should have reached the LLM"
    blob = prompts[0]
    assert "python" in blob
    assert "beard-trim" not in blob, "a business's offerings leaked into the community-event prompt"
    assert "Bob's Barbers" not in blob
    # And the member count in the prompt counts individuals, not listings.
    assert "1 members" in blob
