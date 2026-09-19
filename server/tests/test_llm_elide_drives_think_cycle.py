"""The gate, driven through real think types rather than asserted in isolation.

The unit test next door proves the watermark releases and suppresses. This one
proves the wiring: that ``think_introduction_propose`` and ``think_insight``
actually stop issuing calls when the org stops changing, and start again the
moment it does.

MEASURED BEFORE, MEASURED AFTER. The behaviour being fixed was 486 LLM calls in
a driven 720-tick day for an org where nothing changed, with one prompt sent 60
times byte-identically. The first test below is that shape in miniature: ten
cycles against a frozen org, counting request bodies.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402

import think_cycle  # noqa: E402


class _Memory:
    """agent_memory, as remember/recent_memories see it: insert-only, newest first."""

    def __init__(self) -> None:
        self.rows: dict[str, list[str]] = {}

    async def remember(self, memory_type: str, memory_key: str, value: dict | None = None) -> None:
        self.rows.setdefault(memory_type, []).insert(0, memory_key)

    async def recent(self, memory_type: str, limit: int = 10) -> list[str]:
        return self.rows.get(memory_type, [])[:limit]


class _CountingLLM:
    """Records every request body so repetition is counted, not assumed."""

    def __init__(self, reply: str):
        self.bodies: list[str] = []
        outer = self

        class _Completions:
            @staticmethod
            def create(**kw):
                outer.bodies.append(repr(kw.get("messages")))

                class _Msg:
                    content = reply

                class _Choice:
                    message = _Msg()

                class _Resp:
                    choices = [_Choice()]

                return _Resp()

        class _Chat:
            completions = _Completions()

        self.chat = _Chat()

    @property
    def calls(self) -> int:
        return len(self.bodies)

    @property
    def distinct(self) -> int:
        return len(set(self.bodies))


async def _pg(method, table, **kw):
    if method == "GET":
        return []
    return [{"id": "noop"}]


@pytest.fixture
def org(monkeypatch):
    """A frozen two-member org with the gate enabled."""
    monkeypatch.setenv("LLM_ELIDE_ENABLED", "1")
    mem = _Memory()
    monkeypatch.setattr(think_cycle, "pg_request", _pg)
    monkeypatch.setattr(think_cycle, "remember", mem.remember)
    monkeypatch.setattr(think_cycle, "recent_memories", mem.recent)
    monkeypatch.setattr(think_cycle, "get_intelligence_context", lambda: "")
    monkeypatch.setattr(think_cycle, "log_agent_thought", _noop)
    monkeypatch.setattr(think_cycle, "AGENT_ID", "test-chapter")
    monkeypatch.setattr(think_cycle, "AGENT_NAME", "Test Chapter")
    monkeypatch.setattr(
        think_cycle,
        "members",
        {
            "a": {"name": "Ann", "skills": ["python", "rust"]},
            "b": {"name": "Bo", "skills": ["design"]},
        },
    )
    monkeypatch.setattr(think_cycle, "federation", {})
    return mem


async def _noop(*a, **kw):
    return None


# ── insight ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_insight_stops_re_asking_a_frozen_org(org, monkeypatch):
    """Ten cycles, nothing changed: one call, not ten."""
    llm = _CountingLLM("A title\nA body.")
    monkeypatch.setattr(think_cycle, "llm", llm)

    for _ in range(10):
        await think_cycle.think_insight()

    assert llm.calls == 1, f"expected 1 call across 10 frozen cycles, got {llm.calls}"


@pytest.mark.asyncio
async def test_insight_without_the_flag_re_asks_every_cycle(org, monkeypatch):
    """The before-picture, and the revert path.

    With the flag off the type must behave exactly as it did: ten cycles, ten
    calls, and every body identical — which is the waste being removed.
    """
    monkeypatch.setenv("LLM_ELIDE_ENABLED", "0")
    llm = _CountingLLM("A title\nA body.")
    monkeypatch.setattr(think_cycle, "llm", llm)

    for _ in range(10):
        await think_cycle.think_insight()

    assert llm.calls == 10
    assert llm.distinct == 1, "the ten calls were not byte-identical; the premise changed"


@pytest.mark.asyncio
async def test_a_new_member_releases_the_insight_gate(org, monkeypatch):
    llm = _CountingLLM("A title\nA body.")
    monkeypatch.setattr(think_cycle, "llm", llm)

    await think_cycle.think_insight()
    await think_cycle.think_insight()
    assert llm.calls == 1

    think_cycle.members["c"] = {"name": "Cy", "skills": ["ops"]}
    await think_cycle.think_insight()
    assert llm.calls == 2, "a new member did not release the gate"


@pytest.mark.asyncio
async def test_a_changed_skill_releases_the_insight_gate(org, monkeypatch):
    """The membership COUNT is unchanged here.

    A watermark built from counts rather than content would hold steady across
    exactly this edit — the same shape of mistake as a rowid watermark over a
    table written ON CONFLICT DO UPDATE.
    """
    llm = _CountingLLM("A title\nA body.")
    monkeypatch.setattr(think_cycle, "llm", llm)

    await think_cycle.think_insight()
    assert llm.calls == 1

    think_cycle.members["b"]["skills"] = ["design", "welding"]
    await think_cycle.think_insight()
    assert llm.calls == 2, "a changed skill did not release the gate"


@pytest.mark.asyncio
async def test_a_new_federation_peer_releases_the_insight_gate(org, monkeypatch):
    llm = _CountingLLM("A title\nA body.")
    monkeypatch.setattr(think_cycle, "llm", llm)

    await think_cycle.think_insight()
    think_cycle.federation["boston"] = {"name": "Boston"}
    await think_cycle.think_insight()
    assert llm.calls == 2


@pytest.mark.asyncio
async def test_a_failed_insight_does_not_suppress_its_own_retry(org, monkeypatch):
    """The watermark is recorded after success, not before.

    Recording first would let one provider error silence the type for a whole
    24h window — a transient fault converted into a day of nothing.
    """

    class _Failing:
        class _Chat:
            class _Completions:
                @staticmethod
                def create(**_kw):
                    raise RuntimeError("provider down")

            completions = _Completions()

        chat = _Chat()

    monkeypatch.setattr(think_cycle, "llm", _Failing())
    await think_cycle.think_insight()

    ok = _CountingLLM("A title\nA body.")
    monkeypatch.setattr(think_cycle, "llm", ok)
    await think_cycle.think_insight()
    assert ok.calls == 1, "a failed cycle suppressed its own retry"


# ── introduction_propose ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_introductions_stop_re_serialising_a_frozen_member_list(org, governance_ok, monkeypatch):
    """The 61%-of-tokens case: ten cycles, one serialisation."""
    llm = _CountingLLM('{"member_a": {"agent_id": "a"}, "member_b": {"agent_id": "b"}, "reason": "r"}')
    monkeypatch.setattr(think_cycle, "llm", llm)
    monkeypatch.setattr(think_cycle, "federation_discovery_mod", _StubDiscovery(), raising=False)

    for _ in range(10):
        await think_cycle.think_introduction_propose()

    assert llm.calls == 1, f"expected 1 call across 10 frozen cycles, got {llm.calls}"


@pytest.mark.asyncio
async def test_introductions_without_the_flag_re_serialise_every_cycle(org, governance_ok, monkeypatch):
    monkeypatch.setenv("LLM_ELIDE_ENABLED", "0")
    llm = _CountingLLM('{"member_a": {"agent_id": "a"}, "member_b": {"agent_id": "b"}, "reason": "r"}')
    monkeypatch.setattr(think_cycle, "llm", llm)
    monkeypatch.setattr(think_cycle, "federation_discovery_mod", _StubDiscovery(), raising=False)

    for _ in range(10):
        await think_cycle.think_introduction_propose()

    assert llm.calls == 10
    assert llm.distinct == 1


class _StubDiscovery:
    @staticmethod
    async def query_chapter_members(_fid):
        return []


@pytest.fixture
def governance_ok(monkeypatch):
    """A governance module whose propose() succeeds.

    Without this the real module raises "governance.init() never ran", the
    proposal fails, and the watermark is correctly NOT recorded — which is the
    behaviour ``test_a_failed_insight_does_not_suppress_its_own_retry`` pins.
    Here the point is the gate, so the proposal has to succeed.
    """
    import sys
    from types import ModuleType

    stub = ModuleType("governance")

    async def recent_introduction_exists(_a, _b):
        return False

    async def propose(**_kw):
        return {"id": "prop-1"}

    stub.recent_introduction_exists = recent_introduction_exists
    stub.propose = propose
    monkeypatch.setitem(sys.modules, "governance", stub)
    return stub


# ── introduction_propose: what releases the gate ────────────────────
#
# These did not exist when the gate shipped, and their absence is why the
# defect below survived: dropping members_json from the introduction watermark
# entirely left every other test in this module passing. A gate with no release
# test is a gate nobody has watched release.


def _many_members(n: int) -> dict:
    """An org large enough that a new joiner lands past the prompt's [:30] slice."""
    return {f"m{i:03d}": {"name": f"M{i}", "skills": [f"skill{i}"]} for i in range(n)}


@pytest.mark.asyncio
async def test_a_new_member_releases_the_introduction_gate_past_the_prompt_slice(org, governance_ok, monkeypatch):
    """⚠️ THE ONE THAT FAILS AGAINST THE TRUNCATED WATERMARK.

    The prompt sends ``all_members[:30]`` because that is what bounds its size.
    Reusing that truncated value as the change detector makes the gate blind
    past member 30: the joiner lands outside the slice, the serialisation does
    not change, the watermark does not move, and the org NEVER proposes an
    introduction for them again. The symptom is an absence, so nothing alerts.

    Driven at 31 members, where the 32nd joiner is outside any slice of the
    first 30.
    """
    llm = _CountingLLM('{"member_a": {"agent_id": "m000"}, "member_b": {"agent_id": "m001"}, "reason": "r"}')
    monkeypatch.setattr(think_cycle, "llm", llm)
    monkeypatch.setattr(think_cycle, "federation_discovery_mod", _StubDiscovery(), raising=False)
    monkeypatch.setattr(think_cycle, "members", _many_members(31))

    await think_cycle.think_introduction_propose()
    await think_cycle.think_introduction_propose()
    assert llm.calls == 1, "the gate did not hold on an unchanged org"

    think_cycle.members["m999"] = {"name": "Newcomer", "skills": ["welding"]}
    await think_cycle.think_introduction_propose()
    assert llm.calls == 2, (
        "a member who joined past the prompt's [:30] slice did not release the gate — "
        "the watermark is truncated and this org has silently stopped introducing new people"
    )


@pytest.mark.asyncio
async def test_a_changed_skill_past_the_prompt_slice_releases_the_introduction_gate(org, governance_ok, monkeypatch):
    """Same class, without a membership-count change.

    A count-plus-slice watermark would hold steady here: the roster size is
    identical and the edited member sits outside the serialised window.
    """
    llm = _CountingLLM('{"member_a": {"agent_id": "m000"}, "member_b": {"agent_id": "m001"}, "reason": "r"}')
    monkeypatch.setattr(think_cycle, "llm", llm)
    monkeypatch.setattr(think_cycle, "federation_discovery_mod", _StubDiscovery(), raising=False)
    monkeypatch.setattr(think_cycle, "members", _many_members(40))

    await think_cycle.think_introduction_propose()
    assert llm.calls == 1

    think_cycle.members["m035"]["skills"] = ["welding"]
    await think_cycle.think_introduction_propose()
    assert llm.calls == 2, "a skill change outside the prompt slice did not release the gate"


@pytest.mark.asyncio
async def test_a_new_member_inside_the_slice_releases_the_introduction_gate(org, governance_ok, monkeypatch):
    """The small-org case, which the truncated watermark did handle.

    Kept so a future narrowing of the watermark cannot pass by covering only
    the large-org case.
    """
    llm = _CountingLLM('{"member_a": {"agent_id": "a"}, "member_b": {"agent_id": "b"}, "reason": "r"}')
    monkeypatch.setattr(think_cycle, "llm", llm)
    monkeypatch.setattr(think_cycle, "federation_discovery_mod", _StubDiscovery(), raising=False)

    await think_cycle.think_introduction_propose()
    assert llm.calls == 1

    think_cycle.members["c"] = {"name": "Cy", "skills": ["ops"]}
    await think_cycle.think_introduction_propose()
    assert llm.calls == 2


@pytest.mark.asyncio
async def test_a_new_exclusion_releases_the_introduction_gate(org, governance_ok, monkeypatch):
    """The recent-pairs cap is the OTHER direction and is safe.

    ``recent_memories`` returns the 20 NEWEST entries, so a new exclusion always
    appears in the slice and always moves the watermark; what falls off the end
    is the oldest. That is the opposite of the member list, where the slice is
    over an insertion-ordered roster and it is the NEWEST entries that fall
    outside. Both are caps; only one of them can hide a change.
    """
    mem = org
    llm = _CountingLLM('{"member_a": {"agent_id": "a"}, "member_b": {"agent_id": "b"}, "reason": "r"}')
    monkeypatch.setattr(think_cycle, "llm", llm)
    monkeypatch.setattr(think_cycle, "federation_discovery_mod", _StubDiscovery(), raising=False)

    await think_cycle.think_introduction_propose()
    assert llm.calls == 1

    await mem.remember("intro_pair", "a|b")
    await think_cycle.think_introduction_propose()
    assert llm.calls == 2, "a newly excluded pair did not release the gate"
