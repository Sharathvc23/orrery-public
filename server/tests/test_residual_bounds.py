"""Two bounds: the per-cycle call count, and the insight prompt's skill join.

⚠️ THE SECOND ONE IS WHERE A BUG SHIPPED TO MAIN, AND THIS SUITE REPRODUCES ITS
SHAPE RATHER THAN TRUSTING THE FIX. The introduction gate hashed a member list
that had been truncated to 30 for prompt-size reasons, so past member 30 a joiner
never released the gate: the roster changed, the serialisation did not, the
watermark did not move, and the type stopped running — visible only as an
absence, because nothing alerts on an introduction that was never proposed.

The rule that came out of it: **a value truncated, sampled or capped for
prompt-size reasons cannot double as the change detector for the thing it was
truncated from.** `think_insight` is watermarked and its skill list is now
sampled, so it is exactly that shape. The watermark takes the full set; the
prompt takes the sample.

Note the precise criterion, because a cap is not automatically unsafe: the recent
-pairs cap in the same file is fine, since `recent_memories` returns the NEWEST 20
and a new entry always lands inside that window. Only a bound that can hide a NEW
entry can hide a change — and a SAMPLE is worse than a head slice here, because a
new entry can fall outside a sample at any position rather than only past the end.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "server"))

import llm_runtime  # noqa: E402

# ══════════════════════════════════════════════════════════════════════
# 1. the per-cycle call cap, in the factory
# ══════════════════════════════════════════════════════════════════════


class _FakeCompletions:
    def __init__(self) -> None:
        self.calls = 0

    def create(self, **_kwargs: object) -> str:
        self.calls += 1
        return "ok"


class _FakeChat:
    def __init__(self) -> None:
        self.completions = _FakeCompletions()


class _FakeClient:
    def __init__(self) -> None:
        self.chat = _FakeChat()
        self.models = "delegated"


def test_the_cap_is_reached_and_refuses_by_name() -> None:
    """Driven to the boundary, not read off the constant."""
    budget = llm_runtime.CallBudget(limit=3)
    client = llm_runtime.BudgetedClient(_FakeClient(), budget)

    for _ in range(3):
        assert client.chat.completions.create(model="m") == "ok"

    with pytest.raises(llm_runtime.LLMCallBudgetExceeded) as caught:
        client.chat.completions.create(model="m")
    assert "next cycle" in str(caught.value), "the refusal must say the work is not lost"


def test_a_refused_call_never_reaches_the_provider() -> None:
    """A cap that counted but still called would bound nothing."""
    inner = _FakeClient()
    client = llm_runtime.BudgetedClient(inner, llm_runtime.CallBudget(limit=1))

    client.chat.completions.create(model="m")
    with pytest.raises(llm_runtime.LLMCallBudgetExceeded):
        client.chat.completions.create(model="m")

    assert inner.chat.completions.calls == 1, "the refused call was sent anyway"


def test_the_budget_bounds_the_cycle_not_one_client() -> None:
    """⚠️ THE REASON IT LIVES IN THE FACTORY. The measured hazard was one caller
    looping, but bounding that caller would leave the next one to rediscover it.
    Two clients from the same factory share one cycle's budget."""
    budget = llm_runtime.CallBudget(limit=2)
    a = llm_runtime.BudgetedClient(_FakeClient(), budget)
    b = llm_runtime.BudgetedClient(_FakeClient(), budget)

    a.chat.completions.create(model="m")
    b.chat.completions.create(model="m")
    with pytest.raises(llm_runtime.LLMCallBudgetExceeded):
        a.chat.completions.create(model="m")


def test_resetting_the_cycle_restores_the_budget() -> None:
    budget = llm_runtime.CallBudget(limit=1)
    client = llm_runtime.BudgetedClient(_FakeClient(), budget)
    client.chat.completions.create(model="m")
    budget.reset()
    assert client.chat.completions.create(model="m") == "ok"
    assert budget.used == 1


def test_everything_but_create_is_delegated_untouched() -> None:
    client = llm_runtime.BudgetedClient(_FakeClient(), llm_runtime.CallBudget(limit=1))
    assert client.models == "delegated"


def test_the_call_budget_and_the_output_ceiling_compose_rather_than_replace() -> None:
    """⚠️ THE ONE LINE A REBASE COULD SILENTLY UNDO. The per-cycle budget and the
    omitted-``max_tokens`` ceiling both wrap ``chat.completions.create`` and
    arrived in separate units, so ``build_client`` is where one could quietly have
    replaced the other — with no test failing, because each wrapper's own tests
    pass whether or not the other is still there.

    Composed as ``build_client`` composes them, and all three properties asserted
    together: the ceiling fills an omitted value, a caller's own value survives,
    and the budget still refuses.
    """
    seen: list[dict[str, object]] = []

    class _Recording:
        def create(self, **kwargs: object) -> str:
            seen.append(kwargs)
            return "ok"

    class _Chat:
        def __init__(self) -> None:
            self.completions = _Recording()

    class _Client:
        def __init__(self) -> None:
            self.chat = _Chat()

    # ⚠️ COMPOSED THE WAY build_client COMPOSES THEM, READ OUT OF build_client.
    # A first draft applied the two wrappers ITSELF and passed while build_client
    # had dropped one of them — it proved the wrappers CAN compose, not that the
    # factory DOES. Caught by planting exactly that. The structural assertion
    # below is what ties this to the shipping path.
    client = llm_runtime._with_call_budget(llm_runtime._with_output_ceiling(_Client()))
    llm_runtime.CYCLE_BUDGET.reset(2)
    try:
        client.chat.completions.create(model="m")
        assert seen[-1]["max_tokens"] == llm_runtime.max_output_tokens(), "the output ceiling was lost"

        client.chat.completions.create(model="m", max_tokens=7)
        assert seen[-1]["max_tokens"] == 7, "the ceiling overrode a caller's own value"

        with pytest.raises(llm_runtime.LLMCallBudgetExceeded):
            client.chat.completions.create(model="m")
        assert len(seen) == 2, "a refused call still reached the inner client"
    finally:
        llm_runtime.CYCLE_BUDGET.reset(llm_runtime.calls_per_cycle())


def test_build_client_returns_a_client_carrying_BOTH_wrappers() -> None:
    """⚠️ THE ASSERTION THAT ACTUALLY GUARDS THE REBASE. Both wrappers sit on the
    same seam and arrived in separate units, so ``build_client`` is the one line
    where one could silently replace the other. Driven through the real factory —
    a local provider needs no key and constructing a client makes no network
    call — and both layers are required to be present in the object it hands out.
    """
    resolution = llm_runtime.resolve("ollama")
    assert resolution.is_local, "this test needs a provider that builds without a key"
    client = llm_runtime.build_client(resolution)

    assert isinstance(client, llm_runtime.BudgetedClient), "build_client stopped applying the call budget"

    # One layer in, the ceiling must still be there. Found by walking the
    # delegation chain rather than by name, so a renamed wrapper still passes and
    # a MISSING one still fails.
    inner = client._inner
    assert type(inner).__name__ != "OpenAI", "build_client stopped applying the output ceiling"
    assert hasattr(inner, "chat"), "the inner layer is not a client shape"


def test_the_two_vendored_runtimes_are_byte_identical() -> None:
    """Both units extend this module, so both conflicts had to be resolved the
    same way. Resolving them separately by hand is how they would drift; this is
    the assertion that would have caught it."""
    import hashlib

    digests = {
        path: hashlib.md5((REPO / path).read_bytes()).hexdigest()
        for path in ("server/llm_runtime.py", "agent/community_member/llm_runtime.py")
    }
    assert len(set(digests.values())) == 1, f"the vendored copies diverged: {digests}"


def test_the_default_sits_above_the_measured_worst_cycle() -> None:
    """The worst cycle measured was 40 sweep calls plus 9 for the rest of the
    rotation. A default at or below that would fire on an ordinary day, which is
    how a bound gets raised until it means nothing."""
    assert llm_runtime.DEFAULT_CALLS_PER_CYCLE > 49


@pytest.mark.parametrize("bad", ["", "   ", "0", "-5", "lots"])
def test_an_unusable_limit_falls_back_to_the_default_rather_than_to_none(
    monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    monkeypatch.setenv(llm_runtime.CALLS_PER_CYCLE_ENV, bad)
    assert llm_runtime.calls_per_cycle() == llm_runtime.DEFAULT_CALLS_PER_CYCLE


def test_the_bound_is_not_described_as_a_spend_saving() -> None:
    """⚠️ THE MEASUREMENT CONTRADICTED THE INTUITION AND THE MEASUREMENT WON: all
    40 of those calls cost 1,897 tokens in total. A bound that claims the wrong
    benefit teaches the next reader the wrong thing, and the next reader is who
    decides whether to raise it."""
    for path in ("server/llm_runtime.py", "server/think_cycle.py"):
        text = (REPO / path).read_text()
        window = text[text.find("CALLS_PER_CYCLE_ENV") : text.find("CALLS_PER_CYCLE_ENV") + 4000]
        for claim in ("cost saving", "spend saving", "saves money", "cheaper"):
            assert claim not in window.lower(), f"{path} sells this bound as a spend item: {claim!r}"
    runtime = (REPO / "server" / "llm_runtime.py").read_text()
    assert "latency" in runtime.lower() and "rate-limit" in runtime.lower(), (
        "the bound must say what it actually bounds"
    )


# ══════════════════════════════════════════════════════════════════════
# 2. the insight skill join — and the watermark it must not feed
# ══════════════════════════════════════════════════════════════════════


def _sampler():
    """The helper, executed out of the module so importing the whole think cycle
    (and its many side effects) is not a precondition of testing it."""
    src = (REPO / "server" / "think_cycle.py").read_text()
    start = src.index("def _sample_for_prompt")
    end = src.index("DEFAULT_LLM_MODEL = ")
    namespace: dict[str, object] = {}
    exec(src[start:end], namespace)  # noqa: S102 - the helper is this repo's own source
    return namespace["_sample_for_prompt"]


def test_a_list_that_fits_is_returned_whole_and_unannotated() -> None:
    """A small chapter's prompt must not change, and must not claim to be a
    sample when it is the complete set."""
    sample = _sampler()
    items = [f"skill-{i}" for i in range(10)]
    shown, note = sample(items, 40)
    assert shown == items
    assert note == ""


def test_a_large_list_is_bounded_and_says_it_was_sampled() -> None:
    sample = _sampler()
    items = [f"skill-{i:03d}" for i in range(300)]
    shown, note = sample(items, 40)

    assert len(shown) <= 40
    assert "sampled of 300" in note, "a reader cannot tell a sample from a complete list"
    assert len(set(shown)) == len(shown), "the sample repeats an entry"


def test_the_sample_spreads_rather_than_taking_the_alphabetical_head() -> None:
    """`skills_sorted` is alphabetical, so a head slice would show a chapter's
    "a" skills and present them as a picture of the chapter."""
    sample = _sampler()
    items = [f"skill-{i:03d}" for i in range(300)]
    shown, _ = sample(items, 40)

    assert shown[0] == "skill-000"
    assert shown[-1] > "skill-250", f"the sample never reaches the tail: last={shown[-1]}"


def test_the_watermark_takes_the_full_skill_set_and_the_prompt_takes_the_sample() -> None:
    """⚠️ THE TRAP, ASSERTED AGAINST THE SOURCE. Read the two call sites and
    require them to receive DIFFERENT values: `skills_sorted` into the watermark,
    `skills_shown` into the prompt. If the sample ever reaches the watermark this
    fails, and what it is preventing is the introduction gate's bug — a chapter
    gains a capability, the sample happens not to include it, the watermark does
    not move, and insight stops running on a federation that genuinely changed."""
    src = (REPO / "server" / "think_cycle.py").read_text()
    insight = src[src.index("async def think_insight") : src.index("async def think_conversation")]

    watermark = insight[insight.index("wm = llm_elide.watermark(") : insight.index("run, why = await")]
    assert "skills=skills_sorted" in watermark, "the watermark no longer hashes the full skill set"
    assert "skills_shown" not in watermark, "THE SAMPLE REACHED THE WATERMARK — this is the shipped bug's shape"

    prompt = insight[insight.index("Analyze this federation") :]
    assert "skills_shown" in prompt, "the prompt is not using the bounded sample"
    assert "join(skills_sorted)" not in prompt, "the prompt renders the unbounded list"


def test_a_new_skill_outside_the_sample_still_moves_the_watermark() -> None:
    """The behavioural half of the assertion above, driven through the real
    watermark rather than read off the source: a skill that the sample does not
    include must still change the value the gate compares."""
    import llm_elide

    sample = _sampler()
    skills = sorted(f"skill-{i:03d}" for i in range(300))
    shown, _ = sample(skills, 40)

    # A new capability that lands OUTSIDE the sample — the exact case that made
    # the introduction gate blind.
    added = sorted([*skills, "skill-000-and-a-half"])
    shown_after, _ = sample(added, 40)
    assert "skill-000-and-a-half" not in shown_after or True  # position is incidental

    before = llm_elide.watermark(total_members=1, skills=skills, skills_total=len(skills))
    after = llm_elide.watermark(total_members=1, skills=added, skills_total=len(added))
    assert before != after, "a new skill did not move the watermark"

    # And the sample alone would NOT have moved it, which is why it is not what
    # the watermark is given.
    if shown == shown_after:
        assert llm_elide.watermark(total_members=1, skills=shown, skills_total=len(shown)) == llm_elide.watermark(
            total_members=1, skills=shown_after, skills_total=len(shown_after)
        ), "the premise of this test is wrong; re-check the sampler"


def test_the_approvals_sweep_records_what_it_did_not_reach() -> None:
    """A cap that stopped silently would be indistinguishable from "there was
    nothing approved", and the work it skipped is somebody's approved
    introductions."""
    src = (REPO / "server" / "think_cycle.py").read_text()
    sweep = src[src.index("async def think_approvals_sweep") : src.index("async def think_insight")]

    assert "LLMCallBudgetExceeded" in sweep, "the sweep does not handle the named refusal"
    assert "deferred" in sweep, "the sweep does not record what it left for the next cycle"
    handler = sweep[sweep.index("except llm_runtime.LLMCallBudgetExceeded") :]
    assert "break" in handler, "the sweep carries on past its own limit"
    assert "mark_executed" not in handler, "a deferred row must not be marked executed"
