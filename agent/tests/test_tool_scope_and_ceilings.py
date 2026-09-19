"""Tool scope, the output ceiling, and a loop bounded by tokens rather than turns.

THE MEASUREMENTS THESE PIN. A 26-tool block is 1,957 tokens — 91% of a first
chat turn and 85.9% of a ten-turn conversation. The legacy think loop costs
4,268 input tokens per cycle against think_v2's 1,403, and the 3.15x is
entirely the tool block. The chat stream sent no ``max_tokens`` at all inside a
five-iteration loop, whose measured worst case was 11,469 input tokens and zero
assistant text.

⚠️ WHAT THESE TESTS ARE REALLY GUARDING IS NOT THE SAVING. It is the failure
mode a saving invites: a scoped tool set that omits the tool a turn needed,
which nothing reports because a model does not mention a tool it was never
shown. So the assertions below are weighted toward what must SURVIVE scoping —
the grant-request tool, the withheld account, and an unknown scope widening
rather than emptying — rather than toward how few tools come back.
"""

from __future__ import annotations

from community_member import llm_runtime, token_budget, tool_scope


def _tool(name: str) -> dict:
    return {"type": "function", "function": {"name": name, "parameters": {}}}


ALL_TOOLS = [
    _tool(n)
    for n in (
        "join_chapter",
        "search_chapter",
        "search_federation",
        "submit_intent",
        "respond_to_intent",
        "update_projection",
        "get_chapter_intelligence",
        "start_conversation",
        "list_conversations",
        "save_note",
        "install_skill",
        "rate_skill",
        "list_installed_skills",
        "find_peer",
        "send_to_peer",
        "my_trust",
        "update_settings",
        "connect_channel",
    )
]


# ── the scope registry ──────────────────────────────────────────────


def test_full_scope_sends_everything_it_was_given():
    """The unchanged behaviour, kept as a NAMED scope.

    "No scoping" should be a thing a call site states, not the absence of a
    decision — otherwise the safe option is the one nobody can find in review.
    """
    scoped = tool_scope.select(ALL_TOOLS, scope=tool_scope.SCOPE_FULL)
    names = tool_scope.tool_names(scoped.tools)
    for tool in ALL_TOOLS:
        assert tool["function"]["name"] in names
    assert scoped.withheld == {}


def test_minimal_scope_is_dramatically_smaller():
    scoped = tool_scope.select(ALL_TOOLS, scope=tool_scope.SCOPE_MINIMAL)
    assert len(scoped.tools) < len(ALL_TOOLS) / 3


def test_the_grant_request_tool_survives_every_scope():
    """⚠️ THE ONE THAT MATTERS MOST.

    Without it an ungranted capability is permanently unreachable: the agent
    cannot use it and cannot ask for it, and a user watching it decline has no
    path forward. It is unioned in after every filter, so no scope and no grant
    state can remove it.
    """
    for scope in tool_scope.SCOPES:
        scoped = tool_scope.select(ALL_TOOLS, scope=scope)
        assert "request_grant" in tool_scope.tool_names(scoped.tools), scope


def test_the_grant_request_tool_survives_an_empty_grant_ledger():
    """Nothing granted at all still leaves the way to ask."""
    scoped = tool_scope.select(ALL_TOOLS, scope=tool_scope.SCOPE_FULL, granted=[])
    assert tool_scope.tool_names(scoped.tools) == ["request_grant"]
    assert scoped.withheld_count == len(ALL_TOOLS)
    assert set(scoped.withheld.values()) == {"pending grant"}


def test_no_ledger_is_not_the_same_as_an_empty_ledger():
    """``granted=None`` means no ledger was consulted and filters nothing.

    Collapsing the two would strip every tool from an agent that simply has no
    grant store — a capability regression produced by a default.
    """
    scoped = tool_scope.select(ALL_TOOLS, scope=tool_scope.SCOPE_FULL, granted=None)
    assert scoped.withheld == {}
    assert len(scoped.tools) == len(ALL_TOOLS) + 1


def test_withheld_tools_are_reported_with_a_reason():
    """Silently absent is the failure. The count and the reason must be gettable."""
    scoped = tool_scope.select(ALL_TOOLS, scope=tool_scope.SCOPE_MINIMAL)
    assert scoped.withheld_count > 0
    assert all(why for why in scoped.withheld.values())
    assert "withheld" in scoped.summary()
    assert str(scoped.withheld_count) in scoped.summary()


def test_out_of_scope_and_pending_grant_are_distinguishable():
    """Two different problems with two different fixes.

    Out of scope is a deployment decision; pending grant is something the user
    can approve. A single "unavailable" would send a user to the wrong place.
    """
    scoped = tool_scope.select(ALL_TOOLS, scope=tool_scope.SCOPE_MINIMAL, granted=["search_chapter"])
    assert scoped.withheld["join_chapter"] == "out of scope"
    assert scoped.withheld["save_note"] == "pending grant"


def test_an_unknown_scope_widens_rather_than_empties():
    """A typo must not strip an agent of every tool.

    That failure presents as a model that refuses to act, with no clue why —
    strictly worse than sending too many tools.
    """
    scoped = tool_scope.select(ALL_TOOLS, scope="tpyo")
    assert scoped.scope == tool_scope.SCOPE_FULL
    assert len(scoped.tools) == len(ALL_TOOLS) + 1


def test_every_registered_scope_names_only_tools_that_exist():
    """A scope naming a renamed tool shrinks silently, which is the same defect
    as omitting one. This is why ``unknown_names`` is reported at all."""
    for scope in tool_scope.SCOPES:
        scoped = tool_scope.select(ALL_TOOLS, scope=scope)
        assert scoped.unknown_names == (), f"{scope} names tools that do not exist: {scoped.unknown_names}"


def test_chat_scoping_is_off_unless_asked_for(monkeypatch):
    monkeypatch.delenv(tool_scope.CHAT_SCOPE_ENV, raising=False)
    assert tool_scope.chat_scope_enabled() is False
    monkeypatch.setenv(tool_scope.CHAT_SCOPE_ENV, "ture")
    assert tool_scope.chat_scope_enabled() is False, "a typo must not narrow a live conversation"
    monkeypatch.setenv(tool_scope.CHAT_SCOPE_ENV, "1")
    assert tool_scope.chat_scope_enabled() is True


# ── the output ceiling ──────────────────────────────────────────────


class _RecordingCompletions:
    def __init__(self):
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return object()


class _RecordingClient:
    def __init__(self):
        self.chat = type("_C", (), {})()
        self.chat.completions = _RecordingCompletions()
        self.models = "passed-through"


def test_an_omitted_max_tokens_is_filled_from_the_ceiling(monkeypatch):
    monkeypatch.delenv(llm_runtime.MAX_OUTPUT_TOKENS_ENV, raising=False)
    inner = _RecordingClient()
    client = llm_runtime._with_output_ceiling(inner)
    client.chat.completions.create(model="m", messages=[])
    assert inner.chat.completions.calls[0]["max_tokens"] == llm_runtime.DEFAULT_MAX_OUTPUT_TOKENS


def test_a_callers_own_max_tokens_is_never_overridden(monkeypatch):
    """This raises no ceiling and lowers none. It only refuses to leave it unset."""
    monkeypatch.setenv(llm_runtime.MAX_OUTPUT_TOKENS_ENV, "100")
    inner = _RecordingClient()
    client = llm_runtime._with_output_ceiling(inner)
    client.chat.completions.create(model="m", messages=[], max_tokens=4000)
    assert inner.chat.completions.calls[0]["max_tokens"] == 4000


def test_a_zero_ceiling_disables_injection(monkeypatch):
    monkeypatch.setenv(llm_runtime.MAX_OUTPUT_TOKENS_ENV, "0")
    inner = _RecordingClient()
    client = llm_runtime._with_output_ceiling(inner)
    client.chat.completions.create(model="m", messages=[])
    assert "max_tokens" not in inner.chat.completions.calls[0]


def test_an_unparseable_ceiling_keeps_the_default(monkeypatch):
    """A typo must not remove a bound."""
    monkeypatch.setenv(llm_runtime.MAX_OUTPUT_TOKENS_ENV, "lots")
    assert llm_runtime.max_output_tokens() == llm_runtime.DEFAULT_MAX_OUTPUT_TOKENS


def test_the_wrapper_passes_everything_else_through():
    inner = _RecordingClient()
    client = llm_runtime._with_output_ceiling(inner)
    assert client.models == "passed-through"


# ── the token budget ────────────────────────────────────────────────


def test_the_budget_bounds_the_measured_runaway(monkeypatch):
    """⚠️ THE CASE THE ITERATION COUNTER COULD NOT SEE.

    Five calls, 11,469 input tokens, zero assistant text — and MAX_TOOL_LOOPS
    counted to five and reported success. A token budget stops it partway.
    """
    monkeypatch.delenv(token_budget.BUDGET_ENV, raising=False)
    budget = token_budget.LoopBudget()
    per_call = 11_469 // 5
    steps = 0
    while not budget.exhausted and steps < 5:
        budget.charge("x" * (per_call * token_budget.CHARS_PER_TOKEN))
        steps += 1
    assert steps < 5, "the budget did not stop the measured runaway"
    assert budget.exhausted


def test_cheap_iterations_get_more_turns_than_five(monkeypatch):
    """The bound degrades in the right direction.

    A loop doing cheap work is not the thing being caught, and a token budget
    lets it keep going where an iteration counter cut it off at five.
    """
    monkeypatch.delenv(token_budget.BUDGET_ENV, raising=False)
    budget = token_budget.LoopBudget()
    steps = 0
    while not budget.exhausted and steps < 50:
        budget.charge("tiny")
        steps += 1
    assert steps > 5


def test_provider_reported_usage_is_authoritative():
    budget = token_budget.LoopBudget(limit=1000)
    assert budget.charge_usage({"total_tokens": 400}) == 400
    assert budget.spent == 400
    assert budget.charge_usage(None) == 0
    assert budget.charge_usage({"total_tokens": 0}) == 0


def test_the_estimate_counts_the_tool_block_not_just_the_messages():
    """The tool block is 85% of what is being bounded.

    A budget that counted only the conversation would miss the majority of the
    payload it exists to bound.
    """
    messages = [{"role": "user", "content": "hi"}]
    with_tools = token_budget.estimate_tokens(messages, ALL_TOOLS)
    without = token_budget.estimate_tokens(messages)
    assert with_tools > without * 5


def test_an_unserialisable_part_is_still_counted():
    """A part that silently counted as zero would let the largest payloads
    through the budget untouched."""

    class Weird:
        def __repr__(self):
            return "w" * 4000

    assert token_budget.estimate_tokens(Weird()) >= 900


def test_a_zero_budget_disables_the_bound(monkeypatch):
    monkeypatch.setenv(token_budget.BUDGET_ENV, "0")
    budget = token_budget.LoopBudget()
    assert budget.enabled is False
    budget.charge("x" * 100_000)
    assert budget.exhausted is False


def test_an_unparseable_budget_keeps_the_default(monkeypatch):
    monkeypatch.setenv(token_budget.BUDGET_ENV, "loads")
    assert token_budget.loop_token_budget() == token_budget.DEFAULT_LOOP_TOKEN_BUDGET


def test_stopping_on_budget_is_surfaced_not_silent():
    """A loop that stops silently on a budget is indistinguishable from a model
    that had nothing more to say."""
    budget = token_budget.LoopBudget(limit=10)
    assert budget.summary() == ""
    budget.stopped_on_budget = True
    budget.iterations = 3
    assert "budget" in budget.summary()
    assert "3" in budget.summary()
