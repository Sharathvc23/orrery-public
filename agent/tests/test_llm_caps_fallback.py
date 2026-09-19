"""The measured-capability record, and the planner path it selects.

WHAT THIS GUARDS. ``planner_llm.plan_from_llm`` forces a ``tool_choice`` and
reads ``message.tool_calls``. A provider that ignores the constraint answers
HTTP 200 with free text and no tool call, and the planner turns that into an
empty Plan with no exception — so an agent pointed at such a model loops at its
normal rate producing nothing, and nothing in the stack says why. These tests
cover the record that names such a model and the branch that avoids it.

Three properties are asserted rather than assumed, because each one is a way
the guard could be worse than useless:

  * An UNMEASURED model behaves exactly as it did before the record existed.
    If ``unknown`` changed the request shape, adding a probe file would change
    behaviour for every deployment that never ran the probe.
  * A model measured to fail BOTH shapes triggers no request at all. Spending
    a call to rediscover a measured fact every cycle is the waste being fixed.
  * The JSON-mode fallback requires JSON mode to be MEASURED supported, never
    merely unknown — because that path parses ``message.content``, and content
    is safe to parse only when the endpoint constrained it.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from community_member.llm_caps import (
    IGNORED,
    REJECTED,
    SUPPORTED,
    UNKNOWN,
    ModelCaps,
    caps_for,
    load_probe,
)
from community_member.planner import PlannerContext, TrustedContext
from community_member.planner_llm import plan_from_llm


class RecordingLLM:
    """OpenAI-compatible stub that records every call it receives."""

    def __init__(self, response=None):
        self._response = response
        self.calls: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if self._response is None:
            raise AssertionError("the planner made a call it should have skipped")
        return self._response


def _tool_response(args: dict):
    call = SimpleNamespace(function=SimpleNamespace(name="propose_actions", arguments=json.dumps(args)))
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[call]))])


def _content_response(text: str | None):
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text, tool_calls=None))])


def _ctx() -> PlannerContext:
    return PlannerContext(
        user_task="greet two new members",
        trusted=TrustedContext(items=("the user wants greetings",)),
    )


_PLAN_ARGS = {
    "summary": "greet them",
    "proposals": [
        {
            "capability": "net.http",
            "scope": "https://example.test",
            "context": "greeting",
            "provenance": "trusted",
        }
    ],
}


# ── the record ──────────────────────────────────────────────────────


def test_unmeasured_model_reads_as_unknown_and_stays_usable():
    caps = caps_for("never-probed:1b", {})
    assert caps.forced_tool_choice == UNKNOWN
    assert caps.forced_tool_choice_usable is True
    # Stricter on the fallback: unknown is NOT good enough to start parsing
    # message content.
    assert caps.json_object_usable is False


def test_measured_failures_are_not_usable():
    assert ModelCaps("m", forced_tool_choice=IGNORED).forced_tool_choice_usable is False
    assert ModelCaps("m", forced_tool_choice=REJECTED).forced_tool_choice_usable is False
    assert ModelCaps("m", forced_tool_choice=SUPPORTED).forced_tool_choice_usable is True


def test_lookup_is_exact_not_prefix():
    """One pin's PASS must never vouch for another's.

    ``llama3.1:8b`` and ``llama3.1:70b`` are different measurements. A prefix
    match would let a measured model answer for an unmeasured one.
    """
    table = {"llama3.1:8b": ModelCaps("llama3.1:8b", forced_tool_choice=SUPPORTED)}
    assert caps_for("llama3.1:70b", table).forced_tool_choice == UNKNOWN


def test_probe_file_round_trips(tmp_path):
    path = tmp_path / "probe.json"
    path.write_text(
        json.dumps(
            {
                "schema": "llm-compat-probe/1",
                "models": {
                    "qwen2.5:14b": {
                        "caps": {
                            "forced_tool_choice": IGNORED,
                            "json_object_response_format": SUPPORTED,
                        }
                    }
                },
            }
        )
    )
    table = load_probe(path)
    assert table["qwen2.5:14b"].forced_tool_choice == IGNORED
    assert table["qwen2.5:14b"].json_object_usable is True


def test_unreadable_probe_is_no_measurement_not_a_crash(tmp_path):
    """A malformed or missing file must not stop an agent from running.

    It degrades to 'nothing was measured', which routes every model down the
    unchanged path — never to a guess, and never to an exception on a path
    that has nothing to do with capability detection.
    """
    missing = tmp_path / "absent.json"
    assert load_probe(missing) == {}

    garbage = tmp_path / "garbage.json"
    garbage.write_text("{not json")
    assert load_probe(garbage) == {}

    wrong_schema = tmp_path / "wrong.json"
    wrong_schema.write_text(json.dumps({"schema": "something-else/9", "models": {}}))
    assert load_probe(wrong_schema) == {}


# ── the branch ──────────────────────────────────────────────────────


def test_no_caps_keeps_the_forced_tool_choice_path_unchanged():
    llm = RecordingLLM(_tool_response(_PLAN_ARGS))
    plan = plan_from_llm(_ctx(), llm, model="anything")
    assert len(plan.proposals) == 1
    sent = llm.calls[0]
    assert sent["tool_choice"]["function"]["name"] == "propose_actions"
    assert "response_format" not in sent


def test_unknown_caps_keeps_the_forced_tool_choice_path_unchanged():
    llm = RecordingLLM(_tool_response(_PLAN_ARGS))
    plan_from_llm(_ctx(), llm, model="never-probed", caps=ModelCaps("never-probed"))
    assert llm.calls[0]["tool_choice"]["function"]["name"] == "propose_actions"


def test_measured_ignored_falls_back_to_json_mode():
    """The case reproduced against a real local model.

    Forced ``tool_choice`` measured ``ignored``, JSON mode measured
    ``supported``: the planner must ask for the object through
    ``response_format`` and must not send a tool constraint the model was
    measured to drop.
    """
    llm = RecordingLLM(_content_response(json.dumps(_PLAN_ARGS)))
    caps = ModelCaps(
        "qwen2.5:14b",
        forced_tool_choice=IGNORED,
        json_object_response_format=SUPPORTED,
    )
    plan = plan_from_llm(_ctx(), llm, model="qwen2.5:14b", caps=caps)

    assert len(plan.proposals) == 1
    assert plan.summary == "greet them"
    sent = llm.calls[0]
    assert sent["response_format"] == {"type": "json_object"}
    assert "tools" not in sent
    assert "tool_choice" not in sent


def test_measured_rejected_falls_back_to_json_mode():
    """A 4xx on tools is as disqualifying as a silent drop.

    ``phi3:mini`` answers 400 'does not support tools' and still serves JSON
    mode, so the fallback is the only path that produces a plan at all.
    """
    llm = RecordingLLM(_content_response(json.dumps(_PLAN_ARGS)))
    caps = ModelCaps(
        "phi3:mini",
        forced_tool_choice=REJECTED,
        json_object_response_format=SUPPORTED,
    )
    plan = plan_from_llm(_ctx(), llm, model="phi3:mini", caps=caps)
    assert len(plan.proposals) == 1
    assert llm.calls[0]["response_format"] == {"type": "json_object"}


def test_both_shapes_measured_failing_makes_no_call_at_all():
    """The empty-plan burn, stopped at its source.

    RecordingLLM raises if called. A model with no working request shape must
    not be asked once per cycle to demonstrate a fact already measured.
    """
    llm = RecordingLLM(None)
    caps = ModelCaps(
        "toy:1b",
        forced_tool_choice=IGNORED,
        json_object_response_format=IGNORED,
    )
    plan = plan_from_llm(_ctx(), llm, model="toy:1b", caps=caps)
    assert plan.proposals == ()
    assert "no request made" in plan.summary
    assert llm.calls == []


def test_json_mode_reply_that_is_not_json_yields_an_empty_plan():
    llm = RecordingLLM(_content_response("I'd be happy to help!"))
    caps = ModelCaps(
        "qwen2.5:14b",
        forced_tool_choice=IGNORED,
        json_object_response_format=SUPPORTED,
    )
    plan = plan_from_llm(_ctx(), llm, model="qwen2.5:14b", caps=caps)
    assert plan.proposals == ()
    assert "not valid JSON" in plan.summary


def test_json_mode_empty_reply_yields_an_empty_plan():
    llm = RecordingLLM(_content_response(""))
    caps = ModelCaps(
        "qwen2.5:14b",
        forced_tool_choice=IGNORED,
        json_object_response_format=SUPPORTED,
    )
    plan = plan_from_llm(_ctx(), llm, model="qwen2.5:14b", caps=caps)
    assert plan.proposals == ()
    assert "empty" in plan.summary


def test_json_mode_keeps_the_provenance_downgrade():
    """The fallback changes the request shape, not the trust treatment.

    An unrecognised provenance string coming back through JSON mode must be
    coerced to 'untrusted' exactly as it is on the tool path — otherwise the
    fallback would be a way to launder authorization.
    """
    args = {
        "summary": "s",
        "proposals": [
            {
                "capability": "shell.exec",
                "scope": "rm",
                "context": "c",
                "provenance": "totally-trusted-honest",
            }
        ],
    }
    llm = RecordingLLM(_content_response(json.dumps(args)))
    caps = ModelCaps(
        "qwen2.5:14b",
        forced_tool_choice=IGNORED,
        json_object_response_format=SUPPORTED,
    )
    plan = plan_from_llm(_ctx(), llm, model="qwen2.5:14b", caps=caps)
    assert plan.proposals[0].provenance == "untrusted"
