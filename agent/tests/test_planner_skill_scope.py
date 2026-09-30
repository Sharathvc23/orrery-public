"""A skill.invoke must name a skill and a tool — in BOTH planner paths.

⚠️ THE BUG THIS CLOSES, found on a live agent rather than in review.

`_skill_consent_scope` builds the entire consent scope for a `skill.invoke`
from `extra`. The function-calling schema documented `extra` all along. The JSON
fallback instruction did not mention it at all — so on a model that falls back to
JSON mode, every skill.invoke was malformed by construction:

    skill.invoke  scope="::::44136fa355b3678a"  context="initial_situation_review"

The consent gate accepted it, because its check is `if not req.scope` and that
string is truthy. A human was then asked to approve an action naming nothing.

WHY IT IS WORSE THAN A WASTED PROMPT. Graduation keys on
(device_did, capability, scope, context_sha256). Five approvals of that scope
would become a STANDING auto-approval matching every future malformed proposal
with no skill, no tool and empty args — a wildcard grant earned by approving what
looked like a single harmless action.

One contract, two places, only one kept correct. The load-bearing test is
`test_both_planner_paths_require_the_same_fields`.
"""

from __future__ import annotations

import json

import pytest

from community_member import planner_llm as P

# ── the scope refuses to name nothing ───────────────────────────────────────


def test_a_well_formed_skill_invoke_gets_a_real_scope():
    scope = P._skill_consent_scope({"skill_id": "datetime@1.0.0", "tool_name": "now", "args": {}})

    assert scope.startswith("datetime@1.0.0::now::")
    assert scope.count("::") == 2


@pytest.mark.parametrize(
    "extra",
    [
        {},
        {"args": {}},
        {"skill_id": "datetime@1.0.0"},
        {"tool_name": "now"},
        {"skill_id": "", "tool_name": "now"},
        {"skill_id": "datetime@1.0.0", "tool_name": ""},
        {"skill_id": None, "tool_name": None},
    ],
)
def test_a_skill_invoke_naming_nothing_is_refused(extra):
    with pytest.raises(ValueError, match="requires extra.skill_id and extra.tool_name"):
        P._skill_consent_scope(extra)


def test_control_the_old_behaviour_produced_a_truthy_scope():
    """Why the consent gate could not catch this: the broken scope was a
    non-empty string, and the gate's check is `if not req.scope`."""
    broken = "::::" + "0" * 16

    assert broken, "the gate's emptiness check would have passed this"
    assert broken.count("::") == 2, "and it has the right shape, so it looks legitimate"


# ── the two paths describe the same contract ────────────────────────────────


def test_both_planner_paths_require_the_same_fields():
    """The load-bearing test. The function schema and the JSON instruction are
    two descriptions of one contract; the bug was one of them drifting."""
    schema = json.dumps(P.PROPOSE_ACTIONS_SCHEMA)
    instruction = P.JSON_MODE_INSTRUCTION

    for field in ("capability", "scope", "context", "provenance", "source_ref", "rationale", "extra"):
        assert field in schema, f"{field} missing from the function schema"
        assert field in instruction, f"{field} missing from the JSON instruction"


def test_the_json_instruction_tells_the_model_what_extra_holds():
    """Naming `extra` is not enough — a model that does not know it needs
    skill_id and tool_name will omit them, which is exactly what happened."""
    instruction = P.JSON_MODE_INSTRUCTION

    assert "skill_id" in instruction
    assert "tool_name" in instruction


def test_the_extra_guidance_is_derived_not_duplicated():
    """If the instruction restated the schema's wording, the two could drift
    apart again. It is computed from the schema, so it cannot."""
    described = P.PROPOSE_ACTIONS_SCHEMA["function"]["parameters"]["properties"]
    described = described["proposals"]["items"]["properties"]["extra"]["description"]

    assert described in P.JSON_MODE_INSTRUCTION


# ── one bad proposal does not cost the good ones ────────────────────────────


def _raw(capability="fs.read", **kw):
    base = {"capability": capability, "scope": "/tmp/x", "context": "c", "provenance": "trusted", "rationale": "r"}
    base.update(kw)
    return base


def test_an_unbuildable_proposal_is_dropped_not_fatal():
    """Built inside a tuple(...) generator, one refusal would abort the whole
    plan — trading a bogus prompt for a dead cycle."""
    parsed = {
        "summary": "s",
        "proposals": [
            _raw(),
            _raw("skill.invoke", extra={}),  # names no skill or tool
            _raw("skill.invoke", extra={"skill_id": "datetime@1.0.0", "tool_name": "now", "args": {}}),
        ],
    }

    plan = P._plan_from_arguments(parsed)

    assert len(plan.proposals) == 2, "a dropped proposal took a good one with it"
    assert {p.capability for p in plan.proposals} == {"fs.read", "skill.invoke"}


def test_the_drop_is_counted_in_the_summary():
    """A plan that quietly shrank is indistinguishable from a model that
    proposed less."""
    parsed = {"summary": "s", "proposals": [_raw("skill.invoke", extra={})]}

    plan = P._plan_from_arguments(parsed)

    assert plan.proposals == ()
    assert "unbuildable proposal(s) dropped" in plan.summary
    assert "skill_id" in plan.summary, "the summary must say what was wrong"


def test_a_plan_of_only_good_proposals_says_nothing_about_drops():
    parsed = {"summary": "s", "proposals": [_raw()]}

    plan = P._plan_from_arguments(parsed)

    assert len(plan.proposals) == 1
    assert "dropped" not in plan.summary
