"""Tiering picks a cheaper model, and measurement decides where it may not.

⚠️ THE DISQUALIFYING RISK IS MEASURED, NOT HYPOTHETICAL. The committed probe
(``docs/integrations/llm-compat-probe.json``, five trials per model) found four
models and four different forced-``tool_choice`` behaviours:

    llama3.1:8b        supported   honoured 5 of 5
    phi3:mini          rejected    HTTP 400, 5 of 5
    qwen2.5-coder:14b  ignored     honoured 0 of 5
    qwen2.5:14b        ignored     honoured 2 OF 5

The 400 is the GOOD failure — loud and immediate. The 2-of-5 is the dangerous
one: a call site that works three times in five reads as bad luck rather than as
a misconfiguration, and its failure shape is an empty plan, which is the
production zero-output signature this track exists to remove. So "ignored" covers
both the 0-of-5 and the 2-of-5 model, and that is the correct classification —
partial honouring is not support.

These tests therefore assert two different things and both matter: that tiering
HAPPENS where it is safe (a saving nobody gets is not a saving), and that it is
REFUSED where measurement says it should be.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "server"))

import llm_runtime  # noqa: E402


class _Caps:
    def __init__(self, forced_tool_choice: str) -> None:
        self.forced_tool_choice = forced_tool_choice


def _lookup(status: str):
    return lambda _model: _Caps(status)


# ── the registry, not a parallel table ───────────────────────────────────────


def test_every_provider_declares_every_tier() -> None:
    """A call site names a tier without knowing which provider it will get, so a
    provider missing one would resolve to a KeyError at a call site rather than
    at configuration time."""
    for name, spec in llm_runtime.PROVIDERS.items():
        for tier in llm_runtime.TIERS:
            assert spec.models.get(tier), f"{name} declares no {tier} model"


def test_tiering_reads_the_shared_registry_rather_than_a_second_table() -> None:
    """The resolver already owned (provider, tier) -> model. A parallel table is
    how five provider tables came to disagree about base URLs, which is the thing
    the resolver work removed."""
    for tier in llm_runtime.TIERS:
        chosen = llm_runtime.model_for_tier("anthropic", tier)
        assert chosen.model == llm_runtime.PROVIDERS["anthropic"].models[tier]


# ── tiering happens ──────────────────────────────────────────────────────────


def test_the_fast_tier_is_actually_cheaper_where_a_provider_offers_one() -> None:
    """⚠️ A GUARD THAT ONLY EVER REFUSES WOULD PASS EVERY TEST BELOW AND SAVE
    NOTHING. At least one provider must genuinely move, or tiering is decoration."""
    moved = [
        name
        for name, spec in llm_runtime.PROVIDERS.items()
        if spec.models[llm_runtime.TIER_FAST] != spec.models[llm_runtime.TIER_BALANCED]
    ]
    assert moved, "no provider's fast tier differs from its balanced model"

    for name in moved:
        choice = llm_runtime.model_for_tier(name, llm_runtime.TIER_FAST)
        assert choice.tiered, f"{name}: {choice.refused_reason}"
        assert choice.model == llm_runtime.PROVIDERS[name].models[llm_runtime.TIER_FAST]


def test_an_unmeasured_model_still_tiers_by_default() -> None:
    """Unknown is not a measured failure. Refusing on absence of evidence would
    disable tiering for every provider in the table — see the measurement in
    ``test_no_registry_fast_model_is_measured_yet``."""
    choice = llm_runtime.model_for_tier("anthropic", llm_runtime.TIER_FAST, caps_lookup=_lookup("unknown"))
    assert choice.tiered
    assert choice.model == "claude-haiku-4-5"


# ── tiering is refused ───────────────────────────────────────────────────────


@pytest.mark.parametrize("status", ["ignored", "rejected"])
def test_a_measured_failure_refuses_the_tier_and_says_why(status: str) -> None:
    choice = llm_runtime.model_for_tier("anthropic", llm_runtime.TIER_FAST, caps_lookup=_lookup(status))

    assert not choice.tiered
    assert choice.model == llm_runtime.PROVIDERS["anthropic"].models[llm_runtime.TIER_BALANCED]
    assert choice.requested_tier == llm_runtime.TIER_FAST
    assert status in choice.refused_reason


def test_the_two_of_five_model_is_refused_by_the_same_rule_as_the_zero_of_five() -> None:
    """⚠️ THE CASE THIS UNIT EXISTS TO EXCLUDE, DRIVEN FROM THE COMMITTED PROBE
    RATHER THAN FROM A LITERAL. Both qwen models are classified "ignored" — one
    honoured the constraint 0 of 5 times and the other 2 of 5 — and both must be
    refused, because a control that works 40% of the time is not a control."""
    probe = json.loads((REPO / "docs" / "integrations" / "llm-compat-probe.json").read_text())
    partial = probe["models"]["qwen2.5:14b"]
    assert partial["caps"]["forced_tool_choice"] == "ignored", "the probe's own classification moved"

    status = partial["caps"]["forced_tool_choice"]
    choice = llm_runtime.model_for_tier("anthropic", llm_runtime.TIER_FAST, caps_lookup=_lookup(status))
    assert not choice.tiered, "a model that honours a forced tool_choice 2 of 5 times was tiered onto"


def test_a_refused_tier_falls_back_rather_than_raising() -> None:
    """The tier is an optimisation, and the failure mode of an optimisation is
    that it does not happen — not that the call site breaks."""
    choice = llm_runtime.model_for_tier("anthropic", llm_runtime.TIER_FAST, caps_lookup=_lookup("rejected"))
    assert choice.model  # a usable model, not an exception and not empty


def test_requiring_a_measurement_is_opt_in_and_refuses_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """The stricter posture — a POSITIVE measurement before moving any call — is
    available and off. It is off because of the measurement in the next test."""
    monkeypatch.setenv(llm_runtime.TIER_REQUIRE_MEASURED_ENV, "true")
    choice = llm_runtime.model_for_tier("anthropic", llm_runtime.TIER_FAST, caps_lookup=_lookup("unknown"))
    assert not choice.tiered
    assert llm_runtime.TIER_REQUIRE_MEASURED_ENV in choice.refused_reason

    monkeypatch.setenv(llm_runtime.TIER_REQUIRE_MEASURED_ENV, "")
    assert llm_runtime.model_for_tier("anthropic", llm_runtime.TIER_FAST, caps_lookup=_lookup("unknown")).tiered


def test_no_registry_fast_model_is_measured_yet() -> None:
    """⚠️ THE MEASUREMENT THAT DECIDES THE DEFAULT ABOVE, ASSERTED SO IT CANNOT GO
    STALE SILENTLY. The probe ran against local ollama models; not one model named
    in the tier table has been measured. If that ever changes this test fails, and
    the failure is the prompt to reconsider whether the strict posture should
    become the default rather than a knob."""
    probe = json.loads((REPO / "docs" / "integrations" / "llm-compat-probe.json").read_text())
    measured = set(probe["models"])
    tier_models = {
        spec.models[llm_runtime.TIER_FAST] for spec in llm_runtime.PROVIDERS.values()
    }
    overlap = measured & tier_models
    assert not overlap, (
        f"{sorted(overlap)} is now measured — reconsider whether "
        f"{llm_runtime.TIER_REQUIRE_MEASURED_ENV} should default on"
    )


# ── which call sites may be tiered ───────────────────────────────────────────


def test_every_tiered_call_site_caps_its_output_and_forces_no_tool_choice() -> None:
    """⚠️ THE RULE THAT KEEPS THE 2-OF-5 RISK OFF THESE SITES, CHECKED AGAINST THE
    SOURCE RATHER THAN TRUSTED. A site that forces tool_choice must not be moved;
    a site with no output cap is not what the saving was measured on."""
    source = (REPO / "server" / "think_cycle.py").read_text()
    lines = source.split("\n")
    tiered = [i for i, ln in enumerate(lines) if "model=FAST_MODEL," in ln]
    assert len(tiered) >= 6, f"expected the measured fast sites, found {len(tiered)}"

    for i in tiered:
        indent = len(lines[i]) - len(lines[i].lstrip())
        close = next(
            k
            for k in range(i + 1, len(lines))
            if lines[k].strip().startswith(")") and (len(lines[k]) - len(lines[k].lstrip())) < indent
        )
        body = "\n".join(lines[i:close])
        caps = [int(c) for c in re.findall(r"max_tokens=(\d+)", body)]
        assert caps, f"line {i + 1}: a tiered call sets no max_tokens"
        assert max(caps) <= 100, f"line {i + 1}: max_tokens={max(caps)} is not a fast-tier site"
        assert "tool_choice" not in body, f"line {i + 1}: a tiered call forces tool_choice"


def test_the_planner_and_the_surface_composer_are_not_tiered() -> None:
    """Named because they are the two sites the probe's finding disqualifies."""
    planner = (REPO / "agent" / "community_member" / "planner_llm.py").read_text()
    assert "FAST_MODEL" not in planner, "the planner forces tool_choice and must stay deep"

    chapter = (REPO / "server" / "chapter_agent.py").read_text()
    for line in chapter.split("\n"):
        if "sc.compose(" in line or "surface_composer.compose(" in line:
            assert "FAST_MODEL" not in line, "surface composition must stay deep"


def test_settings_still_shows_a_resolved_model_and_no_literal() -> None:
    """Pinned elsewhere and re-asserted here, because this unit adds two more
    model-valued names and the temptation to write one into settings grows."""
    settings = (REPO / "server" / "settings.py").read_text()
    for literal in ("claude-", "gpt-4", "grok-", "llama-3", "llama3"):
        for line in settings.split("\n"):
            code = line.split("#")[0]
            assert literal not in code, f"settings.py names a model literal: {line.strip()}"
