"""The org-side LLM meter, and the settings surface that names what it costs.

Two defects this file pins:

* ``settings.DEFAULTS`` asserted a model the chapter does not run. On a box with
  only ``XAI_API_KEY`` set it runs ``grok-3-mini``; the surface said
  ``claude-opus-4-7``. Restating the right literal would have been the same bug
  with a fresher string, so the guard is that NO model literal lives there.
* A token total that silently includes calls whose provider reported no usage
  looks complete and is not. Observed and unobserved are held apart.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import agent_telemetry
import settings

SETTINGS_SOURCE = Path(settings.__file__)


# ── the surface names what actually executes ─────────────────────────────────


def test_the_displayed_model_is_the_one_the_chapter_executes(monkeypatch):
    """Read off llm_config's constants — the same ones build_client() uses — so
    the pair displayed cannot drift from the pair executed."""
    import llm_config

    monkeypatch.setattr(llm_config, "PROVIDER", "anthropic")
    monkeypatch.setattr(llm_config, "DEFAULT_MODEL", "claude-sonnet-4-6")
    assert settings.resolved_llm() == {"provider": "anthropic", "model": "claude-sonnet-4-6"}

    monkeypatch.setattr(llm_config, "PROVIDER", "xai")
    monkeypatch.setattr(llm_config, "DEFAULT_MODEL", "grok-3-mini")
    assert settings.resolved_llm() == {"provider": "xai", "model": "grok-3-mini"}


def test_settings_declares_no_model_literal_of_its_own():
    """REGRESSION GUARD, and the reason it is written this way.

    The bug was a hardcoded ``claude-opus-4-7`` next to a runtime that resolved
    something else. Asserting the new correct string would leave the same defect
    one model release away from returning. So: the module may not contain a
    model literal at all — the value has to come from the thing that executes.
    """
    source = SETTINGS_SOURCE.read_text()
    # Ignore comments: the docstring explains the old value on purpose.
    code = "\n".join(line.split("#")[0] for line in source.splitlines())
    offenders = re.findall(r"[\"'](?:claude|gpt|grok|llama|gemini)[-\w.]*[\"']", code, flags=re.I)
    assert offenders == [], f"settings.py hardcodes model name(s): {offenders}"


def test_the_unresolvable_case_says_unknown_rather_than_guessing(monkeypatch):
    """If llm_config cannot be read, the surface must not fall back to a
    plausible model name — an operator cannot tell a guess from a fact."""
    import builtins

    real_import = builtins.__import__

    def _fail(name, *args, **kwargs):
        if name == "llm_config":
            raise ImportError("simulated")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fail)
    assert settings.resolved_llm() == {"provider": "unknown", "model": "unknown"}


def test_effective_defaults_resolves_llm_and_leaves_every_other_section_alone():
    effective = settings.effective_defaults()
    assert effective["llm"] == settings.resolved_llm()
    for section in set(settings.DEFAULTS) - {"llm"}:
        assert effective[section] == settings.DEFAULTS[section]


def test_the_settings_schema_is_unchanged():
    """The fix must not quietly add or drop a settings section."""
    assert settings.VALID_TOP_LEVEL_KEYS == frozenset(settings.DEFAULTS.keys())
    assert set(settings.effective_defaults()) == set(settings.DEFAULTS)


# ── the meter: observed is never mixed with unobserved ───────────────────────


@pytest.fixture
def meter():
    return agent_telemetry.AgentTelemetry()


def _call(meter, **overrides):
    args = {
        "side": "org",
        "callsite": "planner",
        "principal": "member-a",
        "provider": "xai",
        "model": "grok-3-mini",
        "usage": {"input_tokens": 100, "output_tokens": 20, "cached_tokens": 5},
    }
    args.update(overrides)
    meter.record_llm(**args)


def test_a_call_with_no_usage_report_adds_no_tokens_and_is_counted(meter):
    """⚠️ THE CENTRAL PROPERTY. An absent usage report is not zero. If it were
    folded in, the totals would look like a complete measurement of two calls
    while covering one."""
    _call(meter)
    _call(meter, usage=None)
    totals = meter.get_llm_spend()["totals"]
    assert totals["llm_calls"] == 2
    assert totals["llm_calls_without_usage"] == 1
    assert totals["llm_input_tokens"] == 100, "the unreported call must contribute nothing"
    assert totals["llm_output_tokens"] == 20


def test_usage_figures_accumulate_across_calls(meter):
    """The guard has to be able to pass, not only to catch the absent case."""
    _call(meter)
    _call(meter)
    totals = meter.get_llm_spend()["totals"]
    assert (totals["llm_input_tokens"], totals["llm_output_tokens"], totals["llm_cached_tokens"]) == (200, 40, 10)
    assert totals["llm_calls_without_usage"] == 0


def test_two_principals_are_never_summed_into_one_row(meter):
    """Per-principal from day one. member_runtime.think() has no caller today;
    wired on a 245-member chapter it is a per-member multiplier, and an unkeyed
    meter would show that as ordinary growth."""
    _call(meter, principal="member-a")
    _call(meter, principal="member-b")
    spend = meter.get_llm_spend()
    principals = {row["principal"] for row in spend["series"]}
    assert principals == {"member-a", "member-b"}
    assert spend["series_count"] == 2


@pytest.mark.parametrize("field", ["side", "callsite", "provider", "model"])
def test_every_key_field_separates_rows(meter, field):
    _call(meter, **{field: "one"})
    _call(meter, **{field: "two"})
    assert meter.get_llm_spend()["series_count"] == 2


def test_a_missing_principal_is_visible_rather_than_blended(meter):
    _call(meter, principal="")
    assert meter.get_llm_spend()["series"][0]["principal"] == "unknown"


# ── skips are the thing the optimisation will be judged on ───────────────────


def test_a_skip_is_counted_with_its_reason(meter):
    """A skip that is not counted cannot be proven, and a regression in it
    cannot be detected — the reason the meter ships before the saving."""
    meter.record_llm_skip(
        side="org", callsite="planner", principal="member-a", provider="xai",
        model="grok-3-mini", reason="no_change_since_last_cycle",
    )
    totals = meter.get_llm_spend()["totals"]
    assert totals["llm_calls_skipped"] == 1
    assert totals["llm_skip_reason"] == {"no_change_since_last_cycle": 1}
    assert totals["llm_calls"] == 0, "a skipped call is not a call"


def test_skip_reasons_are_kept_apart(meter):
    for reason in ("cache_hit", "cache_hit", "budget_window"):
        meter.record_llm_skip(
            side="org", callsite="planner", principal="p", provider="xai",
            model="grok-3-mini", reason=reason,
        )
    assert meter.get_llm_spend()["totals"]["llm_skip_reason"] == {"cache_hit": 2, "budget_window": 1}


# ── the bound is reported, never silent ──────────────────────────────────────


def test_overflow_is_folded_and_counted_rather_than_dropped():
    """A meter that quietly stops recording is indistinguishable from spend
    that stopped, which is the worse of the two failures."""
    meter = agent_telemetry.AgentTelemetry(max_llm_series=2)
    for n in range(5):
        _call(meter, principal=f"member-{n}")
    spend = meter.get_llm_spend()
    assert spend["series_folded"] == 3
    assert spend["totals"]["llm_calls"] == 5, "every call is still counted, even when folded"
    assert any(row["principal"] == "__overflow__" for row in spend["series"])


def test_the_snapshot_says_it_is_record_only_and_observation_only(meter):
    """The reader has to be able to tell what kind of number this is without
    reading the source: no prices, and no estimates."""
    spend = meter.get_llm_spend()
    assert spend["record_only"] is True
    assert spend["observed_usage_only"] is True
    assert not any("price" in k or "cost" in k or "usd" in k for k in spend["totals"])
