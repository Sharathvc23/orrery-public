"""
Tests for build_policy_surface — leader-visible policy observability.

Covers the observability enhancements on top of the base render:
  - warmup-state indicator when no tune has happened yet
  - sample size + window caption when tuned
  - bounds ([0.5x, 2x] of baseline) for tunable numeric keys
  - empty state
  - module-unavailable failure mode
  - adversarial key names don't crash ID generation

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

from __future__ import annotations

import pytest

import policy
import surfaces


class _FakePolicyModule:
    """Stand-in for the `policy` module — returns a configurable row list."""

    def __init__(self, rows: list[dict]):
        self._rows = rows

    async def list_all(self) -> list[dict]:
        return list(self._rows)


def _extract_components(surface_dict: dict) -> list[dict]:
    """A2UI v0.9 nests components under updateComponents.components."""
    update = surface_dict.get("updateComponents") or {}
    return update.get("components", [])


def _component_text(components: list[dict]) -> list[str]:
    """Flatten every text-bearing component's text content for substring asserts."""
    out: list[str] = []
    for c in components:
        for field in ("text", "label", "value", "action", "suffix", "caption"):
            v = c.get(field)
            if isinstance(v, (str, int, float)):
                out.append(str(v))
    return out


# ══════════════════════════════════════════════════════════════
# HAPPY — tunable key shows sample size, window, and bounds
# ══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_tunable_row_shows_sample_window_and_bounds(monkeypatch):
    row = {
        "key": "intro.confidence_floor",
        "value": 0.6,
        "baseline": 0.5,
        "value_type": "float",
        "auto_tuned": True,
        "pinned_by": None,
        "last_tune_reason": "positive intro-accept rate → loosen floor",
        "last_tune_sample_size": 25,
        "last_tune_outcome_window_days": 14,
    }
    # Patch the policy import inside build_policy_surface
    monkeypatch.setitem(
        __import__("sys").modules,
        "policy",
        _FakePolicyModule([row]),
    )

    result = await surfaces.build_policy_surface()

    blob = " ".join(_component_text(_extract_components(result)))
    assert "25" in blob and ("14 days" in blob or "14d" in blob), (
        f"expected sample size (25) + window (14 days) in surface; got: {blob[:500]}"
    )
    # bounds: 0.5 × 0.5 = 0.25; 2 × 0.5 = 1.0
    assert "0.25" in blob and "1.0" in blob, f"expected bounds [0.25, 1.0] shown; got: {blob[:500]}"

    # Restore the real module after the test
    monkeypatch.setitem(__import__("sys").modules, "policy", policy)


# ══════════════════════════════════════════════════════════════
# EDGE — warmup state (tunable but no tune has happened)
# ══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_warmup_state_shows_warming_up_indicator(monkeypatch):
    row = {
        "key": "call.response_relevance_floor",
        "value": 0.4,
        "baseline": 0.4,
        "value_type": "float",
        "auto_tuned": True,
        "pinned_by": None,
        # warmup: no tune has happened yet — fields are None
        "last_tune_reason": None,
        "last_tune_sample_size": None,
        "last_tune_outcome_window_days": None,
    }
    monkeypatch.setitem(
        __import__("sys").modules,
        "policy",
        _FakePolicyModule([row]),
    )

    result = await surfaces.build_policy_surface()

    blob = " ".join(_component_text(_extract_components(result))).lower()
    assert "warm" in blob, f"expected warmup indicator; got: {blob[:500]}"

    monkeypatch.setitem(__import__("sys").modules, "policy", policy)


# ══════════════════════════════════════════════════════════════
# EDGE — pinned key hides auto-tune bounds (it's frozen)
# ══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_pinned_key_does_not_show_bounds_or_sample(monkeypatch):
    row = {
        "key": "intro.cooldown_days",
        "value": 7,
        "baseline": 5,
        "value_type": "int",
        "auto_tuned": True,
        "pinned_by": "leader-alice",
        "pinned_reason": "we learned this the hard way last quarter",
        "last_tune_reason": "was auto-tuning before pin",
        "last_tune_sample_size": 40,
        "last_tune_outcome_window_days": 14,
    }
    monkeypatch.setitem(
        __import__("sys").modules,
        "policy",
        _FakePolicyModule([row]),
    )

    result = await surfaces.build_policy_surface()

    blob = " ".join(_component_text(_extract_components(result)))
    # Pinner should be visible
    assert "leader-alice" in blob
    # Pin reason should surface for leader context
    assert "we learned this" in blob, f"expected pinned_reason shown; got: {blob[:500]}"
    # Bounds computation should NOT run — pinned keys are frozen, bounds are moot
    # (2.5 / 10 would be the bounds if this were tunable; assert they don't appear)
    assert "2.5" not in blob and "10.0" not in blob, f"bounds should be hidden for pinned keys; got: {blob[:500]}"

    monkeypatch.setitem(__import__("sys").modules, "policy", policy)


# ══════════════════════════════════════════════════════════════
# EDGE — int value_type rounds bounds as ints
# ══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_int_baseline_yields_int_bounds(monkeypatch):
    row = {
        "key": "cooldown.hours",
        "value": 10,
        "baseline": 10,
        "value_type": "int",
        "auto_tuned": True,
        "pinned_by": None,
        "last_tune_reason": "stable",
        "last_tune_sample_size": 12,
        "last_tune_outcome_window_days": 14,
    }
    monkeypatch.setitem(
        __import__("sys").modules,
        "policy",
        _FakePolicyModule([row]),
    )

    result = await surfaces.build_policy_surface()

    blob = " ".join(_component_text(_extract_components(result)))
    # 0.5 × 10 = 5; 2 × 10 = 20 — integers, no decimal
    assert "5" in blob and "20" in blob, f"expected int bounds [5, 20]; got: {blob[:500]}"
    # Critically: should NOT render as 5.0, 20.0 for int types
    assert "5.0" not in blob, f"int bounds shouldn't render as float; got: {blob[:500]}"

    monkeypatch.setitem(__import__("sys").modules, "policy", policy)


# ══════════════════════════════════════════════════════════════
# FAILURE — empty policy list renders helpful placeholder
# ══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_empty_policy_shows_placeholder(monkeypatch):
    monkeypatch.setitem(
        __import__("sys").modules,
        "policy",
        _FakePolicyModule([]),
    )

    result = await surfaces.build_policy_surface()

    blob = " ".join(_component_text(_extract_components(result))).lower()
    assert "no policy" in blob or "migration" in blob, f"expected empty-state placeholder; got: {blob[:500]}"

    monkeypatch.setitem(__import__("sys").modules, "policy", policy)


# ══════════════════════════════════════════════════════════════
# FAILURE — policy module unavailable renders graceful card
# ══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_policy_module_missing_renders_unavailable(monkeypatch):
    # Simulate policy being missing from sys.modules AND unimportable
    import builtins
    import sys

    real_import = builtins.__import__
    # Drop policy from sys.modules so a fresh import is forced
    monkeypatch.delitem(sys.modules, "policy", raising=False)

    def _blocking_import(name, *args, **kwargs):
        if name == "policy":
            raise ImportError("policy module unavailable in test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocking_import)

    result = await surfaces.build_policy_surface()

    blob = " ".join(_component_text(_extract_components(result))).lower()
    assert "not available" in blob or "unavailable" in blob, f"expected graceful unavailable card; got: {blob[:500]}"


# ══════════════════════════════════════════════════════════════
# ADVERSARIAL — malicious key name does not crash ID generation
# ══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_adversarial_key_name_does_not_crash(monkeypatch):
    row = {
        "key": "evil<script>alert(1)</script>.key",
        "value": 0.5,
        "baseline": 0.5,
        "value_type": "float",
        "auto_tuned": True,
        "pinned_by": None,
        "last_tune_reason": None,
        "last_tune_sample_size": None,
        "last_tune_outcome_window_days": None,
    }
    monkeypatch.setitem(
        __import__("sys").modules,
        "policy",
        _FakePolicyModule([row]),
    )

    # Must not raise — A2UI renderer is responsible for HTML escaping, but
    # the surface builder must not crash on odd characters in key names.
    result = await surfaces.build_policy_surface()

    assert result is not None
    # The A2UI v0.9 shape has 'updateComponents'; verify structure intact
    assert "updateComponents" in result
    assert len(_extract_components(result)) > 0

    monkeypatch.setitem(__import__("sys").modules, "policy", policy)
