"""Tests for the v0.10 meta-block helpers added in PR-C5.

The helpers are purely additive: existing surfaces continue to emit v0.9.
These tests cover happy path (each namespace, vendor extension, surface
envelope) plus closed-enum failure modes (typo on role / density /
form_factor / breakpoint, vendor key missing the x- prefix).

The tests do NOT exercise the JSON Schema directly — that lives in
``conformance/test_a2ui_v04_schema.py``. Here we verify only the helper
contract: input → output dict shape + fast-fail on enum typos.
"""

from __future__ import annotations

import pytest

from a2ui_helpers import (
    A2UI_VERSION_V010,
    action_button,
    surface_v010,
    text,
    with_meta,
)


def test_with_meta_no_kwargs_is_identity():
    """Calling with_meta() without any namespace kwargs returns the
    component unchanged — it MUST NOT inject an empty meta block."""
    btn = action_button("b1", "Save", "save")
    result = with_meta(btn)
    assert "meta" not in result
    assert result is btn  # mutated in place


def test_with_meta_a11y_happy():
    btn = action_button("b1", "✎", "edit")
    result = with_meta(btn, a11y={"ariaLabel": "Edit profile", "role": "button"})
    assert result["meta"]["a11y"] == {"ariaLabel": "Edit profile", "role": "button"}


def test_with_meta_a11y_role_typo_fails():
    btn = action_button("b1", "x", "x")
    with pytest.raises(ValueError, match="meta.a11y.role"):
        with_meta(btn, a11y={"role": "marquee"})


def test_with_meta_a11y_arialive_typo_fails():
    t = text("t1", "saved")
    with pytest.raises(ValueError, match="meta.a11y.ariaLive"):
        with_meta(t, a11y={"ariaLive": "loud"})


def test_with_meta_responsive_happy():
    t = text("t1", "x")
    result = with_meta(t, responsive={"breakpointHide": "lg", "minWidthCh": 16})
    assert result["meta"]["responsive"]["breakpointHide"] == "lg"
    assert result["meta"]["responsive"]["minWidthCh"] == 16


def test_with_meta_responsive_breakpoint_typo_fails():
    t = text("t1", "x")
    with pytest.raises(ValueError, match="meta.responsive.breakpointHide"):
        with_meta(t, responsive={"breakpointHide": "phone"})


def test_with_meta_responsive_stackbelow_typo_fails():
    t = text("t1", "x")
    with pytest.raises(ValueError, match="meta.responsive.stackBelow"):
        with_meta(t, responsive={"stackBelow": "tiny"})


def test_with_meta_density_happy():
    t = text("t1", "x")
    result = with_meta(t, density={"preferred": "compact"})
    assert result["meta"]["density"] == {"preferred": "compact"}


def test_with_meta_density_typo_fails():
    t = text("t1", "x")
    with pytest.raises(ValueError, match="meta.density.preferred"):
        with_meta(t, density={"preferred": "ultra"})


def test_with_meta_render_passthrough():
    """meta.render has no enum constraints in C1-C4 — passthrough only."""
    t = text("t1", "x")
    result = with_meta(t, render={"tooltip": "saves the form"})
    assert result["meta"]["render"] == {"tooltip": "saves the form"}


def test_with_meta_vendor_happy():
    t = text("t1", "x")
    result = with_meta(t, vendor={"x-acme-tracking": {"id": "abc"}})
    assert result["meta"]["x-acme-tracking"] == {"id": "abc"}


def test_with_meta_vendor_missing_prefix_fails():
    t = text("t1", "x")
    with pytest.raises(ValueError, match="must match"):
        with_meta(t, vendor={"acme-tracking": {}})


def test_with_meta_vendor_underscore_fails():
    """The pattern is ^x-[a-z][a-z0-9-]*$ — no underscores allowed."""
    t = text("t1", "x")
    with pytest.raises(ValueError, match="must match"):
        with_meta(t, vendor={"x-acme_tracking": {}})


def test_with_meta_combined_namespaces():
    """A11y + responsive + density + render + vendor on one component."""
    t = text("t1", "x")
    result = with_meta(
        t,
        a11y={"ariaLabel": "x"},
        responsive={"order": -1},
        density={"preferred": "comfortable"},
        render={"tooltip": "x"},
        vendor={"x-tag": {"v": 1}},
    )
    assert set(result["meta"].keys()) == {"a11y", "responsive", "density", "render", "x-tag"}


def test_surface_v010_no_meta_kwargs_omits_meta():
    """surface_v010 without meta kwargs MUST omit createSurface.meta
    entirely (an empty {} would be a wire artifact)."""
    env = surface_v010("s1", [text("t1", "hi")], "t1")
    assert "meta" not in env["createSurface"]
    assert env["version"] == A2UI_VERSION_V010


def test_surface_v010_density_only():
    env = surface_v010("s1", [text("t1", "x")], "t1", density="compact")
    assert env["createSurface"]["meta"]["density"] == {"preferred": "compact"}
    assert "target" not in env["createSurface"]["meta"]


def test_surface_v010_form_factor_only():
    env = surface_v010("s1", [text("t1", "x")], "t1", form_factor="mobile")
    assert env["createSurface"]["meta"]["target"] == {"formFactor": "mobile"}
    assert "density" not in env["createSurface"]["meta"]


def test_surface_v010_density_typo_fails():
    with pytest.raises(ValueError, match="density.preferred"):
        surface_v010("s1", [text("t1", "x")], "t1", density="ultra")


def test_surface_v010_form_factor_typo_fails():
    with pytest.raises(ValueError, match="formFactor"):
        surface_v010("s1", [text("t1", "x")], "t1", form_factor="watch")


def test_surface_v010_combined_density_target_vendor():
    env = surface_v010(
        "s1",
        [text("t1", "x")],
        "t1",
        density="comfortable",
        form_factor="desktop",
        vendor={"x-theme": {"name": "dark"}},
    )
    meta = env["createSurface"]["meta"]
    assert meta["density"] == {"preferred": "comfortable"}
    assert meta["target"] == {"formFactor": "desktop"}
    assert meta["x-theme"] == {"name": "dark"}
    assert env["version"] == "0.10"
