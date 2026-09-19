"""
Anti-regression guard — no surface builder may shadow an a2ui_helpers name.

The federation_knowledge surface crashed in production with
    UnboundLocalError: cannot access local variable 'text'
because it assigned `text = "..."` inside the function, which made
the earlier `text("fed-title", ...)` call fail — Python's scoping
rule marks `text` as local throughout the whole function once it's
assigned anywhere inside.

This test walks every surface builder's AST and refuses a local
assignment to any name that collides with an a2ui_helpers export.

Classification: ADVERSARIAL (hostile programmer writes `text = "hi"`)
"""

from __future__ import annotations

import ast
import inspect

import a2ui_helpers
import surfaces


def _helper_names() -> set[str]:
    """Every public name exported by a2ui_helpers that produces a component."""
    return {name for name in dir(a2ui_helpers) if not name.startswith("_") and callable(getattr(a2ui_helpers, name))}


def _surface_builder_sources() -> dict[str, str]:
    """Return {builder_name: source} for every SURFACE_BUILDERS entry."""
    out: dict[str, str] = {}
    for page_id, builder in surfaces.SURFACE_BUILDERS.items():
        try:
            out[page_id] = inspect.getsource(builder)
        except (OSError, TypeError):
            # Some callables (lambdas, partials) don't have inspectable source.
            continue
    return out


def _assigned_names_in(source: str) -> set[str]:
    """Collect every Name being *assigned to* at the function's local scope."""
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
                elif isinstance(target, (ast.Tuple, ast.List)):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            names.add(elt.id)
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                names.add(node.target.id)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                names.add(node.target.id)
    return names


def test_no_surface_builder_shadows_an_a2ui_helper():
    """ADVERSARIAL: a surface builder that assigns to a helper name will
    crash at runtime with UnboundLocalError — caught in prod for
    build_federation_knowledge_surface on 2026-04-19. This test walks
    every builder's AST to catch it before merge."""
    helpers = _helper_names()
    violations: list[str] = []
    for page_id, source in _surface_builder_sources().items():
        assigned = _assigned_names_in(source)
        overlap = assigned & helpers
        if overlap:
            violations.append(f"{page_id}: shadows {sorted(overlap)}")
    assert not violations, (
        "Surface builder(s) shadow a2ui_helpers names, which will cause "
        "UnboundLocalError at runtime:\n  " + "\n  ".join(violations)
    )


def test_every_surface_builder_is_inspectable():
    """EDGE: every builder must have source we can inspect.
    Lambdas + functools.partial are not allowed."""
    for page_id, builder in surfaces.SURFACE_BUILDERS.items():
        try:
            inspect.getsource(builder)
        except (OSError, TypeError):
            raise AssertionError(
                f"surface builder {page_id!r} has no inspectable source — "
                f"use a named `async def`, not a lambda or partial"
            ) from None


def test_helper_names_are_discoverable():
    """Sanity: we found the helpers we're guarding against shadowing of."""
    helpers = _helper_names()
    assert "text" in helpers
    assert "column" in helpers
    assert "surface" in helpers
    assert "heading" in helpers
