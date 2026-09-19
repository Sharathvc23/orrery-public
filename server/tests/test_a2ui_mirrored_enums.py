"""Drift guard: every closed set hand-copied out of ``schema/0.4`` must
still equal its source — and the guard must DISCOVER the copies rather
than trust a list someone wrote from memory.

WHY THIS EXISTS. ``a2ui_helpers`` hand-copies closed enums from the A2UI
JSON Schema so server code fails fast on a typo instead of emitting wire
output a renderer silently drops. Before this test the only thing tying
the tuples to the schema was a comment, and that comment named the wrong
file for ``_FORM_FACTOR_ENUM`` (``formFactor`` is defined in
``a2ui-surface.json``, never in ``a2ui-component.json``). The values were
right; nothing checked, so nothing would have said otherwise.

WHY IT IS DISCOVERY-DRIVEN. The brief for this work listed four enums;
there were five. The count was not the real problem — the METHOD was: the
list came from grepping for names already expected, so it could not have
surfaced a name nobody thought of. A guard built the same way would sail
past a sixth mirror the day someone adds one. So nothing here is keyed off
a remembered list:

  * ``_discover`` enumerates candidate mirrors from the module by SHAPE,
    not by name — every module-level constant holding a collection of
    strings. A new mirror is picked up even if it ignores the ``_*_ENUM``
    naming convention, because a convention is one more thing that can
    quietly stop holding.
  * ``_schema_enum_index`` enumerates every ``enum`` in every file under
    ``schema/0.4``, so the SOURCE side is discovered too. No path is
    trusted because someone typed it.
  * Every discovered constant must resolve to a schema enum. One that
    resolves to nothing FAILS as an unsourced mirror — a finding to
    report, not something to quietly exclude. A constant that genuinely
    mirrors nothing goes in ``NOT_SCHEMA_MIRRORS`` **with a reason**,
    which is a claim a reader can check rather than an omission they
    cannot see.

Two layers, because each catches what the other cannot:

  1. DISCOVERY (``test_every_discovered_constant_has_a_schema_source``) —
     shape-based, no hardcoded paths. Catches a brand-new mirror.
  2. PINNING (``test_pinned_mirror_matches_schema``) — asserts the
     SPECIFIC field each constant mirrors. Catches a schema field being
     renamed or moved, which layer 1 tolerates for as long as some enum
     somewhere happens to still carry the same values.

NOT DONE HERE: replacing the mirrors with a runtime schema read. The
mirror is deliberate — the server does not otherwise open ``schema/`` at
runtime, and adding a file read to surface construction is a bigger change
than a drift guard warrants.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import NamedTuple

import pytest

import a2ui_helpers
import surface_composer

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schema" / "0.4"

# Modules swept for hand-mirrored closed sets. Adding a module here is how
# you bring its constants under the guard.
SWEPT_MODULES = (a2ui_helpers, surface_composer)


class Pin(NamedTuple):
    """A constant and the specific schema location it mirrors."""

    module: str
    const: str
    schema_file: str
    path: tuple[str, ...]  # key path to the object carrying "enum"


# Pinned (constant → exact schema field) pairs. This table is NOT the
# source of what gets checked — discovery is. Every discovered mirror must
# appear here (enforced below), so the table cannot fall behind the code.
# It exists to pin down WHICH field each constant tracks, which a
# value-equality search cannot tell you.
#
# A constant may pin MORE THAN ONE location: _DENSITY_ENUM validates both a
# component-level and a surface-level field, in two different files that
# can drift apart independently, and _BREAKPOINT_ENUM covers two sibling
# properties. Each pair is asserted separately so a one-sided schema edit
# cannot hide behind its twin.
PINS: tuple[Pin, ...] = (
    Pin("a2ui_helpers", "_ARIA_ROLE_ENUM", "a2ui-component.json", ("$defs", "MetaA11y", "properties", "role")),
    Pin("a2ui_helpers", "_ARIA_LIVE_ENUM", "a2ui-component.json", ("$defs", "MetaA11y", "properties", "ariaLive")),
    Pin(
        "a2ui_helpers",
        "_BREAKPOINT_ENUM",
        "a2ui-component.json",
        ("$defs", "MetaResponsive", "properties", "breakpointHide"),
    ),
    Pin(
        "a2ui_helpers",
        "_BREAKPOINT_ENUM",
        "a2ui-component.json",
        ("$defs", "MetaResponsive", "properties", "stackBelow"),
    ),
    Pin("a2ui_helpers", "_DENSITY_ENUM", "a2ui-component.json", ("$defs", "MetaDensity", "properties", "preferred")),
    Pin("a2ui_helpers", "_DENSITY_ENUM", "a2ui-surface.json", ("$defs", "SurfaceDensity", "properties", "preferred")),
    Pin(
        "a2ui_helpers",
        "_FORM_FACTOR_ENUM",
        "a2ui-surface.json",
        ("$defs", "SurfaceTarget", "properties", "formFactor"),
    ),
    Pin("surface_composer", "KNOWN_COMPONENTS", "a2ui-component.json", ("properties", "component")),
)


# Constants that match the discovery shape but mirror NOTHING in the
# schema. Each needs a reason, so the exclusion is a checkable claim rather
# than an invisible omission. If you are adding an entry here to silence a
# failure, that failure was the guard working — confirm the constant really
# has no schema counterpart first.
NOT_SCHEMA_MIRRORS: dict[tuple[str, str], str] = {
    ("surface_composer", "_SINGLE_CHILD_COMPONENTS"): (
        "Renderer child-arity semantics (which components take `child` vs `children`), not a "
        "schema enum. The schema constrains component NAMES, never their arity."
    ),
    ("surface_composer", "_MULTI_CHILD_COMPONENTS"): (
        "Same as _SINGLE_CHILD_COMPONENTS — arity semantics, deliberately a subset of the "
        "component enum rather than a mirror of it."
    ),
}


class Discovered(NamedTuple):
    module: str
    const: str
    values: frozenset[str]


def _module(name: str):
    for mod in SWEPT_MODULES:
        if mod.__name__ == name:
            return mod
    raise AssertionError(f"PINS names module {name!r}, which is not in SWEPT_MODULES")


def _discover() -> tuple[Discovered, ...]:
    """Find candidate hand-mirrored closed sets BY SHAPE.

    Any module-level constant holding a non-empty collection of strings.
    Shape rather than naming convention on purpose: ``_*_ENUM`` is the
    convention today, but a guard that trusts it inherits the same blind
    spot that made this test necessary.
    """
    out: list[Discovered] = []
    for mod in SWEPT_MODULES:
        for name, value in vars(mod).items():
            if name.startswith("__"):
                continue
            if not isinstance(value, tuple | frozenset | set | list):
                continue
            if not value or not all(isinstance(v, str) for v in value):
                continue
            out.append(Discovered(mod.__name__, name, frozenset(value)))
    return tuple(sorted(out))


def _schema_enum_index() -> dict[tuple[str, tuple[str, ...]], list[str]]:
    """Every string ``enum`` in every schema file under ``schema/0.4``,
    keyed by (file, key path). The SOURCE side is discovered too — nothing
    here depends on a path being remembered correctly."""
    index: dict[tuple[str, tuple[str, ...]], list[str]] = {}
    for path in sorted(SCHEMA_DIR.glob("*.json")):
        doc = json.loads(path.read_text())

        def walk(node: object, keys: tuple[str, ...], _file: str = "") -> None:
            if isinstance(node, dict):
                enum = node.get("enum")
                if isinstance(enum, list) and enum and all(isinstance(v, str) for v in enum):
                    index[(_file, keys)] = enum
                for k, v in node.items():
                    walk(v, keys + (k,), _file)
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, keys + (str(i),), _file)

        walk(doc, (), path.name)
    return index


DISCOVERED = _discover()
SCHEMA_ENUMS = _schema_enum_index()


def _fmt(file: str, path: tuple[str, ...]) -> str:
    return f"{file}/{'/'.join(path)}"


# ── layer 0: the sweep is alive ──────────────────────────────────────


def test_discovery_finds_the_known_mirrors():
    """Sanity floor. If the shape rule silently stopped matching — a
    refactor moved the constants, a module import changed — every
    parametrized test below would collapse to zero cases and pass
    vacuously. Assert the sweep still sees what we know is there."""
    assert SCHEMA_ENUMS, f"no enums found under {SCHEMA_DIR} — schema layout changed?"
    found = {(d.module, d.const) for d in DISCOVERED}
    for expected in (
        ("a2ui_helpers", "_DENSITY_ENUM"),
        ("a2ui_helpers", "_BREAKPOINT_ENUM"),
        ("a2ui_helpers", "_FORM_FACTOR_ENUM"),
        ("a2ui_helpers", "_ARIA_ROLE_ENUM"),
        ("a2ui_helpers", "_ARIA_LIVE_ENUM"),
        ("surface_composer", "KNOWN_COMPONENTS"),
    ):
        assert expected in found, f"{expected} not discovered — the shape rule no longer holds"


# ── layer 1: discovery — every mirror has SOME schema source ─────────


@pytest.mark.parametrize("d", DISCOVERED, ids=lambda d: f"{d.module}.{d.const}")
def test_every_discovered_constant_has_a_schema_source(d: Discovered):
    """Every hand-mirrored closed set resolves to a schema enum, or is
    explicitly declared a non-mirror with a reason.

    This is the test that catches a mirror nobody remembered to register,
    including one added long after this file was written.
    """
    if (d.module, d.const) in NOT_SCHEMA_MIRRORS:
        pytest.skip(f"declared non-mirror: {NOT_SCHEMA_MIRRORS[(d.module, d.const)]}")

    matches = [loc for loc, values in SCHEMA_ENUMS.items() if frozenset(values) == d.values]
    assert matches, (
        f"{d.module}.{d.const} looks like a hand-mirrored closed set but matches NO enum in "
        f"{SCHEMA_DIR}.\n"
        f"  values: {sorted(d.values)}\n"
        f"Either it drifted from its source (fix whichever side is wrong), or it mirrors nothing — "
        f"in which case add it to NOT_SCHEMA_MIRRORS with a reason, and report it. Do not delete "
        f"this assertion to make the failure go away."
    )


@pytest.mark.parametrize("d", DISCOVERED, ids=lambda d: f"{d.module}.{d.const}")
def test_every_discovered_mirror_is_pinned(d: Discovered):
    """Discovery drives the pin table, not the other way round.

    A mirror that resolves to the schema but is not pinned would be
    checked only by value equality, so a rename of the field it actually
    tracks would go unnoticed.
    """
    if (d.module, d.const) in NOT_SCHEMA_MIRRORS:
        pytest.skip("declared non-mirror")
    pinned = {(p.module, p.const) for p in PINS}
    assert (d.module, d.const) in pinned, (
        f"{d.module}.{d.const} is a discovered schema mirror with no entry in PINS. Add one naming "
        f"the exact schema file + key path it tracks."
    )


def test_pins_do_not_outlive_their_constants():
    """Reverse direction: a pin for a constant that no longer exists is
    dead weight that reads as coverage."""
    live = {(d.module, d.const) for d in DISCOVERED}
    stale = sorted({(p.module, p.const) for p in PINS} - live)
    assert not stale, f"PINS references constants that no longer exist: {stale}"


# ── layer 2: pinning — each mirror tracks the RIGHT field ────────────


@pytest.mark.parametrize("pin", PINS, ids=lambda p: f"{p.module}.{p.const}->{p.schema_file}:{'/'.join(p.path)}")
def test_pinned_mirror_matches_schema(pin: Pin):
    """The specific schema field each constant mirrors still exists and
    still agrees.

    Compared as SETS: every consumer is a membership test
    (``_validate_enum`` does ``value not in enum``; ``KNOWN_COMPONENTS``
    is a ``frozenset``), so tuple order carries no meaning and reordering
    the schema must not break the build. Duplicates ARE checked on both
    sides, since a set comparison would otherwise hide a doubled entry.
    """
    schema_values = SCHEMA_ENUMS.get((pin.schema_file, pin.path))
    assert schema_values is not None, (
        f"{pin.module}.{pin.const}: {_fmt(pin.schema_file, pin.path)} carries no enum — the schema "
        f"field was renamed, moved, or opened up. Update PINS to the new location, or drop the "
        f"mirror if the field is no longer a closed set."
    )

    code_values = tuple(getattr(_module(pin.module), pin.const))

    assert len(set(schema_values)) == len(schema_values), (
        f"{_fmt(pin.schema_file, pin.path)} has duplicate enum entries: {schema_values}"
    )
    assert len(set(code_values)) == len(code_values), f"{pin.module}.{pin.const} has duplicates: {code_values}"

    missing = sorted(set(schema_values) - set(code_values))
    extra = sorted(set(code_values) - set(schema_values))
    assert not missing and not extra, (
        f"{pin.module}.{pin.const} has drifted from {_fmt(pin.schema_file, pin.path)}.\n"
        f"  in schema, missing from code: {missing}\n"
        f"  in code, absent from schema:  {extra}\n"
        f"Update whichever side is wrong. If the schema change was intentional, the mirror must "
        f"follow it — that is the whole point of this test."
    )


def test_pins_span_both_schema_files():
    """Guards the specific bug that started this: a provenance claim that
    named one schema file when the enums come from two."""
    assert {p.schema_file for p in PINS} == {"a2ui-component.json", "a2ui-surface.json"}
