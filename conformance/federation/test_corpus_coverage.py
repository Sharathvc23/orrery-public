"""The two published constraints Orrery's own conformance claims rest on.

Coverage of the published rejection corpus is **measured and asserted upstream**
as of sm-federation 0.4.2 (`conformance/test_corpus_coverage.py` there), where it
fails at the commit that weakens it, for every consumer at once. It is not
re-asserted here — a recorded number in a consumer can only be checked by
whoever happens to bump the pin, which is what this file used to be and what
upstream replaced.

What stays here is the part that is not upstream's to make: **not every gap is
equal.** `additionalProperties: false` is what makes "emitted but not
expressible" detectable at all, and the descriptor's `allOf` is §2.1's
cross-field rule. Those two are what the assertions in *this directory* rest on,
so a regression in them invalidates conclusions drawn here rather than merely
being upstream hygiene. That claim belongs where the dependency is pinned.

The measurement machinery below exists to answer that narrow question, so it is
kept rather than duplicated from upstream — and `test_the_measurement_is_not_
vacuous` guards it, because a coverage harness fails open in a way an ordinary
test does not: a schema walk that stops walking enumerates nothing, finds
nothing unguarded, and reports green.

Cross-check performed at the 0.4.2 bump, worth recording because the two
harnesses evolved separately in two repos: Orrery's reports **66 of 68 caught**;
upstream's reports **66 guarded, 1 redundant, 0 unguarded**. They agree exactly
on the substantive number and differ only in how they classify the two
constraints no vector can exercise — upstream excludes `if`-subschemas by
construction and computes the other to be redundant, both of which are the better
treatment, which is why the classification now lives there and not here.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
from jsonschema import Draft202012Validator

_BIG = 10**9
_SMALL = -(10**9)

_CORPORA = {
    "node-descriptor": ("descriptors-invalid", "descriptors-valid", "descriptor"),
    "intelligence-envelope": ("envelopes-invalid", "envelopes-valid", "envelope"),
}


def _walk(node: Any, path: str = "$"):
    """Every subschema in a JSON Schema document, with a stable path label."""
    if not isinstance(node, dict):
        return
    yield path, node
    for key in ("properties", "$defs", "definitions", "patternProperties"):
        for name, sub in (node.get(key) or {}).items():
            yield from _walk(sub, f"{path}.{name}")
    for key in ("items", "contains", "additionalProperties", "not", "if", "then", "else"):
        if isinstance(node.get(key), dict):
            yield from _walk(node[key], f"{path}[{key}]")
    for key in ("allOf", "anyOf", "oneOf"):
        for i, sub in enumerate(node.get(key) or []):
            yield from _walk(sub, f"{path}[{key}{i}]")


def _loosenings(node: dict[str, Any], path: str):
    """(label, mutate) for each constraint keyword on this subschema."""
    for kw in ("const", "enum", "pattern", "items", "contains", "format", "type"):
        if kw in node:
            yield f"{path}.{kw} removed", (lambda n, k=kw: n.pop(k, None))
    for kw, val in (("minLength", 0), ("minItems", 0), ("minProperties", 0), ("minimum", _SMALL)):
        if kw in node:
            yield f"{path}.{kw} -> {val}", (lambda n, k=kw, v=val: n.__setitem__(k, v))
    for kw in ("maxLength", "maxItems", "maxProperties", "maximum"):
        if kw in node:
            yield f"{path}.{kw} -> {_BIG}", (lambda n, k=kw: n.__setitem__(k, _BIG))
    if node.get("additionalProperties") is False:
        yield f"{path}.additionalProperties -> true", (lambda n: n.__setitem__("additionalProperties", True))
    elif isinstance(node.get("additionalProperties"), dict) and node["additionalProperties"]:
        yield f"{path}.additionalProperties schema removed", (lambda n: n.__setitem__("additionalProperties", {}))
    for req in node.get("required") or []:
        yield (
            f"{path}.required drops {req!r}",
            (lambda n, r=req: n.__setitem__("required", [x for x in n["required"] if x != r])),
        )
    for kw in ("allOf", "anyOf", "oneOf", "not"):
        if kw in node:
            yield f"{path}.{kw} removed", (lambda n, k=kw: n.pop(k, None))


def _apply_at(schema: dict[str, Any], path: str, fn) -> dict[str, Any]:
    mutated = copy.deepcopy(schema)
    for candidate, node in _walk(mutated):
        if candidate == path:
            fn(node)
            return mutated
    raise KeyError(path)


def _measure(wire) -> tuple[int, int, list[str]]:
    caught = total = 0
    unguarded: list[str] = []

    for schema_name, (invalid, valid, key) in _CORPORA.items():
        schema = wire.load_schema(schema_name)
        bad = wire.load_vectors(invalid)["cases"]
        good = wire.load_vectors(valid)["cases"]
        seen: set[str] = set()

        for path, node in _walk(schema):
            for label, fn in _loosenings(node, path):
                if label in seen:
                    continue
                seen.add(label)
                validator = Draft202012Validator(_apply_at(schema, path, fn))

                # A genuine loosening cannot REJECT a payload that was valid. If
                # it does, the mutation tightened the schema — mutating the
                # condition of an `if` does exactly that — and it is not a
                # coverage question at all. Discarded rather than counted, which
                # is why this reports fewer mutations than it generates.
                if any(list(validator.iter_errors(c[key])) for c in good):
                    continue

                total += 1
                if any(not list(validator.iter_errors(c[key])) for c in bad):
                    caught += 1
                else:
                    unguarded.append(f"{schema_name}: {label}")

    return caught, total, unguarded


@pytest.fixture(scope="module")
def measurement(wire):
    return _measure(wire)


def test_the_measurement_is_not_vacuous(measurement) -> None:
    """A harness that generates no mutations would pass the test above silently.

    0/0 == 0/0. This asserts the enumeration actually found constraints, so a
    walk that stops working is a failure rather than a green.
    """
    _, total, _ = measurement
    assert total >= 50, f"only {total} loosenings enumerated — the schema walk is not reaching the schema"


def test_the_constraints_orrery_itself_relies_on_are_present_and_exercised(measurement, wire) -> None:
    """The two constraints this directory's own conclusions rest on.

    ``additionalProperties: false`` is what makes "emitted but not expressible"
    detectable at all — without it a producer can add any field and every
    validation still passes, which is the entire basis of
    ``envelope_field_map.json``. The descriptor's ``allOf`` is §2.1's cross-field
    rule, which ``test_descriptor_declares_exactly_the_sections_orrery_
    implements`` reads as a declaration rather than an inference.

    PRESENT **and** exercised, in that order, because an earlier version of this
    test checked only the second half and was proven wrong by planting: setting
    ``additionalProperties: true`` in the published wheel made the constraint
    vanish from the enumeration entirely, so it appeared in no unguarded list and
    the test passed. A constraint that has been REMOVED is the more dangerous
    case than one that is merely unexercised, and it was the invisible one.
    """
    envelope = wire.load_schema("intelligence-envelope")
    descriptor = wire.load_schema("node-descriptor")

    assert envelope.get("additionalProperties") is False, (
        "the published envelope schema no longer forbids unknown properties. Everything "
        "envelope_field_map.json concludes about 'emitted but not expressible' depends on it: "
        "without it a producer can add any field and validation still passes."
    )
    assert descriptor.get("additionalProperties") is False, (
        "the published descriptor schema no longer forbids unknown properties"
    )
    assert descriptor.get("allOf"), (
        "the published descriptor schema no longer carries the §2.1 cross-field rule, so a node "
        "can claim federation/<v>#4 without publishing a feed. "
        "test_descriptor_declares_exactly_the_sections_orrery_implements reads that declaration."
    )

    _, _, unguarded = measurement
    still_unexercised = [
        u
        for u in unguarded
        if u.endswith("$.additionalProperties -> true") or u.endswith("$.allOf removed")
    ]
    assert not still_unexercised, (
        "constraints this suite's own claims depend on are present but no longer exercised by any "
        f"shipped rejection vector: {still_unexercised}"
    )
