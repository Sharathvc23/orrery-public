"""Every text-bearing event field is classified untrusted or server-authored — all of them.

WHY THIS FILE EXISTS

The server does not escape event text on the way out, and should not: it does
not know the rendering context, and escaping at the producer either
double-escapes for a consumer doing its job or under-escapes for the context it
guessed wrong. What it owes consumers instead is a statement of which fields it
did not author, so a subscriber knows what to escape.

``event_types.UNTRUSTED_TEXT_FIELDS`` and
``event_types.SERVER_AUTHORED_TEXT_FIELDS`` are that statement. A statement
that drifts from the schemas it describes is worse than none — a subscriber
that trusted a stale "server-authored" entry would skip escaping on a field
that had since become member-supplied. This guard is what stops that.

WHAT IS DERIVED AND WHAT IS DECLARED

The field set is DERIVED by walking ``model_fields`` of every class in
``PAYLOAD_FOR``, so a field cannot hide from the classification by being added
without touching ``event_types``. Which class a field belongs to is DECLARED,
because nothing about a field's TYPE decides who authored its value.

WHAT COUNTS AS TEXT-BEARING

A field can carry characters a renderer must escape iff its annotation admits
``str``, ``dict`` or a container of either. ``Literal``, ``int``, ``float`` and
``HttpUrl`` cannot, and are excluded — listing them would pad the tables and
suggest the classification is doing work it is not. That exclusion is computed
from the annotation here rather than hardcoded, so widening a field's type (say
``Literal[...]`` to ``str``) pulls it into the guard automatically.
"""

from __future__ import annotations

import os
import sys
import typing

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import event_types as et  # noqa: E402

#: Annotations that cannot carry a renderable payload. A field whose annotation
#: reduces entirely to these needs no provenance classification.
_INERT_LEAVES = (int, float, bool, type(None))


def _leaves(annotation) -> list:
    """Flatten an annotation to its leaf types, descending unions and containers."""
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if origin is typing.Literal:
        # Do NOT descend: a Literal's args are the permitted VALUES, not types.
        # Flattening them turns Literal["sovereign", ...] into bare strings and
        # the scan then reports a closed enum as free text.
        return [annotation]
    if origin is None:
        return [annotation]
    out: list = []
    for arg in args:
        if arg is Ellipsis:
            continue
        out.extend(_leaves(arg))
    return out or [origin]


def _is_text_bearing(annotation) -> bool:
    for leaf in _leaves(annotation):
        if typing.get_origin(leaf) is typing.Literal:
            continue
        if leaf in _INERT_LEAVES:
            continue
        if isinstance(leaf, type) and issubclass(leaf, (int, float, bool)):
            continue
        # str, dict, Any, and anything unrecognised: assume it can carry text.
        # Failing toward "needs classification" is the correct direction — the
        # cost is one table entry, the cost of the other direction is an
        # unescaped field nobody was told about.
        name = getattr(leaf, "__name__", str(leaf))
        if name in ("HttpUrl", "AnyUrl", "AnyHttpUrl"):
            continue
        return True
    return False


def _text_fields(cls) -> set[str]:
    return {name for name, f in cls.model_fields.items() if _is_text_bearing(f.annotation)}


ALL_EVENT_TYPES = sorted(et.PAYLOAD_FOR, key=lambda e: e.value)


@pytest.mark.parametrize("event_type", ALL_EVENT_TYPES, ids=lambda e: e.value)
def test_every_text_bearing_field_is_classified(event_type):
    cls = et.PAYLOAD_FOR[event_type]
    derived = _text_fields(cls)
    assert derived, f"{cls.__name__} has no text-bearing fields; the annotation scan is broken"

    declared = et.UNTRUSTED_TEXT_FIELDS.get(event_type, frozenset()) | et.SERVER_AUTHORED_TEXT_FIELDS.get(
        event_type, frozenset()
    )
    missing = sorted(derived - declared)
    assert not missing, (
        f"{event_type.value} ({cls.__name__}): these fields can carry text a subscriber must "
        f"escape, and neither table classifies them: {missing}.\n"
        f"Add each to UNTRUSTED_TEXT_FIELDS (a member, a peer org or a language model authored "
        f"the value) or SERVER_AUTHORED_TEXT_FIELDS (THIS server produced it — a value merely "
        f"constrained here does not qualify)."
    )


@pytest.mark.parametrize("event_type", ALL_EVENT_TYPES, ids=lambda e: e.value)
def test_no_classified_field_has_been_removed_or_renamed(event_type):
    """A stale entry is the failure mode that costs a subscriber, not a missing one.

    A field dropped from a payload leaves its classification behind; the next
    field added with a similar name inherits a verdict nobody re-derived.
    """
    cls = et.PAYLOAD_FOR[event_type]
    declared = et.UNTRUSTED_TEXT_FIELDS.get(event_type, frozenset()) | et.SERVER_AUTHORED_TEXT_FIELDS.get(
        event_type, frozenset()
    )
    stale = sorted(declared - set(cls.model_fields))
    assert not stale, (
        f"{event_type.value} ({cls.__name__}): classified fields that no longer exist on the "
        f"payload: {stale}. Remove them — a classification outliving its field is how the next "
        f"field inherits a verdict nobody re-derived."
    )


@pytest.mark.parametrize("event_type", ALL_EVENT_TYPES, ids=lambda e: e.value)
def test_the_two_classes_are_disjoint(event_type):
    both = et.UNTRUSTED_TEXT_FIELDS.get(event_type, frozenset()) & et.SERVER_AUTHORED_TEXT_FIELDS.get(
        event_type, frozenset()
    )
    assert not both, (
        f"{event_type.value}: {sorted(both)} classified BOTH untrusted and server-authored. "
        f"A subscriber reading the catalog cannot act on a field that is both."
    )


def test_every_event_type_appears_in_the_classification():
    """Parity with PAYLOAD_FOR, the same contract test_event_types.py asserts for it."""
    missing = sorted(e.value for e in et.PAYLOAD_FOR if e not in et.UNTRUSTED_TEXT_FIELDS)
    assert not missing, (
        f"event types with no UNTRUSTED_TEXT_FIELDS entry: {missing}. An absent entry reads as "
        f"'nothing here is untrusted', which is a claim — make it explicitly with frozenset()."
    )


@pytest.mark.parametrize("event_type", ALL_EVENT_TYPES, ids=lambda e: e.value)
def test_text_provenance_returns_the_served_shape(event_type):
    out = et.text_provenance(event_type)
    assert set(out) == {"untrusted", "server_authored"}
    assert out["untrusted"] == sorted(out["untrusted"]), "must be sorted; consumers diff this"
    assert out["server_authored"] == sorted(out["server_authored"])
    assert set(out["untrusted"]) == set(et.UNTRUSTED_TEXT_FIELDS.get(event_type, frozenset()))


def test_text_provenance_rejects_an_unknown_event_type():
    with pytest.raises(ValueError):
        et.text_provenance("not.an.event")


# ══════════════════════════════════════════════════════════════════════
# The catalog is actually served — a classification nobody can read is
# not a contract, which is the whole reason the tables exist.
# ══════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="module")
def catalog():
    from fastapi.testclient import TestClient

    import chapter_agent

    r = TestClient(chapter_agent.app).get("/api/event-catalog")
    assert r.status_code == 200, f"the catalog is not served: {r.status_code}"
    return r.json()


def test_catalog_is_reachable_without_credentials(catalog):
    """Unbounded consumer set: three of the four text-bearing types are trust 0.0."""
    assert catalog["events"], "catalog served no event types"


def test_catalog_covers_every_event_type(catalog):
    assert set(catalog["events"]) == {e.value for e in et.PAYLOAD_FOR}


@pytest.mark.parametrize("event_type", ALL_EVENT_TYPES, ids=lambda e: e.value)
def test_catalog_matches_the_tables_it_publishes(catalog, event_type):
    """A catalog that drifts from the tables is worse than none — it is believed."""
    served = catalog["events"][event_type.value]["text_provenance"]
    assert served == et.text_provenance(event_type)


def test_catalog_states_that_the_server_does_not_escape(catalog):
    """The one sentence a subscriber must not miss."""
    assert "does not escape" in catalog["escaping"]


def test_catalog_publishes_the_trust_tier_alongside(catalog):
    for event_type in ALL_EVENT_TYPES:
        served = catalog["events"][event_type.value]["min_trust_to_subscribe"]
        assert served == et.MIN_TRUST_TO_SUBSCRIBE[event_type]
