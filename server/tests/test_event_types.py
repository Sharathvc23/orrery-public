"""Tests for the event-bus type catalog (EB-1).

Locks the closed-enum ↔ payload-class ↔ trust-tier table parity. A
future PR that adds an EventType member without the matching payload
class or trust tier MUST fail one of these tests at CI time, not at
publish time when a real event silently 5xxs.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from event_types import (
    MIN_TRUST_TO_SUBSCRIBE,
    PAYLOAD_FOR,
    EventType,
    IntentPublishedPayload,
    MemberJoinedPayload,
    min_trust_for,
    validate_event,
)

# ---------------------------------------------------------------------------
# Catalog parity — every enum value has a payload class + trust tier
# ---------------------------------------------------------------------------


def test_every_event_type_has_a_payload_class() -> None:
    """A new EventType member without a PAYLOAD_FOR entry breaks
    publish() at runtime. Lock parity at CI time instead."""
    for et in EventType:
        assert et in PAYLOAD_FOR, f"{et.value!r} missing from PAYLOAD_FOR dispatch"


def test_every_event_type_has_a_trust_tier() -> None:
    """Same parity for the trust-gating table — EB-5 will raise KeyError
    on publish if a tier is missing."""
    for et in EventType:
        assert et in MIN_TRUST_TO_SUBSCRIBE, f"{et.value!r} missing from MIN_TRUST_TO_SUBSCRIBE"


def test_no_extra_payload_classes_for_unknown_event_types() -> None:
    """Inverse parity: if PAYLOAD_FOR has an entry that's not in the
    enum, the dispatch is broken."""
    for key in PAYLOAD_FOR:
        assert isinstance(key, EventType), f"PAYLOAD_FOR key {key!r} not an EventType"


def test_min_trust_values_are_in_known_tier_set() -> None:
    """The four documented tiers (0 public, 25 verified, 50 established,
    75 leader). Loosen the assertion when introducing a new tier
    intentionally — but the test forces the conversation."""
    allowed = {0.0, 25.0, 50.0, 75.0}
    for et, threshold in MIN_TRUST_TO_SUBSCRIBE.items():
        assert threshold in allowed, (
            f"{et.value!r} has trust threshold {threshold} outside the documented tier set {sorted(allowed)}"
        )


# ---------------------------------------------------------------------------
# validate_event() — happy path + closed-set enforcement
# ---------------------------------------------------------------------------


def test_validate_event_returns_pydantic_instance() -> None:
    payload = {
        "agent_id": "alice",
        "did_key": "did:key:z6Mk...",
        "name": "Alice",
        "skills": ["python"],
        "origin": "sovereign",
        "trust_score": 25.0,
    }
    result = validate_event("member.joined", payload)
    assert isinstance(result, MemberJoinedPayload)
    assert result.agent_id == "alice"


def test_validate_event_rejects_unknown_event_type() -> None:
    with pytest.raises(ValueError, match="Unknown event_type"):
        validate_event("totally.fake", {})


def test_validate_event_rejects_payload_missing_required_field() -> None:
    """member.joined requires agent_id + did_key. Drop one — Pydantic
    raises ValidationError which validate_event surfaces."""
    with pytest.raises(ValidationError):
        validate_event("member.joined", {"agent_id": "alice"})  # no did_key


def test_validate_event_rejects_invalid_origin_enum() -> None:
    """origin is a Literal — anything outside the closed set fails."""
    with pytest.raises(ValidationError):
        validate_event(
            "member.joined",
            {
                "agent_id": "alice",
                "did_key": "did:key:z6Mk",
                "origin": "pirate",
            },
        )


def test_validate_event_intent_published_minimal() -> None:
    result = validate_event(
        "intent.published",
        {
            "intent_id": "int-1",
            "submitter_agent_id": "alice",
            "text": "Looking for a Rust mentor",
        },
    )
    assert isinstance(result, IntentPublishedPayload)
    assert result.tags == []  # default_factory


def test_validate_event_match_score_bounded() -> None:
    """intent.matched.match_score is bounded [0, 1]. >1 must fail."""
    with pytest.raises(ValidationError):
        validate_event(
            "intent.matched",
            {
                "intent_id": "i",
                "submitter_agent_id": "alice",
                "matched_agent_ids": ["bob"],
                "match_score": 1.5,
            },
        )


# ---------------------------------------------------------------------------
# min_trust_for() — string + enum input
# ---------------------------------------------------------------------------


def test_min_trust_for_accepts_string_event_type() -> None:
    assert min_trust_for("member.joined") == 0.0
    assert min_trust_for("intent.matched") == 25.0


def test_min_trust_for_accepts_enum() -> None:
    assert min_trust_for(EventType.MEMBER_LEFT) == 25.0


def test_min_trust_for_rejects_unknown_event_type() -> None:
    with pytest.raises(ValueError):
        min_trust_for("nope.nope")


# ---------------------------------------------------------------------------
# Documented expectations the launch story relies on
# ---------------------------------------------------------------------------


def test_public_events_are_actually_public() -> None:
    """member.joined, intent.published, federation peer state must
    stay at trust=0 — these are the events the public dashboard +
    OpenClaw skills + new low-trust subscribers rely on. Raising
    them gates a lot of the demo flow."""
    for et in (
        EventType.MEMBER_JOINED,
        EventType.INTENT_PUBLISHED,
        EventType.FEDERATION_PEER_ONLINE,
        EventType.FEDERATION_PEER_OFFLINE,
    ):
        assert MIN_TRUST_TO_SUBSCRIBE[et] == 0.0, f"{et.value!r} must remain trust-0 (public)"
