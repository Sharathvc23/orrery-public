"""Event-bus type catalog (EB-1).

Closed-enum + Pydantic payload schemas for every event the chapter
can publish. The bus rejects unknown ``event_type`` strings at publish
time so a typo cannot silently slip past subscribers.

Event-type naming convention: ``<domain>.<verb>``. Past-tense for
state-changes, present-tense for transient signals. Examples:

  member.joined           — a new member registered with the chapter
  intent.published        — a member submitted an intent
  federation.peer.online  — peer chapter became reachable
  federation.peer.offline — peer chapter became unreachable

Each event type declares:
  * payload schema (Pydantic, closed-set fields)
  * minimum trust tier required to subscribe (EB-5 enforces)
  * whether the event carries PII (EB-5 may further restrict delivery)

The bus does NOT define delivery semantics here — that's EB-4 (SSE
stream). This module is just the contract.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


class EventType(StrEnum):
    """Closed enum of all publishable event types.

    Adding a new value requires:
      1. New ``StrEnum`` member here
      2. Matching Pydantic payload class below
      3. Entry in ``PAYLOAD_FOR`` dispatch table
      4. Entry in ``MIN_TRUST_TO_SUBSCRIBE`` per-type tier
      5. Conformance test in tests/test_event_types.py
      6. Vector under vectors/events/ (post-EB-1)

    The chapter's ``publish()`` primitive (EB-2) raises on any
    ``event_type`` string not in this enum. No silent acceptance.
    """

    MEMBER_JOINED = "member.joined"
    MEMBER_LEFT = "member.left"
    INTENT_PUBLISHED = "intent.published"
    INTENT_MATCHED = "intent.matched"
    FEDERATION_PEER_ONLINE = "federation.peer.online"
    FEDERATION_PEER_OFFLINE = "federation.peer.offline"
    FEDERATION_REGISTRY_DIVERGENCE = "federation.registry.divergence"
    CHAPTER_DIGEST_WEEKLY = "chapter.digest.weekly"
    CHAPTER_BROADCAST = "chapter.broadcast"


# ─── Payload schemas ────────────────────────────────────────────────
#
# Every payload extends EventPayloadBase so subscribers can rely on
# the common envelope fields (event_id, occurred_at) without
# inspecting event_type. Subscribers MAY ignore unknown fields a
# future minor version adds — the schemas are Pydantic-validated
# server-side at publish time, not client-side at delivery.


class EventPayloadBase(BaseModel):
    """Common fields on every event payload."""

    # Server-set bigserial from event_log. Subscribers use this for
    # SSE Last-Event-ID resume in EB-4.
    event_id: int | None = Field(
        default=None,
        description="Server-assigned bigserial id from event_log; None until persisted.",
    )

    occurred_at: str | None = Field(
        default=None,
        description="ISO-8601 UTC timestamp; server-set on persist.",
    )


class MemberJoinedPayload(EventPayloadBase):
    agent_id: str
    did_key: str
    name: str = ""
    skills: list[str] = Field(default_factory=list)
    origin: Literal["sovereign", "openclaw", "openclaw_sandboxed"] = "sovereign"
    trust_score: float = 0.0


class MemberLeftPayload(EventPayloadBase):
    agent_id: str
    reason: Literal["self_revoke", "panic", "leader_remove", "expired"] = "self_revoke"


class IntentPublishedPayload(EventPayloadBase):
    intent_id: str
    submitter_agent_id: str
    text: str
    tags: list[str] = Field(default_factory=list)
    submitter_trust_score: float = 0.0


class IntentMatchedPayload(EventPayloadBase):
    intent_id: str
    submitter_agent_id: str
    matched_agent_ids: list[str]
    match_score: float = Field(ge=0.0, le=1.0)


class FederationPeerOnlinePayload(EventPayloadBase):
    peer_chapter_id: str
    peer_endpoint: HttpUrl
    member_count: int = 0


class FederationPeerOfflinePayload(EventPayloadBase):
    peer_chapter_id: str
    peer_endpoint: HttpUrl
    consecutive_failures: int = 0
    last_success_at: str | None = None


class ChapterDigestWeeklyPayload(EventPayloadBase):
    """Weekly chapter digest — rich summary of a 7-day window.

    Built from event_log + projections; published either by the
    digest cycle (~weekly cadence) or on-demand via the
    POST /api/digest/build endpoint. Subscribers get the same
    payload regardless of trigger — the demo path and the
    production path don't diverge.
    """

    window_start: str  # ISO-8601 UTC; inclusive
    window_end: str  # ISO-8601 UTC; exclusive
    new_member_count: int = 0
    intent_published_count: int = 0
    intent_matched_count: int = 0
    # Top-N highlights per category. Each list element is a small dict
    # the renderer / podcast-as-agent can read; we don't enforce a
    # nested schema here because the digest evolves faster than the
    # event-bus catalog and the consumer is the server's own
    # renderer + a future podcast composer.
    top_intents: list[dict] = Field(default_factory=list)
    new_members: list[dict] = Field(default_factory=list)
    federation_changes: list[dict] = Field(default_factory=list)
    # Optional human-readable summary the LLM composed at digest time.
    headline: str = ""
    summary_markdown: str = ""


class FederationRegistryDivergencePayload(EventPayloadBase):
    """A cross-registry divergence finding (``registry_divergence.check``).

    One finding about one agent id. ``kind`` selects which of the detail
    fields are populated — the shapes are exactly what ``registry_divergence``
    already emits (this schema does not reshape them):

      * ``omission``     — ``present_on`` + ``missing_from``
      * ``endpoint``     — ``endpoints`` (registry_url → endpoint)
      * ``did``          — ``dids`` (registry_url → attested did)
      * ``unconfirmed``  — ``present_on`` + ``unconfirmed_on`` (F4: a sibling
                            serves the id but another registry errored on it)

    Detail fields are all optional so one schema validates every kind; the
    detector populates the ones the kind defines. Public tier: registry state
    is already visible on ``/api/agents`` at each registry, so a *disagreement*
    between them is not more sensitive than the records themselves.
    """

    kind: Literal["omission", "endpoint", "did", "unconfirmed"]
    agent_id: str
    present_on: list[str] | None = None
    missing_from: list[str] | None = None
    unconfirmed_on: list[str] | None = None
    endpoints: dict[str, str] | None = None
    dids: dict[str, str] | None = None


class ChapterBroadcastPayload(EventPayloadBase):
    """A chapter publishes one message to everyone (local + federated peers).

    Fanout topology:
      * Locally: persisted via ``event_bus.publish``; visible on
        ``/api/events?type=chapter.broadcast``.
      * Federated: the sending chapter pushes a signed POST to each
        peer's ``/api/federation/broadcast/inbox``. The receiver
        re-publishes the same payload (preserving ``origin_chapter_id``)
        so its own subscribers see it. ``origin_chapter_id`` prevents
        re-broadcast loops — receivers MUST NOT forward.

    Audience filtering is the subscriber's job; the publisher does not
    pre-filter. Trust gate at publish time is verified-tier so anonymous
    public scrapers can't subscribe to the firehose — but every member
    who's passed onboarding will see them.
    """

    broadcast_id: str  # UUID; receivers dedupe on this
    origin_chapter_id: str  # The chapter that originated the broadcast
    sender_agent_id: str  # The chapter agent or attested leader who sent it
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=8000)
    tags: list[str] = Field(default_factory=list, max_length=20)
    audience: Literal["local", "federation", "all"] = "all"


# ─── Dispatch table ──────────────────────────────────────────────────
#
# Maps EventType → payload class. The publish primitive (EB-2) uses
# this to validate payloads before persisting. Adding an enum value
# without a matching entry here MUST fail the unit test in
# tests/test_event_types.py::test_every_event_type_has_a_payload_class.

PAYLOAD_FOR: dict[EventType, type[EventPayloadBase]] = {
    EventType.MEMBER_JOINED: MemberJoinedPayload,
    EventType.MEMBER_LEFT: MemberLeftPayload,
    EventType.INTENT_PUBLISHED: IntentPublishedPayload,
    EventType.INTENT_MATCHED: IntentMatchedPayload,
    EventType.FEDERATION_PEER_ONLINE: FederationPeerOnlinePayload,
    EventType.FEDERATION_PEER_OFFLINE: FederationPeerOfflinePayload,
    EventType.FEDERATION_REGISTRY_DIVERGENCE: FederationRegistryDivergencePayload,
    EventType.CHAPTER_DIGEST_WEEKLY: ChapterDigestWeeklyPayload,
    EventType.CHAPTER_BROADCAST: ChapterBroadcastPayload,
}


# ─── Text provenance: which fields a subscriber must escape ─────────
#
# The server does NOT escape event text on the way out, and should not: it
# does not know the rendering context. The same string may land in an HTML
# body, an attribute, a JS string, a terminal or a markdown renderer, and each
# needs a different escape. Escaping at the producer either double-escapes for
# a consumer doing its job or under-escapes for the context it guessed wrong.
# Output encoding belongs at the point of output.
#
# What the server DOES owe consumers is not pretending the text is safe. These
# two tables are that statement, made machine-readable: every field that can
# carry arbitrary characters is named in exactly one of them, and the pair is
# served at ``GET /api/event-catalog`` so a subscriber can act on it.
#
# THE DIVIDING RULE, stated because the borderline cases are where this goes
# wrong: a field is SERVER-AUTHORED iff THIS server produced the value. A value
# this server merely CONSTRAINED is not server-authored — a constraint is not
# authorship, constraints change, and a subscriber that skipped escaping on the
# strength of one would carry the cost of that change. So ``agent_id`` is
# untrusted even though ``sanitize_agent_id`` restricts it today, and
# ``broadcast_id`` is untrusted even though it is a UUID, because a federated
# broadcast arrives from a peer and this server did not mint it.
#
# Fields typed ``Literal``, ``int``, ``float`` or ``HttpUrl`` appear in neither
# table: Pydantic already makes them incapable of carrying a payload, and
# listing them would suggest the classification is doing work it is not.
# ``test_event_text_provenance.py`` enforces that the two tables together cover
# every text-bearing field of every payload class, so a new field cannot land
# unclassified.

#: Fields whose value originates with a member, a peer org, or a language
#: model. A subscriber MUST escape these for its own rendering context.
UNTRUSTED_TEXT_FIELDS: dict[EventType, frozenset[str]] = {
    EventType.MEMBER_JOINED: frozenset({"agent_id", "did_key", "name", "skills"}),
    EventType.MEMBER_LEFT: frozenset({"agent_id"}),
    EventType.INTENT_PUBLISHED: frozenset({"submitter_agent_id", "text", "tags"}),
    EventType.INTENT_MATCHED: frozenset({"submitter_agent_id", "matched_agent_ids"}),
    EventType.FEDERATION_PEER_ONLINE: frozenset({"peer_chapter_id"}),
    EventType.FEDERATION_PEER_OFFLINE: frozenset({"peer_chapter_id"}),
    # Every detail field here is copied from what a REGISTRY served, and the
    # point of the event is that the registries disagree — so at least one of
    # them is wrong about something. Trusting their strings would be odd.
    EventType.FEDERATION_REGISTRY_DIVERGENCE: frozenset(
        {"agent_id", "present_on", "missing_from", "unconfirmed_on", "endpoints", "dids"}
    ),
    # ``top_intents``, ``new_members`` and ``federation_changes`` are bare
    # ``list[dict]`` on purpose (the digest evolves faster than this catalog),
    # so for these three the closed schema bounds neither text NOR shape — the
    # whole field is untrusted, values and keys alike. ``headline`` and
    # ``summary_markdown`` are composed by a language model from member text;
    # ``summary_markdown`` is markdown WITHOUT embedded HTML, and a renderer
    # that permits raw HTML in markdown must disable it for this field.
    EventType.CHAPTER_DIGEST_WEEKLY: frozenset(
        {"top_intents", "new_members", "federation_changes", "headline", "summary_markdown"}
    ),
    # A federated broadcast is re-published by the RECEIVER preserving the
    # sender's payload, so on the receiving side none of this was authored
    # here — including the id.
    EventType.CHAPTER_BROADCAST: frozenset(
        {"broadcast_id", "origin_chapter_id", "sender_agent_id", "title", "body", "tags"}
    ),
}

#: Text-bearing fields THIS server produced. Safe to render without escaping
#: for as long as that remains true, which is what the guard checks.
SERVER_AUTHORED_TEXT_FIELDS: dict[EventType, frozenset[str]] = {
    EventType.MEMBER_JOINED: frozenset({"occurred_at"}),
    EventType.MEMBER_LEFT: frozenset({"occurred_at"}),
    # ``intent_id`` is ``str(uuid.uuid4())`` minted in ``intents.py``.
    EventType.INTENT_PUBLISHED: frozenset({"occurred_at", "intent_id"}),
    EventType.INTENT_MATCHED: frozenset({"occurred_at", "intent_id"}),
    EventType.FEDERATION_PEER_ONLINE: frozenset({"occurred_at"}),
    EventType.FEDERATION_PEER_OFFLINE: frozenset({"occurred_at", "last_success_at"}),
    EventType.FEDERATION_REGISTRY_DIVERGENCE: frozenset({"occurred_at"}),
    EventType.CHAPTER_DIGEST_WEEKLY: frozenset({"occurred_at", "window_start", "window_end"}),
    EventType.CHAPTER_BROADCAST: frozenset({"occurred_at"}),
}


def text_provenance(event_type: str | EventType) -> dict[str, list[str]]:
    """The untrusted/server-authored split for one event type.

    The shape served at ``GET /api/event-catalog``. Sorted so the response is
    stable across processes — a consumer diffing the catalog to detect a
    contract change should see a change only when one happened.
    """
    et = EventType(event_type) if isinstance(event_type, str) else event_type
    return {
        "untrusted": sorted(UNTRUSTED_TEXT_FIELDS.get(et, frozenset())),
        "server_authored": sorted(SERVER_AUTHORED_TEXT_FIELDS.get(et, frozenset())),
    }


# ─── Trust tier per event type (EB-5 enforces) ──────────────────────
#
# Minimum trust score a subscriber must hold to receive this event
# type. EB-5 looks up agents.trust_score per delivery and drops any
# event whose subscriber falls below the threshold. Trust changes
# take effect on the NEXT publish — old subscriptions are NOT
# revoked, just filtered out.
#
# Tiers (informal):
#   0     public (anyone can subscribe)
#   25    verified member (passed onboarding)
#   50    established member (signaled by leader OR sustained activity)
#   75    leader / server-trusted
#
# Federation events are public — servers publishing peer state is
# not sensitive (the same state is on /api/federation already).

MIN_TRUST_TO_SUBSCRIBE: dict[EventType, float] = {
    EventType.MEMBER_JOINED: 0.0,
    EventType.MEMBER_LEFT: 25.0,
    EventType.INTENT_PUBLISHED: 0.0,
    EventType.INTENT_MATCHED: 25.0,
    EventType.FEDERATION_PEER_ONLINE: 0.0,
    EventType.FEDERATION_PEER_OFFLINE: 0.0,
    # Divergence findings are public: the registry records they compare are
    # already on each registry's /api/agents, so a disagreement is no more
    # sensitive than the records. Public tier lets a dashboard/monitor read them.
    EventType.FEDERATION_REGISTRY_DIVERGENCE: 0.0,
    # Server digest is public — it's the "podcast bait" event that any
    # subscriber (the podcast-as-agent, a newsletter generator, a public
    # dashboard) can consume to build a recap. Sensitive details (per-
    # member trust changes, private intents) are NOT included in the
    # payload; only aggregates + top public-tier highlights.
    EventType.CHAPTER_DIGEST_WEEKLY: 0.0,
    # Broadcasts are verified-tier — anonymous public subscribers must
    # not get the firehose, but every onboarded member sees them. The
    # publisher (server leader / server agent) is authenticated at
    # POST time; the trust gate here governs delivery, not publish.
    EventType.CHAPTER_BROADCAST: 25.0,
}


def validate_event(event_type: str, payload: dict) -> EventPayloadBase:
    """Validate ``payload`` against the closed schema for ``event_type``.

    Returns the validated Pydantic instance. Raises ``ValueError`` if:
      * ``event_type`` is not in the closed enum
      * ``payload`` doesn't validate against the registered schema

    The publish primitive (EB-2) is the only caller; subscribers
    receive already-validated payloads from the event_log.
    """
    try:
        et = EventType(event_type)
    except ValueError as e:
        valid = ", ".join(sorted(t.value for t in EventType))
        raise ValueError(f"Unknown event_type {event_type!r}; must be one of: {valid}") from e

    schema = PAYLOAD_FOR.get(et)
    if schema is None:
        # Should be impossible — the test suite enforces parity, but
        # defensive in case an enum value lands without a payload.
        raise ValueError(f"event_type {event_type!r} has no registered payload schema")

    return schema.model_validate(payload)


def min_trust_for(event_type: str | EventType) -> float:
    """Return the minimum trust score a subscriber must hold to receive
    events of this type. Raises ``ValueError`` for unknown types."""
    et = EventType(event_type) if isinstance(event_type, str) else event_type
    return MIN_TRUST_TO_SUBSCRIBE[et]
