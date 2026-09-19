"""sm-listing 0.1 — the consented, discoverable subset of an org's members.

⚠️ **THIS IS NOT A FILTER OVER THE DIRECTORY.** The Directory (`GET /api/members`
and the A2UI pages) is gated and stays gated; it answers *"who are ALL your
members?"* to someone already inside. The Listing is a **different resource over
a different population**: only members who actively chose to be discoverable,
carrying only the fields they chose. A filter over the roster would be the roster
again, slower — and the enumeration closure already ruled on the roster.

**Its default state is EMPTY.** A community that enables this profile with nobody
opted in publishes an empty document forever, and that is correct rather than a
misconfiguration.

**The consent machinery is not new.** Row visibility follows `chronicle_public`:
an explicit per-agent opt-in stored in `agents.config`, DEFAULT PRIVATE, because
computing data and publishing it are separate decisions. Per-field visibility
follows `contact_public`: an unconsented field is ABSENT from the entry, the row
is not hidden for it. `profiles.is_public` is the counter-example on both counts
— `DEFAULT true NOT NULL`, and the member-directory closure found it selected and never consulted.
`consent_gate` is deliberately NOT reused: "I agreed to meet this counterparty"
and "I agreed to be world-readable forever" are different decisions, and sharing
the machinery would bake that confusion into the code.

**§3 binds in BOTH directions, and the second half is the trap.** A non-consenting
member must be ABSENT — but an empty listing trivially contains no non-consenting
member, so a node that dropped everyone would be maximally conformant while
delivering nothing. A consenting member MUST appear, and
`sm_listing.build_listing` RAISES rather than skipping an entry it cannot
publish. Nothing here catches that: a silent drop is the presence half broken
quietly, which is the failure this module is shaped to prevent.

**Consent is decided HERE, at the layer that owns the preference.** The route
serialises what this module returns and never sees a non-consenting member. A
check in the place that happens to serialise protects the paths someone
remembered, and a listing gains paths — a cache warmer, an export, a second
endpoint.
"""

from __future__ import annotations

from typing import Any

import sm_listing

#: THE PROFILE'S path, taken from the package rather than restated — sm-listing
#: 0.3.0 made it mandatory and exports it. the shared-constant change shipped
#: /.well-known/agent-listing.json before the path was normative and chose
#: differently; that path is GONE, not aliased. There is exactly one deployment,
#: it is not public, and a compatibility alias nobody needs is a second URL for
#: one resource that some future reader has to work out the precedence of.
LISTING_PATH = sm_listing.WELL_KNOWN_PATH

#: Whether this org implements the profile at all — an ORG decision, distinct
#: from whether any member consented.
#:
#: ⚠️ §: **a node that does not implement the profile MUST NOT serve the path.**
#: 404, never an empty document — the path is a CLAIM, so an empty listing means
#: "I run this surface and nobody has opted in", which is a different and more
#: useful fact than silence. Serving an empty document from an org that never
#: enabled it would say the first thing while meaning the second.
#:
#: Default OFF, matching the consent model one level up: publishing a discovery
#: surface at all is a decision somebody makes, not one they inherit.
ENABLED_FLAG = "ORRERY_LISTING_ENABLED"


def is_enabled() -> bool:
    """Whether this org serves the listing profile. Default off."""
    import env_flags

    return env_flags.security_flag(ENABLED_FLAG, default=False)

#: The member's own key in ``agents.config``. Named for the decision, not the
#: feature: what is stored is a member's answer to "may this be published".
CONSENT_KEY = "listing"

#: Fields a member may publish, each independently. Absent means the member did
#: not consent to that field — NOT that the row is hidden (contact_public's rule).
#: `subject` and `agent_url` are not here: they are the entry's required identity
#: and its contact route, so consenting to be listed at all is consenting to them.
OPTIONAL_FIELDS = ("did", "geo", "offering", "trade")

#: Written by the SERVER into the consent record at opt-in, never accepted from
#: the member. Two reasons, and the second is why it is stored rather than read
#: live:
#:
#: 1. A member must not be able to point their listing entry at an arbitrary URL;
#:    it is their REGISTERED endpoint or nothing.
#: 2. ⚠️ ``members[id]["endpoint"]`` USED TO BE IN-MEMORY ONLY — registration
#:    never persisted it and ``load_persisted_members`` hardcoded ``""`` — so
#:    after a restart a consenting member had no ``agent_url`` and
#:    `build_listing` RAISED, turning the whole listing into a 500 on every
#:    redeploy. Found by asserting presence ACROSS A RESTART rather than in one
#:    process; every in-process test passed. The consent record is persisted and
#:    rehydrated by the loader, so consent carrying the thing it consented to
#:    publish is what made the entry survive.
#:
#:    The underlying field IS durable now (`_persist_member_to_db` writes
#:    ``config.endpoint``, the loader hydrates it), which does NOT make this
#:    field redundant: reason 1 stands on its own, and reading the endpoint live
#:    would let a later re-registration silently repoint a listing entry the
#:    member consented to as it stood. Snapshot at consent is the contract.
SERVER_SET_FIELDS = ("agent_url",)


def consent_of(member: dict[str, Any]) -> dict[str, Any] | None:
    """The member's listing consent, or None if they have not opted in.

    Default private, and deliberately strict about what counts as consent: only
    ``listed is True`` does. A truthy string, a 1, or a stray dict would all be
    "probably yes" readings of a field whose whole job is to be unambiguous —
    and `profiles.is_public` is what a permissive reading of a consent flag looks
    like after two years.
    """
    raw = (member or {}).get(CONSENT_KEY)
    if not isinstance(raw, dict):
        return None
    return raw if raw.get("listed") is True else None


def entry_for(agent_id: str, member: dict[str, Any], consent: dict[str, Any]) -> dict[str, Any]:
    """Build one listing entry from ONLY what this member consented to publish.

    ⚠️ ``agent_url`` is the member's AGENT ENDPOINT, never a human contact
    detail. An audit put an email address and a phone number in a member's
    free-text description and both came back to an unauthenticated GET; the
    Listing must not become the consented version of that. sm-listing enforces it
    too — §4.1 forbids `email`/`phone`/`address` and §4.2 forbids member-authored
    prose — and this function never has the opportunity to supply either, because
    it copies named fields from the consent record rather than reshaping the
    member row.
    """
    agent_url = str(consent.get("agent_url") or member.get("endpoint") or "").strip()
    entry: dict[str, Any] = {"subject": agent_id, "agent_url": agent_url}
    for field in OPTIONAL_FIELDS:
        value = consent.get(field)
        if value not in (None, "", [], {}):
            entry[field] = value
    return entry


def consenting_entries(members: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Entries for the members who opted in — the non-consenting are DROPPED HERE.

    Dropped, not marked. A present-but-opaque row in an enumeration is a census
    of the non-consenting: it publishes the one fact those members declined to
    publish, which is that they are there. And no count is produced anywhere in
    this module — not even privately — because a count computed and then withheld
    is one refactor from being emitted. `omitted_members` is a field
    `sm_listing.validate_listing` REFUSES, and the resolvable-card rule's `omittedMembers` in the
    catalog is a no-resolvable-card count, not a consent signal; the two must not
    be confused.
    """
    out = []
    for agent_id, member in sorted((members or {}).items()):
        consent = consent_of(member)
        if consent is None:
            continue
        out.append(entry_for(agent_id, member, consent))
    return out


def build(members: dict[str, dict[str, Any]], *, community_id: str, generated_at: str) -> dict[str, Any]:
    """The listing document, built by the PUBLISHED builder.

    Never a local dict: a hand-assembled document is a second copy of the wire
    contract with nothing comparing the two. `build_listing` also validates every
    entry and RAISES on one it cannot publish — which is the §3 presence half, and
    is why nothing here wraps it in a try.
    """
    return sm_listing.build_listing(
        community_id=community_id,
        generated_at=generated_at,
        consenting_entries=consenting_entries(members),
    )


def validate_consent_request(payload: dict[str, Any], member: dict[str, Any]) -> tuple[bool, str]:
    """Whether this opt-in can be honoured, checked at the moment it is made.

    A member who consents but cannot be published would make the org
    non-conformant against §3's presence half at the next build — loudly, since
    `build_listing` raises. Refusing the opt-in instead keeps the invariant
    "consenting implies publishable" true by construction, and puts the error in
    front of the person who can fix it rather than in a 500 for a stranger.
    """
    if payload.get("listed") is not True:
        return True, "ok"
    unknown = sorted(set(payload) - {"listed", *OPTIONAL_FIELDS, *SERVER_SET_FIELDS})
    if unknown:
        # entry_for whitelists, so an unknown key could never reach the wire —
        # but silently ignoring it is the wrong answer for a CONSENT api. A member
        # who supplied `email` believes they published it; telling them the field
        # does not exist is the difference between a refusal and a shrug.
        return False, (
            f"the listing does not carry {unknown}: §4.1 forbids human contact details and §4.2 "
            "forbids member-authored prose. The contact route is the agent endpoint."
        )
    if not str((member or {}).get("endpoint") or "").strip():
        return False, (
            "this member has no agent endpoint, and a listing entry's contact route IS the agent "
            "endpoint (§4.1 — a listing carries no human contact details). Register an endpoint first."
        )
    probe = entry_for("probe", {"endpoint": "https://probe.invalid"}, payload)
    ok, reason = sm_listing.validate_entry(probe)
    if not ok:
        return False, reason
    return True, "ok"
