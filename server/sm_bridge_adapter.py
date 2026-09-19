"""Chapter ↔ sm-bridge adapter.

Mounts ``sm-bridge``'s NANDA-compatible registry endpoints under
``/sm-bridge/*`` ALONGSIDE the chapter's existing ``/.well-known/nanda-agent.json``
+ ``/agentfacts.json``. The parallel-routers approach means existing
federation peers continue consuming the existing endpoints unchanged;
sm-bridge serves the
canonical NANDA shape for new consumers and forward migrations.

Architecture per ``docs/integrations/STELLARMINDS.md``:

  - sm-bridge is UPSTREAM. We never modify it.
  - This adapter is downstream — it inherits from ``AbstractAgentConverter``
    and implements the three abstract methods (``to_sm``, ``list_agents``,
    ``get_agent``) by reading from the chapter's in-memory ``members`` dict.
  - The chapter's existing federation endpoints continue serving — this
    is purely additive.

Migration plan (E4, separate later PR):

  - Bump federation peer chapters one at a time to consume
    ``/sm-bridge/index`` and ``/sm-bridge/resolve`` instead of the
    legacy endpoints.
  - When all peers have migrated, the legacy ``/.well-known/nanda-agent.json``
    + ``/agentfacts.json`` endpoints can be removed.

Public API:

  build_router_pair(*, agent_id, agent_name, public_url, members)
      → returns (nanda_router, wellknown_router, converter)
      Caller mounts the routers on FastAPI app with
        app.include_router(nanda_router, prefix="/sm-bridge")
        app.include_router(wellknown_router, prefix="/sm-bridge")
      and keeps a reference to ``converter`` for future agent additions.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

# All sm-bridge imports inside functions to keep this module importable
# even when sm-bridge isn't installed (graceful no-op fallback).


def _build_skills(member: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a chapter member's skills (list[str]) to sm-bridge's
    list[dict] skill shape. Each skill becomes a minimal SmSkill dict."""
    raw = member.get("skills") or []
    if isinstance(raw, str):
        raw = [s.strip() for s in raw.split(",") if s.strip()]
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for s in raw[:50]:
        if isinstance(s, str) and s.strip():
            out.append({"id": s.strip(), "description": s.strip()})
        elif isinstance(s, dict) and s.get("id"):
            out.append(s)
    return out


def discoverable(member_id: str, member: dict[str, Any] | None) -> bool:
    """Whether a member may appear on the anonymous sm-bridge surfaces at all.

    ONE rule for the index, the delta feed and the boot-time re-seed, so the
    three cannot disagree about who is discoverable: the member opted into
    the Listing (``member_listing.consent_of`` — the same record the Listing
    document reads), and is neither a test fixture nor a demo persona.
    """
    import member_listing

    m = member or {}
    if member_id.startswith("TEST-") or m.get("is_demo"):
        return False
    return member_listing.consent_of(m) is not None


def make_chapter_converter(
    *,
    agent_id: str,
    agent_name: str,
    public_url: str,
    members: dict[str, dict[str, Any]],
):
    """Build a chapter-specific AgentConverter that exposes the chapter's
    in-memory members dict as a NANDA-compliant registry.

    The converter:
      - registry_id = chapter's agent_id (e.g., "bayarea-nanda-chapter")
      - provider_name = chapter's agent_name (e.g., "@bayarea NANDA Chapter")
      - provider_url = chapter's PUBLIC_URL
      - base_url = chapter's PUBLIC_URL (where agents resolve from)

    Returns the converter instance (None if sm-bridge isn't installed).
    """
    try:
        from sm_bridge import (
            AbstractAgentConverter,
            SmAgentFacts,
            SmAuthentication,
            SmCapabilities,
            SmEndpoints,
            SmProvider,
            SmSkill,
        )
    except ImportError as e:
        print(f"[sm_bridge_adapter] sm-bridge not installed, /sm-bridge routes disabled: {e}")
        return None

    class ChapterAgentConverter(AbstractAgentConverter):
        """Reads the chapter's in-memory ``members`` dict and converts
        each entry to a ``SmAgentFacts`` for sm-bridge's routers."""

        def __init__(self) -> None:
            super().__init__(
                registry_id=agent_id,
                provider_name=agent_name,
                provider_url=public_url,
                base_url=public_url,
            )

        def to_sm(self, agent: dict[str, Any]) -> SmAgentFacts:
            """Map a chapter member dict to SmAgentFacts.

            Required SmAgentFacts fields per sm-bridge 0.3.1 models.py:
              id, agent_name, description, version, provider, endpoints,
              capabilities. All others are optional.
            """
            mid = agent.get("agent_id") or ""
            mname = agent.get("name") or mid
            # Not the member row's free-text description: this document is
            # served to anyone, and that field is member-authored prose the
            # consented Listing forbids (sm-listing 0.1 §4.2). The name is
            # what the org itself displays; it is the description here.
            description = mname

            # did:web from server's host (matches the convention used
            # by /.well-known/did.json already shipped by the chapter).
            host = public_url.replace("https://", "").replace("http://", "").split("/")[0]
            agent_did = f"did:web:{host}:agents:{mid}" if mid else f"did:web:{host}"

            # Build SmSkill list from server's flat skills list.
            skill_specs = _build_skills(agent)
            sm_skills = [
                SmSkill(id=spec["id"], description=spec.get("description", spec["id"])) for spec in skill_specs
            ]
            if not sm_skills:
                # NANDA AgentFacts requires >=1 skill (sm-bridge minItems:1).
                sm_skills = [SmSkill(id="urn:skill:general", description="General-purpose agent")]

            return SmAgentFacts(
                id=agent_did,
                agent_name=mname,
                label=mname,
                description=description,
                version="1.0.0",
                provider=SmProvider(
                    name=agent_name,
                    url=public_url,
                ),
                endpoints=SmEndpoints(
                    static=[f"{public_url.rstrip('/')}/a2a"],
                ),
                capabilities=SmCapabilities(
                    modalities=["text"],
                    skills=[s.id for s in sm_skills],
                    authentication=SmAuthentication(methods=["did-auth", "ed25519"]),
                ),
                skills=sm_skills,
            )

        def list_agents(self, limit: int, offset: int) -> Iterator[dict[str, Any]]:
            """Paginated iteration over the members who OPTED IN to be listed.

            ``/sm-bridge/index`` is served to anyone. It used to iterate every
            member — the population ``GET /api/members`` is signature-gated
            for, that the AI catalog withholds from a stranger, and that the
            consented Listing publishes only by opt-in — and it was measured
            doing so on a deployed org: all twenty-three members, names and
            descriptions, to an anonymous GET. The same consent record the
            Listing reads decides this enumeration, so an org has one answer
            to "who is discoverable" rather than one per document. Test
            fixtures (TEST-*) and demo personas stay excluded on top.
            """
            items = [{"agent_id": mid, **m} for mid, m in members.items() if discoverable(mid, m)]
            yield from items[offset : offset + limit]

        def get_agent(self, agent_id_to_resolve: str) -> dict[str, Any] | None:
            """Resolve a specific member.

            The index advertises ``id=did:web:{host}:agents:{mid}`` and
            ``agent_name=<name>``, so resolve MUST round-trip those — not just
            the raw member id — or a NANDA/NEST consumer that reads the index id
            and resolves by it 404s (the org twin of the agent's that change).
            """
            # Fast path: direct member-id match.
            m = members.get(agent_id_to_resolve)
            if m is not None and not m.get("is_demo"):
                return {"agent_id": agent_id_to_resolve, **m}

            # Round-trip the index-advertised did:web id, @handle, and agent_name.
            host = public_url.replace("https://", "").replace("http://", "").split("/")[0]
            for mid, member in members.items():
                if mid.startswith("TEST-") or member.get("is_demo"):
                    continue
                candidates = {
                    mid,
                    f"@{mid}",
                    f"did:web:{host}:agents:{mid}",
                    member.get("name") or mid,
                }
                if agent_id_to_resolve in candidates:
                    return {"agent_id": mid, **member}
            return None

        def is_public(self, agent: dict[str, Any]) -> bool:
            """Per the parent class contract — return False if the member
            should be excluded from public discovery. Currently mirrors
            list_agents's exclusion (TEST-* + is_demo)."""
            mid = agent.get("agent_id", "")
            if mid.startswith("TEST-"):
                return False
            return not agent.get("is_demo", False)

    return ChapterAgentConverter()


def mount_sm_bridge_routers(app, *, agent_id, agent_name, public_url, members, prefix="/sm-bridge"):
    """Wire sm-bridge's two FastAPI routers onto the chapter app at
    ``prefix``. Idempotent — calling twice on the same app is a no-op
    after the first call. Returns the converter for future use, or None
    if sm-bridge isn't available.

    The two routers:
      - nanda_router  — /index, /resolve, /deltas, /tools
      - wellknown_router — /.well-known/nanda-agent.json (mounted at
                           ``prefix`` so it lives at
                           ``/sm-bridge/.well-known/nanda-agent.json``,
                           leaving the chapter's own
                           ``/.well-known/nanda-agent.json`` untouched)
    """
    try:
        from sm_bridge import DeltaStore, create_sm_router
    except ImportError as e:
        print(f"[sm_bridge_adapter] mount skipped, sm-bridge missing: {e}")
        return None

    converter = make_chapter_converter(
        agent_id=agent_id,
        agent_name=agent_name,
        public_url=public_url,
        members=members,
    )
    if converter is None:
        return None

    delta_store = DeltaStore()
    global _mounted_delta_store, _mounted_converter
    _mounted_delta_store = delta_store
    _mounted_converter = converter

    nanda_router, wellknown_router = create_sm_router(
        converter=converter,
        delta_store=delta_store,
        registry_id=agent_id,
        base_url=public_url,
        provider_name=agent_name,
        provider_url=public_url,
        prefix=prefix,
    )

    app.include_router(nanda_router)
    # sm-bridge's wellknown router serves /.well-known/nanda.json which
    # does NOT collide with the server's existing
    # /.well-known/nanda-agent.json (different filename), so mount
    # without a prefix per the upstream's documented requirement.
    app.include_router(wellknown_router)

    # seed the delta feed from the persisted membership + a monotonic
    # base seq. The DeltaStore is in-memory and its counter resets to 0 on
    # every restart, so before this: (a) a delta-only consumer saw an EMPTY
    # feed after a restart even though /index had members — it never converged;
    # and (b) `next_seq` regressed (e.g. 5 → 1), so a consumer whose cursor was
    # ahead silently skipped every post-restart registration until the counter
    # climbed back. Seeding fixes both.
    seed_delta_store(members, base_seq=_monotonic_base_seq())

    return converter


def _monotonic_base_seq() -> int:
    """A delta-seq base that never regresses across a restart. Wall-clock ms:
    a restart takes seconds, so the new base always exceeds every seq the prior
    process issued — cursors can't go stale. (Gaps between bases are fine; the
    delta contract is a monotonic sequence, not a gapless one.)"""
    import time

    return int(time.time() * 1000)


def seed_delta_store(members: dict, *, base_seq: int) -> int:
    """Re-deliver the current membership as `upsert` deltas above ``base_seq``
    so a delta-only consumer converges to the full member set after a restart.
    Upserts are idempotent, so re-delivery is harmless. Returns the count
    seeded. No-op if sm-bridge isn't mounted."""
    if _mounted_delta_store is None or _mounted_converter is None:
        return 0
    _mounted_delta_store._seq = max(base_seq, getattr(_mounted_delta_store, "_seq", 0))
    seeded = 0
    for member_id, member in (members or {}).items():
        # The delta feed is the index in another shape — a consumer that
        # replays it from seq 0 rebuilds the index — so it carries exactly the
        # members the index would. It used to re-deliver every member.
        if not discoverable(member_id, member or {}):
            continue
        try:
            facts = _mounted_converter.to_sm({"agent_id": member_id, **(member or {})})
            _mounted_delta_store.add("upsert", facts)
            seeded += 1
        except Exception as e:  # noqa: BLE001 — a bad member row must not abort seeding
            print(f"[sm_bridge_adapter][WARN] delta seed skipped {member_id!r}: {type(e).__name__}: {e}")
    if seeded:
        print(f"[sm-bridge] delta feed seeded with {seeded} member(s) from base seq {base_seq}")
    return seeded


# The mounted store/converter — populated by mount_sm_bridge_routers so the
# member lifecycle can feed the quilt delta sync feed (the flagship-loop suite: /sm-bridge/deltas
# was served but NOTHING ever recorded a delta, so cross-org sync had an
# always-empty feed).
_mounted_delta_store = None
_mounted_converter = None


def record_member_delta(action: str, member_id: str, member: dict) -> None:
    """Record a member lifecycle change ("upsert"/"delete") into the quilt
    delta feed. No-op (loudly, once per boot pattern) when sm-bridge isn't
    mounted; never raises — registration must not fail on a sync-feed write."""
    if _mounted_delta_store is None or _mounted_converter is None:
        return
    # An upsert publishes; only a discoverable member is published. A delete
    # is always recorded — retracting a member who was never delivered is
    # harmless, and it is what a withdrawn consent has to produce.
    if action == "upsert" and not discoverable(member_id, member or {}):
        return
    try:
        facts = _mounted_converter.to_sm({"agent_id": member_id, **(member or {})})
        _mounted_delta_store.add(action, facts)
    except Exception as e:  # noqa: BLE001 — the feed is best-effort, but say so
        print(f"[sm_bridge_adapter][WARN] delta record failed for {member_id!r}: {type(e).__name__}: {e}")


__all__ = [
    "discoverable",
    "make_chapter_converter",
    "mount_sm_bridge_routers",
    "record_member_delta",
    "seed_delta_store",
]
