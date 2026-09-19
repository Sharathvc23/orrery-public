"""
A2UI Surface Builders — agent-generated page surfaces.

Each function builds a complete A2UI surface for a page. Called via
the SURFACE_BUILDERS dict in response to /api/surfaces/{page_id}.

All state is injected via init() — no circular imports with chapter_agent.
"""

import json
from collections.abc import Awaitable, Callable
from typing import Any

import thought_redaction
from a2ui_helpers import (
    accordion,
    action_button,
    badge,
    callout,
    card,
    chip,
    chip_group,
    code_block,
    column,
    divider,
    form,
    grid,
    heading,
    input_field,
    link,
    list_component,
    markdown,
    member_card,
    metric,
    progress,
    row,
    select,
    stat,
    stat_group,
    surface,
    table,
    text,
    textarea,
    timeline,
    toggle,
    trust_badge,
    with_meta,
)

# Injected state — set by init(), used by surface builders as module globals
pg_request: Callable[..., Awaitable] | None = None

def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if pg_request is None:
        raise RuntimeError("surfaces.init() was never called — no pg_request injected")
    return pg_request

members: dict = {}
federation: dict = {}
_knowledge_cache: dict = {}

# The dashboard's intent form, named once for both sides of the wire. A2UI
# gives an Input no `name` field: a renderer submits a Form's values keyed by
# each child's component id (renderer/src/render.js, c_Input), so the id the
# surface declares here IS the key the action handler must read. The two were
# once spelled independently — `dash-intent-input` here, `intent_text` in
# chapter_agent.handle_surface_action — and the form answered "Missing Intent"
# to every submission made through a renderer.
DASH_INTENT_FORM = "dash-intent-form"
DASH_INTENT_INPUT = "dash-intent-input"
DASH_INTENT_TAGS = "dash-intent-tags"
AGENT_ID = ""
AGENT_NAME = ""
think_cycle_count = 0
_get_think_count: Any = None  # callable
intents: Any = None  # intents module
projections: Any = None
outcome_tracker: Any = None
agent_conversations_mod: Any = None
federation_intelligence: Any = None
activity_tracker = None
portal_layout: Any = None  # callable


def set_display_name(name: str) -> None:
    """Org display name shown in surface titles. chapter_agent calls this on
    startup and on first-run config save; falls back to env AGENT_NAME when the
    org is unconfigured."""
    global AGENT_NAME
    if name:
        AGENT_NAME = name


def init(
    pg_request_fn,
    members_dict,
    federation_dict,
    knowledge_cache,
    agent_id,
    agent_name,
    get_think_count,
    intents_mod=None,
    projections_mod=None,
    outcome_tracker_mod=None,
    agent_conversations_module=None,
    federation_intelligence_mod=None,
    activity_tracker_mod=None,
    portal_layout_fn=None,
):
    global pg_request, members, federation, _knowledge_cache
    global AGENT_ID, AGENT_NAME, _get_think_count
    global intents, projections, outcome_tracker
    global agent_conversations_mod, federation_intelligence, activity_tracker, portal_layout
    pg_request = pg_request_fn
    members = members_dict
    federation = federation_dict
    _knowledge_cache = knowledge_cache
    AGENT_ID = agent_id
    AGENT_NAME = agent_name
    _get_think_count = get_think_count
    intents = intents_mod
    projections = projections_mod
    outcome_tracker = outcome_tracker_mod
    agent_conversations_mod = agent_conversations_module
    federation_intelligence = federation_intelligence_mod
    activity_tracker = activity_tracker_mod
    portal_layout = portal_layout_fn


async def build_members_surface(target: str | None = None) -> dict:
    """A2UI surface for the members directory.

    PR-A7: Each member is now emitted as a single first-class
    ``MemberCard`` component instead of a hand-built tree of
    ``Card → Column → Avatar + Badge + Text + List + Link`` (5+ nodes
    per member). The renderer turns ``MemberCard`` into an ``<article
    aria-label>`` landmark with proper heading hierarchy and a
    typed skills ``<ul>``. End-to-end win on the most-prominent
    chapter surface — ~60 lines of node-building collapse to one
    helper call per member.

    Note: the per-member "GitHub" link node is dropped here. The
    information lives on the agent profile page reachable from the
    MemberCard; replaying it inside every directory cell was
    duplicative and added a fifth interactive target per row.
    """
    agent_profiles = {}
    profile_data = await _pg()(
        "GET",
        "agents",
        params={
            "select": "agent_id,profile_type,interests,github_data,linkedin_url,trust_score",
        },
    )
    if profile_data:
        for p in profile_data:
            agent_profiles[p.get("agent_id", "")] = p

    sections = ["members-title", "members-count"]
    components = [
        text("members-title", "Members", "h1"),
        text("members-count", f"{len(members)} agents in the network", "caption"),
    ]

    humans = [(mid, m) for mid, m in members.items() if not m.get("virtual") and not mid.startswith("STARTUP-")]
    chapter_agents = [(mid, m) for mid, m in members.items() if m.get("virtual") and not mid.startswith("STARTUP-")]
    startup_agents = [(mid, m) for mid, m in members.items() if mid.startswith("STARTUP-")]

    for group_label, group_members in [
        ("Community Members", humans),
        ("Org Agents", chapter_agents),
        ("Startup Team Agents", startup_agents),
    ]:
        if not group_members:
            continue
        gid = group_label.lower().replace(" ", "-")
        sections.extend([f"{gid}-div", f"{gid}-label"])
        components.extend(
            [
                divider(f"{gid}-div"),
                text(f"{gid}-label", f"{group_label} ({len(group_members)})", "h2"),
            ]
        )

        member_card_ids = []
        for i, (mid, m) in enumerate(group_members[:20]):
            cid = f"{gid}-m{i}"
            profile = agent_profiles.get(mid, {})
            role = profile.get("profile_type", "member")
            trust_score = profile.get("trust_score")
            description = m.get("description", "")
            skills = m.get("skills") or []

            components.append(
                member_card(
                    cid,
                    name=m["name"],
                    agent_id=mid,
                    role=role,
                    trust_score=float(trust_score) if trust_score is not None else None,
                    skills=list(skills),
                    subtitle=description,
                )
            )
            member_card_ids.append(cid)

        grid_id = f"{gid}-grid"
        sections.append(grid_id)
        components.append(grid(grid_id, member_card_ids, 3))

    components.insert(0, column("root", sections))
    return surface("surface-members", [card("page", "root")] + components, "page")


async def build_events_surface(target: str | None = None) -> dict:
    """A2UI surface for /page/events — the same anonymously-reachable
    community events board as GET /api/events, so it needs the same
    suggested_speakers redaction. See thought_redaction.redact_suggested_speakers.
    """
    events = await _pg()(
        "GET",
        "agent_events",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": "20",
        },
    )
    events = thought_redaction.redact_suggested_speakers(events or [])

    sections = ["events-title", "events-count"]
    components = [
        text("events-title", "Events", "h1"),
        text("events-count", f"{len(events or [])} community events", "caption"),
    ]

    for i, ev in enumerate(events or []):
        eid = f"ev-{i}"
        children = [f"{eid}-type", f"{eid}-name", f"{eid}-desc"]
        comps = [
            badge(f"{eid}-type", ev.get("event_type", "event").replace("_", " "), "secondary"),
            text(f"{eid}-name", ev.get("title", ""), "h3"),
            text(f"{eid}-desc", ev.get("description", ""), "body"),
        ]
        if ev.get("proposed_reason"):
            children.append(f"{eid}-reason")
            comps.append(text(f"{eid}-reason", f"Why: {ev['proposed_reason']}", "caption"))
        if ev.get("suggested_speakers"):
            children.append(f"{eid}-speakers")
            comps.append(list_component(f"{eid}-speakers", ev["suggested_speakers"]))
        children.append(f"{eid}-status")
        comps.append(badge(f"{eid}-status", ev.get("status", "proposed"), "outline"))

        comps.insert(0, column(f"{eid}-col", children))
        components.extend([card(eid, f"{eid}-col")] + comps)
        sections.append(eid)

    if not events:
        sections.append("events-empty")
        components.append(
            text(
                "events-empty",
                "Agents will propose events based on member skills and interests. Check back soon.",
                "body",
            )
        )

    components.insert(0, column("root", sections))
    return surface("surface-events", [card("page", "root")] + components, "page")




async def build_activity_surface(target: str | None = None) -> dict:
    thoughts = await _pg()(
        "GET",
        "agent_thoughts",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": "20",
            # member_name is NOT selected: nothing below renders it, and the activity-feed PII closure
            # showed this surface is served to anonymous callers.
            "select": "id,thought_type,thought_text,chapter_name,created_at",
        },
    )
    # this surface is PUBLIC and was rendering `member_name` next to
    # `user_message_snippet` — a member's name beside what they said to their
    # agent. Probed live: real member names and the message text appeared
    # VERBATIM in this response on every one of the 8 deployed services.
    #
    # It read as safe because the leak is invisible to a field-name probe: the
    # values are flattened into A2UI `Text` components, so `member_name` and
    # `user_message_snippet` are absent as KEYS while present as VALUES.
    #
    # Neither field is selected now. The counts below keep the page honest
    # about how much is happening without saying who or what.
    activity = await _pg()(
        "GET",
        "agent_activity",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": "20",
            "select": "id,chapter_name,is_cross_chapter,created_at",
        },
    )

    sections = ["activity-title"]
    components = [text("activity-title", "Community Activity", "h1")]

    # Recent thoughts
    if thoughts:
        sections.append("thoughts-label")
        components.append(text("thoughts-label", "Agent Thoughts", "h2"))
        for i, t in enumerate((thoughts or [])[:10]):
            tid = f"th-{i}"
            children = [f"{tid}-type", f"{tid}-text"]
            comps = [
                badge(f"{tid}-type", t.get("thought_type", ""), "secondary"),
                # thought_text is agent-authored PROSE carrying member handles
                # inside the sentence — think_conversation composes it as
                # "@{speaker}: {text}" per line. No `select` can reach that,
                # which is why the earlier PII closure on this surface
                # (member_name, user_message_snippet) left it exposed.
                # Redacted at READ because this covers rows already written;
                # the write path is redacted too and neither makes the other
                # unnecessary — see thought_redaction.
                text(f"{tid}-text", thought_redaction.redact_handles(t.get("thought_text", ""))[:200], "body"),
            ]
            comps.insert(0, column(f"{tid}-col", children))
            components.extend([card(tid, f"{tid}-col")] + comps)
            sections.append(tid)

    # Recent conversations — COUNTS ONLY.
    #
    # This block used to emit one card per conversation carrying the member's
    # name and both message snippets. There is no redacted per-conversation
    # card worth rendering: strip the who and the what and a card says only
    # "a conversation happened", so the aggregate below carries the same
    # information without 10 empty cards. A signed member or an operator reads
    # the full feed at GET /api/activity.
    if activity:
        total = len(activity)
        cross = sum(1 for a in activity if a.get("is_cross_chapter"))
        summary = f"{total} recent conversation{'s' if total != 1 else ''}"
        if cross:
            summary += f" · {cross} cross-server"
        sections.extend(["act-div", "act-label", "act-summary"])
        components.extend(
            [
                divider("act-div"),
                text("act-label", "Conversations", "h2"),
                text("act-summary", summary, "body"),
            ]
        )

    components.insert(0, column("root", sections))
    return surface("surface-activity", [card("page", "root")] + components, "page")


async def build_groups_surface(target: str | None = None) -> dict:
    """Detect skill clusters and generate group proposals."""
    skill_members: dict[str, list[str]] = {}
    for mid, m in members.items():
        if mid.startswith("STARTUP-"):
            continue
        for skill in m.get("skills", []):
            skill_lower = skill.lower()
            skill_members.setdefault(skill_lower, []).append(m["name"])

    # Find clusters (3+ members with same skill)
    clusters = [(skill, names) for skill, names in skill_members.items() if len(names) >= 2]
    clusters.sort(key=lambda x: -len(x[1]))

    sections = ["groups-title", "groups-count"]
    components = [
        text("groups-title", "Working Groups", "h1"),
        text("groups-count", f"{len(clusters)} skill clusters detected", "caption"),
    ]

    for i, (skill, group_members) in enumerate(clusters[:15]):
        gid = f"g-{i}"
        children = [f"{gid}-skill", f"{gid}-count", f"{gid}-members"]
        comps = [
            text(f"{gid}-skill", skill.title(), "h3"),
            text(f"{gid}-count", f"{len(group_members)} members", "caption"),
            list_component(f"{gid}-members", group_members[:6]),
        ]
        comps.insert(0, column(f"{gid}-col", children))
        components.extend([card(gid, f"{gid}-col")] + comps)
        sections.append(gid)

    if not clusters:
        sections.append("groups-empty")
        components.append(text("groups-empty", "Groups will form as more members join with shared skills.", "body"))

    components.insert(0, column("root", sections))
    return surface("surface-groups", [card("page", "root")] + components, "page")


async def build_dashboard_surface(target: str | None = None) -> dict:
    sections = ["dash-title"]
    components = [text("dash-title", f"{AGENT_NAME} — Dashboard", "h1")]

    # Stats row — stacks vertically below md breakpoint so it stays
    # readable on phones instead of squeezing 4 metrics into one row.
    sections.append("dash-stats")
    stats_children = ["dash-members", "dash-federation", "dash-cycles"]
    components.extend(
        [
            with_meta(
                row("dash-stats", stats_children),
                responsive={"stackBelow": "md"},
            ),
            metric("dash-members", str(len(members)), "Members"),
            metric("dash-federation", str(len(federation)), "Peer orgs"),
            metric("dash-cycles", str(_get_think_count()), "Think Cycles"),
        ]
    )

    # Intent submission form (interactive A2UI). ariaLabel on each input
    # so screen-reader users hear the field's purpose, not just the
    # placeholder (which assistive tech doesn't reliably announce).
    sections.extend(["dash-div-intent", "dash-intent-label", DASH_INTENT_FORM])
    components.extend(
        [
            divider("dash-div-intent"),
            text("dash-intent-label", "What Do You Need?", "h2"),
            form(DASH_INTENT_FORM, [DASH_INTENT_INPUT, DASH_INTENT_TAGS], "submit_intent", "Find Match"),
            with_meta(
                input_field(
                    DASH_INTENT_INPUT,
                    "Describe your need",
                    "e.g. Someone who knows Rust for edge computing",
                    "",
                    "text",
                ),
                a11y={"ariaLabel": "Describe what kind of agent or skill you are looking for"},
            ),
            with_meta(
                input_field(DASH_INTENT_TAGS, "Skills (optional)", "e.g. rust, edge-computing, robotics", "", "text"),
                a11y={"ariaLabel": "Optional comma-separated skill tags to refine the match"},
            ),
        ]
    )

    # Active intents
    active_intents = await intents.get_active_intents()
    if active_intents:
        sections.extend(["dash-intents-label"])
        components.append(text("dash-intents-label", f"{len(active_intents)} Active Intents", "h3"))
        for i, intent in enumerate(active_intents[:3]):
            iid = f"dash-int-{i}"
            sections.append(iid)
            status = intent.get("status", "active")
            matches = intent.get("matches_found", 0)
            components.extend(
                [
                    card(iid, f"{iid}-col"),
                    column(f"{iid}-col", [f"{iid}-text", f"{iid}-meta"]),
                    text(f"{iid}-text", intent.get("intent_text", "")[:100], "body"),
                    row(f"{iid}-meta", [f"{iid}-status", f"{iid}-matches"]),
                    badge(f"{iid}-status", status, "outline"),
                    badge(f"{iid}-matches", f"{matches} matches", "secondary"),
                ]
            )

    # Recent thoughts
    thoughts = await _pg()(
        "GET",
        "agent_thoughts",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": "5",
            "select": "thought_type,thought_text",
        },
    )
    if thoughts:
        sections.extend(["dash-div1", "dash-thoughts-label"])
        components.extend([divider("dash-div1"), text("dash-thoughts-label", "Recent Activity", "h2")])
        for i, t in enumerate(thoughts[:5]):
            tid = f"dash-t{i}"
            sections.append(tid)
            components.extend(
                [
                    card(tid, f"{tid}-col"),
                    column(f"{tid}-col", [f"{tid}-type", f"{tid}-text"]),
                    badge(f"{tid}-type", t.get("thought_type", ""), "secondary"),
                    text(f"{tid}-text", t.get("thought_text", "")[:120], "body"),
                ]
            )

    # Federation
    if federation:
        sections.extend(["dash-div2", "dash-fed-label"])
        components.extend([divider("dash-div2"), text("dash-fed-label", "Federation", "h2")])
        for cid, ch in federation.items():
            fid = f"dash-f-{cid[:8]}"
            sections.append(fid)
            components.extend(
                [
                    card(fid, f"{fid}-col"),
                    column(f"{fid}-col", [f"{fid}-name", f"{fid}-status"]),
                    text(f"{fid}-name", ch.get("name", cid), "h4"),
                    badge(f"{fid}-status", f"{ch.get('members', 0)} agents · {ch.get('status', '?')}", "outline"),
                ]
            )

    components.insert(0, column("root", sections))
    return surface("surface-dashboard", [card("page", "root")] + components, "page")


async def build_messages_surface(target: str | None = None) -> dict:
    conversations = await _pg()(
        "GET",
        "agent_conversations",
        params={
            "order": "updated_at.desc",
            "limit": "20",
            "select": "conversation_id,title,updated_at",
        },
    )

    sections = ["msg-title"]
    components = [text("msg-title", "Messages", "h1")]

    if conversations:
        for i, conv in enumerate(conversations[:15]):
            cid = f"msg-{i}"
            sections.append(cid)
            components.extend(
                [
                    card(cid, f"{cid}-col"),
                    column(f"{cid}-col", [f"{cid}-title", f"{cid}-id"]),
                    text(f"{cid}-title", conv.get("title", conv.get("conversation_id", "Conversation")), "h4"),
                    text(f"{cid}-id", conv.get("conversation_id", "")[:30], "caption"),
                ]
            )
    else:
        sections.append("msg-empty")
        components.append(
            text("msg-empty", "No conversations yet. Messages appear when agents interact with each other.", "body")
        )

    components.insert(0, column("root", sections))
    return surface("surface-messages", [card("page", "root")] + components, "page")


async def build_calendar_surface(target: str | None = None) -> dict:
    events = await _pg()(
        "GET",
        "agent_events",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": "20",
        },
    )

    sections = ["cal-title"]
    components = [text("cal-title", "Calendar", "h1")]

    if events:
        for i, ev in enumerate(events or []):
            eid = f"cal-{i}"
            sections.append(eid)
            components.extend(
                [
                    card(eid, f"{eid}-col"),
                    column(f"{eid}-col", [f"{eid}-type", f"{eid}-title", f"{eid}-desc", f"{eid}-status"]),
                    badge(f"{eid}-type", ev.get("event_type", "event").replace("_", " "), "secondary"),
                    text(f"{eid}-title", ev.get("title", ""), "h3"),
                    text(f"{eid}-desc", ev.get("description", ""), "body"),
                    badge(f"{eid}-status", ev.get("status", "proposed"), "outline"),
                ]
            )
    else:
        sections.append("cal-empty")
        components.append(
            text("cal-empty", "No events scheduled. Events will appear here as agents propose them.", "body")
        )

    components.insert(0, column("root", sections))
    return surface("surface-calendar", [card("page", "root")] + components, "page")


async def build_digest_surface(target: str | None = None) -> dict:
    digests = await _pg()(
        "GET",
        "agent_digests",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "created_at.desc",
            "limit": "5",
        },
    )

    sections = ["dig-title"]
    components = [text("dig-title", "Server Digest", "h1")]

    for i, d in enumerate(digests or []):
        did = f"dig-{i}"
        content = d.get("content_json", {})
        highlights = d.get("highlights", [])
        sections.append(did)
        children = [f"{did}-label"]
        comps = [text(f"{did}-label", d.get("title", "Weekly Digest"), "h2")]
        if content.get("summary"):
            children.append(f"{did}-summary")
            comps.append(text(f"{did}-summary", content["summary"], "body"))
        if highlights:
            children.append(f"{did}-highlights")
            comps.append(list_component(f"{did}-highlights", highlights))
        comps.insert(0, column(f"{did}-col", children))
        components.extend([card(did, f"{did}-col")] + comps)

    if not digests:
        sections.append("dig-empty")
        components.append(
            text("dig-empty", "Weekly digests are published automatically. First one coming soon.", "body")
        )

    components.insert(0, column("root", sections))
    return surface("surface-digest", [card("page", "root")] + components, "page")


async def build_knowledge_surface(target: str | None = None) -> dict:
    """A2UI surface showing chapter intelligence and learning."""
    intel = _knowledge_cache.get("chapter_intelligence", {})

    sections = ["know-title"]
    components = [text("know-title", "Server Intelligence", "h1")]

    if not intel:
        sections.append("know-empty")
        components.append(
            text(
                "know-empty",
                "The agent hasn't reflected yet. Intelligence builds over time as the org operates.",
                "body",
            )
        )
    else:
        # Last reflected
        if intel.get("last_reflected"):
            sections.append("know-updated")
            components.append(text("know-updated", f"Last updated: {intel['last_reflected'][:19]}", "caption"))

        # Stats row
        sections.append("know-stats")
        components.extend(
            [
                row("know-stats", ["know-members", "know-active", "know-skills"]),
                metric("know-members", str(intel.get("member_count", 0)), "Members"),
                metric("know-active", str(len(intel.get("active_members", []))), "Active"),
                metric("know-skills", str(len(intel.get("skill_graph", {}))), "Skills"),
            ]
        )

        # Patterns
        if intel.get("patterns"):
            sections.extend(["know-div1", "know-patterns-label", "know-patterns"])
            components.extend(
                [
                    divider("know-div1"),
                    text("know-patterns-label", "Observed Patterns", "h2"),
                    list_component("know-patterns", intel["patterns"]),
                ]
            )

        # Trending topics
        if intel.get("trending_topics"):
            sections.extend(["know-topics-label", "know-topics"])
            components.extend(
                [
                    text("know-topics-label", "Trending Topics", "h2"),
                    list_component("know-topics", intel["trending_topics"]),
                ]
            )

        # Skill gaps
        if intel.get("skill_gaps"):
            sections.extend(["know-gaps-label", "know-gaps"])
            components.extend(
                [
                    text("know-gaps-label", "Skill Gaps", "h2"),
                    list_component("know-gaps", intel["skill_gaps"]),
                ]
            )

        # Recommendations
        if intel.get("recommendations"):
            sections.extend(["know-div2", "know-recs-label", "know-recs"])
            components.extend(
                [
                    divider("know-div2"),
                    text("know-recs-label", "Recommendations", "h2"),
                    list_component("know-recs", intel["recommendations"]),
                ]
            )

        # Skill graph (top 10)
        skill_graph = intel.get("skill_graph", {})
        if skill_graph:
            sections.extend(["know-div3", "know-sg-label"])
            components.extend([divider("know-div3"), text("know-sg-label", "Skill Distribution", "h2")])
            for i, (skill, count) in enumerate(sorted(skill_graph.items(), key=lambda x: -x[1])[:10]):
                sid = f"know-skill-{i}"
                sections.append(sid)
                components.append(progress(sid, min(100, count * 20), f"{skill} ({count} members)"))

        # Member insights
        if intel.get("member_insights"):
            sections.extend(["know-div4", "know-mi-label", "know-mi"])
            components.extend(
                [
                    divider("know-div4"),
                    text("know-mi-label", "Member Insights", "h2"),
                    list_component("know-mi", intel["member_insights"]),
                ]
            )

    components.insert(0, column("root", sections))
    return surface("surface-knowledge", [card("page", "root")] + components, "page")


async def build_federation_knowledge_surface(target: str | None = None) -> dict:
    """A2UI surface showing network-wide intelligence from federation exchange."""
    sections = ["fed-title"]
    components = [text("fed-title", "Federation Intelligence", "h1")]

    our_summary = federation_intelligence.get_our_summary()
    peer_count = len(federation_intelligence.federation_knowledge)
    skill_matches = federation_intelligence.find_skill_matches()
    network_trends = federation_intelligence.get_network_trends()
    network_skills = federation_intelligence.get_network_skill_map()

    # Stats row
    sections.append("fed-stats")
    total_members = our_summary.get("member_count", 0)
    for k in federation_intelligence.federation_knowledge.values():
        total_members += k.get("member_count", 0)
    components.extend(
        [
            row("fed-stats", ["fed-chapters", "fed-members", "fed-skills"]),
            metric("fed-chapters", str(peer_count + 1), "Orgs"),
            metric("fed-members", str(total_members), "Network Members"),
            metric("fed-skills", str(len(network_skills)), "Skills Tracked"),
        ]
    )

    # Skill matches (our gaps ↔ their strengths)
    if skill_matches:
        sections.extend(["fed-div1", "fed-matches-label"])
        components.extend(
            [
                divider("fed-div1"),
                text("fed-matches-label", "Cross-Server Skill Matches", "h2"),
            ]
        )
        for i, match in enumerate(skill_matches[:5]):
            mid = f"fed-match-{i}"
            sections.append(mid)
            match_text = (
                f"Gap: {match['our_gap']} → {match['their_chapter_name']} "
                f"has {', '.join(match['their_matching_skills'])} "
                f"({match['their_member_count']} members)"
            )
            components.append(text(mid, match_text, "body"))

    # Network trends
    if network_trends:
        sections.extend(["fed-div2", "fed-trends-label", "fed-trends"])
        components.extend(
            [
                divider("fed-div2"),
                text("fed-trends-label", "Network-Wide Trends", "h2"),
                list_component("fed-trends", network_trends[:8]),
            ]
        )

    # Top network skills
    if network_skills:
        sections.extend(["fed-div3", "fed-skills-label"])
        components.extend([divider("fed-div3"), text("fed-skills-label", "Network Skill Map", "h2")])
        sorted_skills = sorted(network_skills.items(), key=lambda x: -x[1]["total"])[:10]
        for i, (skill, info) in enumerate(sorted_skills):
            sid = f"fed-skill-{i}"
            sections.append(sid)
            chapter_list = ", ".join(info["chapters"][:3])
            components.append(
                progress(sid, min(100, info["total"] * 10), f"{skill} ({info['total']} members — {chapter_list})")
            )

    # Peer server summaries
    if federation_intelligence.federation_knowledge:
        sections.extend(["fed-div4", "fed-peers-label"])
        components.extend(
            [
                divider("fed-div4"),
                text("fed-peers-label", "Server Intelligence", "h2"),
            ]
        )
        for i, (cid, knowledge) in enumerate(federation_intelligence.federation_knowledge.items()):
            cname = knowledge.get("chapter_name", cid)
            top = knowledge.get("top_skills", [])[:5]
            gaps = knowledge.get("skill_gaps", [])[:3]
            pid = f"fed-peer-{i}"
            sections.append(pid)
            peer_text = f"{cname}: {knowledge.get('member_count', '?')} members"
            if top:
                peer_text += f" | Top skills: {', '.join(top)}"
            if gaps:
                peer_text += f" | Gaps: {', '.join(gaps)}"
            components.append(text(pid, peer_text, "body"))

    if peer_count == 0:
        sections.append("fed-empty")
        components.append(
            text(
                "fed-empty",
                "No federation knowledge yet — exchange happens every ~6 minutes with online orgs.",
                "body",
            )
        )

    components.insert(0, column("root", sections))
    return surface("surface-federation", [card("page", "root")] + components, "page")


async def build_intents_surface(target: str | None = None) -> dict:
    """A2UI surface for intent-based matching."""
    active = await intents.get_active_intents()

    sections = ["int-title"]
    components = [text("int-title", "Intent Matching", "h1")]

    # Stats
    matched = sum(1 for i in active if i.get("status") == "matched")
    total_matches = sum(i.get("matches_found", 0) for i in active)
    sections.append("int-stats")
    components.extend(
        [
            row("int-stats", ["int-active", "int-matched", "int-total"]),
            metric("int-active", str(len(active)), "Active Intents"),
            metric("int-matched", str(matched), "With Matches"),
            metric("int-total", str(total_matches), "Total Matches"),
        ]
    )

    # Active intents with match details
    if active:
        sections.extend(["int-div1", "int-list-label"])
        components.extend([divider("int-div1"), text("int-list-label", "Active Intents", "h2")])
        for i, intent in enumerate(active[:10]):
            iid = f"int-item-{i}"
            sections.append(iid)
            status = intent.get("status", "active")
            matches = intent.get("matches_found", 0)
            match_details = intent.get("match_details") or []
            tags = intent.get("intent_tags", [])

            # Intent card with details
            card_children = [f"{iid}-text", f"{iid}-meta"]
            components.extend(
                [
                    card(iid, f"{iid}-col"),
                    column(f"{iid}-col", card_children),
                    text(f"{iid}-text", intent.get("intent_text", "?")[:120], "body"),
                ]
            )

            meta_items = [f"{iid}-status", f"{iid}-matches"]
            components.extend(
                [
                    row(f"{iid}-meta", meta_items),
                    badge(f"{iid}-status", status, "outline"),
                    badge(f"{iid}-matches", f"{matches} matches", "secondary"),
                ]
            )

            # Show tags
            if tags:
                tag_ids = []
                for ti, tag in enumerate(tags[:5]):
                    tid = f"{iid}-tag-{ti}"
                    tag_ids.append(tid)
                    components.append(badge(tid, tag, "outline"))
                card_children.append(f"{iid}-tags")
                components.append(row(f"{iid}-tags", tag_ids))

            # Show match breakdown per server
            if match_details:
                card_children.append(f"{iid}-details-label")
                components.append(text(f"{iid}-details-label", "Match Breakdown:", "caption"))
                for di, detail in enumerate(match_details[:5]):
                    did = f"{iid}-d-{di}"
                    card_children.append(did)
                    ch = detail.get("chapter", "?")
                    if detail.get("remote"):
                        ch_count = detail.get("match_count", 0)
                        ch_skills = ", ".join(detail.get("skills", [])[:3])
                        components.append(text(did, f"  {ch}: {ch_count} matches ({ch_skills})", "caption"))
                    else:
                        score = detail.get("score", 0)
                        ch_skills = ", ".join(detail.get("skills", [])[:3])
                        components.append(text(did, f"  {ch}: score {score:.1f} ({ch_skills})", "caption"))
    else:
        sections.append("int-empty")
        components.append(
            text(
                "int-empty",
                "No active intents. Use the dashboard form or chat to tell your agent what you need.",
                "body",
            )
        )

    components.insert(0, column("root", sections))
    return surface("surface-intents", [card("page", "root")] + components, "page")


async def build_outcomes_surface(target: str | None = None) -> dict:
    """A2UI surface showing action quality and feedback trends."""
    scores = await outcome_tracker.get_quality_scores()

    sections = ["out-title"]
    components = [text("out-title", "Action Outcomes", "h1")]

    if not scores:
        sections.append("out-empty")
        components.append(
            text(
                "out-empty",
                "No feedback yet. Use the thumbs up/down buttons on agent thoughts to help the agent learn.",
                "body",
            )
        )
    else:
        # Stats row
        total_feedback = sum(s.get("total", 0) for s in scores.values())
        total_positive = sum(s.get("positive", 0) for s in scores.values())
        overall_rate = round(total_positive / max(total_feedback, 1) * 100)
        sections.append("out-stats")
        components.extend(
            [
                row("out-stats", ["out-total", "out-positive", "out-rate"]),
                metric("out-total", str(total_feedback), "Total Feedback"),
                metric("out-positive", str(total_positive), "Positive"),
                metric("out-rate", f"{overall_rate}%", "Success Rate"),
            ]
        )

        # Per-type breakdown
        sections.extend(["out-div1", "out-types-label"])
        components.extend([divider("out-div1"), text("out-types-label", "Quality by Action Type", "h2")])
        for atype, s in sorted(scores.items(), key=lambda x: -x[1].get("avg_quality", 0)):
            oid = f"out-type-{atype}"
            sections.append(oid)
            color = "green" if s.get("avg_quality", 0) > 0.3 else "yellow" if s.get("avg_quality", 0) >= 0 else "red"
            components.append(
                progress(
                    oid,
                    min(100, max(0, s.get("success_rate", 50))),
                    f"{atype}: {s['total']} signals, {s['success_rate']}% positive",
                    color,
                )
            )

    components.insert(0, column("root", sections))
    return surface("surface-outcomes", [card("page", "root")] + components, "page")


async def build_conversations_surface(target: str | None = None) -> dict:
    """A2UI surface showing agent-to-agent conversation threads."""
    # Get all active threads
    all_threads = await _pg()(
        "GET",
        "agent_conversation_threads",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "order": "updated_at.desc",
            "limit": "20",
        },
    )

    sections = ["conv-title"]
    components = [text("conv-title", "Agent Conversations", "h1")]

    active = [t for t in (all_threads or []) if t.get("status") == "active"]
    [t for t in (all_threads or []) if t.get("status") == "completed"]

    # Stats
    sections.append("conv-stats")
    components.extend(
        [
            row("conv-stats", ["conv-active", "conv-total", "conv-msgs"]),
            metric("conv-active", str(len(active)), "Active"),
            metric("conv-total", str(len(all_threads or [])), "Total Threads"),
            metric("conv-msgs", str(sum(t.get("message_count", 0) for t in (all_threads or []))), "Messages"),
        ]
    )

    if not all_threads:
        sections.append("conv-empty")
        components.append(
            text(
                "conv-empty",
                "No agent conversations yet. Sovereign agents can start conversations via the start_conversation tool, or the org agent brokers them during think cycles.",
                "body",
            )
        )
    else:
        # Active threads
        if active:
            sections.extend(["conv-div1", "conv-active-label"])
            components.extend([divider("conv-div1"), text("conv-active-label", "Active Conversations", "h2")])
            for i, t in enumerate(active[:10]):
                tid = f"conv-t-{i}"
                sections.append(tid)
                msgs = t.get("messages") or []
                last_msg = msgs[-1] if msgs else {}
                components.extend(
                    [
                        card(tid, f"{tid}-col"),
                        column(f"{tid}-col", [f"{tid}-header", f"{tid}-topic", f"{tid}-last"]),
                        row(f"{tid}-header", [f"{tid}-from", f"{tid}-arrow", f"{tid}-to", f"{tid}-count"]),
                        badge(f"{tid}-from", f"@{t.get('from_agent_id', '?')}", "secondary"),
                        text(f"{tid}-arrow", "↔", "body"),
                        badge(f"{tid}-to", f"@{t.get('to_agent_id', '?')}", "secondary"),
                        badge(f"{tid}-count", f"{t.get('message_count', 0)} msgs", "outline"),
                        text(f"{tid}-topic", t.get("topic", "")[:80], "caption"),
                        text(
                            f"{tid}-last",
                            f"Latest: {last_msg.get('from', '?')}: {last_msg.get('text', '')[:100]}",
                            "body",
                        ),
                    ]
                )

    components.insert(0, column("root", sections))
    return surface("surface-conversations", [card("page", "root")] + components, "page")


async def build_chapter_surface(target: str | None = None) -> dict:
    """Reuse portal/layout as chapter surface."""
    # include_members=True: this page is /api/surfaces/chapter, which is itself
    # gated to verified callers (auth_verify.MEMBER_BEARING_SURFACES), so the
    # member section is authorized here. Passing it explicitly rather than
    # letting the layout infer from a Request it does not have — an internal
    # caller has no request, and inferring would silently drop the section for a
    # reader who is entitled to it.
    return await portal_layout(include_members=True)


async def build_admin_surface(target: str | None = None) -> dict:
    """A2UI surface for the admin console — org-level intelligence."""
    sections = ["admin-title", "admin-subtitle", "admin-leader-tools"]
    components = [
        text("admin-title", "Admin Console", "h1"),
        text("admin-subtitle", f"Organization intelligence across {AGENT_NAME}", "caption"),
        # Leader navigation — surfaces that leaders need but users shouldn't stumble into
        row(
            "admin-leader-tools",
            ["admin-nav-policy", "admin-nav-approvals", "admin-nav-audit"],
        ),
        link("admin-nav-policy", "Server Policy", "/page/policy"),
        link("admin-nav-approvals", "Approval Queue", "/page/approvals"),
        link("admin-nav-audit", "Audit Log", "/page/audit"),
    ]

    # ── Section 1: Org Health Overview ──────────────────────
    intel = (_knowledge_cache or {}).get("chapter_intelligence", {})
    member_count = len(members)
    human_members = sum(1 for m in members.values() if not m.get("virtual"))
    online_chapters = sum(1 for f in federation.values() if f.get("status") == "online")
    active_intents = await intents.get_active_intents() if intents else []
    matched_intents = [i for i in active_intents if i.get("matches_found", 0) > 0]

    sections.append("admin-health")
    components.extend(
        [
            row("admin-health", ["admin-h-members", "admin-h-humans", "admin-h-chapters", "admin-h-intents"]),
            metric("admin-h-members", str(member_count), "Total Agents"),
            metric("admin-h-humans", str(human_members), "Human Members"),
            metric(
                "admin-h-chapters",
                str(online_chapters + 1),
                "Orgs Online",
                trend="up" if online_chapters > 0 else "neutral",
            ),
            metric("admin-h-intents", str(len(matched_intents)), "Intents Matched", suffix=f"/{len(active_intents)}"),
        ]
    )

    # ── Section 2: Skill Intelligence ──────────────────────
    sections.extend(["admin-div1", "admin-skills-label"])
    components.extend(
        [
            divider("admin-div1"),
            text("admin-skills-label", "Network Skill Intelligence", "h2"),
        ]
    )

    if federation_intelligence:
        network_map = federation_intelligence.get_network_skill_map()
        top_skills = sorted(network_map.items(), key=lambda x: -x[1]["total"])[:12]
        skill_gaps = intel.get("skill_gaps", [])

        # Top skills as stat rows
        skill_items = []
        for i, (skill_name, skill_data) in enumerate(top_skills):
            sid = f"admin-sk-{i}"
            chapters_str = ", ".join(skill_data["chapters"][:3])
            skill_items.append(sid)
            components.append(stat(sid, skill_name, f"{skill_data['total']} members across {chapters_str}"))
        if skill_items:
            sections.append("admin-skills-list")
            components.append(column("admin-skills-list", skill_items))

        # Skill gaps
        if skill_gaps:
            sections.extend(["admin-gaps-label", "admin-gaps-list"])
            components.extend(
                [
                    text("admin-gaps-label", "Skill Gaps", "h3"),
                    list_component("admin-gaps-list", [f"{g} — not covered in this org" for g in skill_gaps[:8]]),
                ]
            )

        # Skill coverage metric
        total_unique = len(network_map)
        our_skills = len(intel.get("skill_graph", {}))
        coverage = round((our_skills / max(total_unique, 1)) * 100)
        sections.append("admin-coverage")
        components.append(
            progress("admin-coverage", coverage, f"Skill Coverage ({our_skills}/{total_unique} network skills)")
        )

    # ── Section 3: Server Health ──────────────────────────
    sections.extend(["admin-div2", "admin-chapters-label"])
    components.extend(
        [
            divider("admin-div2"),
            text("admin-chapters-label", "Server Health", "h2"),
        ]
    )

    chapter_cards = []
    # Our server first
    our_card = "admin-ch-self"
    chapter_cards.append(our_card)
    components.extend(
        [
            card(our_card, f"{our_card}-col"),
            column(f"{our_card}-col", [f"{our_card}-name", f"{our_card}-stats", f"{our_card}-status"]),
            text(f"{our_card}-name", AGENT_NAME, "h3"),
            row(f"{our_card}-stats", [f"{our_card}-members", f"{our_card}-cycles"]),
            stat(f"{our_card}-members", "Members", str(member_count)),
            stat(f"{our_card}-cycles", "Think Cycles", str(_get_think_count())),
            badge(f"{our_card}-status", "This Server", "secondary"),
        ]
    )

    # Federation servers
    for i, (fid, finfo) in enumerate(federation.items()):
        cid = f"admin-ch-{i}"
        chapter_cards.append(cid)
        status = finfo.get("status", "unknown")
        status_color = "bg-green-500/10 text-green-700" if status == "online" else ""
        fed_info = federation_intelligence.federation_knowledge.get(fid, {}) if federation_intelligence else {}
        ch_member_count = fed_info.get("member_count", finfo.get("members", "?"))
        ch_top = fed_info.get("top_skills", [])[:3]

        ch_children = [f"{cid}-name", f"{cid}-stats", f"{cid}-badge"]
        ch_comps = [
            text(f"{cid}-name", finfo.get("name", fid), "h3"),
            row(f"{cid}-stats", [f"{cid}-members"]),
            stat(f"{cid}-members", "Members", str(ch_member_count)),
            badge(f"{cid}-badge", status, "secondary", status_color),
        ]
        if ch_top:
            ch_children.append(f"{cid}-skills")
            ch_comps.append(list_component(f"{cid}-skills", ch_top))

        ch_comps.insert(0, column(f"{cid}-col", ch_children))
        components.extend([card(cid, f"{cid}-col")] + ch_comps)

    sections.append("admin-ch-grid")
    components.append(grid("admin-ch-grid", chapter_cards, 3))

    # ── Section 4: Cross-Server Opportunities ─────────────
    if federation_intelligence:
        opportunities = federation_intelligence.get_cross_chapter_opportunities()
        if opportunities:
            sections.extend(["admin-div3", "admin-opp-label"])
            components.extend(
                [
                    divider("admin-div3"),
                    text("admin-opp-label", "Cross-Server Opportunities", "h2"),
                ]
            )
            for i, opp in enumerate(opportunities[:6]):
                oid = f"admin-opp-{i}"
                sections.append(oid)
                components.extend(
                    [
                        card(oid, f"{oid}-col"),
                        column(f"{oid}-col", [f"{oid}-gap", f"{oid}-match", f"{oid}-skills"]),
                        text(f"{oid}-gap", f"{opp['source_chapter']} needs: {opp['gap']}", "h4"),
                        text(
                            f"{oid}-match",
                            f"{opp['matching_chapter']} has {opp['member_count']} members with matching skills",
                            "body",
                        ),
                        list_component(f"{oid}-skills", opp["matching_skills"][:5]),
                    ]
                )

    # ── Section 5: Activity Summary ────────────────────────
    if activity_tracker:
        summary = await activity_tracker.get_chapter_activity_summary(days=7)
        if summary["total_activities"] > 0:
            sections.extend(["admin-div4", "admin-activity-label"])
            components.extend(
                [
                    divider("admin-div4"),
                    text("admin-activity-label", "Activity (Last 7 Days)", "h2"),
                ]
            )

            # Activity stats
            sections.append("admin-act-stats")
            components.extend(
                [
                    row("admin-act-stats", ["admin-act-total", "admin-act-active"]),
                    metric("admin-act-total", str(summary["total_activities"]), "Total Activities"),
                    metric("admin-act-active", str(summary["active_members"]), "Active Members"),
                ]
            )

            # By activity type
            type_items = []
            for j, (atype, count) in enumerate(sorted(summary["by_type"].items(), key=lambda x: -x[1])[:8]):
                tid = f"admin-act-type-{j}"
                type_items.append(tid)
                components.append(stat(tid, atype.replace("_", " ").title(), str(count)))
            if type_items:
                sections.append("admin-act-types")
                components.append(column("admin-act-types", type_items))

            # Top members
            if summary["top_members"]:
                sections.append("admin-top-label")
                components.append(text("admin-top-label", "Most Active Members", "h3"))
                for j, (mid, count) in enumerate(summary["top_members"][:5]):
                    tmid = f"admin-top-{j}"
                    sections.append(tmid)
                    mname = members.get(mid, {}).get("name", mid)
                    components.append(stat(tmid, mname, f"{int(count)} activities"))

    # ── Section 6: Agent Performance ───────────────────────
    sections.extend(["admin-div5", "admin-perf-label"])
    components.extend(
        [
            divider("admin-div5"),
            text("admin-perf-label", "Agent Performance", "h2"),
        ]
    )
    sections.append("admin-perf-stats")
    components.extend(
        [
            row("admin-perf-stats", ["admin-perf-cycles", "admin-perf-members", "admin-perf-fed"]),
            metric("admin-perf-cycles", str(_get_think_count()), "Think Cycles"),
            metric("admin-perf-members", str(member_count), "Agents Managed"),
            metric("admin-perf-fed", str(len(federation)), "Federation Peers"),
        ]
    )

    # Network trends
    if federation_intelligence:
        trends = federation_intelligence.get_network_trends()
        if trends:
            sections.extend(["admin-trends-label", "admin-trends"])
            components.extend(
                [
                    text("admin-trends-label", "Network Trends", "h3"),
                    list_component("admin-trends", trends[:10]),
                ]
            )

    components.insert(0, column("root", sections))
    return surface("surface-admin", [card("page", "root")] + components, "page")


async def build_approvals_surface(target: str | None = None, admin_verified: bool = False) -> dict:
    """Leader/advisor surface for the approval queue.

    Lists pending proposals ranked by confidence + recency. Each row is an
    ActionButton for one-click approve/reject. The action handlers at
    /api/approvals/{id}/{approve,reject} verify the actor's role via
    ``governance.approve`` — so the buttons are safe to expose even on a
    public surface; an unauthorized POST returns 403.

    Graceful admin gate (``admin_verified``):
      - False (default / public / EventSource): safe-projection floor —
        kind + confidence + timestamp + action buttons only. Member names,
        reason strings, payload contents, nominee/nominator identities are
        NOT embedded. /api/surfaces/approvals is publicly fetchable, so the
        unauthenticated response stays free of operator-sensitive data.
      - True (request carried a valid X-Admin-Token): full detail —
        member names, reason text, payload contents re-embedded for the
        authenticated admin.

    This is additive: the public floor is unchanged from the safe-projection; full detail is layered on top only for verified
    admins, so nothing breaks for unauthenticated callers.
    """
    try:
        import governance
    except ImportError:
        return surface(
            "surface-approvals-unavailable",
            [
                card("page", "root"),
                column("root", ["t"]),
                text("t", "Governance module not available", "h2"),
            ],
            "page",
        )

    dashboard = await governance.get_dashboard()
    pending = await governance.list_pending(kind=target, limit=50)

    sections = ["approvals-title", "approvals-subtitle", "approvals-stats"]
    components = [
        text("approvals-title", "Approval Queue", "h1"),
        text(
            "approvals-subtitle",
            f"Pending proposals for leaders of {AGENT_NAME}. Each item auto-expires after 72h.",
            "caption",
        ),
        row(
            "approvals-stats",
            ["approvals-stat-pending", "approvals-stat-soon", "approvals-stat-approved", "approvals-stat-rejected"],
        ),
        metric(
            "approvals-stat-pending",
            str(dashboard.get("pending_count") or 0),
            "Pending",
            trend="neutral",
        ),
        metric(
            "approvals-stat-soon",
            str(dashboard.get("expiring_soon_count") or 0),
            "Expiring < 12h",
            trend="down" if (dashboard.get("expiring_soon_count") or 0) > 0 else "neutral",
        ),
        metric(
            "approvals-stat-approved",
            str(dashboard.get("approved_last_24h") or 0),
            "Approved (24h)",
            trend="up",
        ),
        metric(
            "approvals-stat-rejected",
            str(dashboard.get("rejected_last_24h") or 0),
            "Rejected (24h)",
            trend="neutral",
        ),
    ]

    # ── Pending proposals ───────────────────────────────────────
    if not pending:
        sections.append("approvals-empty")
        components.append(text("approvals-empty", "No pending proposals. Server is caught up.", "body"))
    else:
        sections.append("approvals-list-label")
        components.append(text("approvals-list-label", "Pending Proposals", "h2"))
        for item in pending[:30]:
            item_id = item.get("id", "")
            kind = item.get("kind", "?")
            confidence = item.get("confidence") or 0.0
            created = item.get("created_at", "")[:16].replace("T", " ")

            if admin_verified:
                # Full detail — the caller proved admin via X-Admin-Token.
                # Member names, reason text, and payload contents are
                # operator-sensitive and shown only to authenticated admins.
                payload = item.get("payload") or {}
                if kind == "introduction":
                    a = payload.get("member_a", {}).get("name") or payload.get("pair", ["?"])[0]
                    b_m = payload.get("member_b", {})
                    b = b_m.get("name") or (
                        payload.get("pair", ["?", "?"])[1] if len(payload.get("pair", [])) > 1 else "?"
                    )
                    summary = f"Introduce {a} × {b}"
                    details = payload.get("reason", "")
                elif kind == "cross_chapter_intent":
                    summary = f"Cross-chapter intent from {item.get('peer_chapter_id', '?')}"
                    details = (payload.get("intent_text") or "")[:200]
                elif kind == "event_proposal":
                    summary = f"Event: {payload.get('title', '?')}"
                    details = (payload.get("description") or "")[:200]
                elif kind == "member_admission":
                    summary = f"Admit {payload.get('nominee_name', payload.get('nominee_agent_id', '?'))}"
                    details = payload.get("note", "")
                elif kind == "role_promotion":
                    summary = f"Promote {payload.get('nominee_agent_id', '?')} to {payload.get('target_role', '?')}"
                    details = payload.get("reason", "")
                else:
                    summary = kind.replace("_", " ").title()
                    details = json.dumps(payload)[:200] if payload else ""
            else:
                # Safe-projection floor: kind-derived generic label only.
                # Sensitive fields stay redacted unless a valid admin token
                # is present. (peer_chapter_id is publicly known via the
                # peer's own /well-known doc, so it's safe even here.)
                if kind == "cross_chapter_intent":
                    summary = f"Cross-chapter intent from {item.get('peer_chapter_id', '?')}"
                elif kind == "introduction":
                    summary = "Introduction proposal"
                elif kind == "event_proposal":
                    summary = "Event proposal"
                elif kind == "member_admission":
                    summary = "Member admission proposal"
                elif kind == "role_promotion":
                    summary = "Role promotion proposal"
                else:
                    summary = kind.replace("_", " ").title()
                details = "Fetch via /api/approvals/{id} for full content (admin only)."

            card_id = f"appr-{item_id[:8]}"
            sections.append(card_id)
            row_items = [
                f"{card_id}-head",
                f"{card_id}-details",
                f"{card_id}-meta",
                f"{card_id}-actions",
            ]
            components.extend(
                [
                    card(card_id, f"{card_id}-col"),
                    column(f"{card_id}-col", row_items),
                    row(f"{card_id}-head", [f"{card_id}-title", f"{card_id}-chip"]),
                    text(f"{card_id}-title", summary, "h3"),
                    chip(f"{card_id}-chip", f"{int(confidence * 100)}%"),
                    text(f"{card_id}-details", details or "(no details)", "body"),
                    text(f"{card_id}-meta", f"kind={kind} · proposed {created}", "caption"),
                    row(
                        f"{card_id}-actions",
                        [f"{card_id}-approve", f"{card_id}-reject"],
                    ),
                    action_button(
                        f"{card_id}-approve",
                        "Approve",
                        action=f"approve:{item_id}",
                        variant="default",
                        data={"approval_id": item_id},
                    ),
                    action_button(
                        f"{card_id}-reject",
                        "Reject",
                        action=f"reject:{item_id}",
                        variant="outline",
                        data={"approval_id": item_id},
                    ),
                ]
            )

    components.insert(0, column("root", sections))
    return surface("surface-approvals", [card("page", "root")] + components, "page")




async def build_policy_surface(target: str | None = None) -> dict:
    """Leader-visible governance hyperparameter table with pin / unpin actions.

    Shows every live value for the chapter, baseline, whether auto-tune touches
    it, and the most recent tune reason. Leaders can pin any auto-tuned key to
    freeze it; admins can override any value outright.
    """
    try:
        import policy as policy_mod
    except ImportError:
        return surface(
            "surface-policy-unavailable",
            [card("page", "root"), column("root", ["t"]), text("t", "Policy module not available", "h2")],
            "page",
        )

    rows = await policy_mod.list_all()

    tunable = [r for r in rows if r.get("auto_tuned") and not r.get("pinned_by")]
    pinned = [r for r in rows if r.get("pinned_by")]
    fixed = [r for r in rows if not r.get("auto_tuned") and not r.get("pinned_by")]

    sections = ["policy-title", "policy-subtitle", "policy-stats"]
    components = [
        text("policy-title", "Server Policy", "h1"),
        text(
            "policy-subtitle",
            "Hyperparameters that auto-tune from outcome signals. "
            "Leaders can pin any key to freeze it; admins can override.",
            "caption",
        ),
        row("policy-stats", ["policy-stat-tunable", "policy-stat-pinned", "policy-stat-fixed"]),
        metric("policy-stat-tunable", str(len(tunable)), "Auto-tuning"),
        metric("policy-stat-pinned", str(len(pinned)), "Pinned"),
        metric("policy-stat-fixed", str(len(fixed)), "Fixed"),
    ]

    def _compute_bounds(baseline_val, value_type: str) -> tuple | None:
        """Auto-tune bounds: [0.5x, 2x] of baseline, typed to match."""
        if not isinstance(baseline_val, (int, float)):
            return None
        lo_raw = baseline_val * 0.5
        hi_raw = baseline_val * 2.0
        if value_type == "int":
            return (int(lo_raw), int(hi_raw))
        return (round(lo_raw, 4), round(hi_raw, 4))

    def _render_row(r: dict, section_label: str) -> tuple[list, str]:
        key = r.get("key", "")
        rid = f"pol-{section_label}-{key.replace('.', '-')}"
        value = r.get("value")
        baseline = r.get("baseline")
        vtype = r.get("value_type", "float")
        last_reason = r.get("last_tune_reason") or "—"
        sample_size = r.get("last_tune_sample_size")
        window_days = r.get("last_tune_outcome_window_days")
        pinned_by = r.get("pinned_by")
        pinned_reason = r.get("pinned_reason")
        is_tunable_now = bool(r.get("auto_tuned")) and not pinned_by
        is_warming_up = is_tunable_now and sample_size is None and r.get("last_tune_reason") is None

        # Compose meta text: last tune reason + pin info (+ pin reason)
        meta_bits = [f"last: {last_reason}"]
        if pinned_by:
            meta_bits.append(f"pinned by @{pinned_by}")
            if pinned_reason:
                meta_bits.append(f"reason: {pinned_reason}")

        children = [f"{rid}-row1", f"{rid}-meta"]
        comps = [
            card(rid, f"{rid}-col"),
            column(f"{rid}-col", children),
            row(f"{rid}-row1", [f"{rid}-key", f"{rid}-val", f"{rid}-base", f"{rid}-chip"]),
            text(f"{rid}-key", key, "body"),
            text(f"{rid}-val", f"now: {value}", "caption"),
            text(f"{rid}-base", f"baseline: {baseline}", "caption"),
            chip(f"{rid}-chip", vtype),
            text(f"{rid}-meta", " · ".join(meta_bits), "caption"),
        ]

        # Bounds + samples line — only meaningful for tunable, non-pinned keys
        if is_tunable_now:
            bounds = _compute_bounds(baseline, vtype)
            telemetry_bits: list[str] = []
            if bounds is not None:
                telemetry_bits.append(f"bounds: {bounds[0]} to {bounds[1]}")
            if is_warming_up:
                telemetry_bits.append("warming up — no tune yet")
            elif sample_size is not None and window_days is not None:
                telemetry_bits.append(f"{sample_size} samples / {window_days} days")
            if telemetry_bits:
                telemetry_id = f"{rid}-telemetry"
                children.append(telemetry_id)
                comps.append(text(telemetry_id, " · ".join(telemetry_bits), "caption"))

        children.append(f"{rid}-actions")
        if pinned_by:
            action = action_button(
                f"{rid}-unpin",
                "Unpin",
                action=f"unpin-policy:{key}",
                variant="outline",
                data={"key": key},
            )
        elif r.get("auto_tuned"):
            action = action_button(
                f"{rid}-pin",
                "Pin",
                action=f"pin-policy:{key}",
                variant="default",
                data={"key": key},
            )
        else:
            action = text(f"{rid}-action-note", "fixed — admin override only", "caption")
        comps.append(row(f"{rid}-actions", [getattr(action, "get", lambda *_: None)("id") or f"{rid}-act"]))
        comps.append(action)
        return comps, rid

    for label, group in [("Auto-tuning", tunable), ("Pinned", pinned), ("Fixed", fixed)]:
        if not group:
            continue
        label_id = f"policy-label-{label.lower().replace(' ', '-')}"
        sections.append(label_id)
        components.append(text(label_id, label, "h2"))
        for r in group:
            row_components, rid = _render_row(r, label.lower().replace(" ", "-"))
            sections.append(rid)
            components.extend(row_components)

    if not rows:
        sections.append("policy-empty")
        components.append(
            text(
                "policy-empty",
                "No policy rows yet. The migration seeds baselines for every org agent — "
                "apply the schema migration (`infra/init.sql`) and redeploy to populate.",
                "body",
            )
        )

    components.insert(0, column("root", sections))
    return surface("surface-policy", [card("page", "root")] + components, "page")


async def build_audit_surface(target: str | None = None) -> dict:
    """A2UI surface for the audit ledger — leader-readable activity summary.

    Aggregate stats only: chain length, last activity, action-type
    breakdown. Per-event details (actor IDs, target IDs, payload
    contents, hash chain values) are deliberately NOT embedded — those
    require admin auth and are available via /admin/api/audit and
    siblings.

    The page IS publicly fetchable (matching the convention for other
    admin surfaces in this module). The safe-projection is the gate:
    nothing sensitive lands in the response body. Deep-link buttons at
    the bottom point at the admin-gated endpoints for actual data
    access.

    Designed for both static fetch (``GET /api/surfaces/audit``) and
    AG-UI streaming (``GET /api/surfaces/audit/stream``) — the streaming
    variant re-runs this builder on its tick and emits StateDelta
    operations when the aggregate counts change.
    """
    try:
        import chapter_audit

        tip = await chapter_audit.chain_tip(AGENT_ID)
        events = await chapter_audit.list_events(chapter_id=AGENT_ID, limit=200)
    except Exception:  # noqa: BLE001 — surface MUST NOT 500
        return surface(
            "surface-audit-unavailable",
            [
                card("page", "root"),
                column("root", ["audit-unavail-t", "audit-unavail-body"]),
                text("audit-unavail-t", "Audit Log", "h1"),
                text(
                    "audit-unavail-body",
                    "Audit ledger temporarily unavailable. Try again in a moment.",
                    "body",
                ),
            ],
            "page",
        )

    sections: list[str] = ["audit-title", "audit-subtitle", "audit-stats-row"]
    last_activity = tip.get("last_occurred_at") or "—"
    if isinstance(last_activity, str) and len(last_activity) >= 16:
        last_activity = last_activity[:16].replace("T", " ")

    components: list[dict] = [
        text("audit-title", "Audit Log", "h1"),
        text(
            "audit-subtitle",
            "Aggregate activity summary. Use the admin endpoints below for full event detail.",
            "caption",
        ),
        row("audit-stats-row", ["audit-stat-length", "audit-stat-last"]),
        metric("audit-stat-length", str(tip.get("length") or 0), "Total Events"),
        metric("audit-stat-last", str(last_activity), "Last Activity"),
    ]

    # Action-type breakdown
    if events:
        from collections import Counter

        type_counts = Counter(e.get("action", "?") for e in events)
        top_types = type_counts.most_common(10)
        if top_types:
            sections.extend(["audit-div1", "audit-types-label", "audit-types-list"])
            type_item_ids = [f"audit-type-{i}" for i in range(len(top_types))]
            components.extend(
                [
                    divider("audit-div1"),
                    text("audit-types-label", "Activity by Action Type", "h2"),
                    column("audit-types-list", type_item_ids),
                ]
            )
            for i, (action_name, count) in enumerate(top_types):
                components.append(stat(f"audit-type-{i}", action_name, str(count)))
    else:
        sections.append("audit-empty")
        components.append(
            text(
                "audit-empty",
                "No audit events yet. The ledger will populate as privileged actions are taken.",
                "body",
            )
        )

    # Admin-endpoint deep-links — these are the actual data-access paths
    sections.extend(["audit-div2", "audit-actions-label", "audit-actions-row"])
    components.extend(
        [
            divider("audit-div2"),
            text("audit-actions-label", "Admin Actions (require auth)", "h2"),
            row(
                "audit-actions-row",
                [
                    "audit-action-query",
                    "audit-action-verify",
                    "audit-action-export",
                    "audit-action-attest",
                ],
            ),
            link("audit-action-query", "Query events", "/admin/api/audit"),
            link("audit-action-verify", "Verify chain", "/admin/api/audit/verify"),
            link("audit-action-export", "Export NDJSON", "/admin/api/audit/export"),
            link("audit-action-attest", "Sign snapshot", "/admin/api/audit/attest"),
        ]
    )

    components.insert(0, column("root", sections))
    return surface("surface-audit", [card("page", "root")] + components, "page")


async def build_authority_surface(target: str | None = None, admin_verified: bool = False) -> dict:
    """A member's authority-scope page — the delegation contract they see.

    Graceful admin gate (``admin_verified``):
      - False (default / public / EventSource): safe-projection floor —
        allowed/denied counts only. The per-action_kind list + constraints
        are NOT embedded, because /api/surfaces/authority?target=<id> is
        publicly fetchable and enumerating an agent's ACL would hand an
        attacker the privilege-escalation map.
      - True (request carried a valid X-Admin-Token): full per-action
        detail — action_kind cards + constraint values.

    Additive: the public floor is the safe-projection unchanged; full
    detail layers on only for verified admins.
    """
    try:
        import authority as auth_mod
    except ImportError:
        return surface(
            "surface-authority-unavailable",
            [card("page", "root"), column("root", ["t"]), text("t", "Authority module not available", "h2")],
            "page",
        )

    target_agent = (target or "").strip() or None
    rows = await auth_mod.list_scope_for(target_agent) if target_agent else []
    allowed_count = sum(1 for r in rows if r.get("allowed"))
    denied_count = sum(1 for r in rows if not r.get("allowed"))

    sections = ["auth-title", "auth-subtitle", "auth-summary"]
    components = [
        text("auth-title", "Agent Authority", "h1"),
        text(
            "auth-subtitle",
            "Aggregate scope summary. Per-action detail requires admin auth — fetch /api/authority/{target}.",
            "caption",
        ),
        row("auth-summary", ["auth-sum-allowed", "auth-sum-denied"]),
        metric("auth-sum-allowed", str(allowed_count), "Allowed"),
        metric("auth-sum-denied", str(denied_count), "Opt-in required"),
    ]

    if not target_agent:
        sections.append("auth-needs-target")
        components.append(
            text(
                "auth-needs-target",
                "Pass ?target=<agent_id> to view aggregate scope counts.",
                "body",
            )
        )
    elif not rows:
        sections.append("auth-empty")
        components.append(
            text(
                "auth-empty",
                "No authority scope configured for this agent. Defaults are seeded at signup.",
                "body",
            )
        )
    elif admin_verified:
        # Full detail behind a valid admin token — per-action_kind cards
        # with constraint values, grouped by allowed vs opt-in.
        auto_allowed = [r for r in rows if r.get("allowed")]
        opt_in = [r for r in rows if not r.get("allowed")]
        for label, group in [("Auto-allowed", auto_allowed), ("Opt-in required", opt_in)]:
            if not group:
                continue
            label_id = f"auth-group-{label.lower().replace(' ', '-')}"
            sections.append(label_id)
            components.append(text(label_id, label, "h2"))
            for r in group:
                rid = f"auth-{r.get('action_kind', '?')}"
                sections.append(rid)
                constraints = r.get("constraints") or {}
                constraint_text = (
                    " · ".join(f"{k}={v}" for k, v in constraints.items()) if constraints else "no constraints"
                )
                components.extend(
                    [
                        card(rid, f"{rid}-col"),
                        column(f"{rid}-col", [f"{rid}-name", f"{rid}-meta"]),
                        text(f"{rid}-name", r.get("action_kind", "?"), "h3"),
                        text(f"{rid}-meta", constraint_text, "caption"),
                    ]
                )
    else:
        # Safe-projection floor: NO per-action_kind cards, NO constraint
        # values. Just a deep-link to the admin-gated REST path.
        sections.append("auth-details-link")
        components.append(
            text(
                "auth-details-link",
                "Per-action details (action_kind, constraints, rate limits) are not exposed "
                "on this public surface. Fetch /api/authority/{target} with admin auth for "
                "the full scope.",
                "body",
            )
        )

    components.insert(0, column("root", sections))
    return surface("surface-authority", [card("page", "root")] + components, "page")


# ═══════════════════════════════════════════════════════════════
# Onboarding — first-run wizard as A2UI surface per step
# ═══════════════════════════════════════════════════════════════


async def build_onboarding_surface(target: str | None = None) -> dict:
    """A2UI surface for /page/onboarding — renders the current step's Form."""
    try:
        import onboarding as onboarding_mod
    except ImportError:
        return surface(
            "surface-onboarding-unavailable",
            [card("page", "root"), column("root", ["t"]), text("t", "Onboarding module not available", "h2")],
            "page",
        )

    if not target:
        return surface(
            "surface-onboarding-welcome",
            [
                card("page", "root"),
                column("root", ["title", "msg"]),
                heading("title", 1, "Welcome"),
                text("msg", "Pass ?target=<agent_id> to start onboarding.", "body"),
            ],
            "page",
        )

    step = await onboarding_mod.get_step(target)
    total = onboarding_mod.total_steps()
    spec = onboarding_mod.step_spec(step)
    if spec is None:
        return surface(
            "surface-onboarding-error",
            [card("page", "root"), column("root", ["t"]), text("t", f"Unknown step {step}", "h2")],
            "page",
        )

    section_ids: list[str] = ["progress-callout", "step-heading", "step-desc"]
    components: list[dict] = [
        callout(
            "progress-callout",
            f"Step {step + 1} of {total}: {spec['title']}",
            variant="info",
        ),
        heading("step-heading", 2, spec["title"]),
        text("step-desc", spec["description"], "body"),
    ]

    # Final step — confirmation only.
    if not spec["fields"]:
        section_ids.append("done-row")
        components.append(row("done-row", ["btn-dashboard", "btn-restart"]))
        components.append(
            action_button(
                "btn-dashboard",
                label="Open dashboard",
                action="goto_dashboard",
                variant="default",
                data={"target": target},
            )
        )
        components.append(
            action_button(
                "btn-restart",
                label="Re-run onboarding",
                action="reset_onboarding",
                variant="outline",
                data={"target": target},
            )
        )
        components.insert(0, column("root", section_ids))
        return surface(f"surface-onboarding-{step}", [card("page", "root")] + components, "page")

    # Form step — render each declared field.
    field_ids: list[str] = []
    for f in spec["fields"]:
        field_id = f"f-{f['key']}"
        field_ids.append(field_id)
        label = f["label"] + (" *" if f.get("required") else "")
        default = f.get("default", "")
        if f["type"] == "select":
            from a2ui_helpers import select as select_cmp

            components.append(
                select_cmp(
                    field_id,
                    label=label,
                    options=f.get("options", []),
                    value=default,
                )
            )
        elif f["type"] == "password":
            components.append(
                input_field(field_id, label=label, placeholder=f.get("placeholder", ""), input_type="password")
            )
        else:
            components.append(
                input_field(
                    field_id,
                    label=label,
                    placeholder=f.get("placeholder", ""),
                    value=default if isinstance(default, str) else "",
                )
            )

    section_ids.append("wizard-form")
    components.append(
        form(
            "wizard-form",
            field_ids,
            action="onboarding_advance",
            submit_label="Continue",
        )
    )

    components.insert(0, column("root", section_ids))
    return surface(f"surface-onboarding-{step}", [card("page", "root")] + components, "page")


# ═══════════════════════════════════════════════════════════════
# Settings — tabbed config view
# ═══════════════════════════════════════════════════════════════


async def build_settings_surface(target: str | None = None) -> dict:
    """A2UI surface for /page/settings — tabbed config view per agent."""
    try:
        import settings as settings_mod
    except ImportError:
        return surface(
            "surface-settings-unavailable",
            [card("page", "root"), column("root", ["t"]), text("t", "Settings module not available", "h2")],
            "page",
        )

    if not target:
        return surface(
            "surface-settings-welcome",
            [
                card("page", "root"),
                column("root", ["title", "msg"]),
                heading("title", 1, "Settings"),
                text("msg", "Pass ?target=<agent_id> to view settings.", "body"),
            ],
            "page",
        )

    cfg = await settings_mod.get_settings(target)
    completed = await settings_mod.is_onboarding_complete(target)

    section_ids = [
        "hero",
        "onboarding-row",
        "llm-heading",
        "llm-card",
        "voice-heading",
        "voice-card",
        "channels-heading",
        "channels-card",
        "privacy-heading",
        "privacy-card",
        "danger-heading",
        "danger-row",
    ]

    components: list[dict] = [
        heading("hero", 1, "Settings"),
        stat_group(
            "onboarding-row",
            [
                {"label": "Agent", "value": target},
                {"label": "Onboarding", "value": "Complete" if completed else "In progress"},
            ],
        ),
        heading("llm-heading", 3, "LLM Provider"),
        card("llm-card", "llm-col"),
        column("llm-col", ["llm-provider-stat", "llm-model-stat", "llm-edit-btn"]),
        stat("llm-provider-stat", "Provider", cfg["llm"].get("provider", "—")),
        stat("llm-model-stat", "Model", cfg["llm"].get("model", "—")),
        action_button(
            "llm-edit-btn",
            label="Change provider",
            action="edit_llm_settings",
            variant="outline",
            data={"target": target},
        ),
        heading("voice-heading", 3, "Voice (roadmap)"),
        card("voice-card", "voice-col"),
        column("voice-col", ["voice-note", "voice-stt-stat", "voice-tts-stat", "voice-alwayson-stat", "voice-edit-btn"]),
        text(
            "voice-note",
            "Roadmap — voice audio (speech-to-text / text-to-speech) isn't shipped yet. These "
            "settings configure it for when the desktop audio runtime lands; nothing is captured "
            "or synthesized today.",
            "caption",
        ),
        stat("voice-stt-stat", "Speech-to-text", cfg["voice"].get("stt_provider") or "disabled"),
        stat("voice-tts-stat", "Text-to-speech", cfg["voice"].get("tts_provider") or "disabled"),
        stat("voice-alwayson-stat", "Always-on", "on" if cfg["voice"].get("always_on") else "off"),
        action_button(
            "voice-edit-btn",
            label="Voice settings",
            action="open_voice_settings",
            variant="outline",
            data={"target": target},
        ),
        heading("channels-heading", 3, "Channels"),
        card("channels-card", "channels-col"),
        column(
            "channels-col",
            ["channels-slack-stat", "channels-email-stat", "channels-edit-btn"],
        ),
        stat(
            "channels-slack-stat",
            "Slack",
            "connected" if cfg["channels"].get("slack", {}).get("enabled") else "disconnected",
        ),
        stat(
            "channels-email-stat",
            "Email",
            "connected" if cfg["channels"].get("email", {}).get("enabled") else "disconnected",
        ),
        action_button(
            "channels-edit-btn",
            label="Connect a channel",
            action="open_channels",
            variant="outline",
            data={"target": target},
        ),
        heading("privacy-heading", 3, "Privacy"),
        card("privacy-card", "privacy-col"),
        column("privacy-col", ["privacy-telemetry-stat", "privacy-edit-btn"]),
        stat(
            "privacy-telemetry-stat",
            "Anonymous telemetry",
            "enabled" if cfg["privacy"].get("telemetry") else "disabled (default)",
        ),
        action_button(
            "privacy-edit-btn",
            label="Privacy preferences",
            action="edit_privacy_settings",
            variant="outline",
            data={"target": target},
        ),
        heading("danger-heading", 3, "Danger zone"),
        row("danger-row", ["danger-reset-btn"]),
        action_button(
            "danger-reset-btn",
            label="Reset to defaults",
            action="reset_settings",
            variant="ghost",
            data={"target": target},
        ),
    ]

    components.insert(0, column("root", section_ids))
    return surface("surface-settings", [card("page", "root")] + components, "page")


# ═══════════════════════════════════════════════════════════════
# Server security — SSO, audit, federation allowlist
# ═══════════════════════════════════════════════════════════════


async def build_chapter_security_surface(target: str | None = None) -> dict:
    """A2UI surface for /page/chapter-security — SSO + allowlist + audit.

    Renders the enterprise-grade chapter security posture: who can log in
    (SSO), which peers the chapter federates with (allowlist), and what
    happened recently (audit). Every operator-facing private-chapter
    control lives here.
    """
    try:
        import chapter_audit
        import chapter_auth
    except ImportError:
        return surface(
            "surface-chapter-security-unavailable",
            [card("page", "root"), column("root", ["t"]), text("t", "Security module not available", "h2")],
            "page",
        )

    chapter_id = target or AGENT_ID
    sso = await chapter_auth.get_sso_config(chapter_id)
    allowlist = await chapter_auth.list_federation_allowlist(chapter_id)
    recent_events = await chapter_audit.list_events(chapter_id, limit=15)
    chain = await chapter_audit.verify_chain(chapter_id)

    section_ids = [
        "hero",
        "posture-callout",
        "stats-row",
        "sso-heading",
        "sso-card",
        "allowlist-heading",
        "allowlist-table",
        "audit-heading",
        "audit-timeline",
        "chain-callout",
    ]

    posture = "private" if (sso and sso.get("enforce_sso")) or allowlist else "public"

    components: list[dict] = [
        heading("hero", 1, "Server security"),
        callout(
            "posture-callout",
            (
                "This chapter is operating in PRIVATE mode. SSO enforcement "
                "or a populated federation allowlist is active — unknown "
                "peers and unauthenticated members are refused."
                if posture == "private"
                else "This chapter is operating in PUBLIC mode. Add an SSO "
                "provider or populate the federation allowlist to switch to "
                "default-deny."
            ),
            variant="success" if posture == "private" else "info",
            title="Posture",
        ),
        stat_group(
            "stats-row",
            [
                {"label": "SSO", "value": sso["provider"] if sso else "none"},
                {"label": "Allowlisted peers", "value": str(len(allowlist))},
                {"label": "Audit events", "value": str(chain.get("length", 0))},
                {"label": "Chain integrity", "value": "ok" if chain.get("ok") else "broken"},
            ],
        ),
        heading("sso-heading", 3, "Single sign-on"),
    ]

    if sso:
        components.extend(
            [
                card("sso-card", "sso-col"),
                column("sso-col", ["sso-provider", "sso-issuer", "sso-client", "sso-enforce", "sso-edit"]),
                stat("sso-provider", "Provider", sso["provider"]),
                stat("sso-issuer", "Issuer", sso["issuer_url"]),
                stat("sso-client", "Client id", sso["client_id"]),
                stat(
                    "sso-enforce",
                    "Enforce SSO",
                    "required (login blocked without)" if sso.get("enforce_sso") else "optional",
                ),
                action_button(
                    "sso-edit",
                    label="Edit SSO config",
                    action="edit_sso",
                    variant="outline",
                    data={"chapter_id": chapter_id},
                ),
            ]
        )
    else:
        components.extend(
            [
                card("sso-card", "sso-col"),
                column("sso-col", ["sso-none-msg", "sso-connect"]),
                text("sso-none-msg", "No SSO provider bound yet.", "caption"),
                action_button(
                    "sso-connect",
                    label="Connect an IdP",
                    action="edit_sso",
                    variant="default",
                    data={"chapter_id": chapter_id},
                ),
            ]
        )

    components.append(heading("allowlist-heading", 3, "Federation allowlist"))
    if allowlist:
        components.append(
            table(
                "allowlist-table",
                columns=["Peer chapter", "Added by", "Reason", "Added at"],
                rows=[
                    [
                        p.get("peer_chapter_id", "?"),
                        p.get("added_by_agent_id", "?"),
                        (p.get("reason") or "")[:64],
                        (p.get("added_at") or "")[:19],
                    ]
                    for p in allowlist
                ],
                caption="Populated allowlist = default-deny federation.",
            )
        )
    else:
        components.append(
            text(
                "allowlist-table",
                "Allowlist is empty — the org accepts all federated peers (public mode).",
                "caption",
            )
        )

    components.append(heading("audit-heading", 3, "Recent audit events"))
    if recent_events:
        components.append(
            timeline(
                "audit-timeline",
                entries=[
                    {
                        "timestamp": (e.get("occurred_at") or "")[:19],
                        "title": f"{e.get('action', '?')}  —  {e.get('outcome', '?')}",
                        "body": (
                            f"by {e.get('actor_agent_id') or 'system'}"
                            + (f" on {e.get('target_type')}/{e.get('target_id')}" if e.get("target_id") else "")
                        ),
                    }
                    for e in recent_events[:10]
                ],
            )
        )
    else:
        components.append(text("audit-timeline", "No audit events yet.", "caption"))

    components.append(
        callout(
            "chain-callout",
            (
                f"Hash chain verified across {chain.get('length', 0)} events. "
                "Every log entry includes the sha256 of the previous — any "
                "tampering is detectable."
                if chain.get("ok")
                else f"Hash chain BROKEN at event {chain.get('broken_index', '?')}. "
                "Investigate immediately — the audit log may have been altered."
            ),
            variant="success" if chain.get("ok") else "danger",
            title="Chain integrity",
        )
    )

    components.insert(0, column("root", section_ids))
    return surface("surface-chapter-security", [card("page", "root")] + components, "page")


# ═══════════════════════════════════════════════════════════════
# Docs — self-documenting server
# ═══════════════════════════════════════════════════════════════


async def build_docs_surface(target: str | None = None) -> dict:
    """A2UI surface for /page/docs — live catalog of this chapter.

    Introspects SURFACE_BUILDERS + surface_cache stats + module list so
    any external developer can see exactly what this chapter exposes.
    No external dependencies — builds from memory.
    """
    import surface_cache

    # SURFACE_BUILDERS is defined below; reference it lazily to avoid cycles.
    builders = SURFACE_BUILDERS
    cache_stats = surface_cache.stats()

    surface_rows: list[list[str]] = []
    for name in sorted(builders.keys()):
        fn = builders[name]
        doc = (fn.__doc__ or "").strip().split("\n")[0][:80] if fn.__doc__ else ""
        s = cache_stats.get(name, {})
        hits = s.get("hits", 0)
        builds = s.get("builds", 0)
        avg_ms = s.get("avg_ms", 0.0)
        surface_rows.append(
            [
                f"/page/{name}",
                doc or "—",
                str(hits),
                str(builds),
                f"{avg_ms}ms" if avg_ms else "—",
            ]
        )

    # Known endpoint groups — keyed by URL prefix for a high-signal summary.
    endpoint_groups = [
        ("GET  /health", "Chapter health + federation state + registry status"),
        ("GET  /health/surfaces", "Per-surface cache + latency telemetry"),
        ("GET  /api/surfaces/{page}", "A2UI surface for any registered page"),
        ("POST /api/surfaces/action", "Interactive component action dispatch"),
        ("GET  /api/members", "Chapter members list"),
        ("POST /api/members", "Register a new member agent"),
        ("GET  /api/skills", "Browse signed skill registry"),
        ("POST /api/skills/publish", "Self-signed skill publish (Ed25519)"),
        ("GET  /api/mesh/peers", "Peers across local + federated chapters"),
        ("POST /api/mesh/send", "Signed a2a message to a peer"),
        ("GET  /api/onboarding/{agent_id}", "First-run wizard state"),
        ("GET  /api/settings/{agent_id}", "Per-agent settings bag"),
        ("GET  /api/voice/providers", "STT/TTS catalog"),
        ("GET  /api/channels/{agent_id}", "Channel connections (Slack/email/…)"),
        ("POST /api/intents", "Broadcast an intent to federation"),
        ("GET  /.well-known/nanda-agent.json", "Chapter discovery manifest"),
        ("GET  /.well-known/did.json", "did:web document"),
        ("GET  /agentfacts.json", "Chapter AgentFacts (NANDA spec)"),
    ]
    endpoint_rows = [[path, desc] for path, desc in endpoint_groups]

    # Modules list — what's in this server.
    module_rows = [
        ["skill_registry", "Ed25519-signed skill catalog"],
        ["onboarding", "First-run 4-step wizard"],
        ["settings", "Per-agent jsonb settings bag"],
        ["voice", "STT/TTS provider catalog"],
        ["channels", "Slack/email/discord connections"],
        ["mesh", "Unified peer + federation interface"],
        ["governance", "Trust scores, approvals"],
        ["policy", "Chapter hyperparameter store"],
        ["federation_discovery", "Peer chapter discovery"],
        ["federation_intelligence", "Cross-chapter knowledge exchange"],
        ["federation_policy", "Per-peer backoff + quarantine"],
        ["intents", "Privacy-preserving intent matching"],
        ["projections", "pgvector-backed anonymized projections"],
        ["outcome_tracker", "Quality signals for auto-tuning"],
        ["agent_conversations", "Inter-agent threaded chats"],
        ["activity_tracker", "Per-member activity log"],
        ["think_cycle", "14-cycle autonomous rotation"],
        ["authority", "Per-agent delegation contract"],
        ["surface_cache", "TTL-memoization for surface builders"],
    ]

    section_ids = [
        "hero",
        "pitch",
        "surfaces-heading",
        "surfaces-table",
        "endpoints-heading",
        "endpoints-table",
        "modules-heading",
        "modules-table",
        "footer-callout",
    ]

    components = [
        heading("hero", 1, "Server docs"),
        callout(
            "pitch",
            "Every screen is an A2UI v0.9 surface. Every surface is one Python "
            "function in surfaces.py. External developers can introspect this "
            "chapter live — no separate documentation portal to drift from reality.",
            variant="info",
            title="Self-documenting",
        ),
        heading("surfaces-heading", 3, f"Surfaces ({len(builders)})"),
        table(
            "surfaces-table",
            columns=["Surface", "Summary", "Hits", "Builds", "Avg"],
            rows=surface_rows,
            caption="Cache hits + builds + average build latency per surface.",
        ),
        heading("endpoints-heading", 3, "Key endpoints"),
        table(
            "endpoints-table",
            columns=["Method + path", "Purpose"],
            rows=endpoint_rows,
            caption="Selected endpoints. Full list: see chapter-runtime source.",
        ),
        heading("modules-heading", 3, f"Backend modules ({len(module_rows)})"),
        table(
            "modules-table",
            columns=["Module", "Responsibility"],
            rows=module_rows,
        ),
        callout(
            "footer-callout",
            "Source: github.com/YOUR_ORG/orrery. Portal: github.com/YOUR_ORG/orrery.",
            variant="success",
            title="Open source",
        ),
    ]

    components.insert(0, column("root", section_ids))
    return surface("surface-docs", [card("page", "root")] + components, "page")


# ═══════════════════════════════════════════════════════════════
# Mesh — first-class agent view of peers + federation
# ═══════════════════════════════════════════════════════════════


async def build_mesh_surface(target: str | None = None) -> dict:
    """A2UI surface for /page/mesh — peer browser + federation state."""
    try:
        import mesh as mesh_mod
    except ImportError:
        return surface(
            "surface-mesh-unavailable",
            [card("page", "root"), column("root", ["t"]), text("t", "Mesh module not available", "h2")],
            "page",
        )

    state = await mesh_mod.get_mesh_state(agent_id=target)
    peers = await mesh_mod.list_peers(limit=24)
    peer_cards = mesh_mod.peer_grid(peers)

    section_ids = [
        "hero",
        "mission-callout",
        "stats-row",
        "peers-heading",
    ]

    components: list[dict] = [
        heading("hero", 1, "Mesh"),
        callout(
            "mission-callout",
            "The mesh is the federation between orgs running Orrery. Your agent "
            "finds peers, submits intents, and exchanges signed messages across "
            "it — regardless of which chapter hosts them.",
            variant="info",
            title="Federated agents",
        ),
        stat_group(
            "stats-row",
            [
                {"label": "Members here", "value": str(state["members_here"])},
                {"label": "Peers online", "value": str(state["peers_online"])},
                {"label": "Peers offline", "value": str(state["peers_offline"])},
                {"label": "Opportunities", "value": str(len(state["opportunities"]))},
            ],
        ),
        heading("peers-heading", 3, "Peers on the mesh"),
    ]

    if peer_cards:
        peer_ids: list[str] = []
        for i, pc in enumerate(peer_cards[:12]):
            pid = f"peer-{i}"
            peer_ids.append(pid)
            components.append(
                member_card(
                    pid,
                    name=pc["name"],
                    agent_id=pc["agent_id"],
                    role=pc["role"],
                    trust_score=pc["trust_score"],
                    skills=pc["skills"],
                    subtitle=pc["subtitle"],
                )
            )
        section_ids.append("peers-grid")
        components.append(grid("peers-grid", peer_ids, cols=3))
    else:
        section_ids.append("peers-empty")
        components.append(text("peers-empty", "No peers on the mesh yet — invite some!", "caption"))

    if state["opportunities"]:
        section_ids.extend(["opps-heading", "opps-timeline"])
        components.append(heading("opps-heading", 3, "Cross-server opportunities"))
        components.append(
            timeline(
                "opps-timeline",
                entries=[
                    {
                        "timestamp": "now",
                        "title": mesh_mod._describe_opportunity(o),
                        "body": "Peers who could fill a gap in your chapter.",
                    }
                    for o in state["opportunities"][:5]
                ],
            )
        )

    if target and state.get("my_trust"):
        section_ids.extend(["self-heading", "self-trust", "self-actions"])
        components.append(heading("self-heading", 3, "Your mesh identity"))
        components.append(
            trust_badge(
                "self-trust",
                score=float(state["my_trust"]["trust_score"]),
                show_score=True,
            )
        )
        components.append(row("self-actions", ["btn-broadcast"]))
        components.append(
            action_button(
                "btn-broadcast",
                label="Submit an intent",
                action="mesh_submit_intent",
                variant="outline",
                data={"target": target},
            )
        )

    components.insert(0, column("root", section_ids))
    return surface("surface-mesh", [card("page", "root")] + components, "page")


# ═══════════════════════════════════════════════════════════════
# Channels — Slack / Email / Discord connection management
# ═══════════════════════════════════════════════════════════════


async def build_channels_surface(target: str | None = None) -> dict:
    """A2UI surface for /page/channels — list + connect + disconnect."""
    try:
        import channels as channels_mod
    except ImportError:
        return surface(
            "surface-channels-unavailable",
            [card("page", "root"), column("root", ["t"]), text("t", "Channels module not available", "h2")],
            "page",
        )

    if not target:
        return surface(
            "surface-channels-welcome",
            [
                card("page", "root"),
                column("root", ["title", "msg"]),
                heading("title", 1, "Channels"),
                text("msg", "Pass ?target=<agent_id> to manage channels.", "body"),
            ],
            "page",
        )

    conns = await channels_mod.list_connections(target)
    active_count = len([c for c in conns if c.get("status") == "active"])

    section_ids = [
        "hero",
        "explainer",
        "stats",
        "connect-form-heading",
        "connect-form",
        "list-heading",
        "connections-table",
        "status-callout",
    ]

    components: list[dict] = [
        heading("hero", 1, "Channels"),
        callout(
            "explainer",
            "Channels bridge your agent to external messaging platforms. Inbound "
            "messages are sandboxed in a per-sender session scope — the same "
            "isolation pattern OpenClaw uses for DMs from unknown senders.",
            variant="info",
            title="How channels work",
        ),
        stat_group(
            "stats",
            [
                {"label": "Connected", "value": str(active_count)},
                {"label": "Supported kinds", "value": str(len(channels_mod.SUPPORTED_KINDS))},
            ],
        ),
        heading("connect-form-heading", 3, "Connect a channel"),
        form(
            "connect-form",
            ["f-kind", "f-remote-id", "f-display-name"],
            action="connect_channel",
            submit_label="Connect",
        ),
        select(
            "f-kind",
            label="Platform",
            options=[
                {"label": "Slack", "value": "slack"},
                {"label": "Email (IMAP/SMTP)", "value": "email"},
                {"label": "Discord", "value": "discord"},
                {"label": "Webhook", "value": "webhook"},
            ],
            value="slack",
        ),
        input_field(
            "f-remote-id",
            label="Remote id",
            placeholder="T12345ABC (Slack) | alice@e.com (email) | guild id (Discord)",
        ),
        input_field("f-display-name", label="Display name", placeholder="optional"),
        heading("list-heading", 3, "Your connections"),
    ]

    if conns:
        rows_data: list[list[str]] = []
        for c in conns:
            last_test = c.get("last_test_at") or "—"
            # last_test_ok: True → real pass, False → real fail, None → not a real
            # connectivity check. Don't render a None attempt as "✓ ok" — if
            # an attempt was recorded (last_test_at set) but ok is None, it was the
            # metadata-only stub: surface "untested", not green.
            if c.get("last_test_ok") is True:
                test_result = "✓ ok"
            elif c.get("last_test_ok") is False:
                test_result = "✗ fail"
            elif c.get("last_test_at"):
                test_result = "untested"
            else:
                test_result = "—"
            rows_data.append(
                [
                    c["kind"],
                    c["display_name"] or c["remote_id"],
                    c["status"],
                    (last_test[:19] if isinstance(last_test, str) else "—"),
                    test_result,
                ]
            )
        components.append(
            table(
                "connections-table",
                columns=["Kind", "Name / Remote id", "Status", "Last tested", "Result"],
                rows=rows_data,
                caption=f"{len(conns)} connection(s).",
            )
        )
    else:
        components.append(text("connections-table", "No channels connected yet.", "caption"))

    components.append(
        callout(
            "status-callout",
            "Wire-level Slack/Email integrations land in W7 of the roadmap. Today the "
            "module persists connections, routes inbound webhooks to the owning agent "
            "(with session sandboxing), and stubs the outbound wire.",
            variant="warning",
            title="In progress",
        )
    )

    components.insert(0, column("root", section_ids))
    return surface("surface-channels", [card("page", "root")] + components, "page")


# ═══════════════════════════════════════════════════════════════
# Voice configuration surface
# ═══════════════════════════════════════════════════════════════


async def build_voice_surface(target: str | None = None) -> dict:
    """A2UI surface for /page/voice — STT/TTS provider selection.

    Actual audio I/O (microphone / speaker / streaming) runs in the
    member-agent desktop app. This surface configures the knobs.
    """
    try:
        import settings as settings_mod
        import voice as voice_mod
    except ImportError:
        return surface(
            "surface-voice-unavailable",
            [card("page", "root"), column("root", ["t"]), text("t", "Voice module not available", "h2")],
            "page",
        )

    if not target:
        return surface(
            "surface-voice-welcome",
            [
                card("page", "root"),
                column("root", ["title", "msg"]),
                heading("title", 1, "Voice"),
                text("msg", "Pass ?target=<agent_id> to configure voice for a specific agent.", "body"),
            ],
            "page",
        )

    cfg = await settings_mod.get_settings(target)
    voice_cfg = cfg.get("voice", {})
    current_tts = voice_cfg.get("tts_provider") or "disabled"

    # Build catalogs for the Select dropdowns.
    stt_options = [{"label": p["label"], "value": p["id"]} for p in voice_mod.stt_providers()]
    tts_options = [{"label": p["label"], "value": p["id"]} for p in voice_mod.tts_providers()]
    voice_id_options = voice_mod.voice_options_for(current_tts) or [
        {"label": "(select a TTS provider first)", "value": ""}
    ]

    section_ids = [
        "hero",
        "privacy-callout",
        "form-heading",
        "voice-form",
        "provider-details-heading",
        "provider-details-table",
        "test-mic-row",
    ]

    components: list[dict] = [
        heading("hero", 1, "Voice Configuration"),
        callout(
            "privacy-callout",
            "Local providers (Whisper, Piper) run on your device and never "
            "transmit audio. Cloud providers send audio to third parties — "
            "review their privacy policies before enabling.",
            variant="info",
            title="Privacy",
        ),
        heading("form-heading", 3, "Voice settings"),
        form(
            "voice-form",
            [
                "f-stt-provider",
                "f-tts-provider",
                "f-voice-id",
                "f-wake-word",
                "f-always-on",
            ],
            action="update_voice_settings",
            submit_label="Save",
        ),
        select(
            "f-stt-provider",
            label="Speech-to-text provider",
            options=stt_options,
            value=voice_cfg.get("stt_provider") or "disabled",
        ),
        select(
            "f-tts-provider",
            label="Text-to-speech provider",
            options=tts_options,
            value=current_tts,
        ),
        select(
            "f-voice-id",
            label="Voice",
            options=voice_id_options,
            value=voice_cfg.get("voice_id", ""),
        ),
        toggle(
            "f-wake-word",
            label="Wake word (say 'Hey agent' to start)",
            checked=bool(voice_cfg.get("wake_word")),
        ),
        toggle(
            "f-always-on",
            label="Always-on listening (background process stays running)",
            checked=bool(voice_cfg.get("always_on")),
        ),
        heading("provider-details-heading", 3, "Provider catalog"),
        table(
            "provider-details-table",
            columns=["Type", "Provider", "Local", "Needs API key"],
            rows=[
                ["STT", p["label"], "yes" if p["local"] else "no", "yes" if p["requires_api_key"] else "no"]
                for p in voice_mod.stt_providers()
            ]
            + [
                ["TTS", p["label"], "yes" if p["local"] else "no", "yes" if p["requires_api_key"] else "no"]
                for p in voice_mod.tts_providers()
            ],
            caption="Available voice providers and their privacy posture.",
        ),
        row("test-mic-row", ["btn-test-mic"]),
        action_button(
            "btn-test-mic",
            label="Test microphone",
            action="voice_test_mic",
            variant="outline",
            data={"target": target},
        ),
    ]

    components.insert(0, column("root", section_ids))
    return surface("surface-voice", [card("page", "root")] + components, "page")


# ═══════════════════════════════════════════════════════════════
# Server skill registry surfaces
# ═══════════════════════════════════════════════════════════════


async def build_skills_surface(target: str | None = None) -> dict:
    """A2UI surface for /page/skills — the signed skill marketplace."""
    try:
        import skill_registry as sr
    except ImportError:
        return surface(
            "surface-skills-unavailable",
            [
                card("page", "root"),
                column("root", ["t"]),
                text("t", "Skill registry not available", "h2"),
            ],
            "page",
        )

    skills = await sr.list_skills(limit=100)
    total = len(skills)
    revoked_count = len([s for s in skills if s.get("revoked_at")])
    high_risk_count = len([s for s in skills if sr.describe_risk(s.get("capabilities") or [])["level"] == "high"])

    section_ids = [
        "hero",
        "trust-callout",
        "stats",
        "filter-row",
        "skills-table",
        "publish-cta",
    ]

    components: list[dict] = [
        heading("hero", 1, "Server Skill Registry"),
        callout(
            "trust-callout",
            "Every skill in this registry is Ed25519-signed by its author's did:key. "
            "The chapter verifies the signature at publish time and re-verifies at install "
            "time against the revocation list. Unsigned skills are refused — by protocol.",
            variant="success",
            title="Signed by default",
        ),
        stat_group(
            "stats",
            [
                {"label": "Skills", "value": str(total - revoked_count)},
                {"label": "Authors", "value": str(len({s.get("author_did") for s in skills}))},
                {"label": "Revoked", "value": str(revoked_count)},
                {"label": "High-risk", "value": str(high_risk_count)},
            ],
        ),
        row("filter-row", ["filter-search", "filter-tags"]),
        input_field("filter-search", label="Search", placeholder="name, tag, or description"),
        chip(
            "filter-tags",
            label="high-risk only",
            selected=False,
            value="high_risk",
        ),
    ]

    # Table rows for all active skills. Revoked skills rendered separately below.
    active = [s for s in skills if not s.get("revoked_at")]
    rows_data: list[list[str]] = []
    for s in active[:60]:
        caps = s.get("capabilities") or []
        risk = sr.describe_risk(caps)
        risk_icon = "⚠" if risk["level"] == "high" else ("!" if risk["level"] == "medium" else "")
        rating_str = f"★ {s.get('avg_rating'):.1f}" if s.get("avg_rating") else "—"
        rows_data.append(
            [
                f"{s.get('name', '?')}@{s.get('version', '?')}",
                _short_did(s.get("author_did", "")),
                sr.tier_from_trust_score(s.get("trust_score") or 0),
                str(s.get("install_count") or 0),
                rating_str,
                f"{risk_icon} {', '.join(caps[:3])}" + ("…" if len(caps) > 3 else ""),
            ]
        )
    components.append(
        table(
            "skills-table",
            columns=["Skill", "Author", "Tier", "Installs", "Rating", "Capabilities"],
            rows=rows_data,
            caption=f"{len(active)} signed skills available for installation",
        )
    )
    components.append(
        action_button(
            "publish-cta",
            label="Publish a skill",
            action="open_publish_skill",
            variant="outline",
            data={},
        )
    )

    # Recently revoked — keep a short audit trail on-screen so the registry's
    # security story is visible.
    if revoked_count:
        revoked_recent = [s for s in skills if s.get("revoked_at")][:5]
        section_ids.extend(["revoked-heading", "revoked-list"])
        components.append(heading("revoked-heading", 3, "Recently revoked"))
        components.append(
            table(
                "revoked-list",
                columns=["Skill", "Revoked at", "Reason"],
                rows=[
                    [
                        f"{s.get('name')}@{s.get('version')}",
                        (s.get("revoked_at") or "")[:19],
                        (s.get("revocation_reason") or "")[:80],
                    ]
                    for s in revoked_recent
                ],
                caption="Revoked skills remain visible for audit purposes.",
            )
        )

    components.insert(0, column("root", section_ids))
    return surface("surface-skills", [card("page", "root")] + components, "page")


async def build_skill_detail_surface(target: str | None = None) -> dict:
    """A2UI surface for /page/skills/{id}."""
    try:
        import skill_registry as sr
    except ImportError:
        return surface(
            "surface-skill-unavailable",
            [
                card("page", "root"),
                column("root", ["t"]),
                text("t", "Skill registry not available", "h2"),
            ],
            "page",
        )

    if not target:
        return surface(
            "surface-skill-notarget",
            [
                card("page", "root"),
                column("root", ["t"]),
                text("t", "No skill specified", "h2"),
            ],
            "page",
        )

    skill = await sr.get_skill(target)
    if not skill:
        return surface(
            "surface-skill-notfound",
            [
                card("page", "root"),
                column("root", ["title", "msg", "back"]),
                heading("title", 2, f"Skill {target!r} not found"),
                text("msg", "It may have been revoked or never existed.", "body"),
                action_button("back", "Back to skills", "open_skills", "outline", {}),
            ],
            "page",
        )

    caps = skill.get("capabilities") or []
    risk = sr.describe_risk(caps)
    author_tier_name = sr.tier_from_trust_score(skill.get("trust_score") or 0)

    section_ids = ["hero", "badges", "author-card"]
    components: list[dict] = [
        heading("hero", 1, f"{skill.get('name')}@{skill.get('version')}"),
        row(
            "badges",
            [
                "badge-version",
                "badge-trust",
                "badge-installs",
            ],
        ),
        badge("badge-version", f"v{skill.get('version', '?')}", "outline"),
        trust_badge("badge-trust", float(skill.get("trust_score") or 0)),
        badge(
            "badge-installs",
            f"{skill.get('install_count') or 0} installs",
            "secondary",
        ),
        member_card(
            "author-card",
            name=_short_did(skill.get("author_did", "")),
            agent_id=skill.get("author_agent_id") or "",
            role=f"Author · {author_tier_name}",
            subtitle=skill.get("description") or "",
        ),
    ]

    # High-risk warning if applicable.
    if risk["level"] != "low":
        section_ids.append("risk-callout")
        components.append(
            callout(
                "risk-callout",
                f"This skill declares elevated capabilities: {', '.join(risk['high_risk'])}. "
                f"Review the manifest carefully before installing.",
                variant="warning" if risk["level"] == "medium" else "danger",
                title=f"{risk['level'].title()} risk",
            )
        )

    # Revoked banner.
    if skill.get("revoked_at"):
        section_ids.append("revoked-callout")
        components.append(
            callout(
                "revoked-callout",
                skill.get("revocation_reason") or "No reason provided",
                variant="danger",
                title=f"Revoked at {(skill.get('revoked_at') or '')[:19]}",
            )
        )

    # Readme as rich Markdown.
    if skill.get("readme_markdown"):
        section_ids.append("readme")
        components.append(markdown("readme", skill["readme_markdown"]))

    # ── Open-format metadata (rendered only when present) ──
    meta_rows: list[list[str]] = []
    if skill.get("category"):
        meta_rows.append(["Category", str(skill["category"])])
    if skill.get("safety_level"):
        meta_rows.append(["Safety", str(skill["safety_level"])])
    if skill.get("license"):
        meta_rows.append(["License", str(skill["license"])])
    if skill.get("risk_tags"):
        meta_rows.append(["Risk tags", ", ".join(str(t) for t in list(skill["risk_tags"])[:12])])
    if isinstance(skill.get("compatibility"), dict) and skill["compatibility"]:
        meta_rows.append(["Compatibility", ", ".join(f"{k}: {v}" for k, v in skill["compatibility"].items())])
    if meta_rows:
        section_ids.extend(["meta-heading", "meta-table"])
        components.append(heading("meta-heading", 3, "Details"))
        components.append(table("meta-table", columns=["Field", "Value"], rows=meta_rows))

    if skill.get("use_cases"):
        section_ids.extend(["uses-heading", "uses-list"])
        components.append(heading("uses-heading", 3, "Use cases"))
        components.append(list_component("uses-list", [str(u) for u in list(skill["use_cases"])[:12]]))

    io_rows: list[list[str]] = []
    for io in skill.get("inputs") or []:
        if isinstance(io, dict) and io.get("name"):
            io_rows.append(["input", str(io["name"]), str(io.get("description") or "")])
    for io in skill.get("outputs") or []:
        if isinstance(io, dict) and io.get("name"):
            io_rows.append(["output", str(io["name"]), str(io.get("description") or "")])
    if io_rows:
        section_ids.extend(["io-heading", "io-table"])
        components.append(heading("io-heading", 3, "Inputs & outputs"))
        components.append(table("io-table", columns=["Kind", "Name", "Description"], rows=io_rows))

    # Capabilities table.
    section_ids.append("caps-heading")
    components.append(heading("caps-heading", 3, "Declared capabilities"))
    if caps:
        section_ids.append("caps-table")
        components.append(
            table(
                "caps-table",
                columns=["Capability", "Risk"],
                rows=[[c, "high" if c in sr.HIGH_RISK_CAPABILITIES else "normal"] for c in caps],
            )
        )
    else:
        section_ids.append("caps-empty")
        components.append(text("caps-empty", "This skill declares no capabilities.", "caption"))

    # Signature proof section.
    section_ids.extend(["sig-heading", "sig-block"])
    components.append(heading("sig-heading", 3, "Signature"))
    components.append(
        code_block(
            "sig-block",
            code=(
                f"sha256(content) = {skill.get('content_sha256', '')}\n"
                f"signed_by      = {skill.get('signing_key_did', '')}\n"
                f"signature      = {skill.get('signature', '')[:64]}…"
            ),
            language="text",
            caption="Ed25519 signature proof",
        )
    )

    # Install + review actions.
    section_ids.append("actions-row")
    action_ids = []
    if not skill.get("revoked_at"):
        action_ids.append("btn-install")
        components.append(
            action_button(
                "btn-install",
                label="Install skill",
                action="install_skill",
                variant="default",
                data={"skill_id": skill.get("id")},
            )
        )
    action_ids.extend(["btn-back"])
    components.append(action_button("btn-back", "Back to skills", "open_skills", "outline", {}))
    components.append(row("actions-row", action_ids))

    components.insert(0, column("root", section_ids))
    return surface(
        f"surface-skill-{skill.get('id', '').replace('@', '-')}", [card("page", "root")] + components, "page"
    )


async def build_marketplace_surface(target: str | None = None) -> dict:
    """A2UI surface for /page/marketplace — featured + categories + top authors.

    Extends /page/skills with curation + discovery. Same registry under the
    hood; this surface is aimed at browse-to-install UX rather than audit.
    """
    try:
        import skill_registry as sr
    except ImportError:
        return surface(
            "surface-marketplace-unavailable",
            [
                card("page", "root"),
                column("root", ["t"]),
                text("t", "Skill registry not available", "h2"),
            ],
            "page",
        )

    skills = await sr.list_skills(limit=200) or []
    featured = sr.featured_skills(skills, limit=4)
    chips_data = sr.category_chips(skills)

    # Group by author for reputation ranking.
    by_author: dict[str, list[dict]] = {}
    for s in skills:
        by_author.setdefault(s.get("author_did", ""), []).append(s)
    top_authors = sr.author_reputation(by_author)[:8]

    section_ids = [
        "hero",
        "pitch-callout",
        "stats-row",
        "featured-heading",
    ]

    total_installs = sum(int(s.get("install_count") or 0) for s in skills)

    components: list[dict] = [
        heading("hero", 1, "Skill Marketplace"),
        callout(
            "pitch-callout",
            "Every skill here is Ed25519-signed by its author — unlike unsigned "
            "marketplaces where ~20% of packages have contained crypto-stealing "
            "malware. Revocation propagates through the mesh; installs are "
            "verified twice.",
            variant="success",
            title="Signed by protocol",
        ),
        stat_group(
            "stats-row",
            [
                {"label": "Skills", "value": str(len([s for s in skills if not s.get("revoked_at")]))},
                {"label": "Authors", "value": str(len(by_author))},
                {"label": "Total installs", "value": str(total_installs)},
                {"label": "Revoked", "value": str(len([s for s in skills if s.get("revoked_at")]))},
            ],
        ),
        heading("featured-heading", 3, "Featured"),
    ]

    if featured:
        featured_ids: list[str] = []
        for i, s in enumerate(featured):
            fid = f"feat-{i}"
            featured_ids.append(fid)
            components.append(
                member_card(
                    fid,
                    name=f"{s.get('name', '?')}@{s.get('version', '?')}",
                    agent_id=s.get("author_did", "")[:22] + "…",
                    role=sr.tier_from_trust_score(s.get("trust_score") or 0),
                    trust_score=float(s.get("trust_score") or 0),
                    skills=list(s.get("capabilities") or [])[:4],
                    subtitle=s.get("description") or "",
                )
            )
        section_ids.append("featured-grid")
        components.append(grid("featured-grid", featured_ids, cols=2))
    else:
        section_ids.append("featured-empty")
        components.append(text("featured-empty", "No featured skills yet.", "caption"))

    # Categories as chips.
    if chips_data:
        section_ids.extend(["categories-heading", "categories-group"])
        components.append(heading("categories-heading", 3, "Categories"))
        chip_ids: list[str] = []
        for i, c in enumerate(chips_data[:12]):
            cid = f"cat-{i}"
            chip_ids.append(cid)
            components.append(chip(cid, label=c["label"], value=c["value"]))
        components.append(chip_group("categories-group", chip_ids, multi=True))

    # Top authors leaderboard.
    if top_authors:
        section_ids.extend(["authors-heading", "authors-table"])
        components.append(heading("authors-heading", 3, "Top authors"))
        components.append(
            table(
                "authors-table",
                columns=["Author", "Tier", "Skills", "Installs", "Avg ★", "Clean"],
                rows=[
                    [
                        (a["author_did"][:14] + "…" + a["author_did"][-4:])
                        if len(a["author_did"]) > 22
                        else a["author_did"],
                        a["tier"],
                        str(a["skill_count"]),
                        str(a["total_installs"]),
                        f"{a['avg_rating']:.1f}" if a["avg_rating"] else "—",
                        f"{int(a['non_revoked_ratio'] * 100)}%",
                    ]
                    for a in top_authors
                ],
                caption="Reputation = f(installs, ratings, skill count, revocation rate).",
            )
        )

    section_ids.append("publish-cta")
    components.append(
        action_button(
            "publish-cta",
            label="Publish a skill",
            action="open_publish_skill",
            variant="outline",
            data={},
        )
    )

    components.insert(0, column("root", section_ids))
    return surface("surface-marketplace", [card("page", "root")] + components, "page")


async def build_skill_publish_surface(target: str | None = None) -> dict:
    """A2UI surface for /page/skills/publish — author flow."""
    try:
        import skill_registry as sr  # noqa: F401 — referenced for availability check
    except ImportError:
        return surface(
            "surface-publish-unavailable",
            [
                card("page", "root"),
                column("root", ["t"]),
                text("t", "Skill registry not available", "h2"),
            ],
            "page",
        )

    components = [
        heading("hero", 1, "Publish a skill"),
        callout(
            "how-it-works",
            "Skills are Ed25519-signed by the author. You generate a keypair locally "
            "(or use your existing chapter member did:key), sign the sha256 of your "
            "package tarball, and submit the manifest + signature here. The chapter "
            "re-verifies before accepting.",
            variant="info",
            title="How signing works",
        ),
        heading("form-heading", 3, "Skill manifest"),
        form(
            "publish-form",
            [
                "f-name",
                "f-version",
                "f-description",
                "f-capabilities",
                "f-readme",
                "f-signing-did",
                "f-content-sha",
                "f-signature",
            ],
            action="publish_skill",
            submit_label="Verify signature + publish",
        ),
        input_field("f-name", label="Name", placeholder="e.g. file-ops"),
        input_field("f-version", label="Version", placeholder="e.g. 1.0.0"),
        input_field("f-description", label="Short description", placeholder="one line"),
        input_field(
            "f-capabilities",
            label="Capabilities (comma-separated)",
            placeholder="fs.read, net.http",
        ),
        textarea(
            "f-readme",
            label="README (Markdown supported)",
            placeholder="# skill-name\n\nWhat it does + how to use it.",
            rows=6,
        ),
        input_field(
            "f-signing-did",
            label="Your did:key",
            placeholder="did:key:z6Mk...",
        ),
        input_field(
            "f-content-sha",
            label="sha256 of skill package (hex)",
            placeholder="64 hex characters",
        ),
        input_field(
            "f-signature",
            label="Ed25519 signature (base64)",
            placeholder="Ed25519 sig over the sha256",
        ),
        heading("cli-heading", 3, "Or publish from the CLI"),
        code_block(
            "cli-snippet",
            code=(
                "# install the CLI\n"
                "pip install member-agent\n\n"
                "# build + sign + publish in one shot\n"
                "member skill init my-skill\n"
                "member skill sign  my-skill/\n"
                "member skill publish my-skill.nandaskill \\\n"
                "    --chapter https://org.example.com"
            ),
            language="bash",
            caption="The CLI handles signing and upload for you.",
        ),
    ]

    components.insert(
        0,
        column(
            "root",
            [
                "hero",
                "how-it-works",
                "form-heading",
                "publish-form",
                "cli-heading",
                "cli-snippet",
            ],
        ),
    )
    return surface("surface-skill-publish", [card("page", "root")] + components, "page")


# ═══════════════════════════════════════════════════════════════════
# Attestation marketplace surfaces — Phase A
# ═══════════════════════════════════════════════════════════════════


async def build_advisor_earnings_surface(target: str | None = None) -> dict:
    """Show an advisor their live attestations + rolling 7/30-day earnings.

    `target` is the advisor's did:key (prefix 'did:key:z...'). When absent
    we render a prompt to pass one — this surface is per-advisor.
    """
    try:
        import skill_revenue
    except ImportError:
        return surface(
            "surface-advisor-earnings-unavailable",
            [card("page", "root"), column("root", ["t"]), text("t", "Revenue module not available", "h2")],
            "page",
        )

    if not target or not target.startswith(("did:key:", "chapter:")):
        return surface(
            "surface-advisor-earnings-welcome",
            [
                card("page", "root"),
                column("root", ["title", "msg"]),
                heading("title", 1, "Advisor earnings"),
                text(
                    "msg",
                    "Pass ?target=<your did:key> to see your attestations and rolling earnings.",
                    "body",
                ),
            ],
            "page",
        )

    # Fetch rolled-up totals (all-time) + last 7 days separately
    from datetime import UTC, datetime, timedelta

    totals_all = await skill_revenue.get_earnings_for_did(target)
    since_7d = (datetime.now(UTC) - timedelta(days=7)).isoformat()
    totals_7d = await skill_revenue.get_earnings_for_did(target, since_iso=since_7d)

    def _fmt(cents: int) -> str:
        return f"${cents / 100:.2f}" if cents else "$0.00"

    sections = ["hero", "totals-row", "breakdown-heading", "breakdown-row"]
    components = [
        heading("hero", 1, "Advisor earnings"),
        row(
            "totals-row",
            ["stat-total-all", "stat-total-7d", "stat-events-all"],
        ),
        metric("stat-total-all", _fmt(totals_all.get("total_cents", 0)), "All-time"),
        metric("stat-total-7d", _fmt(totals_7d.get("total_cents", 0)), "Last 7 days"),
        metric("stat-events-all", str(totals_all.get("event_count", 0)), "Ledger entries"),
        heading("breakdown-heading", 2, "By role"),
        row(
            "breakdown-row",
            ["b-author", "b-advisor", "b-chapter"],
        ),
        metric("b-author", _fmt(totals_all.get("by_role", {}).get("author", 0)), "as author"),
        metric("b-advisor", _fmt(totals_all.get("by_role", {}).get("advisor", 0)), "as advisor"),
        metric("b-chapter", _fmt(totals_all.get("by_role", {}).get("chapter", 0)), "as org"),
    ]

    # Currency breakdown (TEST_USD vs USD once Phase D lands)
    if totals_all.get("by_currency"):
        sections.append("currency-note")
        currencies = ", ".join(f"{k}: {_fmt(v)}" for k, v in sorted(totals_all["by_currency"].items()))
        components.append(text("currency-note", currencies, "caption"))

    components.insert(0, column("root", sections))
    return surface("surface-advisor-earnings", [card("page", "root")] + components, "page")


async def build_trust_surface(target: str | None = None) -> dict:
    """Per-agent trust dossier — score, tier, projection, history.

    `target` is the agent_id whose trust to render. When absent we
    render a friendly explainer + the chapter's own score. R/S
    coverage in tests/test_surfaces.py.
    """
    import trust_events as _trust

    agent_id = (target or AGENT_ID).strip()
    safe_id = agent_id.replace("/", "").replace("@", "")[:128]

    # Score (read from agents table — trigger keeps it in sync)
    score = 0.0
    if pg_request is not None:
        try:
            rows = await pg_request(
                "GET",
                "agents",
                params={"agent_id": f"eq.{safe_id}", "select": "trust_score", "limit": 1},
            )
            if rows:
                score = float(rows[0].get("trust_score") or 0.0)
        except Exception:
            pass

    tier = _trust.tier_for(score)
    history = []
    projection = {"recent_30d_delta": "0", "projected_30d": "0"}
    try:
        history = await _trust.list_history(safe_id, limit=20)
        projection = await _trust.projection_30d(safe_id)
    except Exception:
        pass

    # Days-to-next-tier
    next_min = None
    for t_min in _trust.TRUST_TIERS:
        if t_min > score:
            next_min = t_min
            break
    days_to_next: float | None = None
    rate_30d = float(projection.get("projected_30d") or 0.0)
    if next_min is not None and rate_30d > 0:
        days_to_next = (next_min - score) / (rate_30d / 30.0)

    components: list[dict] = [
        card("page", "root"),
        column("root", []),  # children filled below
        heading("title", 1, f"Trust dossier — @{safe_id}"),
        row("stats-row", ["s-score", "s-tier", "s-next"]),
        metric("s-score", f"{score:.1f}", "Trust score"),
        metric("s-tier", _format_tier(tier), "Tier"),
    ]
    if next_min is not None:
        if days_to_next is not None:
            metric_value = f"{days_to_next:.0f}d"
        else:
            metric_value = "—"
        components.append(
            metric("s-next", metric_value, f"Days to {next_min:.0f}", trend="neutral"),
        )
    else:
        components.append(metric("s-next", "—", "Top tier reached", trend="up"))

    # Projection callout
    rate = float(projection.get("recent_30d_delta") or 0.0)
    if rate > 0:
        components.append(
            callout(
                "proj-cb",
                f"+{rate:.1f} accrued in the last 30 days. At this rate, projected next-30d gain: +{rate:.1f}.",
                "success",
                "Trending up",
            )
        )
    elif rate < 0:
        components.append(
            callout(
                "proj-cb",
                f"{rate:.1f} in the last 30 days — recent decay or revocations.",
                "warning",
                "Trending down",
            )
        )
    else:
        components.append(
            callout(
                "proj-cb",
                "No trust activity in the last 30 days. Active members earn ~+5–10 per month from intent matches and endorsements.",
                "info",
                "Quiet",
            )
        )

    # History timeline
    components.append(heading("hist-title", 2, "Recent activity"))
    if not history:
        components.append(text("hist-empty", "No trust events yet.", "body"))
        history_ids: list[str] = ["hist-empty"]
    else:
        history_ids = []
        for i, ev in enumerate(history[:20]):
            row_id = f"h{i}"
            type_id = f"h{i}-type"
            delta_id = f"h{i}-delta"
            text_id = f"h{i}-text"
            ev_type = (ev.get("event_type") or "").replace("_", " ")
            delta_val = ev.get("delta") or "0"
            try:
                delta_str = f"{float(delta_val):+.1f}"
            except (ValueError, TypeError):
                delta_str = str(delta_val)
            reason = ev.get("reason") or ""
            occurred = (ev.get("occurred_at") or "")[:19]
            components.extend(
                [
                    row(row_id, [type_id, delta_id, text_id]),
                    badge(type_id, ev_type, variant="secondary"),
                    badge(
                        delta_id,
                        delta_str,
                        variant="outline",
                        color="green"
                        if delta_val and float(delta_val) > 0
                        else ("red" if delta_val and float(delta_val) < 0 else ""),
                    ),
                    text(text_id, f"{occurred} — {reason or '(no reason)'}", "body"),
                ]
            )
            history_ids.append(row_id)

    # Build root children list
    components[1] = column(
        "root",
        ["title", "stats-row", "proj-cb", "hist-title"] + history_ids,
    )
    return surface(f"surface-trust-{safe_id}", components, "page")


def _format_tier(tier: dict) -> str:
    """Map a tier dict from trust_events.tier_for to a short label."""
    min_t = tier.get("min_trust", 0)
    if min_t >= 75:
        return "Leader"
    if min_t >= 50:
        return "Trusted"
    if min_t >= 20:
        return "Established"
    return "Newcomer"


async def build_endorsements_surface(target: str | None = None) -> dict:
    """Per-agent endorsements — count + one redacted row per endorsement.

    OPEN BY DESIGN, REDACTED BY NECESSITY. This is one of
    `auth_verify.PER_AGENT_SHAREABLE_SURFACES`: a page a member shares by
    URL, which must keep working without an account. But the rationale that
    keeps those pages open — "it discloses its subject's agent_id and nothing
    more" — is false for THIS one and only this one. `profile`, `reputation`,
    `trust` and `chronicle` disclose the SUBJECT, who chose to share the page.
    An endorsement discloses a THIRD PARTY, the endorser, who made no such
    choice and is not the one sharing. A subject cannot consent on an
    endorser's behalf, so the endorser is coarsened to a chapter_role here
    while the page itself stays open.

    Same redaction, same grain, as `chapter_agent._redact_trust_history`:
    the trust HISTORY is this same relation seen from a different route, and
    two routes over one relation must not disagree. Dropped:
    `endorser_agent_id`, `endorser_did`, and `note_markdown` —
    caller-authored free text, which is how this class of defect survives a
    field-level check (the trust-event `reason` written at
    endorsements.py:226 is literally f"endorsed by {endorser_agent_id}").
    Replaced by a single `endorser_role`, DERIVED from
    governance.get_chapter_role at render time rather than stored on the row.

    An endorsement whose row carries no endorser_agent_id renders "unknown".
    get_chapter_role answers "member" for an id it cannot resolve — a
    default, not a fact — so it is never asked about an absent id; otherwise
    a row with no endorser would claim a member endorsed this agent.

    RESIDUAL, stated rather than papered over: an endorser id that IS present
    but does not resolve (row gone, chapter_role null) still reads "member",
    because get_chapter_role collapses "unresolvable" and "plain member" into
    one answer and does not expose the difference. Distinguishing them would
    mean this surface reimplementing the role lookup instead of deriving from
    the one every gate uses, which is a worse trade: the two would drift. The
    disclosure question is unaffected either way — "member" names no third
    party — so this is a fidelity limit, not a leak.

    The raw API, GET /api/agents/{agent_id}/endorsements, is unchanged: it is
    auth-gated, and a signed member seeing full endorser detail is correct.
    """
    import endorsements as _endorsements
    import governance as _governance

    agent_id = (target or AGENT_ID).strip()
    safe_id = agent_id.replace("/", "").replace("@", "")[:128]

    rows = []
    try:
        rows = await _endorsements.list_endorsements_received(safe_id, limit=50)
    except Exception:
        pass

    components: list[dict] = [
        card("page", "root"),
        column("root", []),
        heading("title", 1, f"Endorsements for @{safe_id}"),
    ]

    sub_ids = ["title"]

    if not rows:
        components.append(
            callout(
                "empty",
                "No endorsements yet. Members with trust ≥20 can endorse you. Each unique endorser is worth +0.5 of trust; collusion costs scale with the number of accomplices.",
                "info",
                "How endorsements work",
            )
        )
        sub_ids.append("empty")
    else:
        components.append(text("count", f"{len(rows)} endorsement{'s' if len(rows) != 1 else ''} received", "body"))
        sub_ids.append("count")
        # Batched per UNIQUE endorser, not per row — a member endorsed by the
        # same peer twice must not cost two role lookups.
        unique_endorsers: set[str] = {eid for r in rows[:50] if (eid := (r.get("endorser_agent_id") or "").strip())}
        roles: dict[str, str] = {eid: await _governance.get_chapter_role(eid) for eid in unique_endorsers}
        for i, e in enumerate(rows[:50]):
            row_id = f"e{i}"
            who_id = f"e{i}-who"
            ts_id = f"e{i}-ts"
            endorser = (e.get("endorser_agent_id") or "").strip()
            role = roles.get(endorser, "unknown") if endorser else "unknown"
            ts = (e.get("created_at") or "")[:10]
            components.extend(
                [
                    card(row_id, f"{row_id}-col"),
                    column(f"{row_id}-col", [who_id, ts_id]),
                    heading(who_id, 4, f"Endorser role: {role}"),
                    text(ts_id, ts, "caption"),
                ]
            )
            sub_ids.append(row_id)

    components[1] = column("root", sub_ids)
    return surface(f"surface-endorsements-{safe_id}", components, "page")


async def build_skill_attest_surface(target: str | None = None) -> dict:
    """Trusted-tier-only form to co-sign an attestation on a published skill.

    Non-trusted visitors see a 'not eligible' explainer instead of the form.
    The actual Ed25519 signing happens client-side; this surface is just
    the input form + capability disclosure.
    """
    return surface(
        "surface-skill-attest",
        [
            card("page", "root"),
            column(
                "root",
                ["hero", "who-can", "flow-heading", "flow-list", "form-heading", "attest-form"],
            ),
            heading("hero", 1, "Attest a skill"),
            text(
                "who-can",
                "Only members at advisor / mentor / leader / admin tier can attest. "
                "Self-attestation (author signing own skill) is rejected by protocol.",
                "caption",
            ),
            heading("flow-heading", 2, "Flow"),
            list_component(
                "flow-list",
                [
                    "1. Pick a published skill from the marketplace.",
                    "2. Review the manifest, capabilities, source, and content_sha256.",
                    "3. Your client signs ATTEST:{chapter}:{skill}:{version}:{sha}:{you}:{ts} with your Ed25519 key.",
                    "4. POST the signature to /api/skills/{id}/attest.",
                    "5. Future tool invocations mint a revenue event; you earn from the advisor pool.",
                ],
            ),
            heading("form-heading", 2, "Your attestation"),
            form(
                "attest-form",
                ["skill-id-input", "note-input", "submit-btn"],
                action="submit-attestation",
                submit_label="Sign + submit",
            ),
            input_field("skill-id-input", label="Skill ID", placeholder="my-skill@1.0.0"),
            textarea("note-input", label="Review notes (public)", placeholder="What did you verify?"),
            action_button("submit-btn", "Sign + submit", action="submit-attestation", variant="default"),
        ],
        "page",
    )


# ─── Stage 2 of the agent-driven portal migration ────────────────────
#
# These three builders replace what used to be hand-written React
# pages in the portal: AgentDirectory.tsx (federation-wide agent
# directory), Search.tsx (cross-server search), and StartupProfile
# .tsx (single-startup detail). Each is now an A2UI surface served
# at /api/surfaces/{pageId} so the portal renders them through
# AgentPage with live AG-UI streaming.


async def build_directory_surface(target: str | None = None) -> dict:
    """Federation-wide agent directory.

    Aggregates the local chapter's members with peer-chapter members
    pulled from the federation cache. Each agent renders as a
    MemberCard. Replaces ``AgentDirectory.tsx`` which fetched
    ``/api/nest/agents`` — a route that has been returning 404 in
    production, so the static page silently showed an empty refresh
    prompt and never updated.
    """
    local = [(mid, m) for mid, m in members.items() if not mid.startswith("STARTUP-")]

    # Federation servers render as a summary row (name + member
    # count + status badge), not a per-member list. The federation
    # cache only carries server-level info — name, endpoint, and
    # an integer ``members`` count. Enumerating peer members would
    # require live HTTP calls to each peer's /api/members; that's a
    # follow-up for when we have a federation-wide member index. The
    # initial surface returned an empty Refresh prompt to users
    # because the static React fetched a 404 endpoint, so even a
    # server-summary view is a strict improvement.
    fed_state = federation if isinstance(federation, dict) else {}
    fed_chapters: list[tuple[str, dict]] = [
        (chapter_id, info) for chapter_id, info in fed_state.items() if isinstance(info, dict)
    ]

    total_local = len(local)
    federated_member_total = sum(
        int(info.get("members", 0)) if isinstance(info.get("members"), int) else 0 for _, info in fed_chapters
    )
    total = total_local + federated_member_total

    sections: list[str] = ["dir-title", "dir-count"]
    components: list[dict] = [
        text("dir-title", "Agent Directory", "h1"),
        text(
            "dir-count",
            f"{total} agents in this org + {len(fed_chapters)} federated peers",
            "caption",
        ),
    ]

    if local:
        sections.append("dir-local-label")
        components.append(text("dir-local-label", f"This server ({total_local})", "h2"))
        local_ids: list[str] = []
        for i, (mid, m) in enumerate(local[:30]):
            cid = f"dir-local-m{i}"
            components.append(
                member_card(
                    cid,
                    name=m.get("name", mid),
                    agent_id=mid,
                    role=m.get("role", "member"),
                    skills=list(m.get("skills") or [])[:6],
                    subtitle=m.get("description", ""),
                )
            )
            local_ids.append(cid)
        components.append(grid("dir-local-grid", local_ids, 3))
        sections.append("dir-local-grid")

    if fed_chapters:
        sections.append("dir-fed-label")
        components.append(text("dir-fed-label", f"Federation ({len(fed_chapters)})", "h2"))
        fed_card_ids: list[str] = []
        for i, (chapter_id, info) in enumerate(fed_chapters):
            cid = f"dir-fed-c{i}"
            name = info.get("name", chapter_id)
            mcount = info.get("members")
            mcount_str = str(mcount) if isinstance(mcount, int) and mcount > 0 else "?"
            status = "online" if info.get("status") != "offline" else "offline"
            # Build a tight Card per peer server: name as Heading,
            # member count + status as Badge row.
            col_id = f"{cid}-col"
            children = [f"{cid}-name", f"{cid}-meta"]
            components.extend(
                [
                    text(f"{cid}-name", name, "h4"),
                    row(
                        f"{cid}-meta",
                        [f"{cid}-count", f"{cid}-status"],
                    ),
                    badge(f"{cid}-count", f"{mcount_str} members", "secondary"),
                    badge(
                        f"{cid}-status",
                        status,
                        "secondary" if status == "online" else "outline",
                    ),
                ]
            )
            components.append(column(col_id, children))
            components.append(card(cid, col_id))
            fed_card_ids.append(cid)
        components.append(grid("dir-fed-grid", fed_card_ids, 3))
        sections.append("dir-fed-grid")

    if not local and not fed_chapters:
        sections.append("dir-empty")
        components.append(
            callout(
                "dir-empty",
                "No agents are currently registered. Federation peers may be offline.",
                variant="info",
                title="Empty directory",
            )
        )

    components.append(column("root", sections))
    components.append(card("page", "root"))
    return surface("surface-directory", components, "page")


async def build_search_surface(target: str | None = None) -> dict:
    """Cross-chapter search across members + events + groups.

    ``target`` is the search query (typically passed via the
    ``?target=`` query param). Empty/missing target renders a search-
    prompt placeholder. Replaces ``Search.tsx`` which queried
    Postgres directly from the browser using the user's session.
    """
    query = (target or "").strip()
    sections: list[str] = ["search-title", "search-input-row"]
    components: list[dict] = [
        text("search-title", "Search", "h1"),
        text(
            "search-input-row",
            "Type a member name, skill, event title, or group name in the URL (?target=…) to search.",
            "caption",
        ),
    ]

    if not query:
        sections.append("search-empty")
        components.append(
            callout(
                "search-empty",
                "Add ?target=<your query> to the URL to begin a search.",
                variant="info",
                title="No query provided",
            )
        )
        components.append(column("root", sections))
        components.append(card("page", "root"))
        return surface("surface-search", components, "page")

    sections.append("search-query")
    components.append(text("search-query", f'Results for "{query}"', "h2"))

    pattern = f"*{query}*"

    member_hits = await _pg()(
        "GET",
        "profiles",
        params={
            "or": f"(full_name.ilike.{pattern},bio.ilike.{pattern})",
            "limit": "10",
            "select": "id,full_name,bio,skills,avatar_url",
        },
    )
    event_hits = await _pg()(
        "GET",
        "agent_events",
        params={
            "chapter_agent_id": f"eq.{AGENT_ID}",
            "or": f"(title.ilike.{pattern},description.ilike.{pattern})",
            "limit": "10",
            "select": "id,title,description,event_type,status",
        },
    )

    sections.append("search-members-label")
    components.append(
        text(
            "search-members-label",
            f"Members ({len(member_hits or [])})",
            "h3",
        )
    )
    if member_hits:
        member_ids: list[str] = []
        for i, m in enumerate(member_hits):
            cid = f"search-m{i}"
            components.append(
                member_card(
                    cid,
                    name=m.get("full_name", "Unknown"),
                    agent_id=m.get("id", ""),
                    role="member",
                    skills=list(m.get("skills") or [])[:5],
                    subtitle=(m.get("bio") or "")[:120],
                )
            )
            member_ids.append(cid)
        components.append(grid("search-members-grid", member_ids, 2))
        sections.append("search-members-grid")
    else:
        sections.append("search-no-members")
        components.append(text("search-no-members", "No matching members.", "caption"))

    sections.append("search-events-label")
    components.append(
        text(
            "search-events-label",
            f"Events ({len(event_hits or [])})",
            "h3",
        )
    )
    if event_hits:
        for i, ev in enumerate(event_hits):
            eid = f"search-ev{i}"
            sections.append(eid)
            components.append(
                callout(
                    eid,
                    (ev.get("description") or "")[:200],
                    variant="info",
                    title=ev.get("title", "Event"),
                )
            )
    else:
        sections.append("search-no-events")
        components.append(text("search-no-events", "No matching events.", "caption"))

    components.append(column("root", sections))
    components.append(card("page", "root"))
    return surface(f"surface-search:{query[:40]}", components, "page")


# ─── Stage 3 of the agent-driven portal migration ─────────────────────
#
# Read-only profile surface. Per the membership tier model
# (cloud OAuth via maritime.sh / local SDK / OpenClaw skill — each
# carrying a different starting trust score that earns capabilities
# over time), profile *editing* lives in the identity-tier-specific
# write paths (Postgres Auth + RLS for cloud, local keystore for
# SDK, read-only for OpenClaw). The server only owns the *read*
# view: which member they are, what the agent has learned about
# them, what tier they sit at, what they've contributed.


# ─── ARP surfaces ──────────────────────────────────────────────────
#
# /page/today and /page/chronicle expose the Agency Receipt Protocol
# data (see spec/arp/0.1/) as agent-generated A2UI surfaces.
#
#   /page/today                — principal-private daily report; the
#                                HTTP layer injects the caller's did:key
#                                into ``target`` after middleware-verified
#                                X-Agent-Signature
#   /page/chronicle?target=X   — agent's first-person Chronicle entries
#                                gated by agents.config.chronicle_public
#                                of the target

_ARP_CATEGORY_DISPLAY: dict[str, str] = {
    "purchase": "Purchases",
    "payment_sent": "Payments sent",
    "payment_received": "Payments received",
    "message_sent": "Messages sent",
    "message_received": "Messages received",
    "decision_made": "Decisions",
    "data_shared": "Data shared",
    "appointment_booked": "Appointments",
    "appointment_cancelled": "Cancellations",
    "subscription_changed": "Subscriptions",
    "record_filed": "Records filed",
    "account_created": "Accounts opened",
    "account_closed": "Accounts closed",
    "attestation_issued": "Attestations issued",
    "attestation_received": "Attestations received",
    "commitment_entered": "Commitments entered",
    "commitment_fulfilled": "Commitments fulfilled",
    "commitment_breached": "Commitments breached",
    "vote_cast": "Votes",
    "other": "Other",
}


async def _todays_receipts(principal_did: str) -> list[dict]:
    """Pull arp_receipts for the principal whose ``issued_at`` falls in
    the current UTC calendar day. Cross-chapter by construction."""
    if not principal_did:
        return []
    # Offline mode: read from the server's local SQLite Issuer Log.
    import arp as _arp

    if _arp.is_offline():
        from datetime import UTC, datetime

        day_iso = datetime.now(UTC).strftime("%Y-%m-%d")
        return await _arp.todays_rows_local(day_iso, principal_did)
    if pg_request is None:
        return []
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    day_end = (now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    rows = await pg_request(
        "GET",
        "arp_receipts",
        params={
            "principal_did": f"eq.{principal_did}",
            "issued_at": f"gte.{day_start}",
            "and": f"(issued_at.lt.{day_end})",
            "select": "receipt_json,issued_at,action_category,action_outcome,human_summary,amount_currency,amount_cents,counterparty_did",
            "order": "issued_at.asc",
            "limit": "500",
        },
    )
    return list(rows or [])


def _money_label(cur: str | None, cents: int | None) -> str:
    if not isinstance(cents, int) or not cur:
        return ""
    sign = "-" if cents < 0 else "+"
    dollars = abs(cents) / 100.0
    return f"{sign}{cur} {dollars:,.2f}"


async def build_today_surface(target: str | None = None) -> dict:
    """The principal-private daily report. ``target`` is the caller's
    did:key — the HTTP layer overrides any client-supplied value with
    the auth-verified did before calling here.

    Renders today's receipts grouped by action category. Each row shows
    the human_summary, time-of-day, counterparty (when present) and
    amount. No drill-down in v1 — that's a follow-up enhancement.
    """
    from datetime import UTC, datetime

    if not target:
        return surface(
            "today-unauth",
            [
                card("c", "root"),
                column("root", ["title", "msg"]),
                text("title", "Sign in to see your Today", "h2"),
                text(
                    "msg",
                    "Your Today report shows every action your agent took on your behalf — but you must be signed in as the principal.",
                    "body",
                ),
            ],
            "c",
        )

    today_label = datetime.now(UTC).strftime("%A, %B %d, %Y")
    receipts = await _todays_receipts(target)

    # Group by category for the rendering pass.
    grouped: dict[str, list[dict]] = {}
    for r in receipts:
        cat = r.get("action_category") or "other"
        grouped.setdefault(cat, []).append(r)

    components: list[dict] = [
        card("c", "root"),
        column("root", ["title", "subtitle", "summary"] + [f"section-{cat}" for cat in grouped] + ["empty"]),
        text("title", "Today", "h1"),
        text("subtitle", today_label, "body"),
    ]

    if not receipts:
        components.append(
            text(
                "summary",
                "Your agent had a quiet day — no recorded actions yet.",
                "body",
            )
        )
        # Drop the per-section placeholder list — there are none.
        components[1] = column("root", ["title", "subtitle", "summary"])
    else:
        components.append(
            text(
                "summary",
                f"{len(receipts)} recorded actions across {len(grouped)} categories.",
                "body",
            )
        )
        for cat, rows in grouped.items():
            head_id = f"section-{cat}-h"
            list_id = f"section-{cat}-list"
            section_id = f"section-{cat}"
            section_label = _ARP_CATEGORY_DISPLAY.get(cat, cat.replace("_", " ").title())
            section_text = f"{section_label} ({len(rows)})"
            items: list[str] = []
            for r in rows:
                summary = r.get("human_summary") or "(no summary)"
                amount_label = _money_label(r.get("amount_currency"), r.get("amount_cents"))
                line = f"• {summary}" + (f"  {amount_label}" if amount_label else "")
                items.append(line)
            components.append(card(section_id, head_id))
            components.append(column(head_id, [f"section-{cat}-title", list_id]))
            components.append(text(f"section-{cat}-title", section_text, "h3"))
            components.append(text(list_id, "\n".join(items), "body"))

    # Tail placeholder so the column reference doesn't dangle.
    components.append(text("empty", "", "body"))

    return surface("today", components, "c")


async def build_chronicle_surface(target: str | None = None) -> dict:
    """The agent's public Chronicle. Gated by agents.config.chronicle_public
    on the target. Shows recent first-person daily entries with the
    deterministic stats card.

    ``target`` is the agent_id (chapter handle) of the agent whose
    Chronicle is being viewed. Anyone can hit this surface; the
    visibility check happens here.
    """
    import chronicle as chronicle_mod
    import sovereign_identity

    if not target:
        return surface(
            "chronicle-missing-target",
            [
                card("c", "root"),
                column("root", ["title", "msg"]),
                text("title", "Chronicle", "h2"),
                text("msg", "Provide ?target=<agent_id> to view a Chronicle.", "body"),
            ],
            "c",
        )

    is_public = await chronicle_mod.is_chronicle_public(target)
    if not is_public:
        return surface(
            "chronicle-private",
            [
                card("c", "root"),
                column("root", ["title", "msg", "hint"]),
                text("title", "This Chronicle is private", "h2"),
                text(
                    "msg",
                    f"@{target} has not made their Chronicle public.",
                    "body",
                ),
                text(
                    "hint",
                    "If this is your agent, toggle ‘Chronicle public’ in your settings to share your daily summary.",
                    "body",
                ),
            ],
            "c",
        )

    # Resolve did:key for the target so we can fetch chronicles.
    try:
        import auth_verify

        stored = auth_verify._agent_keys.get(target, {}) if hasattr(auth_verify, "_agent_keys") else {}
        pubkey = stored.get("ed25519_pubkey") or ""
        principal_did = sovereign_identity.build_did_key_from_ed25519(pubkey) if pubkey else ""
    except Exception:  # noqa: BLE001 — surface must never raise
        principal_did = ""

    chronicles = await chronicle_mod.list_chronicles(principal_did, limit=14) if principal_did else []

    target_row = (
        await pg_request(
            "GET",
            "agents",
            params={"agent_id": f"eq.{target}", "select": "name,description", "limit": "1"},
        )
        if pg_request is not None
        else []
    )
    target_name = (target_row[0].get("name") if target_row else target) or target

    components: list[dict] = [
        card("c", "root"),
        column(
            "root",
            ["title", "subtitle", *[f"entry-{i}" for i in range(len(chronicles))]],
        ),
        text("title", f"{target_name}'s Chronicle", "h1"),
        text(
            "subtitle",
            f"@{target} · {len(chronicles)} day{'s' if len(chronicles) != 1 else ''} of entries",
            "body",
        ),
    ]

    if not chronicles:
        # Override the column children list to drop the (empty) entry refs.
        components[1] = column("root", ["title", "subtitle", "empty"])
        components.append(
            text(
                "empty",
                "No Chronicle entries yet — the agent will publish one at the end of each day.",
                "body",
            )
        )
        return surface("chronicle", components, "c")

    for i, entry in enumerate(chronicles):
        entry_id = f"entry-{i}"
        head_id = f"{entry_id}-h"
        narrative_id = f"{entry_id}-narr"
        stats_id = f"{entry_id}-stats"
        components.append(card(entry_id, head_id))
        components.append(column(head_id, [f"{entry_id}-date", narrative_id, stats_id]))
        components.append(text(f"{entry_id}-date", str(entry.get("chronicle_date", "?")), "h3"))
        components.append(text(narrative_id, str(entry.get("narrative") or ""), "body"))
        stats = entry.get("stats") or {}
        by_cat = stats.get("by_category") or {}
        cat_summary = ", ".join(f"{_ARP_CATEGORY_DISPLAY.get(c, c)}: {n}" for c, n in by_cat.items() if n)
        components.append(text(stats_id, cat_summary or "no recorded actions", "caption"))

    return surface("chronicle", components, "c")


def _corroboration_section(facet: dict) -> tuple[list[str], list[dict]]:
    """A2UI 'Corroborated standing' block from a nanda-rep/0.2 verifiable_receipts
    facet (spec/vrp/0.3 §C): the counterparty-corroborated reputation + corroboration
    rate. Returns ``([], [])`` when the member has no receipts (no facet to show), so
    the caller renders nothing rather than an empty card.

    Pure (takes the facet, returns A2UI nodes) so the surface wiring is testable
    without standing up the Issuer Log.
    """
    if not facet.get("behavioral_merkle_root"):
        return [], []
    rep = facet.get("reputation_score") or 0.0
    corr = facet.get("corroboration_rate") or 0.0
    count = facet.get("receipt_count") or 0
    sections = ["pf-rep-label", "pf-rep-card", "pf-rep-caption"]
    components = [
        text("pf-rep-label", "Corroborated standing", "h2"),
        metric("pf-rep-score", f"{rep:g}", "Corroborated reputation"),
        metric("pf-rep-corr", f"{round(corr * 100)}%", "Corroboration rate"),
        metric("pf-rep-count", str(count), "Receipts"),
        row("pf-rep-card", ["pf-rep-score", "pf-rep-corr", "pf-rep-count"]),
        text(
            "pf-rep-caption",
            "Reputation built only from receipts a counterparty co-signed (nanda-rep/0.2).",
            "caption",
        ),
    ]
    return sections, components


async def build_profile_surface(target: str | None = None) -> dict:
    """Per-agent profile — chapter-driven READ.

    ``target`` is the agent_id (chapter handle, not Postgres UUID).
    Pulls the profile row from Postgres by agent_id → profile_id
    and decorates with chapter-owned facts (trust tier, skills the
    agent has learned). Renders:

      - MemberCard header (name / agent_id / role / skills / bio)
      - Trust-tier Card with link out to /page/trust for the full
        ladder + earn history
      - Recent contributions Timeline (agent thoughts / events /
        intents the user authored, when available)
      - "Edit profile" Link to /profile/edit (the static React
        editor sheet — different write path per identity tier)

    Edit path is intentionally NOT in this surface; see the
    Stage-3 design notes in nanda_a2ui_overhaul memory.
    """
    agent_id_raw = (target or "").strip()
    sections: list[str] = ["pf-title"]
    components: list[dict] = []

    if not agent_id_raw:
        components.append(text("pf-title", "Profile", "h1"))
        sections.append("pf-empty")
        components.append(
            callout(
                "pf-empty",
                "Add ?target=<agent_id> to the URL, or click your name in the sidebar.",
                variant="info",
                title="No profile selected",
            )
        )
        components.append(column("root", sections))
        components.append(card("page", "root"))
        return surface("surface-profile", components, "page")

    safe_id = agent_id_raw.replace("/", "").replace("@", "")[:128]

    # Fetch the agents row (server-side member metadata) by agent_id.
    agent_rows: list[dict] | None = None
    if pg_request is not None:
        try:
            agent_rows = await pg_request(
                "GET",
                "agents",
                params={
                    "agent_id": f"eq.{safe_id}",
                    "select": "agent_id,profile_id,name,description,skills,interests,profile_type,trust_score,github_data,linkedin_url",
                    "limit": "1",
                },
            )
        except Exception:
            agent_rows = None

    agent_row = agent_rows[0] if agent_rows else None

    # Fetch the profiles row (user-account fields) when we have a
    # profile_id mapping. Best-effort — the surface still renders if
    # the join fails.
    profile_row: dict | None = None
    if agent_row and agent_row.get("profile_id") and pg_request is not None:
        try:
            profile_rows = await pg_request(
                "GET",
                "profiles",
                params={
                    "id": f"eq.{agent_row['profile_id']}",
                    "select": "full_name,bio,avatar_url,title,company,location,is_public",
                    "limit": "1",
                },
            )
            profile_row = (profile_rows or [None])[0]
        except Exception:
            profile_row = None

    # ⚠️ CONSULT is_public — it was SELECTED AND NEVER READ. Every account field below (full_name, bio, avatar_url, title,
    # company, location) was composed into this surface regardless of the flag,
    # and this surface is one of the deliberately-open per-agent pages: a
    # shareable URL that needs no account. So a member who set is_public=false
    # had their name, title, company and LOCATION published anyway.
    #
    # A control that is queried and ignored is worse than one that is missing:
    # the column appearing in the select list reads like it is being honoured.
    # Same shape as jurisdiction.py's reads and the dead scheduler
    # — present, wired, inert.
    #
    # Fail closed on absence. `profiles.is_public` is `boolean DEFAULT true NOT
    # NULL` (infra/init.sql), and this query selects it explicitly, so a row that
    # reaches here without the key came from somewhere unexpected — and the safe
    # reading of an unexpected state for a privacy flag is "do not publish".
    # The schema already agrees with the intent: init.sql's public profile view
    # filters `is_public = true AND approved = true`.
    profile_is_public = bool((profile_row or {}).get("is_public")) if profile_row else False
    account_row = profile_row if profile_is_public else None

    # Compose display values, preferring profile fields over agent — but only the
    # ones the member agreed to publish. The agent row's own name/description are
    # what they supplied at registration and are published elsewhere already, so
    # they remain the fallback rather than the surface going blank.
    name = (account_row or {}).get("full_name") or (agent_row or {}).get("name") or safe_id
    bio = (account_row or {}).get("bio") or (agent_row or {}).get("description") or ""
    role = (agent_row or {}).get("profile_type") or "member"
    skills = list((agent_row or {}).get("skills") or [])[:8]
    avatar_url = (account_row or {}).get("avatar_url") or ""
    trust_score = (agent_row or {}).get("trust_score")

    title = (account_row or {}).get("title") or ""
    company = (account_row or {}).get("company") or ""
    location = (account_row or {}).get("location") or ""
    subtitle_parts = [p for p in (title, company, location) if p]
    subtitle = " · ".join(subtitle_parts)

    # Header MemberCard.
    components.append(text("pf-title", name, "h1"))

    components.append(
        member_card(
            "pf-header",
            name=name,
            agent_id=safe_id,
            avatar_url=avatar_url,
            role=role,
            trust_score=float(trust_score) if isinstance(trust_score, (int, float)) else None,
            skills=skills,
            subtitle=subtitle or bio[:120],
        )
    )
    sections.append("pf-header")

    if bio and bio not in (subtitle or ""):
        sections.append("pf-bio-label")
        sections.append("pf-bio")
        components.append(text("pf-bio-label", "About", "h2"))
        components.append(text("pf-bio", bio, "body"))

    # Trust + tier — link to the existing /page/trust surface
    # rather than duplicating its content here.
    sections.append("pf-trust-label")
    components.append(text("pf-trust-label", "Trust + Tier", "h2"))
    if isinstance(trust_score, (int, float)):
        sections.append("pf-trust-card")
        components.extend(
            [
                metric(
                    "pf-trust-score",
                    str(int(trust_score)),
                    "Trust score",
                ),
                row("pf-trust-card", ["pf-trust-score", "pf-trust-link"]),
                link(
                    "pf-trust-link",
                    "See your tier ladder →",
                    f"/page/trust?target={safe_id}",
                ),
            ]
        )
    else:
        sections.append("pf-trust-empty")
        components.append(
            text(
                "pf-trust-empty",
                "Trust score not yet computed for this member.",
                "caption",
            )
        )

    # Corroborated standing — the counterparty-corroborated nanda-rep/0.2 score
    # (spec/vrp/0.3 §C), shown alongside the legacy trust score. Augmentation:
    # never wedge the profile, but LOUD on failure (not silent) so a real
    # scoring/Issuer-Log fault is observable rather than masquerading as "no standing".
    try:
        import arp as _arp_mod
        import vrp as _vrp_mod

        _principal_did = _arp_mod.did_key_for_member(safe_id)
        if _principal_did:
            _, _rep_facet = await _vrp_mod.build_principal_ledger(_principal_did, ledger_uri="", method="nanda-rep/0.2")
            _rep_sections, _rep_components = _corroboration_section(_rep_facet)
            sections.extend(_rep_sections)
            components.extend(_rep_components)
    except Exception as e:  # noqa: BLE001 — augmentation must not wedge the profile
        print(f"[vrp] profile corroboration section failed for {safe_id}: {e}")

    # Recent contributions — pull from agent_thoughts. Best-effort.
    recent_entries: list[dict] = []
    if pg_request is not None:
        try:
            thoughts = await pg_request(
                "GET",
                "agent_thoughts",
                params={
                    "agent_id": f"eq.{safe_id}",
                    "order": "created_at.desc",
                    "limit": "5",
                    "select": "thought,thought_type,created_at",
                },
            )
            for t in thoughts or []:
                created = t.get("created_at", "")[:10]
                recent_entries.append(
                    {
                        "timestamp": created or "—",
                        "title": (t.get("thought_type") or "thought").replace("_", " "),
                        "body": (t.get("thought") or "")[:200],
                    }
                )
        except Exception:
            recent_entries = []

    if recent_entries:
        sections.append("pf-recent-label")
        sections.append("pf-recent")
        components.append(text("pf-recent-label", "Recent activity", "h2"))
        components.append(timeline("pf-recent", recent_entries))
    elif agent_row is not None:
        sections.append("pf-recent-empty")
        components.append(
            text(
                "pf-recent-empty",
                "No recent agent activity.",
                "caption",
            )
        )

    # Edit link — only an indication; the editor at /profile/edit
    # owns the actual write path (different per identity tier).
    sections.append("pf-edit")
    components.append(link("pf-edit", "Edit profile (Postgres Auth)", "/profile/edit"))

    if not agent_row:
        sections.insert(1, "pf-missing")
        components.append(
            callout(
                "pf-missing",
                f"No agent registered for {safe_id}. The profile shown is best-effort.",
                variant="warning",
                title="Agent not found in org registry",
            )
        )

    components.append(column("root", sections))
    components.append(card("page", "root"))
    return surface(f"surface-profile:{safe_id[:40]}", components, "page")


# ── Reputation surface ────────────────────────────────────────────

# The reputation surface always renders the COUNTERPARTY-CORROBORATED score
# (nanda-rep/0.2, spec/vrp/0.3 §C) regardless of the server's PUBLISHED default
# (vrp.DEFAULT_SCORING_METHOD). The point of this page is to show standing built
# only from receipts a counterparty co-signed — the self-attested 0.1 score is
# the legacy trust dossier's job (/page/trust).
_REPUTATION_METHOD = "nanda-rep/0.2"

# Cap how many members we fan out ledger builds for when assembling the
# leaderboard. Each entry is one Issuer-Log read + a Merkle/scoring pass; we run
# them concurrently (asyncio.gather) but still bound the fan-out so a large
# server can't turn one surface hit into hundreds of DB round-trips. Members
# past the cap simply don't appear in the leaderboard (their own /page/reputation
# still renders their full standing).
_REPUTATION_LEADERBOARD_FANOUT = 60
_REPUTATION_LEADERBOARD_SHOWN = 10


async def _principal_standing(did: str, label: str, method: str) -> dict | None:
    """Resolve one principal's corroborated standing for the leaderboard, or None.

    Keyed by ``did`` (the principals come from the Issuer Log, which is keyed by
    principal_did — not every receipt-bearing principal is in the in-memory member
    roster). ``label`` is the display string (``@agent_id`` when the did maps to a
    roster member, else a short did). Returns None (skip the row) when the
    principal has no receipts. Best-effort: a scoring fault for one principal must
    not sink the whole board.
    """
    import vrp as _vrp_mod

    try:
        _ledger, facet = await _vrp_mod.build_principal_ledger(did, ledger_uri="", method=method)
    except Exception as e:  # noqa: BLE001 — one bad principal must not sink the board
        print(f"[vrp] leaderboard standing failed for {did[:24]}: {e}")
        return None
    if not facet.get("behavioral_merkle_root"):
        return None  # no receipts → no rankable standing
    return {
        "did": did,
        "label": label,
        "score": float(facet.get("reputation_score") or 0.0),
        "corr": float(facet.get("corroboration_rate") or 0.0),
        "count": int(facet.get("receipt_count") or 0),
    }


def _short_did(did: str) -> str:
    """Compact label for a did:key with no roster mapping — keep the discriminator
    tail so distinct principals stay visually distinct."""
    return f"{did[:14]}…{did[-6:]}" if len(did) > 24 else did


async def build_reputation_surface(target: str | None = None) -> dict:
    """Per-member corroborated reputation + a chapter leaderboard.

    ``target`` is the agent_id whose standing to feature (defaults to the
    chapter's own agent_id, matching /page/trust). Renders, top to bottom:

      1. The subject's corroborated standing — nanda-rep/0.2 score,
         corroboration rate, receipt count (the same ``_corroboration_section``
         block the profile uses, so the two never disagree).
      2. The subject's recent receipts, each flagged corroborated / self-attested
         via the authoritative ``sm_arp.vrp.is_corroborated``.
      3. A leaderboard of members ranked by corroborated reputation.

    This is the first surface that makes the VRP layer visible in the portal:
    before it, corroboration only showed as one (easily-missed) section on a
    profile. Always uncached + per-target (see _UNCACHED_SURFACES).
    """
    import asyncio

    from sm_arp.vrp import is_corroborated

    import arp as _arp_mod
    import vrp as _vrp_mod

    subject_id = (target or AGENT_ID or "").strip()
    safe_id = subject_id.replace("/", "").replace("@", "")[:128]

    sections: list[str] = ["rep-title", "rep-subtitle"]
    components: list[dict] = [
        text("rep-title", "Reputation", "h1"),
        text(
            "rep-subtitle",
            f"Corroborated standing for @{safe_id} — built only from receipts a counterparty co-signed."
            if safe_id
            else "Corroborated standing — built only from receipts a counterparty co-signed.",
            "caption",
        ),
    ]

    # 1. Subject standing — reuse the profile's corroboration block so the two
    #    surfaces can never show a different score for the same member. Resolve the
    #    did durably (in-memory key store, falling back to the persisted pubkey) so
    #    standing renders even right after a restart.
    subject_did = await _arp_mod.resolve_member_did(safe_id) if safe_id else ""
    subject_receipts: list[dict] = []
    if subject_did:
        try:
            _ledger, facet = await _vrp_mod.build_principal_ledger(
                subject_did, ledger_uri="", method=_REPUTATION_METHOD
            )
            rep_sections, rep_components = _corroboration_section(facet)
            sections.extend(rep_sections)
            components.extend(rep_components)
            if not rep_sections:
                sections.append("rep-none")
                components.append(
                    callout(
                        "rep-none",
                        "No receipts yet. Standing appears once your agent records actions and a "
                        "counterparty co-signs them.",
                        variant="info",
                        title="No corroborated standing yet",
                    )
                )
            else:
                subject_receipts = await _arp_mod.list_for_principal(subject_did, limit=25)
        except Exception as e:  # noqa: BLE001 — surface must never raise
            print(f"[vrp] reputation standing failed for {safe_id}: {e}")
            sections.append("rep-err")
            components.append(
                callout(
                    "rep-err",
                    "Standing is temporarily unavailable — the reputation service did not respond.",
                    variant="warning",
                    title="Couldn't load standing",
                )
            )
    else:
        sections.append("rep-noid")
        components.append(
            callout(
                "rep-noid",
                f"@{safe_id} has no signing key on file yet, so no receipts can be attributed to them."
                if safe_id
                else "Add ?target=<agent_id> to view a member's standing.",
                variant="info",
                title="No identity on file",
            )
        )

    # 2. Recent receipts with corroboration flags.
    if subject_receipts:
        sections.append("rep-receipts-label")
        components.append(text("rep-receipts-label", "Recent receipts", "h2"))
        rows: list[list[str]] = []
        for r in subject_receipts:
            action = r.get("action") or {}
            when = (r.get("issued_at") or "")[:10]
            category = _ARP_CATEGORY_DISPLAY.get(
                action.get("category") or "", (action.get("category") or "—").replace("_", " ").title()
            )
            summary = (action.get("human_summary") or "")[:80]
            flag = "✓ corroborated" if is_corroborated(r) else "self-attested"
            rows.append([when or "—", category, summary or "—", flag])
        sections.append("rep-receipts")
        components.append(
            table(
                "rep-receipts",
                ["Date", "Action", "Summary", "Standing"],
                rows,
                caption=f"{len(rows)} most recent receipt(s).",
            )
        )

    # 3. Leaderboard — principals ranked by corroborated reputation. Source is
    #    the Issuer Log (principals that actually have receipts), NOT the member
    #    roster: a roster member with zero receipts has nothing to rank, and a
    #    receipt-bearing principal may not be in the roster at all. Display label
    #    is @agent_id when the did maps to a roster member, else a short did. Fan
    #    out the per-principal ledger builds concurrently, bounded by _..._FANOUT.
    sections.append("rep-board-label")
    components.append(text("rep-board-label", "Server leaderboard", "h2"))
    did_to_label: dict[str, str] = {}
    for mid in members or {}:
        if mid.startswith("STARTUP-"):
            continue
        mdid = _arp_mod.did_key_for_member(mid)
        if mdid:
            did_to_label[mdid] = f"@{mid}"
    principals = await _arp_mod.list_principals_with_receipts(limit=_REPUTATION_LEADERBOARD_FANOUT)
    standings: list[dict] = []
    if principals:
        results = await asyncio.gather(
            *[
                _principal_standing(did, did_to_label.get(did, _short_did(did)), _REPUTATION_METHOD)
                for did in principals
            ]
        )
        standings = [s for s in results if s]
    standings.sort(key=lambda s: (s["score"], s["count"]), reverse=True)

    if not standings:
        sections.append("rep-board-empty")
        components.append(
            text(
                "rep-board-empty",
                "No member has corroborated receipts yet — the leaderboard fills in as co-signing accrues.",
                "body",
            )
        )
    else:
        board_rows = [
            [
                str(i + 1),
                s["label"],
                f"{s['score']:g}",
                f"{round(s['corr'] * 100)}%",
                str(s["count"]),
            ]
            for i, s in enumerate(standings[:_REPUTATION_LEADERBOARD_SHOWN])
        ]
        sections.append("rep-board")
        components.append(
            table(
                "rep-board",
                ["#", "Member", "Score", "Corroboration", "Receipts"],
                board_rows,
                caption=f"Top {len(board_rows)} by corroborated reputation (nanda-rep/0.2).",
            )
        )

    components.append(column("root", sections))
    components.append(card("page", "root"))
    return surface(f"surface-reputation:{safe_id[:40]}", components, "page")


# ── Broadcasts surface ────────────────────────────────────────────


async def build_broadcasts_surface(target: str | None = None) -> dict:
    """A2UI surface for /page/broadcasts — recent chapter broadcasts.

    Renders each broadcast as a collapsible accordion section so a
    leader can drill into title → body → per-peer delivery without
    leaving the page. Data sources joined by broadcast_id:

      * ``event_log``       — canonical event (title, body, tags,
                              audience, sender, origin) for any
                              ``chapter.broadcast`` published BY this
                              chapter.
      * ``broadcast_log``   — send-side delivery audit (peer counts +
                              failed peers' reasons).

    No mutation surface here — broadcasts originate from
    ``POST /api/broadcast`` or the ``think_chapter_broadcast`` cycle;
    this page is read-only audit.
    """
    # Source of truth for body: event_log. broadcast_log only adds
    # delivery stats. Joining in Python is cheaper than a Postgres JOIN
    # via PostgREST (no FK constraint between the two tables today).
    events = await _pg()(
        "GET",
        "event_log",
        params={
            "event_type": "eq.chapter.broadcast",
            "publisher_agent_id": f"eq.{AGENT_ID}",
            "order": "id.desc",
            "limit": "50",
        },
    )
    stats_rows = await _pg()(
        "GET",
        "broadcast_log",
        params={
            "chapter_id": f"eq.{AGENT_ID}",
            "order": "sent_at.desc",
            "limit": "200",
        },
    )
    stats_by_id: dict[str, dict] = {(r.get("broadcast_id") or ""): r for r in (stats_rows or [])}

    components: list = []
    sections: list[str] = ["bcst-title", "bcst-subtitle"]
    components.append(heading("bcst-title", 1, "Server Broadcasts"))
    components.append(
        text(
            "bcst-subtitle",
            f"Last 50 broadcasts sent by {AGENT_NAME or AGENT_ID}. "
            "Click a row to expand the full body and per-peer delivery.",
            "body",
        )
    )

    if not events:
        sections.append("bcst-empty")
        components.append(
            callout(
                "bcst-empty",
                "No broadcasts have been sent yet. Trigger one via "
                "``POST /api/broadcast`` or enable the autonomous "
                "``chapter_broadcast.enabled`` policy key for the "
                "weekly-digest auto-fanout.",
                variant="info",
                title="No broadcasts yet",
            )
        )
    else:
        # Summary stats — derived from broadcast_log so leaders see
        # delivery quality, not just publish count.
        total = len(stats_rows or [])
        succ = sum(int(r.get("succeeded") or 0) for r in (stats_rows or []))
        fail = sum(int(r.get("failed") or 0) for r in (stats_rows or []))
        sections.append("bcst-stats")
        components.append(
            stat_group(
                "bcst-stats",
                [
                    {"label": "Recent broadcasts", "value": str(total)},
                    {"label": "Peers reached", "value": str(succ)},
                    {"label": "Peer failures", "value": str(fail)},
                ],
            )
        )

        # Accordion — one section per broadcast. Section title is the
        # one-line summary; the expanded child shows body + audit.
        accordion_sections: list[dict] = []
        for i, evt in enumerate(events):
            payload = evt.get("payload") or {}
            bid = payload.get("broadcast_id") or ""
            title_str = (payload.get("title") or "(untitled)")[:120]
            body_str = payload.get("body") or "(empty)"
            sender = payload.get("sender_agent_id") or "?"
            origin = payload.get("origin_chapter_id") or "?"
            audience = payload.get("audience") or "?"
            tags = payload.get("tags") or []
            sent_at = (evt.get("created_at") or "")[:19].replace("T", " ")

            stat_row = stats_by_id.get(bid, {})
            ok = int(stat_row.get("succeeded") or 0)
            total_peers = int(stat_row.get("total_peers") or 0)
            failed_n = int(stat_row.get("failed") or 0)
            peer_results = stat_row.get("peer_results") or []
            status_label = (
                "OK" if total_peers > 0 and ok == total_peers else ("Local only" if total_peers == 0 else "Partial")
            )

            # The expanded body for this broadcast — laid out as a Column.
            child_id = f"bcst-detail-{i}"
            child_children: list[str] = []

            # Body
            components.append(text(f"{child_id}-body", body_str, "body"))
            child_children.append(f"{child_id}-body")

            # Quick stat row inside the accordion
            components.append(
                stat_group(
                    f"{child_id}-stats",
                    [
                        {"label": "Audience", "value": audience},
                        {"label": "Sent", "value": sent_at},
                        {"label": "Peers ok", "value": f"{ok} / {total_peers}"},
                        {"label": "Status", "value": status_label},
                    ],
                )
            )
            child_children.append(f"{child_id}-stats")

            # Sender + origin + broadcast_id (audit detail)
            audit_md = (
                f"**Sender:** `{sender}`  \n"
                f"**Origin chapter:** `{origin}`  \n"
                f"**Broadcast ID:** `{bid}`  \n"
                f"**Event ID:** `{evt.get('id')}`"
            )
            components.append(markdown(f"{child_id}-audit", audit_md))
            child_children.append(f"{child_id}-audit")

            # Tags as chips, only if any.
            if tags:
                components.append(
                    chip_group(
                        f"{child_id}-tags",
                        [{"label": str(t)} for t in tags[:20]],
                    )
                )
                child_children.append(f"{child_id}-tags")

            # Failed-peer details (only when any peers failed).
            if failed_n and peer_results:
                components.append(heading(f"{child_id}-fail-h", 3, "Failed peers"))
                child_children.append(f"{child_id}-fail-h")
                fail_rows = [
                    [
                        str(pr.get("peer_id") or "?"),
                        str(pr.get("reason") or "?"),
                    ]
                    for pr in peer_results[:20]
                ]
                components.append(table(f"{child_id}-fail-tbl", ["Peer", "Reason"], fail_rows))
                child_children.append(f"{child_id}-fail-tbl")

            # Wrap children in a Column so the accordion section
            # references one component.
            components.append(column(f"{child_id}-col", child_children))

            section_title = f"{title_str}  —  {sent_at}  ({status_label})"
            accordion_sections.append(
                {
                    "title": section_title,
                    "childId": f"{child_id}-col",
                    # First entry expanded so the page isn't empty on first load.
                    "defaultOpen": (i == 0),
                }
            )

        sections.append("bcst-accordion")
        components.append(accordion("bcst-accordion", accordion_sections))

    components.insert(0, column("root", sections))
    return surface("surface-broadcasts", [card("page", "root")] + components, "page")


# ── Subscriptions surface ─────────────────────────────────────────


async def build_subscriptions_surface(target: str | None = None) -> dict:
    """A2UI surface for /page/subscriptions — event-bus subscription
    overview + recent event activity, both drill-throughable.

    Two accordions: subscriptions (one section per active subscriber)
    and recent events (one section per event_log row, with the full
    payload markdown-rendered on expand).

    ``target`` (optional) scopes the subscription list to one
    subscriber agent_id. Without it we show all active subscriptions
    on this chapter so the operator sees the topology.

    Read-only: no subscribe form here — that goes through
    ``POST /api/subscriptions`` with a signed body.
    """
    # The DB table is ``event_subscriptions`` (per migration
    # 20260510_event_bus_subscriptions.sql) — the REST endpoint
    # ``/api/subscriptions`` is the operator-facing name, not the
    # table name.
    sub_params: dict = {
        "order": "created_at.desc",
        "limit": "200",
    }
    if target:
        sub_params["subscriber_agent_id"] = f"eq.{target}"
    subs = await _pg()("GET", "event_subscriptions", params=sub_params)

    # Pull the full event payload so expansion can show it. event_log
    # rows are bounded by the LIMIT; we keep it tight (last 20) since
    # each payload may be a few KB.
    events = await _pg()(
        "GET",
        "event_log",
        params={
            "order": "id.desc",
            "limit": "20",
        },
    )

    components: list = []
    sections: list[str] = ["sub-title", "sub-subtitle"]
    components.append(heading("sub-title", 1, "Event Bus Subscriptions"))
    components.append(
        text(
            "sub-subtitle",
            "Active subscriptions on this org's event bus. The bus "
            "publishes typed events (member.joined, intent.published, "
            "chapter.broadcast, …) and subscribers receive a filtered "
            "stream via Server-Sent Events at "
            "``/api/subscriptions/{id}/stream``. Click any row to expand "
            "its detail.",
            "body",
        )
    )

    # ── Subscriptions accordion ────────────────────────────────────
    from collections import Counter

    if subs:
        by_type: Counter[str] = Counter()
        for s in subs:
            topics_raw = s.get("topics") or s.get("event_types") or []
            if isinstance(topics_raw, str):
                topics_raw = [topics_raw]
            for t in topics_raw:
                by_type[t] += 1

        sections.append("sub-stats")
        components.append(
            stat_group(
                "sub-stats",
                [
                    {"label": "Active subscriptions", "value": str(len(subs))},
                    {"label": "Distinct event types", "value": str(len(by_type))},
                ],
            )
        )

        sub_sections: list[dict] = []
        for i, s in enumerate(subs):
            sid = f"sub-detail-{i}"
            subscriber = s.get("subscriber_agent_id") or "?"
            did = s.get("subscriber_did_key") or "?"
            topics = s.get("topics") or []
            if isinstance(topics, str):
                topics = [topics]
            delivery = s.get("delivery") or "stream"
            webhook = s.get("webhook_url") or ""
            filters = s.get("filters") or {}
            created = (s.get("created_at") or "")[:19].replace("T", " ")
            expires = (s.get("expires_at") or "")[:19].replace("T", " ")
            active = bool(s.get("active"))
            sub_id = s.get("id") or ""

            children: list[str] = []

            # Subscriber identity + status as markdown audit
            audit_md = (
                f"**Subscriber:** `{subscriber}`  \n"
                f"**did:key:** `{did}`  \n"
                f"**Subscription ID:** `{sub_id}`  \n"
                f"**Active:** {'yes' if active else 'no'}  \n"
                f"**Created:** {created}  \n"
                f"**Expires:** {expires}  \n"
                f"**Delivery:** `{delivery}`" + (f"  \n**Webhook URL:** `{webhook}`" if webhook else "")
            )
            components.append(markdown(f"{sid}-audit", audit_md))
            children.append(f"{sid}-audit")

            # Topics as chips
            if topics:
                components.append(text(f"{sid}-topics-h", "Topics subscribed:", "caption"))
                children.append(f"{sid}-topics-h")
                components.append(
                    chip_group(
                        f"{sid}-topics",
                        [{"label": str(t)} for t in topics],
                    )
                )
                children.append(f"{sid}-topics")

            # Filters JSON (only if non-empty)
            if filters:
                components.append(
                    code_block(
                        f"{sid}-filters",
                        json.dumps(filters, indent=2),
                        language="json",
                        caption="Server-side filter (applied before SSE delivery)",
                    )
                )
                children.append(f"{sid}-filters")

            components.append(column(f"{sid}-col", children))

            status_marker = "🟢" if active else "⚫"
            section_title = (
                f"{status_marker} {subscriber}  —  {len(topics)} topic{'s' if len(topics) != 1 else ''}  ({delivery})"
            )
            sub_sections.append(
                {
                    "title": section_title,
                    "childId": f"{sid}-col",
                    "defaultOpen": (i == 0),
                }
            )

        sections.append("sub-accordion")
        components.append(accordion("sub-accordion", sub_sections))
    else:
        sections.append("sub-empty")
        components.append(
            callout(
                "sub-empty",
                "No active subscriptions yet. Subscribe via "
                "``POST /api/subscriptions`` with a signed body listing "
                "the event types you want. SSE delivery starts on "
                "``/api/subscriptions/{id}/stream``.",
                variant="info",
                title="No subscriptions",
            )
        )

    # ── Recent events accordion ────────────────────────────────────
    sections.append("sub-recent-title")
    components.append(heading("sub-recent-title", 2, "Recent events on the bus"))

    if not events:
        sections.append("sub-recent-empty")
        components.append(text("sub-recent-empty", "No events yet.", "body"))
    else:
        event_sections: list[dict] = []
        for i, e in enumerate(events):
            eid = f"evt-detail-{i}"
            ev_type = e.get("event_type") or "?"
            publisher = e.get("publisher_agent_id") or "?"
            when = (e.get("created_at") or "")[:19].replace("T", " ")
            payload = e.get("payload") or {}

            # Full payload as JSON
            components.append(
                code_block(
                    f"{eid}-payload",
                    json.dumps(payload, indent=2)[:4000],
                    language="json",
                    caption=f"Event #{e.get('id')} payload",
                )
            )

            event_sections.append(
                {
                    "title": f"#{e.get('id')}  ·  {ev_type}  ·  {publisher[:30]}  ·  {when}",
                    "childId": f"{eid}-payload",
                    "defaultOpen": (i == 0),
                }
            )

        sections.append("sub-recent-accordion")
        components.append(accordion("sub-recent-accordion", event_sections))

    components.insert(0, column("root", sections))
    return surface("surface-subscriptions", [card("page", "root")] + components, "page")


SURFACE_BUILDERS: dict[str, Callable[..., Any]] = {
    "dashboard": build_dashboard_surface,
    "members": build_members_surface,
    "events": build_events_surface,
    "calendar": build_calendar_surface,
    "groups": build_groups_surface,
    "activity": build_activity_surface,
    "messages": build_messages_surface,
    "digest": build_digest_surface,
    "chapter": build_chapter_surface,
    "knowledge": build_knowledge_surface,
    "federation": build_federation_knowledge_surface,
    "intents": build_intents_surface,
    "outcomes": build_outcomes_surface,
    "conversations": build_conversations_surface,
    "admin": build_admin_surface,
    "approvals": build_approvals_surface,
    "policy": build_policy_surface,
    "audit": build_audit_surface,
    "authority": build_authority_surface,
    "skills": build_skills_surface,
    "skill_detail": build_skill_detail_surface,
    "skill_publish": build_skill_publish_surface,
    "marketplace": build_marketplace_surface,
    "onboarding": build_onboarding_surface,
    "settings": build_settings_surface,
    "voice": build_voice_surface,
    "channels": build_channels_surface,
    "mesh": build_mesh_surface,
    "docs": build_docs_surface,
    "chapter-security": build_chapter_security_surface,
    "advisor-earnings": build_advisor_earnings_surface,
    "skill_attest": build_skill_attest_surface,
    "trust": build_trust_surface,
    "endorsements": build_endorsements_surface,
    # Stage-2 portal migration: server surfaces for routes that
    # were previously hand-written React (or in /agents-directory's
    # case, broken — fetched a 404 endpoint).
    "directory": build_directory_surface,
    "search": build_search_surface,
    "profile": build_profile_surface,
    # ARP — Agency Receipt Protocol surfaces (spec/arp/0.1/)
    "today": build_today_surface,
    "chronicle": build_chronicle_surface,
    # VRP — counterparty-corroborated reputation (spec/vrp/0.3 §C)
    "reputation": build_reputation_surface,
    # PR4 follow-up: A2UI surfaces for the broadcast + event-bus
    # subscription layer so members can SEE the broadcasts they're
    # receiving and what's flowing through the bus.
    "broadcasts": build_broadcasts_surface,
    "subscriptions": build_subscriptions_surface,
}


# Surfaces that reread DB / federation state on every hit — never cache.
# Everything else gets a short-TTL memoization for snappy portal refreshes.
_UNCACHED_SURFACES = frozenset(
    {
        "onboarding",
        "settings",
        "channels",
        "voice",
        "mesh",
        "docs",  # docs introspects the cache itself — never cache it
        "chapter-security",  # live audit / allowlist / SSO state
        "trust",  # per-agent live, depends on `target` query param
        "endorsements",  # same — per-agent
        # ARP surfaces — per-principal live state, never cache
        "today",
        "chronicle",
        # VRP reputation — per-target live standing + leaderboard, never cache
        "reputation",
        # Audit ledger — operator wants real-time activity counts.
        # Counts change every time a privileged action lands; caching
        # would mask freshly-emitted events for up to 10 s.
        "audit",
        # Approval queue mutates rapidly during active governance work
        # (proposals enqueue/resolve in seconds). A 10s cache would show
        # admins a stale queue and lead to double-clicks on already-
        # resolved items. Never cache.
        "approvals",
        # Authority scope is admin-aware (full detail behind token) — must
        # never cache, or an authed full-detail render could be served to a
        # later anonymous caller. Also per-target (varies by ?target=).
        "authority",
    }
)

# Surfaces that render FULL operator detail only when the request carried a
# valid admin token, and a redacted safe-projection floor otherwise. The
# builders for these accept an ``admin_verified`` kwarg. MUST be a subset of
# _UNCACHED_SURFACES so an authed render is never cached + served to anon.
_ADMIN_AWARE_SURFACES = frozenset({"approvals", "authority"})


# A2UI v0.9 components we know how to downgrade to v0.8 equivalents.
# Everything not listed falls back to a plain Text representation.
_V09_TO_V08_PASSTHROUGH = frozenset(
    {
        "Text",
        "Badge",
        "Progress",
        "Metric",
        "Stat",
        "List",
        "Avatar",
        "Alert",
        "Link",
        "Image",
        "Divider",
        "Grid",
        "Tabs",
        "Card",
        "Column",
        "Row",
        "Input",
        "TextArea",
        "Select",
        "Toggle",
        "ActionButton",
        "Form",
        "Chip",
        "ChipGroup",
        "Toast",
    }
)

# v0.9-only components that have no v0.8 equivalent — downgrade to Text.
_V09_ONLY = frozenset(
    {
        "Markdown",
        "Heading",
        "CodeBlock",
        "Accordion",
        "Table",
        "Callout",
        "TrustBadge",
        "Timeline",
        "MemberCard",
        "StatGroup",
    }
)


# Every A2UI envelope version this module can EMIT. `chapter_agent`'s
# capabilities block advertises exactly this set (a conformance test pins the
# two together — the advertised set and the emittable set drifting apart is
# what the strict-selector rule was); anything else in `?schema=` is refused rather than silently
# answered with a different version (the strict-selector rule's floor).
A2UI_EMITTABLE_VERSIONS = ("0.8", "0.9", "0.10")


class UnsupportedSchemaVersion(ValueError):
    """``?schema=`` named a wire version this chapter cannot emit.

    Raised instead of falling through to the default, because a client that
    asks for a specific version is telling us it cannot handle the others:
    answering with a different one is a silent wrong answer. Callers at
    the HTTP boundary turn this into a 400.
    """

    def __init__(self, requested: str) -> None:
        self.requested = requested
        self.supported = A2UI_EMITTABLE_VERSIONS
        super().__init__(
            f"unsupported A2UI schema version {requested!r}; "
            f"this chapter emits {', '.join(A2UI_EMITTABLE_VERSIONS)}"
        )


def normalize_schema_selector(schema: str | None) -> str | None:
    """``'v0.9'``/``'0.9'`` → ``'0.9'``; None/empty → None (native default).

    Raises ``UnsupportedSchemaVersion`` for anything this chapter cannot emit,
    so an unrecognised selector cannot reach the surface builders and quietly
    receive the default version.
    """
    if schema is None:
        return None
    requested = schema.strip()
    if not requested:
        return None
    normalized = requested.lstrip("vV")
    if normalized not in A2UI_EMITTABLE_VERSIONS:
        raise UnsupportedSchemaVersion(requested)
    return normalized


def strip_meta(surface: dict) -> dict:
    """Return a copy of a v0.10 surface with every ``meta`` block removed.

    Removes the per-component ``meta`` AND the surface-level
    ``createSurface.meta``, whatever their contents — spec/0.4/a2ui.md §10.2
    requires the strip be deep, "an empty ``meta: {}`` is also removed", so the
    result is byte-equivalent to a v0.9-native emission. ``schema/0.3``
    declares ``additionalProperties: false`` on both, so a surviving ``meta``
    would fail v0.9 conformance.

    Never mutates the input: built surfaces are memoised in ``surface_cache``,
    so stripping in place would serve a later NATIVE request the v0.9-flavoured
    surface out of the cache.
    """
    if not isinstance(surface, dict):
        return surface

    out = {k: v for k, v in surface.items() if k != "meta"}

    create = out.get("createSurface")
    if isinstance(create, dict):
        out["createSurface"] = {k: v for k, v in create.items() if k != "meta"}

    upd = out.get("updateComponents")
    if isinstance(upd, dict):
        components = upd.get("components")
        if isinstance(components, list):
            out["updateComponents"] = {
                **upd,
                "components": [
                    {k: v for k, v in c.items() if k != "meta"} if isinstance(c, dict) else c
                    for c in components
                ],
            }
    return out


def to_v09(surface_v010: dict) -> dict:
    """Transform a native v0.10 surface into the v0.9 wire shape.

    The envelope is identical — v0.10 is an additive minor over v0.9 — so the
    whole transform is: drop every ``meta`` block, then say ``0.9``. Requested
    with ``?schema=v0.9`` per spec/0.4/a2ui.md §8 item 3, which a v0.4 chapter
    MUST honour (spec/0.4/protocol.md:15). Before the strict-selector rule the selector was
    accepted and then ignored: callers asking for 0.9 received 0.10.
    """
    if not isinstance(surface_v010, dict):
        return surface_v010
    return {**strip_meta(surface_v010), "version": "0.9"}


def to_v08(surface_v09: dict) -> dict:
    """Transform a v0.9/v0.10 surface dict into v0.8 wire shape.

    Wire-shape diff (from A2UIRenderer.tsx):
      v0.9: {createSurface, updateComponents: {surfaceId, root, components: [{id, component, ...fields}]}, version: '0.9'}
      v0.8: {beginRendering: {root}, surfaceUpdate: {surfaceId, components: [{<Type>: {...fields}, id}]}, version: '0.8'}

    Component shape in v0.8 wraps each payload under a type-name key rather
    than using a flat `component` discriminator. v0.9-only components
    downgrade to Text with a `[component-name: ...]` prefix so OpenClaw's
    Canvas at least shows the content instead of crashing.

    The v0.10 ``meta`` block is stripped from every payload: spec/0.4
    §8 item 4 and the OpenClaw SKILL.md both state a v0.8 response carries no
    ``meta``, and a v0.8 consumer was told not to expect it. Until the strict-selector rule the
    passthrough copied it through verbatim, so live dashboards shipped ``meta``
    on Row and Input against two documented contracts.
    """
    if not isinstance(surface_v09, dict):
        return surface_v09

    upd = surface_v09.get("updateComponents") or {}
    surface_id = upd.get("surfaceId") or surface_v09.get("surfaceId")
    root = upd.get("root") or surface_v09.get("root")
    components_v09 = upd.get("components") or []

    components_v08: list[dict] = []
    for c in components_v09:
        if not isinstance(c, dict):
            continue
        comp_id = c.get("id")
        comp_type = c.get("component")
        if not comp_id or not comp_type:
            continue
        # Copy payload minus the discriminator + id (id stays at top level in
        # v0.8) and minus the v0.10 `meta` block, which v0.8 does not carry.
        payload = {k: v for k, v in c.items() if k not in ("id", "component", "meta")}

        if comp_type in _V09_ONLY:
            # Degrade to Text so OpenClaw Canvas can render *something*
            prefix = f"[{comp_type}] "
            text_val = c.get("text") or c.get("markdown") or c.get("content") or c.get("title") or ""
            components_v08.append(
                {
                    "id": comp_id,
                    "Text": {
                        "text": f"{prefix}{text_val}" if text_val else prefix.strip(),
                        "usageHint": c.get("usageHint", "body"),
                    },
                }
            )
            continue

        if comp_type in _V09_TO_V08_PASSTHROUGH:
            components_v08.append({"id": comp_id, comp_type: payload})
        else:
            # Unknown component — conservative fallback to Text.
            components_v08.append(
                {
                    "id": comp_id,
                    "Text": {
                        "text": f"[{comp_type}]",
                        "usageHint": "caption",
                    },
                }
            )

    result = {
        "beginRendering": {"root": root} if root else {},
        "surfaceUpdate": {
            "surfaceId": surface_id,
            "components": components_v08,
        },
        "version": "0.8",
    }
    return result


async def get_surface(
    page_id: str,
    target: str | None = None,
    schema: str | None = None,
    admin_verified: bool = False,
) -> dict:
    """Get a surface by page_id. Cached surfaces use a 10s TTL memo;
    per-agent surfaces bypass the cache. Missing page_id → friendly
    error surface instead of 500.

    schema: wire-version selector, with or without the leading 'v'.
            '0.8' returns the OpenClaw-compatible envelope, '0.9' the native
            envelope with every `meta` block stripped, '0.10' (or None) the
            native envelope. Any other value raises
            ``UnsupportedSchemaVersion`` — validated BEFORE the surface is
            built, so a bad selector costs no work and cannot be answered with
            a version the caller did not ask for.

    admin_verified: True iff the request carried a valid admin token
            (resolved at the HTTP layer). Admin-aware surfaces
            (_ADMIN_AWARE_SURFACES) embed full operator detail when True
            and the redacted safe-projection floor when False. The
            public/EventSource path always passes False, so the
            unauthenticated experience is unchanged.
    """
    import surface_cache

    # Refuse an unknown selector before doing any work — a rejected request
    # should not cost a surface build, and validating here means every caller
    # (JSON route, SSE route, in-process) gets the same answer.
    normalize_schema_selector(schema)

    builder = SURFACE_BUILDERS.get(page_id)
    if not builder:
        result = surface(
            f"error-{page_id}",
            [
                card("err", "err-root"),
                column("err-root", ["err-title", "err-msg"]),
                text("err-title", f"Page: {page_id}", "h2"),
                text("err-msg", "This surface is not available yet.", "body"),
            ],
            "err",
        )
        return _maybe_downgrade(result, schema)

    is_admin_aware = page_id in _ADMIN_AWARE_SURFACES

    async def _build() -> dict:
        if is_admin_aware:
            return await builder(target, admin_verified=admin_verified)
        return await builder(target)

    if page_id in _UNCACHED_SURFACES:
        # Per-agent or cache-sensitive — record latency but skip cache.
        # Every admin-aware surface is also uncached (asserted below), so
        # an authed full-detail render can never be cached and served to a
        # later anonymous caller.
        import time as _time

        start = _time.monotonic()
        result = await _build()
        surface_cache._record_build(page_id, (_time.monotonic() - start) * 1000.0)
        return _maybe_downgrade(result, schema)

    key = f"{page_id}:{target or ''}"
    hit = surface_cache.get(key)
    if hit is not None:
        surface_cache._record_hit(page_id)
        return _maybe_downgrade(hit, schema)

    import time as _time

    start = _time.monotonic()
    result = await _build()
    surface_cache._record_build(page_id, (_time.monotonic() - start) * 1000.0)
    surface_cache.set(key, result)
    return _maybe_downgrade(result, schema)


def _maybe_downgrade(surface_dict: dict, schema: str | None) -> dict:
    """Serve the wire version the client asked for, or refuse.

    ``None`` (no selector) and ``0.10`` both mean the native envelope. ``0.9``
    strips ``meta``; ``0.8`` re-shapes to the OpenClaw envelope. Anything else
    raises ``UnsupportedSchemaVersion`` — before the strict-selector rule an unrecognised value,
    ``v0.9`` included, fell through to the native return, so the client got a
    version it had explicitly said it could not handle.
    """
    requested = normalize_schema_selector(schema)
    if requested == "0.8":
        return to_v08(surface_dict)
    if requested == "0.9":
        return to_v09(surface_dict)
    return surface_dict
