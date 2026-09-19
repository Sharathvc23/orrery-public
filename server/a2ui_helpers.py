"""
A2UI Helper Functions — component builders for agent-generated UI.

Implements Google A2UI v0.9 wire format (flat component discriminator,
createSurface/updateComponents envelope, plain children arrays).

Pure functions that produce A2UI component dicts. No state, no side effects.
Used by chapter_agent.py, surfaces.py, and any module that renders A2UI.

Display components: Card, Column, Row, Text, Badge, Progress, Metric,
  Stat, List, Avatar, Alert, Link, Tabs, Grid, Divider, Image,
  Markdown, Heading, CodeBlock, Accordion, Table, Callout, TrustBadge,
  Timeline, MemberCard, StatGroup
Interactive components: Input, TextArea, Select, Toggle, ActionButton,
  Form, Chip, ChipGroup, Toast
"""

import uuid
from typing import Any

A2UI_VERSION = "0.10"

# ─── Layout ──────────────────────────────────────────────────


def card(id: str, child_id: str) -> dict:
    return {"id": id, "component": "Card", "child": child_id}


def column(id: str, children: list[str]) -> dict:
    return {"id": id, "component": "Column", "children": children}


def row(id: str, children: list[str]) -> dict:
    return {"id": id, "component": "Row", "children": children}


def divider(id: str) -> dict:
    return {"id": id, "component": "Divider", "axis": "horizontal"}


def grid(id: str, children: list[str], cols: int = 3) -> dict:
    return {"id": id, "component": "Grid", "children": children, "cols": cols}


def surface(surface_id: str, components: list[dict], root_id: str) -> dict:
    """v0.9 envelope: createSurface + updateComponents with root on updateComponents."""
    return {
        "createSurface": {"surfaceId": surface_id},
        "updateComponents": {
            "surfaceId": surface_id,
            "root": root_id,
            "components": components,
        },
        "version": A2UI_VERSION,
    }


# ─── Display ─────────────────────────────────────────────────


def text(id: str, text_str: str, usage_hint: str = "body") -> dict:
    return {"id": id, "component": "Text", "text": text_str, "usageHint": usage_hint}


def badge(id: str, text_str: str, variant: str = "secondary", color: str = "") -> dict:
    return {"id": id, "component": "Badge", "text": text_str, "variant": variant, "color": color}


def progress(id: str, value: float, label: str = "", color: str = "default") -> dict:
    return {"id": id, "component": "Progress", "value": value, "label": label, "color": color}


def metric(id: str, value: str, label: str, suffix: str = "", trend: str = "neutral") -> dict:
    return {
        "id": id,
        "component": "Metric",
        "value": value,
        "label": label,
        "suffix": suffix,
        "trend": trend,
    }


def stat(id: str, label: str, value: str) -> dict:
    return {"id": id, "component": "Stat", "label": label, "value": value}


def list_component(id: str, items: list[str], ordered: bool = False) -> dict:
    return {"id": id, "component": "List", "items": items, "ordered": ordered}


def avatar(id: str, name: str, subtitle: str = "", image_url: str = "") -> dict:
    return {
        "id": id,
        "component": "Avatar",
        "name": name,
        "subtitle": subtitle,
        "imageUrl": image_url,
    }


def alert(id: str, message: str, title: str = "", variant: str = "default") -> dict:
    return {"id": id, "component": "Alert", "message": message, "title": title, "variant": variant}


def link(id: str, text_str: str, url: str) -> dict:
    return {"id": id, "component": "Link", "text": text_str, "url": url}


def tabs(id: str, tab_list: list[dict]) -> dict:
    return {"id": id, "component": "Tabs", "tabs": tab_list}


def image(id: str, url: str, alt: str = "", width: int = 0, height: int = 0) -> dict:
    node: dict[str, Any] = {"id": id, "component": "Image", "url": url, "alt": alt}
    if width:
        node["width"] = width
    if height:
        node["height"] = height
    return node


# ─── New v0.9 display components (wiki / enterprise) ───────


def markdown(id: str, content: str) -> dict:
    """Long-form rich text — the foundation for wiki pages, notes, proposals.

    Spec-correct field name is ``text`` (consistent with every other
    text-bearing component); renderer also reads ``content`` as a
    back-compat fallback for older surfaces still in flight.
    """
    return {"id": id, "component": "Markdown", "text": content}


def heading(id: str, level: int, text_str: str) -> dict:
    """Semantic heading element per spec/0.4/a2ui.md §3.2 Heading.

    The renderer derives an anchor from `id` automatically — there is no
    wire-level `anchor` field. (Earlier helper had an unused `anchor`
    parameter that leaked an empty string into emission and broke schema
    validation; see conformance/server/test_surfaces.py.)
    """
    lvl = max(1, min(6, int(level)))
    return {"id": id, "component": "Heading", "level": lvl, "text": text_str}


def code_block(id: str, code: str, language: str = "", caption: str = "") -> dict:
    """Monospace code with optional syntax hint.

    spec/0.4/a2ui.md §3.2 CodeBlock defines only `code` and `language`.
    The local `caption` parameter is preserved for source-compat but is
    not emitted on the wire (CodeBlock does not carry a caption field).
    """
    node = {"id": id, "component": "CodeBlock", "code": code}
    if language:
        node["language"] = language
    return node


def accordion(id: str, sections: list[dict]) -> dict:
    """Collapsible sections. Each section: {title, childId, defaultOpen?}."""
    return {"id": id, "component": "Accordion", "sections": sections}


def table(id: str, columns: list[str], rows: list[list[str]], caption: str = "") -> dict:
    """Structured rows — member rosters, call responses, trust tier tables.

    Wire field for column labels is `headers` per spec/0.4/a2ui.md §3.2 Table.
    Local parameter stays `columns` for source-compat with existing callers.
    """
    return {
        "id": id,
        "component": "Table",
        "headers": columns,
        "rows": rows,
        "caption": caption,
    }


def callout(id: str, message: str, variant: str = "info", title: str = "") -> dict:
    """Inline tip/warning/info. Variant: info | success | warning | danger.

    The wire field is `text` per spec/0.4/a2ui.md §3.2 Callout. The local
    parameter is still named `message` for source compatibility with the
    ~30 existing callers in surfaces.py; future PRs may rename it.
    """
    return {
        "id": id,
        "component": "Callout",
        "text": message,
        "variant": variant,
        "title": title,
    }


def trust_badge(id: str, score: float, show_score: bool = True) -> dict:
    """Tier badge derived from trust_score.

    spec/0.4/a2ui.md §3.2 TrustBadge defines `score` and `tier` only.
    `show_score` is a renderer hint not carried on the wire; preserved as
    a parameter for source-compat but not emitted. The internal tier
    vocabulary (newcomer/established/trusted/power) differs from the
    spec's documented enum (newcomer/member/established/leader/core) —
    schema doesn't constrain the enum so this passes today, but the
    spec-vs-implementation reconciliation is its own follow-up.
    """
    _ = show_score  # explicit unused-acknowledgement
    s = float(score or 0)
    if s >= 75:
        tier = "power"
    elif s >= 50:
        tier = "trusted"
    elif s >= 20:
        tier = "established"
    else:
        tier = "newcomer"
    return {
        "id": id,
        "component": "TrustBadge",
        "score": s,
        "tier": tier,
    }


def timeline(id: str, entries: list[dict]) -> dict:
    """Activity feed. Each entry: {timestamp, title, body?, icon?}."""
    return {"id": id, "component": "Timeline", "entries": entries}


def member_card(
    id: str,
    name: str,
    agent_id: str,
    avatar_url: str = "",
    role: str = "",
    trust_score: float | None = None,
    skills: list[str] | None = None,
    subtitle: str = "",
) -> dict:
    """First-class member render — replaces hand-built Card+Column+Avatar."""
    node: dict[str, Any] = {
        "id": id,
        "component": "MemberCard",
        "name": name,
        "agentId": agent_id,
        "avatarUrl": avatar_url,
        "role": role,
        "skills": skills or [],
        "subtitle": subtitle,
    }
    if trust_score is not None:
        node["trustScore"] = float(trust_score)
    return node


def stat_group(id: str, items: list[dict]) -> dict:
    """Dashboard stats row. Each item: {label, value, trend?, suffix?}."""
    return {"id": id, "component": "StatGroup", "items": items}


# ─── Interactive ─────────────────────────────────────────────


def input_field(id: str, label: str = "", placeholder: str = "", value: str = "", input_type: str = "text") -> dict:
    return {
        "id": id,
        "component": "Input",
        "label": label,
        "placeholder": placeholder,
        "value": value,
        "inputType": input_type,
    }


def textarea(id: str, label: str = "", placeholder: str = "", value: str = "", rows: int = 3) -> dict:
    return {
        "id": id,
        "component": "TextArea",
        "label": label,
        "placeholder": placeholder,
        "value": value,
        "rows": rows,
    }


def select(id: str, label: str = "", options: list[dict] | None = None, value: str = "") -> dict:
    return {
        "id": id,
        "component": "Select",
        "label": label,
        "options": options or [],
        "value": value,
    }


def toggle(id: str, label: str = "", checked: bool = False) -> dict:
    return {"id": id, "component": "Toggle", "label": label, "checked": checked}


def action_button(id: str, label: str, action: str, variant: str = "default", data: dict | None = None) -> dict:
    return {
        "id": id,
        "component": "ActionButton",
        "label": label,
        "action": action,
        "variant": variant,
        "data": data or {},
    }


def form(id: str, children: list[str], action: str, submit_label: str = "Submit") -> dict:
    return {
        "id": id,
        "component": "Form",
        "children": children,
        "action": action,
        "submitLabel": submit_label,
    }


def chip(id: str, label: str, selected: bool = False, value: str = "") -> dict:
    return {
        "id": id,
        "component": "Chip",
        "label": label,
        "selected": selected,
        "value": value or label,
    }


def chip_group(id: str, children: list[str] | list[dict], multi: bool = True) -> dict:
    return {"id": id, "component": "ChipGroup", "children": children, "multi": multi}


def toast(id: str, message: str, title: str = "", variant: str = "default") -> dict:
    return {"id": id, "component": "Toast", "message": message, "title": title, "variant": variant}


# ─── Compound Builders ──────────────────────────────────────


def build_member_cards(member_list: list[dict]) -> dict | None:
    """A2UI card grid for a list of members — now uses MemberCard v0.9 component."""
    if not member_list:
        return None
    components: list[dict] = []
    card_ids: list[str] = []
    for i, m in enumerate(member_list):
        cid = f"m{i}"
        card_ids.append(cid)
        components.append(
            member_card(
                cid,
                name=m.get("name", "Unknown"),
                agent_id=m.get("id") or m.get("agent_id", ""),
                avatar_url=m.get("avatar_url", ""),
                role=m.get("role", ""),
                trust_score=m.get("trust_score"),
                skills=m.get("skills", [])[:6],
                subtitle=m.get("description", ""),
            )
        )
    components.insert(0, column("root", card_ids))
    return surface("members", components, "root")


def build_chapter_info(
    agent_name: str,
    agent_description: str,
    agent_focus: str,
    agent_region: str,
    member_count: int,
    federation_count: int,
) -> dict:
    """A2UI card for chapter info with v0.9 Heading + StatGroup."""
    components = [
        column("root", ["title", "desc", "divider", "stats", "badges-row"]),
        heading("title", 1, agent_name),
        text("desc", agent_description, "body"),
        divider("divider"),
        stat_group(
            "stats",
            [
                {"label": "Members", "value": str(member_count)},
                {"label": "Federation", "value": str(federation_count)},
            ],
        ),
        row("badges-row", ["badge-focus", "badge-region"]),
        badge("badge-focus", agent_focus, "secondary"),
        badge("badge-region", agent_region or "Global", "outline"),
    ]
    return surface("chapter-info", components, "root")


def build_federation_cards(federation_data: dict) -> dict | None:
    """A2UI card grid for federation chapters."""
    if not federation_data:
        return None
    components: list[dict] = []
    card_ids: list[str] = []
    for i, (fid, finfo) in enumerate(federation_data.items()):
        cid = f"f{i}"
        card_ids.append(f"{cid}-card")
        status = finfo.get("status", "unknown")
        status_color = "bg-green-500/10 text-green-700" if status == "online" else "bg-red-500/10 text-red-700"
        components.extend(
            [
                card(f"{cid}-card", f"{cid}-col"),
                column(f"{cid}-col", [f"{cid}-header", f"{cid}-focus", f"{cid}-stats"]),
                row(f"{cid}-header", [f"{cid}-name", f"{cid}-status"]),
                heading(f"{cid}-name", 4, finfo.get("name", fid)),
                badge(f"{cid}-status", status, "secondary", status_color),
                badge(f"{cid}-focus", finfo.get("focus", "General"), "outline"),
                stat(f"{cid}-stats", "Members", str(finfo.get("members", "?"))),
            ]
        )
    components.insert(0, column("root", card_ids))
    return surface("federation", components, "root")


def build_thought_card(
    thought_type: str,
    title_text: str,
    body_text: str,
    targets: list[dict] | None = None,
    agent_name: str = "",
) -> dict:
    """A2UI card for an autonomous agent thought."""
    type_colors = {
        "introduction": "bg-green-500/10 text-green-700",
        "insight": "bg-yellow-500/10 text-yellow-700",
        "conversation": "bg-blue-500/10 text-blue-700",
        "observation": "bg-purple-500/10 text-purple-700",
        "startup_idea": "bg-red-500/10 text-red-700",
    }
    type_labels = {
        "introduction": "Introduction",
        "insight": "Insight",
        "conversation": "Conversation",
        "observation": "Observation",
        "startup_idea": "Startup Idea",
    }
    children = ["thought-header", "thought-title", "thought-divider", "thought-body"]
    components = [
        row("thought-header", ["thought-type-badge", "thought-chapter-badge"]),
        badge(
            "thought-type-badge",
            type_labels.get(thought_type, thought_type),
            "secondary",
            type_colors.get(thought_type, ""),
        ),
        badge("thought-chapter-badge", agent_name, "outline"),
        heading("thought-title", 3, title_text),
        divider("thought-divider"),
        text("thought-body", body_text, "body"),
    ]
    if targets:
        target_ids = []
        for i, t in enumerate(targets[:4]):
            tid = f"target-{i}"
            target_ids.append(tid)
            components.append(avatar(tid, t.get("name", "?"), f"@{t.get('agent_id', '?')} — {t.get('chapter', '?')}"))
        children.append("targets-row")
        components.append(column("targets-row", target_ids))

    thought_id = f"thought-{uuid.uuid4().hex[:8]}"
    children.append("thought-feedback")
    components.extend(
        [
            row("thought-feedback", ["thought-fb-up", "thought-fb-down"]),
            action_button(
                "thought-fb-up",
                "Helpful",
                "submit_feedback",
                "outline",
                {"action_id": thought_id, "action_type": thought_type, "signal": "positive"},
            ),
            action_button(
                "thought-fb-down",
                "Not useful",
                "submit_feedback",
                "ghost",
                {"action_id": thought_id, "action_type": thought_type, "signal": "negative"},
            ),
        ]
    )

    components.insert(0, column("root", children))
    return surface(thought_id, [card("thought-card", "root")] + components, "thought-card")


def build_introduction_card(member_a: dict, member_b: dict, reason: str, conversation_msgs: list[dict]) -> dict:
    """A2UI card for a cross-chapter introduction."""
    children = ["intro-header", "intro-people", "intro-reason", "intro-divider"]
    components = [
        row("intro-header", ["intro-badge", "intro-chapters-badge"]),
        badge("intro-badge", "Introduction", "secondary", "bg-green-500/10 text-green-700"),
        badge(
            "intro-chapters-badge", f"{member_a.get('chapter', '?')} \u00d7 {member_b.get('chapter', '?')}", "outline"
        ),
        row("intro-people", ["intro-avatar-a", "intro-avatar-b"]),
        avatar("intro-avatar-a", member_a.get("name", "?"), member_a.get("chapter", "")),
        avatar("intro-avatar-b", member_b.get("name", "?"), member_b.get("chapter", "")),
        text("intro-reason", reason, "body"),
        divider("intro-divider"),
    ]
    for i, msg in enumerate(conversation_msgs[:6]):
        mid = f"conv-{i}"
        children.append(mid)
        speaker = msg.get("speaker", "?")
        msg_text = msg.get("text", "")
        if i % 2 == 0:
            components.append(text(mid, f"\u25b6 @{speaker}: {msg_text}", "body"))
        else:
            components.append(text(mid, f"\u25c0 @{speaker}: {msg_text}", "caption"))

    components.insert(0, column("root", children))
    return surface(f"intro-{uuid.uuid4().hex[:8]}", [card("intro-card", "root")] + components, "intro-card")


def build_insight_card(title_text: str, insight: str, data_points: list[str] | None = None) -> dict:
    """A2UI card for an agent insight/observation."""
    children = ["insight-header", "insight-body"]
    components = [
        row("insight-header", ["insight-badge", "insight-title"]),
        badge("insight-badge", "Insight", "secondary", "bg-yellow-500/10 text-yellow-700"),
        heading("insight-title", 3, title_text),
        text("insight-body", insight, "body"),
    ]
    if data_points:
        children.append("insight-divider")
        components.append(divider("insight-divider"))
        children.append("insight-list")
        components.append(list_component("insight-list", data_points[:5]))

    components.insert(0, column("root", children))
    return surface(f"insight-{uuid.uuid4().hex[:8]}", [card("insight-card", "root")] + components, "insight-card")


# ─── v0.10 meta extension (PR-C5 — additive helpers) ─────────────
#
# These helpers add the optional `meta` block defined in spec/0.4/a2ui.md
# §10 to a v0.9 component dict (or surface envelope). They are purely
# additive: callers that do not invoke them continue to emit v0.9
# verbatim. The server does not yet emit v0.10 by default — that flips
# in a follow-up PR alongside renderer support (PR-C6) and server-wide
# adoption.

A2UI_VERSION_V010 = "0.10"

# Closed enums hand-mirrored from schema/0.4 so server code fails fast on
# typos rather than producing wire output a v0.10 renderer would silently
# drop. They come from TWO schema files, not one — component-level fields
# live in a2ui-component.json, surface-level fields in a2ui-surface.json:
#
#   _DENSITY_ENUM      a2ui-component.json  $defs/MetaDensity/properties/preferred
#                      a2ui-surface.json    $defs/SurfaceDensity/properties/preferred
#                      ^ validated against BOTH — see the two call sites below
#   _BREAKPOINT_ENUM   a2ui-component.json  $defs/MetaResponsive/properties/breakpointHide
#                                           $defs/MetaResponsive/properties/stackBelow
#   _FORM_FACTOR_ENUM  a2ui-surface.json    $defs/SurfaceTarget/properties/formFactor
#   _ARIA_ROLE_ENUM    a2ui-component.json  $defs/MetaA11y/properties/role
#   _ARIA_LIVE_ENUM    a2ui-component.json  $defs/MetaA11y/properties/ariaLive
#
# Editing a schema enum WITHOUT editing the tuple here (or vice versa) is
# a CI failure, not a silent drift: tests/test_a2ui_mirrored_enums.py
# reloads the schema and asserts each pair.
#
# That test does NOT work from this list — it DISCOVERS mirrors by shape
# (every module-level collection-of-strings) and indexes every enum in
# schema/0.4, precisely so a mirror nobody wrote down still gets caught.
# Add a new closed set here and it fails until you either pin its schema
# source or record why it has none. Keep this table current anyway: the
# test proves the values agree, it cannot tell a reader where to look.
_DENSITY_ENUM = ("compact", "comfortable", "spacious")
_BREAKPOINT_ENUM = ("sm", "md", "lg", "xl")
_FORM_FACTOR_ENUM = ("mobile", "tablet", "desktop")
_ARIA_ROLE_ENUM = (
    "button",
    "link",
    "checkbox",
    "radio",
    "switch",
    "menuitem",
    "tab",
    "tabpanel",
    "dialog",
    "alertdialog",
    "alert",
    "status",
    "progressbar",
    "navigation",
    "search",
    "form",
    "region",
)
_ARIA_LIVE_ENUM = ("off", "polite", "assertive")


def _validate_enum(value, enum: tuple[str, ...], field: str) -> None:
    if value not in enum:
        raise ValueError(f"{field}={value!r} not in {enum}")


def with_meta(
    component: dict,
    *,
    a11y: dict | None = None,
    responsive: dict | None = None,
    density: dict | None = None,
    render: dict | None = None,
    vendor: dict | None = None,
) -> dict:
    """Attach a v0.10 `meta` block to an existing v0.9 component dict.

    All four namespaces are optional. ``vendor`` is a dict of
    ``{"x-foo": {...}}`` keys — keys NOT matching the ``^x-...`` pattern
    raise ``ValueError`` so chapter code does not silently produce
    schema-rejected wire output.

    Returns the same component dict mutated in place AND returned, so
    callers may chain (``with_meta(button(...), a11y={...})``).
    """
    if not any([a11y, responsive, density, render, vendor]):
        return component
    meta: dict = component.setdefault("meta", {})
    if a11y is not None:
        if "role" in a11y:
            _validate_enum(a11y["role"], _ARIA_ROLE_ENUM, "meta.a11y.role")
        if "ariaLive" in a11y:
            _validate_enum(a11y["ariaLive"], _ARIA_LIVE_ENUM, "meta.a11y.ariaLive")
        meta["a11y"] = a11y
    if responsive is not None:
        if "breakpointHide" in responsive:
            _validate_enum(
                responsive["breakpointHide"],
                _BREAKPOINT_ENUM,
                "meta.responsive.breakpointHide",
            )
        if "stackBelow" in responsive:
            _validate_enum(
                responsive["stackBelow"],
                _BREAKPOINT_ENUM,
                "meta.responsive.stackBelow",
            )
        meta["responsive"] = responsive
    if density is not None:
        if "preferred" in density:
            _validate_enum(
                density["preferred"],
                _DENSITY_ENUM,
                "meta.density.preferred",
            )
        meta["density"] = density
    if render is not None:
        meta["render"] = render
    if vendor is not None:
        for k, v in vendor.items():
            if not k.startswith("x-") or "_" in k:
                raise ValueError(f"vendor key {k!r} must match ^x-[a-z][a-z0-9-]*$")
            meta[k] = v
    return component


def surface_v010(
    surface_id: str,
    components: list[dict],
    root_id: str,
    *,
    density: str | None = None,
    form_factor: str | None = None,
    vendor: dict | None = None,
) -> dict:
    """v0.10 envelope. Identical shape to ``surface()`` plus optional
    ``createSurface.meta`` (density / target / vendor extensions) and
    ``version: "0.10"`` instead of ``"0.9"``.
    """
    meta: dict = {}
    if density is not None:
        _validate_enum(density, _DENSITY_ENUM, "createSurface.meta.density.preferred")
        meta["density"] = {"preferred": density}
    if form_factor is not None:
        _validate_enum(form_factor, _FORM_FACTOR_ENUM, "createSurface.meta.target.formFactor")
        meta["target"] = {"formFactor": form_factor}
    if vendor:
        for k, v in vendor.items():
            if not k.startswith("x-") or "_" in k:
                raise ValueError(f"vendor key {k!r} must match ^x-[a-z][a-z0-9-]*$")
            meta[k] = v
    cs: dict = {"surfaceId": surface_id}
    if meta:
        cs["meta"] = meta
    return {
        "createSurface": cs,
        "updateComponents": {
            "surfaceId": surface_id,
            "root": root_id,
            "components": components,
        },
        "version": A2UI_VERSION_V010,
    }
