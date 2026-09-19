"""
Prosecution-grade tests for a2ui_helpers.py — Google A2UI v0.9 emitter.

Ensures every builder produces the v0.9 flat shape (component: str discriminator,
plain children arrays, plain text strings, createSurface/updateComponents envelope).

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL
"""

import a2ui_helpers as h

# ── Utility: validate v0.9 component shape contract ──────


def _assert_v09_component(node: dict, expected_type: str):
    """A valid v0.9 component has {id, component: str} at minimum, no nested type wrapper."""
    assert "id" in node, "Missing id"
    assert node.get("component") == expected_type, (
        f"v0.9 expects component:{expected_type!r} flat discriminator, got {node.get('component')!r}"
    )
    # Anti-pattern: v0.8 nested shape must not appear
    inner = node.get(expected_type)
    assert not isinstance(inner, dict), f"v0.9 must NOT nest props under {expected_type!r} key — properties are flat"


# ══════════════════════════════════════════════════════════════
# HAPPY — every builder emits correct v0.9 shape
# ══════════════════════════════════════════════════════════════


def test_text_happy():
    node = h.text("t1", "Hello", "h1")
    _assert_v09_component(node, "Text")
    assert node["text"] == "Hello"  # flat string, NOT {literalString: "..."}
    assert node["usageHint"] == "h1"


def test_card_happy():
    node = h.card("c1", "body")
    _assert_v09_component(node, "Card")
    assert node["child"] == "body"


def test_column_happy():
    node = h.column("col1", ["a", "b", "c"])
    _assert_v09_component(node, "Column")
    assert node["children"] == ["a", "b", "c"]  # plain array, NOT {explicitList}


def test_row_happy():
    node = h.row("r1", ["a"])
    _assert_v09_component(node, "Row")
    assert node["children"] == ["a"]


def test_grid_happy():
    node = h.grid("g1", ["a", "b"], cols=4)
    _assert_v09_component(node, "Grid")
    assert node["children"] == ["a", "b"]
    assert node["cols"] == 4


def test_divider_happy():
    node = h.divider("d1")
    _assert_v09_component(node, "Divider")
    assert node["axis"] == "horizontal"


def test_badge_happy():
    node = h.badge("b1", "Active", "secondary", "green")
    _assert_v09_component(node, "Badge")
    assert node["text"] == "Active"
    assert node["variant"] == "secondary"
    assert node["color"] == "green"


def test_progress_happy():
    node = h.progress("p1", 42.5, "Loading", "green")
    _assert_v09_component(node, "Progress")
    assert node["value"] == 42.5
    assert node["label"] == "Loading"


def test_metric_happy():
    node = h.metric("m1", "42", "Members", "+", "up")
    _assert_v09_component(node, "Metric")
    assert node["value"] == "42"
    assert node["label"] == "Members"
    assert node["trend"] == "up"


def test_stat_happy():
    node = h.stat("s1", "Label", "Value")
    _assert_v09_component(node, "Stat")
    assert node["label"] == "Label"
    assert node["value"] == "Value"


def test_list_component_happy():
    node = h.list_component("l1", ["a", "b"], ordered=True)
    _assert_v09_component(node, "List")
    assert node["items"] == ["a", "b"]
    assert node["ordered"] is True


def test_avatar_happy():
    node = h.avatar("av1", "Alice", "Engineer", "https://img")
    _assert_v09_component(node, "Avatar")
    assert node["name"] == "Alice"
    assert node["subtitle"] == "Engineer"
    assert node["imageUrl"] == "https://img"


def test_alert_happy():
    node = h.alert("a1", "Watch out", "Warning", "warning")
    _assert_v09_component(node, "Alert")
    assert node["message"] == "Watch out"
    assert node["title"] == "Warning"
    assert node["variant"] == "warning"


def test_link_happy():
    node = h.link("lk1", "Click me", "https://x")
    _assert_v09_component(node, "Link")
    assert node["text"] == "Click me"
    assert node["url"] == "https://x"


def test_tabs_happy():
    node = h.tabs("tb1", [{"label": "One", "child": "c1"}])
    _assert_v09_component(node, "Tabs")
    assert node["tabs"][0]["label"] == "One"


def test_image_happy():
    node = h.image("i1", "https://x/y.png", alt="alt", width=100, height=50)
    _assert_v09_component(node, "Image")
    assert node["url"] == "https://x/y.png"
    assert node["width"] == 100


def test_input_field_happy():
    node = h.input_field("in1", "Email", "you@x", "", "email")
    _assert_v09_component(node, "Input")
    assert node["label"] == "Email"
    assert node["inputType"] == "email"


def test_textarea_happy():
    node = h.textarea("ta1", "Notes", "...", "", rows=5)
    _assert_v09_component(node, "TextArea")
    assert node["rows"] == 5


def test_select_happy():
    node = h.select("sel1", "Role", [{"label": "Admin", "value": "admin"}], "admin")
    _assert_v09_component(node, "Select")
    assert node["options"][0]["value"] == "admin"
    assert node["value"] == "admin"


def test_toggle_happy():
    node = h.toggle("tg1", "Enabled", checked=True)
    _assert_v09_component(node, "Toggle")
    assert node["checked"] is True


def test_action_button_happy():
    node = h.action_button("ab1", "Submit", "submit_form", "default", {"x": 1})
    _assert_v09_component(node, "ActionButton")
    assert node["action"] == "submit_form"
    assert node["data"] == {"x": 1}


def test_form_happy():
    node = h.form("f1", ["in1"], "do_it", "Go")
    _assert_v09_component(node, "Form")
    assert node["children"] == ["in1"]
    assert node["action"] == "do_it"
    assert node["submitLabel"] == "Go"


def test_chip_happy():
    node = h.chip("ch1", "python")
    _assert_v09_component(node, "Chip")
    assert node["label"] == "python"
    assert node["value"] == "python"  # defaults to label


def test_chip_group_happy():
    node = h.chip_group("cg1", ["c1", "c2"], multi=False)
    _assert_v09_component(node, "ChipGroup")
    assert node["children"] == ["c1", "c2"]
    assert node["multi"] is False


def test_toast_happy():
    node = h.toast("t1", "Saved", "Success", "success")
    _assert_v09_component(node, "Toast")
    assert node["variant"] == "success"


# ══════════════════════════════════════════════════════════════
# HAPPY — NEW v0.9 display components (wiki / enterprise)
# ══════════════════════════════════════════════════════════════


def test_markdown_happy():
    node = h.markdown("md1", "# Title\n\nBody with **bold**.")
    _assert_v09_component(node, "Markdown")
    # Spec-correct field name; older surfaces with `content` still
    # render via the renderer's back-compat fallback.
    assert "**bold**" in node["text"]


def test_heading_happy():
    node = h.heading("hd1", 2, "Section")
    _assert_v09_component(node, "Heading")
    assert node["level"] == 2
    assert node["text"] == "Section"
    assert "anchor" not in node, (
        "Heading must not carry a wire-level 'anchor' field — spec/0.4/a2ui.md §3.2 "
        "says the renderer derives the anchor from `id`."
    )


def test_heading_clamps_level():
    """EDGE: level clamped to 1..6 range."""
    assert h.heading("h", 0, "x")["level"] == 1
    assert h.heading("h", 99, "x")["level"] == 6
    assert h.heading("h", -5, "x")["level"] == 1


def test_code_block_happy():
    node = h.code_block("cb1", "print('hi')", language="python", caption="greeting")
    _assert_v09_component(node, "CodeBlock")
    assert node["code"] == "print('hi')"
    assert node["language"] == "python"
    assert "caption" not in node, (
        "spec/0.4/a2ui.md §3.2 CodeBlock has no `caption` field; helper accepts "
        "it as a no-op parameter for source-compat but must not emit it."
    )


def test_accordion_happy():
    node = h.accordion("ac1", [{"title": "FAQ", "childId": "q1", "defaultOpen": True}])
    _assert_v09_component(node, "Accordion")
    assert node["sections"][0]["title"] == "FAQ"
    assert node["sections"][0]["defaultOpen"] is True


def test_table_happy():
    node = h.table("tb1", ["Name", "Score"], [["Alice", "42"], ["Bob", "17"]], caption="Leaderboard")
    _assert_v09_component(node, "Table")
    assert node["headers"] == ["Name", "Score"], (
        "Wire field for column labels is `headers` per spec/0.4/a2ui.md §3.2 "
        "Table; the helper's `columns` parameter is mapped to `headers` on emission."
    )
    assert "columns" not in node, "Table must not carry a wire-level `columns` field — spec names it `headers`."
    assert node["rows"] == [["Alice", "42"], ["Bob", "17"]]
    assert node["caption"] == "Leaderboard"


def test_callout_happy():
    node = h.callout("cl1", "Read this", variant="warning", title="Heads up")
    _assert_v09_component(node, "Callout")
    assert node["text"] == "Read this", (
        "Wire field is 'text' per spec/0.4/a2ui.md §3.2 Callout; the helper's "
        "`message` parameter is mapped to `text` on emission."
    )
    assert "message" not in node, (
        "Callout must not carry a wire-level 'message' field — spec/0.4 §3.2 names this field 'text'."
    )
    assert node["variant"] == "warning"


def test_trust_badge_tiers():
    """HAPPY: Tier derivation is correct at each boundary."""
    assert h.trust_badge("t", 0)["tier"] == "newcomer"
    assert h.trust_badge("t", 19.9)["tier"] == "newcomer"
    assert h.trust_badge("t", 20)["tier"] == "established"
    assert h.trust_badge("t", 49.9)["tier"] == "established"
    assert h.trust_badge("t", 50)["tier"] == "trusted"
    assert h.trust_badge("t", 74.9)["tier"] == "trusted"
    assert h.trust_badge("t", 75)["tier"] == "power"
    assert h.trust_badge("t", 100)["tier"] == "power"


def test_trust_badge_shape():
    node = h.trust_badge("tb1", 55, show_score=False)
    _assert_v09_component(node, "TrustBadge")
    assert node["score"] == 55.0
    assert "showScore" not in node, (
        "spec/0.4/a2ui.md §3.2 TrustBadge has no `showScore` field; the "
        "`show_score` parameter is a renderer hint not carried on the wire."
    )


def test_timeline_happy():
    entries = [
        {"timestamp": "2026-04-19T10:00:00Z", "title": "Joined chapter", "body": "via invite"},
        {"timestamp": "2026-04-19T11:00:00Z", "title": "Posted call", "icon": "megaphone"},
    ]
    node = h.timeline("tl1", entries)
    _assert_v09_component(node, "Timeline")
    assert len(node["entries"]) == 2


def test_member_card_happy():
    node = h.member_card(
        "mc1",
        name="Alice",
        agent_id="alice-agent",
        avatar_url="https://x",
        role="Leader",
        trust_score=62.0,
        skills=["python", "ml"],
        subtitle="AI Researcher",
    )
    _assert_v09_component(node, "MemberCard")
    assert node["name"] == "Alice"
    assert node["agentId"] == "alice-agent"
    assert node["trustScore"] == 62.0
    assert node["skills"] == ["python", "ml"]


def test_member_card_optional_trust_score():
    """EDGE: trust_score None → omitted entirely (renderer can hide badge)."""
    node = h.member_card("mc1", name="Bob", agent_id="bob")
    assert "trustScore" not in node


def test_stat_group_happy():
    items = [
        {"label": "Members", "value": "42"},
        {"label": "Online", "value": "12", "trend": "up"},
    ]
    node = h.stat_group("sg1", items)
    _assert_v09_component(node, "StatGroup")
    assert node["items"] == items


# ══════════════════════════════════════════════════════════════
# HAPPY — Surface envelope (v0.9 createSurface + updateComponents)
# ══════════════════════════════════════════════════════════════


def test_surface_envelope_v09():
    """The envelope must use createSurface + updateComponents, NOT surfaceUpdate/beginRendering."""
    components = [h.text("t", "hi"), h.column("root", ["t"])]
    s = h.surface("s1", components, "root")

    assert "createSurface" in s
    assert "updateComponents" in s
    assert "surfaceUpdate" not in s  # v0.8 shape must not leak
    assert "beginRendering" not in s  # v0.8 shape must not leak

    assert s["createSurface"]["surfaceId"] == "s1"
    assert s["updateComponents"]["surfaceId"] == "s1"
    assert s["updateComponents"]["root"] == "root"
    assert s["updateComponents"]["components"] == components
    assert s["version"] == "0.10"


# ══════════════════════════════════════════════════════════════
# EDGE — boundary inputs
# ══════════════════════════════════════════════════════════════


def test_column_empty_children():
    node = h.column("col", [])
    _assert_v09_component(node, "Column")
    assert node["children"] == []


def test_text_empty_string():
    node = h.text("t", "")
    assert node["text"] == ""


def test_member_card_no_skills():
    node = h.member_card("m", name="X", agent_id="x")
    assert node["skills"] == []


def test_table_empty():
    node = h.table("t", [], [])
    assert node["rows"] == []
    assert node["headers"] == []


def test_build_member_cards_empty_returns_none():
    assert h.build_member_cards([]) is None


def test_build_federation_cards_empty_returns_none():
    assert h.build_federation_cards({}) is None


# ══════════════════════════════════════════════════════════════
# EDGE — Compound builders produce v0.9 surfaces
# ══════════════════════════════════════════════════════════════


def test_build_member_cards_is_v09():
    s = h.build_member_cards([{"name": "Alice", "id": "alice-1", "skills": ["py"], "description": "dev"}])
    assert "updateComponents" in s
    assert "surfaceUpdate" not in s

    components = s["updateComponents"]["components"]
    # Now uses MemberCard component (v0.9 first-class)
    member_cards = [c for c in components if c.get("component") == "MemberCard"]
    assert len(member_cards) == 1
    assert member_cards[0]["name"] == "Alice"


def test_build_chapter_info_is_v09():
    s = h.build_chapter_info("NANDA", "desc", "AI", "SF", 10, 5)
    assert "updateComponents" in s
    components = s["updateComponents"]["components"]
    headings = [c for c in components if c.get("component") == "Heading"]
    assert any(hd["text"] == "NANDA" for hd in headings)


def test_build_federation_cards_is_v09():
    s = h.build_federation_cards({"boston": {"name": "Boston", "status": "online", "members": 12}})
    assert "updateComponents" in s
    components = s["updateComponents"]["components"]
    # Each card has a Column with children as plain list
    columns = [c for c in components if c.get("component") == "Column"]
    for col in columns:
        assert isinstance(col["children"], list)  # v0.9 plain list


# ══════════════════════════════════════════════════════════════
# FAILURE — defends invariants (asserting contracts, not existence)
# ══════════════════════════════════════════════════════════════


def test_children_never_wrapped():
    """FAILURE: No v0.9 builder ever wraps children in {explicitList: ...}."""
    for node in [
        h.column("c", ["a"]),
        h.row("r", ["a"]),
        h.grid("g", ["a"]),
        h.form("f", ["a"], "act"),
        h.chip_group("cg", ["a"]),
    ]:
        children = node.get("children")
        assert isinstance(children, list), (
            f"{node['component']} must have plain-list children, got {type(children).__name__}"
        )
        assert "explicitList" not in (children if isinstance(children, dict) else {})


def test_text_never_wrapped_in_literal_string():
    """FAILURE: Text/Heading text must be a raw string, not {literalString: ...}."""
    for node in [
        h.text("t", "hi"),
        h.badge("b", "hi"),
        h.link("l", "hi", "/"),
        h.alert("a", "hi"),
        h.toast("ts", "hi"),
    ]:
        for key in ("text", "message"):
            if key in node:
                assert isinstance(node[key], str), f"{node['component']}.{key} must be a string, not a dict wrapper"


def test_heading_text_is_flat():
    node = h.heading("h", 1, "hello")
    assert node["text"] == "hello"
    assert not isinstance(node["text"], dict)


# ══════════════════════════════════════════════════════════════
# ADVERSARIAL — hostile inputs must pass through raw (renderer's job to sanitize)
# ══════════════════════════════════════════════════════════════


def test_xss_payload_passes_through_raw():
    """ADVERSARIAL: Emitter does NOT escape; renderer escapes. This is the correct contract."""
    payload = "<script>alert(1)</script>"
    node = h.text("t", payload)
    assert node["text"] == payload  # unchanged


def test_markdown_payload_unescaped():
    """ADVERSARIAL: Markdown content is raw — renderer uses sanitizing markdown lib."""
    payload = "[click](javascript:alert(1))"
    node = h.markdown("m", payload)
    assert node["text"] == payload


def test_unicode_and_nulls_preserved():
    """ADVERSARIAL: Unicode + null characters preserved (no silent mutation)."""
    payload = "日本語 \x00 null"
    node = h.text("t", payload)
    assert node["text"] == payload


def test_huge_children_list_passes():
    """ADVERSARIAL: 1000-child Column does not crash or truncate."""
    kids = [f"k{i}" for i in range(1000)]
    node = h.column("c", kids)
    assert len(node["children"]) == 1000


def test_surface_unique_ids_contract():
    """ADVERSARIAL: surface() is agnostic to duplicates — callers must dedupe; we assert that
    if caller passes duplicates, they survive (not silently dropped) so a downstream validator
    can detect the bug."""
    dup = [h.text("dup", "a"), h.text("dup", "b")]
    s = h.surface("s", dup, "dup")
    assert len(s["updateComponents"]["components"]) == 2


def test_trust_badge_negative_score_still_newcomer():
    """ADVERSARIAL: negative trust_score (data corruption) → newcomer, not crash."""
    node = h.trust_badge("t", -50)
    assert node["tier"] == "newcomer"
    assert node["score"] == -50.0


def test_trust_badge_none_score():
    """ADVERSARIAL: None coerced to 0 via `or 0` guard."""
    node = h.trust_badge("t", None)  # type: ignore[arg-type]
    assert node["tier"] == "newcomer"
    assert node["score"] == 0.0
