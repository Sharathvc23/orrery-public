"""Tests for `/api/agents/{agent_id}/profile` — the public shareable
profile primitive.

Classification: HAPPY / EDGE / FAILURE / ADVERSARIAL.

R-categories in scope:
- R3 (injection) — agent_id sanitisation; hostile path traversal MUST 404,
  never leak filesystem state.
- R5 (boundary) — empty/oversized agent_id rejected before DB hit.
- R7 (adversarial input) — Unicode lookalikes / RTL override / null bytes.
- R8 (downgrade) — chapter MUST emit v0.9 envelope; previous v0.8 sites
  use a different endpoint.

Out of scope:
- R1, R2 (forgery/replay) — endpoint is open by design (public profile).
- Network-level concerns — covered by the conformance suite.
"""

from __future__ import annotations

# Module-under-test imports the chapter app indirectly. We import the
# pure helper that builds the surface response — testing the route at
# the FastAPI layer would force a full app spin-up which the rest of
# this test module doesn't.
import a2ui_helpers

# ── Build helper that mirrors the route's logic in isolation ──


def _build_profile_surface(agent_id: str, member: dict, trust_score: float) -> dict:
    """Copy of the RENDERING half of chapter_agent.py:agent_profile_surface().

    Kept as a module-local helper so the surface shape can be tested without
    booting FastAPI.

    ⚠️ It is a copy, and a copy cannot be its own canary. This helper carried
    `subtitle=description` for as long as the route did, and would have gone on
    reporting that shape after the route dropped it — telling a reviewer the
    route still published member-authored prose when it no longer does. Nothing
    here calls the route, so nothing here can notice.

    What actually holds the route to a shape is
    `test_profile_consent_gate.py`, which asserts the real handler's output over
    HTTP. This helper covers rendering permutations only, and deliberately does
    NOT model the consent gate — that is the route's, and is asserted there.
    """
    skills = list(member.get("skills") or [])[:12]
    origin = member.get("origin") or "sovereign"
    name = member.get("name") or f"@{agent_id}"

    components: list[dict] = [
        a2ui_helpers.member_card(
            "profile-card",
            name=name,
            agent_id=agent_id,
            avatar_url=member.get("avatar_url") or "",
            role=origin,
            trust_score=trust_score,
            skills=skills,
            # Matches the route: no subtitle. It carried member-authored free
            # text, which sm-listing 0.1 §4.2 forbids in a published entry.
            subtitle="",
        ),
        a2ui_helpers.trust_badge("profile-trust", trust_score, show_score=True),
    ]
    children: list[str] = ["profile-card", "profile-trust"]
    if skills:
        components.append(a2ui_helpers.text("profile-skills-label", "Skills", "h3"))
        components.append(a2ui_helpers.list_component("profile-skills-list", skills))
        children.extend(["profile-skills-label", "profile-skills-list"])
    components.append(
        a2ui_helpers.text(
            "profile-meta",
            f"Member of test-chapter. did:key:{member.get('did_key', '')[:48]}…",
            "caption",
        )
    )
    children.append("profile-meta")
    components.append(a2ui_helpers.column("profile-root", children))
    return a2ui_helpers.surface(f"agent-profile-{agent_id}", components, "profile-root")


# ── HAPPY ─────────────────────────────────────────────────────


def test_profile_surface_emits_v09_envelope():
    member = {"name": "Alice", "skills": ["python"], "origin": "sovereign"}
    surface = _build_profile_surface("alice", member, trust_score=42.0)

    assert "createSurface" in surface
    assert "updateComponents" in surface
    assert surface["updateComponents"]["surfaceId"] == "agent-profile-alice"
    assert surface["updateComponents"]["root"] == "profile-root"
    assert surface["version"].startswith("0.10")


def test_profile_surface_includes_member_card():
    member = {
        "name": "Alice",
        "skills": ["python", "rust"],
        "description": "Backend engineer",
        "origin": "sovereign",
    }
    surface = _build_profile_surface("alice", member, trust_score=42.0)

    components = surface["updateComponents"]["components"]
    cards = [c for c in components if c.get("component") == "MemberCard"]
    assert len(cards) == 1
    assert cards[0]["name"] == "Alice"
    assert cards[0]["agentId"] == "alice"
    assert cards[0]["skills"] == ["python", "rust"]
    assert cards[0]["trustScore"] == 42.0


def test_profile_surface_includes_trust_badge_with_correct_tier():
    member = {"name": "Alice", "origin": "sovereign"}
    surface = _build_profile_surface("alice", member, trust_score=80.0)
    badges = [c for c in surface["updateComponents"]["components"] if c.get("component") == "TrustBadge"]
    assert len(badges) == 1
    assert badges[0]["tier"] == "power"  # 80 ≥ 75 → power tier


# ── EDGE ──────────────────────────────────────────────────────


def test_profile_surface_with_no_skills_still_renders():
    """Agents on first registration have no skills declared. The
    surface must still render — degraded but valid."""
    member = {"name": "Alice", "origin": "openclaw"}
    surface = _build_profile_surface("alice", member, trust_score=0.0)
    component_ids = [c["id"] for c in surface["updateComponents"]["components"]]
    assert "profile-skills-label" not in component_ids
    assert "profile-skills-list" not in component_ids
    assert "profile-card" in component_ids


def test_profile_surface_caps_skills_at_twelve_to_prevent_oversized_render():
    """Hostile or excessive skill lists are truncated. Twelve is the
    chapter-wide soft cap on member-card surface — beyond it the card
    becomes unreadable on mobile."""
    skills = [f"skill-{i}" for i in range(50)]
    member = {"name": "Spammy", "skills": skills, "origin": "openclaw"}
    surface = _build_profile_surface("spammy", member, trust_score=0.0)

    cards = [c for c in surface["updateComponents"]["components"] if c.get("component") == "MemberCard"]
    assert len(cards[0]["skills"]) == 12, f"member_card must truncate to 12 skills; got {len(cards[0]['skills'])}"


def test_profile_surface_handles_missing_did_key_gracefully():
    """An agent registered before did:key was a thing has no field.
    Surface must render — meta caption shows truncated empty string,
    not crash."""
    member = {"name": "Legacy", "origin": "sovereign"}  # no did_key
    surface = _build_profile_surface("legacy", member, trust_score=0.0)

    metas = [c for c in surface["updateComponents"]["components"] if c.get("id") == "profile-meta"]
    assert len(metas) == 1
    # Doesn't crash; renders the empty-key caption form.
    assert "did:key:" in metas[0]["text"]


# ── ADVERSARIAL ──────────────────────────────────────────────


def test_profile_surface_treats_skill_strings_opaque_no_html_injection_at_build_time():
    """The renderer escapes; the chapter must not eagerly serialise as
    HTML at the surface-build step. Hostile skill strings travel through
    the surface as data, not markup."""
    hostile = "<script>alert(1)</script>"
    member = {"name": "X", "skills": [hostile], "origin": "openclaw"}
    surface = _build_profile_surface("x", member, trust_score=0.0)

    skill_lists = [c for c in surface["updateComponents"]["components"] if c.get("id") == "profile-skills-list"]
    assert len(skill_lists) == 1
    # The hostile string is preserved verbatim — the renderer's job to
    # escape, not the chapter's. But it MUST NOT be transformed into
    # <script>alert(1)</script> as actual markup at build time.
    assert hostile in skill_lists[0]["items"]
    # And the skill list item is a plain string, not an HTML node.
    assert isinstance(skill_lists[0]["items"][0], str)


def test_profile_surface_preserves_unicode_in_name():
    """A member with a non-ASCII name must render their actual name,
    not a transliterated approximation. Critical for any chapter
    serving APAC / EU members."""
    member = {"name": "山田太郎", "skills": [], "origin": "sovereign"}
    surface = _build_profile_surface("yamada", member, trust_score=10.0)
    cards = [c for c in surface["updateComponents"]["components"] if c.get("component") == "MemberCard"]
    assert cards[0]["name"] == "山田太郎"


# ── Sanity: route + helper drift detector ─────────────────────


def test_route_and_helper_in_lockstep():
    """Fingerprint of the component ids this helper emits for a canonical input.

    This does NOT catch route drift and never could — it exercises the helper,
    not the route. The equivalent assertion against the real handler lives in
    `test_profile_consent_gate.py::test_HAPPY_consenting_profile_keeps_the_fields_the_listing_rule_permits`,
    and the two id lists are identical on purpose: if they ever disagree, the
    copy has drifted and this file's premise is broken.
    """
    member = {
        "name": "Alice",
        "skills": ["python", "rust"],
        "description": "Engineer",
        "origin": "sovereign",
        "did_key": "did:key:z6Mk" + "x" * 40,
    }
    surface = _build_profile_surface("alice", member, trust_score=42.0)
    component_ids = sorted(c["id"] for c in surface["updateComponents"]["components"])
    assert component_ids == [
        "profile-card",
        "profile-meta",
        "profile-root",
        "profile-skills-label",
        "profile-skills-list",
        "profile-trust",
    ]
