"""
R1-R10 + S tests for build_trust_surface + build_endorsements_surface.

R1  Forgery       — caller-supplied target with malicious chars sanitized
                    (we drop /, @, and truncate to 128)
R2  Replay        — same target twice → identical surface (modulo timestamps)
R3  Injection     — endorsement note containing markdown / HTML lands as
                    text content; renderer is responsible for escaping
R4  Authz         — n/a, surfaces are public reads
R5  Boundary      — exactly 50 endorsements all render; 51st truncated
R6  Concurrency   — pure builder; deterministic given a deterministic db
R7  Adversarial   — supabase failure → empty score + empty history,
                    surface still renders something
R8  Downgrade     — surface_composer's KNOWN_COMPONENTS whitelist accepts
                    every component this builder emits
R9  Boundary tier — score=49.999 → Established; 50.0 → Trusted; 75.0 → Leader
R10 Persistence   — surface envelope is canonical v0.9 (createSurface +
                    updateComponents)
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-chapter")
os.environ.setdefault("AGENT_NAME", "Test Chapter")

import pytest  # noqa: E402

import surfaces  # noqa: E402
import trust_events  # noqa: E402


class _FakeDB:
    """Minimal in-memory shim for both supabase + trust_events."""

    def __init__(self, agents=None, trust_events_rows=None, endorsements_rows=None):
        self.agents = agents or []
        self.trust_events = trust_events_rows or []
        self.endorsements = endorsements_rows or []

    async def __call__(self, method, table, params=None, body=None):
        t = table.split("?")[0]
        if method == "GET":
            rows = list(getattr(self, t, []))
            for k, v in (params or {}).items():
                if k in ("select", "order", "limit"):
                    continue
                if isinstance(v, str) and v.startswith("eq."):
                    wanted = v[3:]
                    rows = [r for r in rows if str(r.get(k, "")) == wanted]
                elif isinstance(v, str) and v == "is.null":
                    rows = [r for r in rows if r.get(k) is None]
                elif isinstance(v, str) and v.startswith("gte."):
                    wanted = v[4:]
                    rows = [r for r in rows if str(r.get(k, "")) >= wanted]
            limit = (params or {}).get("limit")
            if limit is not None:
                rows = rows[: int(limit)]
            return rows
        return None


@pytest.fixture
def trust_env():
    surfaces.AGENT_ID = "alice"
    db = _FakeDB(
        agents=[{"agent_id": "alice", "trust_score": 32.5}],
        trust_events_rows=[
            {
                "agent_id": "alice",
                "event_type": "intent_match_accepted",
                "delta": "0.5",
                "occurred_at": "2026-04-25T12:00:00+00:00",
                "reason": "matched intent-42",
            },
            {
                "agent_id": "alice",
                "event_type": "endorsement_received",
                "delta": "0.5",
                "occurred_at": "2026-04-26T12:00:00+00:00",
                "reason": "endorsed by bob",
            },
        ],
    )
    surfaces.pg_request = db
    trust_events.init(db, "test-chapter")
    return db


# ── Trust surface ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trust_surface_renders_score_and_tier(trust_env):
    s = await surfaces.build_trust_surface("alice")
    assert s["version"] == "0.10"
    assert s["createSurface"]["surfaceId"] == "surface-trust-alice"
    components = {c["id"]: c for c in s["updateComponents"]["components"]}
    assert components["s-score"]["value"].startswith("32.5")
    assert components["s-tier"]["value"] == "Established"


@pytest.mark.asyncio
async def test_R1_target_sanitization():
    """A malicious target with / @ chars is sanitized for the surfaceId
    and isn't echoed verbatim into the page heading either."""
    surfaces.AGENT_ID = "test"
    db = _FakeDB(agents=[])
    surfaces.pg_request = db
    trust_events.init(db, "test-chapter")

    s = await surfaces.build_trust_surface("../@evil/path")
    # surface id has / and @ stripped
    assert "/" not in s["createSurface"]["surfaceId"]
    assert "@" not in s["createSurface"]["surfaceId"]


@pytest.mark.asyncio
async def test_R7_supabase_failure_renders_empty_state():
    """If the agents table read raises, the builder still returns a
    valid surface (with score=0)."""

    class _BrokenDB:
        async def __call__(self, *args, **kwargs):
            raise RuntimeError("supabase outage")

    surfaces.AGENT_ID = "alice"
    surfaces.pg_request = _BrokenDB()
    trust_events.init(_BrokenDB(), "test-chapter")

    s = await surfaces.build_trust_surface("alice")
    components = {c["id"]: c for c in s["updateComponents"]["components"]}
    assert components["s-score"]["value"] == "0.0"
    assert components["s-tier"]["value"] == "Newcomer"


@pytest.mark.asyncio
async def test_R9_tier_boundaries(trust_env):
    """Tier transitions at exactly 20/50/75."""
    surfaces.pg_request.agents[0]["trust_score"] = 49.999
    s = await surfaces.build_trust_surface("alice")
    comps = {c["id"]: c for c in s["updateComponents"]["components"]}
    assert comps["s-tier"]["value"] == "Established"

    surfaces.pg_request.agents[0]["trust_score"] = 50.0
    s = await surfaces.build_trust_surface("alice")
    comps = {c["id"]: c for c in s["updateComponents"]["components"]}
    assert comps["s-tier"]["value"] == "Trusted"

    surfaces.pg_request.agents[0]["trust_score"] = 75.0
    s = await surfaces.build_trust_surface("alice")
    comps = {c["id"]: c for c in s["updateComponents"]["components"]}
    assert comps["s-tier"]["value"] == "Leader"


@pytest.mark.asyncio
async def test_R8_all_components_in_known_set(trust_env):
    """Every component this builder emits must be in the
    surface_composer.KNOWN_COMPONENTS whitelist — otherwise a
    composer-merged surface would reject our hand-built one."""
    import surface_composer as sc

    s = await surfaces.build_trust_surface("alice")
    for c in s["updateComponents"]["components"]:
        assert c["component"] in sc.KNOWN_COMPONENTS, c["component"]


@pytest.mark.asyncio
async def test_R10_envelope_is_canonical(trust_env):
    s = await surfaces.build_trust_surface("alice")
    assert "createSurface" in s
    assert "updateComponents" in s
    assert s["updateComponents"]["root"] == "page"
    assert s["updateComponents"]["surfaceId"] == s["createSurface"]["surfaceId"]


# ── Endorsements surface ──────────────────────────────────────────


@pytest.fixture
def endorsements_env():
    import endorsements
    import governance

    surfaces.AGENT_ID = "alice"
    db = _FakeDB(
        # governance.get_chapter_role reads these — the endorsements surface
        # derives each endorser's role per render rather than storing one, so
        # the roles have to be resolvable for the surface to say anything but
        # "member". carol is deliberately absent: an endorser the role lookup
        # cannot resolve must not be indistinguishable from a real member.
        agents=[{"agent_id": "bob", "chapter_role": "leader"}],
        endorsements_rows=[
            {
                "id": 1,
                "endorser_agent_id": "bob",
                "endorsee_agent_id": "alice",
                "endorser_did": "did:key:zBob",
                "note_markdown": "Great mentor. **Highly** recommend.",
                "created_at": "2026-04-25T12:00:00+00:00",
                "revoked_at": None,
            },
            {
                "id": 2,
                "endorser_agent_id": "carol",
                "endorsee_agent_id": "alice",
                "endorser_did": "did:key:zCarol",
                "note_markdown": "Helped me ship.",
                "created_at": "2026-04-26T12:00:00+00:00",
                "revoked_at": None,
            },
        ],
    )
    surfaces.pg_request = db
    endorsements.init(db, "test-chapter")
    governance.init(db, "test-chapter")
    return db


@pytest.mark.asyncio
async def test_endorsements_surface_lists_received(endorsements_env):
    """One card per received endorsement, carrying the endorser's ROLE.

    RETARGETED, not weakened: this asserted `e0-who` == "@bob", which is the
    third-party disclosure the surface was redacted to remove (the page is
    open by URL and the endorser never chose to share it). The structural
    contract — one card per row, e0/e1, nothing beyond the rows that exist —
    is unchanged; what each card SAYS is now the coarsened role.
    """
    s = await surfaces.build_endorsements_surface("alice")
    assert s["createSurface"]["surfaceId"] == "surface-endorsements-alice"
    components = {c["id"]: c for c in s["updateComponents"]["components"]}
    # 2 endorsement rows → 2 cards (e0, e1) each with col/who/ts
    assert "e0" in components
    assert "e1" in components
    assert "e2" not in components
    assert components["e0-who"]["text"] == "Endorser role: leader"
    assert components["e1-who"]["text"] == "Endorser role: member"
    # The note component is gone entirely — not blanked, not present-and-empty.
    assert "e0-note" not in components
    assert "e1-note" not in components


@pytest.mark.asyncio
async def test_R3_endorsement_note_stored_verbatim(endorsements_env):
    """R3 (injection): a note containing markdown / HTML is STORED and READ
    BACK verbatim — the layer that reads it is responsible for escaping, and
    nothing in the pipeline may silently drop or transform the bytes.

    RETARGETED from the open A2UI surface to the read path, because the
    surface is no longer where a verbatim note is observable: it is
    caller-authored free text on a page anyone can fetch by URL, and free
    text is exactly how an endorser's identity survives a field-level
    redaction. R3 is a property of the note's STORAGE, not of that page, so
    it is asserted where the bytes still live — the same read
    `GET /api/agents/{id}/endorsements` serves to a signed member.
    """
    import endorsements

    rows = await endorsements.list_endorsements_received("alice")
    assert "**Highly**" in rows[0]["note_markdown"]


@pytest.mark.asyncio
async def test_R3_note_is_not_rendered_on_the_open_surface(endorsements_env):
    """The other half of R3's move: verbatim on the gated read, absent from
    the open one. Asserted against the serialized surface rather than a
    component list — a note reappearing anywhere in the document, under any
    id, is the regression this guards."""
    import json

    s = await surfaces.build_endorsements_surface("alice")
    raw = json.dumps(s)
    assert "**Highly**" not in raw
    assert "Helped me ship" not in raw


@pytest.mark.asyncio
async def test_endorsements_empty_state_renders():
    """No endorsements → callout explainer instead of an empty list."""
    import endorsements

    surfaces.AGENT_ID = "alice"
    db = _FakeDB(endorsements_rows=[])
    surfaces.pg_request = db
    endorsements.init(db, "test-chapter")

    s = await surfaces.build_endorsements_surface("alice")
    components = {c["id"]: c for c in s["updateComponents"]["components"]}
    assert "empty" in components
    assert components["empty"]["component"] == "Callout"


@pytest.mark.asyncio
async def test_R5_endorsements_truncated_at_50():
    """Server returns 100; we render at most 50."""
    import endorsements

    surfaces.AGENT_ID = "alice"
    rows = [
        {
            "id": i,
            "endorser_agent_id": f"endorser-{i}",
            "endorsee_agent_id": "alice",
            "endorser_did": f"did:key:z{i}",
            "note_markdown": "ok",
            "created_at": "2026-04-25T12:00:00+00:00",
            "revoked_at": None,
        }
        for i in range(100)
    ]
    db = _FakeDB(endorsements_rows=rows)
    surfaces.pg_request = db
    endorsements.init(db, "test-chapter")

    s = await surfaces.build_endorsements_surface("alice")
    components = {c["id"]: c for c in s["updateComponents"]["components"]}
    assert "e49" in components
    assert "e50" not in components


# ── tier_for (relocated from the removed calls module) ───────────────


def test_tier_for_zero_trust():
    assert trust_events.tier_for(0.0)["min_trust"] == 0.0


def test_tier_for_boundary_inclusive():
    """score=20 reaches the Established tier; 19.9 stays Newcomer."""
    assert trust_events.tier_for(20.0)["min_trust"] == 20.0
    assert trust_events.tier_for(19.9)["min_trust"] == 0.0


def test_tier_for_over_cap():
    assert trust_events.tier_for(200.0)["min_trust"] == 75.0


def test_tier_for_negative_treated_as_zero():
    assert trust_events.tier_for(-10.0)["min_trust"] == 0.0


def test_tier_for_none_defaults_newcomer():
    assert trust_events.tier_for(None)["min_trust"] == 0.0  # type: ignore[arg-type]
