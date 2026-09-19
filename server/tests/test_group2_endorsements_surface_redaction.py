"""GET /api/surfaces/endorsements is a REDACTION, not a closure.

The page STAYS OPEN. It is one of auth_verify.PER_AGENT_SHAREABLE_SURFACES —
a page a member shares by URL — and gating it would remove a product
capability to fix a disclosure that redaction fixes without that cost.

What it disclosed: `test_read_surface_lockdown.py` justified the whole
shareable set as pages that disclose "its subject's agent_id and nothing
more". That is true of profile/reputation/trust/chronicle, whose subject
chose to share the page. It was NOT true of endorsements, which named a
THIRD PARTY — the endorser's agent_id, rendered as a heading, plus their
free-text note_markdown — and a subject cannot consent on an endorser's
behalf.

The redaction is the one already settled for the trust HISTORY, which is
this same relation reached by a different route: drop the identity fields,
add a single endorser_role derived from governance.get_chapter_role. Two
routes over one relation must not disagree.

WHY THE ASSERTIONS ARE AGAINST RESPONSE BYTES. Removing the ID FIELDS alone
does not close this class of defect — that is exactly what the trust-history
docstring claimed to do and did not, because endorsements.py:226 writes
reason=f"endorsed by {endorser_agent_id}" and :220 writes
source_event_id=f"endorsement:{endorser}:{endorsee}", embedding the raw id in
FREE TEXT. note_markdown is caller-authored and can contain anything at all.
A field-level check passes over every one of those, so these tests search the
serialized response instead.

SCOPE: the open A2UI surface only. The raw API,
GET /api/agents/{agent_id}/endorsements, is auth-gated and unchanged — a
signed member seeing full endorser detail is correct
(test_group2_endorsements_close.py).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests._admin_fixtures import reset_chapter_agent_module

TARGET = "g2surf-endorsee"
ENDORSER_LEADER = "g2surf-endorser-leader"
ENDORSER_PLAIN = "g2surf-endorser-plain"

#: Shaped like the real select list in endorsements.list_endorsements_received
#: (id, endorser_agent_id, endorser_did, note_markdown, created_at, revoked_at,
#: revocation_reason). The note and the revocation reason carry the endorser's
#: raw id on purpose: they are free text, and free text is the path a
#: field-level redaction misses.
RAW_ROWS = [
    {
        "id": "row-1",
        "endorser_agent_id": ENDORSER_LEADER,
        "endorser_did": f"did:key:z6Mk{ENDORSER_LEADER}",
        "note_markdown": f"Great collaborator — {ENDORSER_LEADER} vouches personally.",
        "created_at": "2026-01-01T00:00:00Z",
        "revoked_at": None,
        "revocation_reason": None,
    },
    {
        "id": "row-2",
        "endorser_agent_id": ENDORSER_PLAIN,
        "endorser_did": f"did:key:z6Mk{ENDORSER_PLAIN}",
        "note_markdown": "",
        "created_at": "2026-02-02T00:00:00Z",
        "revoked_at": None,
        "revocation_reason": None,
    },
    {
        # An endorsement whose endorser id did not survive on the row. It must
        # read "unknown" — get_chapter_role answers "member" for an id it
        # cannot resolve, which is a DEFAULT, not a fact, and rendering it here
        # would claim a member endorsed this agent when nobody knows who did.
        "id": "row-3",
        "endorser_agent_id": None,
        "endorser_did": None,
        "note_markdown": None,
        "created_at": "2026-03-03T00:00:00Z",
        "revoked_at": None,
        "revocation_reason": None,
    },
]

ROLES = {ENDORSER_LEADER: "leader", ENDORSER_PLAIN: "member"}


@pytest.fixture
def client(monkeypatch):
    mod = reset_chapter_agent_module(monkeypatch)

    import endorsements as endorsements_mod
    import governance

    async def fake_list_endorsements_received(agent_id, *, include_revoked=False, limit=50):
        assert agent_id == TARGET
        return [dict(r) for r in RAW_ROWS]

    async def fake_get_chapter_role(agent_id):
        # The builder must never ask about an absent endorser — that is the
        # call whose "member" default would become a false claim.
        assert agent_id, "get_chapter_role was called with an empty endorser id"
        return ROLES.get(agent_id, "member")

    monkeypatch.setattr(endorsements_mod, "list_endorsements_received", fake_list_endorsements_received)
    monkeypatch.setattr(governance, "get_chapter_role", fake_get_chapter_role)
    return TestClient(mod.app)


def _surface(client) -> tuple[dict, str]:
    resp = client.get(f"/api/surfaces/endorsements?target={TARGET}")
    assert resp.status_code == 200, resp.text
    return resp.json(), resp.text


# ---------------------------------------------------------------------------
# G1 — the wire guard, asserted against response BYTES
# ---------------------------------------------------------------------------


def test_endorsements_surface_discloses_no_third_party_identity(client) -> None:
    """THE GUARD. No endorser agent_id, no endorser did, no note_markdown, and
    no free text embedding an endorser id survives to the wire."""
    _body, raw = _surface(client)

    assert ENDORSER_LEADER not in raw, "endorser agent_id reached an unauthenticated caller"
    assert ENDORSER_PLAIN not in raw, "endorser agent_id reached an unauthenticated caller"
    assert "did:key:" not in raw, "endorser did reached an unauthenticated caller"
    assert "vouches personally" not in raw, "endorser-authored note_markdown reached the wire"
    assert "endorsed by " not in raw.lower(), (
        "the free-text form of the endorser id (endorsements.py:226) reached the wire"
    )


def test_endorsements_surface_still_names_its_own_subject(client) -> None:
    """The redaction is of the THIRD PARTY, not of the subject. A per-agent
    page that no longer names its own agent is a broken page, not a private
    one — this is the boundary that keeps the fix from over-reaching."""
    _body, raw = _surface(client)
    assert TARGET in raw


def test_endorsements_surface_keeps_its_content(client) -> None:
    """A redaction that empties the page would be a regression wearing a
    fix's clothes. The count and one dated row per endorsement survive."""
    body, _raw = _surface(client)
    rendered = _all_text(body)
    assert any("3 endorsements received" in t for t in rendered), rendered
    assert any("2026-01-01" in t for t in rendered), rendered
    assert any("2026-03-03" in t for t in rendered), rendered


# ---------------------------------------------------------------------------
# G3 — endorser_role is derived, and an unknown endorser reads as unknown
# ---------------------------------------------------------------------------


def test_endorser_role_is_present_and_derived(client) -> None:
    """The replacement signal: 'a leader vouched for this agent' is materially
    different from 'a peer member did', which dropping the endorser outright
    would have lost. Derived per render from governance.get_chapter_role —
    nothing role-shaped is stored on the endorsements row."""
    body, _raw = _surface(client)
    rendered = _all_text(body)
    assert any("Endorser role: leader" in t for t in rendered), rendered
    assert any("Endorser role: member" in t for t in rendered), rendered


def test_unknown_endorser_reads_as_unknown_not_as_the_default_role(client) -> None:
    """governance.get_chapter_role returns 'member' for any id it cannot
    resolve. The row with no endorser must NOT pick that up — 'member' there
    would assert a fact nobody has. The fixture's get_chapter_role asserts it
    is never called with an empty id, so this fails loudly either way."""
    body, _raw = _surface(client)
    rendered = _all_text(body)
    assert any("Endorser role: unknown" in t for t in rendered), rendered
    assert sum("Endorser role: member" in t for t in rendered) == 1, (
        "an unresolvable endorser was rendered as the 'member' default"
    )


def test_role_lookup_is_batched_per_unique_endorser(monkeypatch) -> None:
    """Two endorsements from the same peer cost one role lookup, matching
    _redact_trust_history's batching. Asserted because the natural
    per-row rewrite of this builder issues one DB read per row."""
    import asyncio

    import endorsements as endorsements_mod
    import governance
    import surfaces

    calls: list[str] = []

    async def fake_list_endorsements_received(agent_id, *, include_revoked=False, limit=50):
        return [dict(RAW_ROWS[0]), dict(RAW_ROWS[0]), dict(RAW_ROWS[1])]

    async def counting_get_chapter_role(agent_id):
        calls.append(agent_id)
        return ROLES.get(agent_id, "member")

    monkeypatch.setattr(endorsements_mod, "list_endorsements_received", fake_list_endorsements_received)
    monkeypatch.setattr(governance, "get_chapter_role", counting_get_chapter_role)

    asyncio.run(surfaces.build_endorsements_surface(TARGET))
    assert sorted(calls) == sorted({ENDORSER_LEADER, ENDORSER_PLAIN}), calls


# ---------------------------------------------------------------------------
# G2 — the page is still open. Asserted here too, next to the redaction that
# is the reason it can be, so a future pass that removes the redaction sees
# both halves of the trade in one file.
# ---------------------------------------------------------------------------


def test_endorsements_surface_stays_open() -> None:
    """The ruling was KEEP IT OPEN, redact the third party — not gate it.
    test_read_surface_lockdown.test_public_per_agent_surfaces_stay_open holds
    the same line from the classification side."""
    import auth_verify

    assert auth_verify.requires_auth("GET", "/api/surfaces/endorsements") is False
    assert "endorsements" in auth_verify.PER_AGENT_SHAREABLE_SURFACES


def test_unauthenticated_get_is_answered(client) -> None:
    """Over the wire, with no signature at all: 200, not 401."""
    resp = client.get(f"/api/surfaces/endorsements?target={TARGET}")
    assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# Scope — the gated raw API is untouched
# ---------------------------------------------------------------------------


def test_raw_endorsements_api_stays_gated() -> None:
    """Closing the raw API is not weakened by keeping a redacted view open: a
    signed member reading full endorser detail is the endorsement feature
    working, and that read stays behind a signature."""
    import auth_verify

    assert auth_verify.requires_auth("GET", f"/api/agents/{TARGET}/endorsements") is True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_text(body: dict) -> list[str]:
    """Every string in the A2UI document, flattened. Used only by the
    CONTENT assertions; the disclosure guards read the raw bytes instead."""
    out: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        elif isinstance(node, str):
            out.append(node)

    walk(body)
    return out
