"""The resolvable-card rule — the AI Catalog must only advertise card URLs backed by something.

``_member_catalog_entry()`` emitted a host39 URL for EVERY member whenever
``ORG_HOST39_CARD_BASE`` was set. Publishing a card is an explicit operator
trigger that registration deliberately does not fire, so the catalog
advertised a URL for every member who had ever registered, whether or not a card
was ever created. Measured live on the astrocity org 2026-08-02: **24 entries, 6
resolved, 18 returned 404** — all 18 test residue with no published card.

"The org has ``ORG_HOST39_CARD_BASE`` configured" is a fact about the ORG.
Whether THIS member's card exists is a different fact, and only the publisher
knows it. These tests pin that distinction.

The hermetic CI stack cannot observe this: the same run creates and checks every
entry, so residue cannot exist and the existing probe always passes. That is a
false green, not a flake — the check cannot see the condition. The live-catalog
canary (``.github/workflows/catalog-canary.yml``) is the one that can.

``routes.identity`` is imported inside a fixture, never at module scope:
``test_index_v2_registration`` reloads ``chapter_agent`` with importlib, and a
module-level import here would bind that module (and its ``ca`` reference) before
the reload, changing global import order for the whole session.
"""

from __future__ import annotations

import json
import types

import pytest

CARD_BASE = "https://cards.example.org/astrocity.org"
PUBLISHED = "2026-08-02T20:00:00+00:00"


@pytest.fixture
def identity():
    from routes import identity as _identity

    return _identity


@pytest.fixture
def org_with_card_base(monkeypatch):
    monkeypatch.setenv("ORG_HOST39_CARD_BASE", CARD_BASE)
    monkeypatch.setenv("ORG_AGENT_PREFIX", "astro-")
    return CARD_BASE


def _member(published: str | None = None, endpoint: str = "", **over) -> dict:
    from routes import identity as _identity

    m: dict = {"name": "Probe", "description": "", "endpoint": endpoint}
    if published is not None:
        m[_identity.ca.HOST39_PUBLISHED_AT] = published
    m.update(over)
    return m


# ── The failing-before case ──────────────────────────────────────────────────



def _verified_request(agent_id: str = "catalog-integrity-reader"):
    """The minimal Request this handler reads: a verified caller on request.state.

    the member-directory closure made the catalog withhold member entries from an unverified
    caller. These tests are about which members are OMITTED for want of a
    published card — a different question from who may see them — so they
    ask as somebody entitled to the entries.
    """
    return types.SimpleNamespace(state=types.SimpleNamespace(agent_id=agent_id))


def test_FAILING_BEFORE_unpublished_member_got_a_dead_url(identity, org_with_card_base):
    """Before the resolvable-card rule, a card base alone produced a URL like this one — the shape of all
    18 dead entries on the live org."""
    assert f"{CARD_BASE}/skill-proof-1.json".startswith(org_with_card_base)
    entry = identity._member_catalog_entry("astro-skill-proof-1", _member())
    assert entry is None, f"unpublished member with no endpoint must be OMITTED; got {entry}"


def test_unpublished_member_is_omitted_even_though_the_base_is_set(identity, org_with_card_base):
    assert identity._member_catalog_entry("astro-mem-proof-9", _member()) is None


def test_published_member_gets_the_host39_url(identity, org_with_card_base):
    """Publication state unlocks the URL — and the prefix still drops."""
    entry = identity._member_catalog_entry("astro-ceo", _member(published=PUBLISHED))
    assert entry is not None
    assert entry["url"] == f"{CARD_BASE}/ceo.json"
    assert entry["identifier"] == "astro-ceo"


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_publication_record_is_not_a_record(identity, org_with_card_base, blank):
    """A blank string in the config jsonb must not read as "published" — that
    would reintroduce the defect through the back door."""
    assert identity._member_catalog_entry("astro-x", _member(published=blank)) is None


# ── The self-serve path still works ─────────────────────────────────────


def test_unpublished_member_with_https_endpoint_uses_its_own_card(identity, org_with_card_base):
    """Priority 2: the member's own runtime serves a card, so advertise that."""
    entry = identity._member_catalog_entry("astro-selfhost", _member(endpoint="https://bob.example.org/"))
    assert entry["url"] == "https://bob.example.org/.well-known/agent.json"


def test_published_card_wins_over_the_self_served_one(identity, org_with_card_base):
    entry = identity._member_catalog_entry(
        "astro-both", _member(published=PUBLISHED, endpoint="https://bob.example.org")
    )
    assert entry["url"] == f"{CARD_BASE}/both.json"


@pytest.mark.parametrize("endpoint", ["", "   ", "ftp://x", "javascript:alert(1)", "not-a-url"])
def test_non_http_endpoints_never_reach_a_public_catalog_url(identity, org_with_card_base, endpoint):
    """The endpoint field is member-supplied text and goes into a public URL."""
    assert identity._member_catalog_entry("astro-y", _member(endpoint=endpoint)) is None


def test_no_card_base_falls_back_to_self_serve(identity, monkeypatch):
    """Pure self-hosters are unaffected by this change."""
    monkeypatch.delenv("ORG_HOST39_CARD_BASE", raising=False)
    entry = identity._member_catalog_entry("solo", _member(endpoint="https://solo.example.org"))
    assert entry["url"] == "https://solo.example.org/.well-known/agent.json"


# ── Omission must be visible, not silent ─────────────────────────────────────


async def test_catalog_reports_the_omitted_count(identity, org_with_card_base, monkeypatch):
    """A member silently absent is undiagnosable — the same defect class as a
    silently truncated read."""
    monkeypatch.setattr(
        identity.ca,
        "members",
        {
            "astro-ceo": _member(published=PUBLISHED),
            "astro-skill-proof-1": _member(),
            "astro-mem-proof-2": _member(),
        },
    )
    body = json.loads((await identity.ai_catalog(_verified_request())).body)

    assert body["omittedMembers"] == 2, body
    urls = [e["url"] for e in body["entries"]]
    assert f"{CARD_BASE}/ceo.json" in urls
    assert not any("skill-proof" in u or "mem-proof" in u for u in urls), (
        "an unpublished member's URL is still being advertised"
    )


async def test_omission_is_logged(identity, org_with_card_base, monkeypatch, capsys):
    monkeypatch.setattr(identity.ca, "members", {"astro-orphan": _member()})
    await identity.ai_catalog(_verified_request())
    assert "omitted" in capsys.readouterr().out


async def test_zero_omissions_reported_as_zero(identity, org_with_card_base, monkeypatch):
    """The field is always present, so a crawler can tell 0 from absent."""
    monkeypatch.setattr(identity.ca, "members", {"astro-ceo": _member(published=PUBLISHED)})
    body = json.loads((await identity.ai_catalog(_verified_request())).body)
    assert body["omittedMembers"] == 0
