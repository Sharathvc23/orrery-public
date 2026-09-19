"""`/api/agents/{id}/profile` serves only members who opted in (L1).

WHY THIS FILE EXISTS, AND WHY IT IS NEW RATHER THAN AN EDIT

Nothing in the suite exercised a successful profile fetch over HTTP.
``test_agent_profile_surface.py`` builds its assertions against
``_build_profile_surface`` — a helper hand-copied from the route into the test
file — so it asserts the shape of the COPY. Its ``test_route_and_helper_in_lockstep``
fingerprints that copy's component ids and asks reviewers to notice drift; it
cannot notice, because it never calls the route. The consent gate could
therefore have been added, or later removed, with that file green either way.

WHAT IS ASSERTED HERE

Against the real handler, over HTTP:

1. A consenting member's profile is served, unauthenticated — sharing the URL
   still works without an account, which is the point of the surface.
2. That profile carries NO member-authored prose. ``description`` was the card
   subtitle; an audit found an email address and a phone number inside one
   reaching an unauthenticated GET, and ``sm-listing 0.1`` §4.2 forbids member
   prose in a published entry.
3. A non-consenting member is INDISTINGUISHABLE from an id that never existed.
   This is the assertion that stops the fix from trading a disclosure for an
   oracle: if the two 404s differ in status, body or shape, membership is still
   enumerable and L1 is not closed, it has moved.
4. Consent is read strictly — a truthy string or a 1 is not an opt-in.
5. The route stays unauthenticated. The gate belongs in the handler, where it
   can read the member's decision; if it migrates to the middleware the surface
   stops being shareable at all.
"""

from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient

CONSENTING = "alice"
SILENT = "bob"
NEVER_REGISTERED = "nobody-at-all"

#: The exact string an audit found reaching an unauthenticated GET, in shape.
PROSE = "reach me at alice@example.com or +1-555-0100"


@pytest.fixture
def mod(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_ID", "TEST-fixture-chapter")
    monkeypatch.setenv("AGENT_NAME", "Fixture")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    sys.modules.pop("chapter_agent", None)
    return importlib.import_module("chapter_agent")


@pytest.fixture
def client(mod, monkeypatch) -> TestClient:
    async def _no_db(*_args, **_kwargs):
        return []

    monkeypatch.setattr(mod, "pg_request", _no_db)
    mod.members.clear()
    mod.members.update(
        {
            CONSENTING: {
                "name": "Alice",
                "description": PROSE,
                "skills": ["python", "rust"],
                "origin": "sovereign",
                "did_key": "did:key:z6Mk" + "x" * 40,
                "endpoint": "https://alice.example",
                # The opt-in, in the shape member_listing.consent_of accepts.
                "listing": {"listed": True, "agent_url": "https://alice.example"},
            },
            SILENT: {
                "name": "Bob",
                "description": PROSE,
                "skills": ["go"],
                "origin": "sovereign",
                "did_key": "did:key:z6Mk" + "y" * 40,
                "endpoint": "https://bob.example",
                # No "listing" key at all: the member never answered.
            },
        }
    )
    return TestClient(mod.app)


# ── the surface still works, for a member who agreed ──────────────────


def test_HAPPY_consenting_member_profile_is_served_without_credentials(client):
    r = client.get(f"/api/agents/{CONSENTING}/profile")
    assert r.status_code == 200, "a consenting member's URL must render for anyone"
    body = r.json()
    assert body["updateComponents"]["surfaceId"] == f"agent-profile-{CONSENTING}"


def test_HAPPY_consenting_profile_keeps_the_fields_the_listing_rule_permits(client):
    body = client.get(f"/api/agents/{CONSENTING}/profile").json()
    ids = sorted(c["id"] for c in body["updateComponents"]["components"])
    assert ids == [
        "profile-card",
        "profile-meta",
        "profile-root",
        "profile-skills-label",
        "profile-skills-list",
        "profile-trust",
    ]


# ── and it no longer publishes prose the member wrote ─────────────────


def test_ADVERSARIAL_consenting_profile_carries_no_member_authored_prose(client):
    """The C7 vector, asserted over the whole serialized payload.

    Checked against the raw response text rather than a named field so that
    re-introducing the description under ANY key — subtitle, a new bio field, a
    nested card property — fails this test.
    """
    raw = client.get(f"/api/agents/{CONSENTING}/profile").text
    assert PROSE not in raw
    assert "alice@example.com" not in raw
    assert "+1-555-0100" not in raw


# ── the gate, and the oracle it must not open ─────────────────────────


def test_ADVERSARIAL_member_who_never_opted_in_has_no_profile(client):
    assert client.get(f"/api/agents/{SILENT}/profile").status_code == 404


def test_ADVERSARIAL_silent_member_is_indistinguishable_from_a_stranger(client):
    """The assertion that decides whether L1 is closed or merely moved.

    If these two responses differ in any way a caller can observe, membership
    stays enumerable: probe an id, compare, learn whether that member exists.
    """
    silent = client.get(f"/api/agents/{SILENT}/profile")
    absent = client.get(f"/api/agents/{NEVER_REGISTERED}/profile")

    assert silent.status_code == absent.status_code == 404
    assert silent.json() == absent.json()
    assert silent.text == absent.text


def test_ADVERSARIAL_hidden_prefix_still_wins_over_consent(client, mod):
    """A TEST-* fixture that opted in must still be invisible."""
    mod.members["TEST-fixture"] = {
        "name": "Fixture",
        "skills": [],
        "listing": {"listed": True, "agent_url": "https://x.example"},
    }
    assert client.get("/api/agents/TEST-fixture/profile").status_code == 404


@pytest.mark.parametrize(
    "consent",
    [
        {"listed": "true"},
        {"listed": 1},
        {"listed": False},
        {"agent_url": "https://x.example"},
        "listed",
        None,
        [],
    ],
    ids=["str", "int", "false", "no-listed-key", "bare-string", "null", "list"],
)
def test_ADVERSARIAL_only_listed_is_True_counts_as_consent(client, mod, consent):
    """`consent_of` is strict on purpose — a permissive read of a consent flag is
    how a private-by-default field becomes public two years later."""
    mod.members[SILENT]["listing"] = consent
    assert client.get(f"/api/agents/{SILENT}/profile").status_code == 404


# ── the gate is in the handler, not the middleware ────────────────────


def test_the_route_remains_unauthenticated(mod):
    """Open means "no credential required to ASK". Whether there is anything to
    return is the member's decision — made in the handler, which can read it."""
    import auth_verify

    assert auth_verify.requires_auth("GET", f"/api/agents/{CONSENTING}/profile") is False
    assert auth_verify.is_open_path("GET", f"/api/agents/{CONSENTING}/profile") is True


# ── the documentation states the gate, and no longer points at the oracle ──


def _normalized(path: str) -> str:
    """The document as one line. Markdown prose here is hard-wrapped at ~80
    columns, so a phrase can straddle a line break; a substring check on the
    raw text would pass or fail on where the wrap happened to fall."""
    from pathlib import Path

    repo = Path(__file__).resolve().parents[2]
    return " ".join((repo / path).read_text().split())


def test_api_doc_states_the_consent_condition_and_no_membership_oracle():
    """docs/API.md told readers to use this route as the anonymous answer to
    "does this org know agent X?" — the membership oracle the gate closes. The
    same document must now carry the consent condition, because the reference
    is where an integrator learns that a 404 means "not opted in OR unknown"
    rather than "unknown"."""
    doc = _normalized("docs/API.md")
    assert 'For "does this org know agent X?" use the open `GET /api/agents/{agent_id}/profile`' not in doc, (
        "API.md still directs readers to the profile route as a membership oracle"
    )
    profile_row = doc[doc.index("| GET | `/api/agents/{id}/profile` |") :]
    profile_row = profile_row[: profile_row.index(" |", len("| GET | `/api/agents/{id}/profile` |")) + 2]
    assert "POST /api/me/listing" in profile_row, "the per-agent surfaces row must name the opt-in"
    assert "404" in profile_row, "the per-agent surfaces row must state the non-consent answer"


@pytest.mark.parametrize(
    ("path", "stale"),
    [
        ("README.md", "the joined agent's public profile"),
        ("docs/INSTALL.md", "your agent resolving at `/api/agents/<id>/profile`"),
        ("docs/MANUAL.md", "your agent's profile, and your agent's card"),
        ("docs/CLAIMS.md", "the joined agent's `/api/agents/<id>/profile`"),
    ],
)
def test_installer_docs_do_not_name_the_profile_as_a_drill_probe(path: str, stale: str):
    """The installer's sign-of-life drill polled the profile route and treated a
    200 as proof the agent had joined. It now reads the member count on /health
    (`test_installer_drill_uses_the_configured_bind_addresses` pins the probe
    list), and the installer's agent does not opt in, so a document that still
    lists the profile among the drill's probes describes a probe that would fail
    on a healthy install."""
    assert stale not in _normalized(path), f"{path} still lists the profile route as a drill probe"
