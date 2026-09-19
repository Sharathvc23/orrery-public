"""sm-listing 0.1 — consented discovery, and the two halves of §3.

The Listing is a **different resource over a different population**, not a filter
over the Directory. `L1` asserts that structurally, because "it's just the
directory with a WHERE clause" is the shape that would quietly reinstate the enumeration closure.

**§3 binds both ways, and the second half is the trap.** A non-consenting member
must be ABSENT — but an empty listing trivially contains no non-consenting
member, so a node that dropped everyone would be maximally conformant while
delivering nothing. So every absence assertion here is paired with a POPULATED
one: `A1` (absent) is worthless without `P1` (present), and `P3` asserts the
builder RAISES rather than skipping an entry it cannot publish, which is that
failure made loud.

Per the G-series, the consent check is asserted **present** as well as firing:
`C4` reads the source, because a listing gains paths — a cache warmer, an export,
a second endpoint — and a check that lives in the serialiser protects only the
paths someone remembered.
"""

from __future__ import annotations

import importlib
import json
import sys

import pytest
import sm_listing
from fastapi.testclient import TestClient

import member_listing

_ORG = "TEST-listing-org"


def _member(endpoint="https://napa.example", **consent):
    """A member row as the loader builds it, with an optional consent record."""
    row = {
        "name": "Napa Winery",
        "description": "Contact owner@napa.example +1-707-555-0142",  # the trap the Listing must not repeat
        "skills": ["wine", "viticulture"],
        "endpoint": endpoint,
    }
    if consent:
        row[member_listing.CONSENT_KEY] = consent
    return row


@pytest.fixture
def app_module(monkeypatch):
    monkeypatch.setenv("AGENT_ID", _ORG)
    monkeypatch.setenv("AGENT_NAME", "Listing Org")
    sys.modules.pop("chapter_agent", None)
    mod = importlib.import_module("chapter_agent")
    monkeypatch.setattr(mod, "PUBLIC_URL", "https://listing-org.example")
    return mod


@pytest.fixture
def client(app_module, monkeypatch) -> TestClient:
    """A client for an org that IMPLEMENTS the profile.

    Enabled explicitly: the default is off, because a node that does not
    implement the profile must not serve the path at all (§ — 404, never an empty
    document). `E1`/`E2` are the tests that exercise the default.
    """
    monkeypatch.setenv(member_listing.ENABLED_FLAG, "true")
    app_module._rate_limit_store.clear()
    return TestClient(app_module.app)


def _build(members):
    return member_listing.build(members, community_id=_ORG, generated_at="2026-08-09T00:00:00+00:00")


# ---------------------------------------------------------------------------
# L — a different resource over a different population
# ---------------------------------------------------------------------------


def test_L1_the_listing_is_not_the_directory_with_a_filter(app_module) -> None:
    """The Directory stays gated; the Listing is open. If the Listing were a
    filtered view of the same population, turning it on would re-open the roster
    that the enumeration closure closed — an unbounded filter is the roster again, slower."""
    import auth_verify

    assert auth_verify.requires_auth("GET", "/api/members") is True, "the directory stopped being gated"
    assert auth_verify.is_open_path("GET", member_listing.LISTING_PATH) is True
    assert member_listing.LISTING_PATH not in auth_verify.REQUIRE_AUTH_GET_PATHS


def test_L2_the_default_state_is_an_empty_listing(client) -> None:
    """A community that enables the profile with nobody opted in publishes an
    empty document forever. That is correct, not a misconfiguration."""
    doc = client.get(member_listing.LISTING_PATH).json()

    assert doc["entries"] == []
    ok, reason = sm_listing.validate_listing(doc)
    assert ok, reason


# ---------------------------------------------------------------------------
# A — absence, and no count of it
# ---------------------------------------------------------------------------


def test_A1_a_member_who_did_not_opt_in_is_ABSENT(app_module) -> None:
    doc = _build({"quiet": _member(), "also-quiet": _member(listed=False)})

    assert doc["entries"] == []
    assert "quiet" not in json.dumps(doc)


def test_A2_no_count_of_the_non_consenting_exists_anywhere(app_module) -> None:
    """Not withheld — ABSENT. A present-but-opaque row in an enumeration is a
    census of the non-consenting: it publishes the one fact they declined to
    publish, which is that they are there. And a count computed and then withheld
    is one refactor from being emitted, so none is computed.

    `omittedMembers` in the AI catalog is the resolvable-card rule's no-resolvable-card count and is
    NOT a consent signal; the two must not be confused, which is why the
    published validator refuses the field outright.
    """
    doc = _build({"listed-one": _member(listed=True), "quiet": _member(), "also-quiet": _member()})

    body = json.dumps(doc)
    for forbidden in ("omitted", "hidden", "excluded", "withheld", "member_count", "total"):
        assert forbidden not in body.lower(), f"the listing carries {forbidden!r} — a census of the non-consenting"
    ok, reason = sm_listing.validate_listing(doc)
    assert ok, reason
    assert len(doc["entries"]) == 1, "and the consenting member is still there — see P1"


def test_A3_the_published_validator_refuses_a_count(app_module) -> None:
    """The rule is the profile's, not ours. Asserting our own output alone would
    not catch a future field named something we did not think to grep for."""
    doc = _build({"listed-one": _member(listed=True)})
    doc["omitted_members"] = 2

    ok, reason = sm_listing.validate_listing(doc)
    assert not ok
    assert "census" in reason


# ---------------------------------------------------------------------------
# P — presence: the half an empty listing satisfies trivially
# ---------------------------------------------------------------------------


def test_P1_a_consenting_member_APPEARS(app_module) -> None:
    """Without this, every absence assertion above is satisfied by a listing that
    publishes nobody — maximally conformant, delivering nothing."""
    doc = _build({"napa": _member(listed=True), "quiet": _member()})

    assert [e["subject"] for e in doc["entries"]] == ["napa"]
    assert doc["entries"][0]["agent_url"] == "https://napa.example"


def test_P2_only_the_fields_the_member_chose(app_module) -> None:
    """Per-FIELD consent: an unconsented field is absent from the entry and the
    row is NOT hidden for it — `contact_public`'s rule, not
    `profiles.is_public`'s."""
    doc = _build({"napa": _member(listed=True, geo={"country": "US", "region": "US-CA"})})

    entry = doc["entries"][0]
    assert entry["geo"] == {"country": "US", "region": "US-CA"}
    for unchosen in ("offering", "trade", "did"):
        assert unchosen not in entry, f"{unchosen} was published without being chosen"


def test_P3_an_unpublishable_entry_RAISES_rather_than_being_skipped(app_module) -> None:
    """§3's presence half made loud. A silent skip would leave a consenting member
    absent — and would make the listing MORE conformant against the absence rule
    the less it contained, which is exactly what a one-directional safety property
    rewards."""
    with pytest.raises(ValueError, match="cannot be published"):
        _build({"napa": _member(endpoint="", listed=True)})


def test_P4_the_endpoint_answers_500_rather_than_a_quiet_partial_listing(client, app_module) -> None:
    """The route does not catch-and-continue. A 200 with the member missing is
    the failure this whole design exists to prevent, so the surface fails loudly
    and names it."""
    app_module.members["napa"] = _member(endpoint="", listed=True)
    try:
        resp = client.get(member_listing.LISTING_PATH)
    finally:
        app_module.members.pop("napa", None)

    assert resp.status_code == 500
    assert resp.json()["error"] == "listing_entry_unpublishable"
    assert "silently omitted" in resp.json()["hint"]


# ---------------------------------------------------------------------------
# C — consent: default private, strict, and decided in one place
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("stored", [None, {}, {"listed": False}, {"listed": "true"}, {"listed": 1}, "yes"])
def test_C1_only_an_explicit_true_is_consent(app_module, stored) -> None:
    """A truthy string, a 1, or a stray dict are all "probably yes" readings of a
    field whose whole job is to be unambiguous. `profiles.is_public` is what a
    permissive reading looks like after two years — `DEFAULT true NOT NULL`, and
    selected without ever being consulted."""
    member = _member()
    if stored is not None:
        member[member_listing.CONSENT_KEY] = stored

    assert member_listing.consent_of(member) is None
    assert _build({"m": member})["entries"] == []


def test_C2_the_opt_in_is_self_signed_and_defaults_to_not_listed(client, app_module) -> None:
    anon = client.post("/api/me/listing", json={"listed": True})

    assert anon.status_code == 401, "an unsigned caller could list somebody"


def test_C3_consent_is_refused_when_it_could_not_be_honoured(app_module) -> None:
    """"Consenting implies publishable" is kept true by construction. Otherwise a
    member consents, the next build raises, and a stranger reading the listing
    gets the 500 instead of the person who could fix it."""
    ok, reason = member_listing.validate_consent_request({"listed": True}, {"endpoint": ""})
    assert not ok and "agent endpoint" in reason

    ok, reason = member_listing.validate_consent_request({"listed": True}, {"endpoint": "https://a.example"})
    assert ok, reason


def test_C4_the_consent_check_is_PRESENT_at_the_layer_that_owns_it(app_module) -> None:
    """Present, not merely firing. A listing gains paths — a cache warmer, an
    export, a second endpoint — and a check in whatever happens to serialise
    protects only the paths someone remembered. The filter lives in
    `consenting_entries`, so every caller inherits it."""
    import inspect

    src = inspect.getsource(member_listing.consenting_entries)
    assert "consent_of(member)" in src and "continue" in src, "the drop no longer happens in the owning layer"

    # Asserted on the CALLS the route makes, not on the word "consent" appearing
    # in it. A text scan cannot tell a decision from prose: the route's docstring
    # explains the consent model and its error hint says "a member consented…",
    # and both were reported as the defect by earlier versions of this assertion.
    # Third time the same trap has appeared and the first where
    # stripping comments was not enough, because the offender was a user-facing
    # string. The property is "this function does not decide", so look at what it
    # calls.
    import ast

    tree = ast.parse(inspect.getsource(importlib.import_module("chapter_agent").agent_listing).strip())
    called = {
        node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }

    assert "build" in called, "the route no longer delegates to member_listing.build"
    for decision in ("consent_of", "consenting_entries", "entry_for"):
        assert decision not in called, (
            f"the route calls {decision} — the consent decision must live in the layer that owns "
            "the preference, or a second endpoint will have to remember to make it too"
        )


# ---------------------------------------------------------------------------
# H — no human contact details, ever
# ---------------------------------------------------------------------------


def test_H1_the_contact_route_is_the_agent_endpoint(app_module) -> None:
    """An audit put an email and a phone number in a member's description and both
    came back to an unauthenticated GET. The Listing must not become the consented
    version of that — so the entry carries the AGENT ENDPOINT and no prose."""
    doc = _build({"napa": _member(listed=True)})

    body = json.dumps(doc)
    assert "owner@napa.example" not in body
    assert "555-0142" not in body
    assert "description" not in body
    assert doc["entries"][0]["agent_url"] == "https://napa.example"


def test_H2_a_member_cannot_smuggle_contact_details_through_consent(app_module) -> None:
    """The consent record is not a free-form blob that reaches the wire. The
    published validator refuses §4.1 fields, and the opt-in is checked against it
    at the moment it is made."""
    ok, reason = member_listing.validate_consent_request({"listed": True, "email": "x@y.example"}, _member())

    assert not ok
    assert "email" in reason or "does not define" in reason


# ---------------------------------------------------------------------------
# E — the path is a CLAIM: implement it or do not serve it
# ---------------------------------------------------------------------------


def test_E1_the_mandatory_path_comes_from_the_package(app_module) -> None:
    """sm-listing 0.3.0 made the path normative and exports it. Taking the
    constant rather than restating the string is what stops the shared-constant change's choice
    — made before the path existed — from silently outliving the profile."""
    assert member_listing.LISTING_PATH == sm_listing.WELL_KNOWN_PATH
    assert member_listing.LISTING_PATH == "/.well-known/agent-community-listing.json"


def test_E2_the_old_orrery_path_is_GONE_not_aliased(app_module, monkeypatch) -> None:
    """the shared-constant change served /.well-known/agent-listing.json. It is removed, not
    redirected: there is one deployment, it is not public, and an alias is a
    second URL for one resource whose precedence somebody would later have to
    work out."""
    monkeypatch.setenv(member_listing.ENABLED_FLAG, "true")
    resp = TestClient(app_module.app).get("/.well-known/agent-listing.json")

    assert resp.status_code == 404


def test_E3_a_node_that_does_not_implement_the_profile_404s(app_module, monkeypatch) -> None:
    """NOT an empty document. The path is a claim: an empty listing says "I run
    this surface and nobody opted in", which is a different and more useful fact
    than silence."""
    monkeypatch.delenv(member_listing.ENABLED_FLAG, raising=False)
    resp = TestClient(app_module.app).get(member_listing.LISTING_PATH)

    assert resp.status_code == 404
    assert resp.json()["error"] == "listing_profile_not_implemented"


def test_E4_an_ENABLED_org_with_nobody_opted_in_serves_an_EMPTY_listing(client) -> None:
    """⚠️ THE TRAP, stated as an assertion so nobody later "fixes" it: an org
    that implements the profile and has no consenting members serves an EMPTY
    listing and that is CONFORMANT. There is deliberately NO assertion anywhere
    in this file that a listing must have members — that would fail a correctly
    consented empty org, which is the degrade trap in a new costume."""
    resp = client.get(member_listing.LISTING_PATH)

    assert resp.status_code == 200
    doc = resp.json()
    assert doc["entries"] == []
    ok, reason = sm_listing.validate_listing(doc)
    assert ok, reason


def test_E5_the_enable_flag_defaults_OFF(app_module, monkeypatch) -> None:
    """Publishing a discovery surface at all is a decision somebody makes, not
    one they inherit — the same reasoning as the member-level opt-in one level
    down. Unrecognised spellings are "not a decision" and keep the default."""
    monkeypatch.delenv(member_listing.ENABLED_FLAG, raising=False)
    assert member_listing.is_enabled() is False
    monkeypatch.setenv(member_listing.ENABLED_FLAG, "maybe")
    assert member_listing.is_enabled() is False
    monkeypatch.setenv(member_listing.ENABLED_FLAG, "true")
    assert member_listing.is_enabled() is True


def test_R1_a_consenting_member_survives_a_RESTART(monkeypatch) -> None:
    """THE DEFECT THAT ROLLED UP INTO sm-listing 0.3.0, asserted across two boots.

    Consent hydrated at opt-in and never rebuilt on boot means a consenting
    member silently VANISHES on restart — §3's presence half broken quietly, and
    invisible to every other test in this file because they all set consent in
    the same process that reads it. A test whose setup and assertion live in one
    process cannot detect a property that only fails across two.

    So this boots the app TWICE against a store that keeps the row, and asserts
    the member is listed on the SECOND boot — the one where nothing but
    `load_persisted_members` could have put the consent back.

    ⚠️ It is a store-level restart: the module is dropped and re-imported and the
    lifespan re-runs, so every in-memory handle is rebuilt from the persisted
    row. It is not a new OS process, and saying so matters — the intelligence-feed work shipped a
    CLAIMS row that read as a process restart when it was this.
    """
    import importlib as _importlib

    persisted = [
        {
            "agent_id": "napa",
            "name": "Napa Winery",
            "description": "d",
            "skills": ["wine"],
            "profile_type": "member",
            "config": {
                "parent_chapter": _ORG,
                "endpoint": "https://napa.example",
                # As the opt-in writes it: agent_url is SERVER-SET and stored
                # with the consent, because the member's endpoint is in-memory
                # only and the loader hardcodes "". Before that fix this test —
                # and only this test — failed with "agent_url must be a non-empty
                # string", i.e. the listing 500'd on every redeploy.
                member_listing.CONSENT_KEY: {
                    "listed": True,
                    "geo": {"country": "US"},
                    "agent_url": "https://napa.example",
                },
            },
        }
    ]

    async def _pg(method, table, params=None, body=None):
        return list(persisted) if table == "agents" and method == "GET" else []

    monkeypatch.setenv("AGENT_ID", _ORG)
    monkeypatch.setenv("AGENT_NAME", "Listing Org")
    monkeypatch.setenv(member_listing.ENABLED_FLAG, "true")

    listed_after_each_boot = []
    for _ in range(2):
        sys.modules.pop("chapter_agent", None)
        mod = _importlib.import_module("chapter_agent")
        monkeypatch.setattr(mod, "pg_request", _pg)
        mod.members.clear()
        # The loader is what must put the consent back; nothing else in this test
        # writes to `members`, so a member present here came from the store.
        import asyncio

        asyncio.get_event_loop_policy().new_event_loop().run_until_complete(mod.load_persisted_members())
        doc = member_listing.build(mod.members, community_id=_ORG, generated_at="2026-08-09T00:00:00+00:00")
        listed_after_each_boot.append([e["subject"] for e in doc["entries"]])

    assert listed_after_each_boot == [["napa"], ["napa"]], (
        "a consenting member did not survive the restart — the loader is not rebuilding consent, "
        f"so §3's presence half fails silently on every redeploy: {listed_after_each_boot}"
    )
