"""The route that makes this org findable on the NANDA Index, and the gate it inherits.

Measured against the live index 2026-10-17. Its `/api/v1/agentic-search` ranks
orgs locally and then fans out LIVE to `GET {registry_url}/agents/search?q=...`
for every org registered as `application/ai-catalog+json`. Orrery served no such
route, so `/agents/{identifier}` matched and read `search` as an agent id:

    GET https://<org>/agents/search?q=automation
      → HTTP 404 {"detail":"agent not found in this registry"}

That body is the tell, and the consequence was measured on the index itself —
`q="space science education outreach"` returned count 0 with `orgsUnreachable:
["astrocity"]`, while the same org's catalog answered 200 in 0.13 s on a direct
probe and the fan-out leg came back in 468 ms. Nothing was unreachable; the
fan-out failed on SHAPE. We were registered and we did not appear.

WHAT THESE TESTS HOLD, and why each one is here rather than a 200 check:

* **The exact path, no redirect.** The index fetches with `redirect: 'error'`
  (`registryFanout.ts`), so a 307 to a trailing-slash twin is a failure.
* **Route ORDER, pinned by behaviour** — not by a line number, which would pass
  while the router still matched the catch-all.
* **An empty result is 200 with `entries: []`.** Any non-2xx, timeout or
  malformed body makes the index record the org `unreachable`, so a 404 for "no
  matches" is the original bug wearing a different status code.
* **Every entry is the object the catalog produces** — compared against the
  catalog ROUTE, never a hand-written literal, so the two surfaces describing
  one agent cannot drift apart silently.
* **The member gate is the catalog's.** The fan-out is UNAUTHENTICATED, and
  member entries were closed to anonymous callers after an audit found an email
  address and a phone number in a member's free-text description. A search route
  with its own gate is exactly where that reopens.

The product limit that follows, asserted rather than argued: an org that does
not publish its members publicly is discoverable on the index as ONE agent, not
as its roster. There is no bypass and these tests would fail if one were added.
"""

from __future__ import annotations

import base64
import importlib
import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

_AGENT_ID = "orbsearch"
_ORG_ID = "orb-search-org"
_PUBLIC_URL = "https://orb-search.example"
_FLAG = "ORG_PUBLIC_MEMBER_CATALOG"
_PATH = "/agents/search"
#: The description field an audit found carrying contact details. It must not
#: leave by this route in any flag state, for any caller.
_LEAKY_EMAIL = "ceo@example.invalid"
#: The exact body the catch-all returned for `search` before this route existed.
_CATCH_ALL_DETAIL = "agent not found in this registry"


def _members() -> dict:
    return {
        # Two members with resolvable cards, scoring differently on the queries
        # below so ranking can be observed rather than assumed.
        "orb-ceo": {
            "name": "Chief Executive",
            "description": f"reach me at {_LEAKY_EMAIL}",
            "endpoint": "https://ceo.example",
            "skills": ["executive", "scheduling"],
        },
        "orb-ops": {
            "name": "Head of Operations",
            "description": "",
            "endpoint": "https://ops.example",
            "skills": ["operations", "logistics", "scheduling"],
        },
        # No host39 publication record and no http(s) endpoint, so it has no
        # resolvable card URL and must be OMITTED, never advertised.
        "orb-orphan": {
            "name": "Orphan",
            "description": "",
            "endpoint": "",
            "skills": ["logistics"],
        },
    }


@pytest.fixture
def org(monkeypatch: pytest.MonkeyPatch):
    """A freshly imported org: two members with cards, one with none."""
    monkeypatch.setenv("AGENT_ID", _AGENT_ID)
    monkeypatch.setenv("AGENT_NAME", "Orb Search Org")
    monkeypatch.setenv("AGENT_DESCRIPTION", "An org that answers the agent search")
    monkeypatch.setenv("AGENT_FOCUS", "automation, scheduling")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.setenv("INDEX_ORG_ID", _ORG_ID)
    monkeypatch.delenv(_FLAG, raising=False)
    monkeypatch.delenv("ORG_HOST39_CARD_BASE", raising=False)
    # routes.identity caches a module reference to chapter_agent and reads
    # `ca.members`; both must be dropped together or the route consults a stale
    # object. Same reasoning as test_public_member_catalog's fixture.
    #
    # AND THE MODULES ARE PUT BACK AFTERWARDS, which the older reloading
    # fixtures do not do. `ca` resolves chapter_agent from `sys.modules` at
    # REQUEST time, so a suite that imported chapter_agent at module scope goes
    # on holding the pre-reload object while the handlers read the post-reload
    # one — its members dict is then invisible to its own routes. That is a
    # 404 in somebody else's suite, caused from here, and it depends only on
    # alphabetical file order: `test_agentfacts_scoring_method.py` sorts right
    # after this file and reddens without this teardown.
    reloadable = [m for m in list(sys.modules) if m == "chapter_agent" or m == "routes" or m.startswith("routes.")]
    saved = {name: sys.modules.pop(name) for name in reloadable}
    mod = importlib.import_module("chapter_agent")
    monkeypatch.setattr(mod, "PUBLIC_URL", _PUBLIC_URL)
    monkeypatch.setattr(mod, "members", _members())
    yield mod
    for name in [m for m in list(sys.modules) if m == "chapter_agent" or m == "routes" or m.startswith("routes.")]:
        sys.modules.pop(name, None)
    sys.modules.update(saved)


@pytest.fixture
def client(org) -> TestClient:
    org._rate_limit_store.clear()
    return TestClient(org.app)


def _search(client: TestClient, query: str | None = None, **kw) -> dict:
    url = _PATH if query is None else f"{_PATH}?q={query}"
    response = client.get(url, follow_redirects=False, **kw)
    assert response.status_code == 200, f"{url} → {response.status_code}: {response.text[:300]}"
    return response.json()


def _ids(doc: dict) -> list[str]:
    return [e["identifier"] for e in doc["entries"]]


# ── The contract the index fetches against ───────────────────────────────────


def test_the_exact_path_answers_200_directly_with_no_redirect(client):
    """`redirect: 'error'`: a 307 to `/agents/search/` would read as a failure."""
    response = client.get(f"{_PATH}?q=automation", follow_redirects=False)
    assert response.status_code == 200, response.text
    assert "location" not in {k.lower() for k in response.headers}


def test_FAILING_BEFORE_the_catch_all_read_search_as_an_agent_id(client):
    """The measured 404 body, as a property. This is the whole defect."""
    response = client.get(f"{_PATH}?q=automation", follow_redirects=False)
    assert response.status_code == 200
    assert response.json().get("detail") != _CATCH_ALL_DETAIL


def test_route_order_is_pinned_by_behaviour_not_by_a_line_number(client):
    """Starlette matches in declaration order. Moving `/agents/search` below the
    `/agents/{identifier}` catch-all reddens exactly this."""
    doc = _search(client, "automation")
    assert "entries" in doc, f"the catch-all answered instead: {doc}"
    assert _AGENT_ID in _ids(doc)


def test_the_document_declares_the_catalog_shape(client):
    doc = _search(client, "automation")
    assert doc["specVersion"] == "1.0"
    assert isinstance(doc["entries"], list)


def test_identifiers_stay_bare_rather_than_minting_our_own_urn_anchor(client, monkeypatch):
    """The index's `qualifyIdentifier` anchors a bare id to the domain whose
    ownership IT verified. A urn we mint ourselves anchors to a value nobody
    checked, and `sanitizeRemoteEntry` drops one anchored anywhere else."""
    monkeypatch.setenv(_FLAG, "1")
    for identifier in _ids(_search(client, "scheduling")):
        assert not identifier.lower().startswith("urn:"), identifier


# ── Derived from the catalog, so the two surfaces cannot disagree ────────────


def test_every_entry_is_the_object_the_catalog_produces_for_that_agent(client, monkeypatch):
    """Compared against the catalog ROUTE, not a literal. Two surfaces
    describing one agent that are allowed to disagree is a defect this repo has
    already paid for twice (card vs AgentFacts provider; the catalog's two-level
    media type), so the comparison is what keeps them one surface."""
    monkeypatch.setenv(_FLAG, "1")
    catalog = client.get("/.well-known/ai-catalog.json")
    assert catalog.status_code == 200
    by_id = {e["identifier"]: e for e in catalog.json()["entries"]}

    entries = _search(client)["entries"]
    assert entries, "nothing was compared"
    for entry in entries:
        assert entry == by_id[entry["identifier"]], entry["identifier"]


def test_the_org_entry_carries_the_card_url_and_not_a_second_media_type(client):
    """The org is registered at the index as `application/ai-catalog+json`; THIS
    entry's mediaType is the card it links to. One builder, so one answer."""
    entry = [e for e in _search(client, "automation")["entries"] if e["identifier"] == _AGENT_ID][0]
    assert entry["mediaType"] == "application/a2a-agent-card+json"
    assert entry["url"].endswith("/.well-known/agent.json")


# ── An empty result is 200, never 404 and never 400 ─────────────────────────


def test_a_query_matching_nothing_is_an_empty_list_not_a_404(client, monkeypatch):
    """A 404 or a 400 here makes the index record the org `unreachable`, which
    is the original bug wearing a different status code."""
    monkeypatch.setenv(_FLAG, "1")
    doc = _search(client, "ornithology+basketweaving+thermodynamics")
    assert doc["entries"] == []
    assert doc["specVersion"] == "1.0"


@pytest.mark.parametrize("query", [None, "", "%20%20"])
def test_a_blank_or_missing_q_answers_rather_than_refusing(client, monkeypatch, query):
    """This surface's failure mode is being silently dropped from discovery, so
    no filter beats an argument about what an empty query means."""
    monkeypatch.setenv(_FLAG, "1")
    assert len(_search(client, query)["entries"]) == 3


def test_a_punctuated_query_tokenizes_the_way_the_index_does(client):
    """The index splits on `\\W+`; "automation," must not be one dead term."""
    assert _AGENT_ID in _ids(_search(client, "automation%2C%20scheduling%21"))


def test_ranking_puts_the_better_overlap_first(client, monkeypatch):
    """Score = fraction of query terms present. "operations logistics" hits both
    of one member's tags and neither of the other's."""
    monkeypatch.setenv(_FLAG, "1")
    assert _ids(_search(client, "operations%20logistics"))[0] == "orb-ops"


def test_entries_are_capped_at_ten(client, monkeypatch, org):
    """The index slices every org's response to `perOrgLimit` (10), so entry 11
    is bytes nobody reads inside a 2500 ms budget."""
    monkeypatch.setenv(_FLAG, "1")
    monkeypatch.setattr(
        org,
        "members",
        {
            f"orb-{i}": {"name": f"Agent {i}", "description": "", "endpoint": f"https://a{i}.example", "skills": []}
            for i in range(25)
        },
    )
    assert len(_search(client)["entries"]) == 10


# ── The member gate, which is the catalog's ─────────────────────────────────


def test_an_anonymous_caller_sees_only_the_org_entry_when_members_are_withheld(client):
    """THE PRODUCT LIMIT, as an assertion: an org that does not publish its
    members publicly is discoverable as ONE agent, not as its roster."""
    doc = _search(client, "scheduling")
    assert _ids(doc) == [_AGENT_ID]
    assert doc["withheldMembers"] == 3


def test_an_unrecognised_flag_value_does_not_open_the_surface(client, monkeypatch):
    """"The operator did not decide" must fail closed, not open."""
    monkeypatch.setenv(_FLAG, "maybe")
    assert _search(client, "scheduling")["withheldMembers"] == 3


def test_an_opted_in_org_answers_with_its_members(client, monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    doc = _search(client, "operations")
    assert "orb-ops" in _ids(doc)
    assert doc["withheldMembers"] == 0


def test_the_search_route_and_the_catalog_withhold_identically(client, monkeypatch):
    """Same gate, same source of truth — asserted across both flag states so a
    second copy of the loop cannot pass by being right in only one of them."""
    for flag in ("1", "0"):
        monkeypatch.setenv(_FLAG, flag)
        catalog = client.get("/.well-known/ai-catalog.json").json()
        search = _search(client)
        assert search["withheldMembers"] == catalog["withheldMembers"], flag
        assert search["omittedMembers"] == catalog["omittedMembers"], flag


def test_the_free_text_description_never_leaves_by_this_route(client, monkeypatch):
    """The audit finding, as a property, in both directions of the flag."""
    for flag in ("1", "0"):
        monkeypatch.setenv(_FLAG, flag)
        raw = client.get(f"{_PATH}?q=executive", follow_redirects=False).text
        assert _LEAKY_EMAIL not in raw, f"the member's description leaked with flag={flag}"


# ── omitted and withheld are two different facts ────────────────────────────


def test_a_member_with_no_resolvable_card_is_omitted_and_counted(client, monkeypatch):
    """Advertising a URL nothing backs is what the live catalog did for 18 of 24
    entries. An absent entry is honest; a counted absence is diagnosable."""
    monkeypatch.setenv(_FLAG, "1")
    doc = _search(client)
    assert "orb-orphan" not in _ids(doc)
    assert doc["omittedMembers"] == 1


def test_omitted_and_withheld_are_never_folded_together(client, monkeypatch):
    """Folding them makes a privacy decision indistinguishable from an
    unpublished card (`member_listing.consenting_entries` says why a count must
    not be read as a consent signal either — these are neither)."""
    monkeypatch.setenv(_FLAG, "1")
    opted_in = _search(client)
    assert (opted_in["omittedMembers"], opted_in["withheldMembers"]) == (1, 0)

    monkeypatch.setenv(_FLAG, "0")
    anonymous = _search(client)
    # The gate short-circuits before the card check, exactly as the catalog's
    # does: nothing was examined, so nothing is reported omitted.
    assert (anonymous["omittedMembers"], anonymous["withheldMembers"]) == (0, 3)


def test_the_fan_out_surface_does_not_log_a_line_per_index_query(client, monkeypatch, capsys):
    """The Index fans out to this route on EVERY agentic-search, probe leg
    included, so the catalog's omission log would become one line per query per
    omitted member — measured as 20 on the live astrocity org 2026-10-18. The
    count stays in the response body, which is the diagnosable part; the catalog
    is the document a human fetches and it keeps the log."""
    monkeypatch.setenv(_FLAG, "1")
    doc = _search(client)
    assert doc["omittedMembers"] == 1, "nothing was omitted, so nothing was proved"
    assert "omitted" not in capsys.readouterr().out

    assert client.get("/.well-known/ai-catalog.json").status_code == 200
    assert "omitted" in capsys.readouterr().out, "the catalog lost its omission log"


def test_both_counts_are_always_present_so_zero_differs_from_absent(client, monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    monkeypatch.setattr(sys.modules["chapter_agent"], "members", {})
    doc = _search(client)
    assert doc["omittedMembers"] == 0
    assert doc["withheldMembers"] == 0


# ── A verified caller, over the wire ────────────────────────────────────────


def _signed(agent_id: str, priv: str, pub: str, path: str) -> dict:
    """A real v0.3 signed GET. `url_path` binds the query string, so the
    signature is over the path the index would fetch, query and all."""
    import sovereign_identity

    ts = str(int(time.time()))
    nonce = base64.b64encode(os.urandom(32)).decode()
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-Signature": sovereign_identity.ed25519_sign(f"GET:{path}::{agent_id}:{ts}:{nonce}", priv),
        "X-Agent-Timestamp": ts,
        "X-Agent-Nonce": nonce,
        "X-Agent-Sig-Scheme": "ed25519+nonce",
        "X-Agent-DID-Key": sovereign_identity.build_did_key_from_ed25519(pub),
    }


@pytest.fixture
def signed_member(org):
    """A registered member with a key on file — a caller the gate must admit."""
    import auth_verify
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("orb-search-member")
    org.members["orb-ops"]["public_key"] = kp["public_key"]
    auth_verify.store_agent_key("orb-ops", kp["public_key"], ed25519_pubkey=kp["public_key"])
    yield {"agent_id": "orb-ops", "priv": kp["private_key"], "pub": kp["public_key"]}
    auth_verify._agent_keys.pop("orb-ops", None)


def test_a_verified_member_sees_members_with_the_flag_off(client, signed_member):
    """`/agents/search` is in auth_verify.IDENTITY_AWARE_OPEN_PATHS, so the
    middleware verifies a signature when one is present. Without that entry the
    gate could only ever be opened by the env flag and a signed member would be
    indistinguishable from the anonymous index."""
    path = f"{_PATH}?q=operations"
    doc = _search(
        client,
        "operations",
        headers=_signed(signed_member["agent_id"], signed_member["priv"], signed_member["pub"], path),
    )
    assert "orb-ops" in _ids(doc)
    assert doc["withheldMembers"] == 0


def test_an_unsigned_caller_on_the_same_query_still_gets_only_the_org(client, signed_member):
    """The identity-aware entry populates identity and must never gate: an
    absent signature leaves the path exactly as open as it was."""
    doc = _search(client, "operations")
    assert _ids(doc) == []
    assert doc["withheldMembers"] == 3


# ── The registry hop this route is declared in front of ─────────────────────


def test_the_registry_hop_still_resolves_every_alias(client, monkeypatch):
    """`/agents/search` sits ABOVE `/agents/{identifier}`; the new route must
    not shadow the resolve leg the index actually follows."""
    monkeypatch.setenv(_FLAG, "1")
    # root (the short-name the index sends for an org-level locale), the
    # agent_id, the org_id as registered, and the org DOMAIN (the NEST path).
    for identifier in ("root", _AGENT_ID, _ORG_ID, "orb-search.example"):
        response = client.get(f"/agents/{identifier}")
        assert response.status_code == 200, f"{identifier} → {response.status_code}"
        assert response.json()["identifier"] == _AGENT_ID


def test_the_registry_hop_still_resolves_a_member_id(client):
    response = client.get("/agents/orb-ops")
    assert response.status_code == 200, response.text
    assert response.json()["identifier"] == "orb-ops"


def test_the_registry_hop_still_404s_an_unknown_id(client):
    response = client.get("/agents/no-such-agent-zz")
    assert response.status_code == 404
    assert response.json()["detail"] == _CATCH_ALL_DETAIL
