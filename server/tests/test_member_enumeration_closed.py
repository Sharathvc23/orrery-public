"""Anonymous member enumeration is closed, and stays closed.

The audit established that `GET /api/members` was gated while the same
population was published anonymously three other ways, one of them a document
titled "Agent Directory". This asserts the close, in the two layers the guard
work established: the gate is **present** in the source, and it **fires** over
the wire.

⚠️ **THE GENERAL ASSERTION IS THE ONE THAT MATTERS.** A test that names the five
pages found by the audit is a suppression list — it goes green forever while a
sixth page added next year publishes the directory again. So `G3` drives EVERY
registered A2UI surface anonymously and fails if a member's own id, name,
description or skills appears in any of them. That is the assertion that catches
the surface nobody thought to name, and it is how the three extra pages
(`chapter`, `reputation`, `subscriptions`) were found in the first place — the
ruling named two, and driving the rest found five.

⚠️ **AND THE CATALOG IS NOT GATED, DELIBERATELY.** `/.well-known/ai-catalog.json`
is the unauthenticated registry hop: an org registers at the Index with
`registry_url` pointing at itself, so a resolver that has never met this org
fetches that document next. The DOCUMENT stays resolvable and the MEMBER LIST is
what closes. `C1`-`C3` assert both halves, because asserting only the closure
would be satisfied by a 401 that breaks the hop.
"""

from __future__ import annotations

import base64
import importlib
import json
import os
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_PUBLIC_URL = "https://enum-org.example"

#: Canaries planted in the member's own fields. A privacy assertion must search
#: for the data, not for a field name: the directory published the description
#: under `subtitle`, so a test looking for a key called "description" would have
#: reported the leak closed.
CANARIES = {
    "agent_id": "napa-canary",
    "name": "Napa Canary Winery",
    "email": "owner@napa-canary.example",
    "phone": "+1-707-555-0142",
    "skill": "viticulture-canary",
}


@pytest.fixture
def app_module(monkeypatch):
    monkeypatch.setenv("AGENT_ID", "TEST-enum-org")
    monkeypatch.setenv("AGENT_NAME", "Enumeration Org")
    monkeypatch.setenv("AGENT_DESCRIPTION", "An org for the enumeration test")
    sys.modules.pop("chapter_agent", None)
    mod = importlib.import_module("chapter_agent")
    monkeypatch.setattr(mod, "PUBLIC_URL", _PUBLIC_URL)
    return mod


@pytest.fixture
def member(app_module):
    """A member holding the canaries, registered the way a real one is."""
    import sovereign_identity

    kp = sovereign_identity.generate_ed25519_keypair("enum-probe")
    app_module.members[CANARIES["agent_id"]] = {
        "name": CANARIES["name"],
        "description": f"Winery. Contact: {CANARIES['email']}, {CANARIES['phone']}",
        "skills": [CANARIES["skill"], "wine"],
        "endpoint": "https://napa-canary.example",
        "public_key": kp["public_key"],
        "profile_type": "member",
        "availability": "active",
        "interests": [],
        "virtual": True,
    }
    import auth_verify

    # store_agent_key, not a raw assignment: the store holds a THREE-FIELD dict
    # (public_key / signing_secret / ed25519_pubkey) and verify_request reads
    # ["ed25519_pubkey"]. Assigning the bare string made every signed request
    # crash inside the auth path with "'str' object has no attribute 'get'" —
    # which surfaced as the SIGNED half of these assertions failing, i.e. it
    # read like a broken route rather than a broken fixture.
    auth_verify.store_agent_key(CANARIES["agent_id"], kp["public_key"], ed25519_pubkey=kp["public_key"])
    yield {"agent_id": CANARIES["agent_id"], "priv": kp["private_key"], "pub": kp["public_key"]}
    app_module.members.pop(CANARIES["agent_id"], None)
    auth_verify._agent_keys.pop(CANARIES["agent_id"], None)


@pytest.fixture
def client(app_module, monkeypatch) -> TestClient:
    """A client whose surface builders can actually render — booted the real way.

    Entering the lifespan rather than hand-calling each module's ``init()``. The
    first version injected them one at a time and it was not merely tedious: a
    page whose module was not initialised answers 500, and `G3` skips non-200
    responses — so it would have reported "no leak" for a page that never
    rendered. Booting the app is what makes "this page discloses nothing"
    a statement about the page instead of about the fixture.

    The database is a stub that returns no rows; every surface under test renders
    from the in-memory ``members`` dict, which is what the exposure is about.
    """
    import pg_store

    async def _empty_pg(method, table, params=None, body=None):
        return []

    async def _ddl(sql):
        return None

    async def _reachable():
        return False

    monkeypatch.setattr(app_module, "pg_request", _empty_pg)
    monkeypatch.setattr(pg_store, "pg_request", _empty_pg, raising=False)
    monkeypatch.setattr(pg_store, "execute_ddl", _ddl)
    monkeypatch.setattr(pg_store, "db_reachable", _reachable)
    app_module._rate_limit_store.clear()
    with TestClient(app_module.app) as c:
        yield c


def _signed(m, path: str) -> dict:
    import sovereign_identity

    ts = str(int(time.time()))
    nonce = base64.b64encode(os.urandom(32)).decode()
    msg = f"GET:{path}::{m['agent_id']}:{ts}:{nonce}"
    return {
        "X-Agent-ID": m["agent_id"],
        "X-Agent-Signature": sovereign_identity.ed25519_sign(msg, m["priv"]),
        "X-Agent-Timestamp": ts,
        "X-Agent-Nonce": nonce,
        "X-Agent-Sig-Scheme": "ed25519+nonce",
        "X-Agent-DID-Key": sovereign_identity.build_did_key_from_ed25519(m["pub"]),
    }


#: Driven from the module the gate is declared in, not re-listed here. A second
#: list would let the two drift, and the drift would look like a passing test.
def _gated_pages():
    import auth_verify

    return list(auth_verify.MEMBER_BEARING_SURFACES)


_GATED_PAGES = _gated_pages()


def _canaries_in(text: str) -> list[str]:
    return sorted(k for k, v in CANARIES.items() if v in text)


# ---------------------------------------------------------------------------
# G1/G2 — the gate is PRESENT, then it FIRES
# ---------------------------------------------------------------------------


def test_G1_the_gate_is_declared_in_the_source() -> None:
    """Present before exercised. A gate removed from the set is invisible to a
    test that only drives the endpoint and finds it open — that reads exactly
    like the endpoint never having been gated, which is the state this PR is
    fixing."""
    import auth_verify

    assert auth_verify.MEMBER_BEARING_SURFACES, "the member-bearing surface list is empty"
    for page in auth_verify.MEMBER_BEARING_SURFACES:
        path = f"/api/surfaces/{page}"
        assert path in auth_verify.REQUIRE_AUTH_GET_PATHS, f"{path} is not gated"
        assert auth_verify.requires_auth("GET", path) is True, f"{path} does not require auth"


@pytest.mark.parametrize("page", _GATED_PAGES)
def test_G2_each_member_surface_is_401_anonymous_and_200_signed(client, member, page) -> None:
    """Both halves. Asserting only the 401 would be satisfied by a broken route;
    a member must still be able to read the directory, which is the whole point
    of gating rather than deleting it."""
    path = f"/api/surfaces/{page}"

    assert client.get(path).status_code == 401, f"{path} still answers a stranger"
    assert client.get(path, headers=_signed(member, path)).status_code == 200, (
        f"{path} is closed to a signed member too — that is a broken route, not a gate"
    )


def test_G3_NO_registered_surface_leaks_member_data_anonymously(client, member) -> None:
    """THE ASSERTION THAT CATCHES THE PAGE NOBODY NAMED.

    Every registered A2UI page, driven anonymously, searched for the member's own
    id, name, email, phone and skill. The ruling named two pages; driving all of
    them found five. A test that hard-coded those five would go green forever
    while a sixth page published the directory again — which is exactly the
    suppression-list shape that change removed.

    Searching for the DATA rather than for field names is deliberate: the
    directory published the description under `subtitle`, so a test looking for a
    key called "description" would have reported the leak closed.
    """
    import surfaces

    leaks = {}
    for page in sorted(surfaces.SURFACE_BUILDERS):
        resp = client.get(f"/api/surfaces/{page}")
        if resp.status_code != 200:
            continue
        hits = _canaries_in(resp.text)
        if hits:
            leaks[page] = hits

    assert not leaks, (
        "these surfaces disclose member data to an unauthenticated caller:\n"
        + "\n".join(f"  /api/surfaces/{p} → {', '.join(h)}" for p, h in sorted(leaks.items()))
    )


def test_G4_the_portal_layout_hides_members_but_keeps_the_page(client, member) -> None:
    """The ARRAY is gated, not the DOCUMENT — and both halves are asserted.

    The org's hero, focus and federation are things the org publishes about
    itself and a stranger loading the page is the normal case. Gating the whole
    layout would take the org's own content away to protect data the org never
    meant to publish, so the member section alone is withheld.
    """
    anon = client.get("/api/portal/layout")

    assert anon.status_code == 200, "the org's own landing page must still render for a stranger"
    assert not _canaries_in(anon.text), f"portal/layout still discloses {_canaries_in(anon.text)}"
    assert "Enumeration Org" in anon.text, "the page shell was gated too — only the member array should be"

    signed = client.get("/api/portal/layout", headers=_signed(member, "/api/portal/layout"))
    assert signed.status_code == 200
    assert "agent_id" in _canaries_in(signed.text), "a verified member must still see the member list"


# ---------------------------------------------------------------------------
# C1-C3 — the catalog: the hop survives, the enumeration does not
# ---------------------------------------------------------------------------


def test_C1_the_catalog_document_is_still_publicly_resolvable(client, member) -> None:
    """That change's reason has not stopped being true: an org registers at the Index
    with `registry_url` pointing here, so a resolver that has never met this org
    fetches THIS document as its next hop. A 401 would close the enumeration by
    breaking the resolution the org itself asked for."""
    resp = client.get("/.well-known/ai-catalog.json")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/ai-catalog+json")
    body = resp.json()
    assert body["specVersion"] == "1.0"
    assert body["entries"], "the org's own entry must survive — an empty catalog is a broken hop"
    assert body["entries"][0]["identifier"] == "TEST-enum-org"


def test_C2_the_catalog_withholds_members_from_a_stranger(client, member) -> None:
    body = client.get("/.well-known/ai-catalog.json").json()

    assert not _canaries_in(json.dumps(body)), f"the catalog still discloses {_canaries_in(json.dumps(body))}"
    assert [e["identifier"] for e in body["entries"]] == ["TEST-enum-org"]
    assert body["withheldMembers"] == 1, "a withheld member must be counted, not silently absent"
    assert body["omittedMembers"] == 0, (
        "withholding must not be counted as omission — The resolvable-card rule's count means 'no resolvable card' "
        "and conflating the two makes a privacy decision indistinguishable from an unpublished card"
    )


def test_C3_a_signed_member_still_gets_the_full_catalog(client, member) -> None:
    """The data is withheld from strangers, not deleted. Asserting only C2 would
    be satisfied by a catalog that had stopped listing members at all."""
    resp = client.get("/.well-known/ai-catalog.json", headers=_signed(member, "/.well-known/ai-catalog.json"))

    body = resp.json()
    assert resp.status_code == 200
    assert body["withheldMembers"] == 0
    ids = [e["identifier"] for e in body["entries"]]
    assert CANARIES["agent_id"] in ids, "a verified caller must still see the member entries"


# ---------------------------------------------------------------------------
# The registrant is told
# ---------------------------------------------------------------------------


def test_N1_registration_tells_the_registrant_their_description_is_published(client) -> None:
    """Closing the anonymous surfaces does not un-write what somebody already
    typed. The field is still published to every signed member, to federation
    peers, and through AgentFacts — so the fix that lasts is saying so at the
    point they write it."""
    resp = client.post(
        "/api/members",
        json={"agent_id": "notice-probe", "name": "Notice Probe", "description": "x", "skills": ["y"]},
    )

    notice = resp.json().get("publication_notice")
    assert notice, "a registrant is told nothing about where their description goes"
    assert "description" in notice["published_fields"]
    assert "no per-member opt-out" in notice["detail"], (
        "the notice must state the absence of an opt-out — a control that does not exist "
        "cannot be assumed by whoever reads this"
    )


def test_G5_the_literal_gate_entries_and_the_named_list_agree() -> None:
    """The two representations of one decision must not drift.

    `REQUIRE_AUTH_GET_PATHS` holds literal strings because
    `renderer/tests/e2e/gen_contract.py` reads it STATICALLY and keeps only
    `ast.Constant` elements — the first version of this gate used a starred
    comprehension, which that parser cannot see, so the generated portal
    contract listed these pages as ungated and the browser e2e asserted they
    still paint. It failed in CI for exactly that reason.

    Literals fixed it and introduced the risk they always do: a second list that
    can drift from the first. This asserts both directions, so adding a page to
    one and forgetting the other fails here rather than in a browser.
    """
    import auth_verify

    from_literals = {
        p.removeprefix("/api/surfaces/")
        for p in auth_verify.REQUIRE_AUTH_GET_PATHS
        if p.startswith("/api/surfaces/") and not p.endswith("/stream")
    }

    # Subset, not equality: other /api/surfaces/* pages were already gated for
    # unrelated reasons (today, settings, intents, messages, voice, channels,
    # conversations, chapter-security). Asserting equality would have made this
    # test a second, wrong claim about those — it is about the member-directory
    # decision only.
    missing = set(auth_verify.MEMBER_BEARING_SURFACES) - from_literals
    assert not missing, (
        f"named as member-bearing but not gated in REQUIRE_AUTH_GET_PATHS: {sorted(missing)} — "
        "the literal entries and MEMBER_BEARING_SURFACES have drifted"
    )
    # The /stream twins were LITERALS here in that change and are now covered by a RULE
    # (auth_verify.canonical_surface_path): a twin inherits its page's gate,
    # so the literals were removed to leave one mechanism rather than two that can
    # disagree. The property is unchanged and is still asserted — just at the
    # layer that decides, instead of by string membership.
    for page in auth_verify.MEMBER_BEARING_SURFACES:
        assert auth_verify.requires_auth("GET", f"/api/surfaces/{page}/stream"), (
            f"{page} is gated but its /stream variant is not — the SSE form would re-open it"
        )


def test_G6_the_portal_contract_generator_sees_the_gate() -> None:
    """Drive the generator the browser e2e actually consumes.

    Asserting the set's contents proves nothing about what a downstream AST
    parser extracts from it — that gap is what put this PR's e2e in the red. So
    this runs `gen_contract.py` and checks its output, which is the artefact the
    e2e reads.
    """
    import json as _json
    import subprocess
    import sys as _sys

    repo = Path(__file__).resolve().parents[2]
    out = subprocess.run(
        [_sys.executable, str(repo / "renderer" / "tests" / "e2e" / "gen_contract.py"), str(repo)],
        capture_output=True, text=True, check=True,
    )
    contract = _json.loads(out.stdout)

    import auth_verify

    missing = set(auth_verify.MEMBER_BEARING_SURFACES) - set(contract["gated"])
    assert not missing, (
        f"the portal contract does not list {sorted(missing)} as gated, so the browser suite still "
        "expects those pages to paint for a keyless visitor — which is what failed CI on this PR"
    )


# ---------------------------------------------------------------------------
# P1-P3 — is_public was SELECTED and NEVER READ
# ---------------------------------------------------------------------------


async def _profile_surface(app_module, monkeypatch, *, is_public: bool | None):
    """Render /api/surfaces/profile for a member whose account row has this flag.

    `async def` + `await`, not `get_event_loop().run_until_complete()`: the latter
    works on 3.11 and raises "There is no current event loop" on the 3.12 CI runs,
    so it passed locally and failed in the gate. The suite is `asyncio_mode=auto`,
    so awaiting is the shape the rest of it already uses.
    """
    import surfaces

    agent_row = {
        "agent_id": "flagged-member",
        "name": "Agent Name",
        "description": "agent description",
        "profile_id": "pid-1",
        "profile_type": "member",
        "skills": ["wine"],
    }
    account = {
        "full_name": "Private Person",
        "bio": "private bio",
        "avatar_url": "",
        "title": "Owner",
        "company": "Napa Family Winery",
        "location": "Napa, California",
    }
    if is_public is not None:
        account["is_public"] = is_public

    async def _pg(method, table, params=None, body=None):
        if table == "agents":
            return [agent_row]
        if table == "profiles":
            return [account]
        return []

    monkeypatch.setattr(surfaces, "pg_request", _pg)
    return await surfaces.build_profile_surface("flagged-member")


def _surface_text(doc: dict) -> str:
    return json.dumps(doc)


def test_P1_the_is_public_check_is_PRESENT_in_the_source() -> None:
    """Present before exercised. `is_public` was in the select list and nowhere
    after it — and the column merely appearing in a query reads like it is being
    honoured, which is why this asserts the READ, not the fetch."""
    import inspect

    import surfaces

    src = inspect.getsource(surfaces.build_profile_surface)

    assert '"select": "full_name,bio,avatar_url,title,company,location,is_public"' in src, (
        "the projection changed — this guard is pinned to the query it audits"
    )
    assert 'get("is_public")' in src, (
        "is_public is selected but never read — a control that is queried and ignored is worse "
        "than one that is missing, because the column in the select list reads like it is honoured"
    )


async def test_P2_a_private_profile_withholds_the_account_fields(app_module, monkeypatch) -> None:
    """The flag fires. `/api/surfaces/profile` is one of the deliberately-open
    shareable per-agent pages, so this is what a stranger sees."""
    doc = _surface_text(await _profile_surface(app_module, monkeypatch, is_public=False))

    for private in ("Private Person", "private bio", "Owner", "Napa, California"):
        assert private not in doc, f"a private profile still published {private!r}"
    assert "Agent Name" in doc, "the agent's own registration fields remain — the page must not go blank"


async def test_P3_a_public_profile_still_publishes_them(app_module, monkeypatch) -> None:
    """Both directions. Asserting only P2 would be satisfied by a surface that
    had stopped reading the account row at all, which is a different bug."""
    doc = _surface_text(await _profile_surface(app_module, monkeypatch, is_public=True))

    for public in ("Private Person", "Owner", "Napa, California"):
        assert public in doc, f"a public profile stopped publishing {public!r}"


async def test_P4_a_row_with_no_flag_fails_CLOSED(app_module, monkeypatch) -> None:
    """`profiles.is_public` is `boolean DEFAULT true NOT NULL` and this query
    selects it explicitly, so a row arriving without the key came from somewhere
    unexpected — and the safe reading of an unexpected state for a privacy flag
    is 'do not publish'."""
    doc = _surface_text(await _profile_surface(app_module, monkeypatch, is_public=None))

    assert "Napa, California" not in doc
