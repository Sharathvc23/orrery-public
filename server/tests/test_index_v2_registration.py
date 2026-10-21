"""That change — register Orrery as an org on NANDA Index v2 (leveled 4-hop) + serve
the registry hops so ``hosting_path=registry`` resolves back to Orrery.

Two halves:
  * Orrery-as-registry (in-process): GET /agents/<id> → CatalogEntry pointing at
    the standard A2A card, and GET /.well-known/ai-catalog.json. These are the
    hop-2 surfaces a NANDA resolver hits after the Index hands it
    ``registry_url=PUBLIC_URL``. Public/OPEN.
  * The Index-v2 client (hermetic, mocked httpx): /auth/register→JWT (login on
    409) then POST /api/v1/orgs with hosting_path=registry — surfacing the
    ``pending`` (email-verify) status. NO real network in CI; the live local
    4-hop is verified manually against the running testbed + by the orchestrator.

Two-level media_type is asserted both ways (the easy-to-invert trap):
  * the ORG is registered as ``application/ai-catalog+json`` (so the resolver
    appends /agents/<id> rather than GET-ing registry_url as a direct card);
  * the CatalogEntry it returns is ``application/a2a-agent-card+json`` (the card
    it points at).

Classification: INTEROP. The admin trigger is operator-gated (no startup auto-call).
"""

from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient

_PUBLIC_URL = "https://demo-org.example"
_AGENT_ID = "demo-org"


@pytest.fixture
def chapter_agent_module(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_ID", _AGENT_ID)
    monkeypatch.setenv("AGENT_NAME", "Demo Org")
    monkeypatch.setenv("AGENT_DESCRIPTION", "A demo org for the Index-v2 test")
    monkeypatch.setenv("AGENT_FOCUS", "datetime, web-fetch")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.delenv("CHAPTER_SLUG", raising=False)
    monkeypatch.delenv("CHAPTER_DISPLAY_NAME", raising=False)
    # routes.identity caches a module reference (`ca`) to chapter_agent and reads
    # `ca.members` when building the catalog. Dropping chapter_agent alone leaves
    # that reference pointing at the OLD module, so the patches below would apply
    # to an object the route never consults. This only worked while nothing
    # imported routes.identity earlier in the session — an ordering dependency,
    # not a property. Drop both so the route and the fixture agree.
    # Popping the submodule alone is not enough: `routes` stays imported and keeps
    # `identity` as an ATTRIBUTE, so `from routes import identity` would hand back
    # the stale object regardless of sys.modules. Drop the package too.
    for name in [m for m in list(sys.modules) if m == "routes" or m.startswith("routes.")]:
        sys.modules.pop(name, None)
    sys.modules.pop("chapter_agent", None)
    mod = importlib.import_module("chapter_agent")
    monkeypatch.setattr(mod, "PUBLIC_URL", _PUBLIC_URL)
    return mod


@pytest.fixture
def client(chapter_agent_module) -> TestClient:
    chapter_agent_module._rate_limit_store.clear()
    return TestClient(chapter_agent_module.app)


# ══════════════════════════════════════════════════════════════════════
# Orrery-as-registry — hop-2 surfaces (public/OPEN)
# ══════════════════════════════════════════════════════════════════════


def test_agents_record_is_catalog_entry_pointing_at_card(client: TestClient) -> None:
    resp = client.get(f"/agents/{_AGENT_ID}")
    assert resp.status_code == 200
    entry = resp.json()
    assert entry["identifier"] == _AGENT_ID
    assert entry["displayName"] == "Demo Org"
    # CatalogEntry.url → the standard A2A card (hop 3 fetches this).
    assert entry["url"] == f"{_PUBLIC_URL}/.well-known/agent.json"
    # The card it points at is an a2a-agent-card (NOT ai-catalog — the org-level
    # media_type). Inverting these two breaks the resolver's hop-2 branch.
    assert entry["mediaType"] == "application/a2a-agent-card+json"


def test_agents_record_case_insensitive_match(client: TestClient) -> None:
    assert client.get(f"/agents/{_AGENT_ID.upper()}").status_code == 200


def test_agents_record_aliases_org_domain_and_org_id(client: TestClient, monkeypatch) -> None:
    """A resolver hands hop-2 the agent_id, the org_id, or the org DOMAIN. All
    must return the SAME primary-agent CatalogEntry — else the live NANDA UI
    404s (/agents/<domain> and /agents/<org_id> were 404-ing). The Index's own
    short-name is covered separately, in
    ``test_agents_record_answers_the_air_catalog_short_name``."""
    monkeypatch.setenv("INDEX_ORG_ID", "orrery-demo")  # org_id distinct from agent_id
    domain = "demo-org.example"  # host of _PUBLIC_URL

    by_agent = client.get(f"/agents/{_AGENT_ID}")  # demo-org
    by_domain = client.get(f"/agents/{domain}")
    by_org_id = client.get("/agents/orrery-demo")

    for r in (by_agent, by_domain, by_org_id):
        assert r.status_code == 200, r.text
    # identical CatalogEntry for every alias (always the primary agent).
    assert by_agent.json() == by_domain.json() == by_org_id.json()
    assert by_domain.json()["identifier"] == _AGENT_ID


def test_agents_record_answers_the_air_catalog_short_name(client: TestClient) -> None:
    """REGRESSION, measured live 2026-10-11. The Index keys entries on
    ``urn:air:<FQDN>:<namespace...>:<short-name>`` and ``/resolve`` hands this hop
    the SHORT-NAME alone. Orrery registers with ``hosting_path=registry``, so its
    entry is ``urn:air:<ORG_DOMAIN>:catalog:root`` and every org-level resolve
    arrives as ``root``.

    It arrived as ``root`` and this registry answered 404, which broke the live
    4-hop end to end: ``urn:air:regentix.ai:catalog:root`` resolved at the Index,
    then died on ``GET /agents/root``. None of the other aliases are sent any
    more — the bare-domain locator the old scheme allowed has no ARD form — so
    this one is the whole chain."""
    # Imported here, not at module scope: the chapter_agent fixture drops
    # `routes` from sys.modules, so a top-level import would bind the stale one.
    from routes import identity

    assert identity.AIR_CATALOG_SHORT_NAME == "root"
    by_short_name = client.get(f"/agents/{identity.AIR_CATALOG_SHORT_NAME}")
    assert by_short_name.status_code == 200, by_short_name.text
    assert by_short_name.json() == client.get(f"/agents/{_AGENT_ID}").json()


def test_agents_record_unknown_id_404(client: TestClient) -> None:
    assert client.get("/agents/not-this-org").status_code == 404


# ── That change: org MEMBERS resolve to their host39 card ────────────────────

_HOST39_BASE = "https://server-5a9d.example/regentix.ai"


def _with_members(chapter_agent_module, monkeypatch, *, published=True, **env):
    """Seed two namespaced members + set the host39 env (unless overridden).

    ``published`` carries the publication record. It defaults True because
    these tests are about the host39 RESOLUTION shape (prefix stripping, media
    type, primary-alias precedence), not about publication state — but the record
    has to be present, because since the resolvable-card rule a card base alone no longer produces a
    URL. ``published=False`` is the unpublished case, asserted below.
    """
    monkeypatch.setenv("ORG_AGENT_PREFIX", "regentix-")
    for k, v in env.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    extra = {chapter_agent_module.HOST39_PUBLISHED_AT: "2026-08-02T20:00:00Z"} if published else {}
    monkeypatch.setattr(
        chapter_agent_module,
        "members",
        {
            "regentix-ceo": {"name": "Regentix CEO", "description": "the boss", **extra},
            "regentix-cto": {"name": "Regentix CTO", "description": "the builder", **extra},
        },
    )


def test_agents_member_resolves_to_host39_card(client, chapter_agent_module, monkeypatch) -> None:
    """A member agent_id → CatalogEntry pointing at its host39 card, with the
    ORG_AGENT_PREFIX stripped from the slug (regentix-ceo → ceo.json)."""
    _with_members(chapter_agent_module, monkeypatch, ORG_HOST39_CARD_BASE=_HOST39_BASE)
    r = client.get("/agents/regentix-ceo")
    assert r.status_code == 200
    e = r.json()
    assert e["identifier"] == "regentix-ceo"
    assert e["displayName"] == "Regentix CEO"
    assert e["mediaType"] == "application/a2a-agent-card+json"
    assert e["url"] == f"{_HOST39_BASE}/ceo.json"  # prefix stripped
    # The member row's free-text description is not published on this
    # unauthenticated hop; the card the URL points at describes the agent.
    assert e["description"] == ""


def test_agents_member_404_when_host39_base_unset(client, chapter_agent_module, monkeypatch) -> None:
    """Back-compat: with no ORG_HOST39_CARD_BASE, members stay unresolvable."""
    _with_members(chapter_agent_module, monkeypatch, ORG_HOST39_CARD_BASE=None)
    assert client.get("/agents/regentix-ceo").status_code == 404


def test_agents_unknown_member_still_404(client, chapter_agent_module, monkeypatch) -> None:
    _with_members(chapter_agent_module, monkeypatch, ORG_HOST39_CARD_BASE=_HOST39_BASE)
    assert client.get("/agents/regentix-nobody").status_code == 404


def test_agents_primary_alias_preserved_with_members(client, chapter_agent_module, monkeypatch) -> None:
    """The org-primary alias still returns the standard A2A card, not a host39 one."""
    _with_members(chapter_agent_module, monkeypatch, ORG_HOST39_CARD_BASE=_HOST39_BASE)
    e = client.get(f"/agents/{_AGENT_ID}").json()
    assert e["url"] == f"{_PUBLIC_URL}/.well-known/agent.json"


def _catalog_as_member(client, chapter_agent_module):
    """Fetch the catalog AS A VERIFIED MEMBER.

    the member-directory closure closed anonymous member enumeration: a stranger now gets
    the org's own entry and a `withheldMembers` count, because the same
    population is gated on GET /api/members. These tests are about the host39
    RESOLUTION shape — which URL a member entry carries, and which members are
    omitted for want of a published card — so they need to be entitled to see the
    entries at all. Signing is the precondition, not the subject.
    """
    import base64
    import os
    import time

    import auth_verify
    import sovereign_identity

    # A verified signature counts as "a member" only for a REGISTERED id — a
    # stored key alone is not membership. Sign as one of the seeded members
    # rather than adding a reader, so the entry and omission counts these
    # tests assert are the seeded population's and nothing else.
    reader = next(iter(chapter_agent_module.members))
    kp = sovereign_identity.generate_ed25519_keypair(reader)
    auth_verify.store_agent_key(reader, kp["public_key"], ed25519_pubkey=kp["public_key"])
    path = "/.well-known/ai-catalog.json"
    ts, nonce = str(int(time.time())), base64.b64encode(os.urandom(32)).decode()
    msg = f"GET:{path}::{reader}:{ts}:{nonce}"
    headers = {
        "X-Agent-ID": reader,
        "X-Agent-Signature": sovereign_identity.ed25519_sign(msg, kp["private_key"]),
        "X-Agent-Timestamp": ts,
        "X-Agent-Nonce": nonce,
        "X-Agent-Sig-Scheme": "ed25519+nonce",
        "X-Agent-DID-Key": sovereign_identity.build_did_key_from_ed25519(kp["public_key"]),
    }
    resp = client.get(path, headers=headers)
    body = resp.json()
    assert body["withheldMembers"] == 0, (
        "the signed fetch was not recognised, so this test would be measuring the "
        "anonymous projection and asserting the wrong thing"
    )
    return body


def test_ai_catalog_lists_primary_and_members(client, chapter_agent_module, monkeypatch) -> None:
    _with_members(chapter_agent_module, monkeypatch, ORG_HOST39_CARD_BASE=_HOST39_BASE)
    doc = _catalog_as_member(client, chapter_agent_module)
    ids = [e["identifier"] for e in doc["entries"]]
    assert _AGENT_ID in ids and "regentix-ceo" in ids and "regentix-cto" in ids
    assert len(doc["entries"]) == 3  # primary + 2 members
    ceo = next(e for e in doc["entries"] if e["identifier"] == "regentix-ceo")
    assert ceo["url"] == f"{_HOST39_BASE}/ceo.json"


def test_ai_catalog_only_primary_when_host39_unset(client, chapter_agent_module, monkeypatch) -> None:
    _with_members(chapter_agent_module, monkeypatch, ORG_HOST39_CARD_BASE=None)
    doc = _catalog_as_member(client, chapter_agent_module)
    assert [e["identifier"] for e in doc["entries"]] == [_AGENT_ID]  # primary only
    assert doc["omittedMembers"] == 2  # The resolvable-card rule: reported, not silent


def test_ai_catalog_omits_members_whose_card_was_never_published(
    client, chapter_agent_module, monkeypatch
) -> None:
    """a card base is set, but no card was ever published for these members.

    This is the live failure — 18 of astrocity's 24 advertised entries pointed at
    cards nobody created, because registration does not publish and the
    catalog assumed it did. The members stay resolvable by id; they are dropped
    from the crawl surface, not from existence.
    """
    _with_members(chapter_agent_module, monkeypatch, published=False, ORG_HOST39_CARD_BASE=_HOST39_BASE)
    doc = _catalog_as_member(client, chapter_agent_module)
    assert [e["identifier"] for e in doc["entries"]] == [_AGENT_ID]
    assert doc["omittedMembers"] == 2
    assert not any("ceo.json" in e["url"] for e in doc["entries"])


def test_ai_catalog_document(client: TestClient) -> None:
    resp = client.get("/.well-known/ai-catalog.json")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/ai-catalog+json")
    doc = resp.json()
    assert doc["specVersion"] == "1.0"
    assert len(doc["entries"]) == 1
    assert doc["entries"][0]["identifier"] == _AGENT_ID
    assert doc["entries"][0]["url"] == f"{_PUBLIC_URL}/.well-known/agent.json"


def test_registry_hop_surfaces_are_open() -> None:
    import auth_verify

    assert auth_verify.is_open_path("GET", "/agents/demo-org") is True
    assert auth_verify.is_open_path("GET", "/.well-known/ai-catalog.json") is True
    # The /agents/ prefix must NOT open the distinct /api/agents/ namespace.
    assert auth_verify.is_open_path("DELETE", "/api/agents/import") is False


# ══════════════════════════════════════════════════════════════════════
# Index-v2 client — hermetic (mocked httpx, no real network)
# ══════════════════════════════════════════════════════════════════════


class _FakeResp:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    """Routes by URL suffix; records every call for assertions."""

    def __init__(self, routes: dict, calls: list) -> None:
        self._routes = routes
        self._calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def _answer(self, method, url, body, headers):
        self._calls.append((method, url, body, headers))
        for suffix, resp in self._routes.items():
            if url.endswith(suffix):
                return resp(body, headers) if callable(resp) else resp
        return _FakeResp(404, text="no route")

    async def post(self, url, json=None, headers=None, timeout=None):
        return self._answer("POST", url, json, headers)

    async def get(self, url, headers=None, timeout=None):
        return self._answer("GET", url, None, headers)

    async def put(self, url, json=None, headers=None, timeout=None):
        return self._answer("PUT", url, json, headers)


def _install_index_v2(monkeypatch, routes: dict):
    import nanda_registry

    calls: list = []
    monkeypatch.setattr(nanda_registry.httpx, "AsyncClient", lambda *a, **k: _FakeClient(routes, calls))
    monkeypatch.setattr(nanda_registry, "_index_urls", ["http://localhost:3001"])
    monkeypatch.setattr(nanda_registry, "_agent_id", _AGENT_ID)
    monkeypatch.setattr(nanda_registry, "_agent_name", "Demo Org")
    monkeypatch.setattr(nanda_registry, "_agent_description", "A demo org")
    monkeypatch.setattr(nanda_registry, "_agent_focus", "datetime, web-fetch")
    monkeypatch.setattr(nanda_registry, "_public_url", _PUBLIC_URL)
    monkeypatch.setenv("INDEX_ACCOUNT_EMAIL", "op@demo-org.example")
    monkeypatch.setenv("INDEX_ACCOUNT_PASSWORD", "supersecret8")
    monkeypatch.setenv("ORG_DOMAIN", "orrery-demo.test")
    monkeypatch.setenv("ORG_CONTACT_EMAIL", "op@demo-org.example")
    monkeypatch.delenv("INDEX_ORG_ID", raising=False)
    return calls


@pytest.mark.asyncio
async def test_register_v2_signup_then_create_org_pending(monkeypatch) -> None:
    import nanda_registry

    routes = {
        "/auth/register": _FakeResp(201, {"token": "JWT-NEW"}),
        "/api/v1/orgs": _FakeResp(201, {"org_id": _AGENT_ID, "status": "pending"}),
    }
    calls = _install_index_v2(monkeypatch, routes)

    result = await nanda_registry.register_on_index_v2()
    assert result["ok"] is True
    assert result["status"] == "pending"
    assert result["org_id"] == _AGENT_ID

    # The /api/v1/orgs body must match the Index v2 AJV schema exactly.
    orgs_call = next(c for c in calls if c[1].endswith("/api/v1/orgs"))
    _, _, body, headers = orgs_call
    assert body["org_id"] == _AGENT_ID  # lowercase ^[a-z0-9][a-z0-9-]*[a-z0-9]$
    assert body["hosting_path"] == "registry"
    assert body["domain"] == "orrery-demo.test"
    assert body["registry_url"] == _PUBLIC_URL
    assert body["media_type"] == "application/ai-catalog+json"  # org-level, NOT the card type
    assert body["contact_email"] == "op@demo-org.example"
    assert headers["Authorization"] == "Bearer JWT-NEW"


@pytest.mark.asyncio
async def test_register_v2_logs_in_when_account_exists(monkeypatch) -> None:
    import nanda_registry

    routes = {
        "/auth/register": _FakeResp(409, {"error": "CONFLICT"}),
        "/auth/login": _FakeResp(200, {"token": "JWT-LOGIN"}),
        "/api/v1/orgs": _FakeResp(201, {"status": "pending"}),
    }
    calls = _install_index_v2(monkeypatch, routes)

    result = await nanda_registry.register_on_index_v2()
    assert result["ok"] is True and result["status"] == "pending"
    assert any(c[1].endswith("/auth/login") for c in calls)  # fell back to login
    orgs_call = next(c for c in calls if c[1].endswith("/api/v1/orgs"))
    assert orgs_call[3]["Authorization"] == "Bearer JWT-LOGIN"


# ── A 409 on re-registration: three outcomes, not one ──────────────────────
#
# This block replaces a single test that asserted ``ok is True`` with the
# comment "re-trigger is a no-op success". That was the defect written down as
# intent. A 409 proves only that the org_id is TAKEN; whether the record behind
# it still matches what the org serves is a SEPARATE, CHECKABLE fact, and
# conflating them kept all three live orgs advertising a June placeholder for
# four months while every re-trigger reported success. Measured 2026-10-21.
#
# The tags the fake index returns below are the real measured values:
# ["general ai"] is the default AGENT_FOCUS frozen at registration.


@pytest.mark.asyncio
async def test_register_v2_org_conflict_that_matches_is_a_real_success(monkeypatch) -> None:
    """In sync IS success — the fix must not cry wolf on a correct record."""
    import nanda_registry

    routes = {
        "/auth/register": _FakeResp(201, {"token": "JWT"}),
        "/api/v1/orgs": _FakeResp(409, {"error": "CONFLICT", "detail": "taken"}),
        # _install_index_v2 sets _agent_focus="datetime, web-fetch"
        f"/api/v1/orgs/{_AGENT_ID}": _FakeResp(
            200, {"tags": ["datetime", "web-fetch"], "description": "A demo org"}
        ),
    }
    _install_index_v2(monkeypatch, routes)
    result = await nanda_registry.register_on_index_v2()
    assert result["ok"] is True
    assert result["status"] == "exists"


@pytest.mark.asyncio
async def test_register_v2_org_conflict_with_a_stale_record_is_not_a_success(monkeypatch) -> None:
    """THE REGRESSION GUARD. A caller reading ``ok`` must not be told nothing
    is wrong while the index advertises something the org stopped serving."""
    import nanda_registry

    routes = {
        "/auth/register": _FakeResp(201, {"token": "JWT"}),
        "/api/v1/orgs": _FakeResp(409, {"error": "CONFLICT", "detail": "taken"}),
        f"/api/v1/orgs/{_AGENT_ID}": _FakeResp(
            200, {"tags": ["general ai"], "description": "A demo org"}
        ),
    }
    _install_index_v2(monkeypatch, routes)
    result = await nanda_registry.register_on_index_v2()
    assert result["ok"] is False
    assert result["status"] == "stale"
    assert result["fields"] == ["tags"]
    # Must name the operation that CAN fix it: registration cannot.
    assert "/admin/api/index-v2/resync" in result["detail"]


@pytest.mark.asyncio
async def test_register_v2_org_conflict_with_an_unreadable_record_is_unverifiable(monkeypatch) -> None:
    """Unknown is its own answer. A failed read must not be reported as either
    in-sync or stale — and must NOT be treated as a record with no fields,
    which would claim drift on everything."""
    import nanda_registry

    routes = {
        "/auth/register": _FakeResp(201, {"token": "JWT"}),
        "/api/v1/orgs": _FakeResp(409, {"error": "CONFLICT", "detail": "taken"}),
        f"/api/v1/orgs/{_AGENT_ID}": _FakeResp(503, text="upstream down"),
    }
    _install_index_v2(monkeypatch, routes)
    result = await nanda_registry.register_on_index_v2()
    assert result["ok"] is False
    assert result["status"] == "unverifiable"
    assert "UNKNOWN" in result["detail"]


# ── resync_index_record ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_resync_sends_only_the_fields_that_differ(monkeypatch) -> None:
    """The index rejects an unknown update key wholesale, and a field that
    matches is a write that changes nothing."""
    import nanda_registry

    routes = {
        "/auth/login": _FakeResp(200, {"token": "JWT-LOGIN"}),
        f"/api/v1/orgs/{_AGENT_ID}": lambda body, headers: (
            _FakeResp(200, {"tags": ["datetime", "web-fetch"], **(body or {})})
            if body is not None
            else _FakeResp(
                200,
                {
                    "tags": ["general ai"],
                    "description": "A demo org",  # matches _agent_description
                    "identifier": "urn:air:orrery-demo.test:catalog:root",
                },
            )
        ),
    }
    calls = _install_index_v2(monkeypatch, routes)

    result = await nanda_registry.resync_index_record()
    assert result["ok"] is True and result["status"] == "resynced"
    assert result["fields"] == ["tags"]  # description matched, so NOT sent

    put = next(c for c in calls if c[0] == "PUT")
    body = put[2]
    assert set(body) == {"tags"}, f"sent an unaccepted field: {sorted(body)}"
    assert body["tags"] == ["datetime", "web-fetch"]
    assert put[3]["Authorization"] == "Bearer JWT-LOGIN"


@pytest.mark.asyncio
async def test_resync_never_registers_when_login_fails(monkeypatch) -> None:
    """The 2026-10-20 stray-account bug. A resync acts on a record that already
    exists, so register-on-failure cannot help and DID create a stray
    unverified account — it answers "needs verifying" by creating something."""
    import nanda_registry

    routes = {"/auth/login": _FakeResp(401, {"error": "UNAUTHORIZED"})}
    calls = _install_index_v2(monkeypatch, routes)

    result = await nanda_registry.resync_index_record()
    assert result["ok"] is False and result["status"] == "auth_failed"
    assert not any("/auth/register" in c[1] for c in calls), "resync must never register"
    assert not any(c[0] == "PUT" for c in calls)


@pytest.mark.asyncio
async def test_resync_writes_nothing_when_the_record_cannot_be_read(monkeypatch) -> None:
    """An unreadable record is UNKNOWN, not empty. Treating a failed fetch as
    a record with no fields would make every transient error an overwrite."""
    import nanda_registry

    routes = {
        "/auth/login": _FakeResp(200, {"token": "JWT"}),
        f"/api/v1/orgs/{_AGENT_ID}": _FakeResp(503, text="down"),
    }
    calls = _install_index_v2(monkeypatch, routes)

    result = await nanda_registry.resync_index_record()
    assert result["ok"] is False and result["status"] == "unreadable"
    assert not any(c[0] == "PUT" for c in calls), "wrote on an unknown remote state"


@pytest.mark.asyncio
async def test_resync_in_sync_makes_no_write(monkeypatch) -> None:
    import nanda_registry

    routes = {
        "/auth/login": _FakeResp(200, {"token": "JWT"}),
        f"/api/v1/orgs/{_AGENT_ID}": _FakeResp(
            200, {"tags": ["datetime", "web-fetch"], "description": "A demo org"}
        ),
    }
    calls = _install_index_v2(monkeypatch, routes)

    result = await nanda_registry.resync_index_record()
    assert result["ok"] is True and result["status"] == "in_sync"
    assert not any(c[0] == "PUT" for c in calls)


@pytest.mark.asyncio
async def test_resync_reports_the_identifier_either_side_of_the_write(monkeypatch) -> None:
    """Every agent URN is anchored under the org's identifier, and the index
    rewrites that field on EVERY update. If a PUT ever re-mints it the whole
    catalog is orphaned, so the result must carry both values to be compared
    rather than an ``ok`` to be trusted."""
    import nanda_registry

    urn = "urn:air:orrery-demo.test:catalog:root"
    routes = {
        "/auth/login": _FakeResp(200, {"token": "JWT"}),
        f"/api/v1/orgs/{_AGENT_ID}": lambda body, headers: _FakeResp(
            200,
            {"tags": ["datetime", "web-fetch"] if body else ["general ai"], "identifier": urn},
        ),
    }
    _install_index_v2(monkeypatch, routes)

    result = await nanda_registry.resync_index_record()
    assert result["identifier_before"] == urn
    assert result["identifier_after"] == urn


@pytest.mark.asyncio
async def test_resync_does_not_blank_a_description_it_does_not_have(monkeypatch) -> None:
    import nanda_registry

    routes = {
        "/auth/login": _FakeResp(200, {"token": "JWT"}),
        f"/api/v1/orgs/{_AGENT_ID}": lambda body, headers: _FakeResp(
            200, {"tags": ["datetime", "web-fetch"], "description": "set by hand on the index"}
        ),
    }
    calls = _install_index_v2(monkeypatch, routes)
    monkeypatch.setattr(nanda_registry, "_agent_description", "")

    result = await nanda_registry.resync_index_record()
    assert result["status"] == "in_sync"
    assert not any(c[0] == "PUT" for c in calls)


@pytest.mark.asyncio
async def test_resync_reports_success_when_the_write_lands_but_the_body_is_not_json(monkeypatch) -> None:
    """A 200 IS the write landing. If the body cannot be parsed the report must
    say less about it, not claim the write failed — telling an operator to retry
    a PUT that already succeeded is worse than an unreported field."""
    import nanda_registry

    class _Unparseable(_FakeResp):
        def json(self):
            raise ValueError("not json")

    routes = {
        "/auth/login": _FakeResp(200, {"token": "JWT"}),
        f"/api/v1/orgs/{_AGENT_ID}": lambda body, headers: (
            _Unparseable(200)
            if body is not None
            else _FakeResp(200, {"tags": ["general ai"], "description": "A demo org"})
        ),
    }
    _install_index_v2(monkeypatch, routes)

    result = await nanda_registry.resync_index_record()
    assert result["ok"] is True and result["status"] == "resynced"
    assert result["fields"] == ["tags"]
    assert result["tags_after"] is None  # unknown, not invented
    assert result["representative_queries"] == []


@pytest.mark.asyncio
async def test_resync_unconfigured_makes_no_call(monkeypatch) -> None:
    import nanda_registry

    calls = _install_index_v2(monkeypatch, {})
    monkeypatch.delenv("ORG_DOMAIN", raising=False)

    result = await nanda_registry.resync_index_record()
    assert result["ok"] is False and result["status"] == "unconfigured"
    assert calls == []


def test_tags_are_derived_once_not_restated() -> None:
    """``_served_index_fields`` must be the ONLY place the registration body
    derives tags. Two copies of the transform is how the index's copy and the
    served card came to disagree in the first place."""
    import inspect

    import nanda_registry

    src = inspect.getsource(nanda_registry.register_on_index_v2)
    assert "_served_index_fields()" in src, "registration no longer shares the derivation"
    assert "_agent_focus.split" not in src, "registration re-derives tags instead of sharing"


@pytest.mark.asyncio
async def test_register_v2_unconfigured_makes_no_call(monkeypatch) -> None:
    import nanda_registry

    calls = _install_index_v2(monkeypatch, {})
    monkeypatch.delenv("ORG_DOMAIN", raising=False)  # drop required config

    result = await nanda_registry.register_on_index_v2()
    assert result["ok"] is False
    assert result["status"] == "unconfigured"
    assert calls == []  # NO surprise network call when unconfigured


def test_sanitize_org_id_coerces_to_pattern() -> None:
    import nanda_registry

    assert nanda_registry._sanitize_org_id("TEST-Acme Org!") == "test-acme-org"
    assert nanda_registry._sanitize_org_id("demo-org") == "demo-org"


# ══════════════════════════════════════════════════════════════════════
# Admin trigger — operator-gated (no startup auto-call)
# ══════════════════════════════════════════════════════════════════════


def test_index_v2_register_trigger_is_admin_gated(client: TestClient) -> None:
    """The explicit trigger must reject an unauthenticated caller (operator-gated)."""
    resp = client.post("/admin/api/index-v2/register")
    assert resp.status_code in (401, 403)


# ── That change: self-serve member cards (host39-optional) ────────────────────


def _with_endpoint_members(chapter_agent_module, monkeypatch, *, published=False, **env):
    """Members that registered a public endpoint (the join-flow shape).

    ``published`` adds the host39 publication record; default False, which
    is the realistic join-flow state — a member who registered an endpoint has
    not had anyone run the publisher for them.
    """
    monkeypatch.setenv("ORG_AGENT_PREFIX", "regentix-")
    for k, v in env.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    monkeypatch.setattr(
        chapter_agent_module,
        "members",
        {
            "regentix-ceo": {
                "name": "Regentix CEO",
                "description": "the boss",
                "endpoint": "https://ceo-agent.example:8443/",
                **({chapter_agent_module.HOST39_PUBLISHED_AT: "2026-08-02T20:00:00Z"} if published else {}),
            },
            "regentix-cto": {"name": "Regentix CTO", "description": "the builder", "endpoint": ""},
            "regentix-junk": {"name": "Junk", "description": "", "endpoint": "javascript:alert(1)"},
        },
    )


def test_member_self_serve_card_when_host39_unset(client, chapter_agent_module, monkeypatch) -> None:
    """HAPPY: no host39 base → a member with a registered endpoint
    resolves to ITS OWN served card at {endpoint}/.well-known/agent.json."""
    _with_endpoint_members(chapter_agent_module, monkeypatch, ORG_HOST39_CARD_BASE=None)
    r = client.get("/agents/regentix-ceo")
    assert r.status_code == 200
    e = r.json()
    assert e["url"] == "https://ceo-agent.example:8443/.well-known/agent.json"  # trailing / stripped
    assert e["mediaType"] == "application/a2a-agent-card+json"
    assert e["identifier"] == "regentix-ceo"


def test_member_without_endpoint_still_unresolvable_when_host39_unset(
    client, chapter_agent_module, monkeypatch
) -> None:
    """EDGE: absent endpoint → older behavior, member stays 404."""
    _with_endpoint_members(chapter_agent_module, monkeypatch, ORG_HOST39_CARD_BASE=None)
    assert client.get("/agents/regentix-cto").status_code == 404


def test_member_non_http_endpoint_rejected(client, chapter_agent_module, monkeypatch) -> None:
    """ADVERSARIAL: a member-supplied non-http(s) endpoint never lands
    in a public catalog URL — the member stays unresolvable."""
    _with_endpoint_members(chapter_agent_module, monkeypatch, ORG_HOST39_CARD_BASE=None)
    assert client.get("/agents/regentix-junk").status_code == 404


def test_host39_wins_over_endpoint_when_published(client, chapter_agent_module, monkeypatch) -> None:
    """EDGE: a PUBLISHED host39 card outranks the member's own endpoint."""
    _with_endpoint_members(
        chapter_agent_module, monkeypatch, published=True, ORG_HOST39_CARD_BASE=_HOST39_BASE
    )
    e = client.get("/agents/regentix-ceo").json()
    assert e["url"] == f"{_HOST39_BASE}/ceo.json"


def test_unpublished_member_falls_back_to_its_own_endpoint(
    client, chapter_agent_module, monkeypatch
) -> None:
    """the base being set is no longer enough to claim a host39 card.

    This test previously asserted the opposite — that the host39 URL wins purely
    because ORG_HOST39_CARD_BASE is set, "byte-identical to the older
    default". That assumption is the defect: it advertised a card nobody had
    published. With no publication record the member's OWN endpoint is the thing
    that actually resolves, so that is what the catalog points at.
    """
    _with_endpoint_members(chapter_agent_module, monkeypatch, ORG_HOST39_CARD_BASE=_HOST39_BASE)
    e = client.get("/agents/regentix-ceo").json()
    assert e["url"] == "https://ceo-agent.example:8443/.well-known/agent.json"


def test_ai_catalog_lists_self_serve_members_when_host39_unset(
    client, chapter_agent_module, monkeypatch
) -> None:
    """HAPPY: the catalog enumerates self-serve members (and only them —
    no endpoint / junk endpoint stay out)."""
    _with_endpoint_members(chapter_agent_module, monkeypatch, ORG_HOST39_CARD_BASE=None)
    doc = _catalog_as_member(client, chapter_agent_module)
    ids = [e["identifier"] for e in doc["entries"]]
    assert ids == [_AGENT_ID, "regentix-ceo"]
