"""Every route on the local API is protected unless it is declared open.

Two layers. The AST layer reads ``server.py`` and checks the declaration list
against the routes that exist, in both directions. The behavioural layer drives
every one of those routes with no token and asserts the middleware refuses it —
which is what catches a route the middleware does not actually cover, as
opposed to one that is merely absent from a list.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from community_member import local_auth

SERVER_PY = Path(local_auth.__file__).with_name("server.py")

_ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}

pytestmark = pytest.mark.no_local_token


def declared_routes(source: str) -> set[tuple[str, str]]:
    """Every ``@app.<method>("<path>")`` in the module, as (METHOD, path)."""
    found: set[tuple[str, str]] = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            func = dec.func
            if not isinstance(func, ast.Attribute) or func.attr not in _ROUTE_METHODS:
                continue
            if not (isinstance(func.value, ast.Name) and func.value.id == "app"):
                continue
            if not dec.args or not isinstance(dec.args[0], ast.Constant):
                continue
            found.add((func.attr.upper(), dec.args[0].value))
    return found


@pytest.fixture(scope="module")
def routes() -> set[tuple[str, str]]:
    found = declared_routes(SERVER_PY.read_text())
    assert found, "found no routes — the AST walk stopped matching server.py's shape"
    return found


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("COMMUNITY_MEMBER_HOME", str(tmp_path))
    monkeypatch.setenv(local_auth.TOKEN_ENV_VAR, "guard-token")
    from community_member.config import Config
    from community_member.server import create_app

    cfg = Config(home=tmp_path)
    cfg.agent_id = "guard-agent"
    return create_app(cfg)


# ── The declaration list against the routes that exist ────────────────


def test_the_middleware_is_installed_on_the_app(app):
    """Without this, every other assertion here is about an inert list."""
    assert local_auth.LocalAuthMiddleware in [m.cls for m in app.user_middleware]


def test_no_open_entry_names_a_route_that_does_not_exist(routes):
    """A declaration outliving its route is a standing exemption for nothing,
    and silently pre-approves the path if it is ever reintroduced."""
    stale = sorted(entry for entry in local_auth.OPEN_ROUTES if entry not in routes)
    assert not stale, f"OPEN_ROUTES entries with no matching route in server.py: {stale}"


def test_every_open_entry_carries_a_reason():
    for entry, reason in local_auth.OPEN_ROUTES.items():
        assert isinstance(reason, str) and len(reason.strip()) >= 40, (
            f"{entry} needs a reason a reviewer can weigh, not a placeholder"
        )


def test_the_open_list_stays_short(routes):
    """A long open list means the default has stopped being deny in practice."""
    assert len(local_auth.OPEN_ROUTES) <= len(routes) // 4, (
        f"{len(local_auth.OPEN_ROUTES)} of {len(routes)} routes are open — "
        "re-examine the design rather than extending the list"
    )


# The open list pinned to its exact contents. Declaring a route open is the one
# way a route escapes the token, so widening it has to be a deliberate edit here
# as well as in local_auth — not something a reviewer can miss in a large diff.
EXPECTED_OPEN = {
    ("GET", "/.well-known/agent.json"),
    # Reviewed when the card was added at the path a current A2A client fetches.
    # It discloses NOTHING NEW: byte-for-byte the same document already served
    # unauthenticated one line above, at a second URL. The exposure decision was
    # made for the payload, not for the path, and the payload is unchanged.
    ("GET", "/.well-known/agent-card.json"),
    ("GET", "/.well-known/agent-lifecycle.json"),
    ("GET", "/.well-known/conformance.json"),
    ("GET", "/.well-known/reputation.json"),
    ("GET", "/agentfacts.json"),
    ("GET", "/api/health"),
    ("POST", "/"),
    ("POST", "/webhooks/platform/{platform}/uninstall"),
}


def test_the_open_list_is_exactly_what_was_reviewed():
    added = sorted(set(local_auth.OPEN_ROUTES) - EXPECTED_OPEN)
    removed = sorted(EXPECTED_OPEN - set(local_auth.OPEN_ROUTES))
    assert not added, f"routes newly exempted from the token: {added} — needs a security review, not a test edit"
    assert not removed, f"routes no longer exempted: {removed} — update EXPECTED_OPEN if that is intended"


def test_server_py_mounts_no_sub_application(routes):
    """``app.mount`` and ``include_router`` attach routes the AST walk above
    does not enumerate, so a route could exist that no assertion here covers."""
    source = SERVER_PY.read_text()
    for escape in ("app.mount(", "include_router("):
        assert escape not in source, f"{escape} bypasses this guard's route enumeration"


def test_opening_a_path_for_one_method_does_not_open_another():
    """The list is keyed by (method, path), so a GET exemption is not a POST one."""
    assert local_auth.is_open("GET", "/agentfacts.json")
    assert not local_auth.is_open("POST", "/agentfacts.json")
    assert local_auth.is_open("POST", "/")
    assert not local_auth.is_open("GET", "/")


# ── The routes as the middleware actually sees them ───────────────────


def _concrete(path: str) -> str:
    """Fill path parameters so the request reaches the route it is testing."""
    return re.sub(r"\{[^}]+\}", "guard", path)


def test_every_protected_route_refuses_an_unauthenticated_request(app, routes):
    """Drives each route with no token. A route the middleware does not cover
    answers something other than 401 and fails here."""
    client = TestClient(app)
    leaked: list[tuple[str, str, int]] = []
    for method, path in sorted(routes):
        if (method, path) in local_auth.OPEN_ROUTES:
            continue
        resp = client.request(method, _concrete(path))
        if resp.status_code != 401:
            leaked.append((method, path, resp.status_code))
    assert not leaked, f"routes answered without a token: {leaked}"


def test_declared_open_routes_are_reachable_without_a_token(app):
    """The open list means what it says — otherwise a peer or probe that must
    reach these gets refused and the list is decorative."""
    client = TestClient(app)
    for method, path in local_auth.OPEN_ROUTES:
        if method != "GET":
            continue  # POST entries need a body shaped for their handler
        assert client.request(method, _concrete(path)).status_code != 401, f"{method} {path} is declared open"


def test_a_route_added_without_a_declaration_is_refused(app):
    """The plant: a new route inherits the deny, because the middleware wraps
    the app rather than each handler."""
    client = TestClient(app)

    @app.post("/api/local/planted-route")
    async def _planted():  # pragma: no cover - never reached
        return {"executed": True}

    assert client.post("/api/local/planted-route").status_code == 401
    assert client.post(
        "/api/local/planted-route",
        headers={"Authorization": "Bearer guard-token"},
    ).json() == {"executed": True}


# ── The token check itself ────────────────────────────────────────────


def test_a_wrong_token_is_refused(app):
    client = TestClient(app)
    assert client.get("/api/local/config", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_a_prefix_of_the_token_is_refused(app):
    """compare_digest, not startswith."""
    client = TestClient(app)
    assert client.get("/api/local/config", headers={"Authorization": "Bearer guard"}).status_code == 401


def test_the_token_is_not_accepted_from_the_query_string(app):
    """A query-string token lands in logs, history and Referer headers."""
    client = TestClient(app)
    assert client.get("/api/local/config?token=guard-token").status_code == 401


def test_the_token_is_not_accepted_from_a_cookie(app):
    """A cookie is attached by the browser to cross-site requests, which would
    make every state-changing route reachable from any page the user visits."""
    client = TestClient(app)
    client.cookies.set("token", "guard-token")
    assert client.get("/api/local/config").status_code == 401


def test_the_x_orrery_local_token_header_is_accepted(app):
    client = TestClient(app)
    assert client.get("/api/local/config", headers={"X-Orrery-Local-Token": "guard-token"}).status_code == 200
