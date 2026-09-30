"""The agent's public documents can be read from another origin.

``local_auth.OPEN_ROUTES`` declares the agent card open because *"a resolver
fetches it unauthenticated to learn how to address this agent"*. Without an
``Access-Control-Allow-Origin`` header only a SERVER-side resolver could act on
that: a browser-based one received the same 200 and was forbidden to look at it.

Measured 2026-09-30 against the live estate — a viewer on another origin fetching
an agent's card got no ACAO header at all and could not display its name, while
the org servers (which already carry this middleware) served theirs fine.

These tests pin the header on the documents and, more importantly, its ABSENCE on
``POST /`` — the A2A endpoint lives on the same app, and a wildcard there would
invite any page to drive it.
"""

from __future__ import annotations

import pytest

from community_member import local_auth

PUBLIC_DOCS = sorted(p for m, p in local_auth.OPEN_ROUTES if m == "GET" and "{" not in p)


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    """A real agent app, built the way test_a2a_cleanup builds one."""
    from fastapi.testclient import TestClient

    from community_member import task_store as ts_mod
    from community_member.config import Config
    from community_member.crypto import generate_keypair
    from community_member.server import create_app

    monkeypatch.setattr(ts_mod, "TASK_STORE_PATH", tmp_path / "tasks.jsonl")
    cfg = Config()
    cfg.agent_id = "alice"
    cfg.name = "Alice"
    cfg.chapter_url = "https://chapter.example"
    cfg.api_key = "x" * 32
    kp = generate_keypair()
    cfg.private_key = kp["private_key"]
    cfg.public_key = kp["public_key"]
    return TestClient(create_app(cfg))


@pytest.mark.parametrize("path", PUBLIC_DOCS)
def test_a_public_document_is_readable_from_any_origin(app_client, path):
    response = app_client.get(path, headers={"Origin": "https://viewer.example"})
    assert response.status_code != 401, f"{path} is declared open but answered 401"
    assert response.headers.get("access-control-allow-origin") == "*", (
        f"{path} is published for anyone, but a browser on another origin may not read it"
    )


@pytest.mark.parametrize("path", PUBLIC_DOCS)
def test_the_preflight_for_a_public_document_is_answered(app_client, path):
    response = app_client.options(
        path,
        headers={
            "Origin": "https://viewer.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code in (200, 204)
    assert response.headers.get("access-control-allow-origin") == "*"


def test_the_a2a_endpoint_never_gets_the_wildcard(app_client):
    """The A2A endpoint is on the same app and authenticates its own callers.

    A wildcard there would invite any page a user visits to drive this agent.
    """
    response = app_client.post("/", json={}, headers={"Origin": "https://viewer.example"})
    assert response.headers.get("access-control-allow-origin") != "*"


def test_a_protected_route_does_not_become_readable(app_client):
    """The header is scoped to the declared documents, not to everything open."""
    response = app_client.get("/api/settings", headers={"Origin": "https://viewer.example"})
    assert response.headers.get("access-control-allow-origin") != "*"


def test_no_credentials_header_accompanies_the_wildcard(app_client):
    """`*` is only safe for a credential-less read; pairing it with
    Allow-Credentials would be rejected by browsers and wrong if it were not."""
    response = app_client.get("/.well-known/agent-card.json", headers={"Origin": "https://viewer.example"})
    assert "access-control-allow-credentials" not in {k.lower() for k in response.headers}
