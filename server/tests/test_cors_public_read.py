"""the keyless PUBLIC GET surfaces are world-readable cross-origin.

The deployed mesh runs ``ORRERY_PROFILE=prod``, where the CORS allowlist is
EMPTY — so the public read surfaces (health, federation, divergence, events,
digest, agentfacts, .well-known) emitted no ``Access-Control-Allow-Origin`` and
a browser dashboard on any origin could not read them. (A prior "CORS present
in Chromium" observation went through the renderer's server-side proxy, which
adds its own ACAO and masked the origin server.) These tests run under the prod
profile — the empty-allowlist condition — and assert the public GET set now
carries ``ACAO: *`` regardless, while authenticated routes do NOT.

Classification: HAPPY / EDGE / ADVERSARIAL.
"""

from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient

ORIGIN = "https://any-dashboard.example"


@pytest.fixture
def prod_client(monkeypatch):
    # Prod profile => resolve_cors_origins returns [] => the general CORSMiddleware
    # emits no ACAO. This is the deployed condition the fix must survive.
    monkeypatch.setenv("ORRERY_PROFILE", "prod")
    monkeypatch.setenv("ALLOWED_ORIGINS", "")
    monkeypatch.setenv("AGENT_ID", "test-cors-public")
    monkeypatch.setenv("AGENT_NAME", "Test CORS Public")
    sys.modules.pop("chapter_agent", None)
    mod = importlib.import_module("chapter_agent")
    yield TestClient(mod.app)
    sys.modules.pop("chapter_agent", None)


PUBLIC_GETS = ["/health", "/api/events", "/api/digest", "/api/federation", "/agentfacts.json"]


@pytest.mark.parametrize("path", PUBLIC_GETS)
def test_public_get_is_world_readable_in_prod(prod_client, path):
    """HAPPY: every public keyless GET carries ACAO:* even with an empty
    prod allowlist."""
    r = prod_client.get(path, headers={"Origin": ORIGIN})
    assert r.status_code in (200, 404), f"{path} unexpected status {r.status_code}"
    assert r.headers.get("access-control-allow-origin") == "*", f"{path} must be world-readable cross-origin"


def test_divergence_endpoint_world_readable(prod_client):
    """The divergence read surface is public — it must be reachable by a
    cross-origin monitor."""
    r = prod_client.get("/api/federation/divergence", headers={"Origin": ORIGIN})
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "*"


def test_wellknown_is_world_readable(prod_client):
    r = prod_client.get("/.well-known/agent.json", headers={"Origin": ORIGIN})
    assert r.status_code in (200, 404)
    assert r.headers.get("access-control-allow-origin") == "*"


def test_public_preflight_answered_without_auth(prod_client):
    """HAPPY: an OPTIONS preflight for a public GET is answered directly with
    ACAO:* and no auth — even in prod."""
    r = prod_client.options(
        "/api/federation/divergence",
        headers={"Origin": ORIGIN, "Access-Control-Request-Method": "GET"},
    )
    assert r.status_code == 204
    assert r.headers.get("access-control-allow-origin") == "*"
    assert "GET" in r.headers.get("access-control-allow-methods", "")


def test_authenticated_route_does_not_get_wildcard(prod_client):
    """ADVERSARIAL: the wildcard is scoped to the public set — an authenticated
    surface must NOT become world-readable. In prod (empty allowlist) it carries
    no ACAO at all, and never the wildcard the public middleware adds."""
    r = prod_client.get("/api/surfaces/intents", headers={"Origin": ORIGIN})
    assert r.headers.get("access-control-allow-origin") != "*", (
        "authenticated route leaked the public wildcard (scope breach)"
    )


def test_shared_prefix_post_does_not_get_wildcard(prod_client):
    """ADVERSARIAL: an authenticated POST that shares the /api/federation prefix
    (broadcast inbox) is not a public GET — it must not receive ACAO:*. The
    middleware only stamps GET/HEAD/OPTIONS."""
    r = prod_client.post("/api/federation/broadcast/inbox", json={}, headers={"Origin": ORIGIN})
    # Whatever the handler returns (auth/validation error), it must not be world-CORS'd.
    assert r.headers.get("access-control-allow-origin") != "*", (
        "authenticated POST on a shared prefix leaked the public wildcard (scope breach)"
    )
