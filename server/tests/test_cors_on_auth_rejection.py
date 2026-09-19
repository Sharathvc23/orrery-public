"""auth rejections must carry CORS headers.

The auth middleware emits 401s directly; with CORS registered as an INNER
middleware those responses never passed back through it, so a cross-origin
browser saw an opaque network error instead of a readable 401 — it could not
tell "unauthorized" from "server down". CORS is now the outermost layer.
Header-layer fix only: auth semantics are asserted unchanged.

Classification: HAPPY / EDGE / FAILURE.
"""

import importlib
import os
import sys

os.environ.setdefault("AGENT_ID", "test-cors-chapter")
os.environ.setdefault("AGENT_NAME", "Test CORS Chapter")

import pytest
from fastapi.testclient import TestClient

ORIGIN = "http://portal.example"


@pytest.fixture
def client(monkeypatch):
    # the DEFAULT profile is now prod (empty CORS allowlist), so a foreign
    # origin gets no ACAO. The ordering fix (CORS outermost so a 401 is still
    # browser-readable) only has an effect when CORS is active — reimport under the
    # REAL deployed shape: prod with an explicit allowlist that includes ORIGIN.
    monkeypatch.setenv("ORRERY_PROFILE", "prod")
    monkeypatch.setenv("ALLOWED_ORIGINS", ORIGIN)
    monkeypatch.setenv("AGENT_ID", "test-cors-chapter")
    monkeypatch.setenv("AGENT_NAME", "Test CORS Chapter")
    sys.modules.pop("chapter_agent", None)
    mod = importlib.import_module("chapter_agent")
    yield TestClient(mod.app)
    sys.modules.pop("chapter_agent", None)


def test_gated_surface_401_carries_cors_headers(client):
    """FAILURE path (the bug): an unauthenticated cross-origin request to
    a gated surface still gets a 401 the BROWSER CAN READ."""
    r = client.get("/api/surfaces/intents", headers={"Origin": ORIGIN})
    assert r.status_code == 401  # auth semantics unchanged
    assert "access-control-allow-origin" in r.headers, "401 lost its CORS headers (regression)"
    assert r.json().get("error"), "401 body must stay readable"


def test_preflight_on_gated_surface_succeeds_without_auth(client):
    """HAPPY: the CORS preflight is handled by the CORS layer, unauthenticated
    by design (spec behavior) — it must not 401."""
    r = client.options(
        "/api/surfaces/intents",
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-agent-signature,x-agent-id",
        },
    )
    assert r.status_code == 200
    assert "access-control-allow-origin" in r.headers
    allowed = r.headers.get("access-control-allow-headers", "").lower()
    assert "x-agent-signature" in allowed or allowed == "*"


def test_open_surface_success_still_carries_cors(client):
    """EDGE: the success path keeps its CORS headers (outermost layer serves
    both directions)."""
    r = client.get("/health", headers={"Origin": ORIGIN})
    assert r.status_code == 200
    assert "access-control-allow-origin" in r.headers


def test_auth_status_header_still_stamped_on_pass_through(client):
    """EDGE: the auth middleware still runs and stamps X-Auth-Status on
    responses that pass through it — ordering change only."""
    r = client.get("/health")
    assert r.headers.get("x-auth-status", "").startswith(("verified", "unverified", "open"))
