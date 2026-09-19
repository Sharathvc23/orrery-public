"""API ergonomics tests (Track 4 of pre-launch audit).

The audit found four small papercuts on the chapter's public surface:

  1. ``GET /``          → FastAPI default 404, not a friendly landing
  2. ``HEAD /health``   → 405 Method Not Allowed (breaks load balancers)
  3. ``GET /api/docs``  → 404 (devs reflexively look there because the
                          rest of the surface is namespaced under /api)
  4. ``GET /api/version`` → only advertised v0.2 / v0.3, not v0.4

This module locks the fix for each so they cannot regress.
"""

from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def chapter_agent_module(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_ID", "TEST-fixture-chapter")
    monkeypatch.setenv("AGENT_NAME", "Fixture")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.delenv("CHAPTER_SLUG", raising=False)
    monkeypatch.delenv("CHAPTER_DISPLAY_NAME", raising=False)
    sys.modules.pop("chapter_agent", None)
    return importlib.import_module("chapter_agent")


@pytest.fixture
def client(chapter_agent_module) -> TestClient:
    return TestClient(chapter_agent_module.app)


# ---------------------------------------------------------------------------
# GET / — friendly landing
# ---------------------------------------------------------------------------


def test_root_landing_returns_pointer_doc(client: TestClient) -> None:
    """First-contact GET must NOT be 404 — return a JSON pointer to
    every discoverable surface so a developer probing the bare hostname
    knows where to go next."""
    resp = client.get("/")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # Identity fields tell the caller what they hit.
    assert body["agent_id"]
    assert body["kind"] == "nanda-chapter"
    assert body["name"]
    assert body["slug"]

    # Endpoint pointers cover every surface a stranger needs to navigate.
    endpoints = body["endpoints"]
    for required_pointer in (
        "health",
        "version",
        "agentfacts",
        "well_known",
        "docs",
        "openapi",
        "dashboard_surface",
        "members",
        "thoughts",
    ):
        assert required_pointer in endpoints, f"GET / pointer set missing {required_pointer!r}"


# ---------------------------------------------------------------------------
# HEAD /health — load balancer support
# ---------------------------------------------------------------------------


def test_head_health_returns_200_not_405(client: TestClient) -> None:
    """Common load-balancer probes (HAProxy, nginx upstream checks,
    k8s liveness with HEAD) must succeed, not see 405. FastAPI does not
    add HEAD handlers automatically — the empty-200 must be explicit."""
    resp = client.head("/health")
    assert resp.status_code == 200, (
        f"HEAD /health returned {resp.status_code}; load balancers will mark the chapter as down"
    )
    # HEAD must not return a body (the response body would be discarded
    # anyway, but FastAPI's empty Response is the canonical shape).
    assert resp.content == b""


def test_get_health_still_returns_full_body(client: TestClient) -> None:
    """Adding a HEAD handler must not affect GET — the existing
    health-payload contract is unchanged."""
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("status") == "ok"
    assert "agent_id" in body


# ---------------------------------------------------------------------------
# GET /api/docs — redirect to canonical Swagger UI
# ---------------------------------------------------------------------------


def test_api_docs_redirects_to_docs(client: TestClient) -> None:
    """The Swagger UI lives at FastAPI's default /docs. /api/docs is a
    common typo — redirect (308 preserves method + body) so devs land
    where they expected."""
    resp = client.get("/api/docs", follow_redirects=False)
    assert resp.status_code == 308
    assert resp.headers["location"] == "/docs"


def test_api_docs_redirect_resolves_to_swagger(monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end: following the redirect lands on the actual UI — under the DEV
    profile. That change: the default profile is now prod (docs OFF), so this dev-ergonomics
    path is asserted with an explicit ORRERY_PROFILE=dev import."""
    monkeypatch.setenv("ORRERY_PROFILE", "dev")
    monkeypatch.setenv("AGENT_ID", "TEST-ergo-dev")
    monkeypatch.setenv("AGENT_NAME", "Ergo Dev")
    sys.modules.pop("chapter_agent", None)
    mod = importlib.import_module("chapter_agent")
    try:
        resp = TestClient(mod.app).get("/api/docs", follow_redirects=True)
        assert resp.status_code == 200
        # Swagger UI is HTML containing "swagger-ui" markup.
        assert "swagger" in resp.text.lower() or "openapi" in resp.text.lower()
    finally:
        sys.modules.pop("chapter_agent", None)


# ---------------------------------------------------------------------------
# GET /api/version — advertise the accepted majors + A2UI versions
# ---------------------------------------------------------------------------


def test_version_advertises_accepted_protocol_majors(client: TestClient) -> None:
    """Chapters MUST list every major they accept so clients can negotiate.
    This org implements 0.5 and still accepts 0.2/0.3/0.4 — 0.2 within
    the scope stated in `signature_scheme_scope`. The 0.5 claim itself, and the
    clauses that make it true, are prosecuted in test_spec_05_advertisement.py."""
    resp = client.get("/api/version")
    body = resp.json()
    assert "0.5" in body["protocol_versions"]
    assert "0.4" in body["protocol_versions"]
    assert "0.3" in body["protocol_versions"]  # backward compat
    assert "0.2" in body["protocol_versions"]


def test_version_advertises_a2ui_version_set(client: TestClient) -> None:
    """v0.4 protocol introduces a2ui_versions + preferred_a2ui_version.
    Lock the closed set so a future PR cannot drop a version without a
    test reminding them this is wire-stable."""
    resp = client.get("/api/version")
    body = resp.json()

    assert "a2ui_versions" in body
    assert set(body["a2ui_versions"]) == {"0.8", "0.9", "0.10"}
    # Default emit is still v0.9 — the chapter's a2ui_helpers default
    # output is v0.9 until the surface adoption follow-up flips it.
    assert body["preferred_a2ui_version"] == "0.10"


def test_version_preferred_protocol_is_at_least_0_3(client: TestClient) -> None:
    """preferred_version is the version the chapter speaks fluently. We
    don't claim 0.4 as preferred until surfaces emit v0.10 by default —
    but 0.3 is the minimum acceptable preferred."""
    resp = client.get("/api/version")
    body = resp.json()
    pref = body["preferred_version"]
    # Lexicographic compare is fine for these short numeric strings.
    assert pref >= "0.3"


def test_version_endpoint_unauthenticated(client: TestClient) -> None:
    """/api/version is the bootstrap document. Any auth requirement
    here would create a chicken-and-egg with negotiation."""
    # No headers at all — must succeed.
    resp = client.get("/api/version")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# GET /.well-known/conformance.json — public signed conformance badge
# ---------------------------------------------------------------------------


def test_conformance_badge_served_unauthenticated(client: TestClient, chapter_agent_module) -> None:
    """The signed conformance badge is public — served with NO X-Agent-Signature.
    Gating a proof anyone can verify offline would defeat its purpose. Returns
    the full envelope (payload + signed_by + signature).

    The badge is deployment-generated (each runtime signs its own by running the
    conformance suite), so it is not committed to the repo — skip when absent.
    """
    if not chapter_agent_module._CONFORMANCE_BADGE_PATH.exists():
        pytest.skip("conformance badge is deployment-generated; not committed to the repo")
    resp = client.get("/.well-known/conformance.json")  # deliberately no auth headers
    assert resp.status_code == 200
    body = resp.json()
    assert body["payload"]["runtime"] == "chapter"
    assert body["signed_by"].startswith("did:key:")
    assert isinstance(body["signature"], str) and body["signature"]


def test_well_known_advertises_conformance_url(client: TestClient) -> None:
    """Discovery is one hop: the well-known doc points at the badge URL."""
    body = client.get("/.well-known/nanda-agent.json").json()
    assert body["conformance"].endswith("/.well-known/conformance.json")


def test_conformance_badge_404_when_absent(chapter_agent_module, monkeypatch: pytest.MonkeyPatch) -> None:
    """Boundary: a chapter that has not published a badge returns a clean 404,
    not a 500 or a stale/empty 200."""
    from pathlib import Path

    monkeypatch.setattr(
        chapter_agent_module,
        "_CONFORMANCE_BADGE_PATH",
        Path("/nonexistent/conformance.json"),
    )
    bare = TestClient(chapter_agent_module.app)
    assert bare.get("/.well-known/conformance.json").status_code == 404
