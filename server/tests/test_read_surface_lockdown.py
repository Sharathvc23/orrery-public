"""Read-surface lockdown tests (Track 5 of pre-launch audit).

Pre-launch audit (2026-05-10) found these GET endpoints returning 200
unauth + leaking operational details:

  - /api/agents/{id}/export        25KB+ per agent, full record
  - /api/sessions                  active provider+model leak
  - /api/policy                    chapter governance config
  - /api/federation/peers          full backoff/failure history
  - /api/federation/peers/{id}/history
                                   per-peer call history

Plus: 50/50 sequential GETs to enumerable paths succeeded — no rate
limit on read methods.

This module locks the gate: every flagged endpoint either rejects
unauth GET or trims the response to a non-sensitive subset; rate
limit fires after 60 GETs/min/IP on enumeration-prone path families.
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
    chapter_agent_module._rate_limit_store.clear()
    return TestClient(chapter_agent_module.app)


# ---------------------------------------------------------------------------
# requires_auth() classification — the source of truth
# ---------------------------------------------------------------------------


def test_policy_get_requires_auth() -> None:
    """Chapter governance config — leaders only, never public."""
    import auth_verify

    assert auth_verify.requires_auth("GET", "/api/policy") is True


def test_federation_peers_get_requires_auth() -> None:
    import auth_verify

    assert auth_verify.requires_auth("GET", "/api/federation/peers") is True


def test_federation_peer_history_get_requires_auth() -> None:
    """Templated path — uses prefix matching."""
    import auth_verify

    assert auth_verify.requires_auth("GET", "/api/federation/peers/bangalore-chapter/history") is True


def test_agent_export_requires_auth_via_suffix_match() -> None:
    """/api/agents/{id}/export specifically — but the sibling
    /api/agents/{id}/profile MUST stay open by design."""
    import auth_verify

    assert auth_verify.requires_auth("GET", "/api/agents/alice/export") is True
    assert auth_verify.requires_auth("GET", "/api/agents/alice/profile") is False


def test_sensitive_surfaces_require_auth() -> None:
    """SECURITY (I1): per-agent private + operator surfaces must not be
    readable unauthenticated by passing ?target=<id>. Previously only
    /api/surfaces/today was gated, leaking conversations/intents/settings/
    chapter-security to anyone."""
    import auth_verify

    for gated in (
        "/api/surfaces/intents",
        "/api/surfaces/conversations",
        "/api/surfaces/messages",
        "/api/surfaces/settings",
        "/api/surfaces/channels",
        "/api/surfaces/voice",
        "/api/surfaces/chapter-security",
    ):
        assert auth_verify.requires_auth("GET", gated) is True, f"{gated} must require auth"


def test_redacted_public_surfaces_stay_open() -> None:
    """Surfaces with a built-in redacted safe-projection (e.g. audit) stay open
    by design — gating them breaks their intended anonymous redacted view."""
    import auth_verify

    assert auth_verify.requires_auth("GET", "/api/surfaces/audit") is False


def test_public_per_agent_surfaces_stay_open() -> None:
    """The shareable per-agent surfaces (and the opt-in-public chronicle) must
    keep working without an account — gating them would break URL sharing."""
    import auth_verify

    # ⚠️ `directory` and `members` were on this list and were REMOVED by
    # the member-directory closure, on a human ruling. They are not per-agent pages: they
    # rendered the WHOLE membership — name, agent id, skills and the member's own
    # free-text description — to anyone, while GET /api/members was gated for the
    # same population. An audit put an email address and a phone number in a
    # description and both came back to an unauthenticated GET. URL sharing of a
    # directory is not the same thing as URL sharing of one agent's page, and the
    # ruling chose the members' side of that trade knowing it breaks anonymous
    # links to those two pages.
    #
    # The rest stay open, and `reputation` stays deliberately: it discloses its
    # subject's agent_id and nothing more, which is what a per-agent page is for.
    #
    # ⚠️ That last sentence was written as if it covered all five and it does
    # NOT cover `endorsements`. `profile`, `reputation`, `trust` and
    # `chronicle` disclose the SUBJECT, who chose to share the page; an
    # endorsement names a THIRD PARTY, the endorser, who made no such choice.
    # `endorsements` stays open on a different basis: its builder redacts the
    # endorser to a chapter_role, so the page discloses its subject plus a role
    # per endorsement and no third-party identity. The redaction is what makes
    # the openness defensible — see
    # test_group2_endorsements_surface_redaction.py, which asserts it against
    # the response BYTES, and keep both tests when touching either.
    for public in (
        "/api/surfaces/profile",
        "/api/surfaces/reputation",
        "/api/surfaces/trust",
        "/api/surfaces/endorsements",
        "/api/surfaces/chronicle",  # intentionally public when opted in (handler gate)
    ):
        assert auth_verify.requires_auth("GET", public) is False, f"{public} must stay open"


def test_public_open_paths_remain_open() -> None:
    """Lock the contract: the discovery + public-read surface stays
    open. A future PR that accidentally adds /api/version or /health
    to the auth-required list breaks the bootstrap document."""
    import auth_verify

    for public_path in (
        "/",
        "/health",
        "/api/version",
        # NOT /api/members — The enumeration closure moved the member DIRECTORY behind auth (bulk
        # enumeration of every member's PII). The bootstrap document itself
        # never needed it; the exact-match /api/agents/{id}/profile stays open
        # (its near-duplicate, /api/member/{id}/profile, was retired).
        "/api/thoughts",
        "/api/federation",  # the public summary, NOT /peers
        "/agentfacts.json",
    ):
        assert auth_verify.requires_auth("GET", public_path) is False, f"{public_path} must stay open"


# ---------------------------------------------------------------------------
# Live endpoint behaviour — middleware enforces classification
# ---------------------------------------------------------------------------


def test_unauth_policy_get_is_rejected(client: TestClient) -> None:
    resp = client.get("/api/policy")
    assert resp.status_code == 401


def test_unauth_federation_peers_get_is_rejected(client: TestClient) -> None:
    resp = client.get("/api/federation/peers")
    assert resp.status_code == 401


def test_unauth_agent_export_get_is_rejected(client: TestClient) -> None:
    resp = client.get("/api/agents/alice/export")
    assert resp.status_code == 401


def test_unauth_agent_profile_get_still_works(client: TestClient) -> None:
    """Public profile primitive must keep working — sharing the URL
    on Twitter/LinkedIn must not require an account."""
    resp = client.get("/api/agents/alice/profile")
    # 404 is acceptable (member doesn't exist in fixture); 401 is NOT.
    assert resp.status_code != 401


# ---------------------------------------------------------------------------
# /api/sessions response trimming — auth determines field set
# ---------------------------------------------------------------------------


def test_sessions_unauth_response_omits_provider_and_model(client: TestClient, chapter_agent_module) -> None:
    """Unauth callers must NOT see provider, model, thought_count,
    tool_calls — those are the operational telemetry the audit flagged.
    They get only agent_id + status + last_action_at (liveness)."""

    # Seed a fake session into the in-memory runtime.
    class _FakeSession:
        status = "active"
        provider = "xai"
        model = "grok-3-mini"
        thought_count = 7
        tool_calls = 3
        last_action_at = "2026-05-10T00:00:00Z"

    chapter_agent_module.sovereign_runtime.sessions["alice"] = _FakeSession()

    resp = client.get("/api/sessions")
    assert resp.status_code == 200
    sessions = resp.json()["sessions"]
    assert sessions, "/api/sessions returned empty even though we seeded one"
    s = sessions[0]
    # Must include — liveness fields.
    assert s["agent_id"] == "alice"
    assert "last_action_at" in s
    # Must NOT include — operational telemetry.
    assert "provider" not in s, "leaked provider in unauth response"
    assert "model" not in s, "leaked model in unauth response"
    assert "thought_count" not in s, "leaked thought_count in unauth response"
    assert "tool_calls" not in s, "leaked tool_calls in unauth response"


@pytest.mark.parametrize("path", ["/api/sessions", "/api/sessions/"])
def test_sessions_spoofed_x_auth_status_header_does_not_unlock_the_rich_tier(
    client: TestClient, chapter_agent_module, path: str
) -> None:
    """THE GUARD, both registered forms of the route.

    The bare path is in auth_verify.IDENTITY_AWARE_OPEN_PATHS, so the
    middleware sets X-Auth-Status on the RESPONSE there — never reads one off
    the request. The old handler read request.headers.get('X-Auth-Status')
    instead, which is exactly the header a caller controls: any anonymous GET
    carrying `X-Auth-Status: verified` got the rich tier. The /-suffixed twin
    was never in OPEN_PATHS at all, so it always ran real signature
    verification regardless of this fix — parametrized over both so a future
    change to either path's classification cannot silently reopen one of them.
    Driven end-to-end through the real ASGI app, not a handler-level
    stand-in, because the bug lived at the middleware/handler boundary."""

    class _FakeSession:
        status = "active"
        provider = "xai"
        model = "grok-3-mini"
        thought_count = 7
        tool_calls = 3
        last_action_at = "2026-05-10T00:00:00Z"

    chapter_agent_module.sovereign_runtime.sessions["alice"] = _FakeSession()

    resp = client.get(path, headers={"X-Auth-Status": "verified"})
    assert resp.status_code == 200
    s = resp.json()["sessions"][0]
    assert "provider" not in s, f"a spoofed X-Auth-Status header unlocked the rich tier on {path}"
    assert "model" not in s
    assert "thought_count" not in s
    assert "tool_calls" not in s


def test_sessions_verified_request_state_unlocks_the_rich_tier(chapter_agent_module) -> None:
    """The mechanism that replaced the header: request.state.verified, set by
    the middleware only after a real signature check (never by the caller).
    Driven at the handler level with a stand-in Request — same pattern as
    test_resolve_caller_uses_verified_state — since constructing a live signed
    request end-to-end tests the signing stack, not this property."""
    import asyncio

    class _FakeSession:
        status = "active"
        provider = "xai"
        model = "grok-3-mini"
        thought_count = 7
        tool_calls = 3
        last_action_at = "2026-05-10T00:00:00Z"

    class _State:
        verified = True

    class _Req:
        state = _State()
        headers: dict = {"X-Auth-Status": "unverified:no_signature"}  # must be ignored

    chapter_agent_module.sovereign_runtime.sessions["alice"] = _FakeSession()
    result = asyncio.run(chapter_agent_module.list_sessions(_Req()))
    s = result["sessions"][0]
    assert s["provider"] == "xai", "request.state.verified=True did not unlock the rich tier"
    assert s["model"] == "grok-3-mini"
    assert s["thought_count"] == 7
    assert s["tool_calls"] == 3


# ---------------------------------------------------------------------------
# /api/runtimes response trimming — same tiering, same reason, as /api/sessions
# ---------------------------------------------------------------------------


def test_runtimes_unauth_response_omits_provider_and_model(client: TestClient, chapter_agent_module) -> None:
    """Baseline: an anonymous caller sees only agent_id, status, last_thought_at.
    Until this fix, GET /api/runtimes returned provider/model/thought_count/
    conversation_count unconditionally — the same class of data /api/sessions
    was hardened to hide."""

    class _FakeRuntime:
        status = "active"
        provider = "xai"
        model = "grok-3-mini"
        thought_count = 4
        conversation_count = 2
        last_thought_at = "2026-05-10T00:00:00Z"

    chapter_agent_module.member_runtime.runtimes["alice"] = _FakeRuntime()

    resp = client.get("/api/runtimes")
    assert resp.status_code == 200
    runtimes = resp.json()["runtimes"]
    assert runtimes, "/api/runtimes returned empty even though we seeded one"
    rt = runtimes[0]
    assert rt["agent_id"] == "alice"
    assert "last_thought_at" in rt
    assert "provider" not in rt, "leaked provider in unauth response"
    assert "model" not in rt, "leaked model in unauth response"
    assert "thought_count" not in rt, "leaked thought_count in unauth response"
    assert "conversation_count" not in rt, "leaked conversation_count in unauth response"


@pytest.mark.parametrize("path", ["/api/runtimes", "/api/runtimes/"])
def test_runtimes_spoofed_x_auth_status_header_does_not_unlock_the_rich_tier(
    client: TestClient, chapter_agent_module, path: str
) -> None:
    """THE GUARD, runtimes half, both registered forms. Same shape as the
    sessions guard above."""

    class _FakeRuntime:
        status = "active"
        provider = "xai"
        model = "grok-3-mini"
        thought_count = 4
        conversation_count = 2
        last_thought_at = "2026-05-10T00:00:00Z"

    chapter_agent_module.member_runtime.runtimes["alice"] = _FakeRuntime()

    resp = client.get(path, headers={"X-Auth-Status": "verified"})
    assert resp.status_code == 200
    rt = resp.json()["runtimes"][0]
    assert "provider" not in rt, f"a spoofed X-Auth-Status header unlocked the rich tier on {path}"
    assert "model" not in rt
    assert "thought_count" not in rt
    assert "conversation_count" not in rt


def test_runtimes_verified_request_state_unlocks_the_rich_tier(chapter_agent_module) -> None:
    """request.state.verified, not a header, unlocks the rich tier."""
    import asyncio

    class _FakeRuntime:
        status = "active"
        provider = "xai"
        model = "grok-3-mini"
        thought_count = 4
        conversation_count = 2
        last_thought_at = "2026-05-10T00:00:00Z"

    class _State:
        verified = True

    class _Req:
        state = _State()
        headers: dict = {}

    chapter_agent_module.member_runtime.runtimes["alice"] = _FakeRuntime()
    result = asyncio.run(chapter_agent_module.list_runtimes(_Req()))
    rt = result["runtimes"][0]
    assert rt["provider"] == "xai", "request.state.verified=True did not unlock the rich tier"
    assert rt["model"] == "grok-3-mini"
    assert rt["thought_count"] == 4
    assert rt["conversation_count"] == 2


def test_sessions_and_runtimes_bare_paths_are_identity_aware_open_paths() -> None:
    """The classification the fix depends on for the bare paths: they stay
    open (no 401 for an unsigned caller) but the middleware verifies a
    signature when one is present, per auth_verify.is_identity_aware_open_path
    — so request.state.verified is a real, non-spoofable signal for them."""
    import auth_verify

    for path in ("/api/sessions", "/api/runtimes"):
        assert auth_verify.is_open_path("GET", path) is True, f"{path} must stay open"
        assert auth_verify.is_identity_aware_open_path("GET", path) is True, (
            f"{path} must be identity-aware so request.state.verified is real"
        )


def test_sessions_and_runtimes_trailing_slash_never_took_the_open_short_circuit() -> None:
    """The /-suffixed twins were never declared in OPEN_PATHS, so they never
    took the is_open_path short-circuit at all — the generic middleware path
    runs verify_request unconditionally for them regardless of identity
    awareness, which is why the header-spoofing bug was only ever reachable
    through the bare path. Not classified open here on purpose: fixing that
    inconsistency is a separate decision from closing the spoof, and is
    already recorded as its own pending-ruling entry."""
    import auth_verify

    for path in ("/api/sessions/", "/api/runtimes/"):
        assert auth_verify.is_open_path("GET", path) is False
        assert auth_verify.requires_auth("GET", path) is False


# ---------------------------------------------------------------------------
# Rate limiting on enumerable GET paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/api/members",
        "/api/thoughts",
        "/api/sessions",
        "/api/agents/alice/profile",
        "/api/runtimes",
        "/api/knowledge/network",
    ],
)
def test_rate_limited_path_classification(chapter_agent_module, path: str) -> None:
    """Every enumeration-prone path family is flagged as rate-limited."""
    assert chapter_agent_module._is_rate_limited_get_path(path) is True


def test_non_enumerable_path_not_rate_limited(chapter_agent_module) -> None:
    """The bootstrap surface (/, /health, /api/version) is NOT rate-
    limited — would break legitimate health probes and version
    negotiation under load."""
    for path in ("/", "/health", "/api/version", "/agentfacts.json"):
        assert chapter_agent_module._is_rate_limited_get_path(path) is False


def test_get_rate_limit_kicks_in_after_60_requests(
    client: TestClient, chapter_agent_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pre-launch audit: 50/50 sequential GETs to /api/members all
    succeeded. After this PR, 60 are allowed; the 61st gets 429.

    Use a stable client_ip so the in-memory bucket fills up — TestClient
    sets request.client.host to 'testclient' by default.

    The throttle runs BEFORE the auth gate, so an unauthenticated caller is
    throttled too — which is what matters for a scraper. The enumeration closure auth-gated this
    path, so under the ceiling the anonymous answer is 401, never 200; the
    contract under test is that the 429 arrives, not what the pre-ceiling
    status is."""
    monkeypatch.setattr(chapter_agent_module, "pg_request", _noop_supabase)

    # Burn the bucket. Use a small ceiling override so the test stays fast.
    monkeypatch.setattr(chapter_agent_module, "RATE_LIMIT_GET_MAX", 5)

    # Prime: every request below the ceiling reaches the auth gate un-throttled.
    for i in range(5):
        resp = client.get("/api/members")
        assert resp.status_code == 401, f"request {i + 1} unexpectedly throttled"

    # The 6th must hit 429 with the documented headers.
    resp = client.get("/api/members")
    assert resp.status_code == 429
    body = resp.json()
    assert "rate" in body["error"].lower()
    assert "Retry-After" in resp.headers


def test_get_rate_limit_does_not_apply_to_health(
    client: TestClient, chapter_agent_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    """/health must remain throttle-free even after a flood of other
    GETs — load balancers + monitoring will hammer it."""
    monkeypatch.setattr(chapter_agent_module, "RATE_LIMIT_GET_MAX", 3)

    # Burn the rate limit bucket via /api/members.
    monkeypatch.setattr(chapter_agent_module, "pg_request", _noop_supabase)
    for _ in range(5):
        client.get("/api/members")

    # /health still returns 200 even with the bucket full.
    resp = client.get("/health")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _noop_supabase(*_, **__):  # noqa: ARG001
    return []
