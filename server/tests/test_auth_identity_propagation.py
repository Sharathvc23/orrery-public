"""P0 auth fixes — verified-identity propagation + the /api/surfaces/today
private-receipt leak, JSON and SSE.

Three properties are locked here:

  1. ``_resolve_caller`` trusts ONLY the middleware-set ``request.state.agent_id``
     (populated after a valid Ed25519 signature). A spoofed ``X-Agent-ID`` header
     with no verified state yields NO caller — the old header fallback is gone.
  2. ``/api/surfaces/today`` is auth-required even though it sits under the
     otherwise-open ``/api/surfaces/`` prefix: the explicit auth entry wins over
     the open prefix, so an unsigned/spoofed GET is rejected, and a signed caller
     is served THEIR receipts (the verified did:key overrides any client target).
  3. ``/api/surfaces/today/stream`` (SSE, which cannot carry an auth header)
     refuses the principal-private ``today`` page outright rather than serving a
     client-supplied ``target``.

Classification: ADVERSARIAL (attacker spoofs identity to read another principal).
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


# ── request stand-in for the _resolve_caller unit tests ──────────────


class _State:
    def __init__(self, agent_id: str = "") -> None:
        self.agent_id = agent_id


class _Req:
    def __init__(self, state_agent_id: str = "", header_agent_id: str = "") -> None:
        self.state = _State(state_agent_id)
        self.headers = {"X-Agent-ID": header_agent_id} if header_agent_id else {}


# ── That change — _resolve_caller trusts only the verified state ──────────────


def test_resolve_caller_uses_verified_state(chapter_agent_module) -> None:
    req = _Req(state_agent_id="alice", header_agent_id="bob")
    assert chapter_agent_module._resolve_caller(req) == "alice"


def test_resolve_caller_ignores_spoofed_header_without_state(chapter_agent_module) -> None:
    """The core that change fix: a spoofed X-Agent-ID with no verified state is NOT a
    caller. Previously this returned 'bob' (the spoofable header)."""
    req = _Req(state_agent_id="", header_agent_id="bob")
    assert chapter_agent_module._resolve_caller(req) == ""


# ── That change — classification: explicit auth entry wins over open prefix ───


def test_surfaces_today_is_not_open_path() -> None:
    import auth_verify

    assert auth_verify.is_open_path("GET", "/api/surfaces/today") is False


def test_surfaces_today_requires_auth() -> None:
    import auth_verify

    assert auth_verify.requires_auth("GET", "/api/surfaces/today") is True


def test_other_surface_pages_stay_open() -> None:
    """The `today` page is not the only gated one any more, and this test is about
    the ones that are still open.

    `members` was cited here as a public surface; the member-directory closure gated it
    on a human ruling — it rendered the whole membership, including each
    member's free-text description, to anyone. `dashboard` stays open and is the
    example this test still needs.
    """
    import auth_verify

    assert auth_verify.is_open_path("GET", "/api/surfaces/dashboard") is True
    assert auth_verify.is_open_path("GET", "/api/surfaces/members") is False, (
        "member enumeration re-opened — see auth_verify.MEMBER_BEARING_SURFACES"
    )


# ── That change — live middleware: spoofed/unsigned today GET is rejected ─────


def test_unauth_today_spoofed_header_is_rejected(client: TestClient) -> None:
    """No signature, just a spoofed X-Agent-ID — the middleware must 401
    instead of serving the named victim's private receipts."""
    resp = client.get("/api/surfaces/today", headers={"X-Agent-ID": "victim"})
    assert resp.status_code == 401


# ── That change — signed caller is served THEIR receipts, not a spoofed target ──


def test_today_serves_verified_caller_not_spoofed_target(
    client: TestClient, chapter_agent_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    import auth_verify
    import sovereign_identity
    import surfaces

    # Middleware accepts the request as a signed `alice`.
    monkeypatch.setattr(auth_verify, "verify_request", lambda body, headers, **kw: (True, "alice", "verified"))
    # alice has a stored key; her did:key derives from it.
    monkeypatch.setitem(auth_verify._agent_keys, "alice", {"ed25519_pubkey": "ALICEKEY"})
    # A verified signature is read as "this member" only for a registered id.
    monkeypatch.setitem(chapter_agent_module.members, "alice", {"name": "Alice", "public_key": "ALICEKEY"})
    monkeypatch.setattr(sovereign_identity, "build_did_key_from_ed25519", lambda pk: f"did:key:{pk}")

    async def fake_receipts(target):
        return [{"action_category": "test", "human_summary": f"owner={target}", "ts": "2026-06-22T00:00:00Z"}]

    monkeypatch.setattr(surfaces, "_todays_receipts", fake_receipts)

    # Attacker appends a spoofed victim target on the query string.
    resp = client.get(
        "/api/surfaces/today?target=did:key:VICTIM",
        headers={"X-Agent-Signature": "sig", "X-Agent-ID": "alice"},
    )
    assert resp.status_code == 200
    body = resp.text
    assert "did:key:ALICEKEY" in body, "today did not serve the verified caller's receipts"
    assert "VICTIM" not in body, "today honored the spoofed client target — leak"


# ── That change — the SSE sibling refuses the principal-private page ──────────


def test_today_stream_refuses_principal_private_page(client: TestClient) -> None:
    """SSE cannot carry an auth header, so the stream endpoint must not serve
    the principal-private `today` page for a client-supplied target."""
    resp = client.get("/api/surfaces/today/stream?target=did:key:VICTIM&max_iterations=1")
    # 401, not 403, as of that change. `today/stream` was the ONE gated page whose
    # stream was closed — by a check inside the handler, which answered 403 while
    # the other seven gated pages streamed their documents to anyone. The gate is
    # now a middleware rule that a twin inherits from its page, so the refusal
    # arrives before the handler and says the accurate thing: the caller is
    # UNAUTHENTICATED (401), not authenticated-and-forbidden (403). The handler
    # check is left in place — it is now the second layer rather than the only one.
    assert resp.status_code == 401


def test_public_surface_stream_still_works(client: TestClient) -> None:
    """A public page over SSE is unaffected by the today refusal."""
    resp = client.get("/api/surfaces/members/stream?max_iterations=1")
    assert resp.status_code != 403
