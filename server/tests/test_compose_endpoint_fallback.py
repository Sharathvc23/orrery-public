"""Endpoint-level tests for POST /api/surfaces/compose — the safe
fallback to the default shell.

The public claim is: "Agents that render their own UI from intent once
you supply a model key, with a safe fallback to the default shell."

The composer itself (surface_composer) is unit-tested in
test_surface_composer.py. What was previously *unverified* — and what
made the claim only half-true — is the endpoint behaviour when the LLM
round-trip fails: it used to 500. These tests pin the new contract:

  * LLM SUCCESS            → 200, composed surface, NO `fallback` flag.
  * CompositionError       → 200, `fallback: true`, valid A2UI shell.
  * generic LLM/net error  → 200, `fallback: true`, valid A2UI shell.
  * empty / oversized intent → 400 (input validation is unchanged).

All of this runs keyless in CI: `surface_composer.compose_cached` /
`.compose` are monkeypatched so no real model key is ever needed.
"""

from __future__ import annotations

import os

os.environ.setdefault("AGENT_ID", "test-compose-chapter")
os.environ.setdefault("AGENT_NAME", "Test Compose Chapter")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import chapter_agent  # noqa: E402
import surface_composer as sc  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_rate_limit():
    """Isolate the in-memory per-IP rate limiter across tests."""
    chapter_agent._rate_limit_store.clear()
    yield
    chapter_agent._rate_limit_store.clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(chapter_agent.app)


def _valid_composed_result() -> sc.CompositionResult:
    """A plausible LLM-composed surface (as compose() would return)."""
    from a2ui_helpers import column, surface, text

    components = [
        column("root", ["greeting"]),
        text("greeting", "Your impact this month", "h1"),
    ]
    return sc.CompositionResult(
        surface=surface("composed-abc123", components, "root"),
        unknown_components=(),
        dangling_references=(),
        raw_component_count=len(components),
        final_component_count=len(components),
    )


def _assert_renderable_a2ui(surf: dict) -> None:
    """A2UI v0.9/v0.10 envelope the renderer can paint: createSurface +
    updateComponents(root + components), root resolves to a real
    component, and a version tag is present."""
    assert isinstance(surf, dict)
    assert "createSurface" in surf
    assert "version" in surf
    uc = surf["updateComponents"]
    assert uc["surfaceId"] == surf["createSurface"]["surfaceId"]
    root = uc["root"]
    components = uc["components"]
    assert isinstance(components, list) and components
    ids = {c["id"] for c in components}
    assert root in ids, "root must reference a declared component"
    # Root is a layout component (same rule the composer enforces).
    root_cmp = next(c for c in components if c["id"] == root)
    assert root_cmp["component"] in {"Card", "Column", "Row", "Grid", "Tabs"}


# ── LLM SUCCESS ───────────────────────────────────────────────────


def test_success_returns_composed_surface_no_fallback_flag(client, monkeypatch):
    composed = _valid_composed_result()

    def _fake_compose_cached(intent, **kwargs):
        return composed, False

    monkeypatch.setattr(sc, "compose_cached", _fake_compose_cached)

    r = client.post("/api/surfaces/compose", json={"intent": "show me my impact this month"})
    assert r.status_code == 200
    body = r.json()
    assert body["surface"] == composed.surface
    assert body["cache_hit"] is False
    assert body["final_component_count"] == 2
    # Success path carries NO fallback flag.
    assert "fallback" not in body
    assert "reason" not in body
    _assert_renderable_a2ui(body["surface"])


def test_success_bypass_cache_uses_compose(client, monkeypatch):
    composed = _valid_composed_result()

    def _fake_compose(intent, **kwargs):
        return composed

    monkeypatch.setattr(sc, "compose", _fake_compose)

    r = client.post(
        "/api/surfaces/compose",
        json={"intent": "novel intent", "bypass_cache": True},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["surface"] == composed.surface
    assert "fallback" not in body


# ── CompositionError → graceful 200 fallback ──────────────────────


def test_composition_error_degrades_to_200_fallback(client, monkeypatch):
    def _boom(intent, **kwargs):
        raise sc.CompositionError("LLM did not call emit_surface")

    monkeypatch.setattr(sc, "compose_cached", _boom)

    r = client.post("/api/surfaces/compose", json={"intent": "compose me something novel"})
    # The whole point: NOT a 500.
    assert r.status_code == 200
    body = r.json()
    assert body["fallback"] is True
    assert isinstance(body["reason"], str) and body["reason"]
    assert body["reason"].startswith("composition_failed")
    _assert_renderable_a2ui(body["surface"])


# ── generic LLM / network error → graceful 200 fallback ───────────


def test_generic_llm_error_degrades_to_200_fallback(client, monkeypatch):
    def _boom(intent, **kwargs):
        raise TimeoutError("upstream model timed out")

    monkeypatch.setattr(sc, "compose_cached", _boom)

    r = client.post("/api/surfaces/compose", json={"intent": "another novel intent"})
    assert r.status_code == 200
    body = r.json()
    assert body["fallback"] is True
    assert body["reason"].startswith("llm_error: TimeoutError")
    _assert_renderable_a2ui(body["surface"])


def test_generic_error_on_bypass_cache_also_falls_back(client, monkeypatch):
    def _boom(intent, **kwargs):
        raise ConnectionError("model endpoint unreachable")

    monkeypatch.setattr(sc, "compose", _boom)

    r = client.post(
        "/api/surfaces/compose",
        json={"intent": "novel intent", "bypass_cache": True},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["fallback"] is True
    assert body["reason"].startswith("llm_error: ConnectionError")
    _assert_renderable_a2ui(body["surface"])


# ── input validation is unchanged (still 4xx, never a fallback) ───


def test_empty_intent_is_400(client, monkeypatch):
    def _should_not_run(intent, **kwargs):
        raise AssertionError("composer must not be called for empty intent")

    monkeypatch.setattr(sc, "compose_cached", _should_not_run)

    r = client.post("/api/surfaces/compose", json={"intent": "   "})
    assert r.status_code == 400
    assert "intent required" in r.json()["detail"]


def test_oversized_intent_is_400(client, monkeypatch):
    def _should_not_run(intent, **kwargs):
        raise AssertionError("composer must not be called for oversized intent")

    monkeypatch.setattr(sc, "compose_cached", _should_not_run)

    r = client.post("/api/surfaces/compose", json={"intent": "x" * 1001})
    assert r.status_code == 400
    assert "too long" in r.json()["detail"]


# ── the fallback surface itself is pure + cannot raise ────────────


def test_fallback_surface_is_pure_and_valid():
    """`fallback_surface` builds only from a2ui_helpers pure builders,
    so it never raises and is always renderable — the property that
    makes the endpoint's guarantee real."""
    result = sc.fallback_surface("llm_error: whatever")
    _assert_renderable_a2ui(result.surface)
    assert result.unknown_components == ()
    assert result.dangling_references == ()
    assert result.final_component_count == result.raw_component_count > 0
    # Deterministic: reason text is not painted into the shell.
    dumped = str(result.surface)
    assert "whatever" not in dumped


# ── a chapter with no provider key makes no outbound request ────────


class _OutboundAttempted(AssertionError):
    """Raised by the socket guard below when a non-loopback connect is tried."""


@pytest.fixture
def no_outbound(monkeypatch):
    """Fail the test if anything opens a connection off this machine.

    Asserted at the socket, not at the client object. A test that only checks the
    response body passes just as happily while the request is being made and
    rejected — which is the exact shape of the defect this guards. TestClient
    drives the app in-process over ASGI and opens no socket, so any connect that
    does happen came from the code under test.
    """
    import socket

    real_connect = socket.socket.connect
    attempts: list[str] = []

    def guarded(self, address, *a, **kw):
        host = address[0] if isinstance(address, tuple) else str(address)
        if host not in {"127.0.0.1", "::1", "localhost", ""}:
            attempts.append(str(address))
            raise _OutboundAttempted(f"outbound connection attempted to {address!r}")
        return real_connect(self, address, *a, **kw)

    monkeypatch.setattr(socket.socket, "connect", guarded)
    return attempts


def test_keyless_chapter_composes_without_contacting_a_provider(client, monkeypatch, no_outbound):
    """The claim is that a chapter with no model key needs no provider. With
    detection falling through to a default, the client is aimed at a real remote
    endpoint, so 'no key' has to mean 'no call' rather than 'a call that fails'."""
    monkeypatch.setattr(chapter_agent.llm_config, "API_KEY", "")
    monkeypatch.setattr(chapter_agent.llm_config, "BASE_URL", "https://api.anthropic.com/v1/")

    body = client.post("/api/surfaces/compose", json={"intent": "show me the agents"}).json()

    assert no_outbound == [], f"a keyless chapter reached out: {no_outbound}"
    assert body["fallback"] is True
    assert body["reason"].startswith("planner_disabled:")
    assert body["surface"]["createSurface"]["surfaceId"] == "composed-fallback"


def test_keyless_chapter_never_reaches_the_composer(client, monkeypatch, no_outbound):
    """Same property one layer up: the composer is not entered at all, so no
    prompt is built and nothing is queued for a provider."""
    called: list[str] = []
    monkeypatch.setattr(chapter_agent.llm_config, "API_KEY", "")
    monkeypatch.setattr(chapter_agent.llm_config, "BASE_URL", "https://api.anthropic.com/v1/")
    monkeypatch.setattr(sc, "compose_cached", lambda *a, **kw: called.append("compose_cached"))
    monkeypatch.setattr(sc, "compose", lambda *a, **kw: called.append("compose"))

    client.post("/api/surfaces/compose", json={"intent": "show me the agents"})
    assert called == [], f"the composer ran without a provider: {called}"


def test_a_local_model_needs_no_key(client, monkeypatch):
    """Ollama, LM Studio, llama.cpp and vLLM are configured with no key and a
    loopback endpoint. That is a working setup, not an unconfigured one, so the
    planner must stay on — the guard is about not calling a third party, not
    about the presence of a key."""
    monkeypatch.setattr(chapter_agent.llm_config, "API_KEY", "")
    monkeypatch.setattr(chapter_agent.llm_config, "BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setattr(sc, "compose_cached", lambda *a, **kw: (sc.fallback_surface("stub"), False))

    body = client.post("/api/surfaces/compose", json={"intent": "show me the agents"}).json()
    assert body.get("reason", "").startswith("planner_disabled:") is False, "a local model was treated as no provider"


def test_planner_enabled_reads_key_and_locality():
    """The condition itself, without the endpoint around it."""
    import llm_config

    cases = [
        ("", "https://api.anthropic.com/v1/", False),
        ("sk-real", "https://api.anthropic.com/v1/", True),
        ("", "http://localhost:11434/v1", True),
        ("", "http://127.0.0.1:1234/v1", True),
        ("", "http://my-gpu-box.internal:8000/v1", False),
    ]
    saved = (llm_config.API_KEY, llm_config.BASE_URL)
    try:
        for key, base, expected in cases:
            llm_config.API_KEY, llm_config.BASE_URL = key, base
            assert llm_config.planner_enabled() is expected, f"key={key!r} base={base!r}"
    finally:
        llm_config.API_KEY, llm_config.BASE_URL = saved


# ── M10: the unauthenticated LLM endpoint is on the expensive tier ───────────
# /api/surfaces/compose takes no credential and calls an LLM per request. It was
# absent from EXPENSIVE_WRITE_LIMITS, so it inherited the generic 30/min write
# ceiling — six times the allowance of /api/digest/build, which is on that table
# for the same reason and does strictly more work per call.


def test_compose_is_on_the_expensive_write_tier():
    """ADVERSARIAL: an unauthenticated LLM call must not sit on the generic ceiling."""
    import chapter_agent as ca

    limits = ca.EXPENSIVE_WRITE_LIMITS
    assert "/api/surfaces/compose" in limits, (
        "compose calls an LLM per request with no credential; leaving it off this "
        "table gives an anonymous caller the generic write budget"
    )
    assert limits["/api/surfaces/compose"] <= limits["/api/digest/build"] * 2, (
        "compose must stay in the same order as the sibling LLM endpoint"
    )
    assert limits["/api/surfaces/compose"] < ca.RATE_LIMIT_MAX, (
        "the whole point is that it is tighter than the generic write ceiling"
    )


def test_compose_is_actually_unauthenticated():
    """EDGE: pins the premise. If compose ever stops being open, this ceiling is
    no longer the only thing standing between an anonymous caller and the LLM
    bill, and the reasoning above should be revisited rather than assumed."""
    import auth_verify

    assert auth_verify.is_open_path("POST", "/api/surfaces/compose") is True
