"""Whole-server type sweep — regression tests for the behavior-relevant
fixes the sweep produced (annotations alone need no tests; these do).

Classification: HAPPY / EDGE / FAILURE.
"""

import pytest
from fastapi.responses import JSONResponse

import chapter_agent
import intents
import surfaces

# ── the injected-pg accessor class (99 call sites across 15 modules) ─────
# Before that change an uninitialized module crashed with a bare
# "'NoneType' object is not callable"; now every module fails loudly with a
# named message. One representative per symbol spelling.


def test_uninitialized_pg_accessor_raises_named_error_underscore(monkeypatch):
    """FAILURE: intents._pg() before init() → actionable RuntimeError."""
    monkeypatch.setattr(intents, "_pg_request", None)
    with pytest.raises(RuntimeError, match=r"intents\.init\(\) was never called"):
        intents._pg()


def test_uninitialized_pg_accessor_raises_named_error_bare(monkeypatch):
    """FAILURE: surfaces._pg() before init() → actionable RuntimeError."""
    monkeypatch.setattr(surfaces, "pg_request", None)
    with pytest.raises(RuntimeError, match=r"surfaces\.init\(\) was never called"):
        surfaces._pg()


def test_initialized_pg_accessor_returns_the_injected_callable():
    """HAPPY: after init the accessor hands back exactly what was injected."""

    async def fake_pg(*a, **k):
        return []

    old = intents._pg_request
    try:
        intents._pg_request = fake_pg
        assert intents._pg() is fake_pg
    finally:
        intents._pg_request = old


# ── admin deny fallback (replaced 12 `type: ignore[return-value]` sites) ─


def test_deny_fallback_passes_through_real_denial():
    """HAPPY: the denial _authorize_admin built is returned untouched."""
    denial = JSONResponse(status_code=401, content={"error": "missing_admin"})
    assert chapter_agent._deny_fallback(denial) is denial


def test_deny_fallback_fails_closed_on_broken_invariant():
    """FAILURE: not-ok with denied=None (invariant breach) → 403, never None
    leaking out of an admin-gated route."""
    resp = chapter_agent._deny_fallback(None)
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 403


# ── surfaces._short_did: the duplicate definition was removed ────────────
# Two module-level defs existed; the LATER one (discriminator-tail form)
# already shadowed the first for every caller, so deleting the first is
# behavior-preserving. Pin the surviving semantics so a future re-add of the
# truncating variant can't silently change display labels.


def test_short_did_keeps_discriminator_tail():
    did = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
    label = surfaces._short_did(did)
    assert label.endswith(did[-4:])
    assert len(label) < len(did)


def test_short_did_single_definition():
    """EDGE: exactly one module-level definition exists (the dead duplicate
    stays deleted)."""
    import inspect

    src = inspect.getsource(surfaces)
    assert src.count("def _short_did(") == 1
