"""Test bootstrap for the Orrery org server.

The server reads its configuration from the environment at import time — `AGENT_ID`
is required (via `os.environ[...]`), and Postgres / LLM credentials are read too.
These defaults keep the suite self-contained so `pytest` runs with no external setup
or live services. Real environment values always win (`setdefault`), so a developer
or CI can point the suite at real config without editing this file.
"""

import os

os.environ.setdefault("AGENT_ID", "test-org")
os.environ.setdefault("AGENT_NAME", "Test Org")
os.environ.setdefault("DATABASE_URL", "postgres://test@localhost/test")
os.environ.setdefault("OPENAI_API_KEY", "test")
os.environ.setdefault("LLM_API_KEY", "test")

# Secrets are sealed at rest by default — ORRERY_KEY_SECRET unset makes the
# server refuse to start rather than write a plaintext signing key. Give the suite
# one so the DEFAULT path under test is the sealed path; the tests that assert the
# refusal, the opt-out and legacy-plaintext reads delenv/setenv it themselves.
os.environ.setdefault("ORRERY_KEY_SECRET", "test-key-encryption-secret")

# ── Registry publication ────────────────────────────────────────────
#
# `chapter_agent` calls load_dotenv() at import, so a developer's .env leaks
# into os.environ for the whole session — and this repo's .env carries
# AUTO_REGISTER=false. Once the empty-vs-unset fix made that flag actually work, every test that
# exercises publish MECHANICS started failing depending on whose machine it ran
# on.
#
# The flag was previously read by NO code, which is exactly why the suite never
# noticed it was ambient. Pin a deterministic baseline here so publish tests
# assert on their own inputs rather than on the developer's .env; individual
# tests still override with monkeypatch, which wins over this.
import pytest as _pytest


@_pytest.fixture(autouse=True)
def _deterministic_registry_env(monkeypatch):
    monkeypatch.setenv("AUTO_REGISTER", "true")
    monkeypatch.setenv("REGISTRY_URL", "https://nest.test.invalid")


# ── The segfault investigation: the unit suite must not open a REAL database connection ───────────
#
# `pg_store` says execution is "exercised by the docker e2e, not the mocked unit
# tests". That was not true: tracing `asyncpg` entry points across a full run
# recorded **29 real `create_pool()` attempts** from 8 test modules, against the
# `postgres://test@localhost/test` URL this conftest sets — a database that does
# not exist. Every one of them failed and was swallowed by `_get_pool`'s
# `except Exception`, so the suite stayed green and nobody noticed.
#
# They are not harmless. Each attempt builds asyncpg's C-extension-backed
# connection machinery on a per-test event loop that pytest-asyncio then closes.
# That is the shape the segfault investigation's captured trace points at: the interpreter segfaulted
# mid-GC, and the frame beneath the allocation that triggered the collection was
# a suspended `asyncpg/connection.py connect()`. The suite has hit this class of
# crash before — see the fixture docstring in test_spec_05_advertisement.py,
# which records a segfault under coverage attributed to asyncpg/cffi extension
# state surviving a module re-import.
#
# So: make the comment in pg_store true. Blocking the connection at the asyncpg
# boundary is behaviour-preserving BY CONSTRUCTION — the attempt was already
# guaranteed to fail here, and `_get_pool` already returns None on any exception,
# so callers see exactly what they saw before. What changes is that no socket is
# opened and no C-backed connection object is ever created, which removes the
# leak the trace implicates rather than suppressing its symptom.
#
# This is deliberately NOT gc.disable(), NOT a retry wrapper, and NOT test
# reordering — those hide the signal that a connection is being leaked. This
# removes the leak.
#
# Escape hatch: set ORRERY_ALLOW_REAL_DB=1 for the docker e2e, which genuinely
# does want a live database.

_REAL_DB_ESCAPE_HATCH = "ORRERY_ALLOW_REAL_DB"
_BLOCKED_ASYNCPG_ENTRYPOINTS = ("connect", "create_pool")


def pytest_configure(config):
    """Replace asyncpg's connect entry points with an immediate refusal.

    Done as a session-wide hook rather than an autouse fixture on purpose: some
    of the 29 attempts originate inside a ``TestClient`` portal thread and
    during module import, neither of which a per-test fixture reliably covers.
    """
    if os.environ.get(_REAL_DB_ESCAPE_HATCH, "").strip():
        return
    try:
        import asyncpg
    except ImportError:  # pragma: no cover - asyncpg is in requirements.lock
        return

    async def _refuse(*_args, **_kwargs):
        raise ConnectionRefusedError(
            "the segfault investigation: the unit suite does not open real database connections. "
            f"Set {_REAL_DB_ESCAPE_HATCH}=1 if you genuinely want one (docker e2e)."
        )

    originals = {
        name: getattr(asyncpg, name)
        for name in _BLOCKED_ASYNCPG_ENTRYPOINTS
        if hasattr(asyncpg, name)
    }
    config.stash_orrery_asyncpg_originals = originals
    for name in originals:
        setattr(asyncpg, name, _refuse)


def pytest_unconfigure(config):
    """Put asyncpg back, so an in-process re-run is not affected."""
    originals = getattr(config, "stash_orrery_asyncpg_originals", None)
    if not originals:
        return
    import asyncpg

    for name, original in originals.items():
        setattr(asyncpg, name, original)


# ── 🛑 PR7: no test in this suite may perform a LIVE outbound send ───────────
#
# `external_send` is sandboxed by four independent conditions and each is tested,
# but every one of them is defeatable by a test that sets the environment — and
# "a test that emails a real person" is not a failure you get to discover and
# then fix. So this is the last resort underneath all four: the live transport's
# send method is replaced for the entire suite, so reaching Klaviyo is impossible
# regardless of flags, keys, mocks or what any individual test configures.
#
# It fails LOUDLY rather than silently no-opping. A quiet stub would let a test
# assert a successful live send and pass, which is how the guarantee would rot.
@_pytest.fixture(autouse=True)
def _no_live_external_sends(monkeypatch):
    try:
        import external_send
    except Exception:  # module absent in a partial checkout — nothing to guard
        return

    def _refuse(self, message):
        raise AssertionError(
            f"a test attempted a LIVE send to {message.get('to')!r}. The suite is "
            f"sandbox-only; if you are testing the transport, assert on the request "
            f"it would build rather than performing it."
        )

    monkeypatch.setattr(external_send.KlaviyoTransport, "send", _refuse)
