"""The unit suite must never open a real database connection.

`pg_store` has always claimed execution is "exercised by the docker e2e, not the
mocked unit tests". It wasn't: tracing asyncpg's entry points across a full run
recorded **29 real `create_pool()` attempts** from 8 test modules, aimed at the
`postgres://test@localhost/test` URL `conftest.py` sets — a database that does
not exist. Each failed, `_get_pool` swallowed the exception, and the suite stayed
green, so the drift was invisible.

It matters because of *what those attempts build*: asyncpg's C-extension-backed
connection machinery, on a per-test event loop that pytest-asyncio then closes.
The segfault investigation's captured trace shows the interpreter segfaulting mid-GC with a suspended
`asyncpg/connection.py connect()` frame beneath the allocation that triggered the
collection. `conftest.py::pytest_configure` now refuses those calls at the
asyncpg boundary; this file is what stops the drift coming back.

These tests assert the *guard*, not the crash. The segfault is a heisenbug
(~4 in 20 runs, then 0 in 32) and is not reproducible on demand, so nothing here
claims to prove it fixed — see docs/DEBUGGING_SERVER_SIGSEGV.md.

Classification: ADVERSARIAL (drift guard).
"""

from __future__ import annotations

import asyncio
import socket

import pytest

import pg_store


@pytest.mark.parametrize("entrypoint", ["connect", "create_pool"])
def test_asyncpg_entrypoints_are_blocked_during_the_suite(entrypoint: str) -> None:
    """The guard is installed and still installed by the time tests run.

    Asserted by BEHAVIOUR — awaiting the entry point must refuse with the marker — rather than by identity. A diagnostic plugin that legitimately
    wraps asyncpg (the tracer used to find these 29 calls does exactly that)
    would break an identity check while leaving the guard perfectly intact.
    """
    import asyncpg

    with pytest.raises(ConnectionRefusedError, match="the segfault investigation"):
        asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
            getattr(asyncpg, entrypoint)("postgres://test@localhost/test")
        )


@pytest.mark.asyncio
async def test_get_pool_returns_none_without_touching_the_network(monkeypatch) -> None:
    """The observable contract is unchanged: a bad DATABASE_URL still yields a
    quiet None. What changed is that no socket is opened getting there."""
    monkeypatch.setenv("DATABASE_URL", "postgres://test@localhost/test")
    monkeypatch.setattr(pg_store, "_pool", None)
    monkeypatch.setattr(pg_store, "_pool_unavailable_until", 0.0)

    opened: list[tuple] = []
    real_connect = socket.socket.connect

    def _record(self, address, *a, **kw):
        opened.append(address)
        return real_connect(self, address, *a, **kw)

    monkeypatch.setattr(socket.socket, "connect", _record)

    assert await pg_store._get_pool() is None
    assert not opened, f"the suite opened a real socket to {opened}"


@pytest.mark.asyncio
async def test_guard_is_escapable_for_the_docker_e2e() -> None:
    """The docker e2e genuinely wants a live database, so the guard must be
    opt-outable — otherwise this fix would break the one suite that needs it."""
    import tests.conftest as conftest_mod

    assert conftest_mod._REAL_DB_ESCAPE_HATCH == "ORRERY_ALLOW_REAL_DB"
    # The hook returns early — without patching — when the hatch is set.
    import inspect

    source = inspect.getsource(conftest_mod.pytest_configure)
    assert "_REAL_DB_ESCAPE_HATCH" in source and "return" in source


def test_guard_is_not_a_suppression_workaround() -> None:
    """The segfault investigation explicitly rules out hiding the signal. Assert we did none of it.

    Scans executable code only — the conftest's own prose *names* these
    techniques to explain why they were rejected, and matching on that would
    make the guard fire on its own rationale.
    """
    import ast
    import inspect

    import tests.conftest as conftest_mod

    tree = ast.parse(inspect.getsource(conftest_mod))
    code_only = "\n".join(
        ast.unparse(node)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call | ast.Attribute | ast.Import | ast.ImportFrom)
    )
    for banned in ("gc.disable", "gc.freeze", "flaky", "reruns"):
        assert banned not in code_only, (
            f"conftest CODE uses {banned!r} — The segfault investigation rules out suppressing the "
            "signal rather than removing the leak"
        )
