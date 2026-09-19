"""Server↔Postgres traffic must be encrypted off the local box (AUDIT_HARSH C3).

`create_pool()` used to pass the raw DSN and no `ssl` argument. asyncpg then
negotiates **no TLS** for a `postgres://` URL with no `sslmode`, so signing keys,
API keys, tokens, receipts and member PII crossed that link in plaintext.

Measured against `pgvector/pgvector:pg15` (which reports `ssl=off` and ships no
certificate) while building this:

    no ssl argument   -> connects, plaintext, silently
    ssl="disable"     -> connects, plaintext, explicitly
    ssl="prefer"      -> connects, but downgrades to plaintext with no signal
    ssl="require"     -> ConnectionError: "rejected SSL upgrade"

Two things follow, and both are asserted here. `prefer` is not a security
control, because a downgrade is indistinguishable from success. And `require`
cannot be unconditional, because the dev/CI Postgres genuinely cannot do TLS —
a bare `require` would break every local run, get reverted, and leave the
finding open. So the rule is: **require by default, exempt loopback/compose
explicitly**, and say out loud which branch was taken.

Classification: ADVERSARIAL (security control).
"""

from __future__ import annotations

import pytest

import pg_store


class TestHostDefault:
    """With nothing configured, the decision comes from the host."""

    @pytest.mark.parametrize(
        "url",
        [
            "postgres://u:p@localhost:5432/orrery",
            "postgres://u:p@127.0.0.1:5432/orrery",
            "postgres://u:p@db:5432/orrery",  # this repo's compose service name
            "postgresql://u:p@postgres/orrery",
        ],
    )
    def test_local_and_compose_hosts_are_exempt(self, url: str, monkeypatch) -> None:
        monkeypatch.delenv(pg_store._DB_SSL_ENV, raising=False)
        assert pg_store._resolve_db_ssl(url) == "disable"

    @pytest.mark.parametrize(
        "url",
        [
            # The real production DSN shape, measured 2026-08-02: a private
            # Railway hostname and NO sslmode — the case C3 is actually about.
            "postgres://u:p@db.railway.internal:5432/railway",
            "postgres://u:p@some-db.example.com:5432/orrery",
            "postgresql://u:p@10.0.0.5:5432/orrery",
        ],
    )
    def test_every_real_network_hop_requires_tls(self, url: str, monkeypatch) -> None:
        monkeypatch.delenv(pg_store._DB_SSL_ENV, raising=False)
        assert pg_store._resolve_db_ssl(url) == "require"

    def test_prefer_is_never_the_default(self, monkeypatch) -> None:
        """`prefer` silently falls back to plaintext, so it must never be what a
        deployment gets by accident. An operator may still choose it explicitly."""
        monkeypatch.delenv(pg_store._DB_SSL_ENV, raising=False)
        for url in (
            "postgres://u:p@db.railway.internal/x",
            "postgres://u:p@localhost/x",
            "postgres://u:p@example.com/x",
        ):
            assert pg_store._resolve_db_ssl(url) != "prefer"


class TestPrecedence:
    """Most explicit signal wins, so an operator is never overridden."""

    def test_env_override_beats_the_host_default(self, monkeypatch) -> None:
        """The escape hatch for a Postgres that genuinely cannot do TLS."""
        monkeypatch.setenv(pg_store._DB_SSL_ENV, "disable")
        assert pg_store._resolve_db_ssl("postgres://u:p@db.railway.internal/x") == "disable"

    def test_env_override_can_also_tighten_local(self, monkeypatch) -> None:
        monkeypatch.setenv(pg_store._DB_SSL_ENV, "require")
        assert pg_store._resolve_db_ssl("postgres://u:p@localhost/x") == "require"

    def test_empty_env_is_treated_as_unset(self, monkeypatch) -> None:
        """An empty value must not read as 'the operator chose empty-string'."""
        monkeypatch.setenv(pg_store._DB_SSL_ENV, "")
        assert pg_store._resolve_db_ssl("postgres://u:p@db.railway.internal/x") == "require"
        monkeypatch.setenv(pg_store._DB_SSL_ENV, "   ")
        assert pg_store._resolve_db_ssl("postgres://u:p@db.railway.internal/x") == "require"

    @pytest.mark.parametrize("mode", ["require", "disable", "verify-full"])
    def test_sslmode_already_in_the_dsn_is_left_alone(self, mode: str, monkeypatch) -> None:
        """If the DSN says it, asyncpg honours it — don't override the operator
        from here, in either direction."""
        monkeypatch.delenv(pg_store._DB_SSL_ENV, raising=False)
        assert pg_store._resolve_db_ssl(f"postgres://u:p@host.example/x?sslmode={mode}") is None


class TestRobustness:
    def test_a_malformed_dsn_still_fails_closed(self, monkeypatch) -> None:
        """An unparseable URL must not silently become 'local, no TLS needed'."""
        monkeypatch.delenv(pg_store._DB_SSL_ENV, raising=False)
        assert pg_store._resolve_db_ssl("not a url at all") == "require"

    def test_empty_dsn_fails_closed(self, monkeypatch) -> None:
        monkeypatch.delenv(pg_store._DB_SSL_ENV, raising=False)
        assert pg_store._resolve_db_ssl("") == "require"


@pytest.mark.asyncio
async def test_pool_creation_passes_the_resolved_ssl_mode(monkeypatch) -> None:
    """The decision has to actually reach asyncpg — a resolver nothing calls
    would pass every test above and change nothing on the wire."""
    monkeypatch.delenv(pg_store._DB_SSL_ENV, raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgres://u:p@db.railway.internal:5432/railway")
    monkeypatch.setattr(pg_store, "_pool", None)
    monkeypatch.setattr(pg_store, "_pool_unavailable_until", 0.0)

    seen: dict = {}

    class _FakeAsyncpg:
        @staticmethod
        async def create_pool(url, **kwargs):
            seen["url"] = url
            seen["kwargs"] = kwargs
            raise RuntimeError("not connecting in a unit test")

    import sys

    monkeypatch.setitem(sys.modules, "asyncpg", _FakeAsyncpg)
    assert await pg_store._get_pool() is None
    assert seen["kwargs"].get("ssl") == "require", (
        f"create_pool was called without ssl=require: {seen.get('kwargs')}"
    )


@pytest.mark.asyncio
async def test_local_pool_creation_does_not_force_tls(monkeypatch) -> None:
    """The other half of the contract: dev/CI must keep working. If this fails,
    the compose stack and the e2e job are broken."""
    monkeypatch.delenv(pg_store._DB_SSL_ENV, raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgres://u:p@db:5432/orrery")
    monkeypatch.setattr(pg_store, "_pool", None)
    monkeypatch.setattr(pg_store, "_pool_unavailable_until", 0.0)

    seen: dict = {}

    class _FakeAsyncpg:
        @staticmethod
        async def create_pool(url, **kwargs):
            seen["kwargs"] = kwargs
            raise RuntimeError("not connecting in a unit test")

    import sys

    monkeypatch.setitem(sys.modules, "asyncpg", _FakeAsyncpg)
    assert await pg_store._get_pool() is None
    assert seen["kwargs"].get("ssl") == "disable"
