"""Rate-limit buckets survive a restart, and do so without storing client IPs.

WHAT THIS IS ABOUT

``check_rate_limit`` keeps buckets in a process-local ``OrderedDict`` stamped
with ``time.monotonic()``. Monotonic values from a dead process are meaningless
in a new one, so the buckets were not merely lost across a restart — there was
no representation in which they could have survived. Every client's quota reset
to full on every deploy, crash and restart.

THE TWO PROPERTIES ASSERTED HERE

1. **A near-exhausted bucket stays near-exhausted across a restart.** The
   snapshot/restore round trip is exercised through the real functions, with the
   second process given a different monotonic origin — because a restore that
   only works when the clocks happen to line up works on no real restart.

2. **No client key is recoverable from what is persisted.** Before this change
   no table in the tree held an IP address. The snapshot must not become the
   first, so the bucket id is an HMAC under a salt kept outside the database.

3. **The salt survives the boot, or the process says it does not.** Restore
   matches by equality of ``HMAC(salt, ip)``, so a snapshot is worth nothing
   unless the next process hashes with the same salt. The first version kept
   the salt in a file under the org data directory only; on a service with no
   persistent volume that file is minted fresh on every boot, every restored
   hash fails to match, and the limiter starts empty while ``/health`` reads
   persistence ``true``. Measured on a deployed three-org mesh. The salt now
   has a NAMED source, ``/health`` reports it beside the table flag, and the
   case that was measured — salt changes between boots, buckets do not match —
   is held here so it cannot come back unreported.

Plus the failure directions, which for a limiter matter more than the happy
path: every degradation must fail toward an EMPTY bucket (a client gets its
quota back, which is today's behaviour) and never toward a bucket believed
limited that is not.
"""

from __future__ import annotations

import os
import sys
from collections import OrderedDict
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import rate_limit_persistence as rlp  # noqa: E402

WINDOW = 60.0
SALT = b"\x01" * 32
CLIENT = "203.0.113.7"


def _bucket(now_mono: float, count: int, spacing: float = 1.0) -> list[float]:
    """``count`` admitted requests, the newest at ``now_mono``."""
    return [now_mono - (count - 1 - i) * spacing for i in range(count)]


# ── 1. the round trip ────────────────────────────────────────────────


def test_a_nearly_exhausted_bucket_survives_a_restart():
    """29 of 30 used before; 29 of 30 used after, on a fresh monotonic clock."""
    key = rlp.bucket_key(SALT, CLIENT)
    old_mono, wall = 5_000.0, 1_700_000_000.0
    store: OrderedDict[str, list[float]] = OrderedDict({key: _bucket(old_mono, 29)})

    snap = rlp.snapshot_buckets(store, now_monotonic=old_mono, now_wall=wall, window=WINDOW)

    # The new process: monotonic restarted near zero, wall clock moved on 2s.
    restored = rlp.restore_buckets(snap, now_monotonic=12.5, now_wall=wall + 2.0, window=WINDOW, key_cap=10_000)

    assert key in restored, "the bucket did not survive"
    assert len(restored[key]) == 29, "an attacker got budget back across the restart"
    assert all(t <= 12.5 for t in restored[key]), "restored stamps are in the new monotonic frame"


def test_entries_older_than_the_window_are_not_restored():
    """A snapshot that sat through a long outage restores nothing, not everything."""
    key = rlp.bucket_key(SALT, CLIENT)
    snap = rlp.snapshot_buckets(
        OrderedDict({key: _bucket(5_000.0, 10)}), now_monotonic=5_000.0, now_wall=1_000.0, window=WINDOW
    )
    restored = rlp.restore_buckets(
        snap, now_monotonic=1.0, now_wall=1_000.0 + WINDOW + 5, window=WINDOW, key_cap=10_000
    )
    assert restored == {}


def test_expired_entries_are_not_even_written():
    """Writing a stamp that restore would discard inflates the row for nothing."""
    now = 5_000.0
    store = OrderedDict({"k": [now - 500.0, now - 400.0, now - 1.0]})
    snap = rlp.snapshot_buckets(store, now_monotonic=now, now_wall=9_000.0, window=WINDOW)
    assert len(snap["k"]) == 1


def test_empty_buckets_are_dropped():
    snap = rlp.snapshot_buckets(OrderedDict({"k": []}), now_monotonic=1.0, now_wall=1.0, window=WINDOW)
    assert snap == {}


# ── 2. no client key is recoverable ──────────────────────────────────


def test_the_persisted_payload_contains_no_client_key():
    """The snapshot must not become the first place in the tree holding an IP."""
    key = rlp.bucket_key(SALT, CLIENT)
    snap = rlp.snapshot_buckets(OrderedDict({key: _bucket(10.0, 3)}), now_monotonic=10.0, now_wall=99.0, window=WINDOW)
    blob = repr(snap)
    assert CLIENT not in blob
    assert "203.0.113" not in blob


def test_the_bucket_id_is_salted_so_it_is_not_a_bare_hash_of_the_ip():
    """An unsalted SHA-256 of an IPv4 address is brute-forceable — 2**32 guesses."""
    import hashlib

    key = rlp.bucket_key(SALT, CLIENT)
    assert key != hashlib.sha256(CLIENT.encode()).hexdigest()
    assert rlp.bucket_key(b"\x02" * 32, CLIENT) != key, "different salt must give a different id"


def test_the_bucket_id_is_stable_for_the_same_salt_and_key():
    """Restore matches by equality; an unstable id would silently never match."""
    assert rlp.bucket_key(SALT, CLIENT) == rlp.bucket_key(SALT, CLIENT)


def test_the_salt_is_not_written_to_the_database(tmp_path, monkeypatch):
    """It lives outside the database precisely so a table dump is not enough."""
    monkeypatch.delenv(rlp.SALT_ENV, raising=False)
    salt, _source = rlp.resolve_salt(tmp_path)
    assert (tmp_path / "rate-limit-salt").exists()
    assert len(salt) >= 16
    assert rlp.resolve_salt(tmp_path)[0] == salt, "salt must be stable across calls"
    # The table has three columns and none of them is the salt. If a future
    # change adds one, a dump of this table alone becomes enough to recover the
    # client IPs and the hashing stops buying anything.
    body = rlp.ddl().lower().split("create table")[1].split(");")[0]
    assert "salt" not in body, (
        "the snapshot table must not carry the salt — keeping it in the org data dir instead is the whole point"
    )


def test_a_salt_that_cannot_be_persisted_still_yields_a_usable_salt(tmp_path, monkeypatch):
    """Failing to write must not fail the limiter — worst case, no carry-over."""
    monkeypatch.delenv(rlp.SALT_ENV, raising=False)

    def _no_write(*_a, **_k):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(rlp.Path, "write_bytes", _no_write)
    salt, source = rlp.resolve_salt(tmp_path / "nope")
    assert len(salt) >= 16
    assert source == rlp.SOURCE_EPHEMERAL


# ── 2b. the salt's source is named, and durability follows from it ───
#
# The measured failure: a service with no persistent volume minted a new salt
# file on every boot. Nothing below the health endpoint could tell, because the
# only fact recorded was "the table is writable". Every source here is a
# distinct answer to "will the NEXT process hash with these bytes".


def test_an_operator_salt_from_the_environment_is_the_durable_source(tmp_path, monkeypatch):
    """Set on the platform, it is the same on every boot until the operator changes it."""
    monkeypatch.setenv(rlp.SALT_ENV, "0123456789abcdef0123456789abcdef")
    salt, source = rlp.resolve_salt(tmp_path)
    assert source == rlp.SOURCE_ENV
    assert rlp.salt_durable(source) is True
    assert salt == b"0123456789abcdef0123456789abcdef"
    assert not (tmp_path / "rate-limit-salt").exists(), "an environment salt must not also write a file"


def test_the_environment_salt_wins_over_an_existing_file(tmp_path, monkeypatch):
    """Setting it is an explicit operator decision; a leftover file must not override it."""
    monkeypatch.delenv(rlp.SALT_ENV, raising=False)
    file_salt, _ = rlp.resolve_salt(tmp_path)
    monkeypatch.setenv(rlp.SALT_ENV, "operator-chosen-salt-of-sufficient-length")
    salt, source = rlp.resolve_salt(tmp_path)
    assert source == rlp.SOURCE_ENV
    assert salt != file_salt


def test_a_salt_file_is_reported_new_on_the_boot_that_mints_it_and_file_once_it_survived_one(tmp_path, monkeypatch):
    """The file is only called durable after it has been OBSERVED to survive a boot.

    A volume-backed install reports ``file-new`` on its first boot and ``file``
    from the second on. A volume-less service reports ``file-new`` on every boot
    — which is the state the deployed mesh was in, unreported.
    """
    monkeypatch.delenv(rlp.SALT_ENV, raising=False)
    first, source_1 = rlp.resolve_salt(tmp_path)
    assert source_1 == rlp.SOURCE_FILE_NEW
    assert rlp.salt_durable(source_1) is False, "a salt minted this boot has not survived one"
    second, source_2 = rlp.resolve_salt(tmp_path)
    assert source_2 == rlp.SOURCE_FILE
    assert rlp.salt_durable(source_2) is True
    assert second == first


def test_a_volume_less_boot_is_not_reported_durable(tmp_path, monkeypatch):
    """The org data directory does not survive between boots: every boot is a first boot."""
    monkeypatch.delenv(rlp.SALT_ENV, raising=False)
    import shutil

    boot_1 = tmp_path / "container-1"
    boot_2 = tmp_path / "container-2"
    salt_1, source_1 = rlp.resolve_salt(boot_1)
    shutil.rmtree(boot_1)  # the container filesystem is gone with the process
    salt_2, source_2 = rlp.resolve_salt(boot_2)
    assert salt_1 != salt_2, "precondition: the salt changed between boots"
    assert source_2 == rlp.SOURCE_FILE_NEW
    assert rlp.salt_durable(source_2) is False, (
        "a salt that changed between boots was reported durable — the measured defect, reintroduced"
    )


@pytest.mark.parametrize("value", ["", "   ", "short", "0123456789abcde"], ids=["empty", "blank", "short", "15-chars"])
def test_an_unusable_environment_salt_degrades_by_name(tmp_path, monkeypatch, value):
    """Unset or blank falls through to the file and says so. Too short is REJECTED
    and says so — not silently replaced by the file, because the operator chose
    the environment and the health field should show that choice failing."""
    monkeypatch.setenv(rlp.SALT_ENV, value)
    salt, source = rlp.resolve_salt(tmp_path)
    assert len(salt) >= 16, "every path must hand back a usable salt"
    if value.strip():
        assert source == rlp.SOURCE_ENV_REJECTED
        assert not (tmp_path / "rate-limit-salt").exists(), "a rejected value must not fall back to the file"
    else:
        assert source == rlp.SOURCE_FILE_NEW
    assert rlp.salt_durable(source) is False


def test_the_unresolved_placeholder_is_not_durable():
    """Before lifespan runs the module holds a placeholder; it must never read as durable."""
    assert rlp.salt_durable(rlp.SOURCE_UNRESOLVED) is False


def test_only_the_named_durable_sources_are_durable():
    """The set is closed: a source added later must be classified before it counts."""
    assert rlp.DURABLE_SALT_SOURCES == {rlp.SOURCE_ENV, rlp.SOURCE_FILE}
    for source in (rlp.SOURCE_FILE_NEW, rlp.SOURCE_EPHEMERAL, rlp.SOURCE_ENV_REJECTED, rlp.SOURCE_UNRESOLVED):
        assert rlp.salt_durable(source) is False, source


def test_a_salt_that_changes_between_boots_orphans_the_snapshot():
    """THE MEASUREMENT, held by the suite.

    Boot 1 hashes under salt A and flushes a full bucket. Boot 2 hashes under
    salt B — what a volume-less service does on every restart. The client's key
    under B is not in what was restored, so the client is admitted: the exact
    pre-persistence behaviour, and the reason the salt's source has to be
    reported rather than assumed.
    """
    salt_a, salt_b = b"\x0a" * 32, b"\x0b" * 32
    mono, wall = 5_000.0, 1_700_000_000.0
    store: OrderedDict[str, list[float]] = OrderedDict({rlp.bucket_key(salt_a, CLIENT): _bucket(mono, 30)})
    snap = rlp.snapshot_buckets(store, now_monotonic=mono, now_wall=wall, window=WINDOW)

    restored = rlp.restore_buckets(snap, now_monotonic=1.0, now_wall=wall + 1.0, window=WINDOW, key_cap=10_000)

    assert rlp.bucket_key(salt_a, CLIENT) in restored, "precondition: under the same salt the bucket is there"
    assert rlp.bucket_key(salt_b, CLIENT) not in restored, "under the new salt the client's bucket does not match"


# ── 3. failure directions ────────────────────────────────────────────


@pytest.mark.parametrize(
    "payload",
    [None, [], "not-a-dict", 42, {"k": "not-a-list"}, {"k": [None, "x"]}, {5: [1.0]}],
    ids=["none", "list", "str", "int", "value-not-list", "non-numeric", "non-str-key"],
)
def test_a_malformed_snapshot_restores_empty_rather_than_raising(payload):
    """This runs at boot. Refusing to start over a cache row trades a lost
    optimisation for an outage."""
    out = rlp.restore_buckets(payload, now_monotonic=1.0, now_wall=1.0, window=WINDOW, key_cap=10)
    assert out == OrderedDict()


def test_a_future_timestamp_cannot_extend_a_bucket_beyond_the_window():
    """A doctored row, or a clock that moved backwards. Clamped to 'now', so it
    can only shorten the remaining budget — never grant more of it."""
    restored = rlp.restore_buckets({"k": [10_000.0]}, now_monotonic=50.0, now_wall=1.0, window=WINDOW, key_cap=10)
    assert restored["k"] == [50.0]


def test_restore_respects_the_key_cap():
    """The live store has a bounded key count; a restore must not blow past it."""
    snap = {f"k{i}": [100.0] for i in range(50)}
    restored = rlp.restore_buckets(snap, now_monotonic=1.0, now_wall=100.0, window=WINDOW, key_cap=10)
    assert len(restored) == 10


def test_the_snapshot_keeps_the_fullest_buckets_when_capped():
    """Capping is a choice about WHOSE state is lost. Keeping the emptiest would
    persist exactly the buckets whose loss costs nothing."""
    now = 1_000.0
    store = OrderedDict({"light": _bucket(now, 2), "heavy": _bucket(now, 29), "medium": _bucket(now, 15)})
    snap = rlp.snapshot_buckets(store, now_monotonic=now, now_wall=now, window=WINDOW, max_keys=2)
    assert set(snap) == {"heavy", "medium"}


async def test_ensure_schema_degrades_when_the_table_cannot_be_created():
    """Optional by design: no DDL privilege must not turn a working install into
    a non-booting one, so this returns False instead of raising."""

    async def _refuse(_sql):
        raise PermissionError("permission denied for schema public")

    assert await rlp.ensure_schema(_refuse, has_database=True) is False


async def test_ensure_schema_probes_the_table_before_any_ddl():
    """THE DEFAULT INSTALL. init.sql creates the table as the superuser and 0006
    grants the app role DML on it, but Postgres refuses CREATE TABLE IF NOT
    EXISTS without CREATE on the schema even for a table that exists (measured:
    ``permission denied for schema public`` against a table the same role could
    INSERT into a moment later). An ensure that issues the DDL first therefore
    reports persistence unavailable on every fresh ./orrery-up install — which
    it did, for as long as the feature existed. The probe has to come first."""
    ddl_calls: list[str] = []

    async def _refuse(sql):
        ddl_calls.append(sql)
        raise PermissionError("permission denied for schema public")

    async def _present():
        return True

    assert await rlp.ensure_schema(_refuse, has_database=True, table_usable=_present) is True
    assert ddl_calls == [], "the table is usable; no DDL may be issued, and none was needed"


async def test_ensure_schema_creates_the_table_only_when_the_probe_says_it_is_absent():
    ddl_calls: list[str] = []

    async def _create(sql):
        ddl_calls.append(sql)

    async def _absent():
        return False

    assert await rlp.ensure_schema(_create, has_database=True, table_usable=_absent) is True
    assert len(ddl_calls) == 1 and "CREATE TABLE IF NOT EXISTS public.rate_limit_buckets" in ddl_calls[0]


async def test_ensure_schema_degrades_when_absent_and_the_role_cannot_create_it():
    """An existing least-privilege install that has not applied 0008: nothing to
    probe, DDL refused, persistence off — and the message names the migration."""

    async def _refuse(_sql):
        raise PermissionError("permission denied for schema public")

    async def _absent():
        return False

    assert await rlp.ensure_schema(_refuse, has_database=True, table_usable=_absent) is False


def test_init_sql_and_the_migration_declare_the_same_table():
    """infra/init.sql is what a fresh install gets, as the superuser; 0008 is
    what an existing install applies. The app role can create neither, so the
    fresh-install path is the ONLY thing that makes persistence engage on the
    default install — and it has to declare the same table the runtime writes."""
    repo = Path(__file__).resolve().parents[2]
    init_sql = (repo / "infra" / "init.sql").read_text(encoding="utf-8")
    migration = rlp.ddl()

    def columns(sql: str) -> set[str]:
        body = sql.split("CREATE TABLE IF NOT EXISTS public.rate_limit_buckets")[1].split(");")[0]
        out = set()
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("--") or line.startswith("("):
                continue
            out.add(line.split()[0].strip(","))
        return out

    assert "CREATE TABLE IF NOT EXISTS public.rate_limit_buckets" in init_sql, (
        "a fresh install must create the snapshot table as the superuser; the app role cannot"
    )
    assert columns(init_sql) == columns(migration) == {"scope", "buckets", "saved_at"}


async def test_ensure_schema_is_a_no_op_without_a_database():
    calls: list[str] = []

    async def _ddl(sql):
        calls.append(sql)

    assert await rlp.ensure_schema(_ddl, has_database=False) is False
    assert calls == [], "no database means no DDL attempt"


async def test_load_returns_empty_for_an_unreadable_row():
    async def _pg(_method, _table, **_kw):
        return None

    assert await rlp.load(_pg, "org") == {}


def test_the_ddl_is_read_from_the_shipped_migration():
    """A fresh install, an operator applying the migration and the boot ensure
    must not be three different statements."""
    sql = rlp.ddl()
    assert "CREATE TABLE IF NOT EXISTS public.rate_limit_buckets" in sql


# ══════════════════════════════════════════════════════════════════════
# End to end, through the server: a client that spent its budget does not
# get it back by causing a restart. The module tests above exercise the
# round trip; this exercises the WIRING, which is where it would actually
# be broken — a correct snapshot never called, or restored into a store
# the limiter does not read.
# ══════════════════════════════════════════════════════════════════════


@pytest.fixture
def agent(monkeypatch):
    import importlib

    monkeypatch.setenv("AGENT_ID", "TEST-durability")
    monkeypatch.setenv("AGENT_NAME", "Durability")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    sys.modules.pop("chapter_agent", None)
    mod = importlib.import_module("chapter_agent")
    mod._rate_limit_store.clear()
    mod._rate_limit_salt = SALT
    mod._rate_limit_salt_source = rlp.SOURCE_ENV
    mod._rate_limit_persist_ok = True
    return mod


def _pg_in_memory(agent, monkeypatch):
    """A pg_request stub that holds exactly one snapshot row, like the table does."""
    saved: dict[str, object] = {}

    async def _pg(method, table, params=None, body=None, **_kw):
        assert table == rlp.TABLE
        if method == "POST":
            saved["buckets"] = body["buckets"]
            return [body]
        return [{"buckets": saved.get("buckets", {})}]

    monkeypatch.setattr(agent, "pg_request", _pg)
    return saved


async def test_a_client_cannot_get_its_budget_back_by_forcing_a_restart(agent, monkeypatch):
    _pg_in_memory(agent, monkeypatch)

    key = agent._rate_limit_bucket_key("198.51.100.4")
    for _ in range(agent.RATE_LIMIT_MAX):
        assert agent.check_rate_limit(key) is True
    assert agent.check_rate_limit(key) is False, "the ceiling did not engage"

    assert await agent._persist_rate_limit_buckets() is True

    # ── the restart ──
    agent._rate_limit_store.clear()
    assert agent.check_rate_limit(key) is True, "precondition: an empty store admits"
    agent._rate_limit_store.clear()

    carried = await agent._restore_rate_limit_buckets()
    assert carried == 1, f"nothing was carried across the restart (got {carried})"
    assert agent.check_rate_limit(key) is False, (
        "the client got its quota back by restarting — the whole point of this change"
    )


async def _exhaust_and_flush(agent, ip: str) -> None:
    key = agent._rate_limit_bucket_key(ip)
    for _ in range(agent.RATE_LIMIT_MAX):
        assert agent.check_rate_limit(key) is True
    assert agent.check_rate_limit(key) is False, "the ceiling did not engage"
    assert await agent._persist_rate_limit_buckets() is True


async def test_with_a_stable_salt_the_buckets_restored_after_a_boot_match_what_was_flushed(
    agent, monkeypatch, tmp_path
):
    """Two boots through the real resolver against a data directory that persists.

    Boot 1 mints the file; boot 2 reads it back and is the first process that
    can restore anything. The client that spent its budget before the restart
    is still refused after it.
    """
    monkeypatch.delenv(rlp.SALT_ENV, raising=False)
    _pg_in_memory(agent, monkeypatch)
    ip = "198.51.100.21"

    agent._rate_limit_salt, agent._rate_limit_salt_source = rlp.resolve_salt(tmp_path)
    await _exhaust_and_flush(agent, ip)

    # ── the restart: same directory, new process state ──
    agent._rate_limit_store.clear()
    agent._rate_limit_salt, agent._rate_limit_salt_source = rlp.resolve_salt(tmp_path)
    assert agent._rate_limit_salt_source == rlp.SOURCE_FILE

    assert await agent._restore_rate_limit_buckets() == 1
    assert agent.check_rate_limit(agent._rate_limit_bucket_key(ip)) is False, (
        "with a stable salt the restored bucket must be the one the client is looked up under"
    )


async def test_a_salt_minted_this_boot_restores_nothing_and_the_client_is_admitted(agent, monkeypatch, tmp_path):
    """The deployed shape: no volume, so every boot mints a new salt file.

    The snapshot from boot 1 is still in the table. Boot 2 cannot use it, and
    must say so rather than count its orphaned rows as buckets carried — which
    is what the boot log did on the mesh.
    """
    import shutil

    monkeypatch.delenv(rlp.SALT_ENV, raising=False)
    _pg_in_memory(agent, monkeypatch)
    ip = "198.51.100.22"

    boot_1 = tmp_path / "boot-1"
    agent._rate_limit_salt, agent._rate_limit_salt_source = rlp.resolve_salt(boot_1)
    await _exhaust_and_flush(agent, ip)
    shutil.rmtree(boot_1)

    # ── the restart: the container filesystem is gone ──
    agent._rate_limit_store.clear()
    agent._rate_limit_salt, agent._rate_limit_salt_source = rlp.resolve_salt(tmp_path / "boot-2")
    assert agent._rate_limit_salt_source == rlp.SOURCE_FILE_NEW

    assert await agent._restore_rate_limit_buckets() == 0, "orphaned rows must not be counted as carried"
    assert agent._rate_limit_store == {}, "orphaned hashes must not occupy the live store"
    assert agent.check_rate_limit(agent._rate_limit_bucket_key(ip)) is True, (
        "this IS the degraded behaviour — the point is that it is now reported, not that it is prevented"
    )


async def test_the_live_store_never_holds_a_raw_client_key(agent):
    """The store is what gets snapshotted, so an IP in it is an IP at rest."""
    ip = "198.51.100.9"
    agent.check_rate_limit(agent._rate_limit_bucket_key(ip))
    assert ip not in repr(list(agent._rate_limit_store))


async def test_persistence_failure_does_not_break_limiting(agent, monkeypatch):
    """A database outage must never disable the limiter or raise into the caller."""

    async def _boom(*_a, **_kw):
        raise RuntimeError("database is down")

    monkeypatch.setattr(agent, "pg_request", _boom)
    key = agent._rate_limit_bucket_key("198.51.100.7")
    for _ in range(agent.RATE_LIMIT_MAX):
        agent.check_rate_limit(key)

    assert await agent._persist_rate_limit_buckets() is False
    assert await agent._restore_rate_limit_buckets() == 0
    assert agent.check_rate_limit(key) is False, "limiting stopped when persistence failed"


async def test_no_persistence_configured_is_a_silent_no_op(agent):
    agent._rate_limit_persist_ok = False
    assert await agent._persist_rate_limit_buckets() is False
    assert await agent._restore_rate_limit_buckets() == 0


async def test_health_reports_whether_persistence_is_actually_on(agent, monkeypatch):
    """Silent degradation must be observable, or an operator believes they have
    durable limits when they do not.

    0006 withholds CREATE on schema public from the application role, so on a
    least-privilege install the boot ensure cannot create the table and this is
    False — with no other way to find out than the boot log of a process that
    may since have been replaced.
    """
    from fastapi.testclient import TestClient

    async def _no_db(*_a, **_kw):
        return []

    monkeypatch.setattr(agent, "pg_request", _no_db)
    client = TestClient(agent.app)

    agent._rate_limit_persist_ok = True
    assert client.get("/health").json()["rate_limit_persistence"] is True

    agent._rate_limit_persist_ok = False
    assert client.get("/health").json()["rate_limit_persistence"] is False, (
        "health must report the process's real state, not a constant"
    )


async def test_health_reports_the_salt_source_separately_from_the_table(agent, monkeypatch, tmp_path):
    """Two facts, two fields. The table flag read true on every deployed process
    while the salt changed on every boot; nothing on the endpoint could say so."""
    import shutil

    from fastapi.testclient import TestClient

    monkeypatch.delenv(rlp.SALT_ENV, raising=False)

    async def _no_db(*_a, **_kw):
        return []

    monkeypatch.setattr(agent, "pg_request", _no_db)
    client = TestClient(agent.app)
    agent._rate_limit_persist_ok = True

    # Boot 1 on a volume-less service; boot 2 on the same, after the filesystem is gone.
    boot_1 = tmp_path / "boot-1"
    agent._rate_limit_salt, agent._rate_limit_salt_source = rlp.resolve_salt(boot_1)
    shutil.rmtree(boot_1)
    agent._rate_limit_salt, agent._rate_limit_salt_source = rlp.resolve_salt(tmp_path / "boot-2")

    body = client.get("/health").json()
    assert body["rate_limit_persistence"] is True, "the table IS writable — that fact must not be blurred"
    assert body["rate_limit_salt"] == {"source": "file-new", "durable": False}, (
        "a salt that changed between boots must be reported not-durable, not true"
    )

    # A directory that persisted: the second boot reads the file back.
    kept = tmp_path / "kept"
    rlp.resolve_salt(kept)
    agent._rate_limit_salt, agent._rate_limit_salt_source = rlp.resolve_salt(kept)
    assert client.get("/health").json()["rate_limit_salt"] == {"source": "file", "durable": True}

    # The operator-held source.
    monkeypatch.setenv(rlp.SALT_ENV, "0123456789abcdef0123456789abcdef")
    agent._rate_limit_salt, agent._rate_limit_salt_source = rlp.resolve_salt(tmp_path / "unused")
    assert client.get("/health").json()["rate_limit_salt"] == {"source": "env", "durable": True}


async def test_health_names_an_unusable_salt_source(agent, monkeypatch, tmp_path):
    """Unset degrades by name; so does a value too short to be a salt, and so
    does a data directory that cannot be written. None of them reads durable."""
    from fastapi.testclient import TestClient

    async def _no_db(*_a, **_kw):
        return []

    monkeypatch.setattr(agent, "pg_request", _no_db)
    client = TestClient(agent.app)

    monkeypatch.setenv(rlp.SALT_ENV, "short")
    agent._rate_limit_salt, agent._rate_limit_salt_source = rlp.resolve_salt(tmp_path)
    assert client.get("/health").json()["rate_limit_salt"] == {"source": "env-rejected", "durable": False}

    monkeypatch.delenv(rlp.SALT_ENV)

    def _no_write(*_a, **_k):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(rlp.Path, "write_bytes", _no_write)
    agent._rate_limit_salt, agent._rate_limit_salt_source = rlp.resolve_salt(tmp_path / "ro")
    assert client.get("/health").json()["rate_limit_salt"] == {"source": "ephemeral", "durable": False}

    # Before lifespan has resolved anything at all.
    agent._rate_limit_salt_source = rlp.SOURCE_UNRESOLVED
    assert client.get("/health").json()["rate_limit_salt"] == {"source": "unresolved", "durable": False}


async def test_boot_reports_persistence_on_when_the_table_exists_but_ddl_is_refused(monkeypatch):
    """THE WIRING, on the default install's shape: the table is there and
    readable, DDL is refused. Boot must come up with persistence ON — and it
    came up OFF on every fresh install, with the flag false on /health, because
    the ensure was handed the DDL and nothing else."""
    import importlib

    import pg_store

    monkeypatch.setenv("AGENT_ID", "TEST-durability-boot")
    monkeypatch.setenv("AGENT_NAME", "Durability Boot")
    monkeypatch.setenv("XAI_API_KEY", "test-key")
    monkeypatch.setenv("PUBLIC_URL", "http://localhost:7000")
    monkeypatch.setenv("CHAPTER_ADMIN_TOKEN", "f" * 64)
    monkeypatch.setattr(pg_store, "database_url", lambda: "postgresql://orrery_app:x@db/orrery")

    async def _refuse_ddl(_sql):
        raise PermissionError("permission denied for schema public")

    async def _unreachable():
        return False

    monkeypatch.setattr(pg_store, "execute_ddl", _refuse_ddl)
    monkeypatch.setattr(pg_store, "db_reachable", _unreachable)

    for name in ("admin", "auth_verify", "governance", "chapter_agent"):
        sys.modules.pop(name, None)
    mod = importlib.import_module("chapter_agent")

    async def _pg(method, table, params=None, body=None, **_kw):
        if table == rlp.TABLE and method == "GET":
            return []  # present, readable, empty — a fresh install
        return None

    monkeypatch.setattr(mod, "pg_request", _pg)

    from fastapi.testclient import TestClient

    with TestClient(mod.app) as client:  # runs lifespan
        assert mod._rate_limit_persist_ok is True, (
            "the table is usable by the application role; boot must not report persistence off "
            "over a DDL statement it was refused and did not need"
        )
        assert client.get("/health").json()["rate_limit_persistence"] is True


# ── the documentation names the contract, and its limit ──────────────


def test_configuration_doc_states_the_persistence_contract():
    """docs/CONFIGURATION.md described the limiter as "not persisted" and
    resetting on restart. The document now has to name the mechanism by its
    real identifiers — the health field, the salt file, the table, the two
    tuning variables with the defaults the code actually uses — because that is
    what an operator reads when deciding whether a restart returns budget.

    Whitespace-normalized: the prose is hard-wrapped, and a name split across a
    line break must still count as present.
    """
    doc_path = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "CONFIGURATION.md")
    with open(doc_path, encoding="utf-8") as fh:
        doc = " ".join(fh.read().split())

    assert "is not persisted, and resets when that process restarts" not in doc, (
        "CONFIGURATION.md still describes the pre-snapshot limiter"
    )
    for name in (
        "rate_limit_persistence",  # the /health field for the table
        "rate_limit_salt",  # the /health field for the salt's source
        rlp.SALT_ENV,  # the operator-held source
        rlp._SALT_FILENAME,  # the file source, which has to survive the boot
        rlp.TABLE,
        "ORRERY_RATE_LIMIT_PERSIST_INTERVAL_S",
        "ORRERY_RATE_LIMIT_PERSIST_MAX_KEYS",
    ):
        assert name in doc, f"CONFIGURATION.md does not name {name}"

    if "ORRERY_RATE_LIMIT_PERSIST_INTERVAL_S" not in os.environ:
        assert f"| `ORRERY_RATE_LIMIT_PERSIST_INTERVAL_S` | `{rlp.PERSIST_INTERVAL_S:g}` |" in doc, (
            "the documented default interval must be the module's default"
        )
    if "ORRERY_RATE_LIMIT_PERSIST_MAX_KEYS" not in os.environ:
        assert f"| `ORRERY_RATE_LIMIT_PERSIST_MAX_KEYS` | `{rlp.PERSIST_MAX_KEYS}` |" in doc, (
            "the documented default key cap must be the module's default"
        )
