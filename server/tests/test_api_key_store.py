"""api_key_store — member LLM provider keys sealed at rest (AUDIT_HARSH C1).

``agent_api_keys.api_key_encrypted`` was read straight into the provider client
with no decryption, so the column name asserted a property the storage did not
have. These tests pin the read path (sealed and legacy), the seal-in-place
migration, and the failure modes that must NOT take the org down.

Severity note, kept here so the test file states it as plainly as the PR does:
these are bring-your-own-key member credentials. A leak costs the member their
own provider spend. That is materially less severe than the chapter signing key
(C11, ``test_chapter_keypair_persistence``), which is org identity and forges
receipts, attestations and federation broadcasts.
"""

from __future__ import annotations

import pytest

import api_key_store
import secret_sealing


class _FakePostgres:
    """In-memory stand-in scoped to agent_api_keys."""

    def __init__(self, rows: list[dict] | None = None, fail_writes: bool = False) -> None:
        self.rows = rows or []
        self.fail_writes = fail_writes
        self.calls: list[str] = []

    async def __call__(self, method, table, params=None, body=None):
        self.calls.append(f"{method} {table}")
        assert table == "agent_api_keys"
        if method == "GET":
            return [dict(r) for r in self.rows]
        if method == "PATCH":
            if self.fail_writes:
                return None
            pid = params["profile_id"].removeprefix("eq.")
            prov = params["provider"].removeprefix("eq.")
            hit = [r for r in self.rows if r["profile_id"] == pid and r["provider"] == prov]
            for r in hit:
                r.update(body)
            return [dict(r) for r in hit]
        raise AssertionError(f"unexpected {method}")


def _row(stored: str, pid: str = "p1", provider: str = "anthropic") -> dict:
    return {"profile_id": pid, "provider": provider, "api_key_encrypted": stored, "base_url": ""}


@pytest.fixture(autouse=True)
def _kek(monkeypatch):
    monkeypatch.setenv("ORRERY_KEY_SECRET", "kek-for-api-key-tests")


async def test_C1_sealed_row_is_unsealed_for_the_caller():
    """A sealed row yields usable plaintext under ``api_key``."""
    sealed = secret_sealing.seal("sk-real-provider-key", subject="test")
    pg = _FakePostgres([_row(sealed)])
    rows = await api_key_store.load_api_keys(pg)
    assert [r["api_key"] for r in rows] == ["sk-real-provider-key"]


async def test_C1_plaintext_is_never_returned_under_the_at_rest_field_name():
    """The at-rest column name does not leak into the loaded row.

    The original defect was a call site reading ``api_key_encrypted`` and treating
    it as usable material. There is no such field to read here.
    """
    pg = _FakePostgres([_row("sk-legacy-plaintext")])
    rows = await api_key_store.load_api_keys(pg)
    assert "api_key_encrypted" not in rows[0]
    assert "_stored" not in rows[0]
    assert rows[0]["api_key"] == "sk-legacy-plaintext"


async def test_C1_existing_plaintext_row_is_sealed_in_place():
    """MIGRATION: rows written before sealing are re-stored sealed on first read.

    Without this, sealing would cover only rows written after the out-of-band
    provisioner is updated, and every key already in the table would stay in the
    clear while the code read as fixed.
    """
    pg = _FakePostgres([_row("sk-legacy-plaintext")])
    rows = await api_key_store.load_api_keys(pg)

    stored = pg.rows[0]["api_key_encrypted"]
    assert secret_sealing.is_sealed(stored)  # sealed at rest; version-agnostic by design
    assert "sk-legacy-plaintext" not in stored
    assert rows[0]["api_key"] == "sk-legacy-plaintext"  # the key itself is unchanged
    assert secret_sealing.unseal(stored) == "sk-legacy-plaintext"


async def test_C1_sealed_row_is_not_rewritten():
    """One-shot: an already-sealed row triggers no UPDATE."""
    pg = _FakePostgres([_row(secret_sealing.seal("sk-x", subject="test"))])
    await api_key_store.load_api_keys(pg)
    assert [c for c in pg.calls if c.startswith("PATCH")] == []


async def test_C1_no_migration_without_a_key_encryption_secret(monkeypatch):
    """With sealing opted out and no secret, nothing is rewritten and reads still work.

    Sealing in place here would be impossible (no key to seal under); the useful
    behaviour is to leave the row alone rather than fail the load.
    """
    monkeypatch.delenv("ORRERY_KEY_SECRET", raising=False)
    monkeypatch.setenv("ORRERY_REQUIRE_SEALED_SECRETS", "false")
    pg = _FakePostgres([_row("sk-legacy-plaintext")])
    rows = await api_key_store.load_api_keys(pg)
    assert rows[0]["api_key"] == "sk-legacy-plaintext"
    assert [c for c in pg.calls if c.startswith("PATCH")] == []


async def test_C1_failed_migration_is_loud_and_keeps_the_runtime(capsys):
    """A failed seal-in-place UPDATE logs the still-plaintext state and returns the key.

    The member's runtime must not disappear because the at-rest re-encode failed;
    the load retries on the next boot.
    """
    pg = _FakePostgres([_row("sk-legacy-plaintext")], fail_writes=True)
    rows = await api_key_store.load_api_keys(pg)
    assert rows[0]["api_key"] == "sk-legacy-plaintext"
    out = capsys.readouterr().out
    assert "PLAINTEXT" in out and "Retrying on next load" in out


async def test_C1_unreadable_row_is_dropped_not_raised(monkeypatch, capsys):
    """A row sealed under a DIFFERENT secret drops that member, not the whole load.

    One member's unreadable key must not stop every other member's runtime from
    starting.
    """
    sealed = secret_sealing.seal("sk-under-kek-A", subject="test")
    monkeypatch.setenv("ORRERY_KEY_SECRET", "a-completely-different-kek")
    pg = _FakePostgres([_row(sealed, pid="p1"), _row("sk-fine", pid="p2")])

    rows = await api_key_store.load_api_keys(pg)

    assert [r["profile_id"] for r in rows] == ["p2"]
    assert "could not read" in capsys.readouterr().out


async def test_C1_empty_and_missing_rows_are_skipped():
    """Rows with no key (or no profile) produce no entry rather than an empty client."""
    pg = _FakePostgres([_row("", pid="p1"), _row("sk-ok", pid=""), _row("sk-ok", pid="p3")])
    rows = await api_key_store.load_api_keys(pg)
    assert [r["profile_id"] for r in rows] == ["p3"]


async def test_C1_no_rows_returns_empty():
    pg = _FakePostgres([])
    assert await api_key_store.load_api_keys(pg) == []
