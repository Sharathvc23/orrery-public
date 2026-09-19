"""DAT — member-side hold + verify of Delegated Authority Tokens.

This is the member's half of authority verification. A DAT records what an agent
was *allowed* to do, signed by the grantor (a real chain looks like operator →
chapter → member), so authority is traceable rather than self-claimed. With this
module a sovereign member can:

* **verify** a counterparty's DAT — signature, validity window, scope, the full
  sub-delegation chain, and revocation — *before* transacting, instead of
  trusting its chapter to vouch for the counterparty; and
* **hold and present** the DAT its own principal granted it (``DatStore``).

All verification delegates to the vendored canonical verifier
(``community_member/_dat/``), which is kept byte-for-byte in lockstep with
``conformance/dat`` — one source of verification truth across both runtimes.
See ``spec/arp/0.1/dat-companion.md`` (promoted to ARP 0.2).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ._dat import (
    DAT_VERSION,
    ConstraintResult,
    DatResult,
    build_dat,
    evaluate_constraints,
    make_grant_id,
    verify_dat_chain,
    verify_dat_signature,
)


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def verify_counterparty_dat(
    dat: dict[str, Any],
    *,
    now: str | None = None,
    category: str | None = None,
    dats_by_id: dict[str, dict[str, Any]] | None = None,
    revocations: set[str] | None = None,
) -> DatResult:
    """Verify a presented DAT (and its delegation chain) before transacting.

    Convenience over :func:`verify_dat_chain`: the presented ``dat`` is added to
    the resolution pool automatically, so a single (unchained) DAT just works.
    For a sub-delegated DAT, pass the ancestor DATs via ``dats_by_id`` (the
    counterparty presents the whole chain). ``now`` defaults to the current UTC
    time; ``category`` is checked against the leaf grant's scope.
    """
    pool: dict[str, dict[str, Any]] = dict(dats_by_id or {})
    pool.setdefault(dat["grant_id"], dat)
    return verify_dat_chain(
        dat["grant_id"],
        dats_by_id=pool,
        now=now or _now_iso(),
        category=category,
        revocations=revocations,
    )


@dataclass
class DatStore:
    """Local SQLite store of DATs the member holds — both the grant(s) its own
    principal issued to it (to present to counterparties) and any ancestor DATs
    it has collected to prove a chain. Keyed by ``grant_id`` (idempotent)."""

    home: Path

    def __post_init__(self) -> None:
        self.home = Path(self.home).expanduser().resolve()
        self.home.mkdir(parents=True, exist_ok=True)
        self.db_path = self.home / "dat-store.sqlite"
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._conn() as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS dats (
                    grant_id     TEXT PRIMARY KEY,
                    grantor_did  TEXT NOT NULL,
                    grantee_did  TEXT NOT NULL,
                    not_after    TEXT NOT NULL,
                    dat_json     TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_dats_grantee ON dats(grantee_did)")

    def add(self, dat: dict[str, Any]) -> None:
        """Persist a DAT. Idempotent on ``grant_id``."""
        with self._conn() as c:
            c.execute(
                "INSERT OR IGNORE INTO dats (grant_id, grantor_did, grantee_did, not_after, dat_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    dat["grant_id"],
                    dat["grantor_did"],
                    dat["grantee_did"],
                    dat["not_after"],
                    json.dumps(dat, ensure_ascii=False),
                ),
            )

    def get(self, grant_id: str) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute("SELECT dat_json FROM dats WHERE grant_id = ?", (grant_id,)).fetchone()
        return json.loads(row["dat_json"]) if row else None

    def list_for_grantee(self, grantee_did: str) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT dat_json FROM dats WHERE grantee_did = ? ORDER BY not_after DESC",
                (grantee_did,),
            ).fetchall()
        return [json.loads(r["dat_json"]) for r in rows]


__all__ = [
    "DAT_VERSION",
    "ConstraintResult",
    "DatResult",
    "DatStore",
    "build_dat",
    "evaluate_constraints",
    "make_grant_id",
    "verify_counterparty_dat",
    "verify_dat_chain",
    "verify_dat_signature",
]
