"""Bayesian habit model — P(approve | capability, scope, context).

Per-bucket Beta posterior with a conjugate Beta(α₀=1, β₀=1) prior
(uniform on [0,1]). Each user approval increments α; each denial
increments β. The posterior mean is α/(α+β); graduation (in W3.3)
fires when the mean is > 0.85 AND we've seen ≥5 approvals in that
bucket.

Why Beta/Bernoulli:
  * Closed-form update — O(1) per observation
  * Principled uncertainty quantification via the full posterior
    (graduation can consult lower_confidence_bound later if
    conservatism matters)
  * Auditable — α and β are just integer counts a human can verify

Storage is SQLite, single-table, append-only observation log plus a
denormalized counts table for O(1) P(approve|ctx) reads. The counts
table is a materialized view of the log — reset_for_tests drops it,
rebuild_counts_from_log() can regenerate from the log alone, so
there is no possibility of drift between the two.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

__all__ = [
    "BucketStats",
    "HabitModel",
    "UserDecision",
]


UserDecision = Literal["approved", "denied"]


@dataclass(frozen=True)
class BucketStats:
    """Posterior snapshot for one (capability, scope, context) triple."""

    capability: str
    scope: str
    context_sha256: str
    approvals: int  # α - α₀ (observed approvals)
    denials: int  # β - β₀ (observed denials)
    total: int  # approvals + denials
    posterior_mean: float  # α / (α + β) including priors


_SCHEMA = """
CREATE TABLE IF NOT EXISTS habit_observations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    capability    TEXT NOT NULL,
    scope         TEXT NOT NULL,
    context_sha256 TEXT NOT NULL,
    decision      TEXT NOT NULL,
    recorded_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_obs_bucket
    ON habit_observations(capability, scope, context_sha256);

CREATE TABLE IF NOT EXISTS habit_counts (
    capability    TEXT NOT NULL,
    scope         TEXT NOT NULL,
    context_sha256 TEXT NOT NULL,
    approvals     INTEGER NOT NULL DEFAULT 0,
    denials       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (capability, scope, context_sha256)
);
"""


PRIOR_ALPHA = 1
PRIOR_BETA = 1


class HabitModel:
    """Append-only Bayesian habit model.

    One instance per process typically — constructor opens the SQLite
    file and ensures schema. Methods are thread-safe via an internal
    lock on the write path; reads use WAL so they can proceed in
    parallel with writes.
    """

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.execute("PRAGMA journal_mode = WAL")
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), isolation_level=None, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    # ── Observe ────────────────────────────────────────────────

    def observe(
        self,
        *,
        capability: str,
        scope: str,
        context_sha256: str,
        decision: UserDecision,
        recorded_at: str,
    ) -> None:
        """Log one user decision and update the counts table.

        Both inserts happen in a single transaction so a mid-write
        crash cannot leave the log + counts out of sync. If you
        crash before commit, no observation is visible; after
        commit, both the log and the counts reflect it.
        """
        if decision not in ("approved", "denied"):
            raise ValueError(f"decision must be 'approved' or 'denied', got {decision!r}")
        if not capability or not scope or not context_sha256:
            raise ValueError("capability, scope, context_sha256 all required")

        approval_delta = 1 if decision == "approved" else 0
        denial_delta = 0 if decision == "approved" else 1

        with self._lock, self._connect() as conn:
            conn.execute("BEGIN")
            conn.execute(
                "INSERT INTO habit_observations "
                "(capability, scope, context_sha256, decision, recorded_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (capability, scope, context_sha256, decision, recorded_at),
            )
            conn.execute(
                """
                INSERT INTO habit_counts
                    (capability, scope, context_sha256, approvals, denials)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(capability, scope, context_sha256) DO UPDATE SET
                    approvals = approvals + ?,
                    denials   = denials + ?
                """,
                (
                    capability,
                    scope,
                    context_sha256,
                    approval_delta,
                    denial_delta,
                    approval_delta,
                    denial_delta,
                ),
            )
            conn.execute("COMMIT")

    # ── Read ─────────────────────────────────────────────────────

    def stats(self, capability: str, scope: str, context_sha256: str) -> BucketStats:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT approvals, denials FROM habit_counts WHERE capability=? AND scope=? AND context_sha256=?",
                (capability, scope, context_sha256),
            ).fetchone()
        approvals = row["approvals"] if row else 0
        denials = row["denials"] if row else 0
        return _stats_from_counts(capability, scope, context_sha256, approvals, denials)

    def observation_count(self, capability: str, scope: str, context_sha256: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM habit_observations WHERE capability=? AND scope=? AND context_sha256=?",
                (capability, scope, context_sha256),
            ).fetchone()
        return int(row["n"] or 0)

    # ── Maintenance / integrity ─────────────────────────────────

    def rebuild_counts_from_log(self) -> None:
        """Reconstruct habit_counts from habit_observations.

        Useful after external tampering (tests) or to verify the
        counts table matches the log. The log is the source of truth;
        counts are a materialized view.
        """
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN")
            conn.execute("DELETE FROM habit_counts")
            conn.execute(
                """
                INSERT INTO habit_counts (capability, scope, context_sha256, approvals, denials)
                SELECT capability, scope, context_sha256,
                       SUM(CASE WHEN decision='approved' THEN 1 ELSE 0 END),
                       SUM(CASE WHEN decision='denied' THEN 1 ELSE 0 END)
                FROM habit_observations
                GROUP BY capability, scope, context_sha256
                """
            )
            conn.execute("COMMIT")


def _stats_from_counts(capability: str, scope: str, context_sha256: str, approvals: int, denials: int) -> BucketStats:
    alpha = PRIOR_ALPHA + approvals
    beta = PRIOR_BETA + denials
    mean = alpha / (alpha + beta)
    return BucketStats(
        capability=capability,
        scope=scope,
        context_sha256=context_sha256,
        approvals=approvals,
        denials=denials,
        total=approvals + denials,
        posterior_mean=mean,
    )
