"""Graduation state machine — per-(cap, scope, context) FSM + storage.

States
------

  observing  — initial. Propose goes through the consent gate as
               \"prompt\" (W1 default). Every approval bumps the
               observation count.
  proposing  — transient label used by the tray UI to indicate
               \"waiting for the user to click.\" Not materially
               different from observing for the FSM; tests are
               written against observing.
  approved   — user approved THIS specific action recently. The
               existing gate.approve/find_valid_approval flow
               handles per-call approvals; graduation tracks the
               aggregate trend.
  graduated  — stats pass the bar: ≥5 approvals AND
               posterior_mean > 0.85. This flips the executor to
               auto-execute with notification (W4, SHIPPED):
               `executor.execute_plan` consults `status()` via
               `auto_approve_if_graduated` and runs the action
               without a prompt. `skill.invoke` is exempt
               (executor `_NO_AUTO_APPROVE`) and always prompts.
  revoked    — terminal state. Can be entered from any other
               state via revoke(). Auto-execute STOPS immediately.
               New approvals don't re-graduate until the user
               re-graduates explicitly (a later enhancement).

Device binding (S10)
-------------------

The graduation store is keyed on (device_did, capability, scope,
context_sha256). Copying the SQLite file to another device does not
auto-apply graduations: the other device's did:key won't match.
Un-skips the S10 threat-model test.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

__all__ = [
    "GRADUATION_MIN_APPROVALS",
    "GRADUATION_MIN_POSTERIOR",
    "GraduationState",
    "GraduationStatus",
    "GraduationStore",
    "make_graduation_key",
]


GraduationState = Literal["observing", "proposing", "approved", "graduated", "revoked"]

# Thresholds. Kept here so the FSM + tests share the same constants.
GRADUATION_MIN_APPROVALS = 5
GRADUATION_MIN_POSTERIOR = 0.85


@dataclass(frozen=True)
class GraduationStatus:
    """Current state of one (device, capability, scope, context) cell."""

    device_did: str
    capability: str
    scope: str
    context_sha256: str
    state: GraduationState
    approvals: int
    posterior_mean: float
    graduated_at: str | None = None
    revoked_at: str | None = None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS graduations (
    device_did    TEXT NOT NULL,
    capability    TEXT NOT NULL,
    scope         TEXT NOT NULL,
    context_sha256 TEXT NOT NULL,
    state         TEXT NOT NULL DEFAULT 'observing',
    graduated_at  TEXT,
    revoked_at    TEXT,
    PRIMARY KEY (device_did, capability, scope, context_sha256)
);
"""


def make_graduation_key(
    *,
    device_did: str,
    capability: str,
    scope: str,
    context_sha256: str,
) -> tuple[str, str, str, str]:
    """Canonical key tuple. Reject empty parts."""
    for name, val in (
        ("device_did", device_did),
        ("capability", capability),
        ("scope", scope),
        ("context_sha256", context_sha256),
    ):
        if not val:
            raise ValueError(f"{name} is required for graduation key")
    return (device_did, capability, scope, context_sha256)


class GraduationStore:
    """Tracks graduation state per (device, capability, scope, context).

    State transitions are computed lazily from the habit model's
    (approvals, posterior_mean). The store persists the current
    state + timestamps so the UI can show \"graduated on 2026-04-24\"
    and an auditor can replay transitions.
    """

    def __init__(self, db_path: str | Path, *, device_did: str):
        if not device_did:
            raise ValueError("device_did is required — graduations are per-device")
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.device_did = device_did
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.execute("PRAGMA journal_mode = WAL")
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), isolation_level=None, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    # ── Queries ────────────────────────────────────────────────

    def status(
        self,
        *,
        capability: str,
        scope: str,
        context_sha256: str,
        approvals: int,
        posterior_mean: float,
    ) -> GraduationStatus:
        """Compute current status from stored state + provided stats.

        If the stored state is 'revoked', it stays revoked regardless
        of stats — revocation is sticky until explicit re-graduation.
        Otherwise, the FSM promotes to 'graduated' when stats clear
        the bar, and demotes to 'observing' when they fall below it.
        """
        key = make_graduation_key(
            device_did=self.device_did,
            capability=capability,
            scope=scope,
            context_sha256=context_sha256,
        )
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state, graduated_at, revoked_at FROM graduations "
                "WHERE device_did=? AND capability=? AND scope=? AND context_sha256=?",
                key,
            ).fetchone()
        stored_state: GraduationState = row["state"] if row else "observing"  # type: ignore[assignment]
        graduated_at = row["graduated_at"] if row else None
        revoked_at = row["revoked_at"] if row else None

        # Revoked is sticky.
        if stored_state == "revoked":
            return GraduationStatus(
                device_did=self.device_did,
                capability=capability,
                scope=scope,
                context_sha256=context_sha256,
                state="revoked",
                approvals=approvals,
                posterior_mean=posterior_mean,
                graduated_at=graduated_at,
                revoked_at=revoked_at,
            )

        # FSM: promote if both bars cleared.
        if approvals >= GRADUATION_MIN_APPROVALS and posterior_mean > GRADUATION_MIN_POSTERIOR:
            effective: GraduationState = "graduated"
        else:
            effective = "observing"
        return GraduationStatus(
            device_did=self.device_did,
            capability=capability,
            scope=scope,
            context_sha256=context_sha256,
            state=effective,
            approvals=approvals,
            posterior_mean=posterior_mean,
            graduated_at=graduated_at,
            revoked_at=revoked_at,
        )

    # ── Transitions ────────────────────────────────────────────

    def record_graduation(
        self,
        *,
        capability: str,
        scope: str,
        context_sha256: str,
    ) -> str:
        """Persist the fact that this triple crossed the threshold.

        Callers should invoke this the FIRST time `status(...)` returns
        state='graduated' for a bucket, so the UI/audit has a single
        \"graduated on\" timestamp. Idempotent — calling twice does
        not overwrite the first timestamp.
        """
        key = make_graduation_key(
            device_did=self.device_did,
            capability=capability,
            scope=scope,
            context_sha256=context_sha256,
        )
        now = datetime.now(UTC).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO graduations
                    (device_did, capability, scope, context_sha256, state, graduated_at)
                VALUES (?, ?, ?, ?, 'graduated', ?)
                ON CONFLICT(device_did, capability, scope, context_sha256) DO UPDATE SET
                    state = CASE WHEN graduations.state = 'revoked'
                                 THEN 'revoked'
                                 ELSE 'graduated' END,
                    graduated_at = COALESCE(graduations.graduated_at, ?)
                """,
                (*key, now, now),
            )
        row = self._fetch_row(key)
        return row["graduated_at"] if row else now

    def revoke(
        self,
        *,
        capability: str,
        scope: str,
        context_sha256: str,
    ) -> str:
        """Mark this triple as revoked. Subsequent status() calls stick
        at state='revoked' regardless of habit stats."""
        key = make_graduation_key(
            device_did=self.device_did,
            capability=capability,
            scope=scope,
            context_sha256=context_sha256,
        )
        now = datetime.now(UTC).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO graduations
                    (device_did, capability, scope, context_sha256, state, revoked_at)
                VALUES (?, ?, ?, ?, 'revoked', ?)
                ON CONFLICT(device_did, capability, scope, context_sha256) DO UPDATE SET
                    state = 'revoked',
                    revoked_at = ?
                """,
                (*key, now, now),
            )
        return now

    def revoke_all(self) -> int:
        """Panic-path helper: revoke every graduation for this device.
        Returns the number of rows affected."""
        now = datetime.now(UTC).isoformat()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE graduations SET state='revoked', revoked_at=? WHERE device_did=? AND state != 'revoked'",
                (now, self.device_did),
            )
        return cur.rowcount or 0

    def _fetch_row(self, key: tuple[str, str, str, str]) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM graduations WHERE device_did=? AND capability=? AND scope=? AND context_sha256=?",
                key,
            ).fetchone()
