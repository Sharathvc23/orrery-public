"""Trust-system daily cron tasks (decay sweep + drift detector).

Runs from inside `think_cycle.py` — same place the policy auto-tuner
already lives. Each task self-throttles to once-per-day so adding it
to the ~90-second think tick is harmless.

Plan: WIRE-3 of the post-trust wiring series. The /api/admin/trust/
{decay-sweep,drift} endpoints existed since PR-C but no scheduler
called them. Now the chapter agent runs them on its own.

Why in-process throttle vs an external scheduled-job runner:
  * No external infra to configure
  * Crash-safe (last-run timestamp is in-memory; on restart we just
    re-run, which is idempotent — decay rows are UNIQUE per ISO week,
    drift detector is read-only)
  * Multi-dyno chapters would re-run per dyno but writes are
    idempotent at the DB layer

Coverage in tests/test_trust_cron.py.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from typing import Any

# Once-per-day throttle (in seconds). Each cron stores its last run time
# in this dict; all calls inside the window short-circuit. The key is
# the cron name; the value is the unix timestamp of the last successful run.
_DAY_SECONDS = 24 * 3600
_last_run: dict[str, float] = {}

# Injected — chapter_agent.py wires these on startup.
_pg_request: Callable[..., Awaitable[Any]] | None = None
_chapter_id: str = ""


def init(pg_request, chapter_id: str) -> None:
    global _pg_request, _chapter_id
    _pg_request = pg_request
    _chapter_id = chapter_id


def _due(name: str, *, now: float | None = None, interval: int = _DAY_SECONDS) -> bool:
    """Return True iff `name` hasn't run in the last `interval` seconds."""
    now = now if now is not None else time.time()
    last = _last_run.get(name)
    if last is None:
        return True
    return (now - last) >= interval


def _mark_ran(name: str, *, now: float | None = None) -> None:
    _last_run[name] = now if now is not None else time.time()


def reset_for_tests() -> None:
    """Clear throttle state. Tests use this to drive multiple runs in
    a single test without sleeping."""
    _last_run.clear()


async def run_decay_sweep_if_due(*, now: float | None = None) -> dict:
    """Walk every agent. For any inactive >60d, append a `inactive_decay`
    trust_event (-1.0). Returns {ran: bool, swept, decay_emitted}.
    `ran=False` when throttled."""
    if not _due("decay_sweep", now=now):
        return {"ran": False, "reason": "throttled"}
    if _pg_request is None:
        return {"ran": False, "reason": "uninitialized"}

    import trust_events as _trust

    try:
        rows = (
            await _pg_request(
                "GET",
                "agents",
                params={"select": "agent_id", "limit": 5000},
            )
            or []
        )
    except Exception as e:
        return {"ran": False, "reason": f"agents_read_failed: {e}"}

    fired = 0
    for r in rows:
        aid = r.get("agent_id")
        if not aid:
            continue
        try:
            if await _trust.apply_inactivity_decay_for_agent(agent_id=aid):
                fired += 1
        except Exception:  # noqa: BLE001,S112 — sweep is best-effort per agent
            continue

    _mark_ran("decay_sweep", now=now)
    return {"ran": True, "swept": len(rows), "decay_emitted": fired}


async def run_drift_check_if_due(*, now: float | None = None) -> dict:
    """Compare trigger-maintained agents.trust_score vs SUM(delta) replay.
    Returns {ran: bool, drift_count, drifts}. Non-empty drifts is a P1
    alert (governance overrides bypassed the ledger)."""
    if not _due("drift_check", now=now):
        return {"ran": False, "reason": "throttled"}
    if _pg_request is None:
        return {"ran": False, "reason": "uninitialized"}

    import trust_events as _trust

    try:
        drifts = await _trust.detect_score_drift()
    except Exception as e:
        return {"ran": False, "reason": f"drift_check_failed: {e}"}

    _mark_ran("drift_check", now=now)
    return {"ran": True, "drift_count": len(drifts), "drifts": drifts}
