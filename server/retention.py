"""Data retention policy + nightly sweeper.

Per-category record TTLs. Regulatory regimes come in two shapes, and the
difference decides whether the sweeper deletes: some impose a MINIMUM the
operator may not go below, others impose a MAXIMUM ("keep no longer than
necessary"). ``jurisdiction.Direction`` carries which is which.

  - CCPA/CPRA (California): no fixed minimum; "as long as reasonably
    necessary for the disclosed purpose."
  - GDPR (EU): data minimization principle — keep no longer than needed.
  - HIPAA (US health): 6 years for medical records.
  - SOX / financial / SEC: 7 years for transactions and audit logs.
  - FERPA (US education): 5 years for student records.
  - NIST 800-171 / DFARS (US federal contractor): 3 years for audit logs.

This module defines:

  - A per-category default retention table that ANY chapter can adopt.
  - A loader that reads chapter_policy.retention_days_by_category (a
    Postgres table extension) for operator overrides — e.g., a health-
    oriented chapter sets 'data_shared' to 6×365 days.
  - A nightly sweep that DELETEs records past their TTL. Per-table
    where_clause queries; safe to run repeatedly (idempotent).

Architecture:

  - The sweeper is fire-and-forget. A run failure logs but doesn't
    crash the chapter — retention failure is an operator concern, not
    a request-path concern.
  - Sweeper writes an audit entry per category swept, so operators
    can prove to auditors "we deleted N records past their TTL on this
    date."
  - The sweeper is opt-in via env var ``CHAPTER_RETENTION_SWEEP_ENABLED``.
    Default ON for new deployments; existing deployments must set the
    env to enable (so first-run retention doesn't surprise an existing
    operator with a mass delete).

The sweeper is jurisdiction-aware via the policy table: a Bay Area
chapter has different defaults than a Federal contractor chapter. See
chapter/jurisdiction.py (Compliance-4) for the chapter-side
jurisdiction resolution.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

# ── Per-category default retention (days) ──────────────────────────
#
# These are conservative defaults — long enough to satisfy common
# regulatory minima, short enough to limit blast radius if a server
# is breached. Server operators override per their actual regime via
# chapter_policy.retention_days_by_category.
DEFAULT_RETENTION_DAYS: dict[str, int] = {
    # ARP receipts — primary evidence. Default 7 years (financial /
    # SOX-style). Compliance-conscious servers may go shorter.
    "arp_receipts": 7 * 365,
    # Chronicles — daily narrative summaries. Default 1 year.
    "chronicles": 365,
    # Audit ledger — server operator's own evidence. Default 7 years.
    "chapter_audit_events": 7 * 365,
    # Intents — privacy-sensitive matching state. Default 90 days
    # (CCPA-aligned data minimization). Table is `agent_intents` (init.sql:997).
    "agent_intents": 90,
    # Outcome tracking — telemetry. Default 180 days (~2 quarters).
    "agent_action_outcomes": 180,
    # Trust events — reputation deltas. Default 2 years.
    "trust_events": 730,
    # Role nominations — governance state. Default 1 year.
    "chapter_role_nominations": 365,
    # Pending approvals — short-lived governance. Default 30 days
    # AFTER the TTL on the approval itself expires.
    "pending_approvals": 30,
}

# Table → timestamp column for the TTL query
TIMESTAMP_COLUMN: dict[str, str] = {
    "arp_receipts": "issued_at",
    "chronicles": "created_at",
    "chapter_audit_events": "occurred_at",
    "agent_intents": "created_at",
    "agent_action_outcomes": "created_at",
    # trust_events has no created_at — its timestamp column is occurred_at.
    "trust_events": "occurred_at",
    "chapter_role_nominations": "created_at",
    "pending_approvals": "expires_at",
}


def is_sweep_enabled() -> bool:
    """Read the opt-in env var. Default True for new deployments; an
    existing deployment with the env var explicitly set to '0' / 'false'
    keeps retention paused."""
    # ORG_* canonical; CHAPTER_* back-compat.
    raw = (
        os.environ.get("ORG_RETENTION_SWEEP_ENABLED")
        or os.environ.get("CHAPTER_RETENTION_SWEEP_ENABLED", "true")
    ).strip().lower()
    return raw not in {"0", "false", "no", "off", ""}


def is_dry_run_mode() -> bool:
    """Whether the sweeper should treat every run as dry-run (compute
    cutoffs + log per-table 'would-delete' counts to audit, but never
    actually DELETE).

    Defaults to **False** for GA: a stock deployment ENFORCES
    retention — the sweeper actually DELETEs records past their TTL.
    A system that advertises data-minimization (GDPR Art. 5(1)(e) /
    CCPA) but silently deletes nothing is a compliance gap, so the
    stock behaviour must be to enforce, not to no-op. The default TTLs
    are conservative (90 days … 7 years), so a fresh deploy purges
    nothing on its early runs regardless.

    Operators who want a review period before any deletion opt IN to
    dry-run per chapter by setting ``ORG_RETENTION_SWEEP_DRY_RUN=true``
    (alias ``CHAPTER_RETENTION_SWEEP_DRY_RUN``); the sweeper then logs
    'would-delete' counts to chapter_audit_events without deleting.
    This preserves the safety lever from the 2026-05-23 chapter review
    ("don't delete until I can verify what WOULD be touched") as an
    explicit opt-in rather than the default.
    """
    # ORG_* canonical; CHAPTER_* back-compat.
    raw = (
        os.environ.get("ORG_RETENTION_SWEEP_DRY_RUN")
        or os.environ.get("CHAPTER_RETENTION_SWEEP_DRY_RUN", "false")
    ).strip().lower()
    return raw not in {"0", "false", "no", "off"}


async def resolve_retention_policy(
    pg_request: Callable[..., Awaitable[Any]] | None,
    chapter_id: str,
) -> dict[str, int]:
    """Build the effective per-category retention map.

    Layers:
      1. DEFAULT_RETENTION_DAYS — module-level defaults.
      2. Jurisdiction overrides — ``jurisdiction.retention_overrides_for()``.
         NOT an override in the assignment sense: each rule declares a
         DIRECTION and is applied against layer 1 with ``max`` (FLOOR — a
         statutory minimum) or ``min`` (CEILING — a minimisation regime).
      3. chapter_policy row (key='retention_days_by_category') — operator override,
         and this one IS an assignment: the operator's own policy is the top layer.
         chapter_policy is a key/value table (chapter_id, key, value jsonb), NOT a
         wide table with a retention_days_by_category column (init.sql:1480).

    Returns a complete map: every table in TIMESTAMP_COLUMN has a TTL.

    ⚠️ LAYER 2 WAS MISSING AND THAT WAS A COMPLIANCE GAP, NOT A MISSING FEATURE.
    ``jurisdiction.py`` was a complete, tested module that nothing imported — the
    shape. Its docstring named this function as a consumer and this function
    never called it, so ``ORG_JURISDICTION`` was documented in CONFIGURATION.md,
    read by exactly one module, and that module never ran. The consequence is not
    symmetric: for EU/UK the overrides SHORTEN retention (GDPR minimisation), so
    data was kept longer than the regime allows; for US-FED/US-DOD/HIPAA/GLBA they
    LENGTHEN it, so audit logs and receipts were being swept BEFORE the statutory
    floor — NIST 800-171 wants 3 years of security audit events and this deleted
    them at the 90-day default.

    Deliberately safe to land: ``RETENTION_OVERRIDES["US"]`` is empty and ``US``
    is the default, so an org that never set a jurisdiction sees byte-identical
    behaviour. Only an operator who explicitly declared one gets a change, which
    is precisely what declaring one is for.

    ⚠️ LAYER 2 IS NOT AN ASSIGNMENT, AND WAS ONE UNTIL the floor-versus-ceiling fix. It read
    ``policy[table] = days``, which means "this regime decides the number" —
    and no regime does. A minimum regime and a minimisation regime hand you
    the same integer with opposite instructions, so ``ORG_JURISDICTION=US-FED``
    SHORTENED ``chapter_audit_events`` from the 2555-day default to the NIST
    800-171 three-year *minimum* of 1095 and the sweeper below DELETED four
    years of security audit events to comply with a floor. Each rule now
    carries its direction and resolves through ``RetentionRule.apply``.

    The operator override stays the TOP layer. A jurisdiction is a floor the
    regime imposes, not a ceiling on the operator's own policy.
    """
    policy = dict(DEFAULT_RETENTION_DAYS)

    # Layer 2 — jurisdiction. Imported here rather than at module scope because
    # `jurisdiction.effective_retention_policy` delegates back to this function;
    # a top-level import in both directions is a cycle.
    try:
        import jurisdiction as _jurisdiction

        code = await _jurisdiction.resolve_jurisdiction(pg_request, chapter_id)
        for table, rule in _jurisdiction.retention_overrides_for(code).items():
            # A table with no default has nothing for a floor or a ceiling to
            # bind against, and one with no timestamp column is never swept.
            if table in TIMESTAMP_COLUMN and table in policy:
                policy[table] = rule.apply(policy[table])
    except Exception as e:  # noqa: BLE001
        # Non-fatal, and LOUD. A silently skipped jurisdiction layer is how this
        # module came to be unreachable in the first place; the previous bare
        # `pass` below is what hid a schema mismatch for the whole life of the
        # module. Defaults still apply, so the sweeper stays safe.
        print(f"[Retention] jurisdiction layer skipped: {type(e).__name__}: {e}")

    if pg_request is None:
        # Explicit, not incidental. This used to reach `await None(...)` and land
        # in the bare `except` below — a TypeError standing in for a branch. A
        # control that works by accident is one nobody can reason about.
        return policy

    try:
        rows = await pg_request(
            "GET",
            "chapter_policy",
            params={
                "chapter_id": f"eq.{chapter_id}",
                "key": "eq.retention_days_by_category",
                "select": "value",
                "limit": "1",
            },
        )
        if rows and isinstance(rows, list) and rows:
            override = rows[0].get("value") or {}
            if isinstance(override, dict):
                for table, days in override.items():
                    if table in TIMESTAMP_COLUMN and isinstance(days, int) and days > 0:
                        policy[table] = days
    except Exception:  # noqa: BLE001
        # Missing chapter_policy table is non-fatal — defaults apply.
        pass
    return policy


async def sweep_once(
    pg_request: Callable[..., Awaitable[Any]],
    chapter_id: str,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run one retention sweep pass. Idempotent — safe to call repeatedly.

    Returns a per-table summary:
      {
        "chapter_id": "...",
        "swept_at": "2026-05-22T...",
        "dry_run": False,
        "policy": { table: days, ... },  // effective policy applied
        "results": {
          "arp_receipts": { "cutoff": "iso", "deleted": int, "error": str | None },
          ...
        },
        "total_deleted": int,
      }

    If ``dry_run=True``, the policy is evaluated and cutoffs computed,
    but no DELETEs are issued. Useful for the operator's first-run
    audit before enabling the live sweep.
    """
    policy = await resolve_retention_policy(pg_request, chapter_id)
    results: dict[str, dict[str, Any]] = {}
    total_deleted = 0
    now = datetime.now(UTC)

    for table, days in policy.items():
        ts_column = TIMESTAMP_COLUMN.get(table)
        if not ts_column:
            continue
        cutoff = (now - timedelta(days=days)).isoformat()
        outcome: dict[str, Any] = {"cutoff": cutoff, "deleted": 0, "error": None}
        if not dry_run:
            try:
                resp = await pg_request(
                    "DELETE",
                    table,
                    params={ts_column: f"lt.{cutoff}"},
                )
                if isinstance(resp, list):
                    outcome["deleted"] = len(resp)
                    total_deleted += len(resp)
                else:
                    # pg_request returns None on a non-2xx (e.g. an
                    # unknown column) rather than raising. Record it as an
                    # error so a swept-but-FAILED table is visibly distinct
                    # from a swept-CLEAN one — a broken sweep must not read as
                    # healthy "nothing to purge".
                    outcome["error"] = "delete returned no result (query rejected?)"
            except Exception as e:  # noqa: BLE001
                outcome["error"] = str(e)[:200]
        results[table] = outcome

    return {
        "chapter_id": chapter_id,
        "swept_at": now.isoformat(),
        "dry_run": dry_run,
        "policy": policy,
        "results": results,
        "total_deleted": total_deleted,
    }


async def emit_audit_for_sweep(
    sweep_result: dict[str, Any],
    chapter_id: str,
) -> None:
    """Write the sweep summary to chapter_audit_events so the operator
    can prove to auditors that retention is enforced.

    Fire-and-forget — audit failure must not block the sweep itself.
    """
    try:
        import chapter_audit

        await chapter_audit.record(
            chapter_id=chapter_id,
            action="retention.sweep",
            actor_agent_id="system",
            target_type="retention",
            target_id="all",
            outcome="ok",
            detail={
                "swept_at": sweep_result["swept_at"],
                "dry_run": sweep_result["dry_run"],
                "total_deleted": sweep_result["total_deleted"],
                "per_table_summary": {
                    t: {"deleted": v["deleted"], "errored": bool(v["error"])}
                    for t, v in sweep_result["results"].items()
                },
            },
        )
    except Exception:  # noqa: BLE001
        pass


__all__ = [
    "DEFAULT_RETENTION_DAYS",
    "TIMESTAMP_COLUMN",
    "is_sweep_enabled",
    "resolve_retention_policy",
    "sweep_once",
    "emit_audit_for_sweep",
]
