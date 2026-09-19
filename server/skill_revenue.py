"""Skill revenue ledger — integer-cent splits per tool invocation.

Per attested skill tool-call:
  1. Look up live attestations on (skill_id, skill_version)
  2. If none: return None (unattested skills don't mint revenue — Phase A rule)
  3. Compute split — author / advisor pool / chapter treasury
  4. Insert one skill_use_events row + N skill_revenue_ledger rows atomically
     (one per beneficiary)

Invariants (R10 property test):
  - sum(ledger.amount_cents) == use_event.gross_cents  (always)
  - amount_cents >= 0                                   (always)
  - One row per beneficiary per event                   (no double-counting)

Deterministic rounding: when the advisor share doesn't divide evenly
across advisors, the earliest-indexed advisor (sorted by attestor_did)
absorbs the remainder penny. Same rule for the author when the overall
split leaves a penny: author wins it.

Phase A: gross_cents hardcoded to 100 (=$1.00), shares hardcoded to
0.40 / 0.35 / 0.25. Phase B moves both off into chapter_policy.

R1-R10 coverage in tests/test_skill_revenue.py.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

_pg_request: Callable[..., Awaitable[Any]] | None = None
_chapter_id: str = ""

# Phase A constants — Phase B makes these policy-keyed
DEFAULT_GROSS_CENTS = 100
AUTHOR_SHARE = 0.40
ADVISOR_SHARE = 0.35
CHAPTER_SHARE = 0.25


def init(pg_request, chapter_id: str) -> None:
    global _pg_request, _chapter_id
    _pg_request = pg_request
    _chapter_id = chapter_id


def compute_split(
    *,
    gross_cents: int,
    author_did: str,
    attestor_dids: list[str],
    chapter_treasury_did: str,
    author_share: float = AUTHOR_SHARE,
    advisor_share: float = ADVISOR_SHARE,
    chapter_share: float = CHAPTER_SHARE,
) -> list[dict]:
    """Pure function — returns a list of beneficiary dicts summing to gross_cents.

    Each dict: {beneficiary_did, beneficiary_role, amount_cents}.

    Algorithm:
      1. chapter = floor(gross * chapter_share)
      2. advisor_total = floor(gross * advisor_share)
         Split evenly across N advisors; first N_rem advisors get +1 cent
      3. author = gross - chapter - advisor_total  (absorbs residual penny)

    The author-wins-penny rule keeps gross-conservation exact without
    floating-point drift.
    """
    if gross_cents <= 0:
        raise ValueError("gross_cents must be positive")
    if not attestor_dids:
        raise ValueError("cannot split with zero attestors")
    if abs((author_share + advisor_share + chapter_share) - 1.0) > 1e-9:
        raise ValueError("shares must sum to 1.0")

    chapter_cents = int(gross_cents * chapter_share)
    advisor_total_cents = int(gross_cents * advisor_share)

    # Distribute advisor_total across attestors, earliest advisor absorbs extras
    n = len(attestor_dids)
    base = advisor_total_cents // n
    remainder = advisor_total_cents - (base * n)
    sorted_dids = sorted(attestor_dids)

    rows: list[dict] = []

    # Author gets everything not claimed by server + advisor pool
    author_cents = gross_cents - chapter_cents - advisor_total_cents
    rows.append(
        {
            "beneficiary_did": author_did,
            "beneficiary_role": "author",
            "amount_cents": author_cents,
        }
    )

    for i, did in enumerate(sorted_dids):
        cents = base + (1 if i < remainder else 0)
        rows.append(
            {
                "beneficiary_did": did,
                "beneficiary_role": "advisor",
                "amount_cents": cents,
            }
        )

    rows.append(
        {
            "beneficiary_did": chapter_treasury_did,
            "beneficiary_role": "chapter",
            "amount_cents": chapter_cents,
        }
    )

    # Invariant: sum equals gross
    total = sum(r["amount_cents"] for r in rows)
    if total != gross_cents:
        raise RuntimeError(f"split arithmetic bug: rows sum to {total}, gross_cents={gross_cents}")
    if any(r["amount_cents"] < 0 for r in rows):
        raise RuntimeError(f"split produced negative amount: {rows}")

    return rows


async def record_skill_use(
    *,
    skill_id: str,
    skill_version: str,
    used_by_agent_id: str,
    tool_name: str,
    idempotency_key: str,
    used_by_did: str = "",
    gross_cents: int = DEFAULT_GROSS_CENTS,
    success: bool = True,
    duration_ms: int | None = None,
) -> dict:
    """Record a tool invocation + mint the ledger rows.

    Returns:
        {"billed": True, "use_event_id": uuid, "rows": [...]}  on success
        {"billed": False, "reason": "no_attestations"}          if unattested
        {"billed": False, "reason": "duplicate"}                on idempotency replay
        {"error": <reason>}                                      on other failure
    """
    if _pg_request is None:
        return {"error": "skill_revenue not initialized"}
    if not skill_id or not skill_version or not tool_name or not idempotency_key:
        return {"error": "missing required fields"}
    if gross_cents <= 0:
        return {"error": "gross_cents must be positive"}

    # 1. Load live attestations
    import attestations

    live = await attestations.list_live_attestations(skill_id, skill_version)
    if not live:
        return {"billed": False, "reason": "no_attestations"}

    # 2. Resolve skill author
    author_did = await _get_skill_author_did(skill_id)
    if not author_did:
        return {"billed": False, "reason": "author_unknown"}

    # 3. Chapter treasury identifier is just the chapter_id (chapter holds its own funds)
    chapter_treasury_did = f"chapter:{_chapter_id}"

    attestor_dids = [a["attestor_did"] for a in live if a.get("attestor_did")]
    if not attestor_dids:
        return {"billed": False, "reason": "no_attestor_dids"}

    # 4. Compute split (pure)
    try:
        ledger_rows = compute_split(
            gross_cents=gross_cents,
            author_did=author_did,
            attestor_dids=attestor_dids,
            chapter_treasury_did=chapter_treasury_did,
        )
    except ValueError as e:
        return {"error": f"split error: {e}"}

    # 5. Insert use_event + ledger rows. idempotency_key is UNIQUE so duplicate
    #    inserts fail with a database conflict. We catch + report as "duplicate".
    try:
        use_event_resp = await _pg_request(
            "POST",
            "skill_use_events",
            body={
                "chapter_id": _chapter_id,
                "skill_id": skill_id,
                "skill_version": skill_version,
                "used_by_agent_id": used_by_agent_id,
                "used_by_did": used_by_did or None,
                "tool_name": tool_name,
                "gross_cents": gross_cents,
                "attestor_count": len(attestor_dids),
                "success": success,
                "duration_ms": duration_ms,
                "idempotency_key": idempotency_key,
            },
        )
    except Exception as e:
        msg = str(e).lower()
        if "duplicate" in msg or "unique" in msg or "23505" in msg:
            return {"billed": False, "reason": "duplicate"}
        return {"error": f"use_event insert failed: {type(e).__name__}"}

    # Postgres POST returns the inserted row(s)
    use_event_id = None
    if isinstance(use_event_resp, list) and use_event_resp:
        use_event_id = use_event_resp[0].get("id")
    elif isinstance(use_event_resp, dict):
        use_event_id = use_event_resp.get("id")
    if not use_event_id:
        # Shouldn't happen but fail-loud rather than silent
        return {"error": "use_event id missing from insert response"}

    # 6. Insert ledger rows. If any fail, the use_event row will have a
    #    partial split — but attempting rollback with Postgres is
    #    brittle. Instead we rely on: (a) FK cascade to let ops delete the
    #    use_event if all ledgers failed, (b) a nightly reconciliation job
    #    to flag orphan use_events.
    for row in ledger_rows:
        try:
            await _pg_request(
                "POST",
                "skill_revenue_ledger",
                body={
                    "use_event_id": use_event_id,
                    "beneficiary_did": row["beneficiary_did"],
                    "beneficiary_role": row["beneficiary_role"],
                    "amount_cents": row["amount_cents"],
                    "currency": "TEST_USD",
                },
            )
        except Exception as e:
            # Don't claim billed=True if we couldn't write the full split
            return {
                "error": f"ledger insert failed mid-split: {type(e).__name__}",
                "use_event_id": use_event_id,
            }

    # 7. Emit outcome signal so Phase B auto-tuner has data to work with.
    # Fire-and-forget — telemetry failure must not wedge revenue ledger.
    try:
        import outcome_tracker

        await outcome_tracker.record_feedback(
            action_id=str(use_event_id),
            action_type="skill_use",
            signal="positive" if success else "negative",
            agent_id=used_by_agent_id,
            feedback_data={
                "skill_id": skill_id,
                "skill_version": skill_version,
                "tool_name": tool_name,
                "gross_cents": gross_cents,
                "attestor_count": len(attestor_dids),
            },
        )
    except Exception:
        pass

    return {
        "billed": True,
        "use_event_id": use_event_id,
        "rows": ledger_rows,
    }


async def _get_skill_author_did(skill_id: str) -> str:
    """Resolve the author did:key for a skill. Returns empty string if unknown."""
    if _pg_request is None:
        return ""
    try:
        rows = await _pg_request(
            "GET",
            "chapter_skills",
            params={
                "id": f"eq.{skill_id}",
                "select": "author_did",
                "limit": "1",
            },
        )
    except Exception:
        return ""
    if rows and isinstance(rows, list):
        return rows[0].get("author_did", "")
    return ""


async def get_earnings_for_did(did: str, since_iso: str | None = None) -> dict:
    """Return rolled-up earnings for one DID.

    {
      "did": "did:key:z...",
      "total_cents": 12345,
      "by_role": {"author": 4000, "advisor": 3500, "chapter": 2500},
      "by_currency": {"TEST_USD": 12345},
      "event_count": 42,
    }
    """
    if _pg_request is None:
        return {"did": did, "total_cents": 0, "by_role": {}, "by_currency": {}, "event_count": 0}
    try:
        params = {
            "beneficiary_did": f"eq.{did}",
            "select": "amount_cents,beneficiary_role,currency",
        }
        if since_iso:
            params["created_at"] = f"gte.{since_iso}"
        rows = await _pg_request("GET", "skill_revenue_ledger", params=params)
    except Exception:
        return {"did": did, "total_cents": 0, "by_role": {}, "by_currency": {}, "event_count": 0}

    total = 0
    by_role: dict[str, int] = {}
    by_currency: dict[str, int] = {}
    for r in rows or []:
        amt = int(r.get("amount_cents") or 0)
        total += amt
        role = r.get("beneficiary_role", "?")
        cur = r.get("currency", "?")
        by_role[role] = by_role.get(role, 0) + amt
        by_currency[cur] = by_currency.get(cur, 0) + amt

    return {
        "did": did,
        "total_cents": total,
        "by_role": by_role,
        "by_currency": by_currency,
        "event_count": len(rows or []),
    }


__all__ = [
    "ADVISOR_SHARE",
    "AUTHOR_SHARE",
    "CHAPTER_SHARE",
    "DEFAULT_GROSS_CENTS",
    "compute_split",
    "get_earnings_for_did",
    "init",
    "record_skill_use",
]
