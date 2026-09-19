"""Trust events ledger — automated, anti-game-theoretic trust accrual.

Every observable activity that should move trust generates ONE row in
the `trust_events` table. The Postgres trigger keeps `agents.trust_score`
in sync with `SUM(delta)` — the score is replay-deterministic.

Plan: PR-A of the trust-events series. PR-B adds `endorsement_received`
endpoint, PR-C adds inactivity decay + outcome wiring, PR-D ships history
surface, PR-E ties into the policy auto-tuner.

Design rules (load-bearing):

  * Server-set delta only. Clients call `record(event_type=...)`; the
    delta is read from `EVENT_DELTAS` and never trusted from input.
    Closes the "attacker fakes a +50 endorsement" path.
  * UNIQUE(agent_id, event_type, source_event_id) at the DB layer.
    `record()` returns False if the row already exists. Replay-safe.
  * `source_agent_id != agent_id` — DB constraint AND service-side check.
    No self-promotion path.
  * Per-window caps (day/week/month). Excess deltas land as `delta=0,
    reason="capped:{window}"` so the audit shows the cap fired.
    Closes the burner-account farming path.
  * Anti-bootstrap: endorsement events (PR-B) require endorser
    trust_score >= MIN_ENDORSER_TRUST.

R1-R10 coverage in tests/test_trust_accrual.py.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Literal

EventType = Literal[
    "intent_match_accepted",
    "intent_response_useful",
    "call_response_accepted",
    "conversation_completed_positive",
    "skill_attested_by_trusted",
    "endorsement_received",
    "tenure_milestone_30d",
    "tenure_milestone_90d",
    "tenure_milestone_180d",
    "tenure_milestone_365d",
    "revocation_received",
    "complaint_validated",
    "inactive_decay",
]

# ── Server-set deltas. Clients NEVER set these. ──────────────────────
# Adding a new event_type requires:
#   1. A row here (the only authority)
#   2. An adapter in the calling site (intents.py / calls.py / etc.)
#   3. A test in tests/test_trust_accrual.py exercising it
EVENT_DELTAS: dict[str, Decimal] = {
    "intent_match_accepted": Decimal("0.5"),
    "intent_response_useful": Decimal("1.0"),
    "call_response_accepted": Decimal("0.5"),
    "conversation_completed_positive": Decimal("1.0"),
    "skill_attested_by_trusted": Decimal("2.0"),
    "endorsement_received": Decimal("0.5"),
    "tenure_milestone_30d": Decimal("1.0"),
    "tenure_milestone_90d": Decimal("2.0"),
    "tenure_milestone_180d": Decimal("5.0"),
    "tenure_milestone_365d": Decimal("10.0"),
    "revocation_received": Decimal("-1.0"),
    "complaint_validated": Decimal("-3.0"),
    "inactive_decay": Decimal("-1.0"),
}

# ── Rolling-window caps. Per-agent. Excess → delta=0, reason=capped. ──
DAILY_CAP = Decimal("2.0")
WEEKLY_CAP = Decimal("8.0")
MONTHLY_CAP = Decimal("20.0")

# ── Endorsement bootstrap floor (PR-B uses this). ────────────────────
MIN_ENDORSER_TRUST = Decimal("20.0")

# ── Trust-tier thresholds (consumed by the trust dossier surfaces). ──
# Each entry is the minimum trust score required to reach that tier.
TRUST_TIERS: list[float] = [0.0, 20.0, 50.0, 75.0]


def tier_for(trust_score: float) -> dict:
    """Return the highest tier an agent qualifies for given their trust score.

    The returned dict carries ``min_trust`` only; UI consumers map that to a
    human label (Newcomer / Established / Trusted / Leader).
    """
    score = max(0.0, float(trust_score or 0.0))
    selected = TRUST_TIERS[0]
    for min_trust in TRUST_TIERS:
        if score >= min_trust:
            selected = min_trust
    return {"min_trust": selected}

# ── DI (mirrors attestations.py / skill_revenue.py pattern). ─────────
_pg_request: Callable[..., Awaitable[Any]] | None = None
_chapter_id: str = ""


def init(pg_request, chapter_id: str) -> None:
    """DI — chapter_agent.py calls this on startup."""
    global _pg_request, _chapter_id
    _pg_request = pg_request
    _chapter_id = chapter_id


# ── Helpers (pure, testable in isolation) ────────────────────────────


def _delta_for(event_type: str) -> Decimal:
    """Return the canonical UNSCALED delta for an event_type. Raises on
    unknown. Use `_scaled_delta_for()` from `record()` to apply the
    chapter-policy scale factor (PR-E)."""
    if event_type not in EVENT_DELTAS:
        raise ValueError(f"unknown event_type: {event_type!r}")
    return EVENT_DELTAS[event_type]


async def _scaled_delta_for(event_type: str) -> Decimal:
    """Apply `trust.delta_scale` from chapter_policy if present.

    The auto-tuner (PR-E) writes this key to scale up accrual when too
    many newcomers stall under the federate threshold. Defaults to 1.0
    when the key is missing or policy is unavailable. Bounded
    [0.5, 2.0] by the auto-tuner; never leaks unbounded.
    """
    base = _delta_for(event_type)
    try:
        import policy

        scale_f = await policy.get_float("trust.delta_scale", 1.0)
    except Exception:
        scale_f = 1.0
    # Defense in depth — even if a malicious row sneaks past the auto-
    # tuner clamp, this floor/ceiling rejects pathological values.
    scale_f = max(0.5, min(2.0, float(scale_f)))
    return base * Decimal(str(scale_f))


def _window_starts(now: datetime | None = None) -> tuple[str, str, str]:
    """Return (day, week, month) ISO timestamps for window-cap queries."""
    now = now or datetime.now(UTC)
    day = (now - timedelta(days=1)).isoformat()
    week = (now - timedelta(days=7)).isoformat()
    month = (now - timedelta(days=30)).isoformat()
    return day, week, month


def _cap_remaining(spent: Decimal, cap: Decimal) -> Decimal:
    """Remaining headroom in a cap window. Floors at 0."""
    return max(Decimal("0"), cap - spent)


def apply_caps(
    proposed_delta: Decimal,
    *,
    spent_day: Decimal,
    spent_week: Decimal,
    spent_month: Decimal,
) -> tuple[Decimal, str | None]:
    """Pure cap arithmetic — exposed for unit tests + reuse.

    Returns (effective_delta, capped_reason | None). A negative
    proposed_delta passes through unchanged: caps only constrain
    positive accrual, not penalties.
    """
    if proposed_delta <= 0:
        return proposed_delta, None
    rem_day = _cap_remaining(spent_day, DAILY_CAP)
    rem_week = _cap_remaining(spent_week, WEEKLY_CAP)
    rem_month = _cap_remaining(spent_month, MONTHLY_CAP)
    cap = min(rem_day, rem_week, rem_month)
    if proposed_delta <= cap:
        return proposed_delta, None
    if cap == rem_day and rem_day < rem_week and rem_day < rem_month:
        which = "day"
    elif cap == rem_week and rem_week < rem_month:
        which = "week"
    else:
        which = "month"
    return cap, f"capped:{which}"


# ── Service ──────────────────────────────────────────────────────────


async def record(
    *,
    agent_id: str,
    event_type: str,
    source_event_id: str | None = None,
    source_agent_id: str | None = None,
    reason: str | None = None,
) -> dict | None:
    """Record one trust event. Returns the inserted row dict or None.

    Returns None when:
      * (agent_id, event_type, source_event_id) is a duplicate (idempotent)
      * proposed delta is positive but caps are fully spent — a row
        with delta=0 lands so the cap-fire is auditable, but None
        is returned to the caller so it knows nothing accrued

    Raises:
      * ValueError on unknown event_type, missing agent_id, or
        source_agent_id == agent_id (defense in depth — DB also
        rejects via CHECK constraint)
    """
    if not agent_id:
        raise ValueError("agent_id required")
    if source_agent_id is not None and source_agent_id == agent_id:
        raise ValueError("source_agent_id must differ from agent_id (no self-promotion)")
    proposed_delta = await _scaled_delta_for(event_type)

    if _pg_request is None:
        raise RuntimeError("trust_events.init(...) must be called first")

    # Idempotency check first — a duplicate write would be silently
    # rejected by the DB UNIQUE constraint, but checking here lets
    # us return None without a noisy 409.
    if source_event_id is not None:
        existing = await _pg_request(
            "GET",
            "trust_events",
            params={
                "agent_id": f"eq.{agent_id}",
                "event_type": f"eq.{event_type}",
                "source_event_id": f"eq.{source_event_id}",
                "select": "id",
                "limit": 1,
            },
        )
        if existing:
            return None

    # Cap check — only on positive deltas.
    effective_delta = proposed_delta
    capped_reason: str | None = None
    if proposed_delta > 0:
        day_iso, week_iso, month_iso = _window_starts()
        rows = (
            await _pg_request(
                "GET",
                "trust_events",
                params={
                    "agent_id": f"eq.{agent_id}",
                    "occurred_at": f"gte.{month_iso}",
                    "select": "delta,occurred_at",
                },
            )
            or []
        )
        spent_day = Decimal("0")
        spent_week = Decimal("0")
        spent_month = Decimal("0")
        for r in rows:
            d = Decimal(str(r.get("delta") or "0"))
            if d <= 0:
                continue
            ts = r.get("occurred_at", "")
            if ts >= day_iso:
                spent_day += d
            if ts >= week_iso:
                spent_week += d
            spent_month += d
        effective_delta, capped_reason = apply_caps(
            proposed_delta,
            spent_day=spent_day,
            spent_week=spent_week,
            spent_month=spent_month,
        )

    final_reason = capped_reason or reason
    insert = {
        "agent_id": agent_id,
        "event_type": event_type,
        "source_agent_id": source_agent_id,
        "source_event_id": source_event_id,
        "delta": str(effective_delta),
        "reason": final_reason,
    }
    inserted = await _pg_request("POST", "trust_events", body=insert)
    row = inserted[0] if isinstance(inserted, list) and inserted else inserted
    if effective_delta == 0:
        return None
    return row


async def list_history(agent_id: str, *, limit: int = 20) -> list[dict]:
    """Return the agent's trust_event rows in reverse chronological
    order. Used by the trust-history surface (PR-D)."""
    if _pg_request is None:
        raise RuntimeError("trust_events.init(...) must be called first")
    rows = (
        await _pg_request(
            "GET",
            "trust_events",
            params={
                "agent_id": f"eq.{agent_id}",
                "select": "event_type,delta,source_agent_id,source_event_id,reason,occurred_at",
                "order": "occurred_at.desc",
                "limit": max(1, min(200, int(limit))),
            },
        )
        or []
    )
    return rows


async def projection_30d(agent_id: str, *, now: datetime | None = None) -> dict:
    """Linear projection of next-30-day score change based on the
    last 30 days of activity. Returns {recent_30d_delta, projected_30d}.

    This is a UI estimate — not a guarantee. Real future activity
    can vary widely; the projection is only meaningful with at least
    a week of history.
    """
    if _pg_request is None:
        raise RuntimeError("trust_events.init(...) must be called first")
    now = now or datetime.now(UTC)
    cutoff = (now - timedelta(days=30)).isoformat()
    rows = (
        await _pg_request(
            "GET",
            "trust_events",
            params={
                "agent_id": f"eq.{agent_id}",
                "occurred_at": f"gte.{cutoff}",
                "select": "delta",
            },
        )
        or []
    )
    recent = sum(Decimal(str(r.get("delta") or "0")) for r in rows)
    return {
        "recent_30d_delta": str(recent),
        "projected_30d": str(recent),  # naive linear: same rate forward
    }


async def replay_score(agent_id: str) -> Decimal:
    """Sum SUM(delta) for an agent. Used by the daily drift-check job
    and by the test suite (R10 — replay determinism).
    """
    if _pg_request is None:
        raise RuntimeError("trust_events.init(...) must be called first")
    rows = (
        await _pg_request(
            "GET",
            "trust_events",
            params={
                "agent_id": f"eq.{agent_id}",
                "select": "delta",
            },
        )
        or []
    )
    total = Decimal("0")
    for r in rows:
        total += Decimal(str(r.get("delta") or "0"))
    return total


# ── Tenure milestones (PR-A includes the daily-job entrypoint) ───────


_TENURE_TABLE: tuple[tuple[int, str], ...] = (
    (30, "tenure_milestone_30d"),
    (90, "tenure_milestone_90d"),
    (180, "tenure_milestone_180d"),
    (365, "tenure_milestone_365d"),
)


def tenure_milestones_due(
    *,
    created_at_iso: str,
    now: datetime | None = None,
) -> list[str]:
    """Pure helper — returns the event_types whose tenure thresholds
    have been crossed. Idempotency at the DB UNIQUE level ensures
    each fires exactly once even if this returns the same list across
    successive runs.
    """
    now = now or datetime.now(UTC)
    try:
        created = datetime.fromisoformat(created_at_iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return []
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    days = (now - created).days
    return [evt for threshold, evt in _TENURE_TABLE if days >= threshold]


# ── Inactivity decay ─────────────────────────────────────────────────


# Days of zero activity before decay starts firing.
INACTIVITY_DECAY_AFTER_DAYS = 60
# How often (in days) a new decay row gets emitted while still inactive.
INACTIVITY_DECAY_CADENCE_DAYS = 7
# Floor below which decay no longer fires.
INACTIVITY_DECAY_FLOOR = Decimal("0")


async def apply_inactivity_decay_for_agent(
    *,
    agent_id: str,
    now: datetime | None = None,
) -> bool:
    """If an agent has had no qualifying trust event for >60 days AND
    no decay row in the last 7 days AND their score is above the floor,
    write a `inactive_decay (-1.0)` row.

    Returns True iff a decay row was emitted. Idempotent at the
    UNIQUE constraint level — `source_event_id` is the ISO week
    string, so two calls in the same week emit only one decay row.
    """
    if _pg_request is None:
        raise RuntimeError("trust_events.init(...) must be called first")
    now = now or datetime.now(UTC)

    # Floor check: don't decay an already-zero score below zero. We
    # use the trigger-maintained agents.trust_score for the gate; the
    # drift detector catches discrepancies separately.
    rows = (
        await _pg_request(
            "GET",
            "agents",
            params={"agent_id": f"eq.{agent_id}", "select": "trust_score", "limit": 1},
        )
        or []
    )
    if not rows:
        return False
    score = Decimal(str(rows[0].get("trust_score") or 0))
    if score <= INACTIVITY_DECAY_FLOOR:
        return False

    # Activity window: any trust_event in the last 60 days disqualifies decay.
    activity_cutoff = (now - timedelta(days=INACTIVITY_DECAY_AFTER_DAYS)).isoformat()
    recent_activity = (
        await _pg_request(
            "GET",
            "trust_events",
            params={
                "agent_id": f"eq.{agent_id}",
                "occurred_at": f"gte.{activity_cutoff}",
                "event_type": "neq.inactive_decay",
                "select": "id",
                "limit": 1,
            },
        )
        or []
    )
    if recent_activity:
        return False

    # Idempotency: ISO year-week as source_event_id means one decay
    # per agent per week even if the cron runs multiple times.
    iso_year, iso_week, _ = now.isocalendar()
    source_event_id = f"decay:{iso_year}-W{iso_week:02d}"
    result = await record(
        agent_id=agent_id,
        event_type="inactive_decay",
        source_event_id=source_event_id,
        reason=f"no qualifying activity in {INACTIVITY_DECAY_AFTER_DAYS}+ days",
    )
    return result is not None


# ── Drift detector ───────────────────────────────────────────────────


async def _replayed_scores_all() -> dict[str, Decimal]:
    """``{agent_id: SUM(delta)}`` over the WHOLE ledger in one aggregate.

    Fast path: the ``replay_scores_all`` Postgres RPC (server-side ``GROUP BY``,
    one round-trip). If that RPC is unavailable (e.g. the migration has not been
    applied to this chapter's DB yet), fall back to a keyset-paginated sum over
    the append-only ledger by its ``id`` PK — so pagination can neither skip nor
    double-count — but NEVER to the per-agent N+1 the old detector used.

    Both paths RAISE on a partial read. ``_pg_request`` returns ``None`` on
    a backend failure (distinct from ``[]`` for a genuinely empty result); a
    partial replay would falsely flag every agent as drifted, so we fail loud
    rather than return an incomplete map.
    """
    if _pg_request is None:
        raise RuntimeError("trust_events.init(...) must be called first")

    rows = await _pg_request("POST", "rpc/replay_scores_all", body={})
    if rows is not None:
        return {
            str(r["agent_id"]): Decimal(str(r.get("replayed") or 0))
            for r in rows
            if isinstance(r, dict) and r.get("agent_id") is not None
        }

    # Fallback — keyset over the PK so each row is summed exactly once. Continue
    # until an EMPTY page: we MUST NOT stop on ``len(page) < page_size`` because
    # PostgREST caps rows-per-response (often 1000) below any larger limit we
    # request — stopping early there would silently skip events and mis-sum the
    # ledger. ``id > last_id`` guarantees forward progress and termination on the
    # empty page; the hard iteration bound is a runaway-loop backstop.
    replayed: dict[str, Decimal] = {}
    last_id = 0
    page_size = 1000
    for _ in range(1_000_000):
        page = await _pg_request(
            "GET",
            "trust_events",
            params={"select": "id,agent_id,delta", "id": f"gt.{last_id}", "order": "id.asc", "limit": page_size},
        )
        if page is None:
            raise RuntimeError("trust_events read failed; refusing to compute drift from a partial ledger")
        if not page:
            return replayed
        for r in page:
            aid = r.get("agent_id")
            if aid is not None:
                replayed[str(aid)] = replayed.get(str(aid), Decimal("0")) + Decimal(str(r.get("delta") or 0))
            rid = r.get("id")
            if rid is not None:
                last_id = max(last_id, int(rid))
    raise RuntimeError("trust_events pagination exceeded its safety bound")


async def detect_score_drift(*, tolerance: Decimal = Decimal("0.001")) -> list[dict]:
    """Walk every agent and compare trigger-maintained `agents.trust_score`
    against the SUM(delta) replay over `trust_events`.

    Manual UPDATEs to agents.trust_score (governance overrides) bypass
    the trigger and create drift. This detector is what keeps the
    ledger honest — run daily; alert on any non-empty result.

    The replay is computed for ALL agents in a single aggregate (see
    :func:`_replayed_scores_all`) rather than one query per agent — the old
    per-agent loop was an N+1 that timed out on real chapters. A backend failure
    RAISES rather than returning a partial map, so a failed read can never be
    mistaken for "every agent drifted".

    Returns a list of {agent_id, stored, replayed, drift} for any agent
    whose two values differ by more than `tolerance`.
    """
    if _pg_request is None:
        raise RuntimeError("trust_events.init(...) must be called first")
    agents = await _pg_request("GET", "agents", params={"select": "agent_id,trust_score", "limit": 5000})
    if agents is None:
        raise RuntimeError("could not read agents; refusing to compute drift from a partial read")

    replayed = await _replayed_scores_all()
    drifts: list[dict] = []
    for a in agents:
        aid = a.get("agent_id")
        if not aid:
            continue
        stored = Decimal(str(a.get("trust_score") or 0))
        rep = replayed.get(str(aid), Decimal("0"))  # an agent with no events replays to 0
        diff = abs(stored - rep)
        if diff > tolerance:
            drifts.append(
                {
                    "agent_id": aid,
                    "stored": str(stored),
                    "replayed": str(rep),
                    "drift": str(diff),
                }
            )
    return drifts


# ── Tenure milestones ────────────────────────────────────────────────


async def fire_tenure_milestones_for_agent(
    *,
    agent_id: str,
    created_at_iso: str,
    now: datetime | None = None,
) -> int:
    """Idempotent — fires every threshold the agent has crossed.
    Earlier runs that already fired a threshold get rejected by the
    UNIQUE(agent_id, event_type, source_event_id) constraint (the
    `source_event_id` is the threshold name itself, e.g. "30d", so
    the second run of this fn finds the row and returns None from
    `record()`).
    """
    fired = 0
    for evt in tenure_milestones_due(created_at_iso=created_at_iso, now=now):
        # source_event_id is the milestone name itself — this is what
        # makes the UNIQUE constraint fire on re-run.
        threshold = evt.replace("tenure_milestone_", "")
        result = await record(
            agent_id=agent_id,
            event_type=evt,
            source_event_id=f"tenure:{threshold}",
            reason=f"tenure milestone — {threshold}",
        )
        if result is not None:
            fired += 1
    return fired
