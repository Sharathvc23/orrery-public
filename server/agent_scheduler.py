"""Durable per-agent scheduling — survives restart, spreads load, cannot spin.

WHAT WAS ACTUALLY MISSING. A spike ran four unattended agents on
``COMMUNITY_MEMBER_THINK_INTERVAL=5`` and they worked, so the scheduler was
never the blocker and this module deliberately adds no capability. What the
crude timer lacks is everything that is not "does it fire":

  DURABILITY   ``asyncio.sleep(interval)`` holds the next run time in a local
               variable. A restart loses it, so every agent's cadence silently
               resets to "now" — which is also how a restart turns into a
               stampede (below). Here ``next_run_at`` is a row, so a restart
               resumes the schedule instead of re-deciding it.
  SPREAD       N agents started by one `docker compose up` share a start
               instant, so a fixed interval keeps them phase-locked forever:
               they were born together and they stay together, hitting the LLM
               provider and the database in a burst every cycle. Jitter breaks
               the phase lock permanently rather than just delaying the first
               collision.
  NON-SPINNING It must be structurally incapable of becoming the loop PR3 just
               fixed — a permanent error retried at full rate, 14 failures in
               ~60s, ~17k/day/agent.

HOW THE SPIN IS PREVENTED, and it is two things, not one. Backoff alone is
insufficient: a permanent 4xx retried every ten minutes is still an infinite
loop, just a politer one that still bills forever. So a TERMINAL failure does
not get a longer delay — it stops the agent and records why, which is the only
honest response to "this cannot succeed until a human changes something". Only
RETRYABLE failures back off.

That classification is NOT re-derived here. ``retry_policy`` is vendored
verbatim from ``agent/community_member/retry_policy.py`` at dev's explicit
instruction ("import or copy this file whole; do not re-derive the table"),
because two subtly different opinions about whether a 402 is worth retrying is
exactly the drift that produces one of these bugs again.
``test_retry_policy_vendoring.py`` asserts the two files are byte-identical, so
the copy cannot rot silently.

The pure decision functions take ``now`` and ``rand`` as arguments and touch no
clock, no database and no event loop, so the scheduling behaviour is testable
without waiting for real seconds.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import retry_policy

# The cadence floor. An operator (or a typo) setting the interval to 0 would
# otherwise produce a genuine busy loop — not the retry-a-terminal-error kind
# PR3 fixed, but a tighter one that never yields.
#
# 5s, not 300. A floor high enough to be "safe" would silently override a
# deliberately fast cadence: infra/compose.e2e-federation.yml checks in 15, and
# a floor above that would make the federation e2e run at a pace nobody asked
# for while looking like it honoured the setting. 5s is below every interval
# this repository configures and still cannot busy-loop.
MIN_INTERVAL_S = 5.0
DEFAULT_INTERVAL_S = 300.0

#: Interval variables, in precedence order. Two names because the two sides grew
#: separately: the org path uses THINK_CYCLE_INTERVAL and the member path
#: COMMUNITY_MEMBER_THINK_INTERVAL. Both are read HERE so neither gets its own
#: parsing — the org path previously did ``int(os.environ.get(...))`` at import,
#: which turns a typo into a container that will not start.
ORG_INTERVAL_ENV = "THINK_CYCLE_INTERVAL"
MEMBER_INTERVAL_ENV = "COMMUNITY_MEMBER_THINK_INTERVAL"
INTERVAL_ENV_VARS = (ORG_INTERVAL_ENV, MEMBER_INTERVAL_ENV)

# ±15% of the interval. Enough to decorrelate a fleet that booted together;
# small enough that a 5-minute cadence is still recognisably 5 minutes.
JITTER_FRACTION = 0.15


def interval_seconds(env: dict[str, str] | None = None) -> float:
    """The configured base cadence, clamped to something that cannot spin.

    Reads :data:`INTERVAL_ENV_VARS` in order, so both sides get one parser.

    Unparseable and out-of-range values fall back to the default rather than to
    zero: a scheduler that reads ``THINK_INTERVAL=abc`` and decides to run
    continuously has turned a typo into a billing incident. It FALLS BACK AND
    SAYS SO — the org path used to parse this with a bare ``int()`` at import,
    where the same typo is an unstartable container and the traceback names
    neither the variable nor the value.
    """
    # Fetched name-by-name against ``os.environ`` rather than through the tuple:
    # the environment-flag scanner resolves ``os.environ.get(CONST)`` and cannot
    # follow a name reached through a loop variable. A variable invisible to
    # that scanner is one whose removal nobody notices, so the read stays
    # visible and only the PARSING below is shared.
    if env is None:
        env = {
            ORG_INTERVAL_ENV: os.environ.get(ORG_INTERVAL_ENV, ""),
            MEMBER_INTERVAL_ENV: os.environ.get(MEMBER_INTERVAL_ENV, ""),
        }
    source = env
    for name in INTERVAL_ENV_VARS:
        raw = (source.get(name) or "").strip()
        if not raw:
            continue
        try:
            value = float(raw)
        except (TypeError, ValueError):
            print(f"[scheduler] {name}={raw!r} is not a number — using {DEFAULT_INTERVAL_S:.0f}s")
            return DEFAULT_INTERVAL_S
        if value <= 0:
            print(f"[scheduler] {name}={raw!r} is not positive — using {DEFAULT_INTERVAL_S:.0f}s")
            return DEFAULT_INTERVAL_S
        if value < MIN_INTERVAL_S:
            print(f"[scheduler] {name}={raw!r} is below the {MIN_INTERVAL_S:.0f}s floor — using the floor")
        return max(MIN_INTERVAL_S, value)
    return DEFAULT_INTERVAL_S


def jittered(interval_s: float, *, rand: float) -> float:
    """``interval_s`` spread by ±JITTER_FRACTION. ``rand`` is a 0..1 draw.

    Applied on EVERY scheduling decision, not only the first. Jittering once at
    startup delays the collision instead of removing it: the agents re-lock to
    a fixed period the moment they resume a constant interval.
    """
    span = interval_s * JITTER_FRACTION
    offset = (max(0.0, min(1.0, rand)) * 2.0 - 1.0) * span
    return max(MIN_INTERVAL_S, interval_s + offset)


@dataclass(frozen=True)
class Decision:
    """What to do with an agent after a run. ``paused_reason`` set means the
    agent will not be scheduled again until an operator clears it."""

    next_run_at: datetime | None
    consecutive_failures: int
    paused_reason: str | None = None

    @property
    def paused(self) -> bool:
        return self.paused_reason is not None


def after_success(*, now: datetime, interval_s: float, rand: float) -> Decision:
    """Resets the failure count — backoff must not accumulate across successes,
    or a healthy agent that failed twice yesterday stays slow forever."""
    return Decision(next_run_at=now + timedelta(seconds=jittered(interval_s, rand=rand)), consecutive_failures=0)


def after_failure(exc: BaseException, *, now: datetime, consecutive_failures: int, rand: float) -> Decision:
    """Back off a retryable failure; STOP a terminal one.

    A terminal error returns ``next_run_at=None`` and a reason. It is not
    scheduled at a longer delay, because no delay makes a revoked API key valid
    — retrying it is not patience, it is the bug PR3 removed from the LLM path,
    and putting it back in the scheduler would reintroduce it one layer up.
    """
    verdict = retry_policy.classify(exc)
    if verdict is retry_policy.Decision.TERMINAL:
        return Decision(
            next_run_at=None,
            consecutive_failures=consecutive_failures + 1,
            paused_reason=retry_policy.describe(exc, verdict),
        )
    failures = consecutive_failures + 1
    # Jitter the backoff too: a provider outage fails every agent at once, and
    # an unjittered shared curve marches the whole fleet back in lockstep.
    delay = jittered(float(retry_policy.backoff_seconds(failures)), rand=rand)
    return Decision(next_run_at=now + timedelta(seconds=delay), consecutive_failures=failures)


# ═══════════════════════════════════════════════════════════════
# Durable store — the part that survives a restart
# ═══════════════════════════════════════════════════════════════

_pg_request = None


def init(pg_request) -> None:
    global _pg_request
    _pg_request = pg_request


async def due_agents(*, now: datetime | None = None, limit: int = 50) -> list[dict]:
    """Agents whose ``next_run_at`` has passed and which are not paused.

    ``next_run_at`` is NOT NULL with a ``now()`` default, so a freshly-inserted
    row is immediately due and there is no NULL case to order around. That
    matters concretely: this layer's ``_order`` accepts ``col.asc``/``col.desc``
    and silently drops a ``nullsfirst`` suffix, and Postgres sorts NULLs LAST
    under ASC — so a nullable column would have put never-run agents at the
    back of the queue while the code read as if they were at the front.

    Returns [] on any store error. The caller's loop must keep running: a
    scheduler that raises out of its own tick stops scheduling everything,
    which is a worse failure than skipping one tick.
    """
    if _pg_request is None:
        return []
    stamp = (now or datetime.now(UTC)).isoformat().replace("+00:00", "Z")
    try:
        rows = await _pg_request(
            "GET",
            "agent_schedule",
            params={
                "paused_reason": "is.null",
                "next_run_at": f"lte.{stamp}",
                "order": "next_run_at.asc",
                "limit": str(limit),
            },
        )
        return rows or []
    except Exception as exc:
        print(f"[scheduler] due_agents read failed, skipping this tick: {exc}")
        return []


async def record(agent_id: str, decision: Decision) -> bool:
    """Persist a Decision. Returns True if the write landed.

    The return value is not decoration: if this fails the agent's schedule is
    unchanged, so the caller must not report the run as scheduled. An agent
    whose failure was never recorded is one that retries at full rate on the
    next tick — the spin, arriving through the back door.

    ``pg_request`` SWALLOWS a configured-database failure and returns ``None``
    rather than raising (it logs and increments a metric, but the 45 existing
    callers depend on the quiet return). So success is detected by the return
    value being non-None, not by the absence of an exception — a try/except
    here would report every failed write as a success.

    A paused decision writes ``next_run_at`` unchanged-but-irrelevant and sets
    ``paused_reason``; ``due_agents`` filters on the reason, so a paused row is
    never selected regardless of its timestamp.
    """
    if _pg_request is None:
        return False
    body = {
        "agent_id": agent_id,
        "consecutive_failures": decision.consecutive_failures,
        "paused_reason": decision.paused_reason,
        "updated_at": datetime.now(UTC).isoformat(),
    }
    if decision.next_run_at is not None:
        body["next_run_at"] = decision.next_run_at.isoformat()
    # POST upserts on the table's primary key (agent_id). This layer implements
    # no `on_conflict` param and no headers — passing either is a TypeError.
    result = await _pg_request("POST", "agent_schedule", body=body)
    if result is None:
        print(f"[scheduler] record({agent_id}) did NOT persist — schedule unchanged")
        return False
    return True


async def resume(agent_id: str, *, now: datetime | None = None) -> bool:
    """Clear a pause so a stopped agent is scheduled again.

    Deliberately explicit and operator-driven. Auto-resuming a terminal failure
    on a timer would restore precisely the behaviour this module refuses: the
    condition that stopped the agent cannot clear on its own, so anything that
    reschedules it without a human is retrying by another name.
    """
    if _pg_request is None:
        return False
    stamp = (now or datetime.now(UTC)).isoformat()
    result = await _pg_request(
        "PATCH",
        "agent_schedule",
        params={"agent_id": f"eq.{agent_id}"},
        body={"paused_reason": None, "consecutive_failures": 0, "next_run_at": stamp, "updated_at": stamp},
    )
    if result is None:
        print(f"[scheduler] resume({agent_id}) did NOT persist — agent stays paused")
        return False
    return True
