"""Observation helper — wires planner/executor decisions into HabitModel.

Thin façade that the think loop calls each time a user's decision
on a proposed action lands. Keeps the habit model's public API
stable even as the think loop evolves.
"""

from __future__ import annotations

from datetime import UTC, datetime

from community_member.habits.context import ContextFingerprint
from community_member.habits.model import HabitModel, UserDecision

__all__ = ["observe_decision"]


def observe_decision(
    model: HabitModel,
    *,
    capability: str,
    scope: str,
    context: ContextFingerprint,
    decision: UserDecision,
    now: datetime | None = None,
) -> None:
    """Record one user decision in the habit model.

    `context` is the fingerprint from habits.context.fingerprint_context.
    `decision` is \"approved\" or \"denied\" — whatever the user clicked
    in the tray UI.

    This function is a write-through — it calls HabitModel.observe
    with canonical timestamp formatting. Separated from the model so
    higher layers can mock a HabitModel and skip SQLite I/O in tests.
    """
    now = now or datetime.now(UTC)
    model.observe(
        capability=capability,
        scope=scope,
        context_sha256=context.sha256,
        decision=decision,
        recorded_at=now.isoformat(),
    )
