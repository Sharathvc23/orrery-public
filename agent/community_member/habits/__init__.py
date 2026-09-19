"""Habit engine — shadow-mode observation + Bayesian confidence.

Entered in W3. Everything here is purely observational in W3 itself;
graduation (auto-executing a graduated action) ships in W4 on top of
what this module stores.

Public surface:
  * context.ContextFingerprint — typed record + sha256 fingerprint
  * observer.Observer — append-only observation log in habits.db
  * model.HabitModel — per-(capability, scope, context) Beta posterior
"""

from community_member.habits.context import (
    ActionHistoryRef,
    ContextFingerprint,
    fingerprint_context,
)
from community_member.habits.model import BucketStats, HabitModel, UserDecision
from community_member.habits.observer import observe_decision

__all__ = [
    "ActionHistoryRef",
    "BucketStats",
    "ContextFingerprint",
    "HabitModel",
    "UserDecision",
    "fingerprint_context",
    "observe_decision",
]
