"""Graduation FSM — decides when an action can auto-execute.

Combines habit posterior with approval history + device binding to
transition a (capability, scope, context) triple from \"always prompt\"
to \"auto-execute with notification.\"

  observing (default) → proposing → approved → graduated

Requires:
  * ≥5 approvals in the SAME context bucket
  * posterior_mean > 0.85

Graduations are bound to a device_did (S10 defense) — copying the
graduation store to another device does NOT auto-apply because the
device_did won't match. The device must re-observe + re-approve.

Status (W4 — SHIPPED; see that change): the executor consults graduation on every
proposal and auto-approves a graduated bucket. `executor.execute_plan`
calls `auto_approve_if_graduated` (executor.py, decision step 2) and,
on a hit, returns `decision.state="approved", reason="graduated"`
without prompting — the autonomous think loop then runs the action.
The carve-out: `skill.invoke` is in the executor's `_NO_AUTO_APPROVE`
set (its real arguments live outside the match-key), so it always
prompts and never graduates. Live coverage:
tests/e2e/test_consent_ladder_e2e.py; unit coverage:
tests/graduation/test_auto_approval.py.
"""

from community_member.graduation.auto_approval import auto_approve_if_graduated
from community_member.graduation.state import (
    GraduationStatus,
    GraduationStore,
    make_graduation_key,
)

__all__ = [
    "GraduationStatus",
    "GraduationStore",
    "auto_approve_if_graduated",
    "make_graduation_key",
]
