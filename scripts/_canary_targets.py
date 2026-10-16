"""Whether an unset canary target is a clean skip or a failure.

Both live canaries (``catalog_canary``, ``receipt_verify_canary``) take their
targets from ``ORGS`` and have NO DEFAULT, deliberately: a hardcoded hostname
would print live infrastructure into a public Actions log on a six-hourly timer,
and a fork's scheduled run would probe hosts its owner does not operate. So an
unset ``ORGS`` has to be a clean skip **somewhere** — in a fork — and a failure
**here**, in the repository that actually operates the deployments, where it can
only mean the check was never wired up.

That second half was missing. The ``CANARY_ORGS`` repository variable was never
recreated when the tree was snapshotted into the public repo, so from 2026-09-19
to 2026-10-15 both canaries skipped on every six-hourly run and reported
success. Each printed "This is NOT a pass" — into a log nobody reads, while the
exit status said the opposite. The repository already holds the rule this
violates, in ``smb_host``'s front door: *an unconfigured bound must refuse or
warn by name, never serve openly.* An unconfigured canary serving a green check
is exactly that shape. The same correction was made for agent registration,
which wrote whether it had registered into a log instead of saying so where a
caller would see it — put the signal in the status, not where nobody looks.

This module is the decision, in one place, so a third canary cannot get it
subtly different. It imports **stdlib only**, on purpose: the canaries depend on
``httpx`` and ``sm_arp``, and a guard test that had to install those to check a
two-branch decision would be a test nobody runs in the one job that is meant to
stay cheap.
"""

from __future__ import annotations

import os

#: Set by the canary workflows, TRUE only in the repository that operates the
#: deployments. Bound to a ``github.repository`` comparison rather than to
#: ``github.event.repository.fork``, which is absent on ``schedule`` events —
#: and ``schedule`` is the path that produced the three weeks of false green.
REQUIRE_TARGETS_ENV = "CANARY_REQUIRE_TARGETS"

#: Accepted truthy spellings. A value this does not recognise — including the
#: literal ``false`` GitHub substitutes for a non-match — leaves the skip in
#: place, so a fork is never made to fail by a variable it did not set.
_TRUTHY = frozenset({"1", "true", "yes"})


def targets_are_required() -> bool:
    """True when an unset ``ORGS`` must fail instead of skipping."""
    return os.environ.get(REQUIRE_TARGETS_ENV, "").strip().lower() in _TRUTHY


def refusal(what_did_not_happen: str) -> str:
    """The message a canary prints when it has no targets but needs them.

    Names the variable to set rather than describing it, because the operator
    reading this has to act on it, and names what did NOT happen so the line
    cannot be skim-read as a result.
    """
    return (
        f"FAILED — {REQUIRE_TARGETS_ENV} is set, so this repository is expected "
        f"to hold canary targets, and ORGS is empty. Nothing was "
        f"{what_did_not_happen}. Set the CANARY_ORGS repository variable to a "
        f"space-separated list of org base URLs. Refusing to report green for a "
        f"check that did not run."
    )
