"""Context fingerprint — deterministic hash of host-local signals.

Used by the habit engine to group observations: two action proposals
that happen in the \"same situation\" end up with the same
fingerprint, and the Bayesian posterior tracks P(approve|fingerprint).

Design rules (from plans/…/humble-hopcroft.md §Phase W3):

  * Host-local signals only. The user must not be able to spoof the
    fingerprint by crafting input to the agent — everything that
    feeds the fingerprint is read from the environment or from the
    agent's own audit ledger.
  * Prior-action hash included so \"I'm halfway through reorganizing
    my Downloads folder\" is a different context than \"I just woke
    up and opened Gmail.\" Sequence-of-3-actions hash rather than
    single-last-action so momentary noise doesn't shift fingerprints
    every click.
  * Hour + weekday rather than raw timestamp so reading arxiv at
    2 AM Saturday is the same context whether it's this week or
    next, but different from 9 AM Monday.

The fingerprint is a sha256 hex digest of a canonical JSON blob —
byte-for-byte identical on the same inputs. Tests pin this.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime

__all__ = ["ActionHistoryRef", "ContextFingerprint", "fingerprint_context"]


@dataclass(frozen=True)
class ActionHistoryRef:
    """Reference to one prior action — capability + scope, nothing else.

    Intentionally narrow: we don't stash arbitrary metadata here
    because the fingerprint would then drift on irrelevant changes.
    Capability + scope is the identity of what the agent did.
    """

    capability: str
    scope: str


@dataclass(frozen=True)
class ContextFingerprint:
    """Computed fingerprint + the inputs that produced it.

    `sha256` is the opaque identifier habit storage uses. `inputs`
    is the raw dict fed to the hasher; exposed so the UI (and
    audits) can explain what \"context\" means in human terms.
    """

    sha256: str
    inputs: dict[str, object] = field(default_factory=dict)


def fingerprint_context(
    *,
    now: datetime | None = None,
    focused_app: str | None = None,
    prior_actions: list[ActionHistoryRef] | None = None,
) -> ContextFingerprint:
    """Compute the host-local fingerprint for the current moment.

    Parameters
    ----------
    now
        Timestamp override for tests. Default: datetime.now(UTC).
    focused_app
        Name of the foreground application (e.g. \"Slack\", \"Chrome\").
        If None, read from the OS via an attempt at common envs, or
        falls back to literal \"unknown\". Tests pass this explicitly.
    prior_actions
        Up to 3 most recent ActionHistoryRef values. Older entries
        beyond 3 are truncated so the fingerprint doesn't grow
        unboundedly sensitive with history depth.
    """
    now = now or datetime.now(UTC)
    focused = focused_app if focused_app is not None else _guess_focused_app()
    # Keep the MOST RECENT 3 — callers pass priors in chronological
    # order (oldest first). Truncating from the left drops old noise
    # and preserves the recent-activity signal.
    priors = list(prior_actions or [])[-3:]

    # Hash the prior-actions chain — stable across sessions if the
    # same actions happened. sha256 of their canonical JSON, so any
    # field drift produces a new fingerprint.
    prior_chain = "|".join(f"{a.capability}:{a.scope}" for a in priors)
    prior_sha = hashlib.sha256(prior_chain.encode("utf-8")).hexdigest()

    inputs: dict[str, object] = {
        "hour_of_day": now.hour,
        "day_of_week": now.weekday(),  # 0=Mon
        "focused_app": focused,
        "prior_actions_sha256": prior_sha,
    }
    canonical = json.dumps(inputs, sort_keys=True, separators=(",", ":"))
    fp = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return ContextFingerprint(sha256=fp, inputs=inputs)


def _guess_focused_app() -> str:
    """Read the foreground app name. Best-effort; returns 'unknown'
    on failure.

    W3 does not wire a real OS-level focused-app detector — that
    needs AppKit / UIAutomation / xdotool on the three platforms and
    lands in a later W3 PR. For now we check environment variables
    some terminals set (WINDOWID, TERM_PROGRAM), then fall back.

    Anyone passing focused_app= explicitly (the tray UI once it's
    wired) bypasses this entirely.
    """
    for env_key in ("TERM_PROGRAM", "DESKTOP_SESSION", "XDG_SESSION_DESKTOP"):
        val = os.environ.get(env_key)
        if val:
            return val
    return "unknown"
