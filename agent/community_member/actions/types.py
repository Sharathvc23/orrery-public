"""Shared types for action executors."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from community_member.consent.gate import Provenance


@dataclass(frozen=True)
class ActionResult:
    """The output of an executed action.

    `provenance` tags the CONTENT of `data` — not the authorization
    that let the action run. Web page text is always `untrusted`
    regardless of how trustworthy the triggering request was, so that
    downstream planners cannot accidentally re-label injected content
    as trusted just because the user approved visiting the page.
    """

    capability: str
    scope: str
    outcome: Literal["ok", "fail", "denied"]
    data: object = None
    provenance: Provenance = "untrusted"
    source_ref: str | None = None
    # Executor-specific diagnostics; safe to audit but not to display.
    extra: dict[str, object] = field(default_factory=dict)
