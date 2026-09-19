"""A tool loop bounded by tokens spent, not by iterations taken.

WHY THE ITERATION COUNT IS THE WRONG BOUND. ``MAX_TOOL_LOOPS = 5`` treats five
cheap iterations and five expensive ones as the same thing, and they are not.
The measured worst case on the agent chat stream was five calls carrying 11,469
input tokens that produced ZERO assistant text — one user message, no answer,
85% of the spend being the tool list resent five times. An iteration counter
cannot see any of that: it counted to five and reported success.

A token budget bounds the thing that actually costs, and it degrades in the
right direction. A loop doing cheap work gets MORE iterations than five, which
is a capability gain; a loop doing expensive work gets fewer, which is the
runaway being caught.

HOW SPEND IS COUNTED, AND THE HONEST LIMIT OF IT. Provider-reported usage is
used when the provider reports it. Streaming responses usually do not — usage
arrives only if the caller opts into a final usage chunk, and not every
OpenAI-compatible endpoint sends one. So the fallback is an ESTIMATE from the
serialised request, and it is an estimate: roughly four characters per token,
which is close for English prose and wrong for dense JSON in the conservative
direction (it under-counts, so the budget stops slightly later than an exact
count would). It is not billing. It is a bound, and a bound derived from the
payload the caller is about to send is available on every provider, which an
exact count is not.

The estimate is deliberately applied to the WHOLE request — messages and the
tool block together — because the tool block is the majority of it. A budget
that counted only the conversation would miss 85% of what it is bounding.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "BUDGET_ENV",
    "DEFAULT_LOOP_TOKEN_BUDGET",
    "CHARS_PER_TOKEN",
    "LoopBudget",
    "estimate_tokens",
    "loop_token_budget",
]

#: Chosen against the measurement rather than by feel: the runaway this bounds
#: spent 11,469 input tokens over five calls and produced nothing. A budget
#: below that stops it; one above it would have permitted the whole run. Set
#: here so a normal two-or-three-call turn is untouched and a runaway is not.
BUDGET_ENV = "LLM_TOOL_LOOP_TOKEN_BUDGET"
DEFAULT_LOOP_TOKEN_BUDGET = 8192

#: The estimator's only constant. Four characters per token is the usual rule
#: of thumb for English; JSON runs denser, so this under-counts JSON and the
#: budget errs toward allowing one more call rather than one fewer.
CHARS_PER_TOKEN = 4


def loop_token_budget() -> int:
    """The per-turn ceiling on tokens a tool loop may spend. Default 8192.

    Zero or negative disables the budget, which restores an unbounded loop and
    is therefore something a deployment has to type on purpose. Unset, empty
    and unparseable read as the default — a typo must not remove the bound.
    """
    raw = (os.environ.get(BUDGET_ENV) or "").strip()
    if not raw:
        return DEFAULT_LOOP_TOKEN_BUDGET
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_LOOP_TOKEN_BUDGET


def estimate_tokens(*parts: Any) -> int:
    """A conservative token estimate for anything JSON-serialisable.

    Never raises: an object that will not serialise is measured by its repr
    rather than skipped, because a part that silently counted as zero would let
    the largest payloads through the budget untouched.
    """
    total_chars = 0
    for part in parts:
        if part is None:
            continue
        try:
            rendered = part if isinstance(part, str) else json.dumps(part, default=str)
        except (TypeError, ValueError):
            rendered = repr(part)
        total_chars += len(rendered)
    return max(total_chars // CHARS_PER_TOKEN, 0)


@dataclass
class LoopBudget:
    """Tokens spent so far against a per-turn ceiling.

    ``exhausted`` is checked BEFORE a call rather than after, so the budget is
    a ceiling on what gets sent rather than a report on what already was.
    """

    limit: int = field(default_factory=loop_token_budget)
    spent: int = 0
    iterations: int = 0
    #: Set when the loop stopped because the budget ran out, so a caller can
    #: tell the user why the answer is short. A loop that stops silently on a
    #: budget is indistinguishable from a model that had nothing more to say.
    stopped_on_budget: bool = False

    @property
    def enabled(self) -> bool:
        return self.limit > 0

    @property
    def exhausted(self) -> bool:
        return self.enabled and self.spent >= self.limit

    @property
    def remaining(self) -> int:
        return max(self.limit - self.spent, 0) if self.enabled else 0

    def charge(self, *parts: Any) -> int:
        """Add the estimated cost of a request. Returns what was added."""
        cost = estimate_tokens(*parts)
        self.spent += cost
        self.iterations += 1
        return cost

    def charge_usage(self, usage: Any) -> int:
        """Replace the last estimate with provider-reported usage, when given.

        Returns the reported total, or 0 when the provider reported nothing.
        Reported usage is authoritative; the estimate exists only because most
        streaming responses carry none.
        """
        if usage is None:
            return 0
        total = getattr(usage, "total_tokens", None)
        if total is None and isinstance(usage, dict):
            total = usage.get("total_tokens")
        if not isinstance(total, int) or total <= 0:
            return 0
        self.spent += total
        return total

    def summary(self) -> str:
        """One line for a user when the budget ended the turn, else empty."""
        if not self.stopped_on_budget:
            return ""
        return (
            f"Stopped after {self.iterations} tool step(s): this turn reached its "
            f"{self.limit}-token budget. Ask again to continue."
        )
