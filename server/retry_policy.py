"""Retry discipline for outbound LLM calls — terminal vs retryable.

WHY THIS EXISTS. A keyless-install spike measured the autonomous think loop retrying
a permanent 400 at full rate, forever: 14 failures in ~60 seconds at a 5s
interval, ~17k/day/agent. PR2 stopped the *unconfigured* case from ever
starting. This is the other half — what to do when a provider IS configured and
the call comes back an error anyway.

**Backoff alone would not have fixed it.** A permanent 4xx retried on a 10-minute
cadence is still an infinite loop; it is just a politer one, and it still burns
quota and money forever on an error that cannot succeed. So the first question
is not "how long do we wait" but "is waiting capable of helping at all":

    RETRYABLE  the condition can plausibly clear on its own — rate limits,
               server faults, network trouble. Back off and keep trying, on the
               same curve `outbox.py` already uses.
    TERMINAL   the condition cannot clear without a human changing something —
               a bad key, a revoked key, a malformed request, a model that does
               not exist. Stop. Retrying is not patience, it is a bug.

`outbox.py` already had the backoff half right (durable queue, 10s → 20s → 40s,
cap 10min, attempt tracking) and the think path never adopted it. The constants
here are deliberately identical so the two cannot drift into two disciplines.

SHARED WITH THE SERVER SCHEDULER (PR5). This module is standalone on purpose —
stdlib only, no imports from the rest of `community_member`, no I/O, no logging
— so `server/` can vendor it the way it already vendors `_arp_verify`, rather
than growing a second, subtly different policy. If you are implementing the
scheduler: import or copy this file whole; do not re-derive the table.
"""

from __future__ import annotations

from enum import Enum

# Identical to outbox.py — one curve, not two.
BACKOFF_BASE_SEC = 10
BACKOFF_CAP_SEC = 600
_MAX_DOUBLINGS = 8


class Decision(str, Enum):
    """What waiting can do for this failure."""

    RETRYABLE = "retryable"
    TERMINAL = "terminal"


#: HTTP statuses where waiting can plausibly help.
RETRYABLE_STATUSES = frozenset(
    {
        408,  # request timeout
        409,  # conflict — usually a concurrent-state race
        425,  # too early
        429,  # rate limited: the canonical "wait and it clears"
        500,
        502,
        503,
        504,
    }
)

#: HTTP statuses that cannot clear without a human changing something.
#: 402 and 403 are here deliberately: "out of credit" and "forbidden" feel
#: transient to an optimistic retry loop and are not — they bill or lock out.
TERMINAL_STATUSES = frozenset(
    {
        400,  # malformed request — our bug, or an unsupported parameter
        401,  # bad or missing key
        402,  # payment required
        403,  # forbidden / key lacks access
        404,  # no such model or endpoint
        413,  # payload too large — will be too large next time too
        422,  # unprocessable
    }
)

#: Exception type NAMES treated as transport-level and therefore retryable.
#: Matched by name so this module needs no provider SDK import — which is what
#: lets the server vendor it unchanged.
_RETRYABLE_EXC_NAMES = frozenset(
    {
        "APIConnectionError",
        "APITimeoutError",
        "InternalServerError",
        "RateLimitError",
        "ConnectionError",
        "ConnectionResetError",
        "ConnectTimeout",
        "ReadTimeout",
        "TimeoutError",
        "socket.timeout",
        "RemoteProtocolError",
    }
)

_TERMINAL_EXC_NAMES = frozenset(
    {
        "AuthenticationError",
        "PermissionDeniedError",
        "BadRequestError",
        "NotFoundError",
        "UnprocessableEntityError",
    }
)


def _status_of(exc: BaseException) -> int | None:
    """The HTTP status an exception carries, if any.

    Providers differ: the OpenAI SDK exposes ``status_code``, some wrappers use
    ``status`` or ``code``, and some only put the number in the message. The
    first two are read directly; the message is NOT parsed, because a substring
    match on a number is how "model claude-400-x not found" becomes a retry
    decision.
    """
    for attr in ("status_code", "status"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            return value
    response = getattr(exc, "response", None)
    if response is not None:
        value = getattr(response, "status_code", None)
        if isinstance(value, int):
            return value
    return None


def classify(exc: BaseException) -> Decision:
    """Whether retrying ``exc`` can plausibly succeed.

    Order matters: an explicit status wins over the exception's type name,
    because a provider's generic ``APIStatusError`` carries the real answer in
    its status while its name says nothing.

    The default for something we cannot classify is **TERMINAL**, and that is a
    deliberate choice rather than caution about the network. An unrecognised
    exception from this code path is most often OUR bug — an ``AttributeError``
    in a rare branch, a contract change in the planner — and retrying our own
    bug on a ten-minute cadence forever is precisely the failure this module
    exists to end. Stopping surfaces it; the caller degrades to deterministic
    work rather than dying, so the cost of being wrong here is low and the cost
    of being wrong the other way is unbounded.
    """
    status = _status_of(exc)
    if status is not None:
        if status in RETRYABLE_STATUSES:
            return Decision.RETRYABLE
        if status in TERMINAL_STATUSES:
            return Decision.TERMINAL
        # An unlisted 5xx is still a server fault; an unlisted 4xx is still ours.
        if 500 <= status <= 599:
            return Decision.RETRYABLE
        if 400 <= status <= 499:
            return Decision.TERMINAL

    name = type(exc).__name__
    if name in _RETRYABLE_EXC_NAMES:
        return Decision.RETRYABLE
    if name in _TERMINAL_EXC_NAMES:
        return Decision.TERMINAL
    if isinstance(exc, TimeoutError | ConnectionError):
        return Decision.RETRYABLE

    return Decision.TERMINAL


def backoff_seconds(consecutive_failures: int) -> int:
    """Seconds to wait after ``consecutive_failures`` retryable failures.

    10 → 20 → 40 → … capped at 600. Byte-identical curve to
    ``outbox.mark_failure`` so an operator reading two logs sees one behaviour.
    ``consecutive_failures`` is 1-based: the first failure waits the base.
    """
    n = max(1, int(consecutive_failures))
    return min(BACKOFF_BASE_SEC * (2 ** min(n - 1, _MAX_DOUBLINGS)), BACKOFF_CAP_SEC)


def describe(exc: BaseException, decision: Decision) -> str:
    """A one-line, operator-readable reason. No secrets: the provider's own
    message is included but a key never appears in one."""
    status = _status_of(exc)
    where = f"HTTP {status}" if status is not None else type(exc).__name__
    verb = "will retry" if decision is Decision.RETRYABLE else "STOPPING — retrying cannot help"
    return f"{where}: {verb}. {str(exc)[:200]}"


__all__ = [
    "BACKOFF_BASE_SEC",
    "BACKOFF_CAP_SEC",
    "RETRYABLE_STATUSES",
    "TERMINAL_STATUSES",
    "Decision",
    "backoff_seconds",
    "classify",
    "describe",
]
