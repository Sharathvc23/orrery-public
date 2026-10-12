"""How much work one caller may create on this agent, per window.

WHY THIS EXISTS. ``a2a_auth`` draws the line at attribution and says so
plainly: a verified caller proves "possession of the key they claim", and "it is
not an allowlist and must not be described as one". Anyone can mint an Ed25519
keypair. So once this agent is listed in a public index and holds a provider
key, an arbitrary stranger can sign ``tasks/send`` and spend the owner's credit
— one request at a time, without limit. ``a2a_auth``'s own docstring names the
stake ("it spends their money") and stops at identifying who is spending it.

This bounds how fast. It is deliberately NOT an allowlist either: deciding
WHICH peers may call is a policy question for the operator, and an open agent
network is partly the point. A rate limit is the control that does not require
that decision to be made first.

SCOPED TO WORK-CREATING METHODS, by the same axis ``a2a_auth`` uses. Reads
(``tasks/get``, ``tasks/resubscribe``) are left alone: they are a legitimate
peer's polling flow, they cost no provider credit, and throttling them would
break the thing the open-read decision exists to serve. What is limited is what
runs tools.

KEYED ON THE CALLER'S KEY WHEN THERE IS ONE, the peer address otherwise. The
key is the better identity — it survives a changed address, and work-creating
methods require one — but a caller refused BEFORE verification has no key yet,
and the address is what is left. Neither is forgeable into somebody else's
bucket: a stranger can only ever occupy their own.

NOT A SPEND CAP. This bounds requests per window, not tokens or money. A caller
inside the limit still costs whatever the work costs, and the autonomous think
loop is not inbound traffic at all, so this bounds neither. Both of those want
the metered cap, which is a different control.

IN-MEMORY AND PER-PROCESS, deliberately. A restart forgives, which is the right
failure mode for a limiter whose purpose is bounding a burst rather than
settling a ledger — and durable state here would be a second store to keep
correct for no gain over the attack it stops.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque

__all__ = [
    "DEFAULT_MAX_REQUESTS",
    "DEFAULT_WINDOW_S",
    "MAX_ENV_VAR",
    "WINDOW_ENV_VAR",
    "caller_bucket",
    "check",
    "limits",
    "reset",
]

MAX_ENV_VAR = "COMMUNITY_MEMBER_RPC_RATE_MAX"
WINDOW_ENV_VAR = "COMMUNITY_MEMBER_RPC_RATE_WINDOW_S"

#: Per caller, per window. Chosen to be far above a peer's working rate and far
#: below a rate that runs up a bill: the autonomous loop itself ticks once every
#: 300s, so a peer sending more than one work item every two seconds is not
#: collaborating. A limit nobody legitimate reaches is one nobody tunes, which
#: is why this is generous rather than tight.
DEFAULT_MAX_REQUESTS = 30
DEFAULT_WINDOW_S = 60.0

#: Cap on tracked buckets, so an attacker rotating keys or addresses cannot
#: grow this map without bound — the limiter must not become the memory leak it
#: was added to prevent. On overflow the oldest-idle bucket is dropped, which at
#: worst forgives one caller early.
_MAX_BUCKETS = 4096

_lock = threading.Lock()
_hits: dict[str, deque[float]] = {}


def limits() -> tuple[int, float]:
    """``(max_requests, window_seconds)``, read at call time.

    Read per call rather than bound at import for the same reason
    ``think_interval_seconds`` is: a process that sets the variable after import
    must be honoured, and one definition must serve every entry point. A value
    that is not a positive number falls back to the default rather than
    disabling the limiter — a typo must not silently remove a control.
    """
    try:
        max_requests = int(os.environ.get(MAX_ENV_VAR, "").strip() or DEFAULT_MAX_REQUESTS)
    except ValueError:
        max_requests = DEFAULT_MAX_REQUESTS
    try:
        window = float(os.environ.get(WINDOW_ENV_VAR, "").strip() or DEFAULT_WINDOW_S)
    except ValueError:
        window = DEFAULT_WINDOW_S
    if max_requests <= 0:
        max_requests = DEFAULT_MAX_REQUESTS
    if window <= 0:
        window = DEFAULT_WINDOW_S
    return max_requests, window


def caller_bucket(caller_key: str | None, peer: str | None) -> str:
    """The bucket this request counts against.

    Prefixed by kind so a peer address can never collide with a key, and an
    unidentifiable caller shares one bucket rather than being waved through:
    requests with neither identity are indistinguishable from each other, and
    counting them together is the honest reading.
    """
    key = (caller_key or "").strip()
    if key:
        return f"key:{key}"
    addr = (peer or "").strip()
    return f"peer:{addr}" if addr else "peer:unknown"


def check(bucket: str, *, now: float | None = None) -> tuple[bool, int, float]:
    """Count one request against ``bucket``.

    Returns ``(allowed, remaining, retry_after_seconds)``. A refused request is
    NOT counted: counting it would extend the window every time a blocked
    caller retried, turning a 60-second limit into an indefinite ban and making
    the limiter's behaviour depend on the attacker's patience.
    """
    max_requests, window = limits()
    clock = time.monotonic() if now is None else now
    cutoff = clock - window

    with _lock:
        hits = _hits.get(bucket)
        if hits is None:
            if len(_hits) >= _MAX_BUCKETS:
                _evict_locked(cutoff)
            hits = _hits.setdefault(bucket, deque())
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if len(hits) >= max_requests:
            retry_after = max(0.0, hits[0] + window - clock)
            return False, 0, retry_after
        hits.append(clock)
        return True, max_requests - len(hits), 0.0


def _evict_locked(cutoff: float) -> None:
    """Drop buckets with nothing live in them; if none, drop the stalest."""
    empty = [b for b, hits in _hits.items() if not hits or hits[-1] <= cutoff]
    for b in empty:
        del _hits[b]
    if not empty and _hits:
        stalest = min(_hits, key=lambda b: _hits[b][-1])
        del _hits[stalest]


def reset() -> None:
    """Forget every bucket. For tests and for an operator clearing a mistake."""
    with _lock:
        _hits.clear()
