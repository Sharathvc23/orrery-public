"""Per-execution skill revocation freshness check.

Skills already verify revocation at install time (see
`skills.check_revocations_at_startup`). That's not enough: between
install and use, a chapter may revoke a skill because it's later
found to be malicious, buggy, or its attestor was compromised. This
module closes the gap by checking revocation ON EVERY HIGH-RISK
EXECUTION, with a 24-hour cache to keep the overhead negligible.

Fail-closed rules
-----------------

  1. Chapter says revoked       → `RevocationCheckFailed("skill_revoked")`
  2. Chapter reachable, not revoked → allow
  3. Chapter unreachable AND last successful check < 24h → allow
     (cached freshness still good — network blips don't block work)
  4. Chapter unreachable AND last successful check >= 24h OR none
                                 → `RevocationCheckFailed("freshness_stale")`

The 24h window is a deliberate tradeoff: short enough that a
compromised skill gets yanked within a day, long enough that a
coffee-shop wifi hiccup doesn't disable the agent.

Integration
-----------

`skill_runtime.invoke_tool()` calls `check_fresh(...)` before it runs
any tool whose owning skill declares a high-risk capability. For
low-risk skills (no shell / no net.arbitrary / no fs.any / no
eval.code), the check is skipped — those can't do damage worth
revoking urgently anyway.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

_log = logging.getLogger(__name__)

__all__ = [
    "FRESHNESS_WINDOW_SECONDS",
    "RevocationCheckFailed",
    "check_fresh",
    "reset_for_tests",
]

# 24 hours.
FRESHNESS_WINDOW_SECONDS = 24 * 60 * 60


class RevocationCheckFailed(Exception):
    """Raised when a high-risk skill cannot run because revocation
    state is either bad (revoked) or unverifiable (offline too long).

    `reason` is machine-readable: 'skill_revoked', 'freshness_stale'.
    """

    def __init__(self, reason: str, *, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass
class _CacheEntry:
    revoked: bool
    checked_at: float  # monotonic seconds


# Keyed by (chapter_url, skill_id) — the same skill_id may be hosted
# on multiple servers with independent revocation state.
_cache: dict[tuple[str, str], _CacheEntry] = {}

# Overridable fetcher so tests don't hit the network. Default calls
# the server's revocation endpoint via httpx.
FetcherFn = Callable[[str, str], bool]


def reset_for_tests() -> None:
    """Drop the cache so tests start clean."""
    _cache.clear()


def _default_fetcher(chapter_url: str, skill_id: str) -> bool:
    """Query the chapter for `skill_id`'s revocation status.

    Returns True iff the chapter considers the skill revoked. Raises
    on network errors — the caller translates those into freshness-
    stale errors (after checking the cache).
    """
    import httpx

    url = f"{chapter_url.rstrip('/')}/api/skills/{skill_id}/revocation_status"
    resp = httpx.get(url, timeout=5.0)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError("revocation_status: non-dict response")
    # Accept either {"revoked": bool} or {"revoked_at": iso|null}
    if "revoked" in data:
        return bool(data["revoked"])
    return data.get("revoked_at") is not None


def check_fresh(
    chapter_url: str,
    skill_id: str,
    *,
    fetcher: FetcherFn | None = None,
    now: float | None = None,
) -> None:
    """Verify `skill_id` is non-revoked and the check is fresh enough.

    Raises `RevocationCheckFailed` if:
      - the chapter reports revoked, OR
      - we can't reach the chapter AND have no cached result from
        within the freshness window

    Never silently "best-effort" allows a revoked skill to run. Network
    errors + cache miss = treat as revoked (fail-closed).
    """
    fetcher = fetcher or _default_fetcher
    now = now if now is not None else time.time()
    key = (chapter_url, skill_id)
    cached = _cache.get(key)

    # Try to refresh when cached or first-time. If the fetch succeeds,
    # update cache and enforce. If it fails, fall back to cache.
    try:
        revoked = fetcher(chapter_url, skill_id)
        _cache[key] = _CacheEntry(revoked=revoked, checked_at=now)
        if revoked:
            raise RevocationCheckFailed(
                "skill_revoked",
                detail=f"{skill_id} on {chapter_url}",
            )
        return
    except RevocationCheckFailed:
        raise
    except Exception as e:
        _log.debug("revocation fetch failed for %s: %s", skill_id, e)

    if cached is None:
        raise RevocationCheckFailed(
            "freshness_stale",
            detail=f"no prior check; chapter {chapter_url} unreachable",
        )
    age = now - cached.checked_at
    if age >= FRESHNESS_WINDOW_SECONDS:
        raise RevocationCheckFailed(
            "freshness_stale",
            detail=f"last check {age:.0f}s ago; window {FRESHNESS_WINDOW_SECONDS}s",
        )
    # Cached says not-revoked AND cache is still fresh — allow.
    if cached.revoked:
        raise RevocationCheckFailed(
            "skill_revoked",
            detail=f"{skill_id} (from cache)",
        )
