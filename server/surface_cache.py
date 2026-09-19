"""
Surface cache — TTL-based memoization for expensive A2UI surface builders.

Surface builders like /admin and /marketplace hit Postgres + federation
state on every render, which is wasteful when portal users refresh every
few seconds. This module wraps a builder in a small per-key cache with a
default 10-second TTL.

Not all surfaces should be cached — /onboarding is per-agent stateful,
/channels shows last-test-at; those bypass the cache. Opt-in by passing
through `cached_builder(...)`.

Also records lightweight latency + hit/miss telemetry so /health/surfaces
can report per-surface timings without needing an external APM.

Public API
----------
get(key, ttl)                   — cache lookup
set(key, value, ttl)            — insert
invalidate(key_prefix)          — drop entries matching prefix
cached_builder(name, fn, ttl)   — wrap an async builder with caching
stats()                         — { surface: {hits, misses, avg_ms, last_built_at} }
reset()                         — wipe cache + stats (test helper)
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from typing import Any

DEFAULT_TTL_SECONDS = 10.0

# Cache entries: key → (expires_at_epoch, value)
_cache: dict[str, tuple[float, Any]] = {}

# Per-surface telemetry: name → {hits, misses, total_ms, builds, last_built_at}
_stats: dict[str, dict[str, Any]] = {}


def _now() -> float:
    return time.monotonic()


def get(key: str) -> Any | None:
    entry = _cache.get(key)
    if entry is None:
        return None
    expires_at, value = entry
    if _now() >= expires_at:
        _cache.pop(key, None)
        return None
    return value


def set(key: str, value: Any, ttl: float = DEFAULT_TTL_SECONDS) -> None:
    _cache[key] = (_now() + max(0.1, float(ttl)), value)


def invalidate(key_prefix: str) -> int:
    """Drop all cache keys starting with `key_prefix`. Returns count."""
    keys = [k for k in _cache if k.startswith(key_prefix)]
    for k in keys:
        _cache.pop(k, None)
    return len(keys)


def reset() -> None:
    _cache.clear()
    _stats.clear()


def stats() -> dict[str, dict[str, Any]]:
    """Compact per-surface report for /health/surfaces."""
    out: dict[str, dict[str, Any]] = {}
    for name, s in _stats.items():
        builds = s.get("builds", 0)
        avg_ms = (s.get("total_ms", 0.0) / builds) if builds else 0.0
        out[name] = {
            "hits": s.get("hits", 0),
            "misses": s.get("misses", 0),
            "builds": builds,
            "avg_ms": round(avg_ms, 2),
            "last_built_at": s.get("last_built_at"),
        }
    return out


def _record_hit(name: str) -> None:
    s = _stats.setdefault(name, {})
    s["hits"] = s.get("hits", 0) + 1


def _record_build(name: str, elapsed_ms: float) -> None:
    s = _stats.setdefault(name, {})
    s["misses"] = s.get("misses", 0) + 1
    s["builds"] = s.get("builds", 0) + 1
    s["total_ms"] = s.get("total_ms", 0.0) + elapsed_ms
    s["last_built_at"] = time.time()


def cached_builder(
    name: str,
    builder: Callable[..., Awaitable[Any]],
    ttl: float = DEFAULT_TTL_SECONDS,
) -> Callable[..., Awaitable[Any]]:
    """Wrap an async surface-builder with per-call-args caching + timing.

    Cache key: f"{name}:{target!r}". Callers that don't use target still
    get a stable key.
    """

    async def wrapped(target: str | None = None) -> Any:
        key = f"{name}:{target or ''}"
        hit = get(key)
        if hit is not None:
            _record_hit(name)
            return hit

        start = _now()
        result = await builder(target)
        elapsed_ms = (_now() - start) * 1000.0
        _record_build(name, elapsed_ms)
        set(key, result, ttl)
        return result

    wrapped.__name__ = f"cached_{name}"
    wrapped.__doc__ = (builder.__doc__ or "") + f"\n\n[cached: {ttl}s TTL]"
    return wrapped
