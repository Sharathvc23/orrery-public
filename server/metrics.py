"""Prometheus-shape metrics for chapter observability.

Exposes counters and gauges in the Prometheus text exposition format
(``application/openmetrics-text`` is also acceptable but text/plain is the
common-denominator). No external dependency — emitted by hand because the
schema is two-line-trivial and pinning ``prometheus_client`` for one
endpoint is not worth the supply-chain surface.

Public API:

  record_request(method, status_code)         — bump requests_total
  record_signing_failure(reason)              — bump signing_failures_total
  record_tofu_bootstrap()                     — bump tofu_bootstraps_total
  record_key_mismatch()                       — bump tofu_key_mismatches_total
  record_replay_rejection()                   — bump replay_rejections_total
  record_rate_limit_capacity_rejection()      — bump rate-limit store-cap refusals
  set_members_total(count)                    — gauge: current member count
  set_federation_state(peer, state)           — gauge: federation_peers{state=...}

  render(chapter_id) -> str                   — Prometheus text format

Counters never reset within a process lifetime. Federation gauges are
updated by the same heartbeat that drives federation_state in /health,
so the metrics endpoint is always coherent with /health.

Thread-safety: every mutation acquires an internal lock. Reads against
counters during render do not need to be transactional with the
mutations — Prometheus tolerates near-real-time, not exact-snapshot.
"""

from __future__ import annotations

import threading
from collections import defaultdict

_lock = threading.Lock()

_counters: dict[str, float] = defaultdict(int)
_labelled_counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = defaultdict(int)
_gauges: dict[str, float] = defaultdict(float)
_labelled_gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)

# Counter names + their HELP strings. Order is deterministic for stable
# scrape-diff output (Grafana panels with absolute line numbers).
_COUNTER_DEFS: list[tuple[str, str]] = [
    ("nanda_chapter_signing_failures_total", "Count of signed-request verification failures by reason."),
    ("nanda_chapter_tofu_bootstraps_total", "Count of TOFU bootstraps per spec/0.2 §3.1 idempotence."),
    ("nanda_chapter_tofu_key_mismatches_total", "Count of rejected requests with key_mismatch (impostor probe)."),
    ("nanda_chapter_replay_rejections_total", "Count of expired-timestamp rejections (replay defense)."),
    (
        "nanda_chapter_rate_limit_capacity_rejections_total",
        "Count of unseen client keys refused because every rate-limit bucket is live.",
    ),
    (
        "nanda_chapter_member_persist_failures_total",
        "Count of member rows that failed to persist to Postgres after all retries "
        "(the directory silently diverges from the in-memory bridge when this is non-zero).",
    ),
]

_LABELLED_COUNTER_DEFS: list[tuple[str, str]] = [
    ("nanda_chapter_requests_total", "HTTP requests served, labelled by method and status class."),
    (
        "nanda_chapter_db_failures_total",
        "Count of configured-database operation failures, labelled by operation "
        "(e.g. pool_create, POST:agents). Non-zero means writes/reads are being lost or "
        "the pool is down — an operator alert signal, never a silent return-None.",
    ),
]

_GAUGE_DEFS: list[tuple[str, str]] = [
    ("nanda_chapter_members_total", "Current member count for this chapter."),
]

_LABELLED_GAUGE_DEFS: list[tuple[str, str]] = [
    ("nanda_chapter_federation_peer_state", "Federation peer state (1 = current state, 0 = other)."),
]


def _status_class(status_code: int) -> str:
    """2xx → '2xx', 4xx → '4xx', etc. Bucket cardinality stays bounded."""
    if 200 <= status_code < 300:
        return "2xx"
    if 300 <= status_code < 400:
        return "3xx"
    if 400 <= status_code < 500:
        return "4xx"
    if 500 <= status_code < 600:
        return "5xx"
    return "other"


def record_request(method: str, status_code: int) -> None:
    key = (
        "nanda_chapter_requests_total",
        (("method", method.upper()), ("status_class", _status_class(status_code))),
    )
    with _lock:
        _labelled_counters[key] += 1


def record_signing_failure(reason: str) -> None:
    """Bump signing_failures_total. Reason is a short ascii token from
    auth_verify (invalid_signature, expired_timestamp, key_mismatch, ...).
    Specific reasons that already have their own counter (key_mismatch,
    expired_timestamp) are also recorded there for direct dashboarding —
    the redundancy is intentional and cheap.
    """
    safe = "".join(c for c in (reason or "unknown") if c.isalnum() or c == "_") or "unknown"
    with _lock:
        _counters[f"nanda_chapter_signing_failures_total::{safe}"] += 1


def record_tofu_bootstrap() -> None:
    with _lock:
        _counters["nanda_chapter_tofu_bootstraps_total"] += 1


def record_member_persist_failure() -> None:
    """Bump member_persist_failures_total — a member registered in the in-memory
    bridge whose Postgres row never landed (after retries), so the portal
    directory silently diverges. Non-zero is an operator alert signal."""
    with _lock:
        _counters["nanda_chapter_member_persist_failures_total"] += 1


def record_db_failure(operation: str) -> None:
    """Bump db_failures_total for a configured-DB operation failure. The
    operation label is a short bounded token (pool_create, POST:agents, …) — a
    failure here is a data-loss/outage signal, distinct from 'no DB configured'."""
    safe = "".join(c for c in (operation or "unknown") if c.isalnum() or c in "_:") or "unknown"
    key = ("nanda_chapter_db_failures_total", (("operation", safe),))
    with _lock:
        _labelled_counters[key] += 1


def record_key_mismatch() -> None:
    with _lock:
        _counters["nanda_chapter_tofu_key_mismatches_total"] += 1


def record_replay_rejection() -> None:
    with _lock:
        _counters["nanda_chapter_replay_rejections_total"] += 1


def record_rate_limit_capacity_rejection() -> None:
    """Bump the bounded-cardinality counter for store-capacity refusals."""
    with _lock:
        _counters["nanda_chapter_rate_limit_capacity_rejections_total"] += 1


def set_members_total(count: int) -> None:
    with _lock:
        _gauges["nanda_chapter_members_total"] = float(count)


def set_federation_state(peer: str, state: str) -> None:
    """Set the active state for a peer. Other states for the same peer
    are reset to 0 so a Prometheus scraper sees exactly one '1' per
    (peer) at a time — a clean state machine when graphed."""
    safe_peer = peer.replace('"', "")
    with _lock:
        for s in ("online", "degraded", "offline"):
            key = (
                "nanda_chapter_federation_peer_state",
                (("peer", safe_peer), ("state", s)),
            )
            _labelled_gauges[key] = 1.0 if s == state else 0.0


def _format_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{k}="{v}"' for k, v in labels) + "}"


def render(chapter_id: str = "") -> str:
    """Return the Prometheus text exposition. UTF-8 safe."""
    lines: list[str] = []
    chapter_label = (("chapter_id", chapter_id),) if chapter_id else ()

    with _lock:
        # Plain counters (some carry an embedded :: subkey for reason cardinality)
        for name, help_text in _COUNTER_DEFS:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} counter")
            # Match keys for this counter (with or without ::subkey)
            wrote_any = False
            for k, v in _counters.items():
                if k == name:
                    lines.append(f"{name}{_format_labels(chapter_label)} {v}")
                    wrote_any = True
                elif k.startswith(name + "::"):
                    sub = k.split("::", 1)[1]
                    sub_labels = chapter_label + (("reason", sub),)
                    lines.append(f"{name}{_format_labels(sub_labels)} {v}")
                    wrote_any = True
            if not wrote_any:
                # Emit a zero so dashboards don't show "no data" before any traffic.
                lines.append(f"{name}{_format_labels(chapter_label)} 0")

        # Labelled counters
        for name, help_text in _LABELLED_COUNTER_DEFS:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} counter")
            wrote_any = False
            for (n, labels), v in _labelled_counters.items():
                if n == name:
                    merged = chapter_label + labels
                    lines.append(f"{name}{_format_labels(merged)} {v}")
                    wrote_any = True
            if not wrote_any:
                lines.append(f"{name}{_format_labels(chapter_label)} 0")

        # Plain gauges
        for name, help_text in _GAUGE_DEFS:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            v = _gauges.get(name, 0.0)
            lines.append(f"{name}{_format_labels(chapter_label)} {v:g}")

        # Labelled gauges
        for name, help_text in _LABELLED_GAUGE_DEFS:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            wrote_any = False
            for (n, labels), lv in _labelled_gauges.items():
                if n == name:
                    merged = chapter_label + labels
                    lines.append(f"{name}{_format_labels(merged)} {lv:g}")
                    wrote_any = True
            if not wrote_any:
                lines.append(f"{name}{_format_labels(chapter_label)} 0")

    # Prometheus expects a trailing newline.
    return "\n".join(lines) + "\n"


def reset_for_tests() -> None:
    """Wipe all counters/gauges. Test-only — production processes never
    reset metrics outside of restart."""
    with _lock:
        _counters.clear()
        _labelled_counters.clear()
        _gauges.clear()
        _labelled_gauges.clear()


__all__ = [
    "record_key_mismatch",
    "record_replay_rejection",
    "record_rate_limit_capacity_rejection",
    "record_request",
    "record_signing_failure",
    "record_tofu_bootstrap",
    "render",
    "reset_for_tests",
    "set_federation_state",
    "set_members_total",
]
