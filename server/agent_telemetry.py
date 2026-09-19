"""
Agent Telemetry — request-level metrics for NANDA AgentFacts evaluations.

Tracks latency, errors, throughput, and uptime. Feeds into
NandaEvaluations and NandaTelemetry sections of AgentFacts.

Also carries the ORG-SIDE LLM METER (:meth:`AgentTelemetry.record_llm`). It
lives here rather than in a new module because a second telemetry system is how
two disagreeing answers to "what did we spend" get built.

⚠️ WHAT THE METER IS FOR. Every LLM figure this repo has produced so far is a
TOKENIZER APPROXIMATION: no hosted provider has been called, inputs are tiktoken
run over the request the SDK assembled (measured 3.4% low against a real model's
own ``prompt_tokens``), and every output figure is a ``max_tokens`` CEILING
rather than an observation. This meter records what a provider actually
reported, so that an optimisation which removes calls can be shown to have
removed them, and a regression in it can be seen.

⚠️ AN ABSENT USAGE REPORT IS NEVER ZERO. ``record_llm(usage=None)`` is the only
way to say "the call happened and the provider told us nothing", and it is
counted separately in ``calls_without_usage``. Folding that into the token sums
would produce a total that looks complete and is not — which is the exact
failure this unit exists to end.

RECORD-ONLY. Nothing here gates, skips, caps, or prices. There is no price
table: no output figure has ever been observed, and a cap set on an
approximation is a cap set on a guess.
"""

import threading
import time
from collections import deque
from datetime import UTC, datetime
from typing import Any

#: Distinct (side, callsite, principal, provider, model) series to hold before
#: folding into an overflow bucket. ``member_runtime.think()`` has no caller
#: today; wired on a 245-member chapter it becomes a per-member multiplier, so
#: the bound is real. Overflow is COUNTED, never silently dropped — a meter that
#: quietly stops recording reads as "spend went down".
MAX_LLM_SERIES = 4096

#: The key fields, in order. Per-principal from day one: an unkeyed meter would
#: let a 245x event land looking like ordinary growth.
LLM_KEY_FIELDS = ("side", "callsite", "principal", "provider", "model")

_OVERFLOW = "__overflow__"


class AgentTelemetry:
    """Tracks request-level metrics for AgentFacts telemetry and evaluations."""

    def __init__(self, max_samples: int = 1000, max_llm_series: int = MAX_LLM_SERIES):
        self._latencies: deque[float] = deque(maxlen=max_samples)
        self._errors: deque[bool] = deque(maxlen=max_samples)
        self._start_time: float = time.time()
        self._total_requests: int = 0
        self._total_errors: int = 0
        # ── LLM meter ────────────────────────────────────────────────────────
        # Keyed per (side, callsite, principal, provider, model). Guarded by a
        # lock: LLM calls arrive on request threads while a read surface may be
        # snapshotting, and mutating a dict during iteration raises.
        self._llm: dict[tuple[str, ...], dict[str, Any]] = {}
        self._llm_lock = threading.Lock()
        self._max_llm_series = max_llm_series
        self._llm_series_folded: int = 0

    def record_request(self, latency_ms: float, is_error: bool = False) -> None:
        """Record a single request's metrics."""
        self._latencies.append(max(0.0, latency_ms))
        self._errors.append(is_error)
        self._total_requests += 1
        if is_error:
            self._total_errors += 1

    # ── LLM meter ────────────────────────────────────────────────────────────

    @staticmethod
    def _norm(value: Any) -> str:
        """A key field as a stable string. Empty becomes ``unknown`` rather than
        an empty string, so a missing principal is visible instead of blending
        into the next row."""
        text = str(value).strip() if value is not None else ""
        return text or "unknown"

    def _bucket(self, key: tuple[str, ...]) -> dict[str, Any]:
        """The counter row for ``key``, creating it, or the overflow row.

        Caller holds the lock.
        """
        row = self._llm.get(key)
        if row is not None:
            return row
        if len(self._llm) >= self._max_llm_series:
            overflow = (_OVERFLOW,) * len(LLM_KEY_FIELDS)
            row = self._llm.get(overflow)
            if row is None:
                row = self._new_row()
                self._llm[overflow] = row
            self._llm_series_folded += 1
            return row
        row = self._new_row()
        self._llm[key] = row
        return row

    @staticmethod
    def _new_row() -> dict[str, Any]:
        return {
            "llm_calls": 0,
            "llm_input_tokens": 0,
            "llm_output_tokens": 0,
            "llm_cached_tokens": 0,
            "llm_calls_skipped": 0,
            # Calls that happened but whose provider reported no usage. Held
            # apart from the token sums on purpose — see the module docstring.
            "llm_calls_without_usage": 0,
            "llm_skip_reason": {},
        }

    def record_llm(
        self,
        *,
        side: str,
        callsite: str,
        principal: str,
        provider: str,
        model: str,
        usage: dict[str, Any] | None,
    ) -> None:
        """Record one LLM call that WAS made.

        ``usage`` is the provider's own report, normalised to
        ``{input_tokens, output_tokens, cached_tokens}``. Pass ``None`` when the
        provider reported nothing — that is counted in ``calls_without_usage``
        and contributes no tokens. There is deliberately no way to pass a
        tokenizer estimate through this function: the meter records
        observations, and mixing an estimate in would make the total unauditable.
        """
        key = tuple(
            self._norm(v) for v in (side, callsite, principal, provider, model)
        )
        with self._llm_lock:
            row = self._bucket(key)
            row["llm_calls"] += 1
            if usage is None:
                row["llm_calls_without_usage"] += 1
                return
            for field, source in (
                ("llm_input_tokens", "input_tokens"),
                ("llm_output_tokens", "output_tokens"),
                ("llm_cached_tokens", "cached_tokens"),
            ):
                value = usage.get(source)
                if isinstance(value, (int, float)) and value >= 0:
                    row[field] += int(value)

    def record_llm_skip(
        self,
        *,
        side: str,
        callsite: str,
        principal: str,
        provider: str,
        model: str,
        reason: str,
    ) -> None:
        """Record one LLM call that was NOT made, and why.

        A skip that is not counted cannot be proven, and a regression in it
        cannot be detected — which is the whole reason the meter ships before
        the optimisation that removes 287 of 288 daily calls.
        """
        key = tuple(
            self._norm(v) for v in (side, callsite, principal, provider, model)
        )
        with self._llm_lock:
            row = self._bucket(key)
            row["llm_calls_skipped"] += 1
            bucket = row["llm_skip_reason"]
            label = self._norm(reason)
            bucket[label] = bucket.get(label, 0) + 1

    def get_llm_spend(self) -> dict:
        """A snapshot of the meter: per-series rows plus totals.

        ``series_folded`` is non-zero when the cardinality bound was hit. It is
        reported rather than hidden, because a meter that silently stopped
        recording is indistinguishable from spend that stopped.
        """
        with self._llm_lock:
            rows: list[dict[str, Any]] = [
                {
                    **dict(zip(LLM_KEY_FIELDS, key)),
                    # Copy the reason bucket: the snapshot must not hand a
                    # caller a live reference into the meter's own state.
                    **{k: (dict(v) if isinstance(v, dict) else v) for k, v in row.items()},
                }
                for key, row in self._llm.items()
            ]
            folded = self._llm_series_folded

        totals: dict[str, Any] = {
            field: sum(int(r[field]) for r in rows)
            for field in (
                "llm_calls",
                "llm_input_tokens",
                "llm_output_tokens",
                "llm_cached_tokens",
                "llm_calls_skipped",
                "llm_calls_without_usage",
            )
        }
        reasons: dict[str, int] = {}
        for r in rows:
            for label, count in r["llm_skip_reason"].items():
                reasons[label] = reasons.get(label, 0) + int(count)
        totals["llm_skip_reason"] = reasons

        return {
            "record_only": True,
            "observed_usage_only": True,
            "series": sorted(rows, key=lambda r: tuple(r[f] for f in LLM_KEY_FIELDS)),
            "totals": totals,
            "series_count": len(rows),
            "series_folded": folded,
            "max_series": self._max_llm_series,
            "since": datetime.fromtimestamp(self._start_time, UTC).isoformat(),
            "last_updated": datetime.now(UTC).isoformat(),
        }

    def get_telemetry(self) -> dict:
        """Return NandaTelemetry-compatible dict."""
        if not self._latencies:
            return {
                "enabled": True,
                "latency_p50_ms": None,
                "latency_p99_ms": None,
                "throughput_rpm": None,
                "error_rate_pct": None,
                "uptime_90d_pct": None,
                "last_updated": datetime.now(UTC).isoformat(),
            }

        sorted_latencies = sorted(self._latencies)
        n = len(sorted_latencies)
        p50 = sorted_latencies[n // 2]
        p99 = sorted_latencies[min(int(n * 0.99), n - 1)]

        uptime_seconds = time.time() - self._start_time
        uptime_minutes = max(uptime_seconds / 60.0, 1.0)
        throughput = self._total_requests / uptime_minutes

        error_rate = (self._total_errors / max(self._total_requests, 1)) * 100.0

        return {
            "enabled": True,
            "latency_p50_ms": round(p50, 1),
            "latency_p99_ms": round(p99, 1),
            "throughput_rpm": round(throughput, 2),
            "error_rate_pct": round(error_rate, 2),
            "uptime_90d_pct": None,  # Requires long-running data
            "last_updated": datetime.now(UTC).isoformat(),
        }

    def get_evaluations(self, activity_score: float = 0.0, think_cycles: int = 0) -> dict:
        """Return NandaEvaluations-compatible dict.

        performanceScore: 0-5 composite score based on activity, think cycles, and response time.
        """
        avg_latency = None
        if self._latencies:
            avg_latency = round(sum(self._latencies) / len(self._latencies), 1)

        # Composite score: weighted combination of activity, think cycles, and low error rate
        activity_component = min(2.0, (activity_score / 50.0) * 2.0)
        think_component = min(1.5, (think_cycles / 100.0) * 1.5)
        reliability_component = 1.5 * (1.0 - min(1.0, (self._total_errors / max(self._total_requests, 1))))
        performance_score = round(min(5.0, activity_component + think_component + reliability_component), 2)

        return {
            "performanceScore": performance_score,
            "totalInteractions": self._total_requests,
            "avgResponseTimeMs": avg_latency,
        }


# Module-level singleton
_telemetry = AgentTelemetry()


def record_request(latency_ms: float, is_error: bool = False) -> None:
    _telemetry.record_request(latency_ms, is_error)


def get_telemetry() -> dict:
    return _telemetry.get_telemetry()


def get_evaluations(activity_score: float = 0.0, think_cycles: int = 0) -> dict:
    return _telemetry.get_evaluations(activity_score, think_cycles)


def record_llm(
    *,
    side: str,
    callsite: str,
    principal: str,
    provider: str,
    model: str,
    usage: dict[str, Any] | None,
) -> None:
    _telemetry.record_llm(
        side=side, callsite=callsite, principal=principal, provider=provider, model=model, usage=usage
    )


def record_llm_skip(
    *, side: str, callsite: str, principal: str, provider: str, model: str, reason: str
) -> None:
    _telemetry.record_llm_skip(
        side=side, callsite=callsite, principal=principal, provider=provider, model=model, reason=reason
    )


def get_llm_spend() -> dict:
    return _telemetry.get_llm_spend()
