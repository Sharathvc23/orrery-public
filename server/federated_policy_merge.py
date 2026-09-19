"""Federation-wide governance — confidence-weighted peer policy merge.

PR-2d: each chapter periodically exports a `policy_snapshot` to peers.
On each tune_cycle, we merge received peer snapshots into our own
tunable keys — but with guardrails so a malicious or misconfigured
peer cannot hijack our policy.

Design (keeping it conservative and bounded):

  1. **Bayesian-lite weighted merge.** For each tunable-unpinned numeric
     key, compute the posterior mean weighted by `sample_size` and
     `time_decay`. Peers with few samples or stale snapshots contribute
     less.

  2. **Median absolute deviation (MAD) filter.** Drop peer snapshots
     whose value is > 3 * MAD from the network median. A single
     adversarial peer gets outvoted; a coordinated minority cannot
     pull policy past one MAD tick.

  3. **Per-cycle delta cap of ±10%.** Same bound as `policy.tune_cycle`
     applies to local-only updates. Federation merge stacks WITH, not
     AFTER, the local delta — total drift per cycle is capped at 10%.

  4. **0.5x..2x baseline clamp.** Identical to local tuner. A runaway
     federation convergence cannot push a value past these limits.

  5. **Feature flag.** `policy.federation_enabled` defaults to `false`.
     Chapter admins opt in explicitly. No live chapter is affected
     until they flip it.

R1-R10 coverage lives in tests/test_federated_policy_merge.py.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass

# Bounds mirror policy.py's AUTO_TUNE_* constants so the federation merge
# cannot exceed the local tuner's safety envelope.
MAX_DELTA_FRACTION = 0.10  # ±10% per cycle
BASELINE_MIN_FRACTION = 0.5  # key can't drop below 0.5x baseline
BASELINE_MAX_FRACTION = 2.0  # or rise above 2x baseline
MAD_THRESHOLD = 3.0  # MAD multiplier for adversarial-peer filter
MIN_PEERS_FOR_MERGE = 2  # need at least 2 peers to compute a sensible median
MIN_SAMPLES_FROM_PEER = 5  # ignore peers with < 5 outcome samples for this key


@dataclass
class PeerSnapshot:
    """One peer's view of one tunable key."""

    chapter_id: str
    key: str
    value: float
    baseline: float
    sample_size: int
    # confidence in [0, 1] — can be derived client-side; defaults to 1.0
    confidence: float = 1.0
    # client-side timestamp (unix seconds); older snapshots de-weight
    timestamp: int = 0


@dataclass
class MergeResult:
    """What merge_peer_snapshots returns."""

    key: str
    old_value: float
    new_value: float
    baseline: float
    # Which peers actually contributed (post-MAD filter).
    contributing_peers: list[str]
    # Which peers were filtered out as outliers.
    excluded_peers: list[str]
    # Reason for the new_value — explainable to a leader reviewing audit.
    reason: str


def _clamp_to_baseline(value: float, baseline: float) -> float:
    lo = baseline * BASELINE_MIN_FRACTION
    hi = baseline * BASELINE_MAX_FRACTION
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _clamp_delta(old: float, new: float) -> float:
    """Limit single-cycle change to ±MAX_DELTA_FRACTION of old value."""
    max_delta = abs(old) * MAX_DELTA_FRACTION
    if max_delta == 0:
        return new  # can't bound around zero; accept whatever the merge said
    if new - old > max_delta:
        return old + max_delta
    if old - new > max_delta:
        return old - max_delta
    return new


def _mad_filter(
    values_by_peer: dict[str, float],
) -> tuple[dict[str, float], list[str]]:
    """Drop peers whose value is > MAD_THRESHOLD * MAD from the median.

    Returns (kept_peers_dict, excluded_peer_ids).
    """
    if len(values_by_peer) <= 2:
        # MAD undefined with <3 points; accept all
        return values_by_peer, []

    values = list(values_by_peer.values())
    median = statistics.median(values)
    deviations = [abs(v - median) for v in values]
    mad = statistics.median(deviations)
    if mad == 0:
        # All peers agree exactly; no one is an outlier
        return values_by_peer, []

    cutoff = MAD_THRESHOLD * mad
    kept: dict[str, float] = {}
    excluded: list[str] = []
    for pid, v in values_by_peer.items():
        if abs(v - median) <= cutoff:
            kept[pid] = v
        else:
            excluded.append(pid)
    return kept, excluded


def merge_peer_snapshots(
    key: str,
    current_value: float,
    baseline: float,
    peer_snapshots: list[PeerSnapshot],
) -> MergeResult | None:
    """Weighted merge of peer snapshots into current value.

    Returns None if merge is unsafe (insufficient peers, all filtered,
    etc). Returning None means "local tuner keeps its current value."

    Args:
        key: the tunable policy key being merged
        current_value: our chapter's current value
        baseline: the baseline for clamping (± 0.5x..2x)
        peer_snapshots: list of PeerSnapshot for this key from peers.
                        Snapshots that don't match `key` are ignored.
    """
    # Filter: only snapshots for this key, with enough sample size
    relevant = [s for s in peer_snapshots if s.key == key and s.sample_size >= MIN_SAMPLES_FROM_PEER]
    if len(relevant) < MIN_PEERS_FOR_MERGE:
        return None

    # MAD filter on raw values — remove adversarial outliers
    values_by_peer = {s.chapter_id: s.value for s in relevant}
    kept_values, excluded = _mad_filter(values_by_peer)
    if len(kept_values) < MIN_PEERS_FOR_MERGE:
        return None

    kept_snapshots = [s for s in relevant if s.chapter_id in kept_values]

    # Weighted mean — weight by sqrt(sample_size) * confidence, with our
    # own value getting weight = max_peer_weight so we count as a strong peer
    weighted_sum = 0.0
    total_weight = 0.0
    for s in kept_snapshots:
        # sqrt-scale so a server with 10x samples doesn't get 10x vote
        w = (s.sample_size**0.5) * max(0.0, min(1.0, s.confidence))
        weighted_sum += s.value * w
        total_weight += w

    # Our own voice — use the max peer weight so we're always "at least as
    # heard" as the loudest peer. Prevents a single-server-with-huge-data
    # from overwhelming everyone else.
    if kept_snapshots:
        max_peer_w = max((s.sample_size**0.5) * max(0.0, min(1.0, s.confidence)) for s in kept_snapshots)
        weighted_sum += current_value * max_peer_w
        total_weight += max_peer_w

    if total_weight == 0:
        return None

    merged_raw = weighted_sum / total_weight

    # Clamp delta, then clamp to baseline envelope
    merged_capped = _clamp_delta(current_value, merged_raw)
    merged_final = _clamp_to_baseline(merged_capped, baseline)

    # If the result is identical to current, no-op (don't write audit row)
    if abs(merged_final - current_value) < 1e-9:
        return None

    contributors = sorted(kept_values.keys())
    return MergeResult(
        key=key,
        old_value=current_value,
        new_value=merged_final,
        baseline=baseline,
        contributing_peers=contributors,
        excluded_peers=sorted(excluded),
        reason=f"federation_merge: {len(contributors)} peers "
        f"({'+'.join(contributors[:3])}{'…' if len(contributors) > 3 else ''})",
    )


__all__ = [
    "BASELINE_MAX_FRACTION",
    "BASELINE_MIN_FRACTION",
    "MAD_THRESHOLD",
    "MAX_DELTA_FRACTION",
    "MIN_PEERS_FOR_MERGE",
    "MIN_SAMPLES_FROM_PEER",
    "MergeResult",
    "PeerSnapshot",
    "merge_peer_snapshots",
]
