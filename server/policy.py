"""
Chapter policy — hyperparameters with bounded auto-tuning.

PR-2b. Replaces hardcoded thresholds across governance.py / calls.py /
think_cycle.py with values read from the `chapter_policy` Postgres table.
think_tune_policy (cycle 14) reads 14-day outcome windows and nudges
tunable keys ±10% per tick, bounded to 0.5x..2.0x of baseline.

Leaders can pin any key to freeze it. When pinned, auto-tune skips.

Tunable keys (PR-2b scope — others are stored but auto_tuned=false):
  intro.confidence_floor     — 0-1  higher = stricter intro proposals
  intro.cooldown_days        — int  higher = less frequent re-intros
  call.response_relevance_floor — 0-1  higher = stricter response gate

Reserved keys (manual-only — PR-2c may make some tunable):
  call.trust_min_established (=20), call.trust_min_trusted (=50)
  approval.ttl_hours (=72)
  autopromote.enabled (=false), autopromote.{advisor,leader}_*
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

# Injected by chapter_agent.py lifespan
_pg_request: Callable[..., Awaitable] | None = None

def _pg() -> Callable[..., Awaitable]:
    """The injected pg_request, or a LOUD failure if init() never ran — the
    old unguarded calls crashed with a bare 'NoneType' object is not callable
    (R2 whole-app sweep)."""
    if _pg_request is None:
        raise RuntimeError("policy.init() was never called — no pg_request injected")
    return _pg_request

_agent_id = ""

# In-memory cache of current values — refreshed periodically
_cache: dict[str, Any] = {}
_cache_ts: datetime | None = None
_CACHE_TTL = timedelta(minutes=5)

# Auto-tune guardrails
AUTO_TUNE_DELTA_PCT = 0.10  # ±10% per tick
AUTO_TUNE_MIN_BOUND_X = 0.5  # never below 0.5x baseline
AUTO_TUNE_MAX_BOUND_X = 2.0  # never above 2.0x baseline
AUTO_TUNE_WARMUP_DAYS = 14  # need this much outcome history before first tune
AUTO_TUNE_WINDOW_DAYS = 14  # rolling outcome window to read
AUTO_TUNE_MIN_SAMPLES = 5  # need at least this many outcomes in window


def init(pg_request, agent_id: str) -> None:
    global _pg_request, _agent_id
    _pg_request = pg_request
    _agent_id = agent_id


# ═══════════════════════════════════════════════════════════════
# Read — cache-backed typed getter used across modules
# ═══════════════════════════════════════════════════════════════


async def _refresh_cache() -> None:
    global _cache, _cache_ts
    if _pg_request is None:
        return
    try:
        rows = await _pg_request(
            "GET",
            "chapter_policy",
            params={"chapter_id": f"eq.{_agent_id}", "select": "key,value,value_type,pinned_by"},
        )
    except Exception:
        return
    new_cache: dict[str, Any] = {}
    for row in rows or []:
        new_cache[row["key"]] = {
            "value": row.get("value"),
            "type": row.get("value_type", "float"),
            "pinned": bool(row.get("pinned_by")),
        }
    _cache = new_cache
    _cache_ts = datetime.now(UTC)


async def _ensure_cache() -> None:
    if _cache_ts is None or datetime.now(UTC) - _cache_ts > _CACHE_TTL:
        await _refresh_cache()


async def get(key: str, default: Any = None) -> Any:
    """Read a typed policy value. Falls back to default if missing / unreachable."""
    await _ensure_cache()
    entry = _cache.get(key)
    if entry is None:
        return default
    val = entry.get("value")
    t = entry.get("type", "float")
    try:
        if t == "int":
            return int(val)
        if t == "float":
            return float(val)
        if t == "bool":
            return bool(val)
        return val
    except (TypeError, ValueError):
        return default


async def get_bool(key: str, default: bool = False) -> bool:
    return bool(await get(key, default))


async def get_int(key: str, default: int) -> int:
    v = await get(key, default)
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


async def get_float(key: str, default: float) -> float:
    v = await get(key, default)
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def invalidate_cache() -> None:
    """Force next read to hit Postgres (e.g. after a leader pin)."""
    global _cache_ts
    _cache_ts = None


# ═══════════════════════════════════════════════════════════════
# Write — leader pin / unpin / admin override
# ═══════════════════════════════════════════════════════════════


async def pin(key: str, actor_agent_id: str, reason: str = "") -> dict:
    """Leader freezes a key's current value. Auto-tune will skip it."""
    if _pg_request is None:
        return {"error": "no_database"}
    try:
        rows = await _pg_request(
            "PATCH",
            "chapter_policy", params={"chapter_id": f"eq.{_agent_id}", "key": f"eq.{key}"},
            body={
                "pinned_by": actor_agent_id,
                "pinned_reason": reason[:500],
                "pinned_at": datetime.now(UTC).isoformat(),
            },
        )
        if isinstance(rows, list) and rows:
            await _log_history(
                key, rows[0].get("value"), rows[0].get("value"), reason="leader_pin", actor=actor_agent_id
            )
            invalidate_cache()
            return {"ok": True, "policy": rows[0]}
        return {"error": "not_found"}
    except Exception as e:
        return {"error": "patch_failed", "detail": str(e)[:200]}


async def unpin(key: str, actor_agent_id: str) -> dict:
    if _pg_request is None:
        return {"error": "no_database"}
    try:
        rows = await _pg_request(
            "PATCH",
            "chapter_policy", params={"chapter_id": f"eq.{_agent_id}", "key": f"eq.{key}"},
            body={"pinned_by": None, "pinned_reason": None, "pinned_at": None},
        )
        if isinstance(rows, list) and rows:
            await _log_history(
                key, rows[0].get("value"), rows[0].get("value"), reason="leader_unpin", actor=actor_agent_id
            )
            invalidate_cache()
            return {"ok": True, "policy": rows[0]}
        return {"error": "not_found"}
    except Exception as e:
        return {"error": "patch_failed", "detail": str(e)[:200]}


async def override(key: str, new_value: Any, actor_agent_id: str, reason: str = "") -> dict:
    """Admin manually sets a value. Leaves pin state intact."""
    if _pg_request is None:
        return {"error": "no_database"}
    try:
        rows = await _pg_request(
            "PATCH",
            "chapter_policy", params={"chapter_id": f"eq.{_agent_id}", "key": f"eq.{key}"},
            body={
                "value": new_value,
                "last_updated": datetime.now(UTC).isoformat(),
                "last_tune_reason": f"admin_override: {reason[:200]}",
            },
        )
        if isinstance(rows, list) and rows:
            old_value = rows[0].get("value")  # after PATCH this is the new; but API returns updated rows
            await _log_history(key, old_value, new_value, reason="admin_override", actor=actor_agent_id)
            invalidate_cache()
            return {"ok": True, "policy": rows[0]}
        return {"error": "not_found"}
    except Exception as e:
        return {"error": "patch_failed", "detail": str(e)[:200]}


# ═══════════════════════════════════════════════════════════════
# Auto-tune logic
# ═══════════════════════════════════════════════════════════════


def _clamp_numeric(new_value: float, baseline: float) -> float:
    """Enforce 0.5x..2.0x of baseline so auto-tune can't drift unbounded."""
    if baseline <= 0:
        return new_value
    lo = baseline * AUTO_TUNE_MIN_BOUND_X
    hi = baseline * AUTO_TUNE_MAX_BOUND_X
    return max(lo, min(hi, new_value))


def _step(current: float, direction: str, magnitude: float = AUTO_TUNE_DELTA_PCT) -> float:
    """Move current by ±magnitude fraction.

    direction = 'tighten' raises value for stricter keys (confidence floor,
    relevance floor) and raises value for cooldown-style keys (longer cooldown).
    The 'tighten' semantics are key-specific and resolved by the caller — this
    is just +/- %.
    """
    if direction == "tighten":
        return current * (1.0 + magnitude)
    if direction == "loosen":
        return current * (1.0 - magnitude)
    return current


def propose_intro_adjustment(
    current_floor: float,
    baseline_floor: float,
    approvals: int,
    rejections: int,
    expired: int,
) -> tuple[float, str] | None:
    """Return (new_value, reason) for intro.confidence_floor, or None if no change.

    Heuristic:
      - If rejection rate > 50% → tighten (raise floor; only surface high-confidence proposals)
      - If approval rate > 85% AND sample > 5 → loosen (lower floor; leaders want more proposals)
      - Otherwise no change
    """
    total = approvals + rejections + expired
    if total < AUTO_TUNE_MIN_SAMPLES:
        return None
    reject_rate = rejections / total if total else 0
    approve_rate = approvals / total if total else 0
    if reject_rate > 0.50:
        new_val = _clamp_numeric(_step(current_floor, "tighten"), baseline_floor)
        return (new_val, f"rejection_rate={reject_rate:.2f} > 0.5 → tighten")
    if approve_rate > 0.85 and total >= AUTO_TUNE_MIN_SAMPLES:
        new_val = _clamp_numeric(_step(current_floor, "loosen"), baseline_floor)
        return (new_val, f"approval_rate={approve_rate:.2f} > 0.85 → loosen")
    return None


def propose_cooldown_adjustment(
    current_days: int,
    baseline_days: int,
    repeated_pair_rejections: int,
    window_days: int,
) -> tuple[int, str] | None:
    """Intro cooldown — if rejected pairs keep getting re-proposed, lengthen."""
    if repeated_pair_rejections < AUTO_TUNE_MIN_SAMPLES:
        return None
    if repeated_pair_rejections >= 3:
        new_val = int(round(_clamp_numeric(_step(current_days, "tighten"), baseline_days)))
        if new_val != current_days:
            return (
                new_val,
                f"{repeated_pair_rejections} rejected pairs re-proposed in {window_days}d → extend cooldown",
            )
    return None


def propose_relevance_floor_adjustment(
    current_floor: float,
    baseline_floor: float,
    low_quality_responses: int,
    high_quality_responses: int,
    unreached_calls: int,
) -> tuple[float, str] | None:
    """Call response relevance floor.

    Signals:
      - too many low-quality responses → raise floor
      - many unreached calls (no responses at all) → lower floor so more agents respond
    """
    total = low_quality_responses + high_quality_responses
    if total < AUTO_TUNE_MIN_SAMPLES and unreached_calls < AUTO_TUNE_MIN_SAMPLES:
        return None
    if total >= AUTO_TUNE_MIN_SAMPLES:
        low_rate = low_quality_responses / total
        if low_rate > 0.5:
            new_val = _clamp_numeric(_step(current_floor, "tighten"), baseline_floor)
            return (new_val, f"low-quality response rate={low_rate:.2f} → tighten floor")
    if unreached_calls >= AUTO_TUNE_MIN_SAMPLES and total < AUTO_TUNE_MIN_SAMPLES:
        new_val = _clamp_numeric(_step(current_floor, "loosen"), baseline_floor)
        return (new_val, f"{unreached_calls} calls unreached → loosen floor")
    return None


async def tune_cycle() -> dict:
    """One pass of think_tune_policy. Reads outcome_tracker signals over the
    last 14 days for each tunable, unpinned key and proposes bounded updates.

    Returns a summary dict {key: {old, new, reason}} for logging / leader digest.
    """
    if _pg_request is None:
        return {}
    await _refresh_cache()

    # Load all tunable policies
    try:
        rows = await _pg_request(
            "GET",
            "chapter_policy",
            params={
                "chapter_id": f"eq.{_agent_id}",
                "auto_tuned": "eq.true",
                "select": "key,value,baseline,pinned_by,last_updated",
            },
        )
    except Exception:
        return {}

    if not rows:
        return {}

    # Pull 14-day outcomes once
    since = (datetime.now(UTC) - timedelta(days=AUTO_TUNE_WINDOW_DAYS)).isoformat()
    try:
        outcomes = await _pg_request(
            "GET",
            "agent_action_outcomes",
            params={
                "chapter_agent_id": f"eq.{_agent_id}",
                "created_at": f"gte.{since}",
                "select": "action_type,signal,quality_score",
                "limit": "5000",
            },
        )
    except Exception:
        outcomes = []

    # Bucket by action_type
    buckets: dict[str, dict[str, int]] = {}
    for o in outcomes or []:
        kind = o.get("action_type", "unknown")
        signal = o.get("signal", "")
        buckets.setdefault(kind, {"positive": 0, "negative": 0, "rsvp": 0, "skip": 0})
        if signal in buckets[kind]:
            buckets[kind][signal] += 1

    # Count rejected intro approvals for cooldown tuning
    since_approvals = since
    try:
        intro_approvals = await _pg_request(
            "GET",
            "pending_approvals",
            params={
                "chapter_id": f"eq.{_agent_id}",
                "kind": "eq.introduction",
                "created_at": f"gte.{since_approvals}",
                "select": "status,payload",
                "limit": "500",
            },
        )
    except Exception:
        intro_approvals = []

    approvals_count = sum(1 for a in intro_approvals if a.get("status") == "approved")
    rejections_count = sum(1 for a in intro_approvals if a.get("status") == "rejected")
    expired_count = sum(1 for a in intro_approvals if a.get("status") == "expired")

    # Count calls with no responses (unreached)
    try:
        unreached_calls = await _pg_request(
            "GET",
            "chapter_calls",
            params={
                "chapter_id": f"eq.{_agent_id}",
                "status": "in.(closed,expired)",
                "response_count": "eq.0",
                "created_at": f"gte.{since}",
                "select": "id",
                "limit": "500",
            },
        )
    except Exception:
        unreached_calls = []

    call_positive = buckets.get("call_response", {}).get("positive", 0)
    call_negative = buckets.get("call_response", {}).get("negative", 0)

    summary: dict[str, dict] = {}

    for row in rows:
        if row.get("pinned_by"):
            continue
        key = row["key"]
        current = row["value"]
        baseline = row["baseline"]

        # Warmup check — don't tune before server has 14 days of data
        last_updated = row.get("last_updated")
        if last_updated:
            try:
                age = datetime.now(UTC) - datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
                if age < timedelta(days=AUTO_TUNE_WARMUP_DAYS):
                    continue
            except (ValueError, TypeError):
                pass

        proposal: tuple[Any, str] | None = None

        if key == "intro.confidence_floor":
            proposal = propose_intro_adjustment(
                float(current),
                float(baseline),
                approvals_count,
                rejections_count,
                expired_count,
            )
        elif key == "intro.cooldown_days":
            # Count distinct rejected pairs
            rejected_pairs = set()
            for a in intro_approvals:
                if a.get("status") == "rejected":
                    pair = (a.get("payload") or {}).get("pair", [])
                    if len(pair) == 2:
                        rejected_pairs.add(tuple(sorted(pair)))
            prop = propose_cooldown_adjustment(
                int(current),
                int(baseline),
                len(rejected_pairs),
                AUTO_TUNE_WINDOW_DAYS,
            )
            proposal = prop  # type: ignore[assignment]
        elif key == "call.response_relevance_floor":
            proposal = propose_relevance_floor_adjustment(
                float(current),
                float(baseline),
                call_negative,
                call_positive,
                len(unreached_calls or []),
            )

        if proposal is None:
            continue
        new_value, reason = proposal
        if new_value == current:
            continue

        # Persist the update
        try:
            await _pg_request(
                "PATCH",
                "chapter_policy", params={"chapter_id": f"eq.{_agent_id}", "key": f"eq.{key}"},
                body={
                    "value": new_value,
                    "last_updated": datetime.now(UTC).isoformat(),
                    "last_tune_reason": reason[:500],
                    "last_tune_outcome_window_days": AUTO_TUNE_WINDOW_DAYS,
                    "last_tune_sample_size": approvals_count + rejections_count + expired_count,
                },
            )
            await _log_history(
                key,
                current,
                new_value,
                reason=f"auto_tune: {reason}",
                actor=_agent_id,
                window=AUTO_TUNE_WINDOW_DAYS,
                sample=approvals_count + rejections_count + expired_count,
            )
            summary[key] = {"old": current, "new": new_value, "reason": reason}
        except Exception as e:
            print(f"[Policy] tune {key} failed: {e}")

    # ── Federation-wide governance (Phase 4) ────────────────────────────
    # After local tuning, optionally merge peer server values into our
    # tunable-unpinned keys. Gated by policy.federation_enabled flag
    # (defaults to false — opt-in only).
    try:
        federation_enabled = await _get_bool("federation.enabled")
    except Exception:
        federation_enabled = False

    if federation_enabled:
        merge_updates = await _federation_merge_cycle(rows)
        for key, change in merge_updates.items():
            # Key might have already moved in local step; note that in summary
            summary.setdefault(key, {})
            summary[key]["federation_new"] = change["new"]
            summary[key]["federation_reason"] = change["reason"]

    if summary:
        invalidate_cache()
    return summary


# ═══════════════════════════════════════════════════════════════
# PR-E: trust auto-tuner — adjusts trust.delta_scale based on
# whether newcomers are reaching the federate threshold (50).
# ═══════════════════════════════════════════════════════════════


# Tunable thresholds (themselves overridable via chapter_policy).
TRUST_TUNER_BASELINE_SCALE = 1.0
TRUST_TUNER_MIN_SCALE = 0.5
TRUST_TUNER_MAX_SCALE = 2.0
TRUST_TUNER_STEP_PCT = 0.10  # ±10% per cycle
# If MORE than this fraction of >60d-tenured agents are stalled below
# the federate threshold (20), bump the scale UP. If LESS than the
# inverse (1 - threshold) are stalled, scale DOWN.
TRUST_STALL_FRACTION_THRESHOLD = 0.50
TRUST_STALL_TENURE_DAYS = 60


def _compute_trust_stall_signal(agents: list[dict], *, now: datetime) -> dict:
    """Pure helper — given a list of agent rows with `trust_score` and
    `created_at`, compute the stall signal. Exposed for unit tests.

    Returns:
      {
        eligible: int,         # agents > tenure floor
        stalled: int,          # eligible AND trust_score < 20
        stalled_fraction: float,
        signal: 'tighten'|'loosen'|'hold',
      }

    'tighten' means stall fraction is HIGH → scale UP (more accrual).
    'loosen' means scale DOWN (fewer points needed). Mirrors the
    _step() semantics used elsewhere.
    """
    eligible = 0
    stalled = 0
    cutoff = now - timedelta(days=TRUST_STALL_TENURE_DAYS)
    for a in agents:
        ca = a.get("created_at")
        if not ca:
            continue
        try:
            created = datetime.fromisoformat(str(ca).replace("Z", "+00:00"))
        except ValueError:
            continue
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        if created > cutoff:
            continue  # not yet eligible (under 60d tenure)
        eligible += 1
        try:
            score = float(a.get("trust_score") or 0)
        except (TypeError, ValueError):
            score = 0.0
        if score < 20.0:
            stalled += 1
    if not eligible:
        # No mature agents → no signal to act on.
        fraction = 0.0
        signal = "hold"
    else:
        fraction = stalled / eligible
        if fraction > TRUST_STALL_FRACTION_THRESHOLD:
            signal = "tighten"
        elif fraction < (1.0 - TRUST_STALL_FRACTION_THRESHOLD):
            signal = "loosen"
        else:
            signal = "hold"
    return {
        "eligible": eligible,
        "stalled": stalled,
        "stalled_fraction": round(fraction, 3),
        "signal": signal,
    }


def _next_trust_scale(current: float, signal: str) -> float:
    """Pure step function. Clamped to [MIN_SCALE, MAX_SCALE]."""
    if signal == "tighten":
        new = current * (1.0 + TRUST_TUNER_STEP_PCT)
    elif signal == "loosen":
        new = current * (1.0 - TRUST_TUNER_STEP_PCT)
    else:
        new = current
    return max(TRUST_TUNER_MIN_SCALE, min(TRUST_TUNER_MAX_SCALE, new))


async def tune_trust_cycle() -> dict:
    """Read agents, compute stall signal, and adjust the
    `trust.delta_scale` chapter_policy key. Called from the same place
    as `tune_cycle` (think_cycle.py).

    Returns a summary dict; empty if nothing changed.
    """
    if _pg_request is None:
        return {}
    try:
        agents = (
            await _pg_request(
                "GET",
                "agents",
                params={"select": "agent_id,trust_score,created_at", "limit": 5000},
            )
            or []
        )
    except Exception:
        return {}

    now = datetime.now(UTC)
    signal_info = _compute_trust_stall_signal(agents, now=now)

    # Don't move on small samples — < 5 eligible agents → not enough
    # signal to act on.
    if signal_info["eligible"] < 5 or signal_info["signal"] == "hold":
        return {"signal": signal_info, "applied": None}

    current = await get_float("trust.delta_scale", TRUST_TUNER_BASELINE_SCALE)
    new_value = _next_trust_scale(current, signal_info["signal"])
    if abs(new_value - current) < 1e-6:
        # Already at clamp boundary, no movement.
        return {"signal": signal_info, "applied": None}

    reason = (
        f"trust.tune: {signal_info['stalled']}/{signal_info['eligible']} stalled "
        f"({signal_info['stalled_fraction']}) → {signal_info['signal']}"
    )
    try:
        await _pg_request(
            "PATCH",
            "chapter_policy", params={"chapter_id": f"eq.{_agent_id}", "key": "eq.trust.delta_scale"},
            body={
                "value": new_value,
                "last_updated": datetime.now(UTC).isoformat(),
                "last_tune_reason": reason[:500],
                "last_tune_outcome_window_days": TRUST_STALL_TENURE_DAYS,
                "last_tune_sample_size": signal_info["eligible"],
            },
        )
        await _log_history(
            "trust.delta_scale",
            current,
            new_value,
            reason=f"auto_tune: {reason}",
            actor=_agent_id,
            window=TRUST_STALL_TENURE_DAYS,
            sample=signal_info["eligible"],
        )
        invalidate_cache()
        return {"signal": signal_info, "applied": {"old": current, "new": new_value, "reason": reason}}
    except Exception as e:
        print(f"[Policy] tune_trust_cycle failed: {e}")
        return {"signal": signal_info, "applied": None, "error": str(e)[:200]}


async def _get_bool(key: str) -> bool:
    """Read a single boolean-valued policy key. Returns False on miss."""
    if _pg_request is None:
        return False
    try:
        rows = await _pg_request(
            "GET",
            "chapter_policy",
            params={
                "chapter_id": f"eq.{_agent_id}",
                "key": f"eq.{key}",
                "select": "value",
            },
        )
    except Exception:
        return False
    if not rows:
        return False
    v = rows[0].get("value")
    # jsonb true/false comes back as Python bool via the postgres client
    return bool(v)


async def _federation_merge_cycle(rows: list[dict]) -> dict:
    """Merge peer chapter policy snapshots into our tunable keys.

    Reads `federation_intelligence.federation_knowledge` (in-memory dict
    populated by the 6-min exchange) for `policy_snapshot` entries, then
    calls `federated_policy_merge.merge_peer_snapshots` per key.

    Returns a dict of {key: {new, reason}} for any key we moved.
    """
    updates: dict = {}
    try:
        import federated_policy_merge
        import federation_intelligence
    except ImportError:
        return updates

    peer_knowledge = getattr(federation_intelligence, "federation_knowledge", {})
    if not peer_knowledge:
        return updates

    # Build per-key list of PeerSnapshot
    by_key: dict[str, list] = {}
    for peer_id, data in peer_knowledge.items():
        if not isinstance(data, dict):
            continue
        snaps = data.get("policy_snapshot") or []
        if not isinstance(snaps, list):
            continue
        for entry in snaps:
            if not isinstance(entry, dict):
                continue
            try:
                snap = federated_policy_merge.PeerSnapshot(
                    chapter_id=peer_id,
                    key=str(entry.get("key", "")),
                    value=float(entry.get("value", 0.0)),
                    baseline=float(entry.get("baseline", 0.0)),
                    sample_size=int(entry.get("sample_size", 0)),
                    confidence=float(entry.get("confidence", 1.0)),
                )
            except (TypeError, ValueError):
                continue
            if not snap.key:
                continue
            by_key.setdefault(snap.key, []).append(snap)

    # For each tunable-unpinned numeric key we own, merge
    for r in rows:
        key = r.get("key", "")
        if key not in by_key:
            continue
        if r.get("pinned_by"):  # frozen by leader
            continue
        if not r.get("auto_tuned"):
            continue
        try:
            current = float(r.get("value", 0))
            baseline = float(r.get("baseline", 0))
        except (TypeError, ValueError):
            continue
        if baseline == 0:
            continue

        result = federated_policy_merge.merge_peer_snapshots(
            key, current_value=current, baseline=baseline, peer_snapshots=by_key[key]
        )
        if result is None:
            continue

        # Persist the merged value
        try:
            await _pg()(
                "PATCH",
                "chapter_policy", params={"chapter_id": f"eq.{_agent_id}", "key": f"eq.{key}"},
                body={
                    "value": result.new_value,
                    "last_updated": datetime.now(UTC).isoformat(),
                    "last_tune_reason": result.reason[:500],
                },
            )
            await _log_history(
                key,
                current,
                result.new_value,
                reason=result.reason,
                actor=_agent_id,
                window=AUTO_TUNE_WINDOW_DAYS,
                sample=len(result.contributing_peers),
            )
            updates[key] = {"new": result.new_value, "reason": result.reason}
        except Exception as e:
            print(f"[Policy] federation merge for {key} failed: {e}")

    return updates


async def get_policy_snapshot_for_federation() -> list[dict]:
    """Build our policy snapshot for inclusion in the federation exchange.

    Only exports tunable-unpinned numeric keys — we don't gossip about
    values that aren't ours to share, or that don't change.
    """
    if _pg_request is None:
        return []
    try:
        rows = await _pg_request(
            "GET",
            "chapter_policy",
            params={
                "chapter_id": f"eq.{_agent_id}",
                "auto_tuned": "eq.true",
                "select": "key,value,baseline,value_type,last_tune_sample_size,pinned_by",
            },
        )
    except Exception:
        return []

    snapshots: list[dict] = []
    for r in rows or []:
        if r.get("pinned_by"):
            continue
        vtype = r.get("value_type", "float")
        if vtype not in ("float", "int"):
            continue  # skip strings, bools
        try:
            value = float(r.get("value", 0))
            baseline = float(r.get("baseline", 0))
        except (TypeError, ValueError):
            continue
        sample = r.get("last_tune_sample_size") or 0
        snapshots.append(
            {
                "key": r.get("key", ""),
                "value": value,
                "baseline": baseline,
                "sample_size": int(sample),
                "confidence": 1.0 if sample >= 10 else max(0.1, sample / 10.0),
            }
        )
    return snapshots


async def _log_history(
    key: str,
    old_value: Any,
    new_value: Any,
    reason: str,
    actor: str,
    window: int | None = None,
    sample: int | None = None,
) -> None:
    if _pg_request is None:
        return
    try:
        await _pg_request(
            "POST",
            "chapter_policy_history",
            body={
                "chapter_id": _agent_id,
                "key": key,
                "old_value": old_value,
                "new_value": new_value,
                "reason": reason[:500],
                "actor": actor,
                "outcome_window_days": window,
                "sample_size": sample,
            },
        )
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════
# Retrieval for /page/policy surface + /api/policy
# ═══════════════════════════════════════════════════════════════


async def list_all() -> list[dict]:
    if _pg_request is None:
        return []
    try:
        return (
            await _pg_request(
                "GET",
                "chapter_policy",
                params={"chapter_id": f"eq.{_agent_id}", "order": "key.asc"},
            )
            or []
        )
    except Exception:
        return []


async def history_for(key: str, limit: int = 50) -> list[dict]:
    if _pg_request is None:
        return []
    try:
        return (
            await _pg_request(
                "GET",
                "chapter_policy_history",
                params={
                    "chapter_id": f"eq.{_agent_id}",
                    "key": f"eq.{key}",
                    "order": "created_at.desc",
                    "limit": str(min(limit, 500)),
                },
            )
            or []
        )
    except Exception:
        return []


# ═══════════════════════════════════════════════════════════════
# Auto-promote — reads policy + nominations + trust_score + tenure
# ═══════════════════════════════════════════════════════════════


async def auto_promote_cycle() -> dict:
    """Auto-resolves pending nominations when all thresholds met.

    Thresholds come from chapter_policy:
      autopromote.enabled             (bool — gate, default false)
      autopromote.{advisor,leader}_trust_min        (float)
      autopromote.{advisor,leader}_endorsements_min (int, up-votes minus down-votes)
      autopromote.{advisor,leader}_tenure_days      (int)

    Returns {promoted: [...], skipped: [{nominee, reason}, ...]}.
    """
    if _pg_request is None:
        return {"promoted": [], "skipped": []}

    enabled = await get_bool("autopromote.enabled", False)
    if not enabled:
        return {"promoted": [], "skipped": [], "reason": "flag_off"}

    # Pull pending nominations
    try:
        noms = await _pg_request(
            "GET",
            "chapter_role_nominations",
            params={
                "chapter_id": f"eq.{_agent_id}",
                "status": "eq.pending",
                "select": "id,nominee_agent_id,target_role,endorsements,created_at",
                "limit": "200",
            },
        )
    except Exception:
        return {"promoted": [], "skipped": []}

    promoted: list[dict] = []
    skipped: list[dict] = []

    # Read thresholds once
    adv_trust = await get_float("autopromote.advisor_trust_min", 50.0)
    adv_endorse = await get_int("autopromote.advisor_endorsements_min", 2)
    adv_tenure = await get_int("autopromote.advisor_tenure_days", 14)
    ldr_trust = await get_float("autopromote.leader_trust_min", 75.0)
    ldr_endorse = await get_int("autopromote.leader_endorsements_min", 3)
    ldr_tenure = await get_int("autopromote.leader_tenure_days", 60)

    for nom in noms or []:
        target_role = nom.get("target_role")
        nominee = nom.get("nominee_agent_id")
        if not nominee or target_role not in ("advisor", "leader"):
            skipped.append({"nominee": nominee, "reason": "invalid_target"})
            continue

        # Read nominee's trust + creation date (tenure proxy)
        try:
            rows = await _pg_request(
                "GET",
                "agents",
                params={"agent_id": f"eq.{nominee}", "select": "trust_score,created_at"},
            )
        except Exception:
            skipped.append({"nominee": nominee, "reason": "read_failed"})
            continue
        if not rows:
            skipped.append({"nominee": nominee, "reason": "agent_not_found"})
            continue
        agent = rows[0]

        trust = float(agent.get("trust_score") or 0.0)
        created_at = agent.get("created_at")
        tenure_days = 0
        if created_at:
            try:
                tenure_days = (datetime.now(UTC) - datetime.fromisoformat(created_at.replace("Z", "+00:00"))).days
            except (ValueError, TypeError):
                tenure_days = 0

        # Count endorsements (up - down)
        endorsements = nom.get("endorsements") or []
        up = sum(1 for e in endorsements if e.get("signal") == "up")
        down = sum(1 for e in endorsements if e.get("signal") == "down")
        net = up - down

        # Check thresholds
        if target_role == "advisor":
            required = {"trust": adv_trust, "endorsements": adv_endorse, "tenure": adv_tenure}
        else:
            required = {"trust": ldr_trust, "endorsements": ldr_endorse, "tenure": ldr_tenure}

        reasons: list[str] = []
        if trust < required["trust"]:
            reasons.append(f"trust={trust:.1f}<{required['trust']}")
        if net < required["endorsements"]:
            reasons.append(f"endorsements={net}<{required['endorsements']}")
        if tenure_days < required["tenure"]:
            reasons.append(f"tenure={tenure_days}d<{required['tenure']}d")
        if reasons:
            skipped.append({"nominee": nominee, "target_role": target_role, "reason": ", ".join(reasons)})
            continue

        # All thresholds met — resolve as approved, promote
        try:
            await _pg_request(
                "PATCH",
                "chapter_role_nominations", params={"id": f"eq.{nom['id']}"},
                body={
                    "status": "approved",
                    "resolved_by": _agent_id,
                    "resolved_at": datetime.now(UTC).isoformat(),
                    "resolution_note": f"auto-promoted: trust={trust:.1f}, net_endorsements={net}, tenure={tenure_days}d",
                },
            )
            await _pg_request(
                "PATCH",
                "agents", params={"agent_id": f"eq.{nominee}"},
                body={"chapter_role": target_role},
            )
            promoted.append(
                {
                    "nominee": nominee,
                    "target_role": target_role,
                    "trust": trust,
                    "endorsements": net,
                    "tenure_days": tenure_days,
                }
            )
        except Exception as e:
            skipped.append({"nominee": nominee, "reason": f"promote_failed: {str(e)[:100]}"})

    return {"promoted": promoted, "skipped": skipped}
